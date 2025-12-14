#![allow(dead_code)]

//! TCP SYN (half-open) port scanner
//!
//! This module implements TCP SYN scanning using raw sockets. SYN scanning
//! is stealthier than TCP Connect scanning because it doesn't complete the
//! three-way handshake - it sends SYN, analyzes the response, then resets.
//!
//! **Requires root privileges or CAP_NET_RAW capability.**

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use log::{debug, info, trace, warn};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use rand::Rng;
use tokio::sync::{mpsc, Semaphore};

use crate::types::{PortInfo, PortState, Protocol, ScanConfig, ScanTarget};

/// Default number of concurrent SYN probes
const SYN_DEFAULT_THREADS: usize = 100;

/// Default timeout for SYN probes
const SYN_DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// TCP response types
#[derive(Debug, Clone, Copy, PartialEq)]
enum TcpResponseType {
    SynAck, // Port is open
    Rst,    // Port is closed
}

/// Check if we have raw socket capability for TCP
pub fn has_raw_tcp_capability() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
        if fd >= 0 {
            libc::close(fd);
            true
        } else {
            debug!(
                "Raw TCP socket capability check failed: errno={}",
                *libc::__errno_location()
            );
            false
        }
    }
}

/// Get local IP address for the interface that would route to target
fn get_local_ip(target: Ipv4Addr) -> Result<Ipv4Addr> {
    use std::net::UdpSocket;

    // Create a UDP socket and "connect" to target to determine local IP
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(SocketAddr::new(IpAddr::V4(target), 80))?;

    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(anyhow!("IPv6 not supported for SYN scanning")),
    }
}

/// Scan multiple targets for open TCP ports using SYN scanning
pub async fn scan_syn_ports(config: &ScanConfig) -> Result<HashMap<IpAddr, Vec<PortInfo>>> {
    // Check privileges first
    if !has_raw_tcp_capability() {
        return Err(anyhow!(
            "TCP SYN scanning requires root privileges or CAP_NET_RAW capability.\n\
             Run with sudo or set capabilities: sudo setcap cap_net_raw+ep ./heroforge"
        ));
    }

    let mut results = HashMap::new();

    for target_str in &config.targets {
        match target_str.parse::<IpAddr>() {
            Ok(ip) => {
                let target = ScanTarget {
                    ip,
                    hostname: None,
                };
                match scan_target_syn_ports(&target, config).await {
                    Ok(ports) => {
                        results.insert(ip, ports);
                    }
                    Err(e) => {
                        warn!("Failed to SYN scan {}: {}", ip, e);
                    }
                }
            }
            Err(_) => {
                // Try to resolve hostname
                if let Ok(addrs) = tokio::net::lookup_host(format!("{}:0", target_str)).await {
                    for addr in addrs {
                        let target = ScanTarget {
                            ip: addr.ip(),
                            hostname: Some(target_str.clone()),
                        };
                        match scan_target_syn_ports(&target, config).await {
                            Ok(ports) => {
                                results.insert(addr.ip(), ports);
                            }
                            Err(e) => {
                                warn!("Failed to SYN scan {}: {}", addr.ip(), e);
                            }
                        }
                        break; // Only scan first resolved IP
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Scan TCP ports on a single target using SYN scanning
pub async fn scan_target_syn_ports(
    target: &ScanTarget,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>> {
    let target_ip = match target.ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err(anyhow!("IPv6 SYN scanning not yet implemented"));
        }
    };

    // Get local IP for packet construction
    let local_ip = get_local_ip(target_ip)?;

    // Determine ports to scan
    let ports: Vec<u16> = (config.port_range.0..=config.port_range.1).collect();

    info!(
        "Starting TCP SYN scan of {} ({} ports)",
        target_ip,
        ports.len()
    );

    // Create raw socket for sending
    let send_fd = create_raw_tcp_socket()?;

    // Create raw socket for receiving
    let recv_fd = create_raw_tcp_socket()?;

    // Set up concurrency control
    let threads = std::cmp::min(config.threads, SYN_DEFAULT_THREADS);
    let semaphore = Arc::new(Semaphore::new(threads));

    // Channel for receiving TCP responses
    let (response_tx, mut response_rx) = mpsc::channel::<(u16, TcpResponseType)>(10000);

    // Track which ports we've sent probes to
    let pending_ports: Arc<tokio::sync::RwLock<HashSet<u16>>> =
        Arc::new(tokio::sync::RwLock::new(ports.iter().cloned().collect()));

    // Start response listener in background
    let listener_target = target_ip;
    let listener_pending = pending_ports.clone();
    let listener_handle = tokio::spawn(async move {
        tcp_response_listener(recv_fd, listener_target, response_tx, listener_pending).await
    });

    // Generate random source port base
    let src_port_base: u16 = rand::thread_rng().gen_range(32768..60000);

    // Send SYN packets
    let timeout_duration = config.timeout;
    let mut tasks = Vec::new();

    for (idx, &port) in ports.iter().enumerate() {
        let sem = semaphore.clone();
        let src_port = src_port_base.wrapping_add(idx as u16);

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            // Small delay to avoid overwhelming the network
            if idx > 0 && idx % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            send_syn_packet(send_fd, local_ip, target_ip, src_port, port)
        });
        tasks.push((port, task));
    }

    // Wait for all sends to complete
    for (port, task) in tasks {
        if let Err(e) = task.await {
            trace!("SYN send task for port {} failed: {}", port, e);
        }
    }

    // Wait for responses with timeout
    let wait_time = Duration::from_millis(timeout_duration.as_millis() as u64 + 500);
    tokio::time::sleep(wait_time).await;

    // Stop listener
    listener_handle.abort();

    // Close sockets
    unsafe {
        libc::close(send_fd);
        libc::close(recv_fd);
    }

    // Collect responses
    let mut open_ports = HashSet::new();
    let mut closed_ports = HashSet::new();

    // Drain the channel
    while let Ok((port, response_type)) = response_rx.try_recv() {
        match response_type {
            TcpResponseType::SynAck => {
                debug!("TCP SYN-ACK received for port {} - OPEN", port);
                open_ports.insert(port);
            }
            TcpResponseType::Rst => {
                trace!("TCP RST received for port {} - CLOSED", port);
                closed_ports.insert(port);
            }
        }
    }

    // Build results - only return open ports (like nmap default)
    let mut port_infos: Vec<PortInfo> = open_ports
        .iter()
        .map(|&port| PortInfo {
            port,
            protocol: Protocol::TCP,
            state: PortState::Open,
            service: None, // Service detection happens later
        })
        .collect();

    port_infos.sort_by_key(|p| p.port);

    info!(
        "TCP SYN scan of {} complete: {} open ports found",
        target_ip,
        port_infos.len()
    );

    Ok(port_infos)
}

/// Create a raw TCP socket
fn create_raw_tcp_socket() -> Result<i32> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };

    if fd < 0 {
        return Err(anyhow!(
            "Failed to create raw TCP socket (requires root/CAP_NET_RAW)"
        ));
    }

    // Enable IP_HDRINCL to build our own IP headers
    unsafe {
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Set non-blocking
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    Ok(fd)
}

/// Send a TCP SYN packet
fn send_syn_packet(
    fd: i32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<()> {
    let packet = build_syn_packet(src_ip, dst_ip, src_port, dst_port);

    let dest_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: dst_port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst_ip).to_be(),
        },
        sin_zero: [0; 8],
    };

    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dest_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        trace!("Failed to send SYN to port {}: errno={}", dst_port, unsafe {
            *libc::__errno_location()
        });
    }

    Ok(())
}

/// Build a TCP SYN packet with IP header
fn build_syn_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    // IP header (20 bytes) + TCP header (20 bytes)
    let mut packet = vec![0u8; 40];

    // Build IP header
    {
        let mut ip_packet = MutableIpv4Packet::new(&mut packet[..20]).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_dscp(0);
        ip_packet.set_ecn(0);
        ip_packet.set_total_length(40);
        ip_packet.set_identification(rand::thread_rng().gen());
        ip_packet.set_flags(2); // Don't fragment
        ip_packet.set_fragment_offset(0);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);
        // Checksum will be computed by kernel when IP_HDRINCL is set
        ip_packet.set_checksum(0);
    }

    // Build TCP header
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut packet[20..]).unwrap();
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(rand::thread_rng().gen());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5); // 20 bytes / 4
        tcp_packet.set_reserved(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(65535);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_checksum(0); // Will be set after borrow ends
    }

    // Calculate and set TCP checksum (after mutable borrow ends)
    let checksum = tcp_checksum(src_ip, dst_ip, &packet[20..]);
    // Set checksum at bytes 16-17 of TCP header (offset 36-37 in packet)
    packet[36] = (checksum >> 8) as u8;
    packet[37] = (checksum & 0xFF) as u8;

    packet
}

/// Calculate TCP checksum with pseudo-header
fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_packet: &[u8]) -> u16 {
    let src: u32 = src_ip.into();
    let dst: u32 = dst_ip.into();
    let tcp_len = tcp_packet.len() as u32;

    let mut sum: u32 = 0;

    // Pseudo-header
    sum += (src >> 16) & 0xFFFF;
    sum += src & 0xFFFF;
    sum += (dst >> 16) & 0xFFFF;
    sum += dst & 0xFFFF;
    sum += 6; // TCP protocol number
    sum += tcp_len;

    // TCP header + data
    let mut i = 0;
    while i < tcp_packet.len() {
        let word = if i + 1 < tcp_packet.len() {
            ((tcp_packet[i] as u32) << 8) | (tcp_packet[i + 1] as u32)
        } else {
            (tcp_packet[i] as u32) << 8
        };
        sum += word;
        i += 2;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Listen for TCP responses (SYN-ACK or RST)
async fn tcp_response_listener(
    fd: i32,
    target_ip: Ipv4Addr,
    tx: mpsc::Sender<(u16, TcpResponseType)>,
    pending_ports: Arc<tokio::sync::RwLock<HashSet<u16>>>,
) {
    let mut buf = vec![0u8; 65535];

    loop {
        if tx.is_closed() {
            break;
        }

        // Try to receive a packet
        let len = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };

        if len > 0 {
            let len = len as usize;
            if let Some((port, response_type)) = parse_tcp_response(&buf[..len], target_ip) {
                // Check if this port is one we're scanning
                let is_pending = pending_ports.read().await.contains(&port);
                if is_pending {
                    let _ = tx.send((port, response_type)).await;
                    pending_ports.write().await.remove(&port);
                }
            }
        } else {
            // No data available, sleep briefly
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    }
}

/// Parse a TCP response packet
fn parse_tcp_response(packet: &[u8], target_ip: Ipv4Addr) -> Option<(u16, TcpResponseType)> {
    if packet.len() < 40 {
        return None;
    }

    // Parse IP header
    let ip_packet = Ipv4Packet::new(packet)?;

    // Verify it's from our target
    if ip_packet.get_source() != target_ip {
        return None;
    }

    // Verify it's TCP
    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    // Get TCP portion
    let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
    if packet.len() < ip_header_len + 20 {
        return None;
    }

    let tcp_data = &packet[ip_header_len..];
    let tcp_packet = TcpPacket::new(tcp_data)?;

    let flags = tcp_packet.get_flags();
    let src_port = tcp_packet.get_source(); // This is the port we scanned

    // Check for SYN-ACK (open port)
    if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        return Some((src_port, TcpResponseType::SynAck));
    }

    // Check for RST (closed port)
    if flags & TcpFlags::RST != 0 {
        return Some((src_port, TcpResponseType::Rst));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_raw_tcp_capability() {
        // This will fail in unprivileged tests, which is expected
        let has_cap = has_raw_tcp_capability();
        println!("Raw TCP socket capability: {}", has_cap);
        // Don't assert - just verify it doesn't panic
    }

    #[test]
    fn test_build_syn_packet() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let packet = build_syn_packet(src_ip, dst_ip, 12345, 80);

        // Verify packet length
        assert_eq!(packet.len(), 40);

        // Parse and verify IP header
        let ip_packet = Ipv4Packet::new(&packet).unwrap();
        assert_eq!(ip_packet.get_version(), 4);
        assert_eq!(ip_packet.get_source(), src_ip);
        assert_eq!(ip_packet.get_destination(), dst_ip);
        assert_eq!(ip_packet.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);

        // Parse and verify TCP header
        let tcp_packet = TcpPacket::new(&packet[20..]).unwrap();
        assert_eq!(tcp_packet.get_source(), 12345);
        assert_eq!(tcp_packet.get_destination(), 80);
        assert!(tcp_packet.get_flags() & TcpFlags::SYN != 0);
    }

    #[test]
    fn test_tcp_checksum() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

        // Create a simple TCP packet (SYN)
        let mut tcp = vec![0u8; 20];
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut tcp).unwrap();
            tcp_packet.set_source(12345);
            tcp_packet.set_destination(80);
            tcp_packet.set_sequence(1000);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(65535);
        }

        let checksum = tcp_checksum(src_ip, dst_ip, &tcp);
        // Just verify it produces a non-zero value
        assert!(checksum != 0);
    }
}
