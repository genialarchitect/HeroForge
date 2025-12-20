#![allow(dead_code)]

//! TCP SYN (half-open) port scanner
//!
//! This module implements TCP SYN scanning using raw sockets. SYN scanning
//! is stealthier than TCP Connect scanning because it doesn't complete the
//! three-way handshake - it sends SYN, analyzes the response, then resets.
//!
//! **Supports both IPv4 and IPv6 targets.**
//!
//! ## IPv4 vs IPv6 Implementation Differences
//!
//! - **IPv4**: Uses `IP_HDRINCL` socket option, builds complete IP+TCP packets
//! - **IPv6**: Kernel handles IPv6 header, we only build TCP segments
//! - **Checksum**: IPv6 uses 128-bit addresses in pseudo-header (vs 32-bit for IPv4)
//!
//! **Requires root privileges or CAP_NET_RAW capability.**

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use log::{debug, info, trace, warn};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::Ipv6Packet;
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

/// Get local IPv4 address for the interface that would route to target
fn get_local_ip(target: Ipv4Addr) -> Result<Ipv4Addr> {
    use std::net::UdpSocket;

    // Create a UDP socket and "connect" to target to determine local IP
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(SocketAddr::new(IpAddr::V4(target), 80))?;

    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(anyhow!("Expected IPv4 address but got IPv6")),
    }
}

/// Get local IPv6 address for the interface that would route to target
fn get_local_ip_v6(target: Ipv6Addr) -> Result<Ipv6Addr> {
    use std::net::UdpSocket;

    // Create a UDP socket and "connect" to target to determine local IP
    let socket = UdpSocket::bind("[::]:0")?;
    socket.connect(SocketAddr::new(IpAddr::V6(target), 80))?;

    match socket.local_addr()?.ip() {
        IpAddr::V6(ip) => Ok(ip),
        IpAddr::V4(_) => Err(anyhow!("Expected IPv6 address but got IPv4")),
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
    match target.ip {
        IpAddr::V4(target_ip) => scan_target_syn_ports_v4(target_ip, config).await,
        IpAddr::V6(target_ip) => scan_target_syn_ports_v6(target_ip, config).await,
    }
}

/// Scan TCP ports on a single IPv4 target using SYN scanning
async fn scan_target_syn_ports_v4(
    target_ip: Ipv4Addr,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>> {
    // Get local IP for packet construction
    let local_ip = get_local_ip(target_ip)?;

    // Determine ports to scan, filtering out excluded ports
    let ports: Vec<u16> = (config.port_range.0..=config.port_range.1)
        .filter(|&port| !crate::db::exclusions::should_exclude_port(port, &config.exclusions))
        .collect();

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

    // Send SYN packets - use specialized syn_timeout if set, otherwise fall back to general timeout
    let timeout_duration = config.syn_timeout.unwrap_or(config.timeout);
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

/// Scan TCP ports on a single IPv6 target using SYN scanning
async fn scan_target_syn_ports_v6(
    target_ip: Ipv6Addr,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>> {
    // Get local IPv6 address for packet construction
    let local_ip = get_local_ip_v6(target_ip)?;

    // Determine ports to scan, filtering out excluded ports
    let ports: Vec<u16> = (config.port_range.0..=config.port_range.1)
        .filter(|&port| !crate::db::exclusions::should_exclude_port(port, &config.exclusions))
        .collect();

    info!(
        "Starting TCP SYN scan of {} ({} ports) [IPv6]",
        target_ip,
        ports.len()
    );

    // Create raw socket for sending (IPv6)
    let send_fd = create_raw_tcp_socket_v6()?;

    // Create raw socket for receiving (IPv6)
    let recv_fd = create_raw_tcp_socket_v6()?;

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
        tcp_response_listener_v6(recv_fd, listener_target, response_tx, listener_pending).await
    });

    // Generate random source port base
    let src_port_base: u16 = rand::thread_rng().gen_range(32768..60000);

    // Send SYN packets - use specialized syn_timeout if set, otherwise fall back to general timeout
    let timeout_duration = config.syn_timeout.unwrap_or(config.timeout);
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

            send_syn_packet_v6(send_fd, local_ip, target_ip, src_port, port)
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
                debug!("TCP SYN-ACK received for port {} - OPEN [IPv6]", port);
                open_ports.insert(port);
            }
            TcpResponseType::Rst => {
                trace!("TCP RST received for port {} - CLOSED [IPv6]", port);
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
        "TCP SYN scan of {} complete: {} open ports found [IPv6]",
        target_ip,
        port_infos.len()
    );

    Ok(port_infos)
}

/// Create a raw TCP socket for IPv4 SYN scanning.
///
/// # Safety Rationale
///
/// This function uses `unsafe` blocks for three distinct system call operations:
///
/// 1. **`libc::socket(AF_INET, SOCK_RAW, IPPROTO_TCP)`** - Creates a raw TCP socket
///    - Requires root privileges or CAP_NET_RAW capability
///    - Returns a valid file descriptor on success, -1 on failure
///    - The caller is responsible for eventually closing the fd
///
/// 2. **`libc::setsockopt(..., IP_HDRINCL, ...)`** - Enables manual IP header construction
///    - Safe because we're passing a valid fd and properly-sized option value
///    - IP_HDRINCL allows us to craft custom IP+TCP headers for SYN packets
///
/// 3. **`libc::fcntl(..., O_NONBLOCK)`** - Sets socket to non-blocking mode
///    - Safe because we're operating on a valid fd with standard flags
///    - Non-blocking prevents the scanner from hanging on unresponsive targets
///
/// # Security Implications
///
/// Raw sockets can be used for network attacks (SYN floods, spoofing). This tool
/// is intended for **authorized penetration testing only**. The CAP_NET_RAW
/// requirement ensures only privileged processes can use these capabilities.
fn create_raw_tcp_socket() -> Result<i32> {
    // SAFETY: libc::socket returns -1 on error, valid fd otherwise
    // The fd will be closed when scan completes (RAII via recv thread)
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };

    if fd < 0 {
        return Err(anyhow!(
            "Failed to create raw TCP socket (requires root/CAP_NET_RAW)"
        ));
    }

    // SAFETY: Setting IP_HDRINCL with valid fd and properly-sized value
    // This allows us to construct our own IP headers for SYN packets
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

    // SAFETY: Setting O_NONBLOCK with valid fd and standard flags
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    Ok(fd)
}

/// Create a raw TCP socket for IPv6 SYN scanning.
///
/// # Safety Rationale
///
/// Similar to `create_raw_tcp_socket()` but for IPv6 addresses:
///
/// 1. **`libc::socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)`** - Creates raw IPv6 TCP socket
///    - Requires root privileges or CAP_NET_RAW capability
///    - Unlike IPv4, we do NOT set IP_HDRINCL - the kernel handles IPv6 headers
///    - We only construct and send the TCP segment
///
/// 2. **`libc::fcntl(..., O_NONBLOCK)`** - Sets socket to non-blocking mode
///
/// # Security Implications
///
/// Same as IPv4 - raw sockets require authorization and are for pentesting only.
fn create_raw_tcp_socket_v6() -> Result<i32> {
    // SAFETY: libc::socket returns -1 on error, valid fd otherwise
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_TCP) };

    if fd < 0 {
        return Err(anyhow!(
            "Failed to create raw TCP IPv6 socket (requires root/CAP_NET_RAW)"
        ));
    }

    // For IPv6 raw sockets, we don't use IP_HDRINCL - the kernel handles the IPv6 header
    // We only need to provide the TCP segment

    // SAFETY: Setting O_NONBLOCK with valid fd
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

/// Send a TCP SYN packet over IPv6
fn send_syn_packet_v6(
    fd: i32,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<()> {
    // For IPv6 raw TCP sockets, we only send the TCP segment
    // The kernel handles the IPv6 header
    let packet = build_syn_packet_v6(src_ip, dst_ip, src_port, dst_port);

    // Convert IPv6 address to in6_addr
    let dst_octets = dst_ip.octets();
    let dest_addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: dst_port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: dst_octets,
        },
        sin6_scope_id: 0,
    };

    let sent = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &dest_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };

    if sent < 0 {
        trace!(
            "Failed to send IPv6 SYN to port {}: errno={}",
            dst_port,
            unsafe { *libc::__errno_location() }
        );
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

/// Build a TCP SYN packet for IPv6 (TCP header only - kernel handles IPv6 header)
fn build_syn_packet_v6(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    // TCP header only (20 bytes) - no IP header needed for IPv6 raw sockets
    let mut packet = vec![0u8; 20];

    // Build TCP header
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut packet).unwrap();
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

    // Calculate and set TCP checksum with IPv6 pseudo-header
    let checksum = tcp_checksum_v6(src_ip, dst_ip, &packet);
    // Set checksum at bytes 16-17 of TCP header
    packet[16] = (checksum >> 8) as u8;
    packet[17] = (checksum & 0xFF) as u8;

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

/// Calculate TCP checksum with IPv6 pseudo-header
///
/// The IPv6 pseudo-header differs from IPv4:
/// - Source address: 128 bits (16 bytes)
/// - Destination address: 128 bits (16 bytes)
/// - TCP length: 32 bits (but we use 16-bit words for checksum)
/// - Zero padding: 24 bits
/// - Next header (protocol): 8 bits (TCP = 6)
fn tcp_checksum_v6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, tcp_packet: &[u8]) -> u16 {
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    let tcp_len = tcp_packet.len() as u32;

    let mut sum: u32 = 0;

    // Pseudo-header: source address (128 bits = 8 x 16-bit words)
    for chunk in src_octets.chunks(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }

    // Pseudo-header: destination address (128 bits = 8 x 16-bit words)
    for chunk in dst_octets.chunks(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }

    // Pseudo-header: TCP length (upper 16 bits)
    sum += (tcp_len >> 16) & 0xFFFF;
    // Pseudo-header: TCP length (lower 16 bits)
    sum += tcp_len & 0xFFFF;

    // Pseudo-header: next header (TCP = 6) in the low byte of a 16-bit word
    sum += 6; // TCP protocol number

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

/// Listen for TCP responses (SYN-ACK or RST) over IPv6
async fn tcp_response_listener_v6(
    fd: i32,
    target_ip: Ipv6Addr,
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
            if let Some((port, response_type)) = parse_tcp_response_v6(&buf[..len], target_ip) {
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

/// Parse a TCP response packet from IPv6
///
/// For IPv6 raw TCP sockets, the kernel provides us with the IPv6 header followed
/// by the TCP segment. The IPv6 header is 40 bytes (fixed size, no options in base header).
fn parse_tcp_response_v6(packet: &[u8], target_ip: Ipv6Addr) -> Option<(u16, TcpResponseType)> {
    // IPv6 header (40 bytes) + TCP header (20 bytes minimum)
    if packet.len() < 60 {
        return None;
    }

    // Parse IPv6 header using pnet
    let ipv6_packet = Ipv6Packet::new(packet)?;

    // Verify it's from our target
    if ipv6_packet.get_source() != target_ip {
        return None;
    }

    // Verify it's TCP (next header = 6)
    // Note: This simple check doesn't handle extension headers
    if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        // Could be an extension header - for now we skip these
        trace!(
            "IPv6 packet has next_header={:?}, expected TCP",
            ipv6_packet.get_next_header()
        );
        return None;
    }

    // Get TCP portion - IPv6 header is always 40 bytes (extension headers would need handling)
    let tcp_data = &packet[40..];
    if tcp_data.len() < 20 {
        return None;
    }

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

    #[test]
    fn test_build_syn_packet_v6() {
        let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let packet = build_syn_packet_v6(src_ip, dst_ip, 12345, 80);

        // Verify packet length (TCP header only, no IP header for IPv6 raw sockets)
        assert_eq!(packet.len(), 20);

        // Parse and verify TCP header
        let tcp_packet = TcpPacket::new(&packet).unwrap();
        assert_eq!(tcp_packet.get_source(), 12345);
        assert_eq!(tcp_packet.get_destination(), 80);
        assert!(tcp_packet.get_flags() & TcpFlags::SYN != 0);

        // Verify checksum is set (non-zero at bytes 16-17)
        let checksum = ((packet[16] as u16) << 8) | (packet[17] as u16);
        assert!(checksum != 0);
    }

    #[test]
    fn test_tcp_checksum_v6() {
        let src_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

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

        let checksum = tcp_checksum_v6(src_ip, dst_ip, &tcp);
        // Just verify it produces a non-zero value
        assert!(checksum != 0);
    }

    #[test]
    fn test_tcp_checksum_v6_with_loopback() {
        // Test with IPv6 loopback address
        let src_ip = Ipv6Addr::LOCALHOST;
        let dst_ip = Ipv6Addr::LOCALHOST;

        let mut tcp = vec![0u8; 20];
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut tcp).unwrap();
            tcp_packet.set_source(45678);
            tcp_packet.set_destination(443);
            tcp_packet.set_sequence(5000);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(32768);
        }

        let checksum = tcp_checksum_v6(src_ip, dst_ip, &tcp);
        assert!(checksum != 0);

        // Verify that the same inputs produce the same checksum (deterministic)
        let checksum2 = tcp_checksum_v6(src_ip, dst_ip, &tcp);
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_parse_tcp_response_v6_syn_ack() {
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Build a mock IPv6 + TCP SYN-ACK response packet
        let mut packet = vec![0u8; 60]; // 40 byte IPv6 header + 20 byte TCP header

        // IPv6 header (40 bytes)
        packet[0] = 0x60; // Version 6, traffic class 0
        packet[1] = 0x00;
        packet[2] = 0x00;
        packet[3] = 0x00;
        // Payload length (20 bytes for TCP)
        packet[4] = 0x00;
        packet[5] = 0x14;
        // Next header (TCP = 6)
        packet[6] = 0x06;
        // Hop limit
        packet[7] = 0x40;
        // Source address (target_ip) at bytes 8-23
        let src_octets = target_ip.octets();
        packet[8..24].copy_from_slice(&src_octets);
        // Destination address at bytes 24-39
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_octets = dst_ip.octets();
        packet[24..40].copy_from_slice(&dst_octets);

        // TCP header (at offset 40)
        // Source port (high byte, low byte) - the port we scanned
        packet[40] = 0x00;
        packet[41] = 0x50; // Port 80
        // Destination port
        packet[42] = 0x30;
        packet[43] = 0x39; // Port 12345
        // Sequence number (4 bytes)
        packet[44..48].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Acknowledgement number (4 bytes)
        packet[48..52].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Data offset (5 << 4 = 0x50) and reserved
        packet[52] = 0x50;
        // Flags: SYN + ACK = 0x12
        packet[53] = 0x12;
        // Window
        packet[54] = 0xFF;
        packet[55] = 0xFF;
        // Checksum (we don't validate it in parsing)
        packet[56] = 0x00;
        packet[57] = 0x00;
        // Urgent pointer
        packet[58] = 0x00;
        packet[59] = 0x00;

        let result = parse_tcp_response_v6(&packet, target_ip);
        assert!(result.is_some());
        let (port, response_type) = result.unwrap();
        assert_eq!(port, 80);
        assert_eq!(response_type, TcpResponseType::SynAck);
    }

    #[test]
    fn test_parse_tcp_response_v6_rst() {
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Build a mock IPv6 + TCP RST response packet
        let mut packet = vec![0u8; 60];

        // IPv6 header
        packet[0] = 0x60;
        packet[4] = 0x00;
        packet[5] = 0x14; // Payload length 20
        packet[6] = 0x06; // TCP
        packet[7] = 0x40;
        packet[8..24].copy_from_slice(&target_ip.octets());
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        packet[24..40].copy_from_slice(&dst_ip.octets());

        // TCP header - RST flag (0x04)
        packet[40] = 0x00;
        packet[41] = 0x16; // Port 22
        packet[42] = 0x30;
        packet[43] = 0x39;
        packet[52] = 0x50;
        packet[53] = 0x04; // RST flag

        let result = parse_tcp_response_v6(&packet, target_ip);
        assert!(result.is_some());
        let (port, response_type) = result.unwrap();
        assert_eq!(port, 22);
        assert_eq!(response_type, TcpResponseType::Rst);
    }

    #[test]
    fn test_parse_tcp_response_v6_wrong_source() {
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let wrong_source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);

        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[5] = 0x14;
        packet[6] = 0x06;
        packet[7] = 0x40;
        // Source is wrong_source, not target_ip
        packet[8..24].copy_from_slice(&wrong_source.octets());
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        packet[24..40].copy_from_slice(&dst_ip.octets());
        packet[52] = 0x50;
        packet[53] = 0x12; // SYN-ACK

        let result = parse_tcp_response_v6(&packet, target_ip);
        assert!(result.is_none());
    }
}
