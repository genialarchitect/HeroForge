#![allow(dead_code)]

//! UDP port scanner with ICMP detection
//!
//! This module implements UDP port scanning using raw sockets to detect
//! ICMP "port unreachable" responses, allowing accurate distinction between
//! open, closed, and filtered ports.
//!
//! **Requires root privileges or CAP_NET_RAW capability.**

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use log::{debug, info, trace, warn};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

/// ICMPv6 type for Destination Unreachable
const ICMPV6_DEST_UNREACHABLE: u8 = 1;
/// ICMPv6 code for Port Unreachable
const ICMPV6_PORT_UNREACHABLE: u8 = 4;
/// ICMPv6 header length (type + code + checksum + unused)
const ICMPV6_HEADER_LEN: usize = 8;
/// IPv6 header length (fixed at 40 bytes)
const IPV6_HEADER_LEN: usize = 40;
/// ICMPv6 protocol number
const IPPROTO_ICMPV6: i32 = 58;

use crate::scanner::udp_probes::{get_udp_probe, get_udp_service_name, DEFAULT_UDP_PORTS};
use crate::scanner::udp_service_detection;
use crate::types::{PortInfo, PortState, Protocol as ScanProtocol, ScanConfig, ScanTarget};

/// Default number of concurrent UDP probes (lower than TCP due to ICMP rate limiting)
const UDP_DEFAULT_THREADS: usize = 50;

/// Default timeout for UDP probes (longer than TCP)
const UDP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default number of retries for UDP probes
const UDP_DEFAULT_RETRIES: u8 = 2;

/// Delay between retries (milliseconds)
const RETRY_DELAY_MS: u64 = 100;

/// Result of a UDP port scan
#[derive(Debug, Clone)]
pub struct UdpScanResult {
    pub port: u16,
    pub state: PortState,
    pub response_data: Option<Vec<u8>>,
    pub response_time: Option<Duration>,
}

/// Check if we have raw socket capability for ICMP detection.
///
/// # Safety Rationale
///
/// Uses `unsafe` to call `libc::socket()` and `libc::close()`:
/// - Tests if the process can create raw ICMP sockets (requires root/CAP_NET_RAW)
/// - Immediately closes the test socket if successful
/// - No resources are leaked; fd is properly closed on success
///
/// # Security Implications
///
/// Raw ICMP sockets are used to detect "port unreachable" responses during UDP
/// scanning. This capability check ensures the scanner fails gracefully if run
/// without proper authorization rather than producing incomplete results.
pub fn has_raw_socket_capability() -> bool {
    // SAFETY: socket() returns -1 on error, valid fd otherwise
    // We close immediately after testing - no resource leak
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
        if fd >= 0 {
            libc::close(fd);
            true
        } else {
            debug!("Raw socket capability check failed: errno={}", *libc::__errno_location());
            false
        }
    }
}

/// Scan multiple targets for open UDP ports
pub async fn scan_udp_ports(
    config: &ScanConfig,
) -> Result<HashMap<IpAddr, Vec<PortInfo>>> {
    // Check privileges first
    if !has_raw_socket_capability() {
        return Err(anyhow!(
            "UDP scanning requires root privileges or CAP_NET_RAW capability.\n\
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
                match scan_target_udp_ports(&target, config).await {
                    Ok(ports) => {
                        results.insert(ip, ports);
                    }
                    Err(e) => {
                        warn!("Failed to scan UDP ports on {}: {}", ip, e);
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
                        match scan_target_udp_ports(&target, config).await {
                            Ok(ports) => {
                                results.insert(addr.ip(), ports);
                            }
                            Err(e) => {
                                warn!("Failed to scan UDP ports on {}: {}", addr.ip(), e);
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

/// Scan UDP ports on a single target
pub async fn scan_target_udp_ports(
    target: &ScanTarget,
    config: &ScanConfig,
) -> Result<Vec<PortInfo>> {
    let ip = target.ip;

    // Determine ports to scan, filtering out excluded ports
    let ports: Vec<u16> = if let Some((start, end)) = config.udp_port_range {
        (start..=end)
            .filter(|&port| !crate::db::exclusions::should_exclude_port(port, &config.exclusions))
            .collect()
    } else if config.port_range == (1, 1000) {
        // Use default UDP ports if using default TCP range
        DEFAULT_UDP_PORTS
            .iter()
            .copied()
            .filter(|&port| !crate::db::exclusions::should_exclude_port(port, &config.exclusions))
            .collect()
    } else {
        (config.port_range.0..=config.port_range.1)
            .filter(|&port| !crate::db::exclusions::should_exclude_port(port, &config.exclusions))
            .collect()
    };

    info!(
        "Starting UDP scan of {} ({} ports)",
        ip,
        ports.len()
    );

    // Set up concurrency control
    let threads = std::cmp::min(config.threads, UDP_DEFAULT_THREADS);
    let semaphore = Arc::new(Semaphore::new(threads));

    // Channel for ICMP "port unreachable" notifications
    let (icmp_tx, mut icmp_rx) = mpsc::channel::<u16>(1000);

    // Start ICMP listener in background
    let icmp_target = ip;
    let icmp_handle = tokio::spawn(async move {
        if let Err(e) = icmp_listener(icmp_target, icmp_tx).await {
            warn!("ICMP listener error: {}", e);
        }
    });

    // Track closed ports from ICMP
    let closed_ports = Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()));
    let closed_ports_writer = closed_ports.clone();

    // Background task to collect ICMP responses
    let icmp_collector = tokio::spawn(async move {
        while let Some(port) = icmp_rx.recv().await {
            closed_ports_writer.write().await.insert(port);
        }
    });

    // Spawn probe tasks - use specialized udp_timeout if set, otherwise fall back to general timeout
    let timeout_duration = config.udp_timeout.unwrap_or(config.timeout);
    let retries = config.udp_retries;
    let mut tasks = Vec::new();

    for port in ports {
        let sem = semaphore.clone();
        let target_ip = ip;

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_udp_port_with_retry(target_ip, port, timeout_duration, retries).await
        });
        tasks.push((port, task));
    }

    // Collect results
    let mut scan_results = Vec::new();
    for (port, task) in tasks {
        match task.await {
            Ok(result) => {
                scan_results.push(result);
            }
            Err(e) => {
                warn!("UDP scan task for port {} failed: {}", port, e);
            }
        }
    }

    // Wait a bit for any remaining ICMP responses
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Stop ICMP listener
    icmp_handle.abort();
    drop(icmp_collector);

    // Update states based on ICMP responses
    let closed_set = closed_ports.read().await;

    let mut port_infos: Vec<PortInfo> = scan_results
        .into_iter()
        .map(|result| {
            let state = if closed_set.contains(&result.port) {
                PortState::Closed
            } else {
                result.state
            };

            // Only return open or open|filtered ports (skip closed)
            let service = if state == PortState::Open {
                // Try to detect service from response
                result
                    .response_data
                    .as_ref()
                    .and_then(|data| udp_service_detection::detect_udp_service(result.port, data))
                    .or_else(|| {
                        Some(crate::types::ServiceInfo {
                            name: get_udp_service_name(result.port).to_string(),
                            version: None,
                            banner: None,
                            cpe: None,
                            enumeration: None,
                            ssl_info: None,
                        })
                    })
            } else {
                Some(crate::types::ServiceInfo {
                    name: get_udp_service_name(result.port).to_string(),
                    version: None,
                    banner: None,
                    cpe: None,
                    enumeration: None,
                    ssl_info: None,
                })
            };

            PortInfo {
                port: result.port,
                protocol: ScanProtocol::UDP,
                state,
                service,
            }
        })
        .filter(|p| p.state != PortState::Closed) // Filter out closed ports
        .collect();

    port_infos.sort_by_key(|p| p.port);

    info!(
        "UDP scan of {} complete: {} open/filtered ports",
        ip,
        port_infos.len()
    );

    Ok(port_infos)
}

/// Scan a single UDP port with retries
async fn scan_udp_port_with_retry(
    target: IpAddr,
    port: u16,
    timeout_duration: Duration,
    retries: u8,
) -> UdpScanResult {
    for attempt in 0..=retries {
        let result = scan_udp_port(target, port, timeout_duration).await;

        // If we got a definitive response, return it
        if result.state == PortState::Open {
            return result;
        }

        // If not the last attempt, wait before retrying
        if attempt < retries {
            tokio::time::sleep(Duration::from_millis(
                RETRY_DELAY_MS * (1 << attempt), // Exponential backoff
            ))
            .await;
        }
    }

    // After all retries, return Open|Filtered
    UdpScanResult {
        port,
        state: PortState::OpenFiltered,
        response_data: None,
        response_time: None,
    }
}

/// Scan a single UDP port
async fn scan_udp_port(target: IpAddr, port: u16, timeout_duration: Duration) -> UdpScanResult {
    let probe = get_udp_probe(port);
    let start = std::time::Instant::now();

    // Bind to any available port (use appropriate address family for target)
    let bind_addr = match target {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            trace!("Failed to bind UDP socket: {}", e);
            return UdpScanResult {
                port,
                state: PortState::OpenFiltered,
                response_data: None,
                response_time: None,
            };
        }
    };

    let target_addr = SocketAddr::new(target, port);

    // Send probe
    if let Err(e) = socket.send_to(&probe, target_addr).await {
        trace!("Failed to send UDP probe to {}:{}: {}", target, port, e);
        return UdpScanResult {
            port,
            state: PortState::OpenFiltered,
            response_data: None,
            response_time: None,
        };
    }

    // Wait for response
    let mut buf = vec![0u8; 65535];
    match timeout(timeout_duration, socket.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => {
            // Got a response - port is open
            let elapsed = start.elapsed();
            debug!("UDP port {} open - received {} bytes", port, len);
            UdpScanResult {
                port,
                state: PortState::Open,
                response_data: Some(buf[..len].to_vec()),
                response_time: Some(elapsed),
            }
        }
        Ok(Err(e)) => {
            // Socket error - likely ICMP unreachable (will be caught by ICMP listener)
            trace!("UDP recv error on port {}: {}", port, e);
            UdpScanResult {
                port,
                state: PortState::OpenFiltered,
                response_data: None,
                response_time: None,
            }
        }
        Err(_) => {
            // Timeout - port is open|filtered (no response doesn't mean closed for UDP)
            trace!("UDP timeout on port {}", port);
            UdpScanResult {
                port,
                state: PortState::OpenFiltered,
                response_data: None,
                response_time: None,
            }
        }
    }
}

/// Listen for ICMP "port unreachable" messages
async fn icmp_listener(target: IpAddr, tx: mpsc::Sender<u16>) -> Result<()> {
    match target {
        IpAddr::V4(ip) => icmp_listener_v4(ip, tx).await,
        IpAddr::V6(ip) => icmp_listener_v6(ip, tx).await,
    }
}

/// Listen for ICMPv4 "port unreachable" messages.
///
/// # Safety Rationale
///
/// Uses multiple `unsafe` blocks for raw socket operations:
///
/// 1. **`libc::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`** - Creates raw ICMP socket
///    - Required to receive ICMP "port unreachable" responses from the target
///    - Returns valid fd on success, -1 on failure
///
/// 2. **`libc::fcntl(..., O_NONBLOCK)`** - Sets non-blocking mode
///    - Prevents the listener from blocking indefinitely
///    - Allows proper timeout handling with tokio
///
/// 3. **`std::net::UdpSocket::from_raw_fd(fd)`** - Transfers fd ownership
///    - The fd is now owned by the UdpSocket which will close it on drop
///    - We use UdpSocket as a handle since it implements AsyncFd traits
///    - Note: This is a raw ICMP socket wrapped in UdpSocket for async support
///
/// # Resource Management
///
/// The raw fd is converted to a std UdpSocket, then a tokio UdpSocket.
/// When the async_socket goes out of scope (when the loop exits), the fd is
/// automatically closed via the UdpSocket's Drop implementation.
async fn icmp_listener_v4(target_ip: Ipv4Addr, tx: mpsc::Sender<u16>) -> Result<()> {
    // SAFETY: socket() returns -1 on error, valid fd on success
    // fd ownership is transferred to std_socket below
    let fd = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
    };

    if fd < 0 {
        return Err(anyhow!("Failed to create raw ICMP socket (requires root/CAP_NET_RAW)"));
    }

    // SAFETY: Setting O_NONBLOCK on a valid fd
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // SAFETY: from_raw_fd takes ownership of fd - it will be closed on drop
    // We're using UdpSocket as a generic async socket wrapper for the raw ICMP fd
    use std::os::unix::io::FromRawFd;
    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let async_socket = tokio::net::UdpSocket::from_std(std_socket)?;

    let mut buf = vec![0u8; 65535];

    loop {
        // Check if channel is closed
        if tx.is_closed() {
            break;
        }

        match timeout(Duration::from_millis(100), async_socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                if let Some(port) = parse_icmp_unreachable(&buf[..len], target_ip) {
                    debug!("ICMP port unreachable for UDP port {}", port);
                    let _ = tx.send(port).await;
                }
            }
            Ok(Err(_)) | Err(_) => {
                // Timeout or error, continue listening
                continue;
            }
        }
    }

    Ok(())
}

/// Listen for ICMPv6 "port unreachable" messages.
///
/// # Safety Rationale
///
/// Same pattern as `icmp_listener_v4` but for IPv6:
///
/// 1. **`libc::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)`** - Creates raw ICMPv6 socket
/// 2. **`libc::fcntl(..., O_NONBLOCK)`** - Non-blocking mode for async compatibility
/// 3. **`std::net::UdpSocket::from_raw_fd(fd)`** - Transfers fd ownership to RAII wrapper
///
/// See `icmp_listener_v4` documentation for detailed safety rationale.
async fn icmp_listener_v6(target_ip: Ipv6Addr, tx: mpsc::Sender<u16>) -> Result<()> {
    // SAFETY: socket() returns -1 on error, valid fd on success
    let fd = unsafe {
        libc::socket(libc::AF_INET6, libc::SOCK_RAW, IPPROTO_ICMPV6)
    };

    if fd < 0 {
        // SAFETY: __errno_location() is thread-local, safe to access
        let errno = unsafe { *libc::__errno_location() };
        return Err(anyhow!(
            "Failed to create raw ICMPv6 socket (requires root/CAP_NET_RAW): errno={}",
            errno
        ));
    }

    // SAFETY: Setting O_NONBLOCK on a valid fd
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // SAFETY: from_raw_fd takes ownership of fd - it will be closed on drop
    use std::os::unix::io::FromRawFd;
    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    let async_socket = tokio::net::UdpSocket::from_std(std_socket)?;

    let mut buf = vec![0u8; 65535];

    loop {
        // Check if channel is closed
        if tx.is_closed() {
            break;
        }

        match timeout(Duration::from_millis(100), async_socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                if let Some(port) = parse_icmpv6_unreachable(&buf[..len], target_ip) {
                    debug!("ICMPv6 port unreachable for UDP port {}", port);
                    let _ = tx.send(port).await;
                }
            }
            Ok(Err(_)) | Err(_) => {
                // Timeout or error, continue listening
                continue;
            }
        }
    }

    Ok(())
}

/// Parse ICMP packet to extract destination port from embedded UDP header
fn parse_icmp_unreachable(packet: &[u8], target_ip: Ipv4Addr) -> Option<u16> {
    // IP header is typically 20 bytes, but check IHL
    if packet.len() < 20 {
        return None;
    }

    // Parse outer IP header
    let ip_packet = Ipv4Packet::new(packet)?;

    // Check if it's from our target (the ICMP comes from the target)
    if ip_packet.get_source() != target_ip {
        return None;
    }

    // Get ICMP payload (skip IP header)
    let ip_header_len = (ip_packet.get_header_length() as usize) * 4;
    if packet.len() < ip_header_len + 8 {
        return None;
    }

    let icmp_data = &packet[ip_header_len..];
    let icmp_packet = IcmpPacket::new(icmp_data)?;

    // Check for "Destination Unreachable" (type 3)
    if icmp_packet.get_icmp_type() != IcmpTypes::DestinationUnreachable {
        return None;
    }

    // Code 3 = Port Unreachable
    if icmp_packet.get_icmp_code().0 != 3 {
        return None;
    }

    // ICMP payload contains original IP header + first 8 bytes of UDP header
    // ICMP header is 8 bytes, then comes the original packet
    if icmp_data.len() < 8 + 20 + 8 {
        return None;
    }

    let original_packet = &icmp_data[8..];

    // Parse the original IP packet
    let original_ip = Ipv4Packet::new(original_packet)?;
    let original_ip_header_len = (original_ip.get_header_length() as usize) * 4;

    if original_packet.len() < original_ip_header_len + 4 {
        return None;
    }

    // Get UDP destination port from original packet
    let udp_data = &original_packet[original_ip_header_len..];
    let udp_packet = UdpPacket::new(udp_data)?;

    Some(udp_packet.get_destination())
}

/// Parse ICMPv6 packet to extract destination port from embedded UDP header
///
/// ICMPv6 Destination Unreachable packet structure:
/// - Type (1 byte): 1 = Destination Unreachable
/// - Code (1 byte): 4 = Port Unreachable
/// - Checksum (2 bytes)
/// - Unused (4 bytes)
/// - Original IPv6 header (40 bytes) + as much of the original packet as possible
/// - Original UDP header starts at offset 48 from start of ICMPv6 payload
///
/// Note: For raw ICMPv6 sockets on Linux, the kernel strips the outer IPv6 header,
/// so we receive the ICMPv6 message starting from the type field.
fn parse_icmpv6_unreachable(packet: &[u8], target_ip: Ipv6Addr) -> Option<u16> {
    // Minimum packet size: ICMPv6 header (8) + IPv6 header (40) + UDP ports (4)
    if packet.len() < ICMPV6_HEADER_LEN + IPV6_HEADER_LEN + 4 {
        trace!(
            "ICMPv6 packet too short: {} bytes (need at least {})",
            packet.len(),
            ICMPV6_HEADER_LEN + IPV6_HEADER_LEN + 4
        );
        return None;
    }

    // Check ICMPv6 type (Destination Unreachable = 1)
    let icmpv6_type = packet[0];
    if icmpv6_type != ICMPV6_DEST_UNREACHABLE {
        trace!("ICMPv6 type {} is not Destination Unreachable (1)", icmpv6_type);
        return None;
    }

    // Check ICMPv6 code (Port Unreachable = 4)
    let icmpv6_code = packet[1];
    if icmpv6_code != ICMPV6_PORT_UNREACHABLE {
        trace!("ICMPv6 code {} is not Port Unreachable (4)", icmpv6_code);
        return None;
    }

    // Skip ICMPv6 header (8 bytes) to get to the original IPv6 packet
    let original_ipv6 = &packet[ICMPV6_HEADER_LEN..];

    // Verify we have enough data for the IPv6 header
    if original_ipv6.len() < IPV6_HEADER_LEN + 4 {
        trace!("Original IPv6 packet in ICMPv6 too short");
        return None;
    }

    // Extract source address from original IPv6 header (bytes 8-23)
    // This should match our scanner's source address, but more importantly
    // the destination in the original packet should be our target
    let mut dest_addr_bytes = [0u8; 16];
    dest_addr_bytes.copy_from_slice(&original_ipv6[24..40]);
    let original_dest = Ipv6Addr::from(dest_addr_bytes);

    // The destination of the original packet should be our target
    if original_dest != target_ip {
        trace!(
            "ICMPv6 original dest {} doesn't match target {}",
            original_dest,
            target_ip
        );
        return None;
    }

    // Check Next Header field to verify it's UDP (17)
    let next_header = original_ipv6[6];
    if next_header != 17 {
        // 17 = UDP
        trace!("Original packet next header {} is not UDP (17)", next_header);
        return None;
    }

    // Get UDP header (starts right after IPv6 header for packets without extension headers)
    let udp_data = &original_ipv6[IPV6_HEADER_LEN..];

    // Extract destination port from UDP header (bytes 2-3)
    if udp_data.len() < 4 {
        return None;
    }

    let dest_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
    Some(dest_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_raw_socket_capability() {
        // This will fail in unprivileged tests, which is expected
        let has_cap = has_raw_socket_capability();
        println!("Raw socket capability: {}", has_cap);
        // Don't assert - just verify it doesn't panic
    }

    #[test]
    fn test_default_udp_ports() {
        assert!(!DEFAULT_UDP_PORTS.is_empty());
        assert!(DEFAULT_UDP_PORTS.contains(&53)); // DNS
        assert!(DEFAULT_UDP_PORTS.contains(&161)); // SNMP
    }

    #[test]
    fn test_parse_icmpv6_unreachable() {
        // Create a mock ICMPv6 Destination Unreachable (Port Unreachable) packet
        // ICMPv6 header: type=1, code=4, checksum=0x0000, unused=0x00000000
        // Followed by original IPv6 header and UDP header
        let target_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();

        let mut packet = vec![0u8; ICMPV6_HEADER_LEN + IPV6_HEADER_LEN + 8];

        // ICMPv6 header
        packet[0] = ICMPV6_DEST_UNREACHABLE; // Type = 1
        packet[1] = ICMPV6_PORT_UNREACHABLE; // Code = 4
        // Checksum and unused are zeros

        // Original IPv6 header (starts at offset 8)
        let ipv6_start = ICMPV6_HEADER_LEN;
        packet[ipv6_start] = 0x60; // Version 6, Traffic Class (high nibble)
        packet[ipv6_start + 6] = 17; // Next Header = UDP (17)
        packet[ipv6_start + 7] = 64; // Hop Limit

        // Source address (bytes 8-23 of IPv6 header): ::1 (our scanner)
        packet[ipv6_start + 23] = 1;

        // Destination address (bytes 24-39 of IPv6 header): target_ip
        let dest_bytes = target_ip.octets();
        packet[ipv6_start + 24..ipv6_start + 40].copy_from_slice(&dest_bytes);

        // Original UDP header (starts at offset 8 + 40 = 48)
        let udp_start = ICMPV6_HEADER_LEN + IPV6_HEADER_LEN;
        // Source port: 12345
        packet[udp_start] = 0x30;
        packet[udp_start + 1] = 0x39;
        // Destination port: 53 (DNS)
        packet[udp_start + 2] = 0x00;
        packet[udp_start + 3] = 0x35;

        // Test parsing
        let result = parse_icmpv6_unreachable(&packet, target_ip);
        assert_eq!(result, Some(53));

        // Test with wrong target
        let wrong_target: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let result = parse_icmpv6_unreachable(&packet, wrong_target);
        assert_eq!(result, None);

        // Test with wrong ICMPv6 type
        let mut wrong_type_packet = packet.clone();
        wrong_type_packet[0] = 128; // Echo Request
        let result = parse_icmpv6_unreachable(&wrong_type_packet, target_ip);
        assert_eq!(result, None);

        // Test with wrong ICMPv6 code
        let mut wrong_code_packet = packet.clone();
        wrong_code_packet[1] = 0; // No route to destination
        let result = parse_icmpv6_unreachable(&wrong_code_packet, target_ip);
        assert_eq!(result, None);

        // Test with packet too short
        let short_packet = vec![0u8; 10];
        let result = parse_icmpv6_unreachable(&short_packet, target_ip);
        assert_eq!(result, None);
    }

    #[test]
    fn test_icmpv6_constants() {
        // Verify constants match RFC 4443
        assert_eq!(ICMPV6_DEST_UNREACHABLE, 1);
        assert_eq!(ICMPV6_PORT_UNREACHABLE, 4);
        assert_eq!(ICMPV6_HEADER_LEN, 8);
        assert_eq!(IPV6_HEADER_LEN, 40);
        assert_eq!(IPPROTO_ICMPV6, 58);
    }
}
