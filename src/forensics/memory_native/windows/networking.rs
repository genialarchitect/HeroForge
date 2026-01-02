//! Windows network connection extraction from memory
//!
//! Extract active network connections from Windows memory dumps.

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::WindowsAnalyzer;
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::NetworkConnection;

/// Network connection extractor
pub struct NetworkExtractor<'a> {
    analyzer: &'a WindowsAnalyzer<'a>,
}

/// TCP connection states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
    DeleteTcb = 11,
}

impl TcpState {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Closed,
            1 => Self::Listen,
            2 => Self::SynSent,
            3 => Self::SynReceived,
            4 => Self::Established,
            5 => Self::FinWait1,
            6 => Self::FinWait2,
            7 => Self::CloseWait,
            8 => Self::Closing,
            9 => Self::LastAck,
            10 => Self::TimeWait,
            11 => Self::DeleteTcb,
            _ => Self::Closed,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECEIVED",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::DeleteTcb => "DELETE_TCB",
        }
    }
}

impl<'a> NetworkExtractor<'a> {
    /// Create new network extractor
    pub fn new(analyzer: &'a WindowsAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Extract all network connections
    pub fn extract_connections(&self) -> Result<Vec<NetworkConnection>> {
        let dump = self.analyzer.dump();
        let mut connections = Vec::new();

        // Method 1: Scan for TCP endpoint structures
        let tcp_conns = self.scan_tcp_endpoints(dump)?;
        connections.extend(tcp_conns);

        // Method 2: Scan for UDP endpoint structures
        let udp_conns = self.scan_udp_endpoints(dump)?;
        connections.extend(udp_conns);

        // Method 3: Look for TCB (Transmission Control Block) pool
        let tcb_conns = self.scan_tcb_pool(dump)?;
        connections.extend(tcb_conns);

        // Deduplicate
        connections.sort_by(|a, b| {
            (&a.protocol, a.local_port, &a.local_addr)
                .cmp(&(&b.protocol, b.local_port, &b.local_addr))
        });
        connections.dedup_by(|a, b| {
            a.protocol == b.protocol
                && a.local_port == b.local_port
                && a.local_addr == b.local_addr
                && a.remote_port == b.remote_port
        });

        Ok(connections)
    }

    /// Scan for TCP endpoint structures
    fn scan_tcp_endpoints(&self, dump: &ParsedDump) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();

        // Search for TCP endpoint pool tag "TcpE" or patterns
        // In Windows 10+, TCP endpoints are in a hash table

        // Method: Search for structures that look like TCP endpoints
        // Look for valid port numbers followed by IP addresses

        // Search for common listening ports as indicators
        let common_ports: [u16; 10] = [80, 443, 22, 21, 25, 53, 135, 139, 445, 3389];

        for port in &common_ports {
            // Search for port in network byte order
            let port_be = port.to_be_bytes();
            let pattern = [port_be[0], port_be[1]];

            let matches = dump.search_pattern(&pattern);

            for &offset in matches.iter().take(1000) {
                // Try to validate as TCP endpoint
                if let Some(conn) = self.try_parse_tcp_endpoint(dump, offset, *port) {
                    connections.push(conn);
                }
            }
        }

        Ok(connections)
    }

    /// Try to parse a potential TCP endpoint structure
    fn try_parse_tcp_endpoint(&self, dump: &ParsedDump, offset: u64, expected_port: u16) -> Option<NetworkConnection> {
        // Read surrounding data to validate structure
        let context = dump.read_bytes(offset.saturating_sub(64), 256)?;
        let port_offset = 64; // Port is at middle of our read

        // Verify port
        let port = u16::from_be_bytes([context[port_offset], context[port_offset + 1]]);
        if port != expected_port {
            return None;
        }

        // Look for IP address before or after port
        // Try to find IPv4 address (4 bytes that look like valid IP)
        for ip_offset in [port_offset + 2, port_offset - 4, port_offset + 4, port_offset - 6].iter() {
            if *ip_offset + 4 <= context.len() {
                let ip_bytes = [
                    context[*ip_offset],
                    context[*ip_offset + 1],
                    context[*ip_offset + 2],
                    context[*ip_offset + 3],
                ];

                let ip = Ipv4Addr::from(ip_bytes);

                // Skip obviously invalid IPs
                if ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] == 0 {
                    continue;
                }

                // Check for state indicator nearby
                let state = TcpState::Listen; // Default to LISTEN for common ports

                return Some(NetworkConnection {
                    pid: 0, // Would need process association
                    protocol: "TCP".to_string(),
                    local_addr: ip.to_string(),
                    local_port: port,
                    remote_addr: None,
                    remote_port: None,
                    state: state.as_str().to_string(),
                    create_time: None,
                });
            }
        }

        None
    }

    /// Scan for UDP endpoint structures
    fn scan_udp_endpoints(&self, dump: &ParsedDump) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();

        // UDP endpoints are simpler - just local address/port
        // Search for "UdpA" pool tag or UDP-specific patterns

        let udp_tag = b"UdpA";
        let matches = dump.search_pattern(udp_tag);

        for &offset in matches.iter().take(1000) {
            if let Some(conn) = self.try_parse_udp_endpoint(dump, offset) {
                connections.push(conn);
            }
        }

        Ok(connections)
    }

    /// Try to parse a UDP endpoint
    fn try_parse_udp_endpoint(&self, dump: &ParsedDump, offset: u64) -> Option<NetworkConnection> {
        // UDP_ENDPOINT structure parsing
        // This is version-specific

        let data = dump.read_bytes(offset, 0x80)?;

        // Basic validation - look for reasonable port and IP
        // Structure layout varies by Windows version

        // Placeholder - would need proper structure parsing
        if data.len() < 0x40 {
            return None;
        }

        // Look for port in various offsets
        for port_offset in [0x20, 0x28, 0x30, 0x38].iter() {
            if *port_offset + 2 <= data.len() {
                let port = u16::from_le_bytes([data[*port_offset], data[*port_offset + 1]]);

                if port > 0 && port < 65535 {
                    return Some(NetworkConnection {
                        pid: 0,
                        protocol: "UDP".to_string(),
                        local_addr: "0.0.0.0".to_string(),
                        local_port: port,
                        remote_addr: None,
                        remote_port: None,
                        state: "*".to_string(),
                        create_time: None,
                    });
                }
            }
        }

        None
    }

    /// Scan TCB pool for connections
    fn scan_tcb_pool(&self, dump: &ParsedDump) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();

        // Search for TCB pool tag
        let tcb_tags = [b"TcpT", b"TCPT"];

        for tag in &tcb_tags {
            let matches = dump.search_pattern(*tag);

            for &offset in matches.iter().take(1000) {
                if let Some(conn) = self.try_parse_tcb(dump, offset) {
                    connections.push(conn);
                }
            }
        }

        Ok(connections)
    }

    /// Try to parse a TCB (Transmission Control Block)
    fn try_parse_tcb(&self, dump: &ParsedDump, offset: u64) -> Option<NetworkConnection> {
        let data = dump.read_bytes(offset, 0x200)?;

        // TCB contains full connection information
        // Structure varies by Windows version

        // Look for connection state pattern
        for i in (0..0x100).step_by(4) {
            let state = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);

            if (1..=11).contains(&state) {
                // Found potential state field
                // Look for addresses and ports nearby

                // Try to find local/remote addresses
                if i + 0x20 <= data.len() {
                    // Attempt to extract connection info
                    let local_port = u16::from_be_bytes([data[i + 8], data[i + 9]]);
                    let remote_port = u16::from_be_bytes([data[i + 10], data[i + 11]]);

                    if local_port > 0 && local_port < 65535 {
                        let local_ip = Ipv4Addr::new(
                            data[i + 12], data[i + 13], data[i + 14], data[i + 15]
                        );
                        let remote_ip = Ipv4Addr::new(
                            data[i + 16], data[i + 17], data[i + 18], data[i + 19]
                        );

                        return Some(NetworkConnection {
                            pid: 0,
                            protocol: "TCP".to_string(),
                            local_addr: local_ip.to_string(),
                            local_port,
                            remote_addr: if remote_ip.is_unspecified() {
                                None
                            } else {
                                Some(remote_ip.to_string())
                            },
                            remote_port: if remote_port == 0 { None } else { Some(remote_port) },
                            state: TcpState::from_u32(state).as_str().to_string(),
                            create_time: None,
                        });
                    }
                }
            }
        }

        None
    }
}

/// Find suspicious network connections
pub fn find_suspicious_connections(connections: &[NetworkConnection]) -> Vec<&NetworkConnection> {
    let mut suspicious = Vec::new();

    // Known malicious ports
    let suspicious_ports: [u16; 20] = [
        4444, 5555, 6666, 7777,  // Common RAT ports
        1337, 31337,              // "Elite" ports
        8080, 8888,               // Common C2 ports
        12345, 54321,             // Common backdoor ports
        666, 999,                 // Doom, etc
        1234, 4321,
        9999, 10000,
        20000, 30000,
        6667, 6697,              // IRC (common for botnets)
    ];

    // Known bad destination ranges (simplified)
    let tor_exit_pattern = |ip: &str| {
        ip.starts_with("185.") || ip.starts_with("193.") || ip.starts_with("45.")
    };

    for conn in connections {
        let is_suspicious =
            // Suspicious local port
            suspicious_ports.contains(&conn.local_port) ||
            // Suspicious remote port
            conn.remote_port.map(|p| suspicious_ports.contains(&p)).unwrap_or(false) ||
            // Connection to known suspicious ranges
            conn.remote_addr.as_ref().map(|ip| tor_exit_pattern(ip)).unwrap_or(false) ||
            // Established connection on unusual port
            (conn.state == "ESTABLISHED" && conn.remote_port.map(|p| p > 49152).unwrap_or(false));

        if is_suspicious {
            suspicious.push(conn);
        }
    }

    suspicious
}

/// Parse IPv6 address from bytes
#[allow(dead_code)]
fn parse_ipv6(bytes: &[u8]) -> Option<IpAddr> {
    if bytes.len() < 16 {
        return None;
    }

    let addr = Ipv6Addr::new(
        u16::from_be_bytes([bytes[0], bytes[1]]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u16::from_be_bytes([bytes[10], bytes[11]]),
        u16::from_be_bytes([bytes[12], bytes[13]]),
        u16::from_be_bytes([bytes[14], bytes[15]]),
    );

    Some(IpAddr::V6(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state() {
        assert_eq!(TcpState::from_u32(1).as_str(), "LISTEN");
        assert_eq!(TcpState::from_u32(4).as_str(), "ESTABLISHED");
        assert_eq!(TcpState::from_u32(10).as_str(), "TIME_WAIT");
    }
}
