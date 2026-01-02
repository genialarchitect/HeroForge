//! Linux network connection extraction from memory
//!
//! Extract active network connections from Linux memory dumps.

use anyhow::Result;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::LinuxAnalyzer;
use crate::forensics::memory_native::dump_parser::ParsedDump;
use crate::forensics::memory_native::types::NetworkConnection;

/// Network extractor for Linux memory
pub struct NetworkExtractor<'a> {
    analyzer: &'a LinuxAnalyzer<'a>,
}

/// TCP socket states (from Linux kernel)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    NewSynRecv = 12,
}

impl TcpState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            12 => Self::NewSynRecv,
            _ => Self::Close,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Established => "ESTABLISHED",
            Self::SynSent => "SYN_SENT",
            Self::SynRecv => "SYN_RECV",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::TimeWait => "TIME_WAIT",
            Self::Close => "CLOSE",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::Listen => "LISTEN",
            Self::Closing => "CLOSING",
            Self::NewSynRecv => "NEW_SYN_RECV",
        }
    }
}

impl<'a> NetworkExtractor<'a> {
    /// Create new network extractor
    pub fn new(analyzer: &'a LinuxAnalyzer<'a>) -> Self {
        Self { analyzer }
    }

    /// Extract all network connections
    pub fn extract_connections(&self) -> Result<Vec<NetworkConnection>> {
        let dump = self.analyzer.dump();
        let mut connections = Vec::new();

        // Method 1: Find and parse tcp_hashinfo
        if let Some(kallsyms) = &self.analyzer.kallsyms {
            if let Some(&tcp_hashinfo_addr) = kallsyms.symbols.get("tcp_hashinfo") {
                let tcp_conns = self.parse_tcp_hashinfo(dump, tcp_hashinfo_addr)?;
                connections.extend(tcp_conns);
            }
        }

        // Method 2: Scan for socket structures
        let scanned = self.scan_for_sockets(dump)?;
        connections.extend(scanned);

        // Deduplicate
        connections.sort_by(|a, b| {
            (&a.protocol, a.local_port).cmp(&(&b.protocol, b.local_port))
        });
        connections.dedup_by(|a, b| {
            a.protocol == b.protocol &&
            a.local_port == b.local_port &&
            a.local_addr == b.local_addr &&
            a.remote_port == b.remote_port
        });

        Ok(connections)
    }

    /// Parse tcp_hashinfo structure
    fn parse_tcp_hashinfo(&self, dump: &ParsedDump, hashinfo_addr: u64) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();

        // inet_hashinfo structure contains hash tables for connections
        // ehash (established), bhash (bind), lhash (listen)

        // Read ehash pointer and size
        let hashinfo = dump.read_physical(hashinfo_addr, 0x100)
            .ok_or_else(|| anyhow::anyhow!("Failed to read tcp_hashinfo"))?;

        // ehash is typically at offset 0 or 0x08
        let _ehash = u64::from_le_bytes([
            hashinfo[0], hashinfo[1], hashinfo[2], hashinfo[3],
            hashinfo[4], hashinfo[5], hashinfo[6], hashinfo[7],
        ]);

        // Would walk hash buckets to find sock structures
        // This requires knowing the exact kernel version's layout

        Ok(connections)
    }

    /// Scan for socket structures in memory
    fn scan_for_sockets(&self, dump: &ParsedDump) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();

        // Search for patterns that indicate socket structures
        // Common ports in network byte order

        let common_ports: [(u16, &str); 10] = [
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (21, "FTP"),
            (25, "SMTP"),
            (53, "DNS"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (27017, "MongoDB"),
        ];

        for (port, _) in &common_ports {
            // Search for port in both byte orders
            let port_be = port.to_be_bytes();
            let matches = dump.search_pattern(&port_be);

            for &offset in matches.iter().take(1000) {
                if let Some(conn) = self.try_parse_inet_sock(dump, offset, *port) {
                    connections.push(conn);
                }
            }
        }

        Ok(connections)
    }

    /// Try to parse an inet_sock structure
    fn try_parse_inet_sock(&self, dump: &ParsedDump, offset: u64, expected_port: u16) -> Option<NetworkConnection> {
        // inet_sock contains:
        // - sock common fields
        // - inet_saddr (local address)
        // - inet_daddr (remote address)
        // - inet_sport (source port)
        // - inet_dport (destination port)
        // - inet_num (local port number)

        // Read surrounding context
        let context = dump.read_bytes(offset.saturating_sub(128), 512)?;
        let port_offset = 128;

        // Verify port
        let port = u16::from_be_bytes([context[port_offset], context[port_offset + 1]]);
        if port != expected_port {
            return None;
        }

        // Look for IP addresses nearby
        // IPv4 addresses should appear as 4-byte sequences

        // Try different socket structure layouts
        for addr_offset in [port_offset + 4, port_offset - 4, port_offset + 8, port_offset - 8].iter() {
            if *addr_offset + 4 <= context.len() {
                let addr = Ipv4Addr::new(
                    context[*addr_offset],
                    context[*addr_offset + 1],
                    context[*addr_offset + 2],
                    context[*addr_offset + 3],
                );

                // Skip obviously invalid addresses
                if addr.is_unspecified() && context[port_offset + 2..].starts_with(&[0, 0]) {
                    continue;
                }

                // Found potential connection
                return Some(NetworkConnection {
                    pid: 0, // Would need to find owning task
                    protocol: "TCP".to_string(),
                    local_addr: addr.to_string(),
                    local_port: port,
                    remote_addr: None,
                    remote_port: None,
                    state: "UNKNOWN".to_string(),
                    create_time: None,
                });
            }
        }

        None
    }

    /// Extract Unix domain sockets
    pub fn extract_unix_sockets(&self) -> Result<Vec<UnixSocketInfo>> {
        let dump = self.analyzer.dump();
        let mut sockets = Vec::new();

        // Search for unix_sock structures
        // Unix sockets have a path in their address

        // Common socket paths
        let socket_paths: &[&[u8]] = &[
            b"/var/run/",
            b"/tmp/",
            b"/run/",
            b"@/tmp/",
        ];

        for path in socket_paths {
            let matches = dump.search_pattern(path);

            for &offset in matches.iter().take(100) {
                if let Some(sock) = self.try_parse_unix_socket(dump, offset) {
                    sockets.push(sock);
                }
            }
        }

        Ok(sockets)
    }

    /// Try to parse a Unix socket
    fn try_parse_unix_socket(&self, dump: &ParsedDump, offset: u64) -> Option<UnixSocketInfo> {
        // Read the path
        let path_bytes = dump.read_bytes(offset, 108)?; // UNIX_PATH_MAX
        let end = path_bytes.iter().position(|&b| b == 0).unwrap_or(108);

        let path = String::from_utf8_lossy(&path_bytes[..end]).to_string();

        if path.is_empty() {
            return None;
        }

        Some(UnixSocketInfo {
            path,
            socket_type: "STREAM".to_string(),
            state: "CONNECTED".to_string(),
            inode: 0,
            peer_inode: None,
        })
    }
}

/// Unix domain socket information
#[derive(Debug, Clone)]
pub struct UnixSocketInfo {
    /// Socket path
    pub path: String,
    /// Socket type (STREAM, DGRAM, SEQPACKET)
    pub socket_type: String,
    /// Connection state
    pub state: String,
    /// Socket inode
    pub inode: u64,
    /// Peer inode (if connected)
    pub peer_inode: Option<u64>,
}

/// Netfilter connection tracking entry
#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    /// Protocol
    pub protocol: String,
    /// Source IP
    pub src_addr: String,
    /// Source port
    pub src_port: u16,
    /// Destination IP
    pub dst_addr: String,
    /// Destination port
    pub dst_port: u16,
    /// Connection state
    pub state: String,
}

/// Extract netfilter conntrack entries
pub fn extract_conntrack(_dump: &ParsedDump) -> Result<Vec<ConntrackEntry>> {
    // Conntrack entries are in the nf_conntrack hash table
    // This requires finding nf_conntrack_hash and walking entries

    Ok(Vec::new())
}

/// Find suspicious network connections
pub fn find_suspicious_connections(connections: &[NetworkConnection]) -> Vec<&NetworkConnection> {
    let mut suspicious = Vec::new();

    // Suspicious indicators
    let suspicious_ports: [u16; 15] = [
        4444, 5555, 6666, 7777,  // Common RAT ports
        1337, 31337,              // "Elite" ports
        8080, 8888,               // Common C2 ports
        12345, 54321,             // Common backdoors
        6667, 6697,               // IRC (botnets)
        9001, 9030, 9050,         // Tor
    ];

    for conn in connections {
        let is_suspicious =
            suspicious_ports.contains(&conn.local_port) ||
            conn.remote_port.map(|p| suspicious_ports.contains(&p)).unwrap_or(false) ||
            // High numbered ephemeral listening port
            (conn.state == "LISTEN" && conn.local_port > 32768);

        if is_suspicious {
            suspicious.push(conn);
        }
    }

    suspicious
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state() {
        assert_eq!(TcpState::from_u8(1).as_str(), "ESTABLISHED");
        assert_eq!(TcpState::from_u8(10).as_str(), "LISTEN");
    }
}
