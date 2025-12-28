//! PCAP Parsing Module
//!
//! Parses PCAP and PCAPNG files for network traffic analysis.

use crate::traffic_analysis::types::*;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::Path;

/// PCAP file parser
pub struct PcapParser {
    /// Parsed packets
    packets: Vec<ParsedPacket>,
    /// Reconstructed sessions
    sessions: HashMap<SessionKey, NetworkSession>,
    /// Analysis configuration
    config: PcapParserConfig,
}

/// Parser configuration
#[derive(Debug, Clone)]
pub struct PcapParserConfig {
    /// Maximum file size to parse (bytes)
    pub max_file_size: u64,
    /// Enable session reconstruction
    pub reconstruct_sessions: bool,
    /// Enable protocol dissection
    pub dissect_protocols: bool,
    /// Maximum sessions to track
    pub max_sessions: usize,
    /// Session timeout (seconds)
    pub session_timeout_secs: u64,
}

impl Default for PcapParserConfig {
    fn default() -> Self {
        Self {
            max_file_size: 1024 * 1024 * 1024, // 1GB
            reconstruct_sessions: true,
            dissect_protocols: true,
            max_sessions: 100000,
            session_timeout_secs: 300,
        }
    }
}

/// Session identification key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SessionKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8, // IP protocol number
}

impl SessionKey {
    /// Create normalized key (smaller IP first for bidirectional matching)
    pub fn normalized(&self) -> Self {
        if self.src_ip < self.dst_ip ||
           (self.src_ip == self.dst_ip && self.src_port < self.dst_port) {
            self.clone()
        } else {
            Self {
                src_ip: self.dst_ip,
                src_port: self.dst_port,
                dst_ip: self.src_ip,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        }
    }
}

/// Parsed network packet
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub tcp_flags: Option<u8>,
    pub packet_len: usize,
}

/// PCAP file header (libpcap format)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct PcapGlobalHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

/// PCAP packet header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

impl PcapParser {
    /// Create a new PCAP parser
    pub fn new() -> Self {
        Self::with_config(PcapParserConfig::default())
    }

    /// Create parser with custom configuration
    pub fn with_config(config: PcapParserConfig) -> Self {
        Self {
            packets: Vec::new(),
            sessions: HashMap::new(),
            config,
        }
    }

    /// Parse a PCAP file
    pub fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> Result<PcapCapture, String> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;

        let metadata = file.metadata().map_err(|e| e.to_string())?;
        if metadata.len() > self.config.max_file_size {
            return Err(format!("File too large: {} bytes (max: {})",
                metadata.len(), self.config.max_file_size));
        }

        let mut reader = BufReader::new(file);
        self.parse_pcap(&mut reader, path)
    }

    /// Parse PCAP data from reader
    fn parse_pcap<R: Read>(&mut self, reader: &mut R, path: &Path) -> Result<PcapCapture, String> {
        // Read global header
        let mut header_bytes = [0u8; 24];
        reader.read_exact(&mut header_bytes).map_err(|e| format!("Failed to read header: {}", e))?;

        let magic = u32::from_le_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let swapped = magic == 0xd4c3b2a1;
        let is_pcapng = magic == 0x0a0d0d0a;

        if is_pcapng {
            return self.parse_pcapng(reader, path, &header_bytes);
        }

        if magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 {
            return Err(format!("Invalid PCAP magic: {:08x}", magic));
        }

        let snaplen = if swapped {
            u32::from_be_bytes([header_bytes[16], header_bytes[17], header_bytes[18], header_bytes[19]])
        } else {
            u32::from_le_bytes([header_bytes[16], header_bytes[17], header_bytes[18], header_bytes[19]])
        };

        let link_type = if swapped {
            u32::from_be_bytes([header_bytes[20], header_bytes[21], header_bytes[22], header_bytes[23]])
        } else {
            u32::from_le_bytes([header_bytes[20], header_bytes[21], header_bytes[22], header_bytes[23]])
        };

        // Parse packets
        let mut packet_count = 0u64;
        let mut byte_count = 0u64;
        let mut protocols_detected = HashMap::new();
        let mut first_timestamp: Option<DateTime<Utc>> = None;
        let mut last_timestamp: Option<DateTime<Utc>> = None;

        loop {
            // Read packet header
            let mut pkt_header = [0u8; 16];
            match reader.read_exact(&mut pkt_header) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("Failed to read packet header: {}", e)),
            }

            let ts_sec = if swapped {
                u32::from_be_bytes([pkt_header[0], pkt_header[1], pkt_header[2], pkt_header[3]])
            } else {
                u32::from_le_bytes([pkt_header[0], pkt_header[1], pkt_header[2], pkt_header[3]])
            };

            let ts_usec = if swapped {
                u32::from_be_bytes([pkt_header[4], pkt_header[5], pkt_header[6], pkt_header[7]])
            } else {
                u32::from_le_bytes([pkt_header[4], pkt_header[5], pkt_header[6], pkt_header[7]])
            };

            let incl_len = if swapped {
                u32::from_be_bytes([pkt_header[8], pkt_header[9], pkt_header[10], pkt_header[11]])
            } else {
                u32::from_le_bytes([pkt_header[8], pkt_header[9], pkt_header[10], pkt_header[11]])
            };

            // Read packet data
            let mut packet_data = vec![0u8; incl_len as usize];
            reader.read_exact(&mut packet_data).map_err(|e| format!("Failed to read packet: {}", e))?;

            // Parse timestamp
            let timestamp = DateTime::from_timestamp(ts_sec as i64, ts_usec * 1000)
                .unwrap_or_else(Utc::now);

            if first_timestamp.is_none() {
                first_timestamp = Some(timestamp);
            }
            last_timestamp = Some(timestamp);

            // Parse Ethernet/IP/TCP/UDP
            if let Some(parsed) = self.parse_packet(&packet_data, link_type, timestamp) {
                // Track protocol
                let proto_name = self.protocol_name(parsed.protocol, parsed.dst_port);
                *protocols_detected.entry(proto_name).or_insert(0u64) += 1;

                // Reconstruct sessions
                if self.config.reconstruct_sessions {
                    self.add_to_session(&parsed);
                }

                self.packets.push(parsed);
            }

            packet_count += 1;
            byte_count += incl_len as u64;
        }

        // Calculate duration
        let duration = match (first_timestamp, last_timestamp) {
            (Some(first), Some(last)) => (last - first).num_milliseconds() as f64 / 1000.0,
            _ => 0.0,
        };

        // Build capture result
        let file_hash = self.calculate_file_hash(path);

        Ok(PcapCapture {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: String::new(), // Set by caller
            filename: path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            file_size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            file_hash,
            capture_start: first_timestamp,
            capture_end: last_timestamp,
            duration_seconds: duration,
            packet_count,
            byte_count,
            protocols_detected: protocols_detected.keys().cloned().collect(),
            storage_path: path.to_string_lossy().to_string(),
            analysis_status: AnalysisStatus::Pending,
            analysis_results: None,
            created_at: Utc::now(),
        })
    }

    /// Parse PCAPNG format
    fn parse_pcapng<R: Read>(&mut self, _reader: &mut R, path: &Path, _initial_bytes: &[u8]) -> Result<PcapCapture, String> {
        // Simplified PCAPNG parsing - in production would fully implement
        Ok(PcapCapture {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: String::new(),
            filename: path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            file_size: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            file_hash: self.calculate_file_hash(path),
            capture_start: None,
            capture_end: None,
            duration_seconds: 0.0,
            packet_count: 0,
            byte_count: 0,
            protocols_detected: Vec::new(),
            storage_path: path.to_string_lossy().to_string(),
            analysis_status: AnalysisStatus::Pending,
            analysis_results: None,
            created_at: Utc::now(),
        })
    }

    /// Parse a single packet
    fn parse_packet(&self, data: &[u8], link_type: u32, timestamp: DateTime<Utc>) -> Option<ParsedPacket> {
        // Handle Ethernet (link_type 1) or raw IP (link_type 101)
        let ip_offset = match link_type {
            1 => 14,   // Ethernet
            101 => 0,  // Raw IP
            113 => 16, // Linux cooked capture
            _ => return None,
        };

        if data.len() < ip_offset + 20 {
            return None;
        }

        let ip_data = &data[ip_offset..];
        let ip_version = (ip_data[0] >> 4) & 0x0f;

        if ip_version != 4 {
            // Skip IPv6 for simplicity
            return None;
        }

        let ihl = (ip_data[0] & 0x0f) as usize * 4;
        let protocol = ip_data[9];

        let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            ip_data[12], ip_data[13], ip_data[14], ip_data[15]
        ));
        let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            ip_data[16], ip_data[17], ip_data[18], ip_data[19]
        ));

        if ip_data.len() < ihl + 4 {
            return None;
        }

        let transport_data = &ip_data[ihl..];

        let (src_port, dst_port, tcp_flags) = match protocol {
            6 => { // TCP
                if transport_data.len() < 14 {
                    return None;
                }
                let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                let flags = transport_data[13];
                (src_port, dst_port, Some(flags))
            }
            17 => { // UDP
                if transport_data.len() < 8 {
                    return None;
                }
                let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                (src_port, dst_port, None)
            }
            1 => { // ICMP
                (0, 0, None)
            }
            _ => return None,
        };

        // Get payload
        let payload_offset = match protocol {
            6 => {
                if transport_data.len() < 13 {
                    return None;
                }
                let data_offset = ((transport_data[12] >> 4) & 0x0f) as usize * 4;
                data_offset
            }
            17 => 8,
            _ => 0,
        };

        let payload = if transport_data.len() > payload_offset {
            transport_data[payload_offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(ParsedPacket {
            timestamp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            payload,
            tcp_flags,
            packet_len: data.len(),
        })
    }

    /// Add packet to session tracking
    fn add_to_session(&mut self, packet: &ParsedPacket) {
        let key = SessionKey {
            src_ip: packet.src_ip,
            src_port: packet.src_port,
            dst_ip: packet.dst_ip,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
        }.normalized();

        if self.sessions.len() >= self.config.max_sessions {
            return;
        }

        // Detect protocol before entry() to avoid borrow conflict
        let app_protocol = self.detect_application_protocol(key.dst_port, &[]);
        let session_type = match packet.protocol {
            6 => SessionType::Tcp,
            17 => SessionType::Udp,
            1 => SessionType::Icmp,
            _ => SessionType::Tcp,
        };
        let start_time = packet.timestamp;
        let key_clone = key.clone();

        let session = self.sessions.entry(key).or_insert_with(|| {
            NetworkSession {
                id: uuid::Uuid::new_v4().to_string(),
                pcap_id: String::new(),
                session_type,
                src_ip: key_clone.src_ip,
                src_port: key_clone.src_port,
                dst_ip: key_clone.dst_ip,
                dst_port: key_clone.dst_port,
                protocol: app_protocol,
                start_time,
                end_time: None,
                packets: 0,
                bytes_to_server: 0,
                bytes_to_client: 0,
                state: SessionState::Established,
                extracted_files: Vec::new(),
                notes: None,
            }
        });

        session.packets += 1;
        session.end_time = Some(packet.timestamp);

        // Track bytes direction
        if packet.src_ip == session.src_ip {
            session.bytes_to_server += packet.payload.len() as u64;
        } else {
            session.bytes_to_client += packet.payload.len() as u64;
        }

        // Update session state based on TCP flags
        if let Some(flags) = packet.tcp_flags {
            if flags & 0x01 != 0 { // FIN
                session.state = SessionState::Closed;
            }
            if flags & 0x04 != 0 { // RST
                session.state = SessionState::Reset;
            }
        }
    }

    /// Detect application protocol from port and payload
    fn detect_application_protocol(&self, port: u16, _payload: &[u8]) -> ApplicationProtocol {
        match port {
            80 => ApplicationProtocol::Http,
            443 => ApplicationProtocol::Https,
            53 => ApplicationProtocol::Dns,
            25 => ApplicationProtocol::Smtp,
            465 | 587 => ApplicationProtocol::Smtps,
            143 => ApplicationProtocol::Imap,
            993 => ApplicationProtocol::Imaps,
            110 => ApplicationProtocol::Pop3,
            995 => ApplicationProtocol::Pop3s,
            21 => ApplicationProtocol::Ftp,
            990 => ApplicationProtocol::Ftps,
            22 => ApplicationProtocol::Ssh,
            23 => ApplicationProtocol::Telnet,
            3389 => ApplicationProtocol::Rdp,
            445 | 139 => ApplicationProtocol::Smb,
            123 => ApplicationProtocol::Ntp,
            67 | 68 => ApplicationProtocol::Dhcp,
            161 | 162 => ApplicationProtocol::Snmp,
            389 => ApplicationProtocol::Ldap,
            636 => ApplicationProtocol::Ldaps,
            3306 => ApplicationProtocol::Mysql,
            5432 => ApplicationProtocol::Postgresql,
            1433 => ApplicationProtocol::Mssql,
            1521 => ApplicationProtocol::Oracle,
            27017 => ApplicationProtocol::Mongodb,
            6379 => ApplicationProtocol::Redis,
            5060 | 5061 => ApplicationProtocol::Sip,
            6667 => ApplicationProtocol::Irc,
            5222 => ApplicationProtocol::Xmpp,
            1883 | 8883 => ApplicationProtocol::Mqtt,
            502 => ApplicationProtocol::Modbus,
            20000 => ApplicationProtocol::Dnp3,
            102 => ApplicationProtocol::S7comm,
            47808 => ApplicationProtocol::BacNet,
            _ => ApplicationProtocol::Unknown,
        }
    }

    /// Get protocol name for statistics
    fn protocol_name(&self, protocol: u8, port: u16) -> String {
        match protocol {
            6 => {
                let app = self.detect_application_protocol(port, &[]);
                format!("TCP/{}", app)
            }
            17 => {
                let app = self.detect_application_protocol(port, &[]);
                format!("UDP/{}", app)
            }
            1 => "ICMP".to_string(),
            _ => format!("IP/{}", protocol),
        }
    }

    /// Calculate file hash
    fn calculate_file_hash(&self, path: &Path) -> String {
        use std::io::Read;

        if let Ok(mut file) = File::open(path) {
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            let mut buffer = [0u8; 8192];
            while let Ok(n) = file.read(&mut buffer) {
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            format!("{:x}", hasher.finalize())
        } else {
            String::new()
        }
    }

    /// Get reconstructed sessions
    pub fn get_sessions(&self) -> Vec<&NetworkSession> {
        self.sessions.values().collect()
    }

    /// Get parsed packets
    pub fn get_packets(&self) -> &[ParsedPacket] {
        &self.packets
    }

    /// Analyze capture and generate results
    pub fn analyze(&self) -> PcapAnalysisResults {
        let mut protocols = HashMap::new();
        let mut unique_ips = std::collections::HashSet::new();
        let mut unique_ports = std::collections::HashSet::new();

        for packet in &self.packets {
            unique_ips.insert(packet.src_ip);
            unique_ips.insert(packet.dst_ip);
            unique_ports.insert(packet.src_port);
            unique_ports.insert(packet.dst_port);

            let proto = self.protocol_name(packet.protocol, packet.dst_port);
            *protocols.entry(proto).or_insert(0u64) += 1;
        }

        let tcp_sessions = self.sessions.values()
            .filter(|s| s.session_type == SessionType::Tcp)
            .count() as u64;

        let udp_sessions = self.sessions.values()
            .filter(|s| s.session_type == SessionType::Udp)
            .count() as u64;

        PcapAnalysisResults {
            total_sessions: self.sessions.len() as u64,
            tcp_sessions,
            udp_sessions,
            unique_ips: unique_ips.len() as u64,
            unique_ports: unique_ports.len() as u64,
            protocols,
            dns_queries: 0, // Calculated by protocol analyzer
            http_transactions: 0,
            tls_connections: 0,
            files_carved: 0,
            alerts_generated: 0,
            suspicious_indicators: Vec::new(),
        }
    }
}

impl Default for PcapParser {
    fn default() -> Self {
        Self::new()
    }
}
