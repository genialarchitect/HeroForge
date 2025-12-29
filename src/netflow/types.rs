//! NetFlow/IPFIX/sFlow types and data structures
//! Sprint 5: Network Forensics & Flow Analysis

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Flow collector type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorType {
    NetflowV5,
    NetflowV9,
    Ipfix,
    Sflow,
}

impl std::fmt::Display for CollectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectorType::NetflowV5 => write!(f, "netflow_v5"),
            CollectorType::NetflowV9 => write!(f, "netflow_v9"),
            CollectorType::Ipfix => write!(f, "ipfix"),
            CollectorType::Sflow => write!(f, "sflow"),
        }
    }
}

/// Flow collector status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorStatus {
    Stopped,
    Starting,
    Running,
    Error,
}

impl std::fmt::Display for CollectorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectorStatus::Stopped => write!(f, "stopped"),
            CollectorStatus::Starting => write!(f, "starting"),
            CollectorStatus::Running => write!(f, "running"),
            CollectorStatus::Error => write!(f, "error"),
        }
    }
}

/// Flow collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowCollector {
    pub id: String,
    pub name: String,
    pub collector_type: CollectorType,
    pub listen_address: String,
    pub listen_port: u16,
    pub status: CollectorStatus,
    pub flows_received: u64,
    pub bytes_received: u64,
    pub last_flow_at: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// IP protocol number
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Gre = 47,
    Esp = 50,
    Icmpv6 = 58,
    Ospf = 89,
    Sctp = 132,
}

impl TryFrom<u8> for IpProtocol {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(IpProtocol::Icmp),
            6 => Ok(IpProtocol::Tcp),
            17 => Ok(IpProtocol::Udp),
            47 => Ok(IpProtocol::Gre),
            50 => Ok(IpProtocol::Esp),
            58 => Ok(IpProtocol::Icmpv6),
            89 => Ok(IpProtocol::Ospf),
            132 => Ok(IpProtocol::Sctp),
            other => Err(other),
        }
    }
}

impl IpProtocol {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn name(&self) -> &'static str {
        match self {
            IpProtocol::Icmp => "ICMP",
            IpProtocol::Tcp => "TCP",
            IpProtocol::Udp => "UDP",
            IpProtocol::Gre => "GRE",
            IpProtocol::Esp => "ESP",
            IpProtocol::Icmpv6 => "ICMPv6",
            IpProtocol::Ospf => "OSPF",
            IpProtocol::Sctp => "SCTP",
        }
    }
}

/// TCP flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl From<u8> for TcpFlags {
    fn from(value: u8) -> Self {
        TcpFlags {
            fin: value & 0x01 != 0,
            syn: value & 0x02 != 0,
            rst: value & 0x04 != 0,
            psh: value & 0x08 != 0,
            ack: value & 0x10 != 0,
            urg: value & 0x20 != 0,
            ece: value & 0x40 != 0,
            cwr: value & 0x80 != 0,
        }
    }
}

impl TcpFlags {
    pub fn as_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.syn { flags |= 0x02; }
        if self.rst { flags |= 0x04; }
        if self.psh { flags |= 0x08; }
        if self.ack { flags |= 0x10; }
        if self.urg { flags |= 0x20; }
        if self.ece { flags |= 0x40; }
        if self.cwr { flags |= 0x80; }
        flags
    }
}

impl std::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        if self.syn { s.push('S'); }
        if self.ack { s.push('A'); }
        if self.fin { s.push('F'); }
        if self.rst { s.push('R'); }
        if self.psh { s.push('P'); }
        if self.urg { s.push('U'); }
        if self.ece { s.push('E'); }
        if self.cwr { s.push('C'); }
        write!(f, "{}", s)
    }
}

/// Geolocation data for IP addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

/// Individual flow record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub id: String,
    pub collector_id: String,
    pub exporter_ip: IpAddr,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packets: i64,
    pub bytes: i64,
    pub tcp_flags: Option<u8>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_ms: i64,
    pub src_as: Option<i64>,
    pub dst_as: Option<i64>,
    pub input_interface: Option<i32>,
    pub output_interface: Option<i32>,
    pub tos: Option<u8>,
    pub application: Option<String>,
    pub src_geo: Option<GeoLocation>,
    pub dst_geo: Option<GeoLocation>,
    pub is_suspicious: bool,
    pub created_at: DateTime<Utc>,
}

/// Flow record for database storage (flat structure with strings)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecordRow {
    pub id: String,
    pub collector_id: String,
    pub exporter_ip: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: i32,
    pub dst_port: i32,
    pub protocol: i32,
    pub packets: i64,
    pub bytes: i64,
    pub tcp_flags: Option<i32>,
    pub start_time: String,
    pub end_time: String,
    pub duration_ms: i64,
    pub src_as: Option<i64>,
    pub dst_as: Option<i64>,
    pub input_interface: Option<i32>,
    pub output_interface: Option<i32>,
    pub tos: Option<i32>,
    pub application: Option<String>,
    pub src_country: Option<String>,
    pub dst_country: Option<String>,
    pub is_suspicious: i32,
    pub created_at: String,
}

/// Aggregation period
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationPeriod {
    Minute,
    FiveMinutes,
    FifteenMinutes,
    Hour,
    Day,
}

impl std::fmt::Display for AggregationPeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggregationPeriod::Minute => write!(f, "minute"),
            AggregationPeriod::FiveMinutes => write!(f, "5min"),
            AggregationPeriod::FifteenMinutes => write!(f, "15min"),
            AggregationPeriod::Hour => write!(f, "hour"),
            AggregationPeriod::Day => write!(f, "day"),
        }
    }
}

/// Aggregated flow data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowAggregate {
    pub id: String,
    pub period: AggregationPeriod,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_flows: i64,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
    pub unique_source_ports: i64,
    pub unique_destination_ports: i64,
    pub top_sources: Vec<TopTalker>,
    pub top_destinations: Vec<TopTalker>,
    pub top_source_ports: Vec<PortCount>,
    pub top_destination_ports: Vec<PortCount>,
    pub protocol_distribution: Vec<ProtocolDistribution>,
    pub avg_flow_duration_ms: f64,
    pub created_at: DateTime<Utc>,
}

/// Top talker entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalker {
    pub ip_address: IpAddr,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub flow_count: i64,
    pub percentage: f64,
    pub geo_location: Option<GeoLocation>,
    pub as_number: Option<i64>,
    pub as_name: Option<String>,
}

/// Port usage count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortCount {
    pub port: u16,
    pub service: Option<String>,
    pub count: i64,
    pub bytes: i64,
    pub percentage: f64,
}

/// Protocol distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDistribution {
    pub protocol: u8,
    pub protocol_name: String,
    pub bytes: i64,
    pub packets: i64,
    pub flow_count: i64,
    pub percentage: f64,
}

/// Flow anomaly type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowAnomalyType {
    PortScan,
    NetworkScan,
    DdosAttack,
    DataExfiltration,
    Beaconing,
    UnusualProtocol,
    LargeTransfer,
    SuspiciousPort,
    C2Communication,
    LateralMovement,
    DnsTunneling,
}

impl std::fmt::Display for FlowAnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowAnomalyType::PortScan => write!(f, "port_scan"),
            FlowAnomalyType::NetworkScan => write!(f, "network_scan"),
            FlowAnomalyType::DdosAttack => write!(f, "ddos_attack"),
            FlowAnomalyType::DataExfiltration => write!(f, "data_exfiltration"),
            FlowAnomalyType::Beaconing => write!(f, "beaconing"),
            FlowAnomalyType::UnusualProtocol => write!(f, "unusual_protocol"),
            FlowAnomalyType::LargeTransfer => write!(f, "large_transfer"),
            FlowAnomalyType::SuspiciousPort => write!(f, "suspicious_port"),
            FlowAnomalyType::C2Communication => write!(f, "c2_communication"),
            FlowAnomalyType::LateralMovement => write!(f, "lateral_movement"),
            FlowAnomalyType::DnsTunneling => write!(f, "dns_tunneling"),
        }
    }
}

/// Flow anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowAnomaly {
    pub id: String,
    pub anomaly_type: FlowAnomalyType,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub affected_ports: Vec<u16>,
    pub evidence: serde_json::Value,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub flow_count: i64,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub is_acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Bandwidth utilization data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthUtilization {
    pub timestamp: DateTime<Utc>,
    pub inbound_bytes: i64,
    pub outbound_bytes: i64,
    pub inbound_packets: i64,
    pub outbound_packets: i64,
    pub utilization_percent: f64,
}

/// Flow statistics summary
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowStats {
    pub total_flows: i64,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub flows_per_second: f64,
    pub avg_flow_size: f64,
    pub avg_packet_size: f64,
    pub tcp_flows: i64,
    pub udp_flows: i64,
    pub icmp_flows: i64,
    pub other_flows: i64,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
}

/// Flow timeline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub flows: i64,
    pub bytes: i64,
    pub packets: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
}

/// NetFlow v5 header
#[derive(Debug, Clone)]
pub struct NetflowV5Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling_interval: u16,
}

/// NetFlow v5 record
#[derive(Debug, Clone)]
pub struct NetflowV5Record {
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
    pub next_hop: [u8; 4],
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub first: u32,
    pub last: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub protocol: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
}

/// Template field definition
#[derive(Debug, Clone)]
pub struct TemplateField {
    pub field_type: u16,
    pub field_length: u16,
    pub enterprise_id: Option<u32>,
}

/// Flow template (for NetFlow v9 and IPFIX)
#[derive(Debug, Clone)]
pub struct FlowTemplate {
    pub template_id: u16,
    pub field_count: u16,
    pub fields: Vec<TemplateField>,
    pub total_length: u16,
}

/// sFlow sample type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SflowSampleType {
    FlowSample,
    CounterSample,
    Unknown(u32),
}

/// sFlow header
#[derive(Debug, Clone)]
pub struct SflowHeader {
    pub version: u32,
    pub agent_address: IpAddr,
    pub sub_agent_id: u32,
    pub sequence_number: u32,
    pub uptime: u32,
    pub sample_count: u32,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Map port number to application name
pub fn port_to_application(port: u16, protocol: u8) -> Option<&'static str> {
    // TCP ports
    if protocol == 6 {
        match port {
            20 | 21 => Some("FTP"),
            22 => Some("SSH"),
            23 => Some("Telnet"),
            25 | 587 | 465 => Some("SMTP"),
            53 => Some("DNS"),
            80 | 8080 | 8000 | 8888 => Some("HTTP"),
            110 => Some("POP3"),
            143 => Some("IMAP"),
            443 | 8443 => Some("HTTPS"),
            445 => Some("SMB"),
            993 => Some("IMAPS"),
            995 => Some("POP3S"),
            1433 => Some("MSSQL"),
            1521 => Some("Oracle"),
            3306 => Some("MySQL"),
            3389 => Some("RDP"),
            5432 => Some("PostgreSQL"),
            5900..=5909 => Some("VNC"),
            6379 => Some("Redis"),
            8081 => Some("HTTP-Alt"),
            27017 => Some("MongoDB"),
            _ => None,
        }
    }
    // UDP ports
    else if protocol == 17 {
        match port {
            53 => Some("DNS"),
            67 | 68 => Some("DHCP"),
            69 => Some("TFTP"),
            123 => Some("NTP"),
            161 | 162 => Some("SNMP"),
            500 => Some("IKE"),
            514 => Some("Syslog"),
            1194 => Some("OpenVPN"),
            1900 => Some("SSDP"),
            4500 => Some("IPsec-NAT"),
            5353 => Some("mDNS"),
            _ => None,
        }
    } else {
        None
    }
}

/// Check if a port is typically suspicious
pub fn is_suspicious_port(port: u16, protocol: u8) -> bool {
    // Common malware/C2 ports
    let suspicious_tcp: &[u16] = &[
        4444, 5555, 6666, 7777, 8888, 9999,  // Common RAT ports
        1337, 31337,                          // "Elite" ports
        12345, 54321,                         // Netbus
        27374,                                // SubSeven
        6667, 6668, 6669,                     // IRC (often used for C2)
        4000,                                 // ICQ / Some RATs
    ];

    let suspicious_udp: &[u16] = &[
        4444, 5555, 6666,
        1337, 31337,
    ];

    if protocol == 6 {
        suspicious_tcp.contains(&port)
    } else if protocol == 17 {
        suspicious_udp.contains(&port)
    } else {
        false
    }
}

/// Analyze beaconing behavior by calculating coefficient of variation
pub fn analyze_beaconing(intervals: &[u64]) -> Option<f64> {
    if intervals.len() < 5 {
        return None;
    }

    let n = intervals.len() as f64;
    let mean: f64 = intervals.iter().sum::<u64>() as f64 / n;

    if mean == 0.0 {
        return None;
    }

    let variance: f64 = intervals.iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>() / n;

    let std_dev = variance.sqrt();
    Some(std_dev / mean) // Coefficient of variation
}

/// Calculate Shannon entropy for data size distribution
pub fn calculate_size_entropy(sizes: &[u64]) -> f64 {
    if sizes.is_empty() {
        return 0.0;
    }

    let total: u64 = sizes.iter().sum();
    if total == 0 {
        return 0.0;
    }

    // Count occurrences of each size
    let mut counts = std::collections::HashMap::new();
    for &size in sizes {
        *counts.entry(size).or_insert(0u64) += 1;
    }

    // Calculate entropy
    let n = sizes.len() as f64;
    counts.values()
        .map(|&count| {
            let p = count as f64 / n;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}
