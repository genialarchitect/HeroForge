//! Traffic Analysis Types
//!
//! Core types for network traffic analysis including:
//! - PCAP capture metadata
//! - Session reconstruction
//! - Protocol analysis
//! - IDS rule matching
//! - JA3/JA3S fingerprinting

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// PCAP capture file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapCapture {
    pub id: String,
    pub user_id: String,
    pub filename: String,
    pub file_size: u64,
    pub file_hash: String,
    pub capture_start: Option<DateTime<Utc>>,
    pub capture_end: Option<DateTime<Utc>>,
    pub duration_seconds: f64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub protocols_detected: Vec<String>,
    pub storage_path: String,
    pub analysis_status: AnalysisStatus,
    pub analysis_results: Option<PcapAnalysisResults>,
    pub created_at: DateTime<Utc>,
}

/// Analysis status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Pending,
    Analyzing,
    Completed,
    Failed,
}

/// PCAP analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapAnalysisResults {
    pub total_sessions: u64,
    pub tcp_sessions: u64,
    pub udp_sessions: u64,
    pub unique_ips: u64,
    pub unique_ports: u64,
    pub protocols: HashMap<String, u64>,
    pub dns_queries: u64,
    pub http_transactions: u64,
    pub tls_connections: u64,
    pub files_carved: u64,
    pub alerts_generated: u64,
    pub suspicious_indicators: Vec<String>,
}

/// Network session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSession {
    pub id: String,
    pub pcap_id: String,
    pub session_type: SessionType,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: ApplicationProtocol,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub packets: u64,
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,
    pub state: SessionState,
    pub extracted_files: Vec<ExtractedFile>,
    pub notes: Option<String>,
}

/// Session type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    Tcp,
    Udp,
    Icmp,
}

/// Application protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationProtocol {
    Http,
    Https,
    Dns,
    Smtp,
    Smtps,
    Imap,
    Imaps,
    Pop3,
    Pop3s,
    Ftp,
    Ftps,
    Ssh,
    Telnet,
    Rdp,
    Smb,
    Ntp,
    Dhcp,
    Snmp,
    Ldap,
    Ldaps,
    Mysql,
    Postgresql,
    Mssql,
    Oracle,
    Mongodb,
    Redis,
    Sip,
    Rtp,
    Irc,
    Xmpp,
    Mqtt,
    Modbus,
    Dnp3,
    S7comm,
    BacNet,
    Unknown,
}

impl std::fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplicationProtocol::Http => write!(f, "HTTP"),
            ApplicationProtocol::Https => write!(f, "HTTPS"),
            ApplicationProtocol::Dns => write!(f, "DNS"),
            ApplicationProtocol::Smtp => write!(f, "SMTP"),
            ApplicationProtocol::Smtps => write!(f, "SMTPS"),
            ApplicationProtocol::Imap => write!(f, "IMAP"),
            ApplicationProtocol::Imaps => write!(f, "IMAPS"),
            ApplicationProtocol::Pop3 => write!(f, "POP3"),
            ApplicationProtocol::Pop3s => write!(f, "POP3S"),
            ApplicationProtocol::Ftp => write!(f, "FTP"),
            ApplicationProtocol::Ftps => write!(f, "FTPS"),
            ApplicationProtocol::Ssh => write!(f, "SSH"),
            ApplicationProtocol::Telnet => write!(f, "Telnet"),
            ApplicationProtocol::Rdp => write!(f, "RDP"),
            ApplicationProtocol::Smb => write!(f, "SMB"),
            ApplicationProtocol::Ntp => write!(f, "NTP"),
            ApplicationProtocol::Dhcp => write!(f, "DHCP"),
            ApplicationProtocol::Snmp => write!(f, "SNMP"),
            ApplicationProtocol::Ldap => write!(f, "LDAP"),
            ApplicationProtocol::Ldaps => write!(f, "LDAPS"),
            ApplicationProtocol::Mysql => write!(f, "MySQL"),
            ApplicationProtocol::Postgresql => write!(f, "PostgreSQL"),
            ApplicationProtocol::Mssql => write!(f, "MSSQL"),
            ApplicationProtocol::Oracle => write!(f, "Oracle"),
            ApplicationProtocol::Mongodb => write!(f, "MongoDB"),
            ApplicationProtocol::Redis => write!(f, "Redis"),
            ApplicationProtocol::Sip => write!(f, "SIP"),
            ApplicationProtocol::Rtp => write!(f, "RTP"),
            ApplicationProtocol::Irc => write!(f, "IRC"),
            ApplicationProtocol::Xmpp => write!(f, "XMPP"),
            ApplicationProtocol::Mqtt => write!(f, "MQTT"),
            ApplicationProtocol::Modbus => write!(f, "Modbus"),
            ApplicationProtocol::Dnp3 => write!(f, "DNP3"),
            ApplicationProtocol::S7comm => write!(f, "S7comm"),
            ApplicationProtocol::BacNet => write!(f, "BACnet"),
            ApplicationProtocol::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Session state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Established,
    Closed,
    Reset,
    Timeout,
    Incomplete,
}

/// Extracted file from network stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    pub id: String,
    pub session_id: String,
    pub filename: Option<String>,
    pub mime_type: String,
    pub size: u64,
    pub md5: String,
    pub sha256: String,
    pub storage_path: String,
    pub extraction_method: ExtractionMethod,
    pub is_executable: bool,
    pub is_malicious: Option<bool>,
    pub extracted_at: DateTime<Utc>,
}

/// File extraction method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionMethod {
    HttpResponse,
    FtpTransfer,
    SmtpAttachment,
    SmbTransfer,
    MagicCarving,
    Reassembly,
}

/// DNS query record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub id: String,
    pub pcap_id: String,
    pub session_id: Option<String>,
    pub query_time: DateTime<Utc>,
    pub query_type: DnsQueryType,
    pub query_name: String,
    pub response_code: DnsResponseCode,
    pub answers: Vec<DnsAnswer>,
    pub ttl: Option<u32>,
    pub is_suspicious: bool,
    pub dga_score: Option<f64>,
    pub suspicion_reasons: Vec<String>,
}

/// DNS query type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Srv,
    Txt,
    Any,
    Other,
}

/// DNS response code
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    YxRrset,
    NxRrset,
    NotAuth,
    NotZone,
    Other,
}

/// DNS answer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub answer_type: DnsQueryType,
    pub value: String,
    pub ttl: u32,
}

/// HTTP transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTransaction {
    pub id: String,
    pub pcap_id: String,
    pub session_id: String,
    pub request_time: DateTime<Utc>,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub full_url: String,
    pub user_agent: Option<String>,
    pub request_headers: HashMap<String, String>,
    pub request_body_size: u64,
    pub request_body_hash: Option<String>,
    pub response_time: Option<DateTime<Utc>>,
    pub response_code: Option<u16>,
    pub response_headers: HashMap<String, String>,
    pub response_body_size: u64,
    pub response_body_hash: Option<String>,
    pub content_type: Option<String>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// TLS connection details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConnection {
    pub id: String,
    pub session_id: String,
    pub version: TlsVersion,
    pub cipher_suite: String,
    pub server_name: Option<String>,
    pub certificate_chain: Vec<TlsCertificate>,
    pub ja3_hash: String,
    pub ja3_string: String,
    pub ja3s_hash: Option<String>,
    pub ja3s_string: Option<String>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub is_suspicious: bool,
}

/// TLS version
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown,
}

/// TLS certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
    pub is_ca: bool,
}

/// JA3 fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Fingerprint {
    pub id: String,
    pub ja3_hash: String,
    pub ja3_string: String,
    pub ja3s_hash: Option<String>,
    pub ja3s_string: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub seen_count: u64,
    pub known_client: Option<String>,
    pub threat_score: u8,
    pub notes: Option<String>,
}

/// IDS rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    pub id: String,
    pub user_id: Option<String>,
    pub rule_type: IdsRuleType,
    pub sid: Option<u32>,
    pub gid: Option<u32>,
    pub revision: u32,
    pub rule_content: String,
    pub message: String,
    pub category: String,
    pub severity: IdsSeverity,
    pub enabled: bool,
    pub source: IdsRuleSource,
    pub references: Vec<String>,
    pub hits_count: u64,
    pub last_hit_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// IDS rule type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdsRuleType {
    Suricata,
    Snort,
    Zeek,
}

/// IDS severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IdsSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// IDS rule source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdsRuleSource {
    Custom,
    EmergingThreats,
    Snort3Community,
    Suricata,
    ProofPoint,
    Imported,
}

/// IDS alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsAlert {
    pub id: String,
    pub pcap_id: String,
    pub rule_id: String,
    pub session_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: String,
    pub message: String,
    pub severity: IdsSeverity,
    pub payload_excerpt: Option<String>,
    pub is_false_positive: bool,
    pub notes: Option<String>,
}

/// Beacon detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconDetection {
    pub id: String,
    pub pcap_id: String,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub connection_count: u64,
    pub avg_interval_seconds: f64,
    pub interval_variance: f64,
    pub avg_bytes_per_connection: f64,
    pub jitter_percentage: f64,
    pub beacon_score: f64,
    pub is_likely_beacon: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Protocol anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnomaly {
    pub id: String,
    pub pcap_id: String,
    pub session_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub anomaly_type: AnomalyType,
    pub protocol: String,
    pub description: String,
    pub severity: IdsSeverity,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

/// Anomaly type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    MalformedPacket,
    ProtocolViolation,
    UnusualPort,
    SuspiciousPayload,
    DataExfiltration,
    TunnelingDetected,
    EncryptedNonStandard,
    Other,
}

/// Network forensics timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsTimelineEvent {
    pub id: String,
    pub pcap_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: ForensicsEventType,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub description: String,
    pub details: HashMap<String, String>,
    pub severity: IdsSeverity,
    pub related_session_id: Option<String>,
    pub related_alert_id: Option<String>,
}

/// Forensics event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForensicsEventType {
    SessionStart,
    SessionEnd,
    DnsQuery,
    HttpRequest,
    FileTransfer,
    IdsAlert,
    AnomalyDetected,
    BeaconActivity,
    TlsNegotiation,
    LoginAttempt,
    DataExfiltration,
    CommandExecution,
}

/// Traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStatistics {
    pub total_captures: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_sessions: u64,
    pub unique_ips: u64,
    pub dns_queries: u64,
    pub http_transactions: u64,
    pub files_extracted: u64,
    pub ids_alerts: u64,
    pub beacons_detected: u64,
    pub top_protocols: Vec<(String, u64)>,
    pub top_talkers: Vec<(String, u64)>,
}
