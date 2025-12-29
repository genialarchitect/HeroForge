//! DNS Analytics Types
//!
//! Core data structures for DNS analytics, threat detection, and passive DNS collection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    SRV,
    TXT,
    CAA,
    DNSKEY,
    DS,
    NAPTR,
    RRSIG,
    SPF,
    TLSA,
    Unknown,
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::AAAA => write!(f, "AAAA"),
            DnsRecordType::CNAME => write!(f, "CNAME"),
            DnsRecordType::MX => write!(f, "MX"),
            DnsRecordType::NS => write!(f, "NS"),
            DnsRecordType::PTR => write!(f, "PTR"),
            DnsRecordType::SOA => write!(f, "SOA"),
            DnsRecordType::SRV => write!(f, "SRV"),
            DnsRecordType::TXT => write!(f, "TXT"),
            DnsRecordType::CAA => write!(f, "CAA"),
            DnsRecordType::DNSKEY => write!(f, "DNSKEY"),
            DnsRecordType::DS => write!(f, "DS"),
            DnsRecordType::NAPTR => write!(f, "NAPTR"),
            DnsRecordType::RRSIG => write!(f, "RRSIG"),
            DnsRecordType::SPF => write!(f, "SPF"),
            DnsRecordType::TLSA => write!(f, "TLSA"),
            DnsRecordType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl From<&str> for DnsRecordType {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "A" => DnsRecordType::A,
            "AAAA" => DnsRecordType::AAAA,
            "CNAME" => DnsRecordType::CNAME,
            "MX" => DnsRecordType::MX,
            "NS" => DnsRecordType::NS,
            "PTR" => DnsRecordType::PTR,
            "SOA" => DnsRecordType::SOA,
            "SRV" => DnsRecordType::SRV,
            "TXT" => DnsRecordType::TXT,
            "CAA" => DnsRecordType::CAA,
            "DNSKEY" => DnsRecordType::DNSKEY,
            "DS" => DnsRecordType::DS,
            "NAPTR" => DnsRecordType::NAPTR,
            "RRSIG" => DnsRecordType::RRSIG,
            "SPF" => DnsRecordType::SPF,
            "TLSA" => DnsRecordType::TLSA,
            _ => DnsRecordType::Unknown,
        }
    }
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Unknown(u16),
}

impl From<u16> for DnsResponseCode {
    fn from(code: u16) -> Self {
        match code {
            0 => DnsResponseCode::NoError,
            1 => DnsResponseCode::FormErr,
            2 => DnsResponseCode::ServFail,
            3 => DnsResponseCode::NXDomain,
            4 => DnsResponseCode::NotImp,
            5 => DnsResponseCode::Refused,
            6 => DnsResponseCode::YXDomain,
            7 => DnsResponseCode::YXRRSet,
            8 => DnsResponseCode::NXRRSet,
            9 => DnsResponseCode::NotAuth,
            10 => DnsResponseCode::NotZone,
            _ => DnsResponseCode::Unknown(code),
        }
    }
}

/// Passive DNS record - stores DNS query/response pairs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveDnsRecord {
    pub id: String,
    pub query_name: String,
    pub query_type: DnsRecordType,
    pub response_data: String,
    pub ttl: Option<i32>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub query_count: i64,
    pub source_ips: Vec<IpAddr>,
    pub is_suspicious: bool,
    pub threat_type: Option<DnsThreatType>,
    pub threat_score: i32,
    pub created_at: DateTime<Utc>,
}

/// DNS threat types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsThreatType {
    Dga,
    Tunneling,
    FastFlux,
    Malware,
    Phishing,
    CryptoMining,
    Botnet,
    DataExfiltration,
    CommandAndControl,
    Unknown,
}

impl std::fmt::Display for DnsThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsThreatType::Dga => write!(f, "dga"),
            DnsThreatType::Tunneling => write!(f, "tunneling"),
            DnsThreatType::FastFlux => write!(f, "fast_flux"),
            DnsThreatType::Malware => write!(f, "malware"),
            DnsThreatType::Phishing => write!(f, "phishing"),
            DnsThreatType::CryptoMining => write!(f, "crypto_mining"),
            DnsThreatType::Botnet => write!(f, "botnet"),
            DnsThreatType::DataExfiltration => write!(f, "data_exfiltration"),
            DnsThreatType::CommandAndControl => write!(f, "command_and_control"),
            DnsThreatType::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<&str> for DnsThreatType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "dga" => DnsThreatType::Dga,
            "tunneling" | "tunnel" => DnsThreatType::Tunneling,
            "fast_flux" | "fastflux" => DnsThreatType::FastFlux,
            "malware" => DnsThreatType::Malware,
            "phishing" => DnsThreatType::Phishing,
            "crypto_mining" | "cryptomining" => DnsThreatType::CryptoMining,
            "botnet" => DnsThreatType::Botnet,
            "data_exfiltration" | "exfiltration" => DnsThreatType::DataExfiltration,
            "command_and_control" | "c2" | "cnc" => DnsThreatType::CommandAndControl,
            _ => DnsThreatType::Unknown,
        }
    }
}

/// DNS anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnomaly {
    pub id: String,
    pub anomaly_type: DnsAnomalyType,
    pub domain: String,
    pub severity: DnsAnomalySeverity,
    pub description: String,
    pub indicators: serde_json::Value,
    pub entropy_score: Option<f64>,
    pub dga_probability: Option<f64>,
    pub tunnel_indicators: Option<TunnelIndicators>,
    pub fast_flux_indicators: Option<FastFluxIndicators>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub query_count: i64,
    pub status: DnsAnomalyStatus,
    pub source_ips: Vec<IpAddr>,
    pub created_at: DateTime<Utc>,
}

/// DNS anomaly types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsAnomalyType {
    Dga,
    Tunneling,
    FastFlux,
    HighEntropy,
    LongDomain,
    HighQueryVolume,
    NxdomainSpike,
    UnusualRecordType,
    SuspiciousTxt,
    NewlyObservedDomain,
}

impl std::fmt::Display for DnsAnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsAnomalyType::Dga => write!(f, "dga"),
            DnsAnomalyType::Tunneling => write!(f, "tunneling"),
            DnsAnomalyType::FastFlux => write!(f, "fast_flux"),
            DnsAnomalyType::HighEntropy => write!(f, "high_entropy"),
            DnsAnomalyType::LongDomain => write!(f, "long_domain"),
            DnsAnomalyType::HighQueryVolume => write!(f, "high_query_volume"),
            DnsAnomalyType::NxdomainSpike => write!(f, "nxdomain_spike"),
            DnsAnomalyType::UnusualRecordType => write!(f, "unusual_record_type"),
            DnsAnomalyType::SuspiciousTxt => write!(f, "suspicious_txt"),
            DnsAnomalyType::NewlyObservedDomain => write!(f, "newly_observed_domain"),
        }
    }
}

/// DNS anomaly severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsAnomalySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for DnsAnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsAnomalySeverity::Critical => write!(f, "critical"),
            DnsAnomalySeverity::High => write!(f, "high"),
            DnsAnomalySeverity::Medium => write!(f, "medium"),
            DnsAnomalySeverity::Low => write!(f, "low"),
            DnsAnomalySeverity::Info => write!(f, "info"),
        }
    }
}

/// DNS anomaly status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsAnomalyStatus {
    New,
    Investigating,
    Confirmed,
    FalsePositive,
    Resolved,
}

impl std::fmt::Display for DnsAnomalyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsAnomalyStatus::New => write!(f, "new"),
            DnsAnomalyStatus::Investigating => write!(f, "investigating"),
            DnsAnomalyStatus::Confirmed => write!(f, "confirmed"),
            DnsAnomalyStatus::FalsePositive => write!(f, "false_positive"),
            DnsAnomalyStatus::Resolved => write!(f, "resolved"),
        }
    }
}

/// DNS tunneling indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelIndicators {
    pub avg_query_length: f64,
    pub max_query_length: usize,
    pub subdomain_count: usize,
    pub unique_subdomains: usize,
    pub query_frequency: f64,
    pub txt_record_ratio: f64,
    pub null_record_ratio: f64,
    pub entropy_scores: Vec<f64>,
    pub base64_likelihood: f64,
    pub hex_likelihood: f64,
}

/// Fast-flux indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastFluxIndicators {
    pub unique_ips: usize,
    pub ip_change_rate: f64,
    pub avg_ttl: f64,
    pub min_ttl: i32,
    pub max_ttl: i32,
    pub geographic_diversity: f64,
    pub asn_diversity: usize,
    pub flux_score: f64,
    pub ip_addresses: Vec<IpAddr>,
    pub countries: Vec<String>,
}

/// DGA detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaAnalysis {
    pub domain: String,
    pub is_dga: bool,
    pub probability: f64,
    pub entropy: f64,
    pub consonant_ratio: f64,
    pub digit_ratio: f64,
    pub length_score: f64,
    pub ngram_score: f64,
    pub dictionary_score: f64,
    pub tld: String,
    pub detected_family: Option<String>,
    pub confidence: DgaConfidence,
}

/// DGA confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DgaConfidence {
    High,
    Medium,
    Low,
}

/// Newly observed domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewlyObservedDomain {
    pub id: String,
    pub domain: String,
    pub tld: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub first_query_ip: Option<IpAddr>,
    pub querying_ips: Vec<IpAddr>,
    pub registrar: Option<String>,
    pub registration_date: Option<DateTime<Utc>>,
    pub whois_data: Option<serde_json::Value>,
    pub risk_score: i32,
    pub threat_indicators: Vec<String>,
    pub threat_type: Option<DnsThreatType>,
    pub status: NodStatus,
    pub resolved_ips: Vec<IpAddr>,
    pub query_count: i64,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// NOD status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodStatus {
    New,
    Investigating,
    Reviewed,
    Benign,
    Suspicious,
    Malicious,
}

impl std::fmt::Display for NodStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodStatus::New => write!(f, "new"),
            NodStatus::Investigating => write!(f, "investigating"),
            NodStatus::Reviewed => write!(f, "reviewed"),
            NodStatus::Benign => write!(f, "benign"),
            NodStatus::Suspicious => write!(f, "suspicious"),
            NodStatus::Malicious => write!(f, "malicious"),
        }
    }
}

/// DNS baseline for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBaseline {
    pub id: String,
    pub baseline_type: DnsBaselineType,
    pub entity: String, // IP, subnet, or "global"
    pub period: BaselinePeriod,
    pub mean_value: f64,
    pub std_deviation: f64,
    pub min_value: f64,
    pub max_value: f64,
    pub sample_count: i64,
    pub last_calculated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// DNS baseline types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsBaselineType {
    QueryVolume,
    UniqueDomains,
    NxdomainRate,
    TxtQueryRate,
    AvgQueryLength,
    EntropyScore,
}

impl std::fmt::Display for DnsBaselineType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsBaselineType::QueryVolume => write!(f, "query_volume"),
            DnsBaselineType::UniqueDomains => write!(f, "unique_domains"),
            DnsBaselineType::NxdomainRate => write!(f, "nxdomain_rate"),
            DnsBaselineType::TxtQueryRate => write!(f, "txt_query_rate"),
            DnsBaselineType::AvgQueryLength => write!(f, "avg_query_length"),
            DnsBaselineType::EntropyScore => write!(f, "entropy_score"),
        }
    }
}

/// Baseline period
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselinePeriod {
    Hourly,
    Daily,
    Weekly,
}

impl std::fmt::Display for BaselinePeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaselinePeriod::Hourly => write!(f, "hourly"),
            BaselinePeriod::Daily => write!(f, "daily"),
            BaselinePeriod::Weekly => write!(f, "weekly"),
        }
    }
}

/// DNS query for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub query_name: String,
    pub query_type: DnsRecordType,
    pub response_code: DnsResponseCode,
    pub response_data: Vec<String>,
    pub ttl: Option<i32>,
    pub latency_ms: Option<u32>,
    pub server_ip: Option<IpAddr>,
    pub is_recursive: bool,
    pub is_dnssec: bool,
}

/// DNS statistics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsStats {
    pub total_queries: i64,
    pub unique_domains: i64,
    pub unique_clients: i64,
    pub nxdomain_count: i64,
    pub nxdomain_rate: f64,
    pub dga_detections: i64,
    pub tunnel_detections: i64,
    pub fast_flux_detections: i64,
    pub newly_observed_domains: i64,
    pub suspicious_domains: i64,
    pub top_queried_domains: Vec<DomainCount>,
    pub top_query_types: Vec<QueryTypeCount>,
    pub top_clients: Vec<ClientQueryCount>,
    pub queries_per_hour: Vec<TimeSeriesPoint>,
}

/// Domain query count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: i64,
    pub is_suspicious: bool,
}

/// Query type count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTypeCount {
    pub query_type: DnsRecordType,
    pub count: i64,
    pub percentage: f64,
}

/// Client query count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientQueryCount {
    pub client_ip: IpAddr,
    pub query_count: i64,
    pub unique_domains: i64,
    pub nxdomain_count: i64,
}

/// Time series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: i64,
}

/// DNS threat intelligence correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsThreatIntel {
    pub domain: String,
    pub is_malicious: bool,
    pub threat_types: Vec<DnsThreatType>,
    pub confidence: f64,
    pub sources: Vec<ThreatIntelSource>,
    pub first_reported: Option<DateTime<Utc>>,
    pub last_reported: Option<DateTime<Utc>>,
    pub associated_malware: Vec<String>,
    pub associated_campaigns: Vec<String>,
    pub iocs: Vec<String>,
}

/// Threat intel source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelSource {
    pub name: String,
    pub url: Option<String>,
    pub confidence: f64,
    pub last_updated: DateTime<Utc>,
}

/// DNS collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCollectorConfig {
    pub id: String,
    pub name: String,
    pub collector_type: DnsCollectorType,
    pub listen_address: String,
    pub listen_port: u16,
    pub enabled: bool,
    pub capture_responses: bool,
    pub store_raw_packets: bool,
    pub whitelist_domains: Vec<String>,
    pub blacklist_domains: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// DNS collector types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsCollectorType {
    PassiveTap,
    DnsProxy,
    LogIngestion,
    Pcap,
}

impl std::fmt::Display for DnsCollectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsCollectorType::PassiveTap => write!(f, "passive_tap"),
            DnsCollectorType::DnsProxy => write!(f, "dns_proxy"),
            DnsCollectorType::LogIngestion => write!(f, "log_ingestion"),
            DnsCollectorType::Pcap => write!(f, "pcap"),
        }
    }
}

/// DNS dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsDashboard {
    pub stats: DnsStats,
    pub recent_anomalies: Vec<DnsAnomaly>,
    pub recent_nods: Vec<NewlyObservedDomain>,
    pub threat_breakdown: HashMap<String, i64>,
    pub query_trend: Vec<TimeSeriesPoint>,
    pub anomaly_trend: Vec<TimeSeriesPoint>,
}

/// NOD statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodStats {
    pub total_nods: i64,
    pub high_risk_nods: i64,
    pub recent_nods_24h: i64,
    pub alerts_generated: i64,
    pub unacknowledged_alerts: i64,
    pub top_tlds: Vec<(String, i64)>,
    pub nods_by_status: HashMap<String, i64>,
}

/// NOD alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodAlert {
    pub id: String,
    pub domain: String,
    pub risk_score: i32,
    pub severity: NodAlertSeverity,
    pub threat_type: Option<DnsThreatType>,
    pub indicators: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub source_ip: Option<IpAddr>,
    pub acknowledged: bool,
    pub created_at: DateTime<Utc>,
}

/// NOD alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodAlertSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for NodAlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodAlertSeverity::Critical => write!(f, "critical"),
            NodAlertSeverity::High => write!(f, "high"),
            NodAlertSeverity::Medium => write!(f, "medium"),
            NodAlertSeverity::Low => write!(f, "low"),
        }
    }
}
