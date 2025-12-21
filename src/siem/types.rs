//! Core SIEM types for log collection, storage, and analysis.
//!
//! This module defines the fundamental data structures for the HeroForge SIEM system,
//! including log entries, sources, detection rules, and alerts.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Unique identifier type for SIEM entities
pub type SiemId = String;

/// Severity levels for log entries and alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiemSeverity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl SiemSeverity {
    /// Convert syslog numeric priority (0-7) to severity
    pub fn from_syslog_priority(priority: u8) -> Self {
        match priority {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Info,
            7 => Self::Debug,
            _ => Self::Info,
        }
    }

    /// Convert to syslog numeric priority (0-7)
    pub fn to_syslog_priority(&self) -> u8 {
        match self {
            Self::Emergency => 0,
            Self::Alert => 1,
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Alert => "alert",
            Self::Emergency => "emergency",
        }
    }
}

impl std::fmt::Display for SiemSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for SiemSeverity {
    fn default() -> Self {
        Self::Info
    }
}

/// Syslog facility codes (RFC 5424)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFacility {
    Kern = 0,
    User = 1,
    Mail = 2,
    Daemon = 3,
    Auth = 4,
    Syslog = 5,
    Lpr = 6,
    News = 7,
    Uucp = 8,
    Cron = 9,
    Authpriv = 10,
    Ftp = 11,
    Ntp = 12,
    Audit = 13,
    Console = 14,
    Cron2 = 15,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

impl SyslogFacility {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Kern),
            1 => Some(Self::User),
            2 => Some(Self::Mail),
            3 => Some(Self::Daemon),
            4 => Some(Self::Auth),
            5 => Some(Self::Syslog),
            6 => Some(Self::Lpr),
            7 => Some(Self::News),
            8 => Some(Self::Uucp),
            9 => Some(Self::Cron),
            10 => Some(Self::Authpriv),
            11 => Some(Self::Ftp),
            12 => Some(Self::Ntp),
            13 => Some(Self::Audit),
            14 => Some(Self::Console),
            15 => Some(Self::Cron2),
            16 => Some(Self::Local0),
            17 => Some(Self::Local1),
            18 => Some(Self::Local2),
            19 => Some(Self::Local3),
            20 => Some(Self::Local4),
            21 => Some(Self::Local5),
            22 => Some(Self::Local6),
            23 => Some(Self::Local7),
            _ => None,
        }
    }

    pub fn to_code(&self) -> u8 {
        *self as u8
    }
}

impl Default for SyslogFacility {
    fn default() -> Self {
        Self::User
    }
}

/// Log format types supported by the SIEM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// RFC 3164 BSD syslog format
    SyslogRfc3164,
    /// RFC 5424 structured syslog format
    SyslogRfc5424,
    /// Common Event Format (ArcSight)
    Cef,
    /// Log Event Extended Format (IBM QRadar)
    Leef,
    /// Generic JSON logs
    Json,
    /// Windows Event Log (XML or EVTX)
    WindowsEvent,
    /// Raw/unstructured text
    Raw,
    /// HeroForge internal format
    HeroForge,
}

impl LogFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SyslogRfc3164 => "syslog_rfc3164",
            Self::SyslogRfc5424 => "syslog_rfc5424",
            Self::Cef => "cef",
            Self::Leef => "leef",
            Self::Json => "json",
            Self::WindowsEvent => "windows_event",
            Self::Raw => "raw",
            Self::HeroForge => "heroforge",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "syslog_rfc3164" | "rfc3164" | "bsd" => Some(Self::SyslogRfc3164),
            "syslog_rfc5424" | "rfc5424" | "syslog" => Some(Self::SyslogRfc5424),
            "cef" => Some(Self::Cef),
            "leef" => Some(Self::Leef),
            "json" => Some(Self::Json),
            "windows_event" | "windows" | "evtx" => Some(Self::WindowsEvent),
            "raw" | "text" => Some(Self::Raw),
            "heroforge" | "internal" => Some(Self::HeroForge),
            _ => None,
        }
    }
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::SyslogRfc5424
    }
}

/// Protocol used for log transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Udp,
    Tcp,
    TcpTls,
    Http,
    Https,
}

impl TransportProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::TcpTls => "tcp+tls",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl Default for TransportProtocol {
    fn default() -> Self {
        Self::Udp
    }
}

/// Status of a log source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogSourceStatus {
    Active,
    Inactive,
    Error,
    Pending,
}

impl LogSourceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Error => "error",
            Self::Pending => "pending",
        }
    }
}

impl Default for LogSourceStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Configuration for a log source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub id: SiemId,
    pub name: String,
    pub description: Option<String>,
    /// Type/category of the source (e.g., "firewall", "web_server", "ids")
    pub source_type: String,
    /// IP address or hostname of the source
    pub host: Option<String>,
    /// Expected log format
    pub format: LogFormat,
    /// Transport protocol for receiving logs
    pub protocol: TransportProtocol,
    /// Listening port for this source (if dedicated)
    pub port: Option<u16>,
    /// Status of the log source
    pub status: LogSourceStatus,
    /// Last time a log was received from this source
    pub last_seen: Option<DateTime<Utc>>,
    /// Total number of logs received
    pub log_count: i64,
    /// Number of logs received in the last hour
    pub logs_per_hour: i64,
    /// Custom parsing rules or patterns
    pub custom_patterns: Option<serde_json::Value>,
    /// Field mappings for normalization
    pub field_mappings: Option<HashMap<String, String>>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Whether to automatically parse and enrich logs
    pub auto_enrich: bool,
    /// Retention period in days (overrides global setting)
    pub retention_days: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

impl Default for LogSource {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            description: None,
            source_type: "generic".to_string(),
            host: None,
            format: LogFormat::default(),
            protocol: TransportProtocol::default(),
            port: None,
            status: LogSourceStatus::default(),
            last_seen: None,
            log_count: 0,
            logs_per_hour: 0,
            custom_patterns: None,
            field_mappings: None,
            tags: Vec::new(),
            auto_enrich: true,
            retention_days: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: None,
        }
    }
}

/// A normalized log entry stored in the SIEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unique identifier for this log entry
    pub id: SiemId,
    /// ID of the log source that sent this entry
    pub source_id: SiemId,
    /// Original timestamp from the log (if available)
    pub timestamp: DateTime<Utc>,
    /// Time when the log was received by the SIEM
    pub received_at: DateTime<Utc>,
    /// Severity level
    pub severity: SiemSeverity,
    /// Syslog facility (if applicable)
    pub facility: Option<SyslogFacility>,
    /// Original format of the log
    pub format: LogFormat,
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    /// Destination IP address
    pub destination_ip: Option<IpAddr>,
    /// Source port
    pub source_port: Option<u16>,
    /// Destination port
    pub destination_port: Option<u16>,
    /// Protocol (e.g., TCP, UDP, ICMP)
    pub protocol: Option<String>,
    /// Hostname of the source system
    pub hostname: Option<String>,
    /// Application/process name
    pub application: Option<String>,
    /// Process ID
    pub pid: Option<u32>,
    /// Message ID (RFC 5424)
    pub message_id: Option<String>,
    /// Structured data from RFC 5424 or extracted fields
    pub structured_data: HashMap<String, serde_json::Value>,
    /// The log message content
    pub message: String,
    /// Raw original log data
    pub raw: String,
    /// Event category (e.g., "authentication", "network", "application")
    pub category: Option<String>,
    /// Event action (e.g., "login", "logout", "blocked")
    pub action: Option<String>,
    /// Outcome/result (e.g., "success", "failure")
    pub outcome: Option<String>,
    /// User associated with the event
    pub user: Option<String>,
    /// Tags applied to this log
    pub tags: Vec<String>,
    /// Whether this log has triggered any alerts
    pub alerted: bool,
    /// IDs of alerts triggered by this log
    pub alert_ids: Vec<SiemId>,
    /// Partition date (YYYY-MM-DD) for storage
    pub partition_date: String,
}

impl LogEntry {
    /// Create a new log entry with minimal required fields
    pub fn new(source_id: SiemId, message: String, raw: String) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_id,
            timestamp: now,
            received_at: now,
            severity: SiemSeverity::default(),
            facility: None,
            format: LogFormat::default(),
            source_ip: None,
            destination_ip: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            hostname: None,
            application: None,
            pid: None,
            message_id: None,
            structured_data: HashMap::new(),
            message,
            raw,
            category: None,
            action: None,
            outcome: None,
            user: None,
            tags: Vec::new(),
            alerted: false,
            alert_ids: Vec::new(),
            partition_date: now.format("%Y-%m-%d").to_string(),
        }
    }

    /// Set the partition date based on the log timestamp
    pub fn update_partition_date(&mut self) {
        self.partition_date = self.timestamp.format("%Y-%m-%d").to_string();
    }
}

/// Type of detection rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    /// Simple pattern matching
    Pattern,
    /// Regular expression matching
    Regex,
    /// Threshold-based detection (count over time)
    Threshold,
    /// Correlation across multiple events
    Correlation,
    /// Statistical anomaly detection
    Anomaly,
    /// Machine learning based detection
    MachineLearning,
    /// Sigma rule format
    Sigma,
    /// YARA rule format
    Yara,
}

impl RuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::Regex => "regex",
            Self::Threshold => "threshold",
            Self::Correlation => "correlation",
            Self::Anomaly => "anomaly",
            Self::MachineLearning => "machine_learning",
            Self::Sigma => "sigma",
            Self::Yara => "yara",
        }
    }
}

impl Default for RuleType {
    fn default() -> Self {
        Self::Pattern
    }
}

/// Status of a detection rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Enabled,
    Disabled,
    Testing,
}

impl RuleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Testing => "testing",
        }
    }
}

impl Default for RuleStatus {
    fn default() -> Self {
        Self::Disabled
    }
}

/// A SIEM detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemRule {
    pub id: SiemId,
    pub name: String,
    pub description: Option<String>,
    /// Type of detection rule
    pub rule_type: RuleType,
    /// Severity of alerts generated by this rule
    pub severity: SiemSeverity,
    /// Status of the rule
    pub status: RuleStatus,
    /// Rule logic/definition (format depends on rule_type)
    pub definition: serde_json::Value,
    /// Log sources this rule applies to (empty = all sources)
    pub source_ids: Vec<SiemId>,
    /// Categories this rule applies to (empty = all categories)
    pub categories: Vec<String>,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// False positive rate (0.0 to 1.0)
    pub false_positive_rate: Option<f32>,
    /// Number of times this rule has triggered
    pub trigger_count: i64,
    /// Last time this rule triggered
    pub last_triggered: Option<DateTime<Utc>>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Custom response actions
    pub response_actions: Vec<String>,
    /// Time window for threshold/correlation rules (seconds)
    pub time_window_seconds: Option<i64>,
    /// Threshold count for threshold rules
    pub threshold_count: Option<i64>,
    /// Grouping fields for threshold/correlation rules
    pub group_by_fields: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

impl Default for SiemRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            description: None,
            rule_type: RuleType::default(),
            severity: SiemSeverity::Warning,
            status: RuleStatus::default(),
            definition: serde_json::json!({}),
            source_ids: Vec::new(),
            categories: Vec::new(),
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            false_positive_rate: None,
            trigger_count: 0,
            last_triggered: None,
            tags: Vec::new(),
            response_actions: Vec::new(),
            time_window_seconds: None,
            threshold_count: None,
            group_by_fields: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: None,
        }
    }
}

/// Status of a SIEM alert
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    New,
    InProgress,
    Escalated,
    Resolved,
    FalsePositive,
    Ignored,
}

impl AlertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::InProgress => "in_progress",
            Self::Escalated => "escalated",
            Self::Resolved => "resolved",
            Self::FalsePositive => "false_positive",
            Self::Ignored => "ignored",
        }
    }
}

impl Default for AlertStatus {
    fn default() -> Self {
        Self::New
    }
}

/// A SIEM alert generated by a detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemAlert {
    pub id: SiemId,
    /// ID of the rule that triggered this alert
    pub rule_id: SiemId,
    /// Name of the rule (denormalized for convenience)
    pub rule_name: String,
    /// Severity of the alert
    pub severity: SiemSeverity,
    /// Current status
    pub status: AlertStatus,
    /// Title/summary of the alert
    pub title: String,
    /// Detailed description
    pub description: Option<String>,
    /// IDs of log entries that triggered this alert
    pub log_entry_ids: Vec<SiemId>,
    /// Number of events in this alert
    pub event_count: i64,
    /// Source IPs involved
    pub source_ips: Vec<String>,
    /// Destination IPs involved
    pub destination_ips: Vec<String>,
    /// Users involved
    pub users: Vec<String>,
    /// Hosts involved
    pub hosts: Vec<String>,
    /// First event time
    pub first_seen: DateTime<Utc>,
    /// Last event time
    pub last_seen: DateTime<Utc>,
    /// Time alert was created
    pub created_at: DateTime<Utc>,
    /// Time alert was last updated
    pub updated_at: DateTime<Utc>,
    /// User assigned to investigate
    pub assigned_to: Option<String>,
    /// User who resolved the alert
    pub resolved_by: Option<String>,
    /// Time alert was resolved
    pub resolved_at: Option<DateTime<Utc>>,
    /// Resolution notes
    pub resolution_notes: Option<String>,
    /// MITRE ATT&CK tactics (from rule)
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques (from rule)
    pub mitre_techniques: Vec<String>,
    /// Tags
    pub tags: Vec<String>,
    /// Additional context/evidence
    pub context: serde_json::Value,
    /// Related alert IDs (for correlation)
    pub related_alert_ids: Vec<SiemId>,
    /// External ticket ID (e.g., JIRA, ServiceNow)
    pub external_ticket_id: Option<String>,
}

impl SiemAlert {
    /// Create a new alert from a rule and matching log entries
    pub fn new(rule: &SiemRule, log_entries: &[LogEntry]) -> Self {
        let now = Utc::now();
        let first_seen = log_entries
            .iter()
            .map(|e| e.timestamp)
            .min()
            .unwrap_or(now);
        let last_seen = log_entries
            .iter()
            .map(|e| e.timestamp)
            .max()
            .unwrap_or(now);

        // Collect unique IPs, users, and hosts
        let source_ips: Vec<String> = log_entries
            .iter()
            .filter_map(|e| e.source_ip.map(|ip| ip.to_string()))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let destination_ips: Vec<String> = log_entries
            .iter()
            .filter_map(|e| e.destination_ip.map(|ip| ip.to_string()))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let users: Vec<String> = log_entries
            .iter()
            .filter_map(|e| e.user.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let hosts: Vec<String> = log_entries
            .iter()
            .filter_map(|e| e.hostname.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity,
            status: AlertStatus::default(),
            title: rule.name.clone(),
            description: rule.description.clone(),
            log_entry_ids: log_entries.iter().map(|e| e.id.clone()).collect(),
            event_count: log_entries.len() as i64,
            source_ips,
            destination_ips,
            users,
            hosts,
            first_seen,
            last_seen,
            created_at: now,
            updated_at: now,
            assigned_to: None,
            resolved_by: None,
            resolved_at: None,
            resolution_notes: None,
            mitre_tactics: rule.mitre_tactics.clone(),
            mitre_techniques: rule.mitre_techniques.clone(),
            tags: rule.tags.clone(),
            context: serde_json::json!({}),
            related_alert_ids: Vec::new(),
            external_ticket_id: None,
        }
    }
}

/// Statistics for log ingestion
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngestionStats {
    /// Total logs received
    pub total_received: u64,
    /// Logs successfully parsed
    pub successfully_parsed: u64,
    /// Logs that failed to parse
    pub parse_failures: u64,
    /// Logs stored
    pub stored: u64,
    /// Logs dropped (due to rate limiting, errors, etc.)
    pub dropped: u64,
    /// Current ingestion rate (logs per second)
    pub logs_per_second: f64,
    /// Peak ingestion rate
    pub peak_logs_per_second: f64,
    /// Bytes received
    pub bytes_received: u64,
    /// Active connections (for TCP)
    pub active_connections: u32,
    /// Start time of stats collection
    pub started_at: DateTime<Utc>,
    /// Last update time
    pub updated_at: DateTime<Utc>,
}

impl IngestionStats {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            started_at: now,
            updated_at: now,
            ..Default::default()
        }
    }

    pub fn record_received(&mut self, bytes: usize) {
        self.total_received += 1;
        self.bytes_received += bytes as u64;
        self.updated_at = Utc::now();
    }

    pub fn record_parsed(&mut self) {
        self.successfully_parsed += 1;
    }

    pub fn record_parse_failure(&mut self) {
        self.parse_failures += 1;
    }

    pub fn record_stored(&mut self) {
        self.stored += 1;
    }

    pub fn record_dropped(&mut self) {
        self.dropped += 1;
    }
}

/// Query parameters for searching logs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogQuery {
    /// Full-text search query
    pub query: Option<String>,
    /// Filter by source IDs
    pub source_ids: Vec<SiemId>,
    /// Filter by severity (minimum)
    pub min_severity: Option<SiemSeverity>,
    /// Filter by severity (maximum)
    pub max_severity: Option<SiemSeverity>,
    /// Filter by categories
    pub categories: Vec<String>,
    /// Filter by source IP
    pub source_ip: Option<String>,
    /// Filter by destination IP
    pub destination_ip: Option<String>,
    /// Filter by hostname
    pub hostname: Option<String>,
    /// Filter by application
    pub application: Option<String>,
    /// Filter by user
    pub user: Option<String>,
    /// Filter by tags (any match)
    pub tags: Vec<String>,
    /// Filter logs that have triggered alerts
    pub alerted: Option<bool>,
    /// Start time (inclusive)
    pub start_time: Option<DateTime<Utc>>,
    /// End time (exclusive)
    pub end_time: Option<DateTime<Utc>>,
    /// Field-specific filters
    pub field_filters: HashMap<String, String>,
    /// Sort field
    pub sort_by: Option<String>,
    /// Sort order (true = ascending, false = descending)
    pub sort_asc: bool,
    /// Pagination offset
    pub offset: u32,
    /// Page size limit
    pub limit: u32,
}

impl LogQuery {
    pub fn new() -> Self {
        Self {
            limit: 100,
            ..Default::default()
        }
    }

    /// Create a query for the last N minutes
    pub fn last_minutes(minutes: i64) -> Self {
        let end = Utc::now();
        let start = end - chrono::Duration::minutes(minutes);
        Self {
            start_time: Some(start),
            end_time: Some(end),
            limit: 1000,
            ..Default::default()
        }
    }

    /// Create a query for logs from a specific source
    pub fn from_source(source_id: SiemId) -> Self {
        Self {
            source_ids: vec![source_id],
            limit: 100,
            ..Default::default()
        }
    }
}

/// Result of a log query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogQueryResult {
    /// Matching log entries
    pub entries: Vec<LogEntry>,
    /// Total number of matching entries (for pagination)
    pub total_count: u64,
    /// Query execution time in milliseconds
    pub query_time_ms: u64,
    /// Offset used
    pub offset: u32,
    /// Limit used
    pub limit: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(SiemSeverity::Emergency > SiemSeverity::Debug);
        assert!(SiemSeverity::Critical > SiemSeverity::Warning);
        assert!(SiemSeverity::Warning > SiemSeverity::Info);
    }

    #[test]
    fn test_severity_syslog_conversion() {
        assert_eq!(SiemSeverity::Emergency.to_syslog_priority(), 0);
        assert_eq!(SiemSeverity::Debug.to_syslog_priority(), 7);
        assert_eq!(SiemSeverity::from_syslog_priority(0), SiemSeverity::Emergency);
        assert_eq!(SiemSeverity::from_syslog_priority(7), SiemSeverity::Debug);
    }

    #[test]
    fn test_log_format_conversion() {
        assert_eq!(LogFormat::from_str("syslog"), Some(LogFormat::SyslogRfc5424));
        assert_eq!(LogFormat::from_str("cef"), Some(LogFormat::Cef));
        assert_eq!(LogFormat::from_str("json"), Some(LogFormat::Json));
        assert_eq!(LogFormat::from_str("unknown"), None);
    }

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(
            "source-1".to_string(),
            "Test message".to_string(),
            "raw log data".to_string(),
        );

        assert!(!entry.id.is_empty());
        assert_eq!(entry.source_id, "source-1");
        assert_eq!(entry.message, "Test message");
        assert!(!entry.partition_date.is_empty());
    }

    #[test]
    fn test_log_query_defaults() {
        let query = LogQuery::new();
        assert_eq!(query.limit, 100);
        assert_eq!(query.offset, 0);
        assert!(!query.sort_asc);
    }

    #[test]
    fn test_ingestion_stats() {
        let mut stats = IngestionStats::new();
        stats.record_received(100);
        stats.record_parsed();
        stats.record_stored();

        assert_eq!(stats.total_received, 1);
        assert_eq!(stats.successfully_parsed, 1);
        assert_eq!(stats.stored, 1);
        assert_eq!(stats.bytes_received, 100);
    }
}
