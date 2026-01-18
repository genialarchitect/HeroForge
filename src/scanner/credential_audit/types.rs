#![allow(dead_code)]
//! Types for credential auditing

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Supported service types for credential auditing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialServiceType {
    // Remote access
    Ssh,
    Telnet,
    Rdp,
    Vnc,

    // File transfer
    Ftp,

    // Databases
    Mysql,
    Postgresql,
    Mssql,
    Mongodb,
    Redis,
    Oracle,
    Memcached,
    Cassandra,
    InfluxDb,
    Elasticsearch,
    CouchDb,
    ClickHouse,

    // Web panels
    TomcatManager,
    PhpMyAdmin,
    WordPress,
    Joomla,
    Drupal,

    // Network devices
    Snmp,
    RouterOs,
    CiscoIos,

    // Other services
    Smtp,
    Pop3,
    Imap,
}

impl CredentialServiceType {
    /// Get the default port for this service type
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Telnet => 23,
            Self::Rdp => 3389,
            Self::Vnc => 5900,
            Self::Ftp => 21,
            Self::Mysql => 3306,
            Self::Postgresql => 5432,
            Self::Mssql => 1433,
            Self::Mongodb => 27017,
            Self::Redis => 6379,
            Self::Oracle => 1521,
            Self::Memcached => 11211,
            Self::Cassandra => 9042,
            Self::InfluxDb => 8086,
            Self::Elasticsearch => 9200,
            Self::CouchDb => 5984,
            Self::ClickHouse => 8123,
            Self::TomcatManager => 8080,
            Self::PhpMyAdmin => 80,
            Self::WordPress => 80,
            Self::Joomla => 80,
            Self::Drupal => 80,
            Self::Snmp => 161,
            Self::RouterOs => 8728,
            Self::CiscoIos => 23,
            Self::Smtp => 25,
            Self::Pop3 => 110,
            Self::Imap => 143,
        }
    }

    /// Get a human-readable name for the service
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Ssh => "SSH",
            Self::Telnet => "Telnet",
            Self::Rdp => "RDP",
            Self::Vnc => "VNC",
            Self::Ftp => "FTP",
            Self::Mysql => "MySQL",
            Self::Postgresql => "PostgreSQL",
            Self::Mssql => "Microsoft SQL Server",
            Self::Mongodb => "MongoDB",
            Self::Redis => "Redis",
            Self::Oracle => "Oracle Database",
            Self::Memcached => "Memcached",
            Self::Cassandra => "Apache Cassandra",
            Self::InfluxDb => "InfluxDB",
            Self::Elasticsearch => "Elasticsearch",
            Self::CouchDb => "CouchDB",
            Self::ClickHouse => "ClickHouse",
            Self::TomcatManager => "Tomcat Manager",
            Self::PhpMyAdmin => "phpMyAdmin",
            Self::WordPress => "WordPress",
            Self::Joomla => "Joomla",
            Self::Drupal => "Drupal",
            Self::Snmp => "SNMP",
            Self::RouterOs => "MikroTik RouterOS",
            Self::CiscoIos => "Cisco IOS",
            Self::Smtp => "SMTP",
            Self::Pop3 => "POP3",
            Self::Imap => "IMAP",
        }
    }

    /// Parse service type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ssh" => Some(Self::Ssh),
            "telnet" => Some(Self::Telnet),
            "rdp" | "remote_desktop" => Some(Self::Rdp),
            "vnc" => Some(Self::Vnc),
            "ftp" => Some(Self::Ftp),
            "mysql" => Some(Self::Mysql),
            "postgresql" | "postgres" => Some(Self::Postgresql),
            "mssql" | "sqlserver" | "sql_server" => Some(Self::Mssql),
            "mongodb" | "mongo" => Some(Self::Mongodb),
            "redis" => Some(Self::Redis),
            "oracle" | "ora" => Some(Self::Oracle),
            "memcached" | "memcache" => Some(Self::Memcached),
            "cassandra" | "cql" => Some(Self::Cassandra),
            "influxdb" | "influx" => Some(Self::InfluxDb),
            "elasticsearch" | "elastic" | "es" => Some(Self::Elasticsearch),
            "couchdb" | "couch" => Some(Self::CouchDb),
            "clickhouse" => Some(Self::ClickHouse),
            "tomcat" | "tomcat_manager" => Some(Self::TomcatManager),
            "phpmyadmin" | "pma" => Some(Self::PhpMyAdmin),
            "wordpress" | "wp" => Some(Self::WordPress),
            "joomla" => Some(Self::Joomla),
            "drupal" => Some(Self::Drupal),
            "snmp" => Some(Self::Snmp),
            "routeros" | "mikrotik" => Some(Self::RouterOs),
            "cisco" | "cisco_ios" => Some(Self::CiscoIos),
            "smtp" => Some(Self::Smtp),
            "pop3" => Some(Self::Pop3),
            "imap" => Some(Self::Imap),
            _ => None,
        }
    }
}

impl std::fmt::Display for CredentialServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// A credential pair to test
#[derive(Debug, Clone)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// Result of a single credential test attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTestResult {
    /// Whether authentication succeeded
    pub success: bool,
    /// The username that was tested
    pub username: String,
    /// Hashed representation of the password (for audit logging)
    /// SECURITY: We never store or return the actual password
    pub password_hash: String,
    /// Error message if the test failed (connection error, etc.)
    pub error: Option<String>,
    /// Time taken for this attempt
    pub duration_ms: u64,
}

/// Target for credential auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAuditTarget {
    pub host: String,
    pub port: u16,
    pub service_type: CredentialServiceType,
    /// Optional URL path for web-based services
    pub path: Option<String>,
    /// Whether to use SSL/TLS
    pub use_ssl: bool,
}

impl CredentialAuditTarget {
    pub fn new(host: impl Into<String>, port: u16, service_type: CredentialServiceType) -> Self {
        Self {
            host: host.into(),
            port,
            service_type,
            path: None,
            use_ssl: false,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_ssl(mut self, use_ssl: bool) -> Self {
        self.use_ssl = use_ssl;
        self
    }
}

/// Configuration for credential audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAuditConfig {
    /// Targets to audit
    pub targets: Vec<CredentialAuditTarget>,
    /// Service types to test (empty = all detected)
    pub service_types: Vec<CredentialServiceType>,
    /// Custom credentials to test (in addition to built-in defaults)
    pub custom_credentials: Vec<(String, String)>,
    /// Custom wordlist ID to use (from database)
    pub wordlist_id: Option<String>,
    /// Maximum concurrent connections per host
    pub max_concurrent: usize,
    /// Delay between attempts in milliseconds (to avoid lockouts)
    pub delay_between_attempts_ms: u64,
    /// Connection timeout
    pub timeout: Duration,
    /// Maximum attempts per account before stopping (to avoid lockouts)
    pub max_attempts_per_account: usize,
    /// Whether to stop on first successful credential
    pub stop_on_success: bool,
    /// Whether to use default credentials only (faster)
    pub default_creds_only: bool,
}

impl Default for CredentialAuditConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            service_types: Vec::new(),
            custom_credentials: Vec::new(),
            wordlist_id: None,
            max_concurrent: 5,
            delay_between_attempts_ms: 1000, // 1 second between attempts
            timeout: Duration::from_secs(10),
            max_attempts_per_account: 3, // Conservative to avoid lockouts
            stop_on_success: true,
            default_creds_only: false,
        }
    }
}

/// Status of a credential audit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialAuditStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Summary of credential audit results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAuditSummary {
    pub total_targets: usize,
    pub total_attempts: usize,
    pub successful_logins: usize,
    pub failed_attempts: usize,
    pub connection_errors: usize,
    pub services_tested: Vec<CredentialServiceType>,
}

/// Full credential audit result for a single target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAuditResult {
    pub target: CredentialAuditTarget,
    pub successful_credentials: Vec<CredentialTestResult>,
    pub failed_attempts: usize,
    pub connection_errors: usize,
    pub error_message: Option<String>,
}

/// Complete credential audit results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAuditResult {
    pub id: String,
    pub status: CredentialAuditStatus,
    pub config: CredentialAuditConfig,
    pub results: Vec<TargetAuditResult>,
    pub summary: CredentialAuditSummary,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_secs: Option<f64>,
}

/// Progress message for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialAuditProgress {
    Started {
        id: String,
        total_targets: usize,
    },
    TargetStarted {
        host: String,
        port: u16,
        service_type: CredentialServiceType,
    },
    AttemptMade {
        host: String,
        port: u16,
        username: String,
        success: bool,
    },
    TargetCompleted {
        host: String,
        port: u16,
        successful_logins: usize,
    },
    Completed {
        id: String,
        summary: CredentialAuditSummary,
    },
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_from_str() {
        assert_eq!(CredentialServiceType::from_str("ssh"), Some(CredentialServiceType::Ssh));
        assert_eq!(CredentialServiceType::from_str("SSH"), Some(CredentialServiceType::Ssh));
        assert_eq!(CredentialServiceType::from_str("mysql"), Some(CredentialServiceType::Mysql));
        assert_eq!(CredentialServiceType::from_str("postgres"), Some(CredentialServiceType::Postgresql));
        assert_eq!(CredentialServiceType::from_str("unknown"), None);
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(CredentialServiceType::Ssh.default_port(), 22);
        assert_eq!(CredentialServiceType::Mysql.default_port(), 3306);
        assert_eq!(CredentialServiceType::Rdp.default_port(), 3389);
    }

    #[test]
    fn test_credential_audit_config_default() {
        let config = CredentialAuditConfig::default();
        assert_eq!(config.max_concurrent, 5);
        assert_eq!(config.delay_between_attempts_ms, 1000);
        assert_eq!(config.max_attempts_per_account, 3);
    }
}
