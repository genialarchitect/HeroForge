use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enumeration: Option<crate::scanner::enumeration::types::EnumerationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_info: Option<SslInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SslInfo {
    pub cert_valid: bool,
    pub cert_expired: bool,
    pub days_until_expiry: Option<i64>,
    pub self_signed: bool,
    pub hostname_mismatch: bool,
    pub issuer: String,
    pub subject: String,
    pub valid_from: String,
    pub valid_until: String,
    pub protocols: Vec<String>,
    pub cipher_suites: Vec<String>,
    pub weak_ciphers: Vec<String>,
    pub weak_protocols: Vec<String>,
    pub hsts_enabled: bool,
    pub hsts_max_age: Option<u64>,
    pub chain_issues: Vec<String>,
    /// SSL/TLS grade (A+ to F) with detailed breakdown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_grade: Option<crate::scanner::ssl_scanner::SslGrade>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub target: ScanTarget,
    pub is_alive: bool,
    pub os_guess: Option<OsInfo>,
    pub ports: Vec<PortInfo>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_family: String,
    pub os_version: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve_id: Option<String>,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub affected_service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub port_range: (u16, u16),
    pub threads: usize,
    pub timeout: Duration,
    pub scan_type: ScanType,
    pub enable_os_detection: bool,
    pub enable_service_detection: bool,
    pub enable_vuln_scan: bool,
    pub enable_enumeration: bool,
    pub enum_depth: crate::scanner::enumeration::types::EnumDepth,
    pub enum_wordlist_path: Option<PathBuf>,
    pub enum_services: Vec<crate::scanner::enumeration::types::ServiceType>,
    pub output_format: OutputFormat,
    // UDP-specific configuration
    pub udp_port_range: Option<(u16, u16)>,
    pub udp_retries: u8,
    // Skip host discovery and scan targets directly
    pub skip_host_discovery: bool,
    // Scanner-specific timeouts (optional, defaults used if not set)
    /// Timeout for service detection banner grabbing (default: 2s)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_detection_timeout: Option<Duration>,
    /// Timeout for DNS reconnaissance operations (default: 5s)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_timeout: Option<Duration>,
    /// Timeout for SYN scanner per port (default: 2s)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syn_timeout: Option<Duration>,
    /// Timeout for UDP scanner per port (default: 3s)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<Duration>,
    /// Optional VPN configuration ID to connect through before scanning
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_config_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    TCPConnect,
    TCPSyn,
    UDPScan,
    Comprehensive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Csv,
    Terminal,
    All,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            port_range: (1, 1000),
            threads: 100,
            timeout: Duration::from_secs(3),
            scan_type: ScanType::TCPConnect,
            enable_os_detection: true,
            enable_service_detection: true,
            enable_vuln_scan: false,
            enable_enumeration: false,
            enum_depth: crate::scanner::enumeration::types::EnumDepth::Light,
            enum_wordlist_path: None,
            enum_services: Vec::new(),
            output_format: OutputFormat::Terminal,
            udp_port_range: None,
            udp_retries: 2,
            skip_host_discovery: false,
            service_detection_timeout: None,
            dns_timeout: None,
            syn_timeout: None,
            udp_timeout: None,
            vpn_config_id: None,
        }
    }
}

#[allow(dead_code)]
impl ScanConfig {
    /// Get service detection timeout, defaulting to 2 seconds if not configured
    pub fn get_service_detection_timeout(&self) -> Duration {
        self.service_detection_timeout.unwrap_or(Duration::from_secs(2))
    }

    /// Get DNS timeout, defaulting to 5 seconds if not configured
    pub fn get_dns_timeout(&self) -> Duration {
        self.dns_timeout.unwrap_or(Duration::from_secs(5))
    }

    /// Get SYN scanner timeout, defaulting to 2 seconds if not configured
    pub fn get_syn_timeout(&self) -> Duration {
        self.syn_timeout.unwrap_or(Duration::from_secs(2))
    }

    /// Get UDP scanner timeout, defaulting to 3 seconds if not configured
    pub fn get_udp_timeout(&self) -> Duration {
        self.udp_timeout.unwrap_or(Duration::from_secs(3))
    }
}

// DNS Reconnaissance result (re-exported from scanner module)
pub use crate::scanner::dns_recon::DnsReconResult;

// WebSocket progress message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScanProgressMessage {
    ScanStarted {
        scan_id: String,
        timestamp: String,
    },
    PhaseStarted {
        phase: String,
        progress: f32,
    },
    HostDiscovered {
        ip: String,
        hostname: Option<String>,
    },
    PortFound {
        ip: String,
        port: u16,
        protocol: String,
        state: String,
    },
    ServiceDetected {
        ip: String,
        port: u16,
        service_name: String,
        version: Option<String>,
    },
    VulnerabilityFound {
        ip: String,
        cve_id: Option<String>,
        severity: String,
        title: String,
    },
    EnumerationStarted {
        ip: String,
        port: u16,
        service_type: String,
    },
    EnumerationFinding {
        ip: String,
        port: u16,
        finding_type: String,
        value: String,
    },
    EnumerationCompleted {
        ip: String,
        port: u16,
        findings_count: usize,
    },
    DnsRecordFound {
        domain: String,
        record_type: String,
        value: String,
    },
    SubdomainFound {
        subdomain: String,
    },
    ScanProgress {
        phase: String,
        progress: f32,
        message: String,
    },
    ScanCompleted {
        scan_id: String,
        duration: f64,
        total_hosts: usize,
    },
    Error {
        message: String,
    },
    // VPN connection status messages
    VpnConnecting {
        config_name: String,
    },
    VpnConnected {
        config_name: String,
        assigned_ip: Option<String>,
    },
    VpnDisconnecting {
        config_name: String,
    },
    VpnDisconnected {
        config_name: String,
    },
    VpnError {
        config_name: String,
        message: String,
    },
}

// Web Application Scanning types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAppScanResult {
    pub url: String,
    pub pages_crawled: usize,
    pub findings: Vec<WebAppFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAppFinding {
    pub finding_type: FindingType,
    pub url: String,
    pub parameter: Option<String>,
    pub evidence: String,
    pub severity: Severity,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    MissingSecurityHeader,
    InsecureHeader,
    SqlInjection,
    CrossSiteScripting,
    SensitiveInfoDisclosure,
    InsecureForm,
    WeakCryptography,
    DirectoryListing,
    Other,
}
