//! Types for topology import from external network scanning tools
//!
//! Supports parsing output from: nmap, masscan, netcat, rustscan

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Source tool for topology import
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyImportSource {
    NmapXml,
    NmapGrepable,
    MasscanJson,
    NetcatLog,
    Rustscan,
}

impl std::fmt::Display for TopologyImportSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TopologyImportSource::NmapXml => write!(f, "nmap_xml"),
            TopologyImportSource::NmapGrepable => write!(f, "nmap_grepable"),
            TopologyImportSource::MasscanJson => write!(f, "masscan_json"),
            TopologyImportSource::NetcatLog => write!(f, "netcat_log"),
            TopologyImportSource::Rustscan => write!(f, "rustscan"),
        }
    }
}

/// Host status from scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
    #[default]
    Unknown,
}

/// Port state from scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    #[default]
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
}

impl PortState {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "open" => PortState::Open,
            "closed" => PortState::Closed,
            "filtered" => PortState::Filtered,
            "open|filtered" => PortState::OpenFiltered,
            "closed|filtered" => PortState::ClosedFiltered,
            _ => PortState::Open,
        }
    }
}

/// NSE script result from nmap
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScriptResult {
    pub id: String,
    pub output: String,
}

/// Port information from scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedPort {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub banner: Option<String>,
    pub scripts: Vec<ScriptResult>,
}

impl Default for ImportedPort {
    fn default() -> Self {
        ImportedPort {
            port: 0,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: None,
            product: None,
            version: None,
            extra_info: None,
            banner: None,
            scripts: Vec::new(),
        }
    }
}

/// Host information from scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedTopologyHost {
    pub ip: String,
    pub ipv6: Option<String>,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub mac_vendor: Option<String>,
    pub os: Option<String>,
    pub os_accuracy: Option<u8>,
    pub os_family: Option<String>,
    pub ports: Vec<ImportedPort>,
    pub status: HostStatus,
    pub status_reason: Option<String>,
    pub distance: Option<u8>,
    pub uptime: Option<u64>,
    pub last_boot: Option<String>,
    pub scan_time: Option<DateTime<Utc>>,
}

impl Default for ImportedTopologyHost {
    fn default() -> Self {
        ImportedTopologyHost {
            ip: String::new(),
            ipv6: None,
            hostname: None,
            mac_address: None,
            mac_vendor: None,
            os: None,
            os_accuracy: None,
            os_family: None,
            ports: Vec::new(),
            status: HostStatus::Unknown,
            status_reason: None,
            distance: None,
            uptime: None,
            last_boot: None,
            scan_time: None,
        }
    }
}

/// Scan metadata from tool output
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanMetadata {
    pub scanner: String,
    pub scanner_version: Option<String>,
    pub scan_type: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub command_line: Option<String>,
    pub target_spec: Option<String>,
}

/// Result of parsing a tool output file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyImportResult {
    pub source: TopologyImportSource,
    pub hosts: Vec<ImportedTopologyHost>,
    pub metadata: ScanMetadata,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl Default for TopologyImportResult {
    fn default() -> Self {
        TopologyImportResult {
            source: TopologyImportSource::NmapXml,
            hosts: Vec::new(),
            metadata: ScanMetadata::default(),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl TopologyImportResult {
    pub fn new(source: TopologyImportSource) -> Self {
        TopologyImportResult {
            source,
            ..Default::default()
        }
    }

    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.errors.push(error.into());
        self
    }

    /// Count total open ports across all hosts
    pub fn total_open_ports(&self) -> usize {
        self.hosts
            .iter()
            .flat_map(|h| &h.ports)
            .filter(|p| p.state == PortState::Open)
            .count()
    }

    /// Count hosts that are up
    pub fn hosts_up(&self) -> usize {
        self.hosts.iter().filter(|h| h.status == HostStatus::Up).count()
    }
}

/// Supported format information for API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedFormat {
    pub id: TopologyImportSource,
    pub name: String,
    pub description: String,
    pub extensions: Vec<String>,
    pub example_command: Option<String>,
}

/// Get all supported import formats
pub fn get_supported_formats() -> Vec<SupportedFormat> {
    vec![
        SupportedFormat {
            id: TopologyImportSource::NmapXml,
            name: "Nmap XML".to_string(),
            description: "Nmap XML output with full host/port/service details".to_string(),
            extensions: vec!["xml".to_string()],
            example_command: Some("nmap -sV -oX output.xml <target>".to_string()),
        },
        SupportedFormat {
            id: TopologyImportSource::NmapGrepable,
            name: "Nmap Grepable".to_string(),
            description: "Nmap grepable output format (one line per host)".to_string(),
            extensions: vec!["gnmap".to_string(), "greppable".to_string()],
            example_command: Some("nmap -sV -oG output.gnmap <target>".to_string()),
        },
        SupportedFormat {
            id: TopologyImportSource::MasscanJson,
            name: "Masscan JSON".to_string(),
            description: "Masscan JSON output from high-speed port scanning".to_string(),
            extensions: vec!["json".to_string()],
            example_command: Some("masscan -p1-65535 --rate=10000 -oJ output.json <target>".to_string()),
        },
        SupportedFormat {
            id: TopologyImportSource::NetcatLog,
            name: "Netcat Log".to_string(),
            description: "Netcat connection test output logs".to_string(),
            extensions: vec!["txt".to_string(), "log".to_string()],
            example_command: Some("nc -zv <host> 1-1000 2>&1 | tee output.txt".to_string()),
        },
        SupportedFormat {
            id: TopologyImportSource::Rustscan,
            name: "Rustscan".to_string(),
            description: "Rustscan output (fast port scanner)".to_string(),
            extensions: vec!["txt".to_string(), "rs".to_string()],
            example_command: Some("rustscan -a <target> --greppable > output.txt".to_string()),
        },
    ]
}
