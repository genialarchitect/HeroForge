//! IoT Type Definitions
//!
//! Core data structures for IoT device management and security assessment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// IoT Device Type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IotDeviceType {
    /// IP Camera
    Camera,
    /// Smart Thermostat
    Thermostat,
    /// Smart Speaker / Voice Assistant
    Speaker,
    /// Smart Hub / Gateway
    Hub,
    /// Environmental Sensor
    Sensor,
    /// Smart Lock
    Lock,
    /// Smart Light / Bulb
    Light,
    /// Smart Plug / Outlet
    Plug,
    /// DVR / NVR
    Dvr,
    /// Router / Access Point
    Router,
    /// Smart TV
    Tv,
    /// Smart Appliance
    Appliance,
    /// Industrial IoT (IIoT)
    Industrial,
    /// Medical IoT
    Medical,
    /// Building Automation
    BuildingAutomation,
    /// Unknown device type
    Unknown,
}

impl fmt::Display for IotDeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IotDeviceType::Camera => write!(f, "Camera"),
            IotDeviceType::Thermostat => write!(f, "Thermostat"),
            IotDeviceType::Speaker => write!(f, "Smart Speaker"),
            IotDeviceType::Hub => write!(f, "Hub/Gateway"),
            IotDeviceType::Sensor => write!(f, "Sensor"),
            IotDeviceType::Lock => write!(f, "Smart Lock"),
            IotDeviceType::Light => write!(f, "Smart Light"),
            IotDeviceType::Plug => write!(f, "Smart Plug"),
            IotDeviceType::Dvr => write!(f, "DVR/NVR"),
            IotDeviceType::Router => write!(f, "Router/AP"),
            IotDeviceType::Tv => write!(f, "Smart TV"),
            IotDeviceType::Appliance => write!(f, "Smart Appliance"),
            IotDeviceType::Industrial => write!(f, "Industrial IoT"),
            IotDeviceType::Medical => write!(f, "Medical IoT"),
            IotDeviceType::BuildingAutomation => write!(f, "Building Automation"),
            IotDeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::str::FromStr for IotDeviceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "camera" => Ok(IotDeviceType::Camera),
            "thermostat" => Ok(IotDeviceType::Thermostat),
            "speaker" | "smart_speaker" => Ok(IotDeviceType::Speaker),
            "hub" | "gateway" => Ok(IotDeviceType::Hub),
            "sensor" => Ok(IotDeviceType::Sensor),
            "lock" | "smart_lock" => Ok(IotDeviceType::Lock),
            "light" | "smart_light" | "bulb" => Ok(IotDeviceType::Light),
            "plug" | "smart_plug" | "outlet" => Ok(IotDeviceType::Plug),
            "dvr" | "nvr" => Ok(IotDeviceType::Dvr),
            "router" | "ap" | "access_point" => Ok(IotDeviceType::Router),
            "tv" | "smart_tv" => Ok(IotDeviceType::Tv),
            "appliance" => Ok(IotDeviceType::Appliance),
            "industrial" | "iiot" => Ok(IotDeviceType::Industrial),
            "medical" => Ok(IotDeviceType::Medical),
            "building" | "building_automation" => Ok(IotDeviceType::BuildingAutomation),
            _ => Ok(IotDeviceType::Unknown),
        }
    }
}

/// IoT Protocol Types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IotProtocolType {
    /// MQTT (Message Queuing Telemetry Transport)
    Mqtt,
    /// CoAP (Constrained Application Protocol)
    Coap,
    /// HTTP/HTTPS
    Http,
    /// Telnet
    Telnet,
    /// SSH
    Ssh,
    /// FTP
    Ftp,
    /// RTSP (Real Time Streaming Protocol)
    Rtsp,
    /// ONVIF (Open Network Video Interface Forum)
    Onvif,
    /// UPnP (Universal Plug and Play)
    Upnp,
    /// mDNS/DNS-SD (Multicast DNS / DNS Service Discovery)
    Mdns,
    /// Zigbee (via gateway)
    Zigbee,
    /// Z-Wave (via gateway)
    Zwave,
    /// BLE (Bluetooth Low Energy)
    Ble,
}

impl fmt::Display for IotProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IotProtocolType::Mqtt => write!(f, "MQTT"),
            IotProtocolType::Coap => write!(f, "CoAP"),
            IotProtocolType::Http => write!(f, "HTTP"),
            IotProtocolType::Telnet => write!(f, "Telnet"),
            IotProtocolType::Ssh => write!(f, "SSH"),
            IotProtocolType::Ftp => write!(f, "FTP"),
            IotProtocolType::Rtsp => write!(f, "RTSP"),
            IotProtocolType::Onvif => write!(f, "ONVIF"),
            IotProtocolType::Upnp => write!(f, "UPnP"),
            IotProtocolType::Mdns => write!(f, "mDNS"),
            IotProtocolType::Zigbee => write!(f, "Zigbee"),
            IotProtocolType::Zwave => write!(f, "Z-Wave"),
            IotProtocolType::Ble => write!(f, "BLE"),
        }
    }
}

impl std::str::FromStr for IotProtocolType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mqtt" => Ok(IotProtocolType::Mqtt),
            "coap" => Ok(IotProtocolType::Coap),
            "http" | "https" => Ok(IotProtocolType::Http),
            "telnet" => Ok(IotProtocolType::Telnet),
            "ssh" => Ok(IotProtocolType::Ssh),
            "ftp" => Ok(IotProtocolType::Ftp),
            "rtsp" => Ok(IotProtocolType::Rtsp),
            "onvif" => Ok(IotProtocolType::Onvif),
            "upnp" => Ok(IotProtocolType::Upnp),
            "mdns" | "dns-sd" => Ok(IotProtocolType::Mdns),
            "zigbee" => Ok(IotProtocolType::Zigbee),
            "zwave" | "z-wave" => Ok(IotProtocolType::Zwave),
            "ble" | "bluetooth" => Ok(IotProtocolType::Ble),
            _ => Err(format!("Unknown protocol: {}", s)),
        }
    }
}

/// Default Credentials Status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultCredsStatus {
    /// Device uses default credentials - vulnerable
    Vulnerable,
    /// Default credentials have been changed
    Changed,
    /// Could not determine credential status
    Unknown,
    /// No credentials required (open access)
    NotRequired,
}

impl fmt::Display for DefaultCredsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefaultCredsStatus::Vulnerable => write!(f, "Vulnerable"),
            DefaultCredsStatus::Changed => write!(f, "Changed"),
            DefaultCredsStatus::Unknown => write!(f, "Unknown"),
            DefaultCredsStatus::NotRequired => write!(f, "Not Required"),
        }
    }
}

impl std::str::FromStr for DefaultCredsStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vulnerable" => Ok(DefaultCredsStatus::Vulnerable),
            "changed" => Ok(DefaultCredsStatus::Changed),
            "unknown" => Ok(DefaultCredsStatus::Unknown),
            "not_required" | "notrequired" | "open" => Ok(DefaultCredsStatus::NotRequired),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// IoT Scan Type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IotScanType {
    /// Device discovery
    Discovery,
    /// Credential check
    Credential,
    /// Vulnerability assessment
    Vulnerability,
    /// Comprehensive scan
    Comprehensive,
}

impl fmt::Display for IotScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IotScanType::Discovery => write!(f, "Discovery"),
            IotScanType::Credential => write!(f, "Credential"),
            IotScanType::Vulnerability => write!(f, "Vulnerability"),
            IotScanType::Comprehensive => write!(f, "Comprehensive"),
        }
    }
}

impl std::str::FromStr for IotScanType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "discovery" => Ok(IotScanType::Discovery),
            "credential" => Ok(IotScanType::Credential),
            "vulnerability" => Ok(IotScanType::Vulnerability),
            "comprehensive" => Ok(IotScanType::Comprehensive),
            _ => Err(format!("Unknown scan type: {}", s)),
        }
    }
}

/// Scan Status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanStatus::Pending => write!(f, "Pending"),
            ScanStatus::Running => write!(f, "Running"),
            ScanStatus::Completed => write!(f, "Completed"),
            ScanStatus::Failed => write!(f, "Failed"),
            ScanStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

impl std::str::FromStr for ScanStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ScanStatus::Pending),
            "running" => Ok(ScanStatus::Running),
            "completed" => Ok(ScanStatus::Completed),
            "failed" => Ok(ScanStatus::Failed),
            "cancelled" => Ok(ScanStatus::Cancelled),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// IoT Device representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotDevice {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub device_type: IotDeviceType,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub protocols: Vec<IotProtocolType>,
    pub open_ports: Vec<u16>,
    pub default_creds_status: DefaultCredsStatus,
    pub last_seen: Option<DateTime<Utc>>,
    pub first_seen: Option<DateTime<Utc>>,
    pub risk_score: i32,
    pub notes: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// IoT Scan configuration and results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotScan {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub scan_type: IotScanType,
    pub target_range: Option<String>,
    pub status: ScanStatus,
    pub devices_found: i32,
    pub vulnerabilities_found: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// IoT Scan Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotScanConfig {
    pub name: String,
    pub target_range: Option<String>,
    pub scan_type: IotScanType,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
    /// Enable SSDP/UPnP discovery
    pub enable_ssdp: bool,
    /// Enable MQTT broker discovery
    pub enable_mqtt: bool,
    /// Check default credentials
    pub check_credentials: bool,
    /// Scan timeout in seconds
    pub timeout_secs: u64,
    /// Maximum concurrent connections
    pub max_concurrent: usize,
    /// Customer ID for CRM integration
    pub customer_id: Option<String>,
    /// Engagement ID for CRM integration
    pub engagement_id: Option<String>,
}

impl Default for IotScanConfig {
    fn default() -> Self {
        Self {
            name: "IoT Scan".to_string(),
            target_range: None,
            scan_type: IotScanType::Discovery,
            enable_mdns: true,
            enable_ssdp: true,
            enable_mqtt: true,
            check_credentials: false, // Safe default
            timeout_secs: 30,
            max_concurrent: 20,
            customer_id: None,
            engagement_id: None,
        }
    }
}

/// IoT Credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotCredential {
    pub id: String,
    pub device_type: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub source: String, // 'default', 'leaked', 'common'
    pub created_at: DateTime<Utc>,
}

/// Credential check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCheckResult {
    pub device_id: String,
    pub ip_address: String,
    pub protocol: IotProtocolType,
    pub port: u16,
    pub success: bool,
    pub username: Option<String>,
    pub is_default: bool,
    pub message: String,
}

/// IoT Vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotVulnerability {
    pub id: String,
    pub device_id: String,
    pub cve_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub remediation: Option<String>,
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IotDashboardStats {
    pub total_devices: i32,
    pub devices_by_type: Vec<TypeCount>,
    pub devices_with_default_creds: i32,
    pub devices_by_vendor: Vec<VendorCount>,
    pub recent_scans: Vec<IotScan>,
    pub risk_distribution: Vec<RiskCount>,
    pub protocol_usage: Vec<ProtocolCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeCount {
    pub device_type: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorCount {
    pub vendor: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCount {
    pub risk_level: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCount {
    pub protocol: String,
    pub count: i32,
}
