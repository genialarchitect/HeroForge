//! OT/ICS Type Definitions
//!
//! Core data structures for OT asset management and protocol scanning.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// OT Asset Types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OtAssetType {
    /// Programmable Logic Controller
    Plc,
    /// Human-Machine Interface
    Hmi,
    /// Supervisory Control and Data Acquisition
    Scada,
    /// Remote Terminal Unit
    Rtu,
    /// Intelligent Electronic Device
    Ied,
    /// Distributed Control System
    Dcs,
    /// Historian/Data Historian
    Historian,
    /// Engineering Workstation
    EngineeringWorkstation,
    /// Field Device (sensors, actuators)
    FieldDevice,
    /// Safety Instrumented System
    Sis,
    /// Unknown device type
    Unknown,
}

impl fmt::Display for OtAssetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtAssetType::Plc => write!(f, "PLC"),
            OtAssetType::Hmi => write!(f, "HMI"),
            OtAssetType::Scada => write!(f, "SCADA"),
            OtAssetType::Rtu => write!(f, "RTU"),
            OtAssetType::Ied => write!(f, "IED"),
            OtAssetType::Dcs => write!(f, "DCS"),
            OtAssetType::Historian => write!(f, "Historian"),
            OtAssetType::EngineeringWorkstation => write!(f, "Engineering Workstation"),
            OtAssetType::FieldDevice => write!(f, "Field Device"),
            OtAssetType::Sis => write!(f, "SIS"),
            OtAssetType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::str::FromStr for OtAssetType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plc" => Ok(OtAssetType::Plc),
            "hmi" => Ok(OtAssetType::Hmi),
            "scada" => Ok(OtAssetType::Scada),
            "rtu" => Ok(OtAssetType::Rtu),
            "ied" => Ok(OtAssetType::Ied),
            "dcs" => Ok(OtAssetType::Dcs),
            "historian" => Ok(OtAssetType::Historian),
            "engineering_workstation" => Ok(OtAssetType::EngineeringWorkstation),
            "field_device" => Ok(OtAssetType::FieldDevice),
            "sis" => Ok(OtAssetType::Sis),
            "unknown" | _ => Ok(OtAssetType::Unknown),
        }
    }
}

/// Industrial Protocol Types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OtProtocolType {
    /// Modbus TCP/RTU
    Modbus,
    /// DNP3 (Distributed Network Protocol)
    Dnp3,
    /// OPC UA (Open Platform Communications Unified Architecture)
    OpcUa,
    /// BACnet (Building Automation and Control Networks)
    Bacnet,
    /// EtherNet/IP (Industrial Protocol)
    EthernetIp,
    /// Siemens S7 Protocol
    S7,
    /// IEC 61850 (Power Utility Automation)
    Iec61850,
    /// PROFINET
    Profinet,
    /// HART (Highway Addressable Remote Transducer)
    Hart,
    /// CIP (Common Industrial Protocol)
    Cip,
    /// MQTT (for IoT/IIoT)
    Mqtt,
    /// CoAP (Constrained Application Protocol)
    Coap,
}

impl fmt::Display for OtProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtProtocolType::Modbus => write!(f, "Modbus"),
            OtProtocolType::Dnp3 => write!(f, "DNP3"),
            OtProtocolType::OpcUa => write!(f, "OPC UA"),
            OtProtocolType::Bacnet => write!(f, "BACnet"),
            OtProtocolType::EthernetIp => write!(f, "EtherNet/IP"),
            OtProtocolType::S7 => write!(f, "S7"),
            OtProtocolType::Iec61850 => write!(f, "IEC 61850"),
            OtProtocolType::Profinet => write!(f, "PROFINET"),
            OtProtocolType::Hart => write!(f, "HART"),
            OtProtocolType::Cip => write!(f, "CIP"),
            OtProtocolType::Mqtt => write!(f, "MQTT"),
            OtProtocolType::Coap => write!(f, "CoAP"),
        }
    }
}

impl std::str::FromStr for OtProtocolType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "modbus" => Ok(OtProtocolType::Modbus),
            "dnp3" => Ok(OtProtocolType::Dnp3),
            "opcua" | "opc_ua" | "opc-ua" => Ok(OtProtocolType::OpcUa),
            "bacnet" => Ok(OtProtocolType::Bacnet),
            "ethernetip" | "ethernet_ip" | "ethernet-ip" => Ok(OtProtocolType::EthernetIp),
            "s7" => Ok(OtProtocolType::S7),
            "iec61850" | "iec_61850" => Ok(OtProtocolType::Iec61850),
            "profinet" => Ok(OtProtocolType::Profinet),
            "hart" => Ok(OtProtocolType::Hart),
            "cip" => Ok(OtProtocolType::Cip),
            "mqtt" => Ok(OtProtocolType::Mqtt),
            "coap" => Ok(OtProtocolType::Coap),
            _ => Err(format!("Unknown protocol type: {}", s)),
        }
    }
}

/// Asset Criticality Level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Criticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Criticality::Low => write!(f, "Low"),
            Criticality::Medium => write!(f, "Medium"),
            Criticality::High => write!(f, "High"),
            Criticality::Critical => write!(f, "Critical"),
        }
    }
}

impl std::str::FromStr for Criticality {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Criticality::Low),
            "medium" => Ok(Criticality::Medium),
            "high" => Ok(Criticality::High),
            "critical" => Ok(Criticality::Critical),
            _ => Err(format!("Unknown criticality level: {}", s)),
        }
    }
}

/// OT Scan Type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OtScanType {
    /// Passive discovery (network monitoring only)
    Discovery,
    /// Protocol-specific scanning
    Protocol,
    /// Vulnerability assessment
    Vulnerability,
    /// Comprehensive scan (all types)
    Comprehensive,
}

impl fmt::Display for OtScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtScanType::Discovery => write!(f, "Discovery"),
            OtScanType::Protocol => write!(f, "Protocol"),
            OtScanType::Vulnerability => write!(f, "Vulnerability"),
            OtScanType::Comprehensive => write!(f, "Comprehensive"),
        }
    }
}

impl std::str::FromStr for OtScanType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "discovery" => Ok(OtScanType::Discovery),
            "protocol" => Ok(OtScanType::Protocol),
            "vulnerability" => Ok(OtScanType::Vulnerability),
            "comprehensive" => Ok(OtScanType::Comprehensive),
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

/// OT Asset representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtAsset {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub asset_type: OtAssetType,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub protocols: Vec<OtProtocolType>,
    pub purdue_level: Option<i32>,
    pub zone: Option<String>,
    pub criticality: Criticality,
    pub last_seen: Option<DateTime<Utc>>,
    pub first_seen: Option<DateTime<Utc>>,
    pub scan_id: Option<String>,
    pub vulnerabilities: Vec<OtVulnerability>,
    pub risk_score: i32,
    pub notes: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// OT Protocol Details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtProtocol {
    pub id: String,
    pub asset_id: String,
    pub protocol_type: OtProtocolType,
    pub port: i32,
    pub details: ProtocolDetails,
    pub security_issues: Vec<SecurityIssue>,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Protocol-specific details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDetails {
    /// Device identification from protocol
    pub device_id: Option<String>,
    /// Protocol version
    pub version: Option<String>,
    /// Vendor-specific info
    pub vendor_info: Option<String>,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

impl Default for ProtocolDetails {
    fn default() -> Self {
        Self {
            device_id: None,
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        }
    }
}

/// Security Issue identified during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub remediation: Option<String>,
}

/// OT Vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtVulnerability {
    pub cve_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub affected_component: String,
    pub remediation: Option<String>,
}

/// OT Scan configuration and results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtScan {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub scan_type: OtScanType,
    pub target_range: String,
    pub protocols_enabled: Vec<OtProtocolType>,
    pub status: ScanStatus,
    pub assets_discovered: i32,
    pub vulnerabilities_found: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// OT Scan Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtScanConfig {
    pub name: String,
    pub target_range: String,
    pub scan_type: OtScanType,
    pub protocols: Vec<OtProtocolType>,
    /// Enable passive-only mode (no active probing)
    pub passive_only: bool,
    /// Scan timeout in seconds
    pub timeout_secs: u64,
    /// Maximum concurrent connections
    pub max_concurrent: usize,
    /// Customer ID for CRM integration
    pub customer_id: Option<String>,
    /// Engagement ID for CRM integration
    pub engagement_id: Option<String>,
}

impl Default for OtScanConfig {
    fn default() -> Self {
        Self {
            name: "OT Scan".to_string(),
            target_range: String::new(),
            scan_type: OtScanType::Discovery,
            protocols: vec![
                OtProtocolType::Modbus,
                OtProtocolType::Dnp3,
                OtProtocolType::OpcUa,
                OtProtocolType::Bacnet,
                OtProtocolType::EthernetIp,
                OtProtocolType::S7,
            ],
            passive_only: true, // Safe default
            timeout_secs: 30,
            max_concurrent: 10,
            customer_id: None,
            engagement_id: None,
        }
    }
}

/// Network topology node for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub purdue_level: Option<i32>,
    pub ip_address: Option<String>,
    pub criticality: Option<Criticality>,
}

/// Network topology edge for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub protocol: Option<String>,
    pub edge_type: String,
}

/// Network topology response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtDashboardStats {
    pub total_assets: i32,
    pub assets_by_type: Vec<TypeCount>,
    pub assets_by_criticality: Vec<CriticalityCount>,
    pub assets_by_purdue_level: Vec<PurdueCount>,
    pub total_vulnerabilities: i32,
    pub vulnerabilities_by_severity: Vec<SeverityCount>,
    pub recent_scans: Vec<OtScan>,
    pub protocols_detected: Vec<ProtocolCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeCount {
    pub asset_type: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalityCount {
    pub criticality: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurdueCount {
    pub level: i32,
    pub name: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCount {
    pub protocol: String,
    pub count: i32,
}
