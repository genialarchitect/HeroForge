//! Attack Surface Management types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// ASM Monitor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmMonitor {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub domains: Vec<String>,
    pub discovery_config: AssetDiscoveryConfig,
    pub schedule: String, // Cron expression
    pub alert_config: AlertConfig,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Asset discovery configuration for ASM
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AssetDiscoveryConfig {
    pub enable_subdomain_enum: bool,
    pub enable_port_scan: bool,
    pub enable_service_detection: bool,
    pub enable_ssl_analysis: bool,
    pub enable_tech_detection: bool,
    pub port_range: Option<String>,
    pub threads: Option<u32>,
    pub dns_resolvers: Vec<String>,
}

/// Alert configuration for change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub alert_on_new_subdomain: bool,
    pub alert_on_new_port: bool,
    pub alert_on_cert_change: bool,
    pub alert_on_tech_change: bool,
    pub alert_on_ip_change: bool,
    pub alert_on_asset_removed: bool,
    pub alert_on_shadow_it: bool,
    pub min_severity: AlertSeverity,
    pub notification_channels: Vec<String>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            alert_on_new_subdomain: true,
            alert_on_new_port: true,
            alert_on_cert_change: true,
            alert_on_tech_change: true,
            alert_on_ip_change: true,
            alert_on_asset_removed: true,
            alert_on_shadow_it: true,
            min_severity: AlertSeverity::Low,
            notification_channels: vec![],
        }
    }
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Critical => write!(f, "critical"),
            AlertSeverity::High => write!(f, "high"),
            AlertSeverity::Medium => write!(f, "medium"),
            AlertSeverity::Low => write!(f, "low"),
            AlertSeverity::Info => write!(f, "info"),
        }
    }
}

/// Baseline snapshot of discovered assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmBaseline {
    pub id: String,
    pub monitor_id: String,
    pub assets: Vec<BaselineAsset>,
    pub summary: BaselineSummary,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Individual asset in a baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineAsset {
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub ports: Vec<BaselinePort>,
    pub technologies: Vec<String>,
    pub ssl_info: Option<BaselineSslInfo>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Port information in baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselinePort {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

/// SSL information in baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSslInfo {
    pub issuer: String,
    pub subject: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub fingerprint: String,
}

/// Summary statistics for a baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub total_assets: usize,
    pub total_ports: usize,
    pub total_services: usize,
    pub assets_with_ssl: usize,
    pub unique_technologies: usize,
}

/// Types of changes detected between baselines
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    NewSubdomain,
    NewPort,
    PortClosed,
    CertificateChange,
    CertificateExpiring,
    TechnologyChange,
    IpAddressChange,
    AssetRemoved,
    ServiceChange,
    ShadowItDetected,
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeType::NewSubdomain => write!(f, "new_subdomain"),
            ChangeType::NewPort => write!(f, "new_port"),
            ChangeType::PortClosed => write!(f, "port_closed"),
            ChangeType::CertificateChange => write!(f, "certificate_change"),
            ChangeType::CertificateExpiring => write!(f, "certificate_expiring"),
            ChangeType::TechnologyChange => write!(f, "technology_change"),
            ChangeType::IpAddressChange => write!(f, "ip_address_change"),
            ChangeType::AssetRemoved => write!(f, "asset_removed"),
            ChangeType::ServiceChange => write!(f, "service_change"),
            ChangeType::ShadowItDetected => write!(f, "shadow_it_detected"),
        }
    }
}

/// A detected change in the attack surface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmChange {
    pub id: String,
    pub monitor_id: String,
    pub baseline_id: String,
    pub change_type: ChangeType,
    pub severity: AlertSeverity,
    pub hostname: String,
    pub details: ChangeDetails,
    pub detected_at: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// Detailed information about a change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeDetails {
    pub description: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub affected_ports: Vec<u16>,
    pub metadata: HashMap<String, String>,
}

/// Authorized asset pattern for shadow IT detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedAsset {
    pub id: String,
    pub user_id: String,
    pub hostname_pattern: String, // Regex pattern
    pub ip_ranges: Vec<String>,   // CIDR notation
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Risk score for an asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRiskScore {
    pub id: String,
    pub asset_id: Option<String>,
    pub hostname: String,
    pub overall_score: u32, // 0-100
    pub factors: Vec<RiskFactor>,
    pub calculated_at: DateTime<Utc>,
}

/// Individual risk factor contributing to overall score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub weight: f32,
    pub score: u32,
    pub description: String,
    pub details: Option<String>,
}

/// Types of risk factors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactorType {
    ExposedPorts,
    TechnologyStack,
    SslTls,
    InternetExposure,
    Visibility,
    Authorization,
    VulnerabilityPresence,
    ServiceAge,
}

impl RiskFactorType {
    /// Get the default weight for this factor type
    pub fn default_weight(&self) -> f32 {
        match self {
            RiskFactorType::ExposedPorts => 0.25,
            RiskFactorType::TechnologyStack => 0.20,
            RiskFactorType::SslTls => 0.15,
            RiskFactorType::InternetExposure => 0.20,
            RiskFactorType::Visibility => 0.10,
            RiskFactorType::Authorization => 0.10,
            RiskFactorType::VulnerabilityPresence => 0.0, // Added bonus weight
            RiskFactorType::ServiceAge => 0.0,
        }
    }
}

/// ASM Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmDashboard {
    pub total_monitors: usize,
    pub active_monitors: usize,
    pub total_assets: usize,
    pub total_changes_24h: usize,
    pub total_changes_7d: usize,
    pub critical_changes: usize,
    pub unacknowledged_changes: usize,
    pub average_risk_score: f32,
    pub high_risk_assets: usize,
    pub shadow_it_count: usize,
    pub next_scan_at: Option<DateTime<Utc>>,
    pub last_scan_at: Option<DateTime<Utc>>,
}

/// Request types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMonitorRequest {
    pub name: String,
    pub description: Option<String>,
    pub domains: Vec<String>,
    pub discovery_config: Option<AssetDiscoveryConfig>,
    pub schedule: String,
    pub alert_config: Option<AlertConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMonitorRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub domains: Option<Vec<String>>,
    pub discovery_config: Option<AssetDiscoveryConfig>,
    pub schedule: Option<String>,
    pub alert_config: Option<AlertConfig>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBaselineRequest {
    pub monitor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgeChangeRequest {
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuthorizedAssetRequest {
    pub hostname_pattern: String,
    pub ip_ranges: Option<Vec<String>>,
    pub description: Option<String>,
}

/// Monitor execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRunResult {
    pub monitor_id: String,
    pub baseline_id: String,
    pub assets_discovered: usize,
    pub changes_detected: usize,
    pub duration_secs: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub error: Option<String>,
}

/// Timeline event for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub monitor_id: String,
    pub monitor_name: String,
    pub description: String,
    pub severity: Option<AlertSeverity>,
    pub change_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventType {
    MonitorRun,
    BaselineCreated,
    ChangeDetected,
    ChangeAcknowledged,
    MonitorEnabled,
    MonitorDisabled,
}
