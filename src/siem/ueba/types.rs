//! UEBA (User Entity Behavior Analytics) type definitions.
//!
//! This module defines all the core types used by the UEBA engine including:
//! - Entity types (users, hosts, service accounts)
//! - Activity types and events
//! - Anomaly types and detection results
//! - Risk scoring components
//! - Baseline definitions

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Entity type being tracked by UEBA
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    User,
    Host,
    ServiceAccount,
    Application,
    Device,
    IpAddress,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::User => "user",
            EntityType::Host => "host",
            EntityType::ServiceAccount => "service_account",
            EntityType::Application => "application",
            EntityType::Device => "device",
            EntityType::IpAddress => "ip_address",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(EntityType::User),
            "host" => Some(EntityType::Host),
            "service_account" => Some(EntityType::ServiceAccount),
            "application" => Some(EntityType::Application),
            "device" => Some(EntityType::Device),
            "ip_address" => Some(EntityType::IpAddress),
            _ => None,
        }
    }
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    pub fn from_score(score: i32) -> Self {
        match score {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// UEBA Entity - A tracked user, host, or service account
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UebaEntity {
    pub id: String,
    pub user_id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub display_name: Option<String>,
    pub department: Option<String>,
    pub role: Option<String>,
    pub manager: Option<String>,
    pub location: Option<String>,
    pub peer_group_id: Option<String>,
    pub risk_score: i32,
    pub risk_level: String,
    pub baseline_data: Option<String>,
    pub tags: Option<String>,
    pub last_activity_at: Option<String>,
    pub first_seen_at: Option<String>,
    pub is_active: bool,
    pub is_privileged: bool,
    pub is_service_account: bool,
    pub metadata: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create a new UEBA entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEntityRequest {
    pub entity_type: String,
    pub entity_id: String,
    pub display_name: Option<String>,
    pub department: Option<String>,
    pub role: Option<String>,
    pub manager: Option<String>,
    pub location: Option<String>,
    pub is_privileged: Option<bool>,
    pub is_service_account: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
}

/// Request to update an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEntityRequest {
    pub display_name: Option<String>,
    pub department: Option<String>,
    pub role: Option<String>,
    pub manager: Option<String>,
    pub location: Option<String>,
    pub peer_group_id: Option<String>,
    pub is_privileged: Option<bool>,
    pub is_service_account: Option<bool>,
    pub is_active: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
}

/// UEBA Peer Group - A group of similar entities for baseline comparison
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UebaPeerGroup {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub criteria: String,
    pub member_count: i32,
    pub baseline_metrics: Option<String>,
    pub is_auto_generated: bool,
    pub last_updated_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Peer group criteria for auto-generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerGroupCriteria {
    pub department: Option<String>,
    pub role: Option<String>,
    pub location: Option<String>,
    pub is_privileged: Option<bool>,
    pub entity_type: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Request to create a peer group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePeerGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub criteria: PeerGroupCriteria,
}

/// Activity type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityType {
    Login,
    Logout,
    FailedLogin,
    FileAccess,
    FileModify,
    FileDelete,
    PrivilegeUse,
    PrivilegeEscalation,
    NetworkConnection,
    EmailSend,
    EmailReceive,
    DataDownload,
    DataUpload,
    ProcessExecution,
    ServiceAccess,
    AdminAction,
    ConfigChange,
    PolicyViolation,
    Other,
}

impl ActivityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActivityType::Login => "login",
            ActivityType::Logout => "logout",
            ActivityType::FailedLogin => "failed_login",
            ActivityType::FileAccess => "file_access",
            ActivityType::FileModify => "file_modify",
            ActivityType::FileDelete => "file_delete",
            ActivityType::PrivilegeUse => "privilege_use",
            ActivityType::PrivilegeEscalation => "privilege_escalation",
            ActivityType::NetworkConnection => "network_connection",
            ActivityType::EmailSend => "email_send",
            ActivityType::EmailReceive => "email_receive",
            ActivityType::DataDownload => "data_download",
            ActivityType::DataUpload => "data_upload",
            ActivityType::ProcessExecution => "process_execution",
            ActivityType::ServiceAccess => "service_access",
            ActivityType::AdminAction => "admin_action",
            ActivityType::ConfigChange => "config_change",
            ActivityType::PolicyViolation => "policy_violation",
            ActivityType::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "login" => ActivityType::Login,
            "logout" => ActivityType::Logout,
            "failed_login" => ActivityType::FailedLogin,
            "file_access" => ActivityType::FileAccess,
            "file_modify" => ActivityType::FileModify,
            "file_delete" => ActivityType::FileDelete,
            "privilege_use" => ActivityType::PrivilegeUse,
            "privilege_escalation" => ActivityType::PrivilegeEscalation,
            "network_connection" => ActivityType::NetworkConnection,
            "email_send" => ActivityType::EmailSend,
            "email_receive" => ActivityType::EmailReceive,
            "data_download" => ActivityType::DataDownload,
            "data_upload" => ActivityType::DataUpload,
            "process_execution" => ActivityType::ProcessExecution,
            "service_access" => ActivityType::ServiceAccess,
            "admin_action" => ActivityType::AdminAction,
            "config_change" => ActivityType::ConfigChange,
            "policy_violation" => ActivityType::PolicyViolation,
            _ => ActivityType::Other,
        }
    }
}

/// UEBA Activity - An individual event/activity for an entity
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UebaActivity {
    pub id: String,
    pub entity_id: String,
    pub activity_type: String,
    pub source_ip: Option<String>,
    pub source_location: Option<String>,
    pub source_country: Option<String>,
    pub source_city: Option<String>,
    pub source_lat: Option<f64>,
    pub source_lon: Option<f64>,
    pub destination: Option<String>,
    pub destination_type: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub resource_type: Option<String>,
    pub status: Option<String>,
    pub risk_contribution: i32,
    pub is_anomalous: bool,
    pub anomaly_reasons: Option<String>,
    pub raw_event: Option<String>,
    pub event_source: Option<String>,
    pub timestamp: String,
    pub created_at: String,
}

/// Request to record an activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordActivityRequest {
    pub entity_id: String,
    pub activity_type: String,
    pub source_ip: Option<String>,
    pub source_country: Option<String>,
    pub source_city: Option<String>,
    pub source_lat: Option<f64>,
    pub source_lon: Option<f64>,
    pub destination: Option<String>,
    pub destination_type: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub resource_type: Option<String>,
    pub status: Option<String>,
    pub raw_event: Option<serde_json::Value>,
    pub event_source: Option<String>,
    pub timestamp: Option<String>,
}

/// Anomaly type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    ImpossibleTravel,
    UnusualLoginTime,
    UnusualLoginLocation,
    ExcessiveFailedLogins,
    UnusualDataAccess,
    LargeDataTransfer,
    UnusualPrivilegeUse,
    ServiceAccountAbuse,
    LateralMovement,
    DataExfiltration,
    OffHoursActivity,
    UnusualNetworkActivity,
    NewDeviceLogin,
    SuspiciousProcessExecution,
    PolicyViolation,
    BaselineDeviation,
    RapidActivityBurst,
    DormantAccountActivity,
    CredentialSharing,
    Other,
}

impl AnomalyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyType::ImpossibleTravel => "impossible_travel",
            AnomalyType::UnusualLoginTime => "unusual_login_time",
            AnomalyType::UnusualLoginLocation => "unusual_login_location",
            AnomalyType::ExcessiveFailedLogins => "excessive_failed_logins",
            AnomalyType::UnusualDataAccess => "unusual_data_access",
            AnomalyType::LargeDataTransfer => "large_data_transfer",
            AnomalyType::UnusualPrivilegeUse => "unusual_privilege_use",
            AnomalyType::ServiceAccountAbuse => "service_account_abuse",
            AnomalyType::LateralMovement => "lateral_movement",
            AnomalyType::DataExfiltration => "data_exfiltration",
            AnomalyType::OffHoursActivity => "off_hours_activity",
            AnomalyType::UnusualNetworkActivity => "unusual_network_activity",
            AnomalyType::NewDeviceLogin => "new_device_login",
            AnomalyType::SuspiciousProcessExecution => "suspicious_process_execution",
            AnomalyType::PolicyViolation => "policy_violation",
            AnomalyType::BaselineDeviation => "baseline_deviation",
            AnomalyType::RapidActivityBurst => "rapid_activity_burst",
            AnomalyType::DormantAccountActivity => "dormant_account_activity",
            AnomalyType::CredentialSharing => "credential_sharing",
            AnomalyType::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "impossible_travel" => AnomalyType::ImpossibleTravel,
            "unusual_login_time" => AnomalyType::UnusualLoginTime,
            "unusual_login_location" => AnomalyType::UnusualLoginLocation,
            "excessive_failed_logins" => AnomalyType::ExcessiveFailedLogins,
            "unusual_data_access" => AnomalyType::UnusualDataAccess,
            "large_data_transfer" => AnomalyType::LargeDataTransfer,
            "unusual_privilege_use" => AnomalyType::UnusualPrivilegeUse,
            "service_account_abuse" => AnomalyType::ServiceAccountAbuse,
            "lateral_movement" => AnomalyType::LateralMovement,
            "data_exfiltration" => AnomalyType::DataExfiltration,
            "off_hours_activity" => AnomalyType::OffHoursActivity,
            "unusual_network_activity" => AnomalyType::UnusualNetworkActivity,
            "new_device_login" => AnomalyType::NewDeviceLogin,
            "suspicious_process_execution" => AnomalyType::SuspiciousProcessExecution,
            "policy_violation" => AnomalyType::PolicyViolation,
            "baseline_deviation" => AnomalyType::BaselineDeviation,
            "rapid_activity_burst" => AnomalyType::RapidActivityBurst,
            "dormant_account_activity" => AnomalyType::DormantAccountActivity,
            "credential_sharing" => AnomalyType::CredentialSharing,
            _ => AnomalyType::Other,
        }
    }

    /// Get MITRE ATT&CK techniques associated with this anomaly type
    pub fn mitre_techniques(&self) -> Vec<&'static str> {
        match self {
            AnomalyType::ImpossibleTravel => vec!["T1078", "T1110"],
            AnomalyType::UnusualLoginTime => vec!["T1078"],
            AnomalyType::UnusualLoginLocation => vec!["T1078", "T1133"],
            AnomalyType::ExcessiveFailedLogins => vec!["T1110.001", "T1110.003"],
            AnomalyType::UnusualDataAccess => vec!["T1083", "T1005"],
            AnomalyType::LargeDataTransfer => vec!["T1041", "T1567"],
            AnomalyType::UnusualPrivilegeUse => vec!["T1068", "T1548"],
            AnomalyType::ServiceAccountAbuse => vec!["T1078.002"],
            AnomalyType::LateralMovement => vec!["T1021", "T1563"],
            AnomalyType::DataExfiltration => vec!["T1041", "T1048", "T1567"],
            AnomalyType::OffHoursActivity => vec!["T1078"],
            AnomalyType::UnusualNetworkActivity => vec!["T1071", "T1095"],
            AnomalyType::NewDeviceLogin => vec!["T1078"],
            AnomalyType::SuspiciousProcessExecution => vec!["T1059", "T1204"],
            AnomalyType::PolicyViolation => vec![],
            AnomalyType::BaselineDeviation => vec![],
            AnomalyType::RapidActivityBurst => vec!["T1087", "T1046"],
            AnomalyType::DormantAccountActivity => vec!["T1078"],
            AnomalyType::CredentialSharing => vec!["T1078"],
            AnomalyType::Other => vec![],
        }
    }
}

/// Anomaly status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyStatus {
    New,
    Acknowledged,
    Investigating,
    Confirmed,
    FalsePositive,
    Resolved,
    Suppressed,
}

impl AnomalyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnomalyStatus::New => "new",
            AnomalyStatus::Acknowledged => "acknowledged",
            AnomalyStatus::Investigating => "investigating",
            AnomalyStatus::Confirmed => "confirmed",
            AnomalyStatus::FalsePositive => "false_positive",
            AnomalyStatus::Resolved => "resolved",
            AnomalyStatus::Suppressed => "suppressed",
        }
    }
}

/// UEBA Anomaly - A detected behavioral anomaly
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UebaAnomaly {
    pub id: String,
    pub entity_id: String,
    pub anomaly_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub baseline_deviation: Option<f64>,
    pub confidence: Option<f64>,
    pub status: String,
    pub priority: String,
    pub assigned_to: Option<String>,
    pub related_activities: Option<String>,
    pub related_anomalies: Option<String>,
    pub mitre_techniques: Option<String>,
    pub risk_score_impact: i32,
    pub detected_at: String,
    pub acknowledged_at: Option<String>,
    pub acknowledged_by: Option<String>,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<String>,
    pub resolution_notes: Option<String>,
    pub false_positive: bool,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Evidence for an anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvidence {
    pub activities: Vec<String>,
    pub baseline_metrics: Option<serde_json::Value>,
    pub current_values: Option<serde_json::Value>,
    pub deviation_details: Option<String>,
    pub context: Option<serde_json::Value>,
}

/// Request to update anomaly status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAnomalyRequest {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assigned_to: Option<String>,
    pub resolution_notes: Option<String>,
    pub false_positive: Option<bool>,
    pub suppressed: Option<bool>,
    pub suppression_reason: Option<String>,
}

/// UEBA Baseline - Statistical baseline for metrics
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UebaBaseline {
    pub id: String,
    pub entity_id: Option<String>,
    pub peer_group_id: Option<String>,
    pub metric_name: String,
    pub metric_category: String,
    pub period: String,
    pub mean_value: Option<f64>,
    pub std_deviation: Option<f64>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub median_value: Option<f64>,
    pub percentile_25: Option<f64>,
    pub percentile_75: Option<f64>,
    pub percentile_95: Option<f64>,
    pub percentile_99: Option<f64>,
    pub sample_count: Option<i32>,
    pub last_value: Option<f64>,
    pub trend: Option<String>,
    pub is_stable: bool,
    pub last_calculated_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Metric categories for baselines
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetricCategory {
    LoginActivity,
    FileActivity,
    NetworkActivity,
    PrivilegeUsage,
    DataTransfer,
    ApplicationUsage,
    TimePatterns,
    LocationPatterns,
}

impl MetricCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricCategory::LoginActivity => "login_activity",
            MetricCategory::FileActivity => "file_activity",
            MetricCategory::NetworkActivity => "network_activity",
            MetricCategory::PrivilegeUsage => "privilege_usage",
            MetricCategory::DataTransfer => "data_transfer",
            MetricCategory::ApplicationUsage => "application_usage",
            MetricCategory::TimePatterns => "time_patterns",
            MetricCategory::LocationPatterns => "location_patterns",
        }
    }
}

/// UEBA Session - Login/session tracking
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UebaSession {
    pub id: String,
    pub entity_id: String,
    pub session_id: Option<String>,
    pub session_type: String,
    pub source_ip: String,
    pub source_country: Option<String>,
    pub source_city: Option<String>,
    pub source_lat: Option<f64>,
    pub source_lon: Option<f64>,
    pub source_asn: Option<String>,
    pub source_isp: Option<String>,
    pub user_agent: Option<String>,
    pub device_type: Option<String>,
    pub device_fingerprint: Option<String>,
    pub auth_method: Option<String>,
    pub auth_status: String,
    pub mfa_used: bool,
    pub is_vpn: bool,
    pub is_tor: bool,
    pub is_proxy: bool,
    pub risk_score: i32,
    pub anomaly_flags: Option<String>,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub duration_seconds: Option<i32>,
    pub created_at: String,
}

/// Request to record a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordSessionRequest {
    pub entity_id: String,
    pub session_id: Option<String>,
    pub session_type: String,
    pub source_ip: String,
    pub source_country: Option<String>,
    pub source_city: Option<String>,
    pub source_lat: Option<f64>,
    pub source_lon: Option<f64>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub auth_method: Option<String>,
    pub auth_status: String,
    pub mfa_used: Option<bool>,
}

/// UEBA Risk Factor - Component contributing to risk score
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UebaRiskFactor {
    pub id: String,
    pub entity_id: String,
    pub factor_type: String,
    pub factor_value: Option<String>,
    pub description: Option<String>,
    pub weight: f64,
    pub contribution: Option<i32>,
    pub source: Option<String>,
    pub source_id: Option<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Risk factor types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactorType {
    Anomaly,
    FailedLogin,
    PolicyViolation,
    Watchlist,
    HighPrivilege,
    ServiceAccount,
    ExternalAccess,
    DataAccess,
    ManualAdjustment,
}

impl RiskFactorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskFactorType::Anomaly => "anomaly",
            RiskFactorType::FailedLogin => "failed_login",
            RiskFactorType::PolicyViolation => "policy_violation",
            RiskFactorType::Watchlist => "watchlist",
            RiskFactorType::HighPrivilege => "high_privilege",
            RiskFactorType::ServiceAccount => "service_account",
            RiskFactorType::ExternalAccess => "external_access",
            RiskFactorType::DataAccess => "data_access",
            RiskFactorType::ManualAdjustment => "manual_adjustment",
        }
    }

    /// Default weight for this factor type
    pub fn default_weight(&self) -> f64 {
        match self {
            RiskFactorType::Anomaly => 1.0,
            RiskFactorType::FailedLogin => 0.5,
            RiskFactorType::PolicyViolation => 0.8,
            RiskFactorType::Watchlist => 2.0,
            RiskFactorType::HighPrivilege => 0.3,
            RiskFactorType::ServiceAccount => 0.2,
            RiskFactorType::ExternalAccess => 0.4,
            RiskFactorType::DataAccess => 0.3,
            RiskFactorType::ManualAdjustment => 1.0,
        }
    }
}

/// UEBA Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaDashboardStats {
    pub total_entities: i64,
    pub high_risk_entities: i64,
    pub critical_risk_entities: i64,
    pub total_anomalies: i64,
    pub new_anomalies: i64,
    pub open_anomalies: i64,
    pub anomalies_by_type: Vec<AnomalyTypeCount>,
    pub risk_distribution: RiskDistribution,
    pub recent_anomalies: Vec<UebaAnomaly>,
    pub top_risk_entities: Vec<EntityRiskSummary>,
    pub activity_trend: Vec<ActivityTrendPoint>,
}

/// Count by anomaly type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyTypeCount {
    pub anomaly_type: String,
    pub count: i64,
}

/// Risk score distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDistribution {
    pub low: i64,
    pub medium: i64,
    pub high: i64,
    pub critical: i64,
}

/// Summary of entity risk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRiskSummary {
    pub entity_id: String,
    pub entity_type: String,
    pub display_name: Option<String>,
    pub risk_score: i32,
    pub risk_level: String,
    pub anomaly_count: i64,
    pub last_activity_at: Option<String>,
}

/// Activity trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityTrendPoint {
    pub timestamp: String,
    pub total_activities: i64,
    pub anomalous_activities: i64,
}

/// Geo location for distance calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub lat: f64,
    pub lon: f64,
    pub country: Option<String>,
    pub city: Option<String>,
}

impl GeoLocation {
    /// Calculate distance in kilometers to another location (Haversine formula)
    pub fn distance_km(&self, other: &GeoLocation) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1_rad = self.lat.to_radians();
        let lat2_rad = other.lat.to_radians();
        let delta_lat = (other.lat - self.lat).to_radians();
        let delta_lon = (other.lon - self.lon).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }

    /// Check if travel between two locations is "impossible" given the time difference
    /// Assumes max reasonable travel speed of 900 km/h (commercial flight)
    pub fn is_impossible_travel(&self, other: &GeoLocation, time_diff_hours: f64) -> bool {
        const MAX_TRAVEL_SPEED_KMH: f64 = 900.0;

        if time_diff_hours <= 0.0 {
            return false;
        }

        let distance = self.distance_km(other);
        let required_speed = distance / time_diff_hours;

        required_speed > MAX_TRAVEL_SPEED_KMH
    }
}

/// Query parameters for listing entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntitiesQuery {
    pub entity_type: Option<String>,
    pub risk_level: Option<String>,
    pub peer_group_id: Option<String>,
    pub is_privileged: Option<bool>,
    pub is_active: Option<bool>,
    pub search: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
    pub order_by: Option<String>,
}

/// Query parameters for listing anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAnomaliesQuery {
    pub entity_id: Option<String>,
    pub anomaly_type: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Query parameters for listing activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListActivitiesQuery {
    pub entity_id: Option<String>,
    pub activity_type: Option<String>,
    pub is_anomalous: Option<bool>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(26), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(51), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(76), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
    }

    #[test]
    fn test_geo_distance() {
        // New York to London
        let ny = GeoLocation { lat: 40.7128, lon: -74.0060, country: Some("US".into()), city: Some("New York".into()) };
        let london = GeoLocation { lat: 51.5074, lon: -0.1278, country: Some("UK".into()), city: Some("London".into()) };

        let distance = ny.distance_km(&london);
        // Should be approximately 5570 km
        assert!(distance > 5500.0 && distance < 5650.0);
    }

    #[test]
    fn test_impossible_travel() {
        let ny = GeoLocation { lat: 40.7128, lon: -74.0060, country: Some("US".into()), city: Some("New York".into()) };
        let london = GeoLocation { lat: 51.5074, lon: -0.1278, country: Some("UK".into()), city: Some("London".into()) };

        // NY to London in 1 hour is impossible (~5570 km/h required)
        assert!(ny.is_impossible_travel(&london, 1.0));

        // NY to London in 8 hours is possible (~696 km/h required)
        assert!(!ny.is_impossible_travel(&london, 8.0));
    }

    #[test]
    fn test_anomaly_mitre_techniques() {
        let techniques = AnomalyType::ImpossibleTravel.mitre_techniques();
        assert!(techniques.contains(&"T1078"));

        let techniques = AnomalyType::DataExfiltration.mitre_techniques();
        assert!(techniques.contains(&"T1041"));
        assert!(techniques.contains(&"T1567"));
    }
}
