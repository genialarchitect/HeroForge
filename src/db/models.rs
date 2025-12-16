#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub accepted_terms_at: Option<DateTime<Utc>>,
    pub terms_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanResult {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub targets: String,
    pub status: String, // pending, running, completed, failed
    pub results: Option<String>, // JSON string of scan results
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
    pub accept_terms: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub refresh_token: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
}

impl From<User> for UserInfo {
    fn from(user: User) -> Self {
        UserInfo {
            id: user.id,
            username: user.username,
            email: user.email,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateScanRequest {
    pub name: String,
    pub targets: Vec<String>,
    pub port_range: (u16, u16),
    pub threads: usize,
    pub enable_os_detection: bool,
    pub enable_service_detection: bool,
    pub enable_vuln_scan: bool,
    // Enumeration options
    #[serde(default)]
    pub enable_enumeration: bool,
    /// Enumeration depth: "passive", "light", or "aggressive"
    pub enum_depth: Option<String>,
    /// Services to enumerate: ["http", "dns", "smb", "ftp", "ssh", "smtp", "ldap", "mysql", "postgresql", "mongodb", "redis", "elasticsearch"]
    pub enum_services: Option<Vec<String>>,
    // Scan type options
    /// Scan type: "tcp_connect", "udp", "comprehensive" (default: tcp_connect)
    pub scan_type: Option<String>,
    /// UDP-specific port range (uses common UDP ports if not specified)
    pub udp_port_range: Option<(u16, u16)>,
    /// Number of UDP probe retries (default: 2)
    #[serde(default = "default_udp_retries")]
    pub udp_retries: u8,
    /// Optional target group ID to associate with this scan
    pub target_group_id: Option<String>,
}

fn default_udp_retries() -> u8 {
    2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: String,
    pub progress: f32,
    pub current_target: Option<String>,
    pub message: String,
}

// Admin Console Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub can_manage_users: bool,
    pub can_manage_scans: bool,
    pub can_view_all_scans: bool,
    pub can_delete_any_scan: bool,
    pub can_view_audit_logs: bool,
    pub can_manage_settings: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserRole {
    pub user_id: String,
    pub role_id: String,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SystemSetting {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
    pub updated_by: Option<String>,
    pub updated_at: DateTime<Utc>,
}

// Admin DTOs for API

#[derive(Debug, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSettingRequest {
    pub value: String,
}

// Report Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Report {
    pub id: String,
    pub user_id: String,
    pub scan_id: String,
    pub name: String,
    pub description: Option<String>,
    pub format: String,
    pub template_id: String,
    pub sections: String, // JSON array of section names
    pub file_path: Option<String>,
    pub file_size: Option<i64>,
    pub status: String, // pending, generating, completed, failed
    pub error_message: Option<String>,
    pub metadata: Option<String>, // JSON object
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateReportRequest {
    pub scan_id: String,
    pub name: String,
    pub description: Option<String>,
    pub format: String, // "pdf", "html", "json"
    pub template_id: String, // "executive", "technical", "compliance"
    pub sections: Vec<String>,
    #[serde(default)]
    pub options: ReportOptions,
}

// Re-export ReportOptions from reports module
pub use crate::reports::types::ReportOptions;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_sections: Vec<String>,
    pub supports_formats: Vec<String>,
}

// Scan Template Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanTemplate {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub config: String, // JSON string of scan configuration
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub description: Option<String>,
    pub config: ScanTemplateConfig,
    pub is_default: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTemplateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config: Option<ScanTemplateConfig>,
    pub is_default: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTemplateConfig {
    pub port_range: (u16, u16),
    pub threads: usize,
    pub enable_os_detection: bool,
    pub enable_service_detection: bool,
    pub enable_vuln_scan: bool,
    pub enable_enumeration: bool,
    pub enum_depth: Option<String>,
    pub enum_services: Option<Vec<String>>,
    pub scan_type: Option<String>,
    pub udp_port_range: Option<(u16, u16)>,
    #[serde(default = "default_udp_retries")]
    pub udp_retries: u8,
    pub target_group_id: Option<String>,
}

// Target Group Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TargetGroup {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub targets: String, // JSON array of target strings
    pub color: String,   // Hex color code for UI (e.g., "#3b82f6")
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTargetGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub targets: Vec<String>,
    pub color: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTargetGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub targets: Option<Vec<String>>,
    pub color: Option<String>,
}

// Scheduled Scan Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScheduledScan {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub config: String, // JSON string of scan configuration
    pub schedule_type: String, // "daily", "weekly", "monthly", "cron"
    pub schedule_value: String, // time for daily, day+time for weekly, or cron expression
    pub next_run_at: DateTime<Utc>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_scan_id: Option<String>,
    pub is_active: bool,
    pub run_count: i32,
    pub retry_count: i32,
    pub max_retries: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScheduledScanExecution {
    pub id: String,
    pub scheduled_scan_id: String,
    pub scan_result_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String, // "running", "completed", "failed"
    pub error_message: Option<String>,
    pub retry_attempt: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateScheduledScanRequest {
    pub name: String,
    pub description: Option<String>,
    pub config: ScheduledScanConfig,
    pub schedule_type: String,
    pub schedule_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateScheduledScanRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config: Option<ScheduledScanConfig>,
    pub schedule_type: Option<String>,
    pub schedule_value: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScanConfig {
    pub targets: Vec<String>,
    pub port_range: (u16, u16),
    pub threads: usize,
    pub enable_os_detection: bool,
    pub enable_service_detection: bool,
    pub enable_vuln_scan: bool,
    pub enable_enumeration: bool,
    pub enum_depth: Option<String>,
    pub enum_services: Option<Vec<String>>,
    pub scan_type: Option<String>,
    pub udp_port_range: Option<(u16, u16)>,
    #[serde(default = "default_udp_retries")]
    pub udp_retries: u8,
}

// Notification Settings Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NotificationSettings {
    pub user_id: String,
    pub email_on_scan_complete: bool,
    pub email_on_critical_vuln: bool,
    pub email_address: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateNotificationSettingsRequest {
    pub email_on_scan_complete: Option<bool>,
    pub email_on_critical_vuln: Option<bool>,
    pub email_address: Option<String>,
}

// Refresh Token Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

// Login Attempt and Account Lockout Models (NIST 800-53 AC-7, CIS Controls 16.11)

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LoginAttempt {
    pub id: i64,
    pub username: String,
    pub attempt_time: DateTime<Utc>,
    pub success: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountLockout {
    pub username: String,
    pub locked_until: DateTime<Utc>,
    pub attempt_count: i32,
    pub first_failed_attempt: DateTime<Utc>,
    pub last_failed_attempt: DateTime<Utc>,
    pub lockout_reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
}

// GDPR Compliance Models

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserDataExport {
    pub user: UserExportData,
    pub scans: Vec<ScanResult>,
    pub reports: Vec<Report>,
    pub templates: Vec<ScanTemplate>,
    pub target_groups: Vec<TargetGroup>,
    pub scheduled_scans: Vec<ScheduledScan>,
    pub notification_settings: Option<NotificationSettings>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserExportData {
    pub id: String,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub accepted_terms_at: Option<DateTime<Utc>>,
    pub terms_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TermsStatusResponse {
    pub accepted: bool,
    pub accepted_at: Option<DateTime<Utc>>,
    pub current_version: String,
    pub user_version: Option<String>,
    pub needs_update: bool,
}

// ============================================================================
// MFA (Two-Factor Authentication) Models
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub qr_code_url: String, // otpauth:// URI for QR code generation
    pub recovery_codes: Vec<String>, // Plain-text recovery codes (only shown once)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerifySetupRequest {
    pub totp_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaDisableRequest {
    pub password: String,
    pub totp_code: Option<String>, // Optional if using recovery code
    pub recovery_code: Option<String>, // Alternative to TOTP code
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerifyRequest {
    pub mfa_token: String,
    pub totp_code: Option<String>,
    pub recovery_code: Option<String>, // Alternative to TOTP code
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaLoginResponse {
    pub mfa_required: bool,
    pub mfa_token: Option<String>, // Short-lived token for MFA verification step
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaRegenerateRecoveryCodesRequest {
    pub password: String,
    pub totp_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaRegenerateRecoveryCodesResponse {
    pub recovery_codes: Vec<String>, // New recovery codes (only shown once)
}

// ============================================================================
// Analytics Models
// ============================================================================

/// Summary statistics for analytics dashboard
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalyticsSummary {
    pub total_scans: i64,
    pub total_hosts: i64,
    pub total_ports: i64,
    pub total_vulnerabilities: i64,
    pub critical_vulns: i64,
    pub high_vulns: i64,
    pub medium_vulns: i64,
    pub low_vulns: i64,
    pub scans_this_week: i64,
    pub scans_this_month: i64,
}

/// Time series data point for charts
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub date: String, // YYYY-MM-DD
    pub value: i64,
}

/// Service distribution for top services chart
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceCount {
    pub service: String,
    pub count: i64,
}

/// Vulnerability trend over time with severity breakdown
#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityTrend {
    pub date: String, // YYYY-MM-DD
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

// ============================================================================
// Vulnerability Management Models
// ============================================================================

/// Vulnerability tracking status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityStatus {
    Open,
    InProgress,
    Resolved,
    FalsePositive,
    AcceptedRisk,
}

impl VulnerabilityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::Resolved => "resolved",
            Self::FalsePositive => "false_positive",
            Self::AcceptedRisk => "accepted_risk",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "in_progress" => Some(Self::InProgress),
            "resolved" => Some(Self::Resolved),
            "false_positive" => Some(Self::FalsePositive),
            "accepted_risk" => Some(Self::AcceptedRisk),
            _ => None,
        }
    }
}

/// Vulnerability tracking record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VulnerabilityTracking {
    pub id: String,
    pub scan_id: String,
    pub host_ip: String,
    pub port: Option<i32>,
    pub vulnerability_id: String,
    pub severity: String,
    pub status: String,
    pub assignee_id: Option<String>,
    pub notes: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
}

/// Vulnerability comment
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct VulnerabilityComment {
    pub id: String,
    pub vulnerability_tracking_id: String,
    pub user_id: String,
    pub comment: String,
    pub created_at: DateTime<Utc>,
}

/// Request to update vulnerability tracking
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateVulnerabilityRequest {
    pub status: Option<String>,
    pub assignee_id: Option<String>,
    pub notes: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
}

/// Request to add comment to vulnerability
#[derive(Debug, Serialize, Deserialize)]
pub struct AddVulnerabilityCommentRequest {
    pub comment: String,
}

/// Request to bulk update vulnerabilities
#[derive(Debug, Serialize, Deserialize)]
pub struct BulkUpdateVulnerabilitiesRequest {
    pub vulnerability_ids: Vec<String>,
    pub status: Option<String>,
    pub assignee_id: Option<String>,
}

/// Vulnerability statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityStats {
    pub total: i64,
    pub open: i64,
    pub in_progress: i64,
    pub resolved: i64,
    pub false_positive: i64,
    pub accepted_risk: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

/// Vulnerability with comments and assignee details
#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityDetail {
    pub vulnerability: VulnerabilityTracking,
    pub comments: Vec<VulnerabilityCommentWithUser>,
    pub assignee: Option<UserInfo>,
    pub resolved_by_user: Option<UserInfo>,
}

/// Comment with user information
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct VulnerabilityCommentWithUser {
    pub id: String,
    pub vulnerability_tracking_id: String,
    pub user_id: String,
    pub username: String,
    pub comment: String,
    pub created_at: DateTime<Utc>,
}
