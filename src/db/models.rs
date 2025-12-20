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
    // CRM integration fields
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
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
    /// Optional VPN configuration ID to connect through for this scan
    pub vpn_config_id: Option<String>,
    /// Optional CRM customer ID to associate with this scan
    pub customer_id: Option<String>,
    /// Optional CRM engagement ID to associate with this scan
    pub engagement_id: Option<String>,
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
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for filtering audit logs
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuditLogFilter {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response structure for paginated audit logs
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLogResponse {
    pub logs: Vec<AuditLogWithUser>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Audit log with user information for display
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogWithUser {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
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

// Scan Tags Models

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanTag {
    pub id: String,
    pub name: String,
    pub color: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateScanTagRequest {
    pub name: String,
    #[serde(default = "default_tag_color")]
    pub color: String,
}

fn default_tag_color() -> String {
    "#06b6d4".to_string() // cyan-500
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AddTagsToScanRequest {
    pub tag_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanWithTags {
    #[serde(flatten)]
    pub scan: ScanResult,
    pub tags: Vec<ScanTag>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DuplicateScanRequest {
    /// Optional new name for the duplicated scan. If not provided, uses original name with " (Copy)" suffix.
    pub name: Option<String>,
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

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
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
    pub slack_webhook_url: Option<String>,
    pub teams_webhook_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateNotificationSettingsRequest {
    pub email_on_scan_complete: Option<bool>,
    pub email_on_critical_vuln: Option<bool>,
    pub email_address: Option<String>,
    pub slack_webhook_url: Option<String>,
    pub teams_webhook_url: Option<String>,
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

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MfaVerifySetupRequest {
    pub totp_code: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
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
// Executive Analytics Models
// ============================================================================

/// Customer security trends over time
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CustomerSecurityTrends {
    pub customer_id: String,
    pub customer_name: String,
    pub months: Vec<MonthlySecuritySnapshot>,
    pub improvement_percent: f64,
    pub current_risk_score: f64,
}

/// Monthly security snapshot for trend analysis
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MonthlySecuritySnapshot {
    pub month: String,  // "2024-01"
    pub total_vulnerabilities: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub resolved: i64,
    pub risk_score: f64,
}

/// Executive summary for a customer
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExecutiveSummary {
    pub customer_id: String,
    pub customer_name: String,
    pub total_engagements: i64,
    pub active_engagements: i64,
    pub total_scans: i64,
    pub total_vulnerabilities: i64,
    pub open_vulnerabilities: i64,
    pub critical_open: i64,
    pub high_open: i64,
    pub avg_remediation_days: f64,
    pub compliance_score: Option<f64>,
    pub last_scan_date: Option<String>,
    pub risk_rating: String,  // Critical, High, Medium, Low
    pub trend_direction: String,  // Improving, Stable, Declining
}

/// Remediation velocity metrics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RemediationVelocity {
    pub avg_days_to_remediate: f64,
    pub avg_days_critical: f64,
    pub avg_days_high: f64,
    pub avg_days_medium: f64,
    pub avg_days_low: f64,
    pub remediation_rate: f64,  // % resolved vs total
    pub velocity_trend: Vec<VelocityPoint>,
}

/// Weekly velocity data point
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VelocityPoint {
    pub week: String,
    pub resolved_count: i64,
    pub avg_days: f64,
}

/// Risk trend data point
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RiskTrendPoint {
    pub date: String,
    pub risk_score: f64,
    pub vulnerability_count: i64,
    pub weighted_severity: f64,
}

/// Compliance trend data point
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ComplianceTrendPoint {
    pub date: String,
    pub framework: String,
    pub compliance_score: f64,
    pub controls_passed: i64,
    pub controls_failed: i64,
    pub controls_total: i64,
}

/// Methodology testing coverage statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MethodologyCoverage {
    pub total_checklists: i64,
    pub completed_checklists: i64,
    pub total_items_tested: i64,
    pub passed_items: i64,
    pub failed_items: i64,
    pub coverage_by_framework: Vec<FrameworkCoverage>,
}

/// Coverage statistics per framework
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FrameworkCoverage {
    pub framework_name: String,
    pub total_items: i64,
    pub tested_items: i64,
    pub coverage_percent: f64,
}

/// Combined executive dashboard data
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExecutiveDashboard {
    pub summary: Option<ExecutiveSummary>,
    pub security_trends: Option<CustomerSecurityTrends>,
    pub remediation_velocity: Option<RemediationVelocity>,
    pub risk_trends: Vec<RiskTrendPoint>,
    pub methodology_coverage: Option<MethodologyCoverage>,
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
    // Remediation workflow fields
    pub priority: Option<String>,
    pub remediation_steps: Option<String>,
    pub estimated_effort: Option<i32>,
    pub actual_effort: Option<i32>,
    pub verification_scan_id: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_by: Option<String>,
    // JIRA integration fields
    pub jira_ticket_id: Option<String>,
    pub jira_ticket_key: Option<String>,
    // Retest workflow fields
    pub retest_requested_at: Option<DateTime<Utc>>,
    pub retest_completed_at: Option<DateTime<Utc>>,
    pub retest_result: Option<String>,
    pub retest_scan_id: Option<String>,
    pub retest_requested_by: Option<String>,
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
    // Remediation workflow fields
    pub priority: Option<String>,
    pub remediation_steps: Option<String>,
    pub estimated_effort: Option<i32>,
    pub actual_effort: Option<i32>,
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
    pub due_date: Option<DateTime<Utc>>,
    pub priority: Option<String>,
}

/// Vulnerability statistics
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
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
    pub timeline: Vec<RemediationTimelineEventWithUser>,
    pub assignee: Option<UserInfo>,
    pub resolved_by_user: Option<UserInfo>,
    pub verified_by_user: Option<UserInfo>,
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

/// Remediation timeline event for tracking all changes to vulnerability
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RemediationTimelineEvent {
    pub id: String,
    pub vulnerability_tracking_id: String,
    pub user_id: String,
    pub event_type: String, // "status_change", "assignment", "note_added", "verification_requested", "verified"
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Timeline event with user information
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct RemediationTimelineEventWithUser {
    pub id: String,
    pub vulnerability_tracking_id: String,
    pub user_id: String,
    pub username: String,
    pub event_type: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to mark vulnerability for verification
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct VerifyVulnerabilityRequest {
    pub scan_id: Option<String>, // Optional scan ID to use for verification
}

/// Request to bulk assign vulnerabilities
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkAssignVulnerabilitiesRequest {
    pub vulnerability_ids: Vec<String>,
    pub assignee_id: String,
}

/// Request to request a retest for a vulnerability
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RequestRetestRequest {
    pub notes: Option<String>,
}

/// Request to bulk request retests
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkRetestRequest {
    pub vulnerability_ids: Vec<String>,
    pub notes: Option<String>,
}

/// Request to complete a retest
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CompleteRetestRequest {
    pub result: String, // "still_vulnerable", "remediated", "partially_remediated"
    pub scan_id: Option<String>,
    pub notes: Option<String>,
}

/// Retest history entry
#[derive(Debug, Serialize, Deserialize)]
pub struct RetestHistoryEntry {
    pub id: String,
    pub vulnerability_id: String,
    pub requested_at: DateTime<Utc>,
    pub requested_by: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: Option<String>,
    pub scan_id: Option<String>,
    pub notes: Option<String>,
}

// ============================================================================
// Finding Templates Models
// ============================================================================

/// Pre-written vulnerability finding template
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct FindingTemplate {
    pub id: String,
    pub user_id: Option<String>,
    pub category: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub impact: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<String>,  // JSON array
    pub cwe_ids: Option<String>,     // JSON array
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub tags: Option<String>,        // JSON array
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new finding template
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateFindingTemplateRequest {
    pub category: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub impact: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<Vec<String>>,
    pub cwe_ids: Option<Vec<i32>>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub tags: Option<Vec<String>>,
}

/// Request to update a finding template
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateFindingTemplateRequest {
    pub category: Option<String>,
    pub title: Option<String>,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub impact: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<Vec<String>>,
    pub cwe_ids: Option<Vec<i32>>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub tags: Option<Vec<String>>,
}

// ============================================================================
// Asset Inventory Models
// ============================================================================

/// Asset tracked across multiple scans
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Asset {
    pub id: String,
    pub user_id: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub scan_count: i32,
    pub os_family: Option<String>,
    pub os_version: Option<String>,
    pub status: String, // "active", "inactive"
    pub tags: String,   // JSON array of tags
    pub notes: Option<String>,
}

/// Port associated with an asset
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetPort {
    pub id: String,
    pub asset_id: String,
    pub port: i32,
    pub protocol: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub current_state: String, // "open", "closed", "filtered"
}

/// Historical record of asset changes
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetHistory {
    pub id: String,
    pub asset_id: String,
    pub scan_id: String,
    pub changes: String, // JSON object of changes
    pub recorded_at: DateTime<Utc>,
}

/// Request to update asset metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAssetRequest {
    pub status: Option<String>,
    pub tags: Option<Vec<String>>,
    pub notes: Option<String>,
}

/// Asset with port details for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetDetail {
    pub asset: Asset,
    pub ports: Vec<AssetPort>,
    pub history: Vec<AssetHistoryWithScan>,
}

/// Asset history with scan information
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetHistoryWithScan {
    pub id: String,
    pub scan_id: String,
    pub scan_name: String,
    pub changes: serde_json::Value,
    pub recorded_at: DateTime<Utc>,
}

// ============================================================================
// Asset Tags Models
// ============================================================================

/// Tag category types for asset classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AssetTagCategory {
    Environment,
    Criticality,
    Owner,
    Department,
    Location,
    Compliance,
    Custom,
}

impl std::fmt::Display for AssetTagCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetTagCategory::Environment => write!(f, "environment"),
            AssetTagCategory::Criticality => write!(f, "criticality"),
            AssetTagCategory::Owner => write!(f, "owner"),
            AssetTagCategory::Department => write!(f, "department"),
            AssetTagCategory::Location => write!(f, "location"),
            AssetTagCategory::Compliance => write!(f, "compliance"),
            AssetTagCategory::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for AssetTagCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "environment" => Ok(AssetTagCategory::Environment),
            "criticality" => Ok(AssetTagCategory::Criticality),
            "owner" => Ok(AssetTagCategory::Owner),
            "department" => Ok(AssetTagCategory::Department),
            "location" => Ok(AssetTagCategory::Location),
            "compliance" => Ok(AssetTagCategory::Compliance),
            "custom" => Ok(AssetTagCategory::Custom),
            _ => Err(format!("Unknown tag category: {}", s)),
        }
    }
}

/// Asset tag for categorizing and organizing assets
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetTag {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub color: String,         // Hex color code (e.g., "#22c55e")
    pub category: String,      // AssetTagCategory as string
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Mapping between assets and tags (many-to-many)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetTagMapping {
    pub asset_id: String,
    pub tag_id: String,
    pub created_at: DateTime<Utc>,
}

/// Request to create a new asset tag
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAssetTagRequest {
    pub name: String,
    pub color: String,
    pub category: String,
    pub description: Option<String>,
}

/// Request to update an asset tag
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAssetTagRequest {
    pub name: Option<String>,
    pub color: Option<String>,
    pub category: Option<String>,
    pub description: Option<String>,
}

/// Request to add tags to an asset
#[derive(Debug, Serialize, Deserialize)]
pub struct AddAssetTagsRequest {
    pub tag_ids: Vec<String>,
}

/// Asset tag with usage count for listing
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetTagWithCount {
    pub tag: AssetTag,
    pub asset_count: i64,
}

/// Asset with its tags for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetWithTags {
    #[serde(flatten)]
    pub asset: Asset,
    pub asset_tags: Vec<AssetTag>,
}

/// Asset detail with port details and tags for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetDetailWithTags {
    pub asset: Asset,
    pub ports: Vec<AssetPort>,
    pub history: Vec<AssetHistoryWithScan>,
    pub asset_tags: Vec<AssetTag>,
}

// ============================================================================
// API Keys Models
// ============================================================================

/// API key record in database (key_hash is bcrypt hashed)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub prefix: String, // First 8 chars for display (e.g., "hf_xxxxx")
    pub permissions: Option<String>, // JSON array of permissions
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Request to create new API key
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub permissions: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response when creating API key (includes full key ONCE)
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key: String, // Full API key (only returned once)
    pub prefix: String,
    pub permissions: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to update API key
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateApiKeyRequest {
    pub name: Option<String>,
    pub permissions: Option<Vec<String>>,
}

// ============================================================================
// JIRA Integration Models
// ============================================================================

/// JIRA integration settings for a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct JiraSettings {
    pub user_id: String,
    pub jira_url: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub api_token: String,
    pub project_key: String,
    pub issue_type: String,
    pub default_assignee: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update JIRA settings
#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertJiraSettingsRequest {
    pub jira_url: String,
    pub username: String,
    pub api_token: String,
    pub project_key: String,
    pub issue_type: String,
    pub default_assignee: Option<String>,
    pub enabled: bool,
}

/// Request to create a JIRA ticket from a vulnerability
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateJiraTicketRequest {
    pub assignee: Option<String>,
    pub labels: Option<Vec<String>>,
}

/// Response after creating a JIRA ticket
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateJiraTicketResponse {
    pub jira_ticket_id: String,
    pub jira_ticket_key: String,
    pub jira_ticket_url: String,
}


// ============================================================================
// SIEM Integration Models
// ============================================================================

/// SIEM integration settings for a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SiemSettings {
    pub id: String,
    pub user_id: String,
    pub siem_type: String, // "syslog", "splunk", "elasticsearch"
    pub endpoint_url: String,
    pub api_key: Option<String>,
    pub protocol: Option<String>, // For syslog: "tcp" or "udp"
    pub enabled: bool,
    pub export_on_scan_complete: bool,
    pub export_on_critical_vuln: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create SIEM settings
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSiemSettingsRequest {
    pub siem_type: String,
    pub endpoint_url: String,
    pub api_key: Option<String>,
    pub protocol: Option<String>,
    pub enabled: bool,
    pub export_on_scan_complete: bool,
    pub export_on_critical_vuln: bool,
}

/// Request to update SIEM settings
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSiemSettingsRequest {
    pub endpoint_url: Option<String>,
    pub api_key: Option<String>,
    pub protocol: Option<String>,
    pub enabled: Option<bool>,
    pub export_on_scan_complete: Option<bool>,
    pub export_on_critical_vuln: Option<bool>,
}

// ============================================================================
// Methodology Checklists Models
// ============================================================================

/// Methodology template (system framework like PTES, OWASP WSTG)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct MethodologyTemplate {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub categories: Option<String>,  // JSON array
    pub item_count: i32,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Individual item within a methodology template
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct MethodologyTemplateItem {
    pub id: String,
    pub template_id: String,
    pub category: String,
    pub item_id: Option<String>,  // e.g., WSTG-INFO-01
    pub title: String,
    pub description: Option<String>,
    pub guidance: Option<String>,
    pub expected_evidence: Option<String>,
    pub tools: Option<String>,      // JSON array
    pub references: Option<String>, // JSON array
    pub sort_order: i32,
}

/// User's methodology checklist instance
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct MethodologyChecklist {
    pub id: String,
    pub template_id: String,
    pub user_id: String,
    pub scan_id: Option<String>,
    pub engagement_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub progress_percent: f64,
    pub status: String,  // in_progress, completed, archived
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Individual checklist item with user's progress
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct ChecklistItem {
    pub id: String,
    pub checklist_id: String,
    pub template_item_id: String,
    pub status: String,  // not_started, in_progress, pass, fail, na
    pub notes: Option<String>,
    pub evidence: Option<String>,
    pub findings: Option<String>,  // JSON array of finding IDs
    pub tested_at: Option<DateTime<Utc>>,
    pub tester_id: Option<String>,
}

/// Request to create a new checklist from a template
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateChecklistRequest {
    pub template_id: String,
    pub name: String,
    pub description: Option<String>,
    pub scan_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to update checklist metadata
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateChecklistRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
}

/// Request to update a checklist item
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateChecklistItemRequest {
    pub status: Option<String>,
    pub notes: Option<String>,
    pub evidence: Option<String>,
    pub findings: Option<Vec<String>>,
}

/// Progress summary for a checklist
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChecklistProgress {
    pub total_items: i32,
    pub completed_items: i32,
    pub passed: i32,
    pub failed: i32,
    pub not_applicable: i32,
    pub in_progress: i32,
    pub not_started: i32,
    pub progress_percent: f64,
    pub by_category: Vec<CategoryProgress>,
}

/// Progress for a single category
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CategoryProgress {
    pub category: String,
    pub total: i32,
    pub completed: i32,
}

impl CategoryProgress {
    pub fn progress_percent(&self) -> f64 {
        if self.total > 0 {
            (self.completed as f64 / self.total as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// Checklist with template name for list views
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct ChecklistSummary {
    pub id: String,
    pub template_id: String,
    pub template_name: String,
    pub user_id: String,
    pub scan_id: Option<String>,
    pub engagement_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub progress_percent: f64,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_items: i32,
}

/// Template with all its items
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MethodologyTemplateWithItems {
    pub template: MethodologyTemplate,
    pub items: Vec<MethodologyTemplateItem>,
}

/// Checklist with all items and template info
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChecklistWithItems {
    pub checklist: MethodologyChecklist,
    pub template_name: String,
    pub template_version: Option<String>,
    pub items: Vec<super::methodology::ChecklistItemWithTemplate>,
}
