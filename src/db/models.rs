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
    pub first_name: Option<String>,
    pub last_name: Option<String>,
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
    // Multi-tenant organization field
    pub organization_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
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
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

impl From<User> for UserInfo {
    fn from(user: User) -> Self {
        UserInfo {
            id: user.id,
            username: user.username,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
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
    /// Optional tag IDs to attach to this scan
    #[serde(default)]
    pub tag_ids: Vec<String>,
    /// Optional exclusion IDs to apply to this scan (in addition to global exclusions)
    #[serde(default)]
    pub exclusion_ids: Vec<String>,
    /// If true, skip applying global exclusions (only use per-scan exclusions)
    #[serde(default)]
    pub skip_global_exclusions: bool,
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
    pub report_type: Option<String>, // "executive", "technical", "compliance" - for portal display
    pub sections: String, // JSON array of section names
    pub file_path: Option<String>,
    pub file_size: Option<i64>,
    pub status: String, // pending, generating, completed, failed
    pub error_message: Option<String>,
    pub metadata: Option<String>, // JSON object
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    // Multi-tenant organization field
    pub organization_id: Option<String>,
    // Portal engagement link - reports with engagement_id are visible to portal customers
    pub engagement_id: Option<String>,
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

/// Template category for organizing scan profiles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateCategory {
    Quick,
    Standard,
    Comprehensive,
    Web,
    Stealth,
    Custom,
}

impl Default for TemplateCategory {
    fn default() -> Self {
        TemplateCategory::Custom
    }
}

impl std::fmt::Display for TemplateCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateCategory::Quick => write!(f, "quick"),
            TemplateCategory::Standard => write!(f, "standard"),
            TemplateCategory::Comprehensive => write!(f, "comprehensive"),
            TemplateCategory::Web => write!(f, "web"),
            TemplateCategory::Stealth => write!(f, "stealth"),
            TemplateCategory::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for TemplateCategory {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quick" => Ok(TemplateCategory::Quick),
            "standard" => Ok(TemplateCategory::Standard),
            "comprehensive" => Ok(TemplateCategory::Comprehensive),
            "web" => Ok(TemplateCategory::Web),
            "stealth" => Ok(TemplateCategory::Stealth),
            "custom" => Ok(TemplateCategory::Custom),
            _ => Ok(TemplateCategory::Custom),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanTemplate {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub config: String, // JSON string of scan configuration
    pub is_default: bool,
    pub is_system: bool,
    pub category: String, // Stored as string, maps to TemplateCategory
    pub estimated_duration_mins: Option<i32>,
    pub use_count: i32,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Extended scan template with parsed category for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTemplateResponse {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub config: ScanTemplateConfig,
    pub is_default: bool,
    pub is_system: bool,
    pub category: TemplateCategory,
    pub estimated_duration_mins: Option<i32>,
    pub use_count: i32,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScanTemplate {
    /// Convert database row to API response with parsed config and category
    pub fn to_response(&self) -> Result<ScanTemplateResponse, serde_json::Error> {
        let config: ScanTemplateConfig = serde_json::from_str(&self.config)?;
        let category = self.category.parse().unwrap_or(TemplateCategory::Custom);

        Ok(ScanTemplateResponse {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            config,
            is_default: self.is_default,
            is_system: self.is_system,
            category,
            estimated_duration_mins: self.estimated_duration_mins,
            use_count: self.use_count,
            last_used_at: self.last_used_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub description: Option<String>,
    pub config: ScanTemplateConfig,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub category: Option<TemplateCategory>,
    pub estimated_duration_mins: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTemplateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config: Option<ScanTemplateConfig>,
    pub is_default: Option<bool>,
    pub category: Option<TemplateCategory>,
    pub estimated_duration_mins: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloneScanTemplateRequest {
    pub new_name: Option<String>,
}

/// Template categories summary for filtering
#[derive(Debug, Serialize, Deserialize)]
pub struct TemplateCategorySummary {
    pub category: String,
    pub count: i32,
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

// Scheduled Report Models

/// Scheduled report configuration for automated report generation and email delivery
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScheduledReport {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    /// Report type: "vulnerability", "compliance", "executive", "scan_summary"
    pub report_type: String,
    /// Output format: "pdf", "html", "csv"
    pub format: String,
    /// Cron expression for scheduling (e.g., "0 8 * * *" for daily at 8am)
    pub schedule: String,
    /// JSON array of recipient email addresses
    pub recipients: String,
    /// JSON object with filter criteria
    pub filters: Option<String>,
    /// Include charts in the report
    pub include_charts: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: DateTime<Utc>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateScheduledReportRequest {
    pub name: String,
    pub description: Option<String>,
    /// Report type: "vulnerability", "compliance", "executive", "scan_summary"
    pub report_type: String,
    /// Output format: "pdf", "html", "csv"
    pub format: String,
    /// Cron expression for scheduling
    pub schedule: String,
    /// List of recipient email addresses
    pub recipients: Vec<String>,
    /// Filter criteria
    pub filters: Option<ScheduledReportFilters>,
    /// Include charts in the report (default: true)
    pub include_charts: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateScheduledReportRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub report_type: Option<String>,
    pub format: Option<String>,
    pub schedule: Option<String>,
    pub recipients: Option<Vec<String>>,
    pub filters: Option<ScheduledReportFilters>,
    pub include_charts: Option<bool>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledReportFilters {
    /// For vulnerability reports: minimum severity to include
    pub min_severity: Option<String>,
    /// For compliance reports: frameworks to include
    pub frameworks: Option<Vec<String>>,
    /// Date range: number of days to look back
    pub days_back: Option<i32>,
    /// Specific scan IDs to include
    pub scan_ids: Option<Vec<String>>,
    /// Customer ID for CRM-filtered reports
    pub customer_id: Option<String>,
    /// Engagement ID for engagement-specific reports
    pub engagement_id: Option<String>,
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
    /// Whether to send notifications for workflow actions
    #[serde(default)]
    pub notify_on_workflow_action: Option<bool>,
    /// Whether to send notifications on SLA breaches
    #[serde(default)]
    pub notify_on_sla_breach: Option<bool>,
    /// Notification email (alias for email_address for compatibility)
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateNotificationSettingsRequest {
    pub email_on_scan_complete: Option<bool>,
    pub email_on_critical_vuln: Option<bool>,
    pub email_address: Option<String>,
    pub slack_webhook_url: Option<String>,
    pub teams_webhook_url: Option<String>,
    pub notify_on_workflow_action: Option<bool>,
    pub notify_on_sla_breach: Option<bool>,
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
    pub first_name: Option<String>,
    pub last_name: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub updated_at: Option<DateTime<Utc>>,
}

/// Request to update a vulnerability comment
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateVulnerabilityCommentRequest {
    pub comment: String,
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
    pub updated_at: Option<DateTime<Utc>>,
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
    pub due_date: Option<String>,
}

/// Request to bulk update severity
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkUpdateSeverityRequest {
    pub vulnerability_ids: Vec<String>,
    pub severity: String,
}

/// Request to bulk delete vulnerabilities
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkDeleteVulnerabilitiesRequest {
    pub vulnerability_ids: Vec<String>,
}

/// Request to bulk add tags to vulnerabilities
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkAddTagsRequest {
    pub vulnerability_ids: Vec<String>,
    pub tags: Vec<String>,
}

/// Response for bulk operations
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkOperationResponse {
    pub updated: usize,
    pub failed: usize,
    pub message: String,
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
// Vulnerability Assignment Models
// ============================================================================

/// Vulnerability assignment with user info for display
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct VulnerabilityAssignmentWithUser {
    pub id: String,
    pub scan_id: String,
    pub host_ip: String,
    pub port: Option<i32>,
    pub vulnerability_id: String,
    pub severity: String,
    pub status: String,
    pub assignee_id: Option<String>,
    pub assignee_username: Option<String>,
    pub assignee_email: Option<String>,
    pub notes: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub priority: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub scan_name: Option<String>,
    pub is_overdue: bool,
    pub days_until_due: Option<i64>,
}

/// User assignment statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserAssignmentStats {
    pub total: i64,
    pub open: i64,
    pub in_progress: i64,
    pub overdue: i64,
    pub due_today: i64,
    pub due_this_week: i64,
    pub critical: i64,
    pub high: i64,
}

/// Request to assign a vulnerability
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssignVulnerabilityRequest {
    pub assignee_id: String,
    pub due_date: Option<DateTime<Utc>>,
    pub priority: Option<String>,
}

/// Request to update an assignment
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateAssignmentRequest {
    pub due_date: Option<DateTime<Utc>>,
    pub priority: Option<String>,
    pub status: Option<String>,
}

/// Response for my assignments endpoint
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MyAssignmentsResponse {
    pub stats: UserAssignmentStats,
    pub assignments: Vec<VulnerabilityAssignmentWithUser>,
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
    // Enhanced fields for findings template library
    pub evidence_placeholders: Option<String>,  // JSON array of EvidencePlaceholder
    pub testing_steps: Option<String>,          // Markdown testing steps
    pub owasp_category: Option<String>,         // OWASP Top 10 category
    pub mitre_attack_ids: Option<String>,       // JSON array of MITRE ATT&CK IDs
    pub compliance_mappings: Option<String>,    // JSON object mapping frameworks to controls
    pub use_count: Option<i32>,                 // Usage count for popularity sorting
    pub last_used_at: Option<DateTime<Utc>>,    // Last time template was applied
    pub affected_components: Option<String>,    // JSON array of affected components
}

/// Finding template category for organizing templates
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct FindingTemplateCategory {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
}

/// Evidence placeholder type
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePlaceholderType {
    Screenshot,
    CodeSnippet,
    RequestResponse,
    CommandOutput,
    File,
    Text,
}

/// Evidence placeholder definition for templates
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EvidencePlaceholder {
    pub id: String,
    pub label: String,
    pub placeholder_type: EvidencePlaceholderType,
    pub description: Option<String>,
    pub required: bool,
}

/// Compliance framework mapping for templates
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ComplianceMapping {
    pub framework: String,  // e.g., "PCI-DSS", "NIST 800-53"
    pub controls: Vec<String>,  // e.g., ["6.5.1", "6.5.7"]
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
    // Enhanced fields
    pub evidence_placeholders: Option<Vec<EvidencePlaceholder>>,
    pub testing_steps: Option<String>,
    pub owasp_category: Option<String>,
    pub mitre_attack_ids: Option<Vec<String>>,
    pub compliance_mappings: Option<Vec<ComplianceMapping>>,
    pub affected_components: Option<Vec<String>>,
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
    // Enhanced fields
    pub evidence_placeholders: Option<Vec<EvidencePlaceholder>>,
    pub testing_steps: Option<String>,
    pub owasp_category: Option<String>,
    pub mitre_attack_ids: Option<Vec<String>>,
    pub compliance_mappings: Option<Vec<ComplianceMapping>>,
    pub affected_components: Option<Vec<String>>,
}

/// Request to apply a template to a vulnerability
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApplyTemplateRequest {
    pub template_id: String,
    pub vulnerability_id: String,
    pub evidence: Option<Vec<AppliedEvidence>>,
}

/// Evidence provided when applying a template
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AppliedEvidence {
    pub placeholder_id: String,
    pub content: String,
    pub content_type: Option<String>,  // MIME type for file uploads
}

/// Request to import templates from JSON
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportTemplatesRequest {
    pub templates: Vec<CreateFindingTemplateRequest>,
    pub overwrite_existing: Option<bool>,
}

/// Response from template import
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportTemplatesResponse {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Request to clone a template
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloneFindingTemplateRequest {
    pub new_title: Option<String>,
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
    // Multi-tenant organization field
    pub organization_id: Option<String>,
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
// Asset Groups Models
// ============================================================================

/// Asset group for organizing assets into logical groupings
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetGroup {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub color: String,         // Hex color code (e.g., "#3b82f6")
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Asset group member record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetGroupMember {
    pub asset_group_id: String,
    pub asset_id: String,
    pub added_at: DateTime<Utc>,
}

/// Request to create a new asset group
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAssetGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub color: String,
}

/// Request to update an asset group
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAssetGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub color: Option<String>,
}

/// Request to add assets to a group
#[derive(Debug, Serialize, Deserialize)]
pub struct AddAssetsToGroupRequest {
    pub asset_ids: Vec<String>,
}

/// Asset group with member count for listing
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetGroupWithCount {
    pub group: AssetGroup,
    pub asset_count: i64,
}

/// Asset group with its member assets
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetGroupWithMembers {
    pub group: AssetGroup,
    pub assets: Vec<Asset>,
}

/// Asset detail with port details, tags, and groups for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct AssetDetailFull {
    pub asset: Asset,
    pub ports: Vec<AssetPort>,
    pub history: Vec<AssetHistoryWithScan>,
    pub asset_tags: Vec<AssetTag>,
    pub asset_groups: Vec<AssetGroup>,
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

// ============================================================================
// Secret Finding Models
// ============================================================================

/// A detected secret/credential finding in a scan
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct SecretFindingRecord {
    pub id: String,
    pub scan_id: String,
    pub host_ip: String,
    pub port: Option<i32>,
    pub secret_type: String,
    pub severity: String,
    pub redacted_value: String,
    pub source_type: String,
    pub source_location: String,
    pub line_number: Option<i32>,
    pub context: Option<String>,
    pub confidence: f64,
    pub status: String,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<String>,
    pub false_positive: bool,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Entropy score for entropy-based detection (0.0 - 8.0)
    #[sqlx(default)]
    pub entropy_score: Option<f64>,
    /// Detection method: 'pattern', 'entropy', 'key_name', etc.
    #[sqlx(default)]
    pub detection_method: Option<String>,
}

/// Git secret scan record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct GitSecretScanRecord {
    pub id: String,
    pub user_id: String,
    pub repository_url: Option<String>,
    pub repository_path: Option<String>,
    pub branch: Option<String>,
    pub scan_history: bool,
    pub history_depth: Option<i32>,
    pub status: String,
    pub finding_count: Option<i32>,
    pub files_scanned: Option<i32>,
    pub commits_scanned: Option<i32>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Git secret finding - links a secret finding to git-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct GitSecretFindingRecord {
    pub id: String,
    pub git_scan_id: String,
    pub finding_id: String,
    pub commit_sha: String,
    pub commit_author: Option<String>,
    pub commit_email: Option<String>,
    pub commit_date: Option<String>,
    pub commit_message: Option<String>,
    pub file_path: String,
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
}

/// Filesystem secret scan record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct FilesystemSecretScanRecord {
    pub id: String,
    pub user_id: String,
    pub scan_paths: String,
    pub recursive: bool,
    pub max_depth: Option<i32>,
    pub include_patterns: Option<String>,
    pub exclude_patterns: Option<String>,
    pub max_file_size: Option<i64>,
    pub entropy_detection: bool,
    pub status: String,
    pub finding_count: Option<i32>,
    pub files_scanned: Option<i32>,
    pub bytes_scanned: Option<i64>,
    pub files_skipped: Option<i32>,
    pub directories_scanned: Option<i32>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Filesystem secret finding - links a secret finding to file-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct FilesystemSecretFindingRecord {
    pub id: String,
    pub fs_scan_id: String,
    pub finding_id: String,
    pub file_path: String,
    pub relative_path: String,
    pub file_size: i64,
    pub file_modified: Option<String>,
    pub file_owner: Option<String>,
    pub file_permissions: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Summary statistics for secret findings
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecretFindingStats {
    pub total_findings: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub open_count: i64,
    pub resolved_count: i64,
    pub false_positive_count: i64,
    pub by_type: Vec<SecretTypeCount>,
}

/// Count of findings by secret type
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecretTypeCount {
    pub secret_type: String,
    pub count: i64,
}

/// Request to update a secret finding status
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateSecretFindingRequest {
    pub status: Option<String>,
    pub false_positive: Option<bool>,
    pub notes: Option<String>,
}

// ============================================================================
// CI/CD Pipeline Security Scanning Models
// ============================================================================

/// CI/CD Pipeline scan record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CiCdPipelineScanRecord {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub scan_type: String,
    pub repository_url: Option<String>,
    pub branch: Option<String>,
    pub commit_sha: Option<String>,
    pub status: String,
    pub finding_count: Option<i32>,
    pub critical_count: Option<i32>,
    pub high_count: Option<i32>,
    pub medium_count: Option<i32>,
    pub low_count: Option<i32>,
    pub info_count: Option<i32>,
    pub files_scanned: Option<i32>,
    pub duration_ms: Option<i64>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// CI/CD Pipeline finding record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CiCdPipelineFindingRecord {
    pub id: String,
    pub scan_id: String,
    pub rule_id: String,
    pub platform: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub workflow_file: String,
    pub job_name: Option<String>,
    pub step_name: Option<String>,
    pub line_number: Option<i32>,
    pub column_number: Option<i32>,
    pub code_snippet: Option<String>,
    pub remediation: String,
    pub cwe_id: Option<String>,
    pub status: String,
    pub false_positive: bool,
    pub suppressed: bool,
    pub suppressed_by: Option<String>,
    pub suppressed_at: Option<DateTime<Utc>>,
    pub suppression_reason: Option<String>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to start a CI/CD pipeline scan
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StartCiCdScanRequest {
    /// Type of scan: github_actions, gitlab_ci, jenkins, or auto (detect automatically)
    pub scan_type: String,
    /// Repository URL (optional - can use uploaded files instead)
    pub repository_url: Option<String>,
    /// Branch to scan (defaults to main/master)
    pub branch: Option<String>,
    /// Pipeline configuration files (for direct file scanning)
    pub files: Option<Vec<CiCdFileContent>>,
    /// CRM customer ID
    pub customer_id: Option<String>,
    /// CRM engagement ID
    pub engagement_id: Option<String>,
}

/// CI/CD file content for direct scanning
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CiCdFileContent {
    /// File path (e.g., .github/workflows/ci.yml)
    pub path: String,
    /// File content
    pub content: String,
}

/// Request to analyze a single CI/CD file
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AnalyzeCiCdFileRequest {
    /// Pipeline type: github_actions, gitlab_ci, jenkins
    pub platform: String,
    /// File content to analyze
    pub content: String,
    /// Optional file path for context
    pub file_path: Option<String>,
}

/// Response from immediate file analysis
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CiCdAnalysisResponse {
    pub platform: String,
    pub findings: Vec<CiCdFindingResponse>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub duration_ms: u64,
}

/// CI/CD finding response (simplified for API)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CiCdFindingResponse {
    pub rule_id: String,
    pub platform: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub file_path: String,
    pub line_number: Option<usize>,
    pub job_name: Option<String>,
    pub step_name: Option<String>,
    pub code_snippet: Option<String>,
    pub remediation: String,
    pub cwe_id: Option<String>,
}

/// Request to suppress a finding
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SuppressCiCdFindingRequest {
    pub reason: String,
}

/// Request to update finding status
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateCiCdFindingRequest {
    pub status: Option<String>,
    pub false_positive: Option<bool>,
}

/// CI/CD scan statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CiCdScanStats {
    pub total_scans: i64,
    pub total_findings: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub info_count: i64,
    pub open_findings: i64,
    pub resolved_findings: i64,
    pub false_positives: i64,
    pub by_platform: Vec<CiCdPlatformCount>,
    pub by_category: Vec<CiCdCategoryCount>,
}

/// Count by platform
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CiCdPlatformCount {
    pub platform: String,
    pub count: i64,
}

/// Count by category
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CiCdCategoryCount {
    pub category: String,
    pub count: i64,
}
