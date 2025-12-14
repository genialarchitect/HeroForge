use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
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
