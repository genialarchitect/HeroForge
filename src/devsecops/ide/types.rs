//! IDE Integration Types
//!
//! Data types for IDE integration.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Supported IDE types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdeType {
    Vscode,
    IntelliJ,
    PyCharm,
    WebStorm,
    Vim,
    Neovim,
    Emacs,
    SublimeText,
    Atom,
    Eclipse,
    Other,
}

impl std::fmt::Display for IdeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdeType::Vscode => write!(f, "vscode"),
            IdeType::IntelliJ => write!(f, "intellij"),
            IdeType::PyCharm => write!(f, "pycharm"),
            IdeType::WebStorm => write!(f, "webstorm"),
            IdeType::Vim => write!(f, "vim"),
            IdeType::Neovim => write!(f, "neovim"),
            IdeType::Emacs => write!(f, "emacs"),
            IdeType::SublimeText => write!(f, "sublime_text"),
            IdeType::Atom => write!(f, "atom"),
            IdeType::Eclipse => write!(f, "eclipse"),
            IdeType::Other => write!(f, "other"),
        }
    }
}

impl std::str::FromStr for IdeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vscode" | "visual_studio_code" | "vs_code" => Ok(IdeType::Vscode),
            "intellij" | "idea" | "intellij_idea" => Ok(IdeType::IntelliJ),
            "pycharm" => Ok(IdeType::PyCharm),
            "webstorm" => Ok(IdeType::WebStorm),
            "vim" => Ok(IdeType::Vim),
            "neovim" | "nvim" => Ok(IdeType::Neovim),
            "emacs" => Ok(IdeType::Emacs),
            "sublime_text" | "sublime" => Ok(IdeType::SublimeText),
            "atom" => Ok(IdeType::Atom),
            "eclipse" => Ok(IdeType::Eclipse),
            _ => Ok(IdeType::Other),
        }
    }
}

/// IDE Session record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct IdeSession {
    pub id: String,
    pub user_id: String,
    pub ide_type: String,
    pub ide_version: Option<String>,
    pub project_path: Option<String>,
    pub project_name: Option<String>,
    pub workspace_id: Option<String>,
    pub session_start: String,
    pub session_end: Option<String>,
    pub last_activity: String,
    pub files_scanned: i32,
    pub findings_shown: i32,
    pub findings_fixed: i32,
    pub client_ip: Option<String>,
    pub client_info: Option<String>,
    pub created_at: String,
}

/// IDE Settings record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct IdeSettings {
    pub id: String,
    pub user_id: String,
    pub scan_on_save: bool,
    pub scan_on_open: bool,
    pub show_inline_hints: bool,
    pub severity_filter: Option<String>,
    pub excluded_paths: Option<String>,
    pub custom_rules_enabled: bool,
    pub scan_timeout_seconds: i32,
    pub max_file_size_kb: i32,
    pub enable_quick_fixes: bool,
    pub enable_code_actions: bool,
    pub theme: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// IDE Finding record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct IdeFinding {
    pub id: String,
    pub session_id: String,
    pub user_id: String,
    pub file_path: String,
    pub file_hash: Option<String>,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub line_start: i32,
    pub line_end: i32,
    pub column_start: Option<i32>,
    pub column_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub fix_suggestion: Option<String>,
    pub fix_code: Option<String>,
    pub cwe_id: Option<String>,
    pub is_dismissed: bool,
    pub dismissed_reason: Option<String>,
    pub dismissed_at: Option<String>,
    pub created_at: String,
}

/// IDE Quick Fix record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IdeQuickFix {
    pub id: String,
    pub finding_id: String,
    pub user_id: String,
    pub fix_type: String,
    pub original_code: Option<String>,
    pub fixed_code: Option<String>,
    pub applied_at: String,
    pub reverted_at: Option<String>,
}

/// Request to start an IDE session
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StartSessionRequest {
    pub ide_type: String,
    pub ide_version: Option<String>,
    pub project_path: Option<String>,
    pub project_name: Option<String>,
    pub workspace_id: Option<String>,
    pub client_info: Option<String>,
}

/// Request to end an IDE session
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EndSessionRequest {
    pub session_id: String,
}

/// Request to scan a file
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScanFileRequest {
    pub session_id: Option<String>,
    pub file_path: String,
    pub content: String,
    pub language: Option<String>,
}

/// Request to scan multiple files
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScanFilesRequest {
    pub session_id: Option<String>,
    pub files: Vec<FileContent>,
}

/// File content for scanning
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FileContent {
    pub path: String,
    pub content: String,
    pub language: Option<String>,
}

/// Request to update IDE settings
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateSettingsRequest {
    pub scan_on_save: Option<bool>,
    pub scan_on_open: Option<bool>,
    pub show_inline_hints: Option<bool>,
    pub severity_filter: Option<Vec<String>>,
    pub excluded_paths: Option<Vec<String>>,
    pub custom_rules_enabled: Option<bool>,
    pub scan_timeout_seconds: Option<i32>,
    pub max_file_size_kb: Option<i32>,
    pub enable_quick_fixes: Option<bool>,
    pub enable_code_actions: Option<bool>,
    pub theme: Option<String>,
}

/// Request to dismiss a finding
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DismissFindingRequest {
    pub finding_id: String,
    pub reason: Option<String>,
}

/// Request to apply a quick fix
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApplyQuickFixRequest {
    pub finding_id: String,
    pub fix_type: String,
}

/// Response for file scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    pub file_path: String,
    pub findings: Vec<IdeFindingResponse>,
    pub scan_duration_ms: i64,
}

/// IDE finding response (formatted for IDE display)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdeFindingResponse {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub line_start: i32,
    pub line_end: i32,
    pub column_start: Option<i32>,
    pub column_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub fix_suggestion: Option<String>,
    pub fix_code: Option<String>,
    pub cwe_id: Option<String>,
    pub quick_fixes: Vec<QuickFixOption>,
}

/// Quick fix option for IDE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickFixOption {
    pub id: String,
    pub title: String,
    pub description: String,
    pub fix_type: String,
    pub preview: Option<String>,
}

/// IDE statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdeStats {
    pub total_sessions: i64,
    pub active_sessions: i64,
    pub total_files_scanned: i64,
    pub total_findings: i64,
    pub total_fixed: i64,
    pub by_ide_type: Vec<IdeTypeCount>,
    pub by_severity: Vec<SeverityCount>,
}

/// Count by IDE type
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IdeTypeCount {
    pub ide_type: String,
    pub count: i64,
}

/// Count by severity
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

/// Default IDE settings
impl Default for UpdateSettingsRequest {
    fn default() -> Self {
        Self {
            scan_on_save: Some(true),
            scan_on_open: Some(false),
            show_inline_hints: Some(true),
            severity_filter: Some(vec![
                "critical".to_string(),
                "high".to_string(),
                "medium".to_string(),
            ]),
            excluded_paths: Some(vec![
                "**/node_modules/**".to_string(),
                "**/vendor/**".to_string(),
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
            ]),
            custom_rules_enabled: Some(true),
            scan_timeout_seconds: Some(30),
            max_file_size_kb: Some(1024),
            enable_quick_fixes: Some(true),
            enable_code_actions: Some(true),
            theme: Some("auto".to_string()),
        }
    }
}
