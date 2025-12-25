// Nuclei Scanner Types
// Data structures for Nuclei vulnerability scanner integration

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Severity levels matching Nuclei's classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NucleiSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

impl Default for NucleiSeverity {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for NucleiSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<&str> for NucleiSeverity {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "info" | "informational" => Self::Info,
            _ => Self::Unknown,
        }
    }
}

/// Nuclei scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiConfig {
    /// Target URLs or hosts to scan
    pub targets: Vec<String>,
    /// Specific template paths or IDs to use
    #[serde(default)]
    pub templates: Vec<String>,
    /// Template tags to filter by (e.g., "cve", "rce", "sqli")
    #[serde(default)]
    pub template_tags: Vec<String>,
    /// Exclude templates with these tags
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    /// Severity levels to include
    #[serde(default)]
    pub severity: Vec<NucleiSeverity>,
    /// Rate limit (requests per second)
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
    /// Number of concurrent templates to run
    #[serde(default = "default_concurrency")]
    pub concurrency: u32,
    /// Timeout per request
    #[serde(default = "default_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// Enable headless browser for JavaScript-heavy targets
    #[serde(default)]
    pub headless: bool,
    /// Follow redirects
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    /// Maximum redirects to follow
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u32,
    /// Custom headers to include
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Proxy URL
    pub proxy: Option<String>,
    /// Path to custom templates directory
    pub custom_templates_path: Option<String>,
    /// Enable automatic template updates before scan
    #[serde(default)]
    pub auto_update_templates: bool,
    /// Silent mode (minimal output)
    #[serde(default)]
    pub silent: bool,
}

fn default_rate_limit() -> u32 {
    150
}

fn default_concurrency() -> u32 {
    25
}

fn default_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_true() -> bool {
    true
}

fn default_max_redirects() -> u32 {
    10
}

impl Default for NucleiConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            templates: Vec::new(),
            template_tags: Vec::new(),
            exclude_tags: Vec::new(),
            severity: vec![
                NucleiSeverity::Critical,
                NucleiSeverity::High,
                NucleiSeverity::Medium,
            ],
            rate_limit: default_rate_limit(),
            concurrency: default_concurrency(),
            timeout: default_timeout(),
            headless: false,
            follow_redirects: true,
            max_redirects: default_max_redirects(),
            headers: Vec::new(),
            proxy: None,
            custom_templates_path: None,
            auto_update_templates: false,
            silent: false,
        }
    }
}

/// Template information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiTemplate {
    pub id: String,
    pub name: String,
    pub author: Vec<String>,
    pub severity: NucleiSeverity,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub reference: Vec<String>,
    pub classification: Option<TemplateClassification>,
    pub path: String,
}

/// Template classification metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateClassification {
    #[serde(rename = "cve-id")]
    pub cve_id: Option<String>,
    #[serde(rename = "cwe-id")]
    pub cwe_id: Option<String>,
    #[serde(rename = "cvss-metrics")]
    pub cvss_metrics: Option<String>,
    #[serde(rename = "cvss-score")]
    pub cvss_score: Option<f32>,
}

/// Result from a Nuclei scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiResult {
    /// Unique result ID
    pub id: String,
    /// Template ID that matched
    pub template_id: String,
    /// Template name
    pub template_name: String,
    /// Severity of the finding
    pub severity: NucleiSeverity,
    /// Target host/URL
    pub host: String,
    /// Specific matched URL or endpoint
    pub matched_at: String,
    /// Type of check (http, dns, network, etc.)
    pub check_type: String,
    /// Extracted data from the match
    #[serde(default)]
    pub extracted_results: Vec<String>,
    /// Request that triggered the match
    pub request: Option<String>,
    /// Response that matched
    pub response: Option<String>,
    /// Curl command to reproduce
    pub curl_command: Option<String>,
    /// IP address of target
    pub ip: Option<String>,
    /// Matcher name that triggered
    pub matcher_name: Option<String>,
    /// CVE ID if applicable
    pub cve_id: Option<String>,
    /// When the result was found
    pub timestamp: DateTime<Utc>,
}

/// Nuclei scan status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NucleiScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl Default for NucleiScanStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl std::fmt::Display for NucleiScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Nuclei scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiScan {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub targets: Vec<String>,
    pub config: NucleiConfig,
    pub status: NucleiScanStatus,
    pub results_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Progress update for a running scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NucleiProgress {
    Started {
        scan_id: String,
        total_targets: usize,
        total_templates: usize,
    },
    TargetStarted {
        target: String,
        index: usize,
        total: usize,
    },
    ResultFound {
        template_id: String,
        host: String,
        severity: NucleiSeverity,
    },
    TemplatesLoaded {
        count: usize,
    },
    Progress {
        percent: u8,
        message: String,
    },
    Completed {
        scan_id: String,
        total_results: usize,
        duration_ms: u64,
    },
    Error {
        scan_id: String,
        message: String,
    },
    Cancelled {
        scan_id: String,
    },
}

/// Request to create a new Nuclei scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNucleiScanRequest {
    pub name: Option<String>,
    pub targets: Vec<String>,
    #[serde(flatten)]
    pub config: NucleiConfig,
}

/// Statistics about available templates
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemplateStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub tags: Vec<(String, usize)>,
    pub last_updated: Option<DateTime<Utc>>,
}
