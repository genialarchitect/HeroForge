//! Core SCAP 1.3 data structures
//!
//! This module defines the fundamental types used throughout the SCAP engine,
//! including common enums, result types, and shared structures.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Common Types
// ============================================================================

/// Unique identifier for SCAP content bundles
pub type BundleId = String;

/// Unique identifier for SCAP scan executions
pub type ExecutionId = String;

/// SCAP version supported by this implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ScapVersion {
    #[default]
    V1_3,
    V1_2,
    V1_1,
}

impl std::fmt::Display for ScapVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScapVersion::V1_3 => write!(f, "1.3"),
            ScapVersion::V1_2 => write!(f, "1.2"),
            ScapVersion::V1_1 => write!(f, "1.1"),
        }
    }
}

/// Localized text with optional language code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalizedText {
    pub text: String,
    pub lang: Option<String>,
}

impl LocalizedText {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            lang: None,
        }
    }

    pub fn with_lang(text: impl Into<String>, lang: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            lang: Some(lang.into()),
        }
    }
}

impl Default for LocalizedText {
    fn default() -> Self {
        Self {
            text: String::new(),
            lang: None,
        }
    }
}

/// Reference to external resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub href: String,
    pub title: Option<String>,
    pub publisher: Option<String>,
}

// ============================================================================
// SCAP Content Bundle
// ============================================================================

/// Source of SCAP content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScapContentSource {
    /// Defense Information Systems Agency
    Disa,
    /// Center for Internet Security
    Cis,
    /// National Institute of Standards and Technology
    Nist,
    /// Custom/user-provided content
    Custom,
}

impl std::fmt::Display for ScapContentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScapContentSource::Disa => write!(f, "DISA"),
            ScapContentSource::Cis => write!(f, "CIS"),
            ScapContentSource::Nist => write!(f, "NIST"),
            ScapContentSource::Custom => write!(f, "Custom"),
        }
    }
}

/// Status of imported SCAP content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContentStatus {
    #[default]
    Active,
    Deprecated,
    Disabled,
}

/// SCAP Content Bundle metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScapContentBundle {
    pub id: BundleId,
    pub name: String,
    pub version: String,
    pub source: ScapContentSource,
    pub source_url: Option<String>,
    pub file_hash: String,
    pub imported_at: DateTime<Utc>,
    pub imported_by: Option<String>,
    pub status: ContentStatus,
    pub metadata: HashMap<String, String>,
    /// Number of benchmarks in this bundle
    pub benchmark_count: usize,
    /// Number of OVAL definitions in this bundle
    pub oval_definition_count: usize,
}

// ============================================================================
// Severity and Status Types
// ============================================================================

/// SCAP/XCCDF severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ScapSeverity {
    Unknown,
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ScapSeverity {
    /// Convert to weight for scoring (0.0 to 1.0)
    pub fn weight(&self) -> f64 {
        match self {
            ScapSeverity::Unknown => 0.0,
            ScapSeverity::Info => 0.1,
            ScapSeverity::Low => 0.3,
            ScapSeverity::Medium => 0.5,
            ScapSeverity::High => 0.7,
            ScapSeverity::Critical => 1.0,
        }
    }

    /// Parse from string (case-insensitive)
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" | "cat1" | "cat i" | "cati" => ScapSeverity::Critical,
            "high" | "cat2" | "cat ii" | "catii" => ScapSeverity::High,
            "medium" | "cat3" | "cat iii" | "catiii" => ScapSeverity::Medium,
            "low" => ScapSeverity::Low,
            "info" | "informational" => ScapSeverity::Info,
            _ => ScapSeverity::Unknown,
        }
    }
}

impl std::fmt::Display for ScapSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScapSeverity::Unknown => write!(f, "Unknown"),
            ScapSeverity::Info => write!(f, "Info"),
            ScapSeverity::Low => write!(f, "Low"),
            ScapSeverity::Medium => write!(f, "Medium"),
            ScapSeverity::High => write!(f, "High"),
            ScapSeverity::Critical => write!(f, "Critical"),
        }
    }
}

/// STIG Category (CAT I, II, III)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum StigCategory {
    /// CAT I - Critical
    CatI,
    /// CAT II - High
    CatII,
    /// CAT III - Medium
    CatIII,
}

impl StigCategory {
    pub fn to_severity(&self) -> ScapSeverity {
        match self {
            StigCategory::CatI => ScapSeverity::Critical,
            StigCategory::CatII => ScapSeverity::High,
            StigCategory::CatIII => ScapSeverity::Medium,
        }
    }
}

impl std::fmt::Display for StigCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StigCategory::CatI => write!(f, "CAT I"),
            StigCategory::CatII => write!(f, "CAT II"),
            StigCategory::CatIII => write!(f, "CAT III"),
        }
    }
}

// ============================================================================
// Identifiers (CCE, CCI, CVE)
// ============================================================================

/// Common Configuration Enumeration identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CceId(pub String);

impl CceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Validate CCE format (CCE-XXXXX-X or CCE-XXXXXXX-X)
    pub fn is_valid(&self) -> bool {
        let re = regex::Regex::new(r"^CCE-\d{5,7}-\d$").unwrap();
        re.is_match(&self.0)
    }
}

impl std::fmt::Display for CceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Control Correlation Identifier (DoD)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CciId(pub String);

impl CciId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Validate CCI format (CCI-XXXXXX)
    pub fn is_valid(&self) -> bool {
        let re = regex::Regex::new(r"^CCI-\d{6}$").unwrap();
        re.is_match(&self.0)
    }
}

impl std::fmt::Display for CciId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Common Vulnerabilities and Exposures identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CveId(pub String);

impl CveId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Validate CVE format (CVE-YYYY-NNNNN)
    pub fn is_valid(&self) -> bool {
        let re = regex::Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap();
        re.is_match(&self.0)
    }
}

impl std::fmt::Display for CveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generic identifier that can reference CCE, CCI, CVE, or other systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ident {
    pub system: String,
    pub value: String,
}

impl Ident {
    pub fn cce(id: impl Into<String>) -> Self {
        Self {
            system: "http://cce.mitre.org".to_string(),
            value: id.into(),
        }
    }

    pub fn cci(id: impl Into<String>) -> Self {
        Self {
            system: "http://iase.disa.mil/cci".to_string(),
            value: id.into(),
        }
    }

    pub fn cve(id: impl Into<String>) -> Self {
        Self {
            system: "http://cve.mitre.org".to_string(),
            value: id.into(),
        }
    }

    pub fn is_cce(&self) -> bool {
        self.system.contains("cce")
    }

    pub fn is_cci(&self) -> bool {
        self.system.contains("cci")
    }

    pub fn is_cve(&self) -> bool {
        self.system.contains("cve")
    }
}

// ============================================================================
// Platform Types
// ============================================================================

/// Target platform for SCAP content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TargetPlatform {
    /// Cross-platform (independent)
    Independent,
    /// Unix-like systems (generic)
    Unix,
    /// Linux-specific
    Linux,
    /// Windows-specific
    Windows,
    /// macOS-specific
    MacOs,
    /// Solaris-specific
    Solaris,
    /// AIX-specific
    Aix,
    /// HP-UX specific
    HpUx,
    /// Cisco IOS
    CiscoIos,
    /// Juniper Junos
    Junos,
    /// VMware ESXi
    Esxi,
}

impl TargetPlatform {
    /// Check if this platform is a subset of another
    pub fn is_subset_of(&self, other: &TargetPlatform) -> bool {
        match (self, other) {
            (TargetPlatform::Independent, _) => true,
            (TargetPlatform::Linux, TargetPlatform::Unix) => true,
            (TargetPlatform::MacOs, TargetPlatform::Unix) => true,
            (TargetPlatform::Solaris, TargetPlatform::Unix) => true,
            (TargetPlatform::Aix, TargetPlatform::Unix) => true,
            (TargetPlatform::HpUx, TargetPlatform::Unix) => true,
            (a, b) => a == b,
        }
    }
}

impl std::fmt::Display for TargetPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetPlatform::Independent => write!(f, "Independent"),
            TargetPlatform::Unix => write!(f, "Unix"),
            TargetPlatform::Linux => write!(f, "Linux"),
            TargetPlatform::Windows => write!(f, "Windows"),
            TargetPlatform::MacOs => write!(f, "macOS"),
            TargetPlatform::Solaris => write!(f, "Solaris"),
            TargetPlatform::Aix => write!(f, "AIX"),
            TargetPlatform::HpUx => write!(f, "HP-UX"),
            TargetPlatform::CiscoIos => write!(f, "Cisco IOS"),
            TargetPlatform::Junos => write!(f, "Junos"),
            TargetPlatform::Esxi => write!(f, "ESXi"),
        }
    }
}

// ============================================================================
// Scan Execution Types
// ============================================================================

/// Status of a SCAP scan execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionStatus {
    #[default]
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionStatus::Pending => write!(f, "Pending"),
            ExecutionStatus::Running => write!(f, "Running"),
            ExecutionStatus::Completed => write!(f, "Completed"),
            ExecutionStatus::Failed => write!(f, "Failed"),
            ExecutionStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

/// Configuration for a SCAP scan execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScapScanConfig {
    /// Target host or IP
    pub target: String,
    /// XCCDF benchmark ID to use
    pub benchmark_id: String,
    /// XCCDF profile ID to use
    pub profile_id: String,
    /// Optional credentials for remote execution
    pub credentials: Option<ScapCredentials>,
    /// Timeout in seconds for the entire scan
    pub timeout_secs: u64,
    /// Maximum parallel OVAL evaluations
    pub parallel_evaluations: usize,
    /// Customer/engagement association
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

impl Default for ScapScanConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            benchmark_id: String::new(),
            profile_id: String::new(),
            credentials: None,
            timeout_secs: 3600,
            parallel_evaluations: 4,
            customer_id: None,
            engagement_id: None,
        }
    }
}

/// Credentials for remote SCAP execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScapCredentials {
    /// Authentication type
    pub auth_type: ScapAuthType,
    /// Username
    pub username: String,
    /// Password (never logged/serialized in full)
    #[serde(skip_serializing)]
    pub password: Option<String>,
    /// SSH private key (for Unix)
    #[serde(skip_serializing)]
    pub ssh_key: Option<String>,
    /// Domain (for Windows)
    pub domain: Option<String>,
    /// Use SSL/TLS for connection
    pub use_ssl: bool,
    /// Port override
    pub port: Option<u16>,
}

/// Authentication type for remote execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScapAuthType {
    /// SSH with password
    SshPassword,
    /// SSH with public key
    SshKey,
    /// WinRM with NTLM
    WinrmNtlm,
    /// WinRM with Kerberos
    WinrmKerberos,
    /// Local execution (no remote auth needed)
    Local,
}

/// SCAP scan execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScapScanExecution {
    pub id: ExecutionId,
    pub scan_id: String,
    pub benchmark_id: String,
    pub profile_id: String,
    pub target_host: String,
    pub target_cpes: Vec<String>,
    pub status: ExecutionStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub statistics: ExecutionStatistics,
    pub created_at: DateTime<Utc>,
}

/// Statistics for a SCAP execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionStatistics {
    pub rules_total: usize,
    pub rules_pass: usize,
    pub rules_fail: usize,
    pub rules_error: usize,
    pub rules_unknown: usize,
    pub rules_not_applicable: usize,
    pub rules_not_checked: usize,
    pub rules_not_selected: usize,
    pub rules_informational: usize,
    pub oval_definitions_evaluated: usize,
    pub oval_objects_collected: usize,
    pub score: Option<f64>,
    pub score_max: Option<f64>,
}

impl ExecutionStatistics {
    /// Calculate pass rate (0.0 to 100.0)
    pub fn pass_rate(&self) -> f64 {
        let total = self.rules_pass + self.rules_fail;
        if total == 0 {
            0.0
        } else {
            (self.rules_pass as f64 / total as f64) * 100.0
        }
    }

    /// Calculate weighted score percentage
    pub fn score_percentage(&self) -> Option<f64> {
        match (self.score, self.score_max) {
            (Some(score), Some(max)) if max > 0.0 => Some((score / max) * 100.0),
            _ => None,
        }
    }
}

// ============================================================================
// Remediation Types
// ============================================================================

/// Remediation/fix information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationInfo {
    /// Human-readable fix description
    pub description: Option<String>,
    /// Script or command to apply fix
    pub script: Option<String>,
    /// Script type (shell, powershell, etc.)
    pub script_type: Option<String>,
    /// Complexity estimate
    pub complexity: RemediationComplexity,
    /// Whether this fix can be applied automatically
    pub automatable: bool,
    /// Disruption level if fix is applied
    pub disruption: DisruptionLevel,
    /// Reboot required after fix
    pub reboot_required: bool,
}

/// Complexity of remediation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RemediationComplexity {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

/// Disruption level of applying a fix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DisruptionLevel {
    #[default]
    Unknown,
    /// No service interruption
    None,
    /// Brief interruption
    Low,
    /// Moderate interruption
    Medium,
    /// Significant interruption
    High,
}

// ============================================================================
// Error Types
// ============================================================================

/// SCAP-specific error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScapError {
    /// Content parsing error
    ParseError { message: String, location: Option<String> },
    /// Content validation error
    ValidationError { message: String, rule_id: Option<String> },
    /// OVAL evaluation error
    EvaluationError { message: String, definition_id: Option<String> },
    /// Remote execution error
    RemoteError { message: String, host: String },
    /// Database error
    DatabaseError { message: String },
    /// Configuration error
    ConfigError { message: String },
    /// Timeout
    Timeout { operation: String, timeout_secs: u64 },
    /// Content not found
    NotFound { content_type: String, id: String },
}

impl std::fmt::Display for ScapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScapError::ParseError { message, location } => {
                write!(f, "Parse error: {}", message)?;
                if let Some(loc) = location {
                    write!(f, " at {}", loc)?;
                }
                Ok(())
            }
            ScapError::ValidationError { message, rule_id } => {
                write!(f, "Validation error: {}", message)?;
                if let Some(id) = rule_id {
                    write!(f, " (rule: {})", id)?;
                }
                Ok(())
            }
            ScapError::EvaluationError { message, definition_id } => {
                write!(f, "Evaluation error: {}", message)?;
                if let Some(id) = definition_id {
                    write!(f, " (definition: {})", id)?;
                }
                Ok(())
            }
            ScapError::RemoteError { message, host } => {
                write!(f, "Remote error on {}: {}", host, message)
            }
            ScapError::DatabaseError { message } => {
                write!(f, "Database error: {}", message)
            }
            ScapError::ConfigError { message } => {
                write!(f, "Configuration error: {}", message)
            }
            ScapError::Timeout { operation, timeout_secs } => {
                write!(f, "Timeout after {}s: {}", timeout_secs, operation)
            }
            ScapError::NotFound { content_type, id } => {
                write!(f, "{} not found: {}", content_type, id)
            }
        }
    }
}

impl std::error::Error for ScapError {}

// ============================================================================
// Utility Functions
// ============================================================================

/// Generate a unique ID for SCAP entities
pub fn generate_scap_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Parse a date string in common SCAP formats
pub fn parse_scap_date(s: &str) -> Option<NaiveDate> {
    // Try common formats
    let formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d-%m-%Y",
        "%m/%d/%Y",
    ];

    for fmt in formats {
        if let Ok(date) = NaiveDate::parse_from_str(s, fmt) {
            return Some(date);
        }
    }

    None
}

/// Sanitize XML content for safe inclusion
pub fn sanitize_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_weight() {
        assert_eq!(ScapSeverity::Critical.weight(), 1.0);
        assert_eq!(ScapSeverity::High.weight(), 0.7);
        assert_eq!(ScapSeverity::Medium.weight(), 0.5);
        assert_eq!(ScapSeverity::Low.weight(), 0.3);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(ScapSeverity::from_str_loose("critical"), ScapSeverity::Critical);
        assert_eq!(ScapSeverity::from_str_loose("CAT I"), ScapSeverity::Critical);
        assert_eq!(ScapSeverity::from_str_loose("high"), ScapSeverity::High);
        assert_eq!(ScapSeverity::from_str_loose("CAT II"), ScapSeverity::High);
    }

    #[test]
    fn test_cce_id_validation() {
        assert!(CceId::new("CCE-12345-6").is_valid());
        assert!(CceId::new("CCE-1234567-8").is_valid());
        assert!(!CceId::new("CCE-123-4").is_valid());
        assert!(!CceId::new("invalid").is_valid());
    }

    #[test]
    fn test_cci_id_validation() {
        assert!(CciId::new("CCI-000001").is_valid());
        assert!(CciId::new("CCI-123456").is_valid());
        assert!(!CciId::new("CCI-12345").is_valid());
        assert!(!CciId::new("invalid").is_valid());
    }

    #[test]
    fn test_cve_id_validation() {
        assert!(CveId::new("CVE-2021-12345").is_valid());
        assert!(CveId::new("CVE-2024-1234").is_valid());
        assert!(!CveId::new("CVE-21-123").is_valid());
        assert!(!CveId::new("invalid").is_valid());
    }

    #[test]
    fn test_platform_subset() {
        assert!(TargetPlatform::Linux.is_subset_of(&TargetPlatform::Unix));
        assert!(TargetPlatform::MacOs.is_subset_of(&TargetPlatform::Unix));
        assert!(!TargetPlatform::Windows.is_subset_of(&TargetPlatform::Unix));
        assert!(TargetPlatform::Independent.is_subset_of(&TargetPlatform::Windows));
    }

    #[test]
    fn test_execution_statistics() {
        let mut stats = ExecutionStatistics::default();
        stats.rules_pass = 80;
        stats.rules_fail = 20;
        stats.score = Some(85.5);
        stats.score_max = Some(100.0);

        assert_eq!(stats.pass_rate(), 80.0);
        assert_eq!(stats.score_percentage(), Some(85.5));
    }

    #[test]
    fn test_parse_scap_date() {
        assert_eq!(
            parse_scap_date("2024-01-15"),
            Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap())
        );
        assert_eq!(
            parse_scap_date("2024/01/15"),
            Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap())
        );
        assert!(parse_scap_date("invalid").is_none());
    }

    #[test]
    fn test_sanitize_xml() {
        assert_eq!(sanitize_xml("a < b"), "a &lt; b");
        assert_eq!(sanitize_xml("a & b"), "a &amp; b");
        assert_eq!(sanitize_xml("\"quoted\""), "&quot;quoted&quot;");
    }
}
