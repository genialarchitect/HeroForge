// CI/CD Integration Types
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// CI/CD platform types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CiCdPlatform {
    GitHubActions,
    Jenkins,
    GitLabCi,
    Generic,
}

impl CiCdPlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GitHubActions => "github_actions",
            Self::Jenkins => "jenkins",
            Self::GitLabCi => "gitlab_ci",
            Self::Generic => "generic",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "github_actions" => Some(Self::GitHubActions),
            "jenkins" => Some(Self::Jenkins),
            "gitlab_ci" => Some(Self::GitLabCi),
            "generic" => Some(Self::Generic),
            _ => None,
        }
    }
}

/// Token permissions for CI/CD tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CiCdTokenPermissions {
    /// Can trigger scans
    pub can_scan: bool,
    /// Can read scan results
    pub can_read_results: bool,
    /// Can export reports (SARIF, JUnit)
    pub can_export: bool,
    /// Can view quality gate status
    pub can_view_quality_gates: bool,
}

/// CI/CD API token stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CiCdToken {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub platform: String,
    pub permissions: String, // JSON-encoded CiCdTokenPermissions
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// CI/CD token response (without sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdTokenInfo {
    pub id: String,
    pub name: String,
    pub token_prefix: String,
    pub platform: String,
    pub permissions: CiCdTokenPermissions,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Response when creating a new CI/CD token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCiCdTokenResponse {
    pub id: String,
    pub token: String, // Only returned once at creation
    pub token_prefix: String,
    pub name: String,
    pub platform: String,
    pub permissions: CiCdTokenPermissions,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a new CI/CD token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCiCdTokenRequest {
    pub name: String,
    pub platform: CiCdPlatform,
    #[serde(default)]
    pub permissions: CiCdTokenPermissions,
    /// Token expiration in days (None = never expires)
    pub expires_in_days: Option<u32>,
}

/// CI/CD triggered scan run stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CiCdRun {
    pub id: String,
    pub token_id: String,
    pub scan_id: String,
    pub platform: String,
    /// Reference from CI system (commit SHA, build number, etc.)
    pub ci_ref: Option<String>,
    /// Branch or tag name
    pub ci_branch: Option<String>,
    /// Pipeline/workflow URL
    pub ci_url: Option<String>,
    /// Repository identifier
    pub repository: Option<String>,
    pub status: String, // pending, running, completed, failed
    pub quality_gate_passed: Option<bool>,
    pub quality_gate_details: Option<String>, // JSON
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Severity threshold for quality gates
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SeverityThreshold {
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityThreshold {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

/// Quality gate configuration
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct QualityGate {
    pub id: String,
    pub user_id: String,
    pub name: String,
    /// Fail if vulnerabilities at or above this severity are found
    pub fail_on_severity: String, // SeverityThreshold as string
    /// Maximum allowed vulnerabilities before failing (None = any count fails)
    pub max_vulnerabilities: Option<i32>,
    /// Maximum allowed vulnerabilities per severity level
    pub max_critical: Option<i32>,
    pub max_high: Option<i32>,
    pub max_medium: Option<i32>,
    pub max_low: Option<i32>,
    /// Fail on new vulnerabilities compared to baseline scan
    pub fail_on_new_vulns: bool,
    /// Baseline scan ID for comparison
    pub baseline_scan_id: Option<String>,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update a quality gate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateRequest {
    pub name: String,
    pub fail_on_severity: SeverityThreshold,
    pub max_vulnerabilities: Option<i32>,
    pub max_critical: Option<i32>,
    pub max_high: Option<i32>,
    pub max_medium: Option<i32>,
    pub max_low: Option<i32>,
    #[serde(default)]
    pub fail_on_new_vulns: bool,
    pub baseline_scan_id: Option<String>,
    #[serde(default)]
    pub is_default: bool,
}

/// Quality gate evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateResult {
    pub passed: bool,
    pub gate_name: String,
    pub fail_reason: Option<String>,
    pub vulnerability_counts: VulnerabilityCounts,
    pub threshold_violations: Vec<ThresholdViolation>,
    pub new_vulnerabilities: Option<i32>,
}

/// Counts of vulnerabilities by severity
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityCounts {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub total: i32,
}

/// A single threshold violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdViolation {
    pub threshold_type: String,
    pub threshold_value: i32,
    pub actual_value: i32,
    pub message: String,
}

/// Request to trigger a CI/CD scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdScanRequest {
    pub name: String,
    pub targets: Vec<String>,
    #[serde(default = "default_port_range")]
    pub port_range: (u16, u16),
    #[serde(default = "default_threads")]
    pub threads: usize,
    #[serde(default = "default_true")]
    pub enable_os_detection: bool,
    #[serde(default = "default_true")]
    pub enable_service_detection: bool,
    #[serde(default)]
    pub enable_vuln_scan: bool,
    /// Quality gate ID to evaluate against (uses default if not specified)
    pub quality_gate_id: Option<String>,
    /// CI/CD metadata
    pub ci_ref: Option<String>,
    pub ci_branch: Option<String>,
    pub ci_url: Option<String>,
    pub repository: Option<String>,
}

fn default_port_range() -> (u16, u16) {
    (1, 1000)
}

fn default_threads() -> usize {
    100
}

fn default_true() -> bool {
    true
}

/// CI/CD scan status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdScanStatus {
    pub run_id: String,
    pub scan_id: String,
    pub status: String,
    pub progress: f32,
    pub quality_gate_passed: Option<bool>,
    pub quality_gate_result: Option<QualityGateResult>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Exit code recommendation (0 = pass, 1 = fail)
    pub exit_code: i32,
}

/// SARIF (Static Analysis Results Interchange Format) output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

impl Default for SarifReport {
    fn default() -> Self {
        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<SarifMessage>,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRuleProperties>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "security-severity")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String, // error, warning, note
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: i32,
    #[serde(rename = "startColumn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifInvocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(rename = "endTimeUtc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,
}

/// JUnit XML output structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JUnitTestSuites {
    pub testsuites: Vec<JUnitTestSuite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JUnitTestSuite {
    pub name: String,
    pub tests: i32,
    pub failures: i32,
    pub errors: i32,
    pub skipped: i32,
    pub time: f64,
    pub timestamp: String,
    pub testcases: Vec<JUnitTestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JUnitTestCase {
    pub name: String,
    pub classname: String,
    pub time: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<JUnitFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JUnitError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<JUnitSkipped>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JUnitFailure {
    pub message: String,
    #[serde(rename = "type")]
    pub failure_type: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JUnitError {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JUnitSkipped {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_threshold_ordering() {
        assert!(SeverityThreshold::Low < SeverityThreshold::Medium);
        assert!(SeverityThreshold::Medium < SeverityThreshold::High);
        assert!(SeverityThreshold::High < SeverityThreshold::Critical);
    }

    #[test]
    fn test_platform_from_str() {
        assert_eq!(CiCdPlatform::from_str("github_actions"), Some(CiCdPlatform::GitHubActions));
        assert_eq!(CiCdPlatform::from_str("jenkins"), Some(CiCdPlatform::Jenkins));
        assert_eq!(CiCdPlatform::from_str("gitlab_ci"), Some(CiCdPlatform::GitLabCi));
        assert_eq!(CiCdPlatform::from_str("generic"), Some(CiCdPlatform::Generic));
        assert_eq!(CiCdPlatform::from_str("unknown"), None);
    }

    #[test]
    fn test_sarif_report_default() {
        let report = SarifReport::default();
        assert_eq!(report.version, "2.1.0");
        assert!(report.runs.is_empty());
    }
}
