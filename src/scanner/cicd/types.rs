//! Types for CI/CD pipeline security scanning

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of CI/CD platform
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CiCdPlatform {
    GitHubActions,
    GitLabCI,
    Jenkins,
    CircleCI,
    TravisCI,
    AzurePipelines,
}

impl std::fmt::Display for CiCdPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiCdPlatform::GitHubActions => write!(f, "GitHub Actions"),
            CiCdPlatform::GitLabCI => write!(f, "GitLab CI"),
            CiCdPlatform::Jenkins => write!(f, "Jenkins"),
            CiCdPlatform::CircleCI => write!(f, "CircleCI"),
            CiCdPlatform::TravisCI => write!(f, "Travis CI"),
            CiCdPlatform::AzurePipelines => write!(f, "Azure Pipelines"),
        }
    }
}

/// Severity level for CI/CD findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum CiCdSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for CiCdSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiCdSeverity::Info => write!(f, "info"),
            CiCdSeverity::Low => write!(f, "low"),
            CiCdSeverity::Medium => write!(f, "medium"),
            CiCdSeverity::High => write!(f, "high"),
            CiCdSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Category of CI/CD security issue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CiCdCategory {
    /// Hardcoded secrets or credentials
    Secrets,
    /// Script injection vulnerabilities
    Injection,
    /// Permission and access control issues
    Permissions,
    /// Supply chain security risks
    SupplyChain,
    /// Insecure configuration
    Configuration,
    /// Data exposure risks
    DataExposure,
    /// Code execution risks
    CodeExecution,
}

impl std::fmt::Display for CiCdCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiCdCategory::Secrets => write!(f, "Secrets"),
            CiCdCategory::Injection => write!(f, "Injection"),
            CiCdCategory::Permissions => write!(f, "Permissions"),
            CiCdCategory::SupplyChain => write!(f, "Supply Chain"),
            CiCdCategory::Configuration => write!(f, "Configuration"),
            CiCdCategory::DataExposure => write!(f, "Data Exposure"),
            CiCdCategory::CodeExecution => write!(f, "Code Execution"),
        }
    }
}

/// A CI/CD security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdRule {
    /// Unique rule identifier (e.g., "ACTIONS001")
    pub id: String,
    /// Platform this rule applies to
    pub platform: CiCdPlatform,
    /// Category of the rule
    pub category: CiCdCategory,
    /// Severity level
    pub severity: CiCdSeverity,
    /// Short title of the rule
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Remediation guidance
    pub remediation: String,
    /// Related CWE ID (if applicable)
    pub cwe_id: Option<String>,
    /// References/documentation links
    pub references: Vec<String>,
}

/// A finding from CI/CD security scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdFinding {
    /// The rule that triggered this finding
    pub rule_id: String,
    /// Platform where the issue was found
    pub platform: CiCdPlatform,
    /// Category of the issue
    pub category: CiCdCategory,
    /// Severity level
    pub severity: CiCdSeverity,
    /// Short title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// File where the issue was found
    pub file_path: String,
    /// Line number (if applicable)
    pub line_number: Option<usize>,
    /// Column number (if applicable)
    pub column: Option<usize>,
    /// Job name (if applicable)
    pub job_name: Option<String>,
    /// Step name (if applicable)
    pub step_name: Option<String>,
    /// Code snippet showing the issue
    pub code_snippet: Option<String>,
    /// Remediation guidance
    pub remediation: String,
    /// Related CWE ID
    pub cwe_id: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl CiCdFinding {
    /// Create a new finding from a rule match
    pub fn from_rule(
        rule: &CiCdRule,
        file_path: &str,
        line_number: Option<usize>,
        code_snippet: Option<String>,
    ) -> Self {
        Self {
            rule_id: rule.id.clone(),
            platform: rule.platform.clone(),
            category: rule.category.clone(),
            severity: rule.severity.clone(),
            title: rule.title.clone(),
            description: rule.description.clone(),
            file_path: file_path.to_string(),
            line_number,
            column: None,
            job_name: None,
            step_name: None,
            code_snippet,
            remediation: rule.remediation.clone(),
            cwe_id: rule.cwe_id.clone(),
            metadata: HashMap::new(),
        }
    }

    /// Add job context
    pub fn with_job(mut self, job_name: &str) -> Self {
        self.job_name = Some(job_name.to_string());
        self
    }

    /// Add step context
    pub fn with_step(mut self, step_name: &str) -> Self {
        self.step_name = Some(step_name.to_string());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Result of a CI/CD scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdScanResult {
    /// Platform that was scanned
    pub platform: CiCdPlatform,
    /// Files that were scanned
    pub files_scanned: Vec<String>,
    /// All findings
    pub findings: Vec<CiCdFinding>,
    /// Count by severity
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
    /// Any errors encountered
    pub errors: Vec<String>,
}

impl CiCdScanResult {
    /// Create a new scan result
    pub fn new(platform: CiCdPlatform) -> Self {
        Self {
            platform,
            files_scanned: Vec::new(),
            findings: Vec::new(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            duration_ms: 0,
            errors: Vec::new(),
        }
    }

    /// Add a finding and update counts
    pub fn add_finding(&mut self, finding: CiCdFinding) {
        match finding.severity {
            CiCdSeverity::Critical => self.critical_count += 1,
            CiCdSeverity::High => self.high_count += 1,
            CiCdSeverity::Medium => self.medium_count += 1,
            CiCdSeverity::Low => self.low_count += 1,
            CiCdSeverity::Info => self.info_count += 1,
        }
        self.findings.push(finding);
    }

    /// Get total finding count
    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }
}

/// Configuration for CI/CD scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdScanConfig {
    /// Enable GitHub Actions scanning
    pub scan_github_actions: bool,
    /// Enable GitLab CI scanning
    pub scan_gitlab_ci: bool,
    /// Enable Jenkins scanning
    pub scan_jenkins: bool,
    /// Minimum severity to report
    pub min_severity: CiCdSeverity,
    /// Categories to include (empty = all)
    pub categories: Vec<CiCdCategory>,
    /// Rule IDs to exclude
    pub exclude_rules: Vec<String>,
    /// Maximum file size to scan (bytes)
    pub max_file_size: usize,
}

impl Default for CiCdScanConfig {
    fn default() -> Self {
        Self {
            scan_github_actions: true,
            scan_gitlab_ci: true,
            scan_jenkins: true,
            min_severity: CiCdSeverity::Low,
            categories: Vec::new(),
            exclude_rules: Vec::new(),
            max_file_size: 10 * 1024 * 1024, // 10MB
        }
    }
}
