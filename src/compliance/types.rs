//! Core types for compliance scanning
//!
//! This module defines the fundamental types used throughout the compliance
//! scanning system, including frameworks, controls, findings, and summaries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::types::Severity;

/// Supported compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    /// CIS Benchmarks - System hardening standards
    CisBenchmarks,
    /// NIST 800-53 - Federal information systems security controls
    Nist80053,
    /// NIST Cybersecurity Framework - Risk management framework
    NistCsf,
    /// PCI DSS 4.0 - Payment Card Industry Data Security Standard
    PciDss4,
    /// HIPAA Security Rule - Healthcare data protection
    Hipaa,
    /// FERPA - Family Educational Rights and Privacy Act
    Ferpa,
    /// SOC 2 - Service Organization Control 2 Trust Services Criteria
    Soc2,
    /// OWASP Top 10 2021 - Web Application Security Risks
    OwaspTop10,
}

impl ComplianceFramework {
    /// Get all available frameworks
    pub fn all() -> Vec<Self> {
        vec![
            Self::CisBenchmarks,
            Self::Nist80053,
            Self::NistCsf,
            Self::PciDss4,
            Self::Hipaa,
            Self::Ferpa,
            Self::Soc2,
            Self::OwaspTop10,
        ]
    }

    /// Get the framework ID string
    pub fn id(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "cis",
            Self::Nist80053 => "nist_800_53",
            Self::NistCsf => "nist_csf",
            Self::PciDss4 => "pci_dss",
            Self::Hipaa => "hipaa",
            Self::Ferpa => "ferpa",
            Self::Soc2 => "soc2",
            Self::OwaspTop10 => "owasp_top10",
        }
    }

    /// Get the human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "CIS Benchmarks",
            Self::Nist80053 => "NIST 800-53",
            Self::NistCsf => "NIST Cybersecurity Framework",
            Self::PciDss4 => "PCI DSS 4.0",
            Self::Hipaa => "HIPAA Security Rule",
            Self::Ferpa => "FERPA",
            Self::Soc2 => "SOC 2",
            Self::OwaspTop10 => "OWASP Top 10",
        }
    }

    /// Get the framework version
    pub fn version(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "v8.0",
            Self::Nist80053 => "Rev 5",
            Self::NistCsf => "v2.0",
            Self::PciDss4 => "v4.0",
            Self::Hipaa => "2013",
            Self::Ferpa => "2023",
            Self::Soc2 => "2017",
            Self::OwaspTop10 => "2021",
        }
    }

    /// Get the framework description
    pub fn description(&self) -> &'static str {
        match self {
            Self::CisBenchmarks => "Center for Internet Security configuration benchmarks for system hardening",
            Self::Nist80053 => "Security and privacy controls for federal information systems and organizations",
            Self::NistCsf => "Framework for improving critical infrastructure cybersecurity",
            Self::PciDss4 => "Security standards for organizations handling payment card data",
            Self::Hipaa => "Security standards for protecting electronic health information",
            Self::Ferpa => "Federal law protecting student education records and privacy",
            Self::Soc2 => "Trust Services Criteria for service organization security, availability, and confidentiality",
            Self::OwaspTop10 => "Top 10 web application security risks identified by OWASP",
        }
    }

    /// Parse from string ID
    pub fn from_id(id: &str) -> Option<Self> {
        match id.to_lowercase().as_str() {
            "cis" | "cis_benchmarks" => Some(Self::CisBenchmarks),
            "nist_800_53" | "nist80053" => Some(Self::Nist80053),
            "nist_csf" | "nistcsf" => Some(Self::NistCsf),
            "pci_dss" | "pci_dss_4" | "pcidss" => Some(Self::PciDss4),
            "hipaa" => Some(Self::Hipaa),
            "ferpa" => Some(Self::Ferpa),
            "soc2" | "soc_2" => Some(Self::Soc2),
            "owasp" | "owasp_top10" | "owasp_top_10" => Some(Self::OwaspTop10),
            _ => None,
        }
    }
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Control priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlPriority {
    High,
    Medium,
    Low,
}

impl fmt::Display for ControlPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

/// Control status indicating compliance state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    /// Control requirements are fully met
    Compliant,
    /// Control requirements are not met
    NonCompliant,
    /// Some control requirements are met
    PartiallyCompliant,
    /// Control is not applicable to this environment
    NotApplicable,
    /// Control has not been assessed (requires manual review)
    NotAssessed,
    /// Control status has been manually overridden
    ManualOverride,
}

impl ControlStatus {
    /// Check if this status indicates a compliance issue
    pub fn is_issue(&self) -> bool {
        matches!(self, Self::NonCompliant | Self::PartiallyCompliant)
    }

    /// Check if this status counts toward compliance score
    pub fn counts_toward_score(&self) -> bool {
        !matches!(self, Self::NotApplicable | Self::NotAssessed)
    }
}

impl fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compliant => write!(f, "Compliant"),
            Self::NonCompliant => write!(f, "Non-Compliant"),
            Self::PartiallyCompliant => write!(f, "Partially Compliant"),
            Self::NotApplicable => write!(f, "Not Applicable"),
            Self::NotAssessed => write!(f, "Not Assessed"),
            Self::ManualOverride => write!(f, "Manual Override"),
        }
    }
}

/// Source of a compliance finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingSource {
    /// Finding derived from vulnerability mapping
    VulnerabilityMapping {
        cve_id: Option<String>,
        vuln_title: String,
    },
    /// Finding from direct compliance check
    DirectCheck {
        check_id: String,
        check_name: String,
    },
    /// Finding from manual assessment
    ManualReview {
        reviewer: Option<String>,
        review_date: Option<DateTime<Utc>>,
    },
}

/// A compliance control definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    /// Unique identifier (e.g., "AC-7", "1.1.1", "PCI-DSS-1.1.1")
    pub id: String,
    /// Control ID within the framework (e.g., "AC-7" for NIST, "1.1.1" for CIS)
    pub control_id: String,
    /// Framework this control belongs to
    pub framework: ComplianceFramework,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Category/family (e.g., "Access Control", "Encryption")
    pub category: String,
    /// Priority level
    pub priority: ControlPriority,
    /// Whether this control can be automatically assessed
    pub automated_check: bool,
    /// Parent control ID for hierarchical controls
    pub parent_id: Option<String>,
    /// Related controls in other frameworks
    pub cross_references: Vec<String>,
    /// Remediation guidance
    pub remediation_guidance: Option<String>,
}

/// A compliance finding from a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Unique finding ID
    pub id: String,
    /// Scan this finding belongs to
    pub scan_id: String,
    /// Control this finding relates to
    pub control_id: String,
    /// Framework ID
    pub framework: ComplianceFramework,
    /// Compliance status
    pub status: ControlStatus,
    /// Severity of non-compliance
    pub severity: Severity,
    /// Evidence supporting the finding
    pub evidence: Vec<String>,
    /// Affected host IPs
    pub affected_hosts: Vec<String>,
    /// Affected ports (if applicable)
    pub affected_ports: Vec<u16>,
    /// Remediation recommendation
    pub remediation: String,
    /// Source of this finding
    pub source: FindingSource,
    /// Additional notes
    pub notes: Option<String>,
    /// When the finding was created
    pub created_at: DateTime<Utc>,
    /// When the finding was last updated
    pub updated_at: DateTime<Utc>,
    /// User who manually overrode status (if applicable)
    pub override_by: Option<String>,
    /// Reason for manual override (if applicable)
    pub override_reason: Option<String>,
}

/// Summary statistics for a framework
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSummary {
    /// Framework ID
    pub framework: ComplianceFramework,
    /// Total controls in the framework
    pub total_controls: usize,
    /// Number of compliant controls
    pub compliant: usize,
    /// Number of non-compliant controls
    pub non_compliant: usize,
    /// Number of partially compliant controls
    pub partially_compliant: usize,
    /// Number of not-applicable controls
    pub not_applicable: usize,
    /// Number of not-assessed controls
    pub not_assessed: usize,
    /// Number of manually overridden controls
    pub manual_overrides: usize,
    /// Compliance score (0-100)
    pub compliance_score: f32,
    /// Breakdown by category
    pub by_category: Vec<CategorySummary>,
}

/// Summary statistics for a control category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    /// Category name
    pub category: String,
    /// Total controls in category
    pub total: usize,
    /// Compliant controls
    pub compliant: usize,
    /// Non-compliant controls
    pub non_compliant: usize,
    /// Compliance percentage
    pub percentage: f32,
}

/// Overall compliance summary for a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    /// Scan ID
    pub scan_id: String,
    /// Per-framework summaries
    pub frameworks: Vec<FrameworkSummary>,
    /// Overall compliance score across all frameworks
    pub overall_score: f32,
    /// Total findings count
    pub total_findings: usize,
    /// Critical severity findings
    pub critical_findings: usize,
    /// High severity findings
    pub high_findings: usize,
    /// Medium severity findings
    pub medium_findings: usize,
    /// Low severity findings
    pub low_findings: usize,
    /// When the summary was generated
    pub generated_at: DateTime<Utc>,
}

/// Configuration for compliance scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScanConfig {
    /// Frameworks to assess
    pub frameworks: Vec<ComplianceFramework>,
    /// Whether to run compliance checks during scan (integrated mode)
    pub integrated_mode: bool,
    /// Categories to include (empty = all)
    pub include_categories: Vec<String>,
    /// Categories to exclude
    pub exclude_categories: Vec<String>,
    /// Minimum control priority to assess
    pub min_priority: Option<ControlPriority>,
    /// Whether to include not-assessed controls in reports
    pub include_not_assessed: bool,
}

impl Default for ComplianceScanConfig {
    fn default() -> Self {
        Self {
            frameworks: vec![ComplianceFramework::PciDss4],
            integrated_mode: false,
            include_categories: Vec::new(),
            exclude_categories: Vec::new(),
            min_priority: None,
            include_not_assessed: true,
        }
    }
}

/// Request to analyze a scan for compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAnalysisRequest {
    /// Scan ID to analyze
    pub scan_id: String,
    /// Frameworks to assess
    pub frameworks: Vec<String>,
}

/// Request to manually override a finding's status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualOverrideRequest {
    /// New status
    pub status: ControlStatus,
    /// Reason for override
    pub reason: String,
    /// Additional notes
    pub notes: Option<String>,
}

/// Response for compliance analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAnalysisResponse {
    /// Job ID for tracking async analysis
    pub job_id: String,
    /// Status of the analysis
    pub status: String,
    /// Message
    pub message: String,
}
