//! Compliance Automation Module
//!
//! This module provides automated compliance assessment and reporting for:
//! - SOC 2 Trust Services Criteria (TSC)
//! - ISO 27001 Information Security Management System (ISMS)
//! - FedRAMP Authorization to Operate (ATO)
//!
//! ## Features
//!
//! - **Automated Control Testing**: Continuous validation of security controls
//! - **Evidence Collection**: Automated gathering of compliance evidence
//! - **Report Generation**: Automated SOC 2, ISO 27001, and FedRAMP reports
//! - **Gap Analysis**: Identify non-compliant controls and remediation steps
//!
//! ## Example
//!
//! ```rust,ignore
//! use compliance_automation::soc2::Soc2Analyzer;
//!
//! let analyzer = Soc2Analyzer::new();
//! let results = analyzer.assess_controls().await?;
//! ```

#![allow(dead_code)]

pub mod soc2;
pub mod iso27001;
pub mod fedramp;
pub mod evidence;
pub mod types;

// Re-export commonly used types
pub use soc2::Soc2Analyzer;
pub use iso27001::Iso27001Analyzer;
pub use fedramp::FedRampAnalyzer;

use anyhow::Result;

/// Initialize compliance automation
pub async fn init() -> Result<()> {
    log::info!("Initializing compliance automation");
    Ok(())
}

/// Run automated compliance assessment
pub async fn assess_compliance(
    framework: ComplianceFramework,
) -> Result<ComplianceAssessmentResult> {
    match framework {
        ComplianceFramework::Soc2 => {
            let analyzer = Soc2Analyzer::new();
            analyzer.assess().await
        }
        ComplianceFramework::Iso27001 => {
            let analyzer = Iso27001Analyzer::new();
            analyzer.assess().await
        }
        ComplianceFramework::FedRamp => {
            let analyzer = FedRampAnalyzer::new();
            analyzer.assess().await
        }
    }
}

/// Supported compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ComplianceFramework {
    Soc2,
    Iso27001,
    FedRamp,
}

/// Compliance assessment result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComplianceAssessmentResult {
    pub framework: ComplianceFramework,
    pub assessment_date: chrono::DateTime<chrono::Utc>,
    pub overall_score: f64,
    pub controls_passed: usize,
    pub controls_failed: usize,
    pub controls_manual: usize,
    pub evidence_items: usize,
    pub findings: Vec<Finding>,
}

/// Compliance finding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub control_id: String,
    pub control_name: String,
    pub status: ControlStatus,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
    pub evidence_ids: Vec<String>,
}

/// Control status
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ControlStatus {
    Pass,
    Fail,
    Manual,
    NotApplicable,
}

/// Finding severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
