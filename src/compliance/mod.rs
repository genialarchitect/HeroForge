//! Compliance Scanning Module
//!
//! This module provides compliance assessment capabilities for HeroForge,
//! supporting multiple compliance frameworks including:
//!
//! - CIS Benchmarks
//! - NIST 800-53
//! - NIST Cybersecurity Framework (CSF)
//! - PCI DSS 4.0
//! - HIPAA Security Rule
//! - FERPA
//! - SOC 2
//!
//! The module supports two modes of operation:
//!
//! 1. **Hybrid Mode (Default)**: Post-scan analysis that maps discovered
//!    vulnerabilities to compliance controls and runs supplemental checks.
//!
//! 2. **Integrated Mode**: Real-time compliance checks during the scan
//!    pipeline for more thorough assessment.

pub mod types;
pub mod frameworks;
pub mod controls;
pub mod analyzer;
pub mod scanner;
pub mod scoring;

// Re-export commonly used types
pub use types::{
    ComplianceFramework,
    ComplianceFinding,
    ComplianceSummary,
    FrameworkSummary,
    CategorySummary,
};

pub use analyzer::ComplianceAnalyzer;

use crate::types::HostInfo;
use anyhow::Result;

/// Analyze scan results for compliance (Option C - Hybrid mode)
///
/// This is the primary entry point for post-scan compliance analysis.
/// It maps existing vulnerabilities to compliance controls and runs
/// supplemental compliance-specific checks.
pub async fn analyze_compliance(
    hosts: &[HostInfo],
    scan_id: &str,
    frameworks: &[ComplianceFramework],
) -> Result<ComplianceSummary> {
    let analyzer = ComplianceAnalyzer::new(frameworks.to_vec());
    analyzer.analyze(hosts, scan_id).await
}

/// Get all available compliance frameworks
pub fn available_frameworks() -> Vec<ComplianceFramework> {
    ComplianceFramework::all()
}

/// Get framework information
pub fn get_framework_info(framework: ComplianceFramework) -> FrameworkInfo {
    FrameworkInfo {
        id: framework.id().to_string(),
        name: framework.name().to_string(),
        version: framework.version().to_string(),
        description: framework.description().to_string(),
        control_count: frameworks::get_control_count(framework),
        automated_percentage: frameworks::get_automated_percentage(framework),
    }
}

/// Framework information summary
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FrameworkInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub control_count: usize,
    pub automated_percentage: f32,
}
