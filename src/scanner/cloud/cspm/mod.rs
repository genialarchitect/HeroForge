//! Cloud Security Posture Management (CSPM)
//!
//! Continuous cloud security assessment and misconfiguration detection

#![allow(dead_code)]

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod remediation;
pub mod types;

pub use types::*;
use anyhow::Result;

/// CSPM scanner
pub struct CspmScanner {
    // TODO: Add cloud provider configurations
}

impl CspmScanner {
    pub fn new() -> Self {
        Self {}
    }

    /// Scan all configured cloud environments
    pub async fn scan_all(&self) -> Result<CspmScanResult> {
        // TODO: Scan AWS, Azure, GCP
        Ok(CspmScanResult::default())
    }
}

impl Default for CspmScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CspmScanResult {
    pub aws_results: Vec<CspmFinding>,
    pub azure_results: Vec<CspmFinding>,
    pub gcp_results: Vec<CspmFinding>,
    pub total_findings: usize,
    pub critical_findings: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CspmFinding {
    pub resource_id: String,
    pub resource_type: String,
    pub finding_type: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
}
