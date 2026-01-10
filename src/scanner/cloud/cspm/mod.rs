//! Cloud Security Posture Management (CSPM)
//!
//! Continuous cloud security assessment and misconfiguration detection

#![allow(dead_code)]

pub mod aws;
pub mod azure;
pub mod gcp;
pub mod remediation;
pub mod types;

use anyhow::Result;

/// CSPM scanner configuration
pub struct CspmConfig {
    pub scan_aws: bool,
    pub scan_azure: bool,
    pub scan_gcp: bool,
    pub aws_regions: Vec<String>,
    pub azure_subscriptions: Vec<String>,
    pub gcp_projects: Vec<String>,
}

impl Default for CspmConfig {
    fn default() -> Self {
        Self {
            scan_aws: true,
            scan_azure: true,
            scan_gcp: true,
            aws_regions: vec!["us-east-1".to_string()],
            azure_subscriptions: Vec::new(),
            gcp_projects: Vec::new(),
        }
    }
}

/// CSPM scanner
pub struct CspmScanner {
    config: CspmConfig,
}

impl CspmScanner {
    pub fn new() -> Self {
        Self {
            config: CspmConfig::default(),
        }
    }

    pub fn with_config(config: CspmConfig) -> Self {
        Self { config }
    }

    /// Scan all configured cloud environments
    pub async fn scan_all(&self) -> Result<CspmScanResult> {
        let mut result = CspmScanResult::default();

        // Scan AWS
        if self.config.scan_aws {
            let aws_scanner = aws::AwsCspm::new();
            match aws_scanner.scan_all().await {
                Ok(findings) => {
                    result.critical_findings += findings.iter()
                        .filter(|f| f.severity == "Critical")
                        .count();
                    result.total_findings += findings.len();
                    result.aws_results = findings;
                }
                Err(e) => {
                    log::warn!("AWS scan failed: {}", e);
                }
            }
        }

        // Scan Azure
        if self.config.scan_azure {
            let azure_scanner = azure::AzureCspm::new();
            match azure_scanner.scan_all().await {
                Ok(findings) => {
                    result.critical_findings += findings.iter()
                        .filter(|f| f.severity == "Critical")
                        .count();
                    result.total_findings += findings.len();
                    result.azure_results = findings;
                }
                Err(e) => {
                    log::warn!("Azure scan failed: {}", e);
                }
            }
        }

        // Scan GCP
        if self.config.scan_gcp {
            let gcp_scanner = gcp::GcpCspm::new();
            match gcp_scanner.scan_all().await {
                Ok(findings) => {
                    result.critical_findings += findings.iter()
                        .filter(|f| f.severity == "Critical")
                        .count();
                    result.total_findings += findings.len();
                    result.gcp_results = findings;
                }
                Err(e) => {
                    log::warn!("GCP scan failed: {}", e);
                }
            }
        }

        Ok(result)
    }

    /// Scan specific cloud provider
    pub async fn scan_aws(&self) -> Result<Vec<CspmFinding>> {
        let scanner = aws::AwsCspm::new();
        scanner.scan_all().await
    }

    pub async fn scan_azure(&self) -> Result<Vec<CspmFinding>> {
        let scanner = azure::AzureCspm::new();
        scanner.scan_all().await
    }

    pub async fn scan_gcp(&self) -> Result<Vec<CspmFinding>> {
        let scanner = gcp::GcpCspm::new();
        scanner.scan_all().await
    }

    /// Generate remediation for findings
    pub fn generate_remediation(&self, findings: &[CspmFinding]) -> Vec<remediation::RemediationScript> {
        let engine = remediation::RemediationEngine::new();
        engine.generate_remediation(findings)
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
