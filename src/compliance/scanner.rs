//! Compliance Scanner (Option A - Integrated Mode)
//!
//! Real-time compliance scanning during the network scan pipeline.
//! This scanner runs compliance checks as hosts are discovered.

use crate::compliance::controls::{run_compliance_checks, check_results_to_findings};
use crate::compliance::types::{ComplianceFinding, ComplianceFramework, ControlStatus};
use crate::types::HostInfo;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::debug;

/// Real-time compliance scanner for integrated scanning mode
pub struct ComplianceScanner {
    /// Frameworks to scan against
    frameworks: Vec<ComplianceFramework>,
    /// Accumulated findings
    findings: Arc<RwLock<Vec<ComplianceFinding>>>,
}

impl ComplianceScanner {
    /// Create a new scanner for the specified frameworks
    pub fn new(frameworks: &[String]) -> Self {
        let parsed_frameworks: Vec<ComplianceFramework> = frameworks
            .iter()
            .filter_map(|id| ComplianceFramework::from_id(id))
            .collect();

        Self {
            frameworks: parsed_frameworks,
            findings: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a scanner with pre-parsed frameworks
    pub fn with_frameworks(frameworks: Vec<ComplianceFramework>) -> Self {
        Self {
            frameworks,
            findings: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Scan a single host for compliance during the scan pipeline
    pub async fn scan_host_compliance(
        &self,
        host: &HostInfo,
        scan_id: &str,
    ) -> Vec<ComplianceFinding> {
        if self.frameworks.is_empty() {
            return Vec::new();
        }

        debug!(
            "Running compliance checks on {} for {} frameworks",
            host.target.ip,
            self.frameworks.len()
        );

        // Run compliance checks
        let check_results = run_compliance_checks(host, &self.frameworks);

        // Convert to findings
        let findings = check_results_to_findings(check_results, scan_id, &host.target.ip.to_string());

        // Store findings
        {
            let mut all_findings = self.findings.write().await;
            all_findings.extend(findings.clone());
        }

        findings
    }

    /// Get all accumulated findings
    pub async fn get_all_findings(&self) -> Vec<ComplianceFinding> {
        self.findings.read().await.clone()
    }

    /// Get findings for a specific framework
    pub async fn get_framework_findings(
        &self,
        framework: ComplianceFramework,
    ) -> Vec<ComplianceFinding> {
        self.findings
            .read()
            .await
            .iter()
            .filter(|f| f.framework == framework)
            .cloned()
            .collect()
    }

    /// Get non-compliant findings
    pub async fn get_non_compliant_findings(&self) -> Vec<ComplianceFinding> {
        self.findings
            .read()
            .await
            .iter()
            .filter(|f| f.status == ControlStatus::NonCompliant)
            .cloned()
            .collect()
    }

    /// Clear all findings (for scanner reset)
    pub async fn clear(&self) {
        self.findings.write().await.clear();
    }

    /// Get the number of findings
    pub async fn findings_count(&self) -> usize {
        self.findings.read().await.len()
    }

    /// Get the frameworks being scanned
    pub fn frameworks(&self) -> &[ComplianceFramework] {
        &self.frameworks
    }

    /// Quick compliance check for progress reporting
    pub fn quick_check(&self, host: &HostInfo) -> QuickComplianceStatus {
        if self.frameworks.is_empty() {
            return QuickComplianceStatus {
                total_checks: 0,
                passed: 0,
                failed: 0,
                warnings: 0,
            };
        }

        let results = run_compliance_checks(host, &self.frameworks);

        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;

        for result in &results {
            match result.status {
                ControlStatus::Compliant => passed += 1,
                ControlStatus::NonCompliant => failed += 1,
                ControlStatus::PartiallyCompliant => warnings += 1,
                _ => {}
            }
        }

        QuickComplianceStatus {
            total_checks: results.len(),
            passed,
            failed,
            warnings,
        }
    }
}

/// Quick compliance status for progress reporting
#[derive(Debug, Clone)]
pub struct QuickComplianceStatus {
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
}

impl QuickComplianceStatus {
    /// Get pass rate as percentage
    pub fn pass_rate(&self) -> f32 {
        if self.total_checks == 0 {
            100.0
        } else {
            (self.passed as f32 / self.total_checks as f32) * 100.0
        }
    }
}

/// Create compliance scanner from scan configuration
pub fn create_scanner_from_config(
    enable_compliance: bool,
    frameworks: &[String],
) -> Option<ComplianceScanner> {
    if !enable_compliance || frameworks.is_empty() {
        return None;
    }

    Some(ComplianceScanner::new(frameworks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = ComplianceScanner::new(&[
            "pci_dss".to_string(),
            "cis".to_string(),
        ]);
        assert_eq!(scanner.frameworks.len(), 2);
    }

    #[test]
    fn test_scanner_with_invalid_framework() {
        let scanner = ComplianceScanner::new(&[
            "invalid_framework".to_string(),
            "pci_dss".to_string(),
        ]);
        // Should only have one valid framework
        assert_eq!(scanner.frameworks.len(), 1);
    }

    #[tokio::test]
    async fn test_scanner_clear() {
        let scanner = ComplianceScanner::new(&["pci_dss".to_string()]);
        scanner.clear().await;
        assert_eq!(scanner.findings_count().await, 0);
    }
}
