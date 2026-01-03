//! Supply Chain Security Module
//!
//! Comprehensive supply chain security including SBOM, provenance, and attestation

#![allow(dead_code)]

pub mod dependency_firewall;
pub mod license;
pub mod provenance;
pub mod sbom;
pub mod signing;
pub mod types;

pub use types::*;
use anyhow::Result;
use std::path::Path;

use crate::supply_chain::license::LicenseAnalyzer;
use crate::supply_chain::provenance::ProvenanceTracker;
use crate::supply_chain::sbom::SbomGenerator;
use crate::supply_chain::signing::CodeSigner;

/// Supply chain security scanner
pub struct SupplyChainScanner {
    sbom_generator: SbomGenerator,
    license_analyzer: LicenseAnalyzer,
    provenance_tracker: ProvenanceTracker,
    code_signer: CodeSigner,
}

impl SupplyChainScanner {
    pub fn new() -> Self {
        Self {
            sbom_generator: SbomGenerator::new(),
            license_analyzer: LicenseAnalyzer::new(),
            provenance_tracker: ProvenanceTracker::new(),
            code_signer: CodeSigner::new(),
        }
    }

    /// Perform comprehensive supply chain scan
    pub async fn scan(&self, project_path: &str) -> Result<SupplyChainReport> {
        let path = Path::new(project_path);
        if !path.exists() {
            anyhow::bail!("Project path does not exist: {}", project_path);
        }

        let mut report = SupplyChainReport::default();
        let mut dependency_details = Vec::new();
        let mut license_issues_details = Vec::new();

        // 1. Generate SBOM
        log::info!("Generating SBOM for project at {}", project_path);
        match self.sbom_generator.generate_cyclonedx(project_path).await {
            Ok(sbom_json) => {
                report.sbom_generated = true;
                report.sbom_json = Some(sbom_json.clone());

                // Parse SBOM to analyze dependencies
                if let Ok(sbom) = serde_json::from_str::<serde_json::Value>(&sbom_json) {
                    if let Some(components) = sbom.get("components").and_then(|c| c.as_array()) {
                        report.dependencies_analyzed = components.len();

                        // Analyze each component for license issues
                        for component in components {
                            let name = component.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown");
                            let version = component.get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let license = component.get("licenses")
                                .and_then(|l| l.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|lic| lic.get("license"))
                                .and_then(|l| l.get("id"))
                                .and_then(|id| id.as_str());

                            let license_str = license.unwrap_or("UNKNOWN");
                            let risk = self.license_analyzer.analyze_risk(license_str);

                            dependency_details.push(DependencyDetail {
                                name: name.to_string(),
                                version: version.to_string(),
                                license: license_str.to_string(),
                                risk: format!("{:?}", risk),
                                vulnerabilities: vec![],
                            });

                            // Check for high-risk licenses
                            if matches!(risk, license::LicenseRisk::High) {
                                report.license_issues += 1;
                                license_issues_details.push(LicenseIssue {
                                    dependency: format!("{}@{}", name, version),
                                    license: license_str.to_string(),
                                    issue: format!("{} license requires careful compliance", license_str),
                                    recommendation: "Review license obligations and ensure compliance".to_string(),
                                });
                            }

                            // Check for copyleft licenses in what might be a proprietary project
                            if self.license_analyzer.is_copyleft(license_str) {
                                license_issues_details.push(LicenseIssue {
                                    dependency: format!("{}@{}", name, version),
                                    license: license_str.to_string(),
                                    issue: format!("{} is a copyleft license", license_str),
                                    recommendation: "Ensure your distribution model complies with copyleft requirements".to_string(),
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to generate SBOM: {}", e);
            }
        }

        report.dependencies = dependency_details;
        report.license_issues_details = license_issues_details;

        // 2. Check provenance for known artifacts
        log::info!("Checking provenance for project artifacts");
        let common_artifacts = [
            path.join("target/release").join(path.file_name().unwrap_or_default()),
            path.join("dist").join("index.js"),
            path.join("build").join("main"),
        ];

        let mut provenance_checked = false;
        for artifact in &common_artifacts {
            if artifact.exists() {
                match self.provenance_tracker.verify_provenance(artifact.to_str().unwrap_or_default()).await {
                    Ok(verified) => {
                        if verified {
                            report.provenance_verified = true;
                        }
                        provenance_checked = true;
                    }
                    Err(e) => {
                        log::debug!("Provenance check failed for {:?}: {}", artifact, e);
                    }
                }
            }
        }

        // If no artifacts found, provenance check is not applicable
        if !provenance_checked {
            log::info!("No built artifacts found for provenance verification");
        }

        // 3. Verify signatures if cosign is available
        log::info!("Checking code signing status");
        let signer_status = self.code_signer.status();
        report.signing_available = signer_status.cosign_available;

        if signer_status.cosign_available {
            // Check for any signed artifacts
            for artifact in &common_artifacts {
                if artifact.exists() {
                    let sig_file = format!("{}.sig", artifact.to_str().unwrap_or_default());
                    if Path::new(&sig_file).exists() {
                        match self.code_signer.verify_signature(artifact.to_str().unwrap_or_default()).await {
                            Ok(valid) => {
                                if valid {
                                    report.signatures_verified += 1;
                                }
                            }
                            Err(e) => {
                                log::debug!("Signature verification failed: {}", e);
                            }
                        }
                    }
                }
            }
        }

        // 4. Calculate overall risk score
        report.risk_score = self.calculate_risk_score(&report);

        log::info!(
            "Supply chain scan complete: {} dependencies, {} license issues, provenance: {}, risk score: {}",
            report.dependencies_analyzed,
            report.license_issues,
            report.provenance_verified,
            report.risk_score
        );

        Ok(report)
    }

    /// Calculate overall supply chain risk score (0-100, lower is better)
    fn calculate_risk_score(&self, report: &SupplyChainReport) -> u32 {
        let mut score = 0u32;

        // No SBOM is high risk
        if !report.sbom_generated {
            score += 30;
        }

        // License issues add risk
        score += (report.license_issues * 5).min(25) as u32;

        // No provenance verification
        if !report.provenance_verified {
            score += 20;
        }

        // No signing available
        if !report.signing_available {
            score += 15;
        }

        // Vulnerabilities (would be populated by vulnerability scanning)
        score += (report.vulnerabilities_found * 10).min(30) as u32;

        score.min(100)
    }

    /// Check license compatibility across all dependencies
    pub fn check_license_compatibility(&self, project_license: &str, dependencies: &[DependencyDetail]) -> Vec<LicenseIssue> {
        let mut issues = Vec::new();

        for dep in dependencies {
            match self.license_analyzer.check_compatibility(project_license, &dep.license) {
                Ok(compatible) => {
                    if !compatible {
                        issues.push(LicenseIssue {
                            dependency: format!("{}@{}", dep.name, dep.version),
                            license: dep.license.clone(),
                            issue: format!(
                                "License '{}' may not be compatible with project license '{}'",
                                dep.license, project_license
                            ),
                            recommendation: "Review license compatibility or find an alternative dependency".to_string(),
                        });
                    }
                }
                Err(e) => {
                    log::warn!("Failed to check license compatibility for {}: {}", dep.name, e);
                }
            }
        }

        issues
    }
}

impl Default for SupplyChainScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SupplyChainReport {
    pub sbom_generated: bool,
    pub sbom_json: Option<String>,
    pub dependencies_analyzed: usize,
    pub dependencies: Vec<DependencyDetail>,
    pub vulnerabilities_found: usize,
    pub license_issues: usize,
    pub license_issues_details: Vec<LicenseIssue>,
    pub provenance_verified: bool,
    pub signing_available: bool,
    pub signatures_verified: usize,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DependencyDetail {
    pub name: String,
    pub version: String,
    pub license: String,
    pub risk: String,
    pub vulnerabilities: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LicenseIssue {
    pub dependency: String,
    pub license: String,
    pub issue: String,
    pub recommendation: String,
}
