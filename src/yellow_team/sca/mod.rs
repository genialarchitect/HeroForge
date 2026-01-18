//! Software Composition Analysis (SCA) Module
//!
//! Provides comprehensive dependency vulnerability scanning and analysis including:
//! - OSV (Open Source Vulnerabilities) database queries
//! - Version range matching for vulnerability detection
//! - Package registry update checking
//! - Integration with existing SBOM generation

pub mod osv_client;
pub mod vuln_matcher;
pub mod update_checker;

use crate::yellow_team::sbom::SbomGenerator;
use crate::yellow_team::types::{SbomComponent, VulnSeverity};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub use osv_client::{OsvClient, OsvVulnerability, OsvAffected};
pub use vuln_matcher::{VulnerabilityMatcher, MatchedVulnerability};
pub use update_checker::{UpdateChecker, UpdateRecommendation, UpdateType};

// ============================================================================
// Core Types
// ============================================================================

/// Supported package ecosystems
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    #[default]
    Npm,
    PyPI,
    #[serde(alias = "crates.io")]
    Cargo,
    Go,
    Maven,
    NuGet,
    RubyGems,
    Composer,
    Unknown,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::PyPI => write!(f, "pypi"),
            Ecosystem::Cargo => write!(f, "cargo"),
            Ecosystem::Go => write!(f, "go"),
            Ecosystem::Maven => write!(f, "maven"),
            Ecosystem::NuGet => write!(f, "nuget"),
            Ecosystem::RubyGems => write!(f, "rubygems"),
            Ecosystem::Composer => write!(f, "composer"),
            Ecosystem::Unknown => write!(f, "unknown"),
        }
    }
}

impl Ecosystem {
    /// Convert ecosystem string to OSV ecosystem name
    pub fn to_osv_ecosystem(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Maven => "Maven",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Composer => "Packagist",
            Ecosystem::Unknown => "unknown",
        }
    }

    /// Parse ecosystem from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "npm" => Ecosystem::Npm,
            "pypi" | "python" => Ecosystem::PyPI,
            "cargo" | "crates.io" | "rust" => Ecosystem::Cargo,
            "go" | "golang" => Ecosystem::Go,
            "maven" | "java" => Ecosystem::Maven,
            "nuget" | "dotnet" | ".net" => Ecosystem::NuGet,
            "rubygems" | "gem" | "ruby" => Ecosystem::RubyGems,
            "composer" | "php" | "packagist" => Ecosystem::Composer,
            _ => Ecosystem::Unknown,
        }
    }
}

/// License risk level for dependencies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LicenseRiskLevel {
    Low,      // MIT, Apache-2.0, BSD
    Medium,   // LGPL, MPL
    High,     // GPL, AGPL
    #[default]
    Unknown,
}

impl std::fmt::Display for LicenseRiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseRiskLevel::Low => write!(f, "low"),
            LicenseRiskLevel::Medium => write!(f, "medium"),
            LicenseRiskLevel::High => write!(f, "high"),
            LicenseRiskLevel::Unknown => write!(f, "unknown"),
        }
    }
}

/// Vulnerability status in SCA workflow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VulnStatus {
    #[default]
    New,
    Acknowledged,
    InProgress,
    Fixed,
    Ignored,
    FalsePositive,
}

impl std::fmt::Display for VulnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnStatus::New => write!(f, "new"),
            VulnStatus::Acknowledged => write!(f, "acknowledged"),
            VulnStatus::InProgress => write!(f, "in_progress"),
            VulnStatus::Fixed => write!(f, "fixed"),
            VulnStatus::Ignored => write!(f, "ignored"),
            VulnStatus::FalsePositive => write!(f, "false_positive"),
        }
    }
}

// ============================================================================
// SCA Project Types
// ============================================================================

/// SCA Project - represents a codebase being analyzed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaProject {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub repository_url: Option<String>,
    pub ecosystem: Ecosystem,
    pub manifest_files: Vec<String>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub total_dependencies: i32,
    pub vulnerable_dependencies: i32,
    pub license_issues: i32,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// SCA Dependency - a package dependency in a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaDependency {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub purl: Option<String>,
    pub is_direct: bool,
    pub parent_id: Option<String>,
    pub depth: i32,
    pub license: Option<String>,
    pub license_risk: LicenseRiskLevel,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub created_at: DateTime<Utc>,
}

/// SCA Vulnerability - a vulnerability affecting a dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaVulnerability {
    pub id: String,
    pub dependency_id: String,
    pub project_id: String,
    pub vuln_id: String,
    pub source: String,
    pub severity: VulnSeverity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub affected_versions: Option<String>,
    pub fixed_version: Option<String>,
    pub references: Vec<String>,
    pub exploited_in_wild: bool,
    pub status: VulnStatus,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create an SCA project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScaProjectRequest {
    pub name: String,
    pub repository_url: Option<String>,
    pub ecosystem: Option<Ecosystem>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to analyze a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeProjectRequest {
    pub source_path: Option<String>,
    pub manifest_content: Option<String>,
    pub check_updates: Option<bool>,
}

/// Filter for listing dependencies
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DependencyFilter {
    pub is_direct: Option<bool>,
    pub has_vulnerabilities: Option<bool>,
    pub license_risk: Option<LicenseRiskLevel>,
    pub update_available: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Filter for listing vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VulnerabilityFilter {
    pub severity: Option<VulnSeverity>,
    pub status: Option<VulnStatus>,
    pub exploited_in_wild: Option<bool>,
    pub has_fix: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// SCA Dashboard Statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScaStats {
    pub total_projects: i64,
    pub total_dependencies: i64,
    pub direct_dependencies: i64,
    pub transitive_dependencies: i64,
    pub total_vulnerabilities: i64,
    pub critical_vulns: i64,
    pub high_vulns: i64,
    pub medium_vulns: i64,
    pub low_vulns: i64,
    pub license_issues: i64,
    pub outdated_dependencies: i64,
    pub avg_dependency_age_days: Option<f64>,
    pub vulns_by_ecosystem: HashMap<String, i64>,
    pub top_vulnerable_packages: Vec<TopVulnerablePackage>,
}

/// Top vulnerable package for statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopVulnerablePackage {
    pub name: String,
    pub ecosystem: String,
    pub vuln_count: i64,
    pub project_count: i64,
}

/// Analysis result for a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaAnalysisResult {
    pub project_id: String,
    pub dependencies_found: i32,
    pub vulnerabilities_found: i32,
    pub license_issues_found: i32,
    pub updates_available: i32,
    pub analysis_duration_ms: u64,
    pub errors: Vec<String>,
}

// ============================================================================
// SCA Analyzer - Main analysis engine
// ============================================================================

/// SCA Analyzer - orchestrates dependency analysis
pub struct ScaAnalyzer {
    pub osv_client: OsvClient,
    pub vuln_matcher: VulnerabilityMatcher,
    pub update_checker: UpdateChecker,
}

impl ScaAnalyzer {
    /// Create a new SCA analyzer
    pub fn new() -> Self {
        Self {
            osv_client: OsvClient::new(),
            vuln_matcher: VulnerabilityMatcher::new(),
            update_checker: UpdateChecker::new(),
        }
    }

    /// Analyze a project directory for dependencies and vulnerabilities
    pub async fn analyze_directory(&self, path: &Path, ecosystem: Ecosystem) -> Result<ScaAnalysisResult> {
        let start = std::time::Instant::now();
        let mut errors = Vec::new();
        #[allow(unused_assignments)]
        let mut dependencies_found = 0;
        let mut vulnerabilities_found = 0;
        let mut license_issues_found = 0;
        let mut updates_available = 0;

        // Use existing SBOM generator to parse dependencies
        let mut sbom_generator = SbomGenerator::new(
            path.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string())
                .as_str(),
            None,
            &path.to_string_lossy(),
        );

        // Generate SBOM from directory
        if let Err(e) = sbom_generator.generate_from_directory(path).await {
            errors.push(format!("Failed to parse dependencies: {}", e));
        }

        dependencies_found = sbom_generator.components.len() as i32;

        // Check each component for vulnerabilities
        for component in &sbom_generator.components {
            let osv_ecosystem = ecosystem.to_osv_ecosystem();

            match self.osv_client.query_package(&component.name, &component.version, osv_ecosystem).await {
                Ok(vulns) => {
                    vulnerabilities_found += vulns.len() as i32;
                }
                Err(e) => {
                    errors.push(format!("Failed to check {} for vulnerabilities: {}", component.name, e));
                }
            }

            // Check license risk
            if let Some(license) = component.license() {
                let risk = assess_license_risk(&license);
                if matches!(risk, LicenseRiskLevel::High) {
                    license_issues_found += 1;
                }
            }

            // Check for updates
            match self.update_checker.check_latest_version(&component.name, osv_ecosystem).await {
                Ok(Some(latest)) => {
                    if latest != component.version {
                        updates_available += 1;
                    }
                }
                Err(e) => {
                    // Non-fatal error
                    log::debug!("Failed to check updates for {}: {}", component.name, e);
                }
                _ => {}
            }
        }

        Ok(ScaAnalysisResult {
            project_id: String::new(), // Will be set by caller
            dependencies_found,
            vulnerabilities_found,
            license_issues_found,
            updates_available,
            analysis_duration_ms: start.elapsed().as_millis() as u64,
            errors,
        })
    }

    /// Analyze dependencies from parsed SBOM components
    pub async fn analyze_components(
        &self,
        components: &[SbomComponent],
        ecosystem: Ecosystem,
    ) -> Vec<MatchedVulnerability> {
        let mut all_vulns = Vec::new();
        let osv_ecosystem = ecosystem.to_osv_ecosystem();

        for component in components {
            if let Ok(vulns) = self.osv_client
                .query_package(&component.name, &component.version, osv_ecosystem)
                .await
            {
                for vuln in vulns {
                    let matched = self.vuln_matcher.match_vulnerability(&vuln, &component.version);
                    if matched.is_affected {
                        all_vulns.push(matched);
                    }
                }
            }
        }

        all_vulns
    }

    /// Get update recommendations for components
    pub async fn get_updates(
        &self,
        components: &[SbomComponent],
        ecosystem: Ecosystem,
    ) -> Vec<UpdateRecommendation> {
        let mut updates = Vec::new();
        let osv_ecosystem = ecosystem.to_osv_ecosystem();

        for component in components {
            if let Ok(Some(recommendation)) = self.update_checker
                .get_update_recommendation(&component.name, &component.version, osv_ecosystem)
                .await
            {
                updates.push(recommendation);
            }
        }

        updates
    }
}

impl Default for ScaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Assess license risk level from license string
pub fn assess_license_risk(license: &str) -> LicenseRiskLevel {
    let license_lower = license.to_lowercase();

    // Permissive licenses - low risk
    if license_lower.contains("mit")
        || license_lower.contains("apache")
        || license_lower.contains("bsd")
        || license_lower.contains("isc")
        || license_lower.contains("unlicense")
        || license_lower.contains("cc0")
        || license_lower.contains("wtfpl")
        || license_lower.contains("zlib")
    {
        return LicenseRiskLevel::Low;
    }

    // Weak copyleft - medium risk
    if license_lower.contains("lgpl")
        || license_lower.contains("mpl")
        || license_lower.contains("epl")
        || license_lower.contains("cddl")
    {
        return LicenseRiskLevel::Medium;
    }

    // Strong copyleft - high risk
    if license_lower.contains("gpl")
        || license_lower.contains("agpl")
        || license_lower.contains("sspl")
        || license_lower.contains("elastic")
    {
        return LicenseRiskLevel::High;
    }

    LicenseRiskLevel::Unknown
}

/// Generate Package URL (PURL) for a dependency
pub fn generate_purl(name: &str, version: &str, ecosystem: Ecosystem) -> String {
    let purl_type = match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::Cargo => "cargo",
        Ecosystem::Go => "golang",
        Ecosystem::Maven => "maven",
        Ecosystem::NuGet => "nuget",
        Ecosystem::RubyGems => "gem",
        Ecosystem::Composer => "composer",
        Ecosystem::Unknown => "generic",
    };

    format!("pkg:{}/{}@{}", purl_type, name, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_conversion() {
        assert_eq!(Ecosystem::Npm.to_osv_ecosystem(), "npm");
        assert_eq!(Ecosystem::PyPI.to_osv_ecosystem(), "PyPI");
        assert_eq!(Ecosystem::Cargo.to_osv_ecosystem(), "crates.io");
        assert_eq!(Ecosystem::Go.to_osv_ecosystem(), "Go");
    }

    #[test]
    fn test_ecosystem_from_str() {
        assert_eq!(Ecosystem::from_str("npm"), Ecosystem::Npm);
        assert_eq!(Ecosystem::from_str("python"), Ecosystem::PyPI);
        assert_eq!(Ecosystem::from_str("rust"), Ecosystem::Cargo);
        assert_eq!(Ecosystem::from_str("unknown_ecosystem"), Ecosystem::Unknown);
    }

    #[test]
    fn test_license_risk_assessment() {
        assert_eq!(assess_license_risk("MIT"), LicenseRiskLevel::Low);
        assert_eq!(assess_license_risk("Apache-2.0"), LicenseRiskLevel::Low);
        assert_eq!(assess_license_risk("LGPL-3.0"), LicenseRiskLevel::Medium);
        assert_eq!(assess_license_risk("GPL-3.0"), LicenseRiskLevel::High);
        assert_eq!(assess_license_risk("Proprietary"), LicenseRiskLevel::Unknown);
    }

    #[test]
    fn test_purl_generation() {
        assert_eq!(generate_purl("lodash", "4.17.21", Ecosystem::Npm), "pkg:npm/lodash@4.17.21");
        assert_eq!(generate_purl("requests", "2.28.0", Ecosystem::PyPI), "pkg:pypi/requests@2.28.0");
        assert_eq!(generate_purl("serde", "1.0.0", Ecosystem::Cargo), "pkg:cargo/serde@1.0.0");
    }
}
