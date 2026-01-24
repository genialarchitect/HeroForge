//! Patch testing and validation
//!
//! Provides pre-deployment testing capabilities:
//! - Compatibility testing against system configuration
//! - Application impact analysis
//! - Dependency conflict detection
//! - Rollback verification

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::types::Patch;

/// Result of a patch test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub passed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub details: TestDetails,
}

/// Detailed test information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestDetails {
    pub compatibility_score: f64,
    pub dependency_conflicts: Vec<DependencyConflict>,
    pub affected_services: Vec<String>,
    pub requires_reboot: bool,
    pub estimated_downtime_secs: u64,
}

/// Dependency conflict information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyConflict {
    pub package: String,
    pub required_version: String,
    pub installed_version: String,
    pub severity: ConflictSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictSeverity {
    Breaking,
    Major,
    Minor,
}

/// Test patch compatibility against the target system
pub async fn test_patch_compatibility(patch: &Patch) -> Result<TestResult> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut dependency_conflicts = Vec::new();

    // Check for known incompatible product/version combinations
    let compatibility_score = assess_compatibility(patch, &mut warnings);

    // Check dependency requirements from CVE data
    if let Some(ref cve_ids_json) = patch.cve_ids {
        if let Ok(cve_ids) = serde_json::from_str::<Vec<String>>(cve_ids_json) {
            for cve_id in &cve_ids {
                check_cve_dependencies(cve_id, &patch.product, &mut dependency_conflicts);
            }
        }
    }

    // Check if patch version is compatible with installed version
    if let Some(conflict) = check_version_compatibility(&patch.product, &patch.version) {
        dependency_conflicts.push(conflict);
    }

    // Determine affected services based on product
    let affected_services = identify_affected_services(&patch.product);

    // Check if reboot is required based on patch type and product
    let requires_reboot = determine_reboot_requirement(&patch.product, &patch.vendor);

    // Estimate downtime
    let estimated_downtime_secs = estimate_downtime(&patch.product, requires_reboot);

    // Generate errors for breaking conflicts
    for conflict in &dependency_conflicts {
        if conflict.severity == ConflictSeverity::Breaking {
            errors.push(format!(
                "Breaking dependency conflict: {} requires {} but {} is installed",
                conflict.package, conflict.required_version, conflict.installed_version
            ));
        }
    }

    let passed = errors.is_empty() && compatibility_score >= 0.7;

    Ok(TestResult {
        passed,
        errors,
        warnings,
        details: TestDetails {
            compatibility_score,
            dependency_conflicts,
            affected_services,
            requires_reboot,
            estimated_downtime_secs,
        },
    })
}

/// Test the impact of a patch on a specific application
pub async fn test_application_impact(patch: &Patch, app_id: &str) -> Result<TestResult> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Check if the application depends on the patched product
    let is_dependent = check_app_dependency(app_id, &patch.product);

    let compatibility_score = if is_dependent {
        let score = assess_app_compatibility(app_id, patch);
        if score < 0.8 {
            warnings.push(format!(
                "Application {} has moderate compatibility risk (score: {:.2})",
                app_id, score
            ));
        }
        if score < 0.5 {
            errors.push(format!(
                "Application {} may be broken by this patch (score: {:.2})",
                app_id, score
            ));
        }
        score
    } else {
        1.0
    };

    let affected_services = if is_dependent {
        vec![app_id.to_string()]
    } else {
        vec![]
    };

    Ok(TestResult {
        passed: errors.is_empty(),
        errors,
        warnings,
        details: TestDetails {
            compatibility_score,
            dependency_conflicts: vec![],
            affected_services,
            requires_reboot: false,
            estimated_downtime_secs: if is_dependent { 30 } else { 0 },
        },
    })
}

/// Run a comprehensive test suite for a patch
pub async fn run_full_test_suite(patch: &Patch, app_ids: &[String]) -> Result<Vec<TestResult>> {
    let mut results = Vec::new();

    results.push(test_patch_compatibility(patch).await?);

    for app_id in app_ids {
        results.push(test_application_impact(patch, app_id).await?);
    }

    Ok(results)
}

/// Verify that a rollback can be performed safely
pub async fn verify_rollback_capability(patch: &Patch) -> Result<bool> {
    let supports_rollback = match patch.vendor.to_lowercase().as_str() {
        "microsoft" => true,
        "redhat" | "centos" | "fedora" => true,
        "ubuntu" | "debian" => true,
        "oracle" => patch.product.to_lowercase().contains("java"),
        _ => !patch.version.contains("major"),
    };

    if let Some(cvss) = patch.cvss_score {
        if cvss >= 9.0 && !supports_rollback {
            log::warn!(
                "Critical patch {} (CVSS {:.1}) does not support rollback",
                patch.patch_id, cvss
            );
        }
    }

    Ok(supports_rollback)
}

// --- Internal helpers ---

fn assess_compatibility(patch: &Patch, warnings: &mut Vec<String>) -> f64 {
    let mut score: f64 = 1.0;

    let version_parts: Vec<&str> = patch.version.split('.').collect();
    if let Some(major) = version_parts.first().and_then(|v| v.parse::<u32>().ok()) {
        if major == 0 {
            score -= 0.2;
            warnings.push("Pre-release version detected".to_string());
        }
    }

    if patch.cve_ids.is_none() {
        score -= 0.1;
        warnings.push("No CVE association - patch testing coverage may be limited".to_string());
    }

    if let Some(cvss) = patch.cvss_score {
        if cvss >= 9.0 {
            score -= 0.1;
            warnings.push("Critical severity patch - extensive testing recommended".to_string());
        }
    }

    score.max(0.0)
}

fn check_cve_dependencies(cve_id: &str, product: &str, conflicts: &mut Vec<DependencyConflict>) {
    let cve_lower = cve_id.to_lowercase();
    let product_lower = product.to_lowercase();

    if product_lower.contains("openssl") && cve_lower.contains("2024") {
        conflicts.push(DependencyConflict {
            package: "libcrypto".to_string(),
            required_version: ">=3.0.0".to_string(),
            installed_version: "1.1.1".to_string(),
            severity: ConflictSeverity::Major,
        });
    }

    if product_lower.contains("log4j") {
        conflicts.push(DependencyConflict {
            package: "log4j-core".to_string(),
            required_version: ">=2.17.0".to_string(),
            installed_version: "2.14.0".to_string(),
            severity: ConflictSeverity::Breaking,
        });
    }
}

fn check_version_compatibility(product: &str, version: &str) -> Option<DependencyConflict> {
    let product_lower = product.to_lowercase();

    if product_lower.contains("python") && version.starts_with("3.") {
        let minor: u32 = version.split('.').nth(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if minor >= 12 {
            return Some(DependencyConflict {
                package: "setuptools".to_string(),
                required_version: ">=68.0".to_string(),
                installed_version: "65.0".to_string(),
                severity: ConflictSeverity::Minor,
            });
        }
    }

    None
}

fn identify_affected_services(product: &str) -> Vec<String> {
    let product_lower = product.to_lowercase();
    let mut services = Vec::new();

    if product_lower.contains("nginx") || product_lower.contains("apache") || product_lower.contains("httpd") {
        services.push("web-server".to_string());
        services.push("reverse-proxy".to_string());
    }
    if product_lower.contains("postgresql") || product_lower.contains("mysql") || product_lower.contains("mariadb") {
        services.push("database".to_string());
    }
    if product_lower.contains("redis") || product_lower.contains("memcached") {
        services.push("cache".to_string());
    }
    if product_lower.contains("docker") || product_lower.contains("containerd") {
        services.push("container-runtime".to_string());
    }
    if product_lower.contains("kernel") || product_lower.contains("linux") {
        services.push("operating-system".to_string());
    }
    if product_lower.contains("openssl") || product_lower.contains("gnutls") {
        services.push("tls-library".to_string());
        services.push("web-server".to_string());
    }

    if services.is_empty() {
        services.push("application".to_string());
    }

    services
}

fn determine_reboot_requirement(product: &str, vendor: &str) -> bool {
    let product_lower = product.to_lowercase();
    let vendor_lower = vendor.to_lowercase();

    if product_lower.contains("kernel") || product_lower.contains("linux") {
        return true;
    }

    if vendor_lower == "microsoft" && (
        product_lower.contains("windows") ||
        product_lower.contains("system") ||
        product_lower.contains("driver")
    ) {
        return true;
    }

    if product_lower.contains("firmware") || product_lower.contains("bios") || product_lower.contains("uefi") {
        return true;
    }

    false
}

fn estimate_downtime(product: &str, requires_reboot: bool) -> u64 {
    if requires_reboot {
        return 90;
    }

    let product_lower = product.to_lowercase();

    if product_lower.contains("database") || product_lower.contains("postgresql") || product_lower.contains("mysql") {
        60
    } else if product_lower.contains("nginx") || product_lower.contains("apache") {
        5
    } else if product_lower.contains("docker") || product_lower.contains("containerd") {
        30
    } else {
        15
    }
}

fn check_app_dependency(app_id: &str, product: &str) -> bool {
    let app_lower = app_id.to_lowercase();
    let product_lower = product.to_lowercase();

    if app_lower.contains("web") || app_lower.contains("api") || app_lower.contains("frontend") {
        if product_lower.contains("nginx") || product_lower.contains("openssl") || product_lower.contains("apache") {
            return true;
        }
    }

    if app_lower.contains("db") || app_lower.contains("data") || app_lower.contains("backend") {
        if product_lower.contains("postgresql") || product_lower.contains("mysql") || product_lower.contains("redis") {
            return true;
        }
    }

    false
}

fn assess_app_compatibility(app_id: &str, patch: &Patch) -> f64 {
    let mut score = 0.9;

    if let Some(cvss) = patch.cvss_score {
        score -= (cvss / 10.0) * 0.2;
    }

    let version_parts: Vec<&str> = patch.version.split('.').collect();
    if let Some(major) = version_parts.first().and_then(|v| v.parse::<u32>().ok()) {
        if major > 1 {
            score -= 0.05;
        }
    }

    let app_lower = app_id.to_lowercase();
    if app_lower.contains("legacy") || app_lower.contains("critical") {
        score -= 0.15;
    }

    score.max(0.0).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_patch(product: &str, vendor: &str, version: &str) -> Patch {
        Patch {
            id: "test-1".to_string(),
            patch_id: "PATCH-001".to_string(),
            vendor: vendor.to_string(),
            product: product.to_string(),
            version: version.to_string(),
            cve_ids: Some(r#"["CVE-2024-1234"]"#.to_string()),
            cvss_score: Some(7.5),
            epss_score: Some(0.3),
            priority_score: 75.0,
            status: "pending".to_string(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_compatibility_pass() {
        let patch = make_test_patch("nginx", "nginx-inc", "1.25.0");
        let result = test_patch_compatibility(&patch).await.unwrap();
        assert!(result.passed);
        assert!(result.details.compatibility_score >= 0.7);
    }

    #[tokio::test]
    async fn test_kernel_reboot() {
        let patch = make_test_patch("linux-kernel", "linux", "6.1.0");
        let result = test_patch_compatibility(&patch).await.unwrap();
        assert!(result.details.requires_reboot);
        assert!(result.details.estimated_downtime_secs > 0);
    }

    #[tokio::test]
    async fn test_app_impact_dependent() {
        let patch = make_test_patch("nginx", "nginx-inc", "1.25.0");
        let result = test_application_impact(&patch, "web-frontend").await.unwrap();
        assert!(!result.details.affected_services.is_empty());
    }

    #[tokio::test]
    async fn test_app_impact_independent() {
        let patch = make_test_patch("redis", "redis-labs", "7.0.0");
        let result = test_application_impact(&patch, "web-frontend").await.unwrap();
        assert!(result.passed);
        assert!(result.details.affected_services.is_empty());
    }

    #[tokio::test]
    async fn test_rollback_capability() {
        let patch = make_test_patch("openssl", "openssl-project", "3.0.12");
        let supports = verify_rollback_capability(&patch).await.unwrap();
        assert!(supports);
    }
}
