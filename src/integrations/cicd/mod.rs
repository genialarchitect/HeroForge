// CI/CD Integration Module
//
// Provides integration with CI/CD pipelines including:
// - GitHub Actions (SARIF reports)
// - Jenkins (JUnit XML reports)
// - GitLab CI (Security reports, Code Quality)
//
// Features:
// - CI/CD-specific API tokens with limited scope
// - Quality gates for pass/fail decisions
// - Multiple report formats

#![allow(dead_code)]

pub mod types;
pub mod github_actions;
pub mod jenkins;
pub mod gitlab;
pub mod azure_devops;

use anyhow::Result;
use crate::types::{HostInfo, Severity};
use types::*;

/// Evaluate scan results against a quality gate
pub fn evaluate_quality_gate(
    hosts: &[HostInfo],
    gate: &QualityGate,
    baseline_vulns: Option<i32>,
) -> QualityGateResult {
    let counts = count_vulnerabilities(hosts);
    let fail_on = SeverityThreshold::from_str(&gate.fail_on_severity)
        .unwrap_or(SeverityThreshold::High);

    let mut violations: Vec<ThresholdViolation> = Vec::new();
    let mut passed = true;

    // Check severity threshold
    let severity_exceeded = match fail_on {
        SeverityThreshold::Critical => counts.critical > 0,
        SeverityThreshold::High => counts.critical > 0 || counts.high > 0,
        SeverityThreshold::Medium => counts.critical > 0 || counts.high > 0 || counts.medium > 0,
        SeverityThreshold::Low => counts.total > 0,
    };

    if severity_exceeded {
        passed = false;
        violations.push(ThresholdViolation {
            threshold_type: "severity".to_string(),
            threshold_value: 0,
            actual_value: match fail_on {
                SeverityThreshold::Critical => counts.critical,
                SeverityThreshold::High => counts.critical + counts.high,
                SeverityThreshold::Medium => counts.critical + counts.high + counts.medium,
                SeverityThreshold::Low => counts.total,
            },
            message: format!(
                "Vulnerabilities at or above {:?} severity found",
                fail_on
            ),
        });
    }

    // Check max total vulnerabilities
    if let Some(max) = gate.max_vulnerabilities {
        if counts.total > max {
            passed = false;
            violations.push(ThresholdViolation {
                threshold_type: "max_vulnerabilities".to_string(),
                threshold_value: max,
                actual_value: counts.total,
                message: format!("Total vulnerabilities: {} (max: {})", counts.total, max),
            });
        }
    }

    // Check per-severity limits
    if let Some(max) = gate.max_critical {
        if counts.critical > max {
            passed = false;
            violations.push(ThresholdViolation {
                threshold_type: "max_critical".to_string(),
                threshold_value: max,
                actual_value: counts.critical,
                message: format!("Critical vulnerabilities: {} (max: {})", counts.critical, max),
            });
        }
    }

    if let Some(max) = gate.max_high {
        if counts.high > max {
            passed = false;
            violations.push(ThresholdViolation {
                threshold_type: "max_high".to_string(),
                threshold_value: max,
                actual_value: counts.high,
                message: format!("High vulnerabilities: {} (max: {})", counts.high, max),
            });
        }
    }

    if let Some(max) = gate.max_medium {
        if counts.medium > max {
            passed = false;
            violations.push(ThresholdViolation {
                threshold_type: "max_medium".to_string(),
                threshold_value: max,
                actual_value: counts.medium,
                message: format!("Medium vulnerabilities: {} (max: {})", counts.medium, max),
            });
        }
    }

    if let Some(max) = gate.max_low {
        if counts.low > max {
            passed = false;
            violations.push(ThresholdViolation {
                threshold_type: "max_low".to_string(),
                threshold_value: max,
                actual_value: counts.low,
                message: format!("Low vulnerabilities: {} (max: {})", counts.low, max),
            });
        }
    }

    // Check for new vulnerabilities
    let new_vulns = if gate.fail_on_new_vulns {
        baseline_vulns.map(|baseline| {
            let new = counts.total - baseline;
            if new > 0 {
                passed = false;
                violations.push(ThresholdViolation {
                    threshold_type: "new_vulnerabilities".to_string(),
                    threshold_value: 0,
                    actual_value: new,
                    message: format!("{} new vulnerabilities found compared to baseline", new),
                });
            }
            new
        })
    } else {
        None
    };

    let fail_reason = if !passed {
        Some(
            violations
                .iter()
                .map(|v| v.message.clone())
                .collect::<Vec<_>>()
                .join("; "),
        )
    } else {
        None
    };

    QualityGateResult {
        passed,
        gate_name: gate.name.clone(),
        fail_reason,
        vulnerability_counts: counts,
        threshold_violations: violations,
        new_vulnerabilities: new_vulns,
    }
}

/// Count vulnerabilities by severity
pub fn count_vulnerabilities(hosts: &[HostInfo]) -> VulnerabilityCounts {
    let mut counts = VulnerabilityCounts::default();

    for host in hosts {
        for vuln in &host.vulnerabilities {
            match vuln.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
            }
            counts.total += 1;
        }
    }

    counts
}

/// Generate the appropriate report format for a CI/CD platform
pub fn generate_report(
    platform: &CiCdPlatform,
    scan_id: &str,
    hosts: &[HostInfo],
    scan_name: &str,
    quality_gate_result: Option<&QualityGateResult>,
) -> Result<CiCdReport> {
    match platform {
        CiCdPlatform::GitHubActions => {
            let sarif = github_actions::generate_sarif_report(scan_id, hosts, scan_name)?;
            Ok(CiCdReport::Sarif(sarif))
        }
        CiCdPlatform::Jenkins | CiCdPlatform::Generic => {
            let junit = jenkins::generate_junit_report(scan_id, hosts, scan_name, quality_gate_result)?;
            Ok(CiCdReport::JUnit(junit))
        }
        CiCdPlatform::GitLabCi => {
            let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let security = gitlab::generate_security_report(scan_id, hosts, scan_name, &now, &now)?;
            Ok(CiCdReport::GitLabSecurity(security))
        }
        CiCdPlatform::AzureDevOps => {
            let sarif = azure_devops::generate_sarif_report(scan_id, hosts, scan_name)?;
            Ok(CiCdReport::Sarif(sarif))
        }
    }
}

/// Wrapper enum for different report types
#[derive(Debug, Clone)]
pub enum CiCdReport {
    Sarif(types::SarifReport),
    JUnit(String),
    GitLabSecurity(gitlab::GitLabSecurityReport),
    GitLabQuality(Vec<gitlab::GitLabCodeQualityIssue>),
}

/// Generate pipeline configuration example for a platform
pub fn generate_pipeline_example(platform: &CiCdPlatform, api_url: &str) -> String {
    match platform {
        CiCdPlatform::GitHubActions => github_actions::generate_workflow_example(api_url),
        CiCdPlatform::Jenkins => jenkins::generate_pipeline_example(api_url),
        CiCdPlatform::GitLabCi => gitlab::generate_pipeline_example(api_url),
        CiCdPlatform::AzureDevOps => azure_devops::generate_pipeline_example(api_url),
        CiCdPlatform::Generic => jenkins::generate_pipeline_example(api_url), // Use JUnit as default
    }
}

/// Generate a secure random token for CI/CD authentication
pub fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token: String = (0..48)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            chars[idx] as char
        })
        .collect();
    format!("hf_cicd_{}", token)
}

/// Hash a token for storage
pub fn hash_token(token: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Get token prefix for display
pub fn get_token_prefix(token: &str) -> String {
    if token.len() >= 12 {
        format!("{}...", &token[..12])
    } else {
        token.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanTarget, Severity, Vulnerability};
    use std::net::IpAddr;
    use std::time::Duration;

    fn create_test_hosts(vulns: Vec<(Severity, &str)>) -> Vec<HostInfo> {
        vec![HostInfo {
            target: ScanTarget {
                ip: "192.168.1.1".parse::<IpAddr>().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: vec![],
            vulnerabilities: vulns
                .into_iter()
                .map(|(sev, title)| Vulnerability {
                    cve_id: None,
                    title: title.to_string(),
                    severity: sev,
                    description: "Test".to_string(),
                    affected_service: None,
                })
                .collect(),
            scan_duration: Duration::from_secs(5),
        }]
    }

    #[test]
    fn test_count_vulnerabilities() {
        let hosts = create_test_hosts(vec![
            (Severity::Critical, "Crit1"),
            (Severity::Critical, "Crit2"),
            (Severity::High, "High1"),
            (Severity::Medium, "Med1"),
            (Severity::Low, "Low1"),
            (Severity::Low, "Low2"),
        ]);

        let counts = count_vulnerabilities(&hosts);
        assert_eq!(counts.critical, 2);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.low, 2);
        assert_eq!(counts.total, 6);
    }

    #[test]
    fn test_quality_gate_passes() {
        let hosts = create_test_hosts(vec![(Severity::Low, "Low1")]);
        let gate = QualityGate {
            id: "test".to_string(),
            user_id: "user1".to_string(),
            name: "Test Gate".to_string(),
            fail_on_severity: "high".to_string(),
            max_vulnerabilities: None,
            max_critical: None,
            max_high: None,
            max_medium: None,
            max_low: None,
            fail_on_new_vulns: false,
            baseline_scan_id: None,
            is_default: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let result = evaluate_quality_gate(&hosts, &gate, None);
        assert!(result.passed);
        assert!(result.fail_reason.is_none());
    }

    #[test]
    fn test_quality_gate_fails_on_severity() {
        let hosts = create_test_hosts(vec![(Severity::Critical, "Crit1")]);
        let gate = QualityGate {
            id: "test".to_string(),
            user_id: "user1".to_string(),
            name: "Test Gate".to_string(),
            fail_on_severity: "high".to_string(),
            max_vulnerabilities: None,
            max_critical: None,
            max_high: None,
            max_medium: None,
            max_low: None,
            fail_on_new_vulns: false,
            baseline_scan_id: None,
            is_default: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let result = evaluate_quality_gate(&hosts, &gate, None);
        assert!(!result.passed);
        assert!(result.fail_reason.is_some());
    }

    #[test]
    fn test_quality_gate_max_limits() {
        let hosts = create_test_hosts(vec![
            (Severity::Critical, "Crit1"),
            (Severity::Critical, "Crit2"),
        ]);
        let gate = QualityGate {
            id: "test".to_string(),
            user_id: "user1".to_string(),
            name: "Test Gate".to_string(),
            fail_on_severity: "critical".to_string(),
            max_vulnerabilities: None,
            max_critical: Some(1), // Allow max 1 critical
            max_high: None,
            max_medium: None,
            max_low: None,
            fail_on_new_vulns: false,
            baseline_scan_id: None,
            is_default: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let result = evaluate_quality_gate(&hosts, &gate, None);
        assert!(!result.passed);
        assert!(result.threshold_violations.iter().any(|v| v.threshold_type == "max_critical"));
    }

    #[test]
    fn test_generate_token() {
        let token = generate_token();
        assert!(token.starts_with("hf_cicd_"));
        assert!(token.len() > 20);
    }

    #[test]
    fn test_hash_token() {
        let token = "hf_cicd_test123";
        let hash = hash_token(token);
        assert_eq!(hash.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_token_prefix() {
        let token = "hf_cicd_abc123def456xyz789";
        let prefix = get_token_prefix(token);
        assert_eq!(prefix, "hf_cicd_abc1...");
    }
}
