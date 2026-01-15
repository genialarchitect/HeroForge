//! STIG Check Implementations
//!
//! Comprehensive CAT I, CAT II, and CAT III checks for Windows STIG compliance.
//! These checks evaluate Windows system configuration against DISA STIGs.

pub mod cat1;
pub mod cat2;
pub mod cat3;

use anyhow::Result;
use crate::scanner::windows_audit::types::{
    StigCheckResult, StigCategory, WindowsAuditResult,
};

/// Run all CAT I (Critical) STIG checks
///
/// These are high-severity findings that represent critical vulnerabilities.
/// They must be addressed immediately and can result in direct system compromise.
pub async fn run_cat1_checks(scan_data: &WindowsAuditResult) -> Result<Vec<StigCheckResult>> {
    Ok(cat1::run_all(scan_data))
}

/// Run all CAT II (Medium) STIG checks
///
/// These are medium-severity findings that should be addressed in a reasonable timeframe.
/// They represent potential security weaknesses that could be exploited.
pub async fn run_cat2_checks(scan_data: &WindowsAuditResult) -> Result<Vec<StigCheckResult>> {
    Ok(cat2::run_all(scan_data))
}

/// Run all CAT III (Low) STIG checks
///
/// These are low-severity findings that represent best practices.
/// They should be addressed as resources permit.
pub async fn run_cat3_checks(scan_data: &WindowsAuditResult) -> Result<Vec<StigCheckResult>> {
    Ok(cat3::run_all(scan_data))
}

/// Run all STIG checks (CAT I, II, and optionally III)
pub async fn run_all_checks(scan_data: &WindowsAuditResult, include_cat3: bool) -> Result<Vec<StigCheckResult>> {
    let mut results = Vec::new();

    // Run CAT I checks (always)
    results.extend(run_cat1_checks(scan_data).await?);

    // Run CAT II checks (always)
    results.extend(run_cat2_checks(scan_data).await?);

    // Run CAT III checks (optional)
    if include_cat3 {
        results.extend(run_cat3_checks(scan_data).await?);
    }

    Ok(results)
}

/// Get summary statistics for STIG check results
pub fn get_check_summary(results: &[StigCheckResult]) -> StigCheckSummary {
    let mut summary = StigCheckSummary::default();

    for result in results {
        match result.category {
            StigCategory::CatI => {
                summary.cat1_total += 1;
                match result.status {
                    crate::scanner::windows_audit::types::StigCheckStatus::NotAFinding => summary.cat1_pass += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::Open => summary.cat1_fail += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::NotApplicable => summary.cat1_na += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::NotReviewed => summary.cat1_nr += 1,
                }
            }
            StigCategory::CatII => {
                summary.cat2_total += 1;
                match result.status {
                    crate::scanner::windows_audit::types::StigCheckStatus::NotAFinding => summary.cat2_pass += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::Open => summary.cat2_fail += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::NotApplicable => summary.cat2_na += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::NotReviewed => summary.cat2_nr += 1,
                }
            }
            StigCategory::CatIII => {
                summary.cat3_total += 1;
                match result.status {
                    crate::scanner::windows_audit::types::StigCheckStatus::NotAFinding => summary.cat3_pass += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::Open => summary.cat3_fail += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::NotApplicable => summary.cat3_na += 1,
                    crate::scanner::windows_audit::types::StigCheckStatus::NotReviewed => summary.cat3_nr += 1,
                }
            }
        }
    }

    summary.total = summary.cat1_total + summary.cat2_total + summary.cat3_total;
    summary.pass = summary.cat1_pass + summary.cat2_pass + summary.cat3_pass;
    summary.fail = summary.cat1_fail + summary.cat2_fail + summary.cat3_fail;
    summary.na = summary.cat1_na + summary.cat2_na + summary.cat3_na;
    summary.nr = summary.cat1_nr + summary.cat2_nr + summary.cat3_nr;

    // Calculate compliance percentage (excluding N/A and NR)
    let assessed = summary.pass + summary.fail;
    if assessed > 0 {
        summary.compliance_percentage = (summary.pass as f64 / assessed as f64) * 100.0;
    }

    summary
}

/// Summary of STIG check results
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StigCheckSummary {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub na: usize,
    pub nr: usize,
    pub compliance_percentage: f64,

    pub cat1_total: usize,
    pub cat1_pass: usize,
    pub cat1_fail: usize,
    pub cat1_na: usize,
    pub cat1_nr: usize,

    pub cat2_total: usize,
    pub cat2_pass: usize,
    pub cat2_fail: usize,
    pub cat2_na: usize,
    pub cat2_nr: usize,

    pub cat3_total: usize,
    pub cat3_pass: usize,
    pub cat3_fail: usize,
    pub cat3_na: usize,
    pub cat3_nr: usize,
}

impl StigCheckSummary {
    /// Get the number of critical (CAT I) failures
    pub fn critical_failures(&self) -> usize {
        self.cat1_fail
    }

    /// Check if the system has any critical findings
    pub fn has_critical_findings(&self) -> bool {
        self.cat1_fail > 0
    }

    /// Get a compliance rating based on findings
    pub fn compliance_rating(&self) -> ComplianceRating {
        if self.cat1_fail > 0 {
            ComplianceRating::Critical
        } else if self.cat2_fail > 5 {
            ComplianceRating::High
        } else if self.cat2_fail > 0 || self.cat3_fail > 10 {
            ComplianceRating::Medium
        } else if self.cat3_fail > 0 {
            ComplianceRating::Low
        } else {
            ComplianceRating::Compliant
        }
    }
}

/// Compliance rating based on STIG findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ComplianceRating {
    /// System is fully compliant
    Compliant,
    /// System has minor (CAT III only) findings
    Low,
    /// System has some medium findings
    Medium,
    /// System has multiple medium findings
    High,
    /// System has critical (CAT I) findings
    Critical,
}

impl std::fmt::Display for ComplianceRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceRating::Compliant => write!(f, "Compliant"),
            ComplianceRating::Low => write!(f, "Low Risk"),
            ComplianceRating::Medium => write!(f, "Medium Risk"),
            ComplianceRating::High => write!(f, "High Risk"),
            ComplianceRating::Critical => write!(f, "Critical"),
        }
    }
}

/// Filter results by category
pub fn filter_by_category(results: &[StigCheckResult], category: StigCategory) -> Vec<&StigCheckResult> {
    results.iter().filter(|r| r.category == category).collect()
}

/// Filter results by status
pub fn filter_by_status(
    results: &[StigCheckResult],
    status: crate::scanner::windows_audit::types::StigCheckStatus,
) -> Vec<&StigCheckResult> {
    results.iter().filter(|r| r.status == status).collect()
}

/// Get only failed checks (Open findings)
pub fn get_failures(results: &[StigCheckResult]) -> Vec<&StigCheckResult> {
    filter_by_status(results, crate::scanner::windows_audit::types::StigCheckStatus::Open)
}

/// Get only passed checks (Not A Finding)
pub fn get_passed(results: &[StigCheckResult]) -> Vec<&StigCheckResult> {
    filter_by_status(results, crate::scanner::windows_audit::types::StigCheckStatus::NotAFinding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::windows_audit::types::{StigCheckStatus, WindowsAuditResult};

    #[tokio::test]
    async fn test_run_all_checks() {
        let scan_data = WindowsAuditResult::new("test-target");
        let results = run_all_checks(&scan_data, true).await.unwrap();

        // Should have checks from all three categories
        assert!(!results.is_empty());

        let summary = get_check_summary(&results);
        assert!(summary.cat1_total > 0);
        assert!(summary.cat2_total > 0);
        assert!(summary.cat3_total > 0);
    }

    #[test]
    fn test_get_check_summary() {
        let results = vec![
            StigCheckResult {
                stig_id: "V-1".to_string(),
                rule_id: "SV-1".to_string(),
                title: "Test CAT I Pass".to_string(),
                category: StigCategory::CatI,
                status: StigCheckStatus::NotAFinding,
                finding_details: None,
                expected: "expected".to_string(),
                actual: "actual".to_string(),
                remediation: None,
            },
            StigCheckResult {
                stig_id: "V-2".to_string(),
                rule_id: "SV-2".to_string(),
                title: "Test CAT I Fail".to_string(),
                category: StigCategory::CatI,
                status: StigCheckStatus::Open,
                finding_details: None,
                expected: "expected".to_string(),
                actual: "actual".to_string(),
                remediation: None,
            },
            StigCheckResult {
                stig_id: "V-3".to_string(),
                rule_id: "SV-3".to_string(),
                title: "Test CAT II Pass".to_string(),
                category: StigCategory::CatII,
                status: StigCheckStatus::NotAFinding,
                finding_details: None,
                expected: "expected".to_string(),
                actual: "actual".to_string(),
                remediation: None,
            },
        ];

        let summary = get_check_summary(&results);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.cat1_total, 2);
        assert_eq!(summary.cat1_pass, 1);
        assert_eq!(summary.cat1_fail, 1);
        assert_eq!(summary.cat2_total, 1);
        assert_eq!(summary.cat2_pass, 1);
        assert!(summary.has_critical_findings());
        assert_eq!(summary.compliance_rating(), ComplianceRating::Critical);
    }

    #[test]
    fn test_compliance_rating() {
        let mut summary = StigCheckSummary::default();

        // No failures = Compliant
        assert_eq!(summary.compliance_rating(), ComplianceRating::Compliant);

        // CAT III only failures = Low
        summary.cat3_fail = 5;
        assert_eq!(summary.compliance_rating(), ComplianceRating::Low);

        // CAT II failures = Medium
        summary.cat2_fail = 2;
        assert_eq!(summary.compliance_rating(), ComplianceRating::Medium);

        // Many CAT II failures = High
        summary.cat2_fail = 10;
        assert_eq!(summary.compliance_rating(), ComplianceRating::High);

        // Any CAT I failure = Critical
        summary.cat1_fail = 1;
        assert_eq!(summary.compliance_rating(), ComplianceRating::Critical);
    }
}
