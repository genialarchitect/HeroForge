//! CI/CD Quality Gate Policies
//!
//! Policy evaluation for CI/CD pipeline quality gates.

use super::types::{
    GateStatus, PolicyActions, PolicyConditions, QualityGateDetails, QualityGateResult,
};

/// Quality gate policy evaluator
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluate quality gate conditions against scan results
    pub fn evaluate(
        conditions: &PolicyConditions,
        details: &QualityGateDetails,
    ) -> QualityGateResult {
        let mut passed = Vec::new();
        let mut failed = Vec::new();
        let warnings = Vec::new();

        // Check max new findings
        if let Some(max) = conditions.max_new_findings {
            if details.new_findings > max {
                failed.push(format!(
                    "New findings ({}) exceeds maximum ({})",
                    details.new_findings, max
                ));
            } else {
                passed.push(format!(
                    "New findings ({}) within limit ({})",
                    details.new_findings, max
                ));
            }
        }

        // Check max total findings
        if let Some(max) = conditions.max_total_findings {
            if details.total_findings > max {
                failed.push(format!(
                    "Total findings ({}) exceeds maximum ({})",
                    details.total_findings, max
                ));
            } else {
                passed.push(format!(
                    "Total findings ({}) within limit ({})",
                    details.total_findings, max
                ));
            }
        }

        // Check max critical findings
        if let Some(max) = conditions.max_critical {
            if details.critical_count > max {
                failed.push(format!(
                    "Critical findings ({}) exceeds maximum ({})",
                    details.critical_count, max
                ));
            } else {
                passed.push(format!(
                    "Critical findings ({}) within limit ({})",
                    details.critical_count, max
                ));
            }
        }

        // Check max high severity findings
        if let Some(max) = conditions.max_high {
            if details.high_count > max {
                failed.push(format!(
                    "High severity findings ({}) exceeds maximum ({})",
                    details.high_count, max
                ));
            } else {
                passed.push(format!(
                    "High severity findings ({}) within limit ({})",
                    details.high_count, max
                ));
            }
        }

        // Check minimum severity threshold
        if let Some(ref min_severity) = conditions.min_severity {
            let severity_breach = match min_severity.to_lowercase().as_str() {
                "critical" => details.critical_count > 0,
                "high" => details.critical_count > 0 || details.high_count > 0,
                "medium" => {
                    details.critical_count > 0 || details.high_count > 0 || details.medium_count > 0
                }
                "low" => {
                    details.critical_count > 0
                        || details.high_count > 0
                        || details.medium_count > 0
                        || details.low_count > 0
                }
                _ => false,
            };

            if severity_breach {
                failed.push(format!(
                    "Findings above {} severity threshold exist",
                    min_severity
                ));
            } else {
                passed.push(format!("No findings above {} severity", min_severity));
            }
        }

        // Check code coverage if available
        if let (Some(min_coverage), Some(actual_coverage)) =
            (conditions.min_coverage, details.coverage)
        {
            if actual_coverage < min_coverage {
                failed.push(format!(
                    "Code coverage ({:.1}%) below minimum ({:.1}%)",
                    actual_coverage, min_coverage
                ));
            } else {
                passed.push(format!(
                    "Code coverage ({:.1}%) meets minimum ({:.1}%)",
                    actual_coverage, min_coverage
                ));
            }
        }

        // Determine overall status
        let status = if !failed.is_empty() {
            GateStatus::Failed
        } else if !warnings.is_empty() {
            GateStatus::Warning
        } else {
            GateStatus::Passed
        };

        // Generate summary
        let summary = match status {
            GateStatus::Passed => format!(
                "Quality gate passed. {} conditions checked, all passed.",
                passed.len()
            ),
            GateStatus::Warning => format!(
                "Quality gate passed with warnings. {} conditions passed, {} warnings.",
                passed.len(),
                warnings.len()
            ),
            GateStatus::Failed => format!(
                "Quality gate failed. {} conditions failed, {} passed.",
                failed.len(),
                passed.len()
            ),
            GateStatus::Pending => "Quality gate evaluation pending.".to_string(),
        };

        QualityGateResult {
            status,
            passed_conditions: passed,
            failed_conditions: failed,
            warning_conditions: warnings,
            summary,
            details: details.clone(),
        }
    }

    /// Create default policy conditions for different strictness levels
    pub fn default_conditions(strictness: PolicyStrictness) -> PolicyConditions {
        match strictness {
            PolicyStrictness::Lenient => PolicyConditions {
                min_severity: Some("critical".to_string()),
                max_new_findings: None,
                max_total_findings: None,
                max_critical: Some(0),
                max_high: None,
                min_coverage: None,
                custom_expressions: Vec::new(),
            },
            PolicyStrictness::Standard => PolicyConditions {
                min_severity: Some("high".to_string()),
                max_new_findings: Some(5),
                max_total_findings: None,
                max_critical: Some(0),
                max_high: Some(0),
                min_coverage: None,
                custom_expressions: Vec::new(),
            },
            PolicyStrictness::Strict => PolicyConditions {
                min_severity: Some("medium".to_string()),
                max_new_findings: Some(0),
                max_total_findings: Some(10),
                max_critical: Some(0),
                max_high: Some(0),
                min_coverage: Some(80.0),
                custom_expressions: Vec::new(),
            },
        }
    }

    /// Create default policy actions
    pub fn default_actions(strictness: PolicyStrictness) -> PolicyActions {
        match strictness {
            PolicyStrictness::Lenient => PolicyActions {
                block_on_fail: false,
                notify_on_fail: true,
                notify_on_success: false,
                create_ticket_on_fail: false,
                webhook_urls: Vec::new(),
                comment_on_pr: true,
                update_commit_status: true,
            },
            PolicyStrictness::Standard => PolicyActions {
                block_on_fail: true,
                notify_on_fail: true,
                notify_on_success: false,
                create_ticket_on_fail: false,
                webhook_urls: Vec::new(),
                comment_on_pr: true,
                update_commit_status: true,
            },
            PolicyStrictness::Strict => PolicyActions {
                block_on_fail: true,
                notify_on_fail: true,
                notify_on_success: true,
                create_ticket_on_fail: true,
                webhook_urls: Vec::new(),
                comment_on_pr: true,
                update_commit_status: true,
            },
        }
    }
}

/// Policy strictness levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyStrictness {
    /// Lenient - only block on critical issues
    Lenient,
    /// Standard - block on critical and high severity
    Standard,
    /// Strict - comprehensive security requirements
    Strict,
}

impl std::str::FromStr for PolicyStrictness {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "lenient" | "low" => Ok(PolicyStrictness::Lenient),
            "standard" | "medium" | "normal" => Ok(PolicyStrictness::Standard),
            "strict" | "high" => Ok(PolicyStrictness::Strict),
            _ => Err(format!("Unknown strictness level: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_passing_gate() {
        let conditions = PolicyConditions {
            max_critical: Some(0),
            max_high: Some(5),
            ..Default::default()
        };

        let details = QualityGateDetails {
            new_findings: 2,
            fixed_findings: 1,
            total_findings: 10,
            critical_count: 0,
            high_count: 3,
            medium_count: 5,
            low_count: 2,
            info_count: 0,
            coverage: None,
        };

        let result = PolicyEvaluator::evaluate(&conditions, &details);
        assert_eq!(result.status, GateStatus::Passed);
    }

    #[test]
    fn test_evaluate_failing_gate() {
        let conditions = PolicyConditions {
            max_critical: Some(0),
            max_high: Some(0),
            ..Default::default()
        };

        let details = QualityGateDetails {
            new_findings: 5,
            fixed_findings: 0,
            total_findings: 15,
            critical_count: 1,
            high_count: 5,
            medium_count: 5,
            low_count: 4,
            info_count: 0,
            coverage: None,
        };

        let result = PolicyEvaluator::evaluate(&conditions, &details);
        assert_eq!(result.status, GateStatus::Failed);
        assert!(!result.failed_conditions.is_empty());
    }
}
