//! Pipeline Security Status

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// CI/CD pipeline security status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStatus {
    /// Pipeline ID
    pub pipeline_id: String,
    /// Project name
    pub project: String,
    /// Branch
    pub branch: String,
    /// Commit SHA
    pub commit_sha: String,
    /// Pipeline status
    pub status: PipelineState,
    /// Security checks
    pub security_checks: Vec<SecurityCheck>,
    /// Overall security gate result
    pub security_gate_passed: bool,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
}

/// Pipeline state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineState {
    Pending,
    Running,
    Passed,
    Failed,
    Cancelled,
    Blocked,
}

/// Individual security check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCheck {
    /// Check name
    pub name: String,
    /// Check type
    pub check_type: SecurityCheckType,
    /// Status
    pub status: CheckStatus,
    /// Findings count
    pub findings_count: u32,
    /// Critical findings
    pub critical_count: u32,
    /// High findings
    pub high_count: u32,
    /// Duration in seconds
    pub duration_seconds: u32,
    /// Details URL
    pub details_url: Option<String>,
}

/// Type of security check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCheckType {
    Sast,
    Dast,
    Sca,
    SecretScan,
    IacScan,
    ContainerScan,
    LicenseCheck,
    CodeCoverage,
}

/// Check status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pending,
    Running,
    Passed,
    Failed,
    Skipped,
    Warning,
}

/// Pipeline summary for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSummary {
    /// Total pipelines today
    pub total_today: u32,
    /// Passed today
    pub passed_today: u32,
    /// Failed today
    pub failed_today: u32,
    /// Blocked by security gate
    pub blocked_by_security: u32,
    /// Average duration (seconds)
    pub avg_duration_seconds: u32,
    /// Most common failures
    pub common_failures: Vec<FailureReason>,
}

/// Common failure reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureReason {
    /// Reason
    pub reason: String,
    /// Check type
    pub check_type: SecurityCheckType,
    /// Count
    pub count: u32,
}

/// Get pipeline summary
pub fn summarize_pipelines(pipelines: &[PipelineStatus]) -> PipelineSummary {
    let total = pipelines.len() as u32;
    let passed = pipelines.iter()
        .filter(|p| matches!(p.status, PipelineState::Passed))
        .count() as u32;
    let failed = pipelines.iter()
        .filter(|p| matches!(p.status, PipelineState::Failed))
        .count() as u32;
    let blocked = pipelines.iter()
        .filter(|p| matches!(p.status, PipelineState::Blocked) || !p.security_gate_passed)
        .count() as u32;

    let durations: Vec<u32> = pipelines.iter()
        .filter_map(|p| {
            p.completed_at.map(|end| {
                (end - p.started_at).num_seconds() as u32
            })
        })
        .collect();

    let avg_duration = if durations.is_empty() {
        0
    } else {
        durations.iter().sum::<u32>() / durations.len() as u32
    };

    // Calculate common failure reasons from security checks
    let common_failures = calculate_common_failures(pipelines);

    PipelineSummary {
        total_today: total,
        passed_today: passed,
        failed_today: failed,
        blocked_by_security: blocked,
        avg_duration_seconds: avg_duration,
        common_failures,
    }
}

/// Calculate common failure reasons across pipelines
fn calculate_common_failures(pipelines: &[PipelineStatus]) -> Vec<FailureReason> {
    use std::collections::HashMap;

    // Count failures by check type and reason
    let mut failure_counts: HashMap<(SecurityCheckType, String), u32> = HashMap::new();

    for pipeline in pipelines {
        if matches!(pipeline.status, PipelineState::Failed | PipelineState::Blocked) {
            for check in &pipeline.security_checks {
                if matches!(check.status, CheckStatus::Failed) {
                    // Create failure reason based on check type and findings
                    let reason = if check.critical_count > 0 {
                        format!("{} critical findings", check.critical_count)
                    } else if check.high_count > 0 {
                        format!("{} high findings", check.high_count)
                    } else if check.findings_count > 0 {
                        format!("{} findings", check.findings_count)
                    } else {
                        "Check failed".to_string()
                    };

                    *failure_counts.entry((check.check_type, reason)).or_insert(0) += 1;
                }
            }
        }
    }

    // Convert to sorted list of FailureReason
    let mut failures: Vec<FailureReason> = failure_counts
        .into_iter()
        .map(|((check_type, reason), count)| FailureReason {
            reason,
            check_type,
            count,
        })
        .collect();

    // Sort by count descending
    failures.sort_by(|a, b| b.count.cmp(&a.count));

    // Return top 10 most common failures
    failures.truncate(10);
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summarize_empty() {
        let summary = summarize_pipelines(&[]);
        assert_eq!(summary.total_today, 0);
        assert_eq!(summary.avg_duration_seconds, 0);
    }

    #[test]
    fn test_pipeline_status() {
        let status = PipelineStatus {
            pipeline_id: "123".to_string(),
            project: "test".to_string(),
            branch: "main".to_string(),
            commit_sha: "abc123".to_string(),
            status: PipelineState::Passed,
            security_checks: vec![],
            security_gate_passed: true,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
        };
        
        assert!(matches!(status.status, PipelineState::Passed));
    }
}
