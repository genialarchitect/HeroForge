//! DevSecOps Metrics

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security metrics for a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSecurityMetrics {
    /// Project ID
    pub project_id: String,
    /// Project name
    pub project_name: String,
    /// Total findings
    pub total_findings: FindingCounts,
    /// Open findings
    pub open_findings: FindingCounts,
    /// Mean time to remediate (hours)
    pub mttr_hours: f64,
    /// Fix rate (percent of findings fixed)
    pub fix_rate: f64,
    /// Security score (0-100)
    pub security_score: u32,
    /// Last scan date
    pub last_scan_at: Option<DateTime<Utc>>,
}

/// Finding counts by severity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl FindingCounts {
    pub fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }

    pub fn weighted_score(&self) -> u32 {
        // Higher weight for more severe findings
        self.critical * 10 + self.high * 5 + self.medium * 2 + self.low
    }
}

/// Organization-wide security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgSecurityMetrics {
    /// Total projects
    pub total_projects: u32,
    /// Active projects (scanned in last 30 days)
    pub active_projects: u32,
    /// Total findings across all projects
    pub total_findings: FindingCounts,
    /// Average security score
    pub avg_security_score: f64,
    /// Average MTTR
    pub avg_mttr_hours: f64,
    /// Projects by health status
    pub projects_by_health: HashMap<String, u32>,
    /// Top vulnerable projects
    pub top_vulnerable: Vec<ProjectSecurityMetrics>,
    /// Best performing projects
    pub top_secure: Vec<ProjectSecurityMetrics>,
}

/// Historical metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    pub date: NaiveDate,
    pub value: f64,
}

/// Metric trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricTrend {
    /// Metric name
    pub metric_name: String,
    /// Current value
    pub current_value: f64,
    /// Previous period value
    pub previous_value: f64,
    /// Change percentage
    pub change_percent: f64,
    /// Trend direction
    pub trend: TrendDirection,
    /// Historical data
    pub history: Vec<MetricDataPoint>,
}

/// Trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Improving,
    Declining,
    Stable,
}

/// Calculate security score from finding counts
pub fn calculate_security_score(findings: &FindingCounts) -> u32 {
    // Start at 100 and deduct based on findings
    let mut score: i32 = 100;
    
    score -= (findings.critical * 20) as i32;
    score -= (findings.high * 10) as i32;
    score -= (findings.medium * 3) as i32;
    score -= findings.low as i32;
    
    score.max(0).min(100) as u32
}

/// Calculate fix rate
pub fn calculate_fix_rate(total: u32, fixed: u32) -> f64 {
    if total == 0 {
        return 100.0;
    }
    (fixed as f64 / total as f64) * 100.0
}

/// Calculate MTTR from remediation times
pub fn calculate_mttr(remediation_times_hours: &[f64]) -> f64 {
    if remediation_times_hours.is_empty() {
        return 0.0;
    }
    remediation_times_hours.iter().sum::<f64>() / remediation_times_hours.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_counts_total() {
        let counts = FindingCounts {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 5,
        };
        assert_eq!(counts.total(), 15);
    }

    #[test]
    fn test_calculate_security_score() {
        let perfect = FindingCounts::default();
        assert_eq!(calculate_security_score(&perfect), 100);

        let with_critical = FindingCounts {
            critical: 1,
            ..Default::default()
        };
        assert_eq!(calculate_security_score(&with_critical), 80);
    }

    #[test]
    fn test_calculate_fix_rate() {
        assert_eq!(calculate_fix_rate(100, 80), 80.0);
        assert_eq!(calculate_fix_rate(0, 0), 100.0);
    }
}
