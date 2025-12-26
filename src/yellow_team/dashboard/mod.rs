//! DevSecOps Dashboard Module
//!
//! Provides metrics, pipeline status, and trend analysis for
//! security operations in the software development lifecycle.

pub mod metrics;
pub mod pipeline_status;

use crate::yellow_team::types::*;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DevSecOps Dashboard data aggregator
pub struct DashboardAggregator {
    /// Projects being tracked
    pub projects: Vec<DevSecOpsProject>,
    /// Historical metrics
    pub metrics_history: Vec<DevSecOpsMetrics>,
}

/// Dashboard overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardOverview {
    /// Total projects
    pub total_projects: u32,
    /// Projects with security gate enabled
    pub security_gate_enabled: u32,
    /// Last 24h statistics
    pub last_24h: PeriodStats,
    /// Last 7d statistics
    pub last_7d: PeriodStats,
    /// Last 30d statistics
    pub last_30d: PeriodStats,
    /// Overall security health score (0-100)
    pub security_health_score: u32,
    /// Top issues by category
    pub top_issues: Vec<TopIssue>,
    /// Recent builds
    pub recent_builds: Vec<BuildSummary>,
}

/// Statistics for a time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodStats {
    /// New findings
    pub new_findings: u32,
    /// Fixed findings
    pub fixed_findings: u32,
    /// Builds total
    pub builds_total: u32,
    /// Builds passed security gate
    pub builds_passed: u32,
    /// Builds blocked by security gate
    pub builds_blocked: u32,
    /// Average MTTR in hours
    pub avg_mttr_hours: Option<f64>,
}

/// Top issue summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopIssue {
    /// Issue category
    pub category: String,
    /// Count
    pub count: u32,
    /// Severity
    pub severity: Severity,
    /// Trend (up, down, stable)
    pub trend: Trend,
}

/// Trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trend {
    Up,
    Down,
    Stable,
}

/// Build summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSummary {
    /// Project name
    pub project: String,
    /// Build number/ID
    pub build_id: String,
    /// Status
    pub status: BuildStatus,
    /// Security gate passed
    pub security_gate_passed: bool,
    /// New findings in this build
    pub new_findings: u32,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Security trend data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTrend {
    /// Time series data points
    pub data_points: Vec<TrendDataPoint>,
    /// Period covered
    pub period: TrendPeriod,
    /// Overall trend direction
    pub trend: Trend,
    /// Percentage change
    pub change_percent: f64,
}

/// Trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    /// Date
    pub date: NaiveDate,
    /// New findings
    pub new_findings: u32,
    /// Fixed findings
    pub fixed_findings: u32,
    /// Open findings (cumulative)
    pub open_findings: u32,
    /// Security score
    pub security_score: u32,
}

/// Trend period
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendPeriod {
    Week,
    Month,
    Quarter,
    Year,
}

impl DashboardAggregator {
    /// Create a new dashboard aggregator
    pub fn new() -> Self {
        Self {
            projects: Vec::new(),
            metrics_history: Vec::new(),
        }
    }

    /// Add project metrics
    pub fn add_metrics(&mut self, metrics: DevSecOpsMetrics) {
        self.metrics_history.push(metrics);
    }

    /// Add project
    pub fn add_project(&mut self, project: DevSecOpsProject) {
        self.projects.push(project);
    }

    /// Get dashboard overview
    pub fn get_overview(&self) -> DashboardOverview {
        let now = Utc::now();
        
        DashboardOverview {
            total_projects: self.projects.len() as u32,
            security_gate_enabled: self.projects.iter()
                .filter(|p| p.security_gate_enabled)
                .count() as u32,
            last_24h: self.get_period_stats(now - Duration::hours(24), now),
            last_7d: self.get_period_stats(now - Duration::days(7), now),
            last_30d: self.get_period_stats(now - Duration::days(30), now),
            security_health_score: self.calculate_health_score(),
            top_issues: self.get_top_issues(),
            recent_builds: self.get_recent_builds(10),
        }
    }

    /// Get statistics for a time period
    fn get_period_stats(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> PeriodStats {
        let metrics_in_period: Vec<_> = self.metrics_history.iter()
            .filter(|m| m.metric_date >= start.date_naive() && m.metric_date <= end.date_naive())
            .collect();

        if metrics_in_period.is_empty() {
            return PeriodStats {
                new_findings: 0,
                fixed_findings: 0,
                builds_total: 0,
                builds_passed: 0,
                builds_blocked: 0,
                avg_mttr_hours: None,
            };
        }

        let new_findings: u32 = metrics_in_period.iter().map(|m| m.new_findings as u32).sum();
        let fixed_findings: u32 = metrics_in_period.iter().map(|m| m.fixed_findings as u32).sum();
        let builds_passed: u32 = metrics_in_period.iter()
            .filter(|m| m.security_gate_passed)
            .count() as u32;
        let builds_blocked: u32 = metrics_in_period.iter()
            .filter(|m| m.build_blocked)
            .count() as u32;

        let mttr_values: Vec<f64> = metrics_in_period.iter()
            .filter_map(|m| m.mttr_hours)
            .collect();
        let avg_mttr = if mttr_values.is_empty() {
            None
        } else {
            Some(mttr_values.iter().sum::<f64>() / mttr_values.len() as f64)
        };

        PeriodStats {
            new_findings,
            fixed_findings,
            builds_total: metrics_in_period.len() as u32,
            builds_passed,
            builds_blocked,
            avg_mttr_hours: avg_mttr,
        }
    }

    /// Calculate overall health score
    fn calculate_health_score(&self) -> u32 {
        if self.projects.is_empty() {
            return 0;
        }

        let mut score: u32 = 100;
        
        // Deduct for security gate not enabled
        let gate_ratio = self.projects.iter()
            .filter(|p| p.security_gate_enabled)
            .count() as f64 / self.projects.len() as f64;
        score = (score as f64 * gate_ratio) as u32;

        // Deduct for failed builds
        let recent_metrics: Vec<_> = self.metrics_history.iter()
            .rev()
            .take(30)
            .collect();
        
        if !recent_metrics.is_empty() {
            let blocked_ratio = recent_metrics.iter()
                .filter(|m| m.build_blocked)
                .count() as f64 / recent_metrics.len() as f64;
            score = (score as f64 * (1.0 - blocked_ratio * 0.5)) as u32;
            
            // Deduct for high MTTR
            let avg_mttr: f64 = recent_metrics.iter()
                .filter_map(|m| m.mttr_hours)
                .sum::<f64>() / recent_metrics.iter().filter(|m| m.mttr_hours.is_some()).count().max(1) as f64;
            
            if avg_mttr > 72.0 {
                score = (score as f64 * 0.8) as u32; // More than 3 days
            } else if avg_mttr > 24.0 {
                score = (score as f64 * 0.9) as u32; // More than 1 day
            }
        }

        score.min(100)
    }

    /// Get top issues
    fn get_top_issues(&self) -> Vec<TopIssue> {
        // Mock implementation - would normally aggregate from findings
        vec![
            TopIssue {
                category: "Hardcoded Secrets".to_string(),
                count: 12,
                severity: Severity::Critical,
                trend: Trend::Down,
            },
            TopIssue {
                category: "SQL Injection".to_string(),
                count: 5,
                severity: Severity::High,
                trend: Trend::Stable,
            },
            TopIssue {
                category: "Vulnerable Dependencies".to_string(),
                count: 23,
                severity: Severity::Medium,
                trend: Trend::Up,
            },
        ]
    }

    /// Get recent builds
    fn get_recent_builds(&self, limit: usize) -> Vec<BuildSummary> {
        // Mock implementation
        Vec::new()
    }

    /// Get security trend
    pub fn get_trend(&self, period: TrendPeriod) -> SecurityTrend {
        let days = match period {
            TrendPeriod::Week => 7,
            TrendPeriod::Month => 30,
            TrendPeriod::Quarter => 90,
            TrendPeriod::Year => 365,
        };

        let now = Utc::now();
        let start = now - Duration::days(days);

        let mut data_points: Vec<TrendDataPoint> = Vec::new();
        let mut cumulative_open = 0i32;

        for day_offset in 0..days {
            let date = (start + Duration::days(day_offset)).date_naive();
            
            let day_metrics: Vec<_> = self.metrics_history.iter()
                .filter(|m| m.metric_date == date)
                .collect();
            
            let new_findings: u32 = day_metrics.iter().map(|m| m.new_findings as u32).sum();
            let fixed_findings: u32 = day_metrics.iter().map(|m| m.fixed_findings as u32).sum();
            
            cumulative_open += new_findings as i32 - fixed_findings as i32;
            cumulative_open = cumulative_open.max(0);
            
            data_points.push(TrendDataPoint {
                date,
                new_findings,
                fixed_findings,
                open_findings: cumulative_open as u32,
                security_score: self.calculate_health_score(),
            });
        }

        // Calculate trend
        let (trend, change_percent) = if data_points.len() >= 2 {
            let first_half: u32 = data_points[..data_points.len()/2].iter()
                .map(|d| d.open_findings)
                .sum();
            let second_half: u32 = data_points[data_points.len()/2..].iter()
                .map(|d| d.open_findings)
                .sum();
            
            let change = if first_half > 0 {
                ((second_half as f64 - first_half as f64) / first_half as f64) * 100.0
            } else {
                0.0
            };
            
            let trend = if change > 5.0 {
                Trend::Up
            } else if change < -5.0 {
                Trend::Down
            } else {
                Trend::Stable
            };
            
            (trend, change)
        } else {
            (Trend::Stable, 0.0)
        };

        SecurityTrend {
            data_points,
            period,
            trend,
            change_percent,
        }
    }

    /// Get MTTR (Mean Time To Remediate) statistics
    pub fn get_mttr_stats(&self) -> MttrStats {
        let recent_metrics: Vec<_> = self.metrics_history.iter()
            .rev()
            .take(90)
            .filter_map(|m| m.mttr_hours)
            .collect();

        if recent_metrics.is_empty() {
            return MttrStats {
                current_avg_hours: 0.0,
                previous_avg_hours: 0.0,
                trend: Trend::Stable,
                by_severity: HashMap::new(),
            };
        }

        let current_avg = recent_metrics[..recent_metrics.len().min(30)].iter()
            .sum::<f64>() / recent_metrics.len().min(30) as f64;
        
        let previous_avg = if recent_metrics.len() > 30 {
            recent_metrics[30..].iter().sum::<f64>() / (recent_metrics.len() - 30) as f64
        } else {
            current_avg
        };

        let trend = if current_avg < previous_avg * 0.9 {
            Trend::Down // Improving
        } else if current_avg > previous_avg * 1.1 {
            Trend::Up // Getting worse
        } else {
            Trend::Stable
        };

        MttrStats {
            current_avg_hours: current_avg,
            previous_avg_hours: previous_avg,
            trend,
            by_severity: HashMap::new(), // Would be populated from actual data
        }
    }
}

impl Default for DashboardAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// MTTR Statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MttrStats {
    /// Current average MTTR in hours
    pub current_avg_hours: f64,
    /// Previous period average
    pub previous_avg_hours: f64,
    /// Trend
    pub trend: Trend,
    /// MTTR by severity
    pub by_severity: HashMap<String, f64>,
}

/// Security gate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGateConfig {
    /// Block on critical findings
    pub block_on_critical: bool,
    /// Block on high findings
    pub block_on_high: bool,
    /// Maximum allowed critical findings
    pub max_critical: u32,
    /// Maximum allowed high findings
    pub max_high: u32,
    /// Maximum allowed medium findings
    pub max_medium: u32,
    /// Block on vulnerable dependencies
    pub block_on_vulnerable_deps: bool,
    /// Block on license violations
    pub block_on_license_violations: bool,
    /// Minimum code coverage
    pub min_code_coverage: Option<f64>,
}

impl Default for SecurityGateConfig {
    fn default() -> Self {
        Self {
            block_on_critical: true,
            block_on_high: false,
            max_critical: 0,
            max_high: 10,
            max_medium: 50,
            block_on_vulnerable_deps: true,
            block_on_license_violations: true,
            min_code_coverage: Some(80.0),
        }
    }
}

/// Evaluate security gate
pub fn evaluate_security_gate(
    config: &SecurityGateConfig,
    critical_count: u32,
    high_count: u32,
    medium_count: u32,
    has_vulnerable_deps: bool,
    has_license_violations: bool,
    code_coverage: Option<f64>,
) -> SecurityGateResult {
    let mut blocked = false;
    let mut reasons = Vec::new();

    if config.block_on_critical && critical_count > config.max_critical {
        blocked = true;
        reasons.push(format!("{} critical findings exceed maximum of {}", critical_count, config.max_critical));
    }

    if config.block_on_high && high_count > config.max_high {
        blocked = true;
        reasons.push(format!("{} high findings exceed maximum of {}", high_count, config.max_high));
    }

    if medium_count > config.max_medium {
        blocked = true;
        reasons.push(format!("{} medium findings exceed maximum of {}", medium_count, config.max_medium));
    }

    if config.block_on_vulnerable_deps && has_vulnerable_deps {
        blocked = true;
        reasons.push("Vulnerable dependencies detected".to_string());
    }

    if config.block_on_license_violations && has_license_violations {
        blocked = true;
        reasons.push("License violations detected".to_string());
    }

    if let (Some(min), Some(actual)) = (config.min_code_coverage, code_coverage) {
        if actual < min {
            blocked = true;
            reasons.push(format!("Code coverage {:.1}% below minimum {:.1}%", actual, min));
        }
    }

    SecurityGateResult {
        passed: !blocked,
        reasons,
    }
}

/// Security gate evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGateResult {
    /// Whether the gate passed
    pub passed: bool,
    /// Reasons for blocking (if any)
    pub reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_aggregator() {
        let aggregator = DashboardAggregator::new();
        assert!(aggregator.projects.is_empty());
    }

    #[test]
    fn test_security_gate_pass() {
        let config = SecurityGateConfig::default();
        let result = evaluate_security_gate(&config, 0, 5, 20, false, false, Some(85.0));
        assert!(result.passed);
    }

    #[test]
    fn test_security_gate_fail_critical() {
        let config = SecurityGateConfig::default();
        let result = evaluate_security_gate(&config, 1, 0, 0, false, false, Some(90.0));
        assert!(!result.passed);
        assert!(result.reasons[0].contains("critical"));
    }

    #[test]
    fn test_security_gate_fail_coverage() {
        let config = SecurityGateConfig::default();
        let result = evaluate_security_gate(&config, 0, 0, 0, false, false, Some(50.0));
        assert!(!result.passed);
        assert!(result.reasons[0].contains("coverage"));
    }
}
