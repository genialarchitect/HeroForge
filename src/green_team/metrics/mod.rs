//! Response Metrics for SOAR
//!
//! Provides comprehensive metrics tracking:
//! - Mean Time to Detect (MTTD)
//! - Mean Time to Respond (MTTR)
//! - Mean Time to Contain (MTTC)
//! - SLA compliance tracking

use crate::green_team::types::*;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Metrics engine for tracking response effectiveness
pub struct MetricsEngine {
    daily_metrics: HashMap<NaiveDate, ResponseMetrics>,
    sla_configs: HashMap<Severity, SlaConfig>,
    case_metrics: HashMap<Uuid, CaseMetrics>,
}

impl MetricsEngine {
    /// Create a new metrics engine
    pub fn new() -> Self {
        let mut engine = Self {
            daily_metrics: HashMap::new(),
            sla_configs: HashMap::new(),
            case_metrics: HashMap::new(),
        };
        engine.initialize_default_slas();
        engine
    }

    /// Initialize default SLA configurations
    fn initialize_default_slas(&mut self) {
        let slas = vec![
            SlaConfig {
                id: Uuid::new_v4(),
                name: "Critical SLA".to_string(),
                severity: Severity::Critical,
                response_time_minutes: 15,
                resolution_time_hours: 4,
                escalation_time_minutes: Some(30),
                is_active: true,
                created_at: Utc::now(),
            },
            SlaConfig {
                id: Uuid::new_v4(),
                name: "High SLA".to_string(),
                severity: Severity::High,
                response_time_minutes: 60,
                resolution_time_hours: 24,
                escalation_time_minutes: Some(120),
                is_active: true,
                created_at: Utc::now(),
            },
            SlaConfig {
                id: Uuid::new_v4(),
                name: "Medium SLA".to_string(),
                severity: Severity::Medium,
                response_time_minutes: 240,
                resolution_time_hours: 72,
                escalation_time_minutes: Some(480),
                is_active: true,
                created_at: Utc::now(),
            },
            SlaConfig {
                id: Uuid::new_v4(),
                name: "Low SLA".to_string(),
                severity: Severity::Low,
                response_time_minutes: 1440,
                resolution_time_hours: 168,
                escalation_time_minutes: None,
                is_active: true,
                created_at: Utc::now(),
            },
        ];

        for sla in slas {
            self.sla_configs.insert(sla.severity.clone(), sla);
        }
    }

    /// Record case creation
    pub fn record_case_created(&mut self, case_id: Uuid, severity: Severity, created_at: DateTime<Utc>) {
        let metrics = CaseMetrics {
            case_id,
            severity: severity.clone(),
            created_at,
            first_response_at: None,
            contained_at: None,
            resolved_at: None,
            closed_at: None,
            playbooks_executed: 0,
            sla_response_met: None,
            sla_resolution_met: None,
        };

        self.case_metrics.insert(case_id, metrics);
        self.update_daily_metrics(created_at.date_naive(), |m| m.cases_opened += 1);
    }

    /// Record first response to a case
    pub fn record_first_response(&mut self, case_id: &Uuid, response_at: DateTime<Utc>) {
        if let Some(metrics) = self.case_metrics.get_mut(case_id) {
            if metrics.first_response_at.is_none() {
                metrics.first_response_at = Some(response_at);

                // Check SLA
                if let Some(sla) = self.sla_configs.get(&metrics.severity) {
                    let response_time = response_at - metrics.created_at;
                    let sla_target = Duration::minutes(sla.response_time_minutes as i64);
                    metrics.sla_response_met = Some(response_time <= sla_target);
                }
            }
        }
    }

    /// Record case containment
    pub fn record_containment(&mut self, case_id: &Uuid, contained_at: DateTime<Utc>) {
        if let Some(metrics) = self.case_metrics.get_mut(case_id) {
            metrics.contained_at = Some(contained_at);
        }
    }

    /// Record case resolution
    pub fn record_resolution(&mut self, case_id: &Uuid, resolved_at: DateTime<Utc>) {
        if let Some(metrics) = self.case_metrics.get_mut(case_id) {
            metrics.resolved_at = Some(resolved_at);

            // Check SLA
            if let Some(sla) = self.sla_configs.get(&metrics.severity) {
                let resolution_time = resolved_at - metrics.created_at;
                let sla_target = Duration::hours(sla.resolution_time_hours as i64);
                metrics.sla_resolution_met = Some(resolution_time <= sla_target);
            }

            self.update_daily_metrics(resolved_at.date_naive(), |m| m.cases_closed += 1);
        }
    }

    /// Record playbook execution
    pub fn record_playbook_execution(&mut self, case_id: &Uuid) {
        if let Some(metrics) = self.case_metrics.get_mut(case_id) {
            metrics.playbooks_executed += 1;
        }

        let today = Utc::now().date_naive();
        self.update_daily_metrics(today, |m| m.playbooks_executed += 1);
    }

    /// Update daily metrics
    fn update_daily_metrics<F>(&mut self, date: NaiveDate, updater: F)
    where
        F: FnOnce(&mut ResponseMetrics),
    {
        let metrics = self.daily_metrics.entry(date).or_insert_with(|| ResponseMetrics {
            metric_date: date,
            total_cases: 0,
            cases_opened: 0,
            cases_closed: 0,
            avg_mttd_minutes: None,
            avg_mttr_minutes: None,
            avg_mttc_minutes: None,
            avg_resolution_hours: None,
            sla_met_count: 0,
            sla_breached_count: 0,
            playbooks_executed: 0,
        });

        updater(metrics);
    }

    /// Calculate and update aggregate metrics for a date
    pub fn calculate_daily_aggregates(&mut self, date: NaiveDate) {
        // Collect all needed data upfront to avoid borrow issues
        let (total_count, avg_mttr, avg_mttc, avg_resolution, sla_met, sla_breached) = {
            let cases_for_date: Vec<_> = self
                .case_metrics
                .values()
                .filter(|m| m.created_at.date_naive() == date)
                .collect();

            if cases_for_date.is_empty() {
                return;
            }

            let total_count = cases_for_date.len() as u32;

            // Calculate MTTR (Mean Time to Respond)
            let response_times: Vec<f64> = cases_for_date
                .iter()
                .filter_map(|m| {
                    m.first_response_at.map(|r| {
                        (r - m.created_at).num_minutes() as f64
                    })
                })
                .collect();

            let avg_mttr = if !response_times.is_empty() {
                Some(response_times.iter().sum::<f64>() / response_times.len() as f64)
            } else {
                None
            };

            // Calculate MTTC (Mean Time to Contain)
            let containment_times: Vec<f64> = cases_for_date
                .iter()
                .filter_map(|m| {
                    m.contained_at.map(|c| {
                        (c - m.created_at).num_minutes() as f64
                    })
                })
                .collect();

            let avg_mttc = if !containment_times.is_empty() {
                Some(containment_times.iter().sum::<f64>() / containment_times.len() as f64)
            } else {
                None
            };

            // Calculate resolution time
            let resolution_times: Vec<f64> = cases_for_date
                .iter()
                .filter_map(|m| {
                    m.resolved_at.map(|r| {
                        (r - m.created_at).num_minutes() as f64 / 60.0
                    })
                })
                .collect();

            let avg_resolution = if !resolution_times.is_empty() {
                Some(resolution_times.iter().sum::<f64>() / resolution_times.len() as f64)
            } else {
                None
            };

            // Count SLA status
            let sla_met = cases_for_date
                .iter()
                .filter(|m| m.sla_resolution_met == Some(true))
                .count() as u32;

            let sla_breached = cases_for_date
                .iter()
                .filter(|m| m.sla_resolution_met == Some(false))
                .count() as u32;

            (total_count, avg_mttr, avg_mttc, avg_resolution, sla_met, sla_breached)
        };

        self.update_daily_metrics(date, |m| {
            m.total_cases = total_count;
            m.avg_mttr_minutes = avg_mttr;
            m.avg_mttc_minutes = avg_mttc;
            m.avg_resolution_hours = avg_resolution;
            m.sla_met_count = sla_met;
            m.sla_breached_count = sla_breached;
        });
    }

    /// Get metrics overview
    pub fn get_overview(&self) -> MetricsOverview {
        let all_cases: Vec<_> = self.case_metrics.values().collect();

        let total_cases = all_cases.len() as u32;
        let open_cases = all_cases
            .iter()
            .filter(|m| m.resolved_at.is_none())
            .count() as u32;

        let today = Utc::now().date_naive();
        let resolved_today = all_cases
            .iter()
            .filter(|m| m.resolved_at.map(|r| r.date_naive() == today).unwrap_or(false))
            .count() as u32;

        // Calculate overall averages
        let response_times: Vec<f64> = all_cases
            .iter()
            .filter_map(|m| {
                m.first_response_at.map(|r| (r - m.created_at).num_minutes() as f64)
            })
            .collect();

        let avg_mttd = if !response_times.is_empty() {
            response_times.iter().sum::<f64>() / response_times.len() as f64
        } else {
            0.0
        };

        let resolution_times: Vec<f64> = all_cases
            .iter()
            .filter_map(|m| {
                m.resolved_at.map(|r| (r - m.created_at).num_minutes() as f64)
            })
            .collect();

        let avg_mttr = if !resolution_times.is_empty() {
            resolution_times.iter().sum::<f64>() / resolution_times.len() as f64
        } else {
            0.0
        };

        let sla_met_count = all_cases
            .iter()
            .filter(|m| m.sla_resolution_met == Some(true))
            .count();
        let sla_checked_count = all_cases
            .iter()
            .filter(|m| m.sla_resolution_met.is_some())
            .count();

        let sla_compliance = if sla_checked_count > 0 {
            (sla_met_count as f64 / sla_checked_count as f64) * 100.0
        } else {
            100.0
        };

        let total_playbooks: u32 = all_cases.iter().map(|m| m.playbooks_executed).sum();

        let cases_with_playbooks = all_cases
            .iter()
            .filter(|m| m.playbooks_executed > 0)
            .count();

        let automation_rate = if !all_cases.is_empty() {
            (cases_with_playbooks as f64 / all_cases.len() as f64) * 100.0
        } else {
            0.0
        };

        MetricsOverview {
            total_cases,
            open_cases,
            resolved_today,
            avg_mttd_minutes: avg_mttd,
            avg_mttr_minutes: avg_mttr,
            sla_compliance_rate: sla_compliance,
            playbooks_executed: total_playbooks,
            automation_rate,
        }
    }

    /// Get metrics for a date range
    pub fn get_metrics_range(&self, start: NaiveDate, end: NaiveDate) -> Vec<&ResponseMetrics> {
        self.daily_metrics
            .values()
            .filter(|m| m.metric_date >= start && m.metric_date <= end)
            .collect()
    }

    /// Get SLA configuration
    pub fn get_sla_config(&self, severity: &Severity) -> Option<&SlaConfig> {
        self.sla_configs.get(severity)
    }

    /// Update SLA configuration
    pub fn update_sla_config(&mut self, config: SlaConfig) {
        self.sla_configs.insert(config.severity.clone(), config);
    }

    /// Get cases approaching SLA breach
    pub fn get_cases_approaching_sla(&self, threshold_percent: f64) -> Vec<SlaBreach> {
        let now = Utc::now();
        let mut breaches = Vec::new();

        for metrics in self.case_metrics.values() {
            if metrics.resolved_at.is_some() {
                continue; // Already resolved
            }

            if let Some(sla) = self.sla_configs.get(&metrics.severity) {
                let elapsed = now - metrics.created_at;
                let sla_target = Duration::hours(sla.resolution_time_hours as i64);
                let percent_used = (elapsed.num_minutes() as f64 / sla_target.num_minutes() as f64) * 100.0;

                if percent_used >= threshold_percent {
                    breaches.push(SlaBreach {
                        case_id: metrics.case_id,
                        severity: metrics.severity.clone(),
                        sla_target_hours: sla.resolution_time_hours,
                        elapsed_hours: elapsed.num_minutes() as f64 / 60.0,
                        percent_used,
                        breached: percent_used >= 100.0,
                    });
                }
            }
        }

        breaches.sort_by(|a, b| b.percent_used.partial_cmp(&a.percent_used).unwrap_or(std::cmp::Ordering::Equal));
        breaches
    }

    /// Get trend data for a metric over time
    pub fn get_trend(&self, metric_type: MetricType, days: i64) -> Vec<TrendPoint> {
        let end = Utc::now().date_naive();
        let start = end - Duration::days(days);

        let mut points = Vec::new();
        let mut current = start;

        while current <= end {
            let value = self.daily_metrics.get(&current).map(|m| {
                match metric_type {
                    MetricType::Mttd => m.avg_mttd_minutes.unwrap_or(0.0),
                    MetricType::Mttr => m.avg_mttr_minutes.unwrap_or(0.0),
                    MetricType::Mttc => m.avg_mttc_minutes.unwrap_or(0.0),
                    MetricType::SlaCompliance => {
                        let total = m.sla_met_count + m.sla_breached_count;
                        if total > 0 {
                            (m.sla_met_count as f64 / total as f64) * 100.0
                        } else {
                            100.0
                        }
                    }
                    MetricType::CasesOpened => m.cases_opened as f64,
                    MetricType::CasesClosed => m.cases_closed as f64,
                    MetricType::PlaybooksExecuted => m.playbooks_executed as f64,
                }
            }).unwrap_or(0.0);

            points.push(TrendPoint {
                date: current,
                value,
            });

            current += Duration::days(1);
        }

        points
    }
}

impl Default for MetricsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics for a single case
#[derive(Debug, Clone)]
pub struct CaseMetrics {
    pub case_id: Uuid,
    pub severity: Severity,
    pub created_at: DateTime<Utc>,
    pub first_response_at: Option<DateTime<Utc>>,
    pub contained_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub playbooks_executed: u32,
    pub sla_response_met: Option<bool>,
    pub sla_resolution_met: Option<bool>,
}

/// SLA breach information
#[derive(Debug, Clone)]
pub struct SlaBreach {
    pub case_id: Uuid,
    pub severity: Severity,
    pub sla_target_hours: u32,
    pub elapsed_hours: f64,
    pub percent_used: f64,
    pub breached: bool,
}

/// Types of metrics for trending
#[derive(Debug, Clone)]
pub enum MetricType {
    Mttd,
    Mttr,
    Mttc,
    SlaCompliance,
    CasesOpened,
    CasesClosed,
    PlaybooksExecuted,
}

/// A point in a trend
#[derive(Debug, Clone)]
pub struct TrendPoint {
    pub date: NaiveDate,
    pub value: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_metrics_lifecycle() {
        let mut engine = MetricsEngine::new();
        let case_id = Uuid::new_v4();
        let created = Utc::now();

        engine.record_case_created(case_id, Severity::High, created);
        engine.record_first_response(&case_id, created + Duration::minutes(30));
        engine.record_containment(&case_id, created + Duration::hours(2));
        engine.record_resolution(&case_id, created + Duration::hours(12));

        let metrics = engine.case_metrics.get(&case_id).unwrap();
        assert!(metrics.first_response_at.is_some());
        assert!(metrics.contained_at.is_some());
        assert!(metrics.resolved_at.is_some());
        assert!(metrics.sla_response_met == Some(true)); // 30 min < 60 min SLA
        assert!(metrics.sla_resolution_met == Some(true)); // 12 hrs < 24 hrs SLA
    }

    #[test]
    fn test_overview_calculation() {
        let engine = MetricsEngine::new();
        let overview = engine.get_overview();

        assert_eq!(overview.total_cases, 0);
        assert_eq!(overview.sla_compliance_rate, 100.0);
    }
}
