#![allow(dead_code)]
//! Prioritization Algorithms
//!
//! Contains the core prioritization logic and algorithms for
//! ranking vulnerabilities based on calculated scores.

use crate::ai::models::{
    AIVulnerabilityScore, PrioritizationSummary, RiskCategory,
};
use std::collections::HashMap;

/// Prioritization engine for ranking vulnerabilities
pub struct PrioritizationEngine;

impl PrioritizationEngine {
    /// Sort vulnerabilities by effective risk score (descending)
    pub fn sort_by_risk(scores: &mut [AIVulnerabilityScore]) {
        scores.sort_by(|a, b| {
            b.effective_risk_score
                .partial_cmp(&a.effective_risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// Sort by risk category, then by score within category
    pub fn sort_by_category_and_risk(scores: &mut [AIVulnerabilityScore]) {
        scores.sort_by(|a, b| {
            let cat_order = Self::category_order(&b.risk_category)
                .cmp(&Self::category_order(&a.risk_category));
            if cat_order == std::cmp::Ordering::Equal {
                b.effective_risk_score
                    .partial_cmp(&a.effective_risk_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            } else {
                cat_order
            }
        });
    }

    /// Get numeric order for risk category
    fn category_order(category: &RiskCategory) -> u8 {
        match category {
            RiskCategory::Critical => 4,
            RiskCategory::High => 3,
            RiskCategory::Medium => 2,
            RiskCategory::Low => 1,
        }
    }

    /// Group vulnerabilities by risk category
    pub fn group_by_category(
        scores: &[AIVulnerabilityScore],
    ) -> HashMap<RiskCategory, Vec<&AIVulnerabilityScore>> {
        let mut groups: HashMap<RiskCategory, Vec<&AIVulnerabilityScore>> = HashMap::new();

        for score in scores {
            groups
                .entry(score.risk_category)
                .or_default()
                .push(score);
        }

        // Sort each group by score
        for group in groups.values_mut() {
            group.sort_by(|a, b| {
                b.effective_risk_score
                    .partial_cmp(&a.effective_risk_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        groups
    }

    /// Calculate priority ranks for scores
    pub fn assign_priorities(scores: &mut [AIVulnerabilityScore]) {
        // Sort first
        Self::sort_by_risk(scores);

        // Assign priorities
        for (i, score) in scores.iter_mut().enumerate() {
            score.remediation_priority = (i + 1) as u32;
        }
    }

    /// Generate summary statistics from scores
    pub fn calculate_summary(scores: &[AIVulnerabilityScore]) -> PrioritizationSummary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut total_score = 0.0;
        let mut highest = 0.0;

        for score in scores {
            match score.risk_category {
                RiskCategory::Critical => critical += 1,
                RiskCategory::High => high += 1,
                RiskCategory::Medium => medium += 1,
                RiskCategory::Low => low += 1,
            }
            total_score += score.effective_risk_score;
            if score.effective_risk_score > highest {
                highest = score.effective_risk_score;
            }
        }

        PrioritizationSummary {
            total_vulnerabilities: scores.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            average_risk_score: if scores.is_empty() {
                0.0
            } else {
                total_score / scores.len() as f64
            },
            highest_risk_score: highest,
        }
    }

    /// Get top N priority vulnerabilities
    pub fn get_top_priorities(
        scores: &[AIVulnerabilityScore],
        n: usize,
    ) -> Vec<&AIVulnerabilityScore> {
        let mut sorted: Vec<&AIVulnerabilityScore> = scores.iter().collect();
        sorted.sort_by(|a, b| {
            b.effective_risk_score
                .partial_cmp(&a.effective_risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.into_iter().take(n).collect()
    }

    /// Filter scores by minimum risk threshold
    pub fn filter_by_min_score(
        scores: &[AIVulnerabilityScore],
        min_score: f64,
    ) -> Vec<&AIVulnerabilityScore> {
        scores
            .iter()
            .filter(|s| s.effective_risk_score >= min_score)
            .collect()
    }

    /// Filter scores by risk category
    pub fn filter_by_category<'a>(
        scores: &'a [AIVulnerabilityScore],
        categories: &[RiskCategory],
    ) -> Vec<&'a AIVulnerabilityScore> {
        scores
            .iter()
            .filter(|s| categories.contains(&s.risk_category))
            .collect()
    }

    /// Calculate remediation workload estimation
    pub fn estimate_total_workload(scores: &[AIVulnerabilityScore]) -> WorkloadEstimate {
        let mut total_hours = 0u32;
        let mut requiring_downtime = 0usize;
        let mut requiring_testing = 0usize;

        for score in scores {
            total_hours += score.estimated_effort.estimated_hours;
            if score.estimated_effort.requires_downtime {
                requiring_downtime += 1;
            }
            if score.estimated_effort.requires_testing {
                requiring_testing += 1;
            }
        }

        WorkloadEstimate {
            total_vulnerabilities: scores.len(),
            total_estimated_hours: total_hours,
            estimated_days: (total_hours as f64 / 8.0).ceil() as u32,
            requiring_downtime,
            requiring_testing,
        }
    }

    /// Calculate risk reduction impact for remediation order
    pub fn calculate_risk_reduction_curve(
        scores: &[AIVulnerabilityScore],
    ) -> Vec<RiskReductionPoint> {
        let total_risk: f64 = scores.iter().map(|s| s.effective_risk_score).sum();
        let mut remaining_risk = total_risk;
        let mut cumulative_hours = 0u32;
        let mut curve = Vec::new();

        // Sort by priority
        let mut sorted: Vec<&AIVulnerabilityScore> = scores.iter().collect();
        sorted.sort_by(|a, b| a.remediation_priority.cmp(&b.remediation_priority));

        for score in sorted {
            cumulative_hours += score.estimated_effort.estimated_hours;
            remaining_risk -= score.effective_risk_score;

            let reduction_percent = if total_risk > 0.0 {
                ((total_risk - remaining_risk) / total_risk) * 100.0
            } else {
                100.0
            };

            curve.push(RiskReductionPoint {
                vulnerability_id: score.vulnerability_id.clone(),
                cumulative_hours,
                remaining_risk,
                risk_reduction_percent: reduction_percent,
            });
        }

        curve
    }
}

/// Workload estimation summary
#[derive(Debug, Clone)]
pub struct WorkloadEstimate {
    pub total_vulnerabilities: usize,
    pub total_estimated_hours: u32,
    pub estimated_days: u32,
    pub requiring_downtime: usize,
    pub requiring_testing: usize,
}

/// Point on the risk reduction curve
#[derive(Debug, Clone)]
pub struct RiskReductionPoint {
    pub vulnerability_id: String,
    pub cumulative_hours: u32,
    pub remaining_risk: f64,
    pub risk_reduction_percent: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::models::{EffortLevel, ImpactLevel, RemediationEffort};
    use chrono::Utc;

    fn create_test_score(id: &str, risk_score: f64) -> AIVulnerabilityScore {
        AIVulnerabilityScore {
            vulnerability_id: id.to_string(),
            effective_risk_score: risk_score,
            risk_category: RiskCategory::from_score(risk_score),
            factor_scores: vec![],
            remediation_priority: 0,
            estimated_effort: RemediationEffort {
                estimated_hours: 4,
                effort_level: EffortLevel::Medium,
                impact_level: ImpactLevel::Medium,
                requires_downtime: false,
                requires_testing: true,
            },
            confidence: 85.0,
            calculated_at: Utc::now(),
        }
    }

    #[test]
    fn test_sort_by_risk() {
        let mut scores = vec![
            create_test_score("vuln-1", 50.0),
            create_test_score("vuln-2", 90.0),
            create_test_score("vuln-3", 70.0),
        ];

        PrioritizationEngine::sort_by_risk(&mut scores);

        assert_eq!(scores[0].vulnerability_id, "vuln-2");
        assert_eq!(scores[1].vulnerability_id, "vuln-3");
        assert_eq!(scores[2].vulnerability_id, "vuln-1");
    }

    #[test]
    fn test_assign_priorities() {
        let mut scores = vec![
            create_test_score("vuln-1", 50.0),
            create_test_score("vuln-2", 90.0),
            create_test_score("vuln-3", 70.0),
        ];

        PrioritizationEngine::assign_priorities(&mut scores);

        assert_eq!(scores[0].remediation_priority, 1);
        assert_eq!(scores[1].remediation_priority, 2);
        assert_eq!(scores[2].remediation_priority, 3);
    }

    #[test]
    fn test_calculate_summary() {
        let scores = vec![
            create_test_score("vuln-1", 90.0),
            create_test_score("vuln-2", 70.0),
            create_test_score("vuln-3", 50.0),
            create_test_score("vuln-4", 30.0),
        ];

        let summary = PrioritizationEngine::calculate_summary(&scores);

        assert_eq!(summary.total_vulnerabilities, 4);
        assert_eq!(summary.critical_count, 1);
        assert_eq!(summary.high_count, 1);
        assert_eq!(summary.medium_count, 1);
        assert_eq!(summary.low_count, 1);
        assert_eq!(summary.highest_risk_score, 90.0);
    }

    #[test]
    fn test_group_by_category() {
        let scores = vec![
            create_test_score("vuln-1", 90.0),
            create_test_score("vuln-2", 85.0),
            create_test_score("vuln-3", 50.0),
        ];

        let groups = PrioritizationEngine::group_by_category(&scores);

        assert_eq!(groups.get(&RiskCategory::Critical).map(|v| v.len()), Some(2));
        assert_eq!(groups.get(&RiskCategory::Medium).map(|v| v.len()), Some(1));
    }

    #[test]
    fn test_get_top_priorities() {
        let scores = vec![
            create_test_score("vuln-1", 50.0),
            create_test_score("vuln-2", 90.0),
            create_test_score("vuln-3", 70.0),
        ];

        let top = PrioritizationEngine::get_top_priorities(&scores, 2);

        assert_eq!(top.len(), 2);
        assert_eq!(top[0].vulnerability_id, "vuln-2");
        assert_eq!(top[1].vulnerability_id, "vuln-3");
    }

    #[test]
    fn test_estimate_total_workload() {
        let scores = vec![
            create_test_score("vuln-1", 90.0),
            create_test_score("vuln-2", 70.0),
        ];

        let workload = PrioritizationEngine::estimate_total_workload(&scores);

        assert_eq!(workload.total_vulnerabilities, 2);
        assert_eq!(workload.total_estimated_hours, 8);
        assert_eq!(workload.estimated_days, 1);
    }
}
