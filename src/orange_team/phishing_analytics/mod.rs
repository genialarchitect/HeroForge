//! Phishing analytics module - Susceptibility scoring and department risk analysis

use crate::orange_team::types::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Phishing analytics engine
pub struct PhishingAnalytics {
    user_scores: HashMap<Uuid, PhishingSusceptibility>,
    department_stats: HashMap<String, DepartmentPhishingStats>,
}

impl PhishingAnalytics {
    /// Create a new phishing analytics engine
    pub fn new() -> Self {
        Self {
            user_scores: HashMap::new(),
            department_stats: HashMap::new(),
        }
    }

    /// Update user susceptibility score
    pub fn update_user_score(
        &mut self,
        user_id: Uuid,
        click_rate: f64,
        report_rate: f64,
        training_completion: f64,
    ) -> PhishingSusceptibility {
        // Calculate composite score (lower is better)
        let score = calculate_susceptibility_score(click_rate, report_rate, training_completion);
        let risk_level = score_to_risk_level(score);

        let susceptibility = PhishingSusceptibility {
            id: Uuid::new_v4(),
            user_id,
            score,
            click_rate,
            report_rate,
            training_completion_rate: training_completion,
            last_phished_at: None,
            last_trained_at: None,
            risk_level,
            updated_at: Utc::now(),
        };

        self.user_scores.insert(user_id, susceptibility.clone());
        susceptibility
    }

    /// Record a phishing click
    pub fn record_click(&mut self, user_id: Uuid, campaign_id: Option<Uuid>) {
        if let Some(score) = self.user_scores.get_mut(&user_id) {
            score.last_phished_at = Some(Utc::now());
            // Increase click rate slightly
            score.click_rate = (score.click_rate + 0.1).min(1.0);
            score.score = calculate_susceptibility_score(
                score.click_rate,
                score.report_rate,
                score.training_completion_rate,
            );
            score.risk_level = score_to_risk_level(score.score);
            score.updated_at = Utc::now();
        }
    }

    /// Record a phishing report
    pub fn record_report(&mut self, user_id: Uuid, campaign_id: Option<Uuid>) {
        if let Some(score) = self.user_scores.get_mut(&user_id) {
            // Increase report rate
            score.report_rate = (score.report_rate + 0.1).min(1.0);
            score.score = calculate_susceptibility_score(
                score.click_rate,
                score.report_rate,
                score.training_completion_rate,
            );
            score.risk_level = score_to_risk_level(score.score);
            score.updated_at = Utc::now();
        }
    }

    /// Record training completion
    pub fn record_training(&mut self, user_id: Uuid) {
        if let Some(score) = self.user_scores.get_mut(&user_id) {
            score.last_trained_at = Some(Utc::now());
            score.training_completion_rate = (score.training_completion_rate + 0.1).min(1.0);
            score.score = calculate_susceptibility_score(
                score.click_rate,
                score.report_rate,
                score.training_completion_rate,
            );
            score.risk_level = score_to_risk_level(score.score);
            score.updated_at = Utc::now();
        }
    }

    /// Get user's susceptibility score
    pub fn get_user_score(&self, user_id: Uuid) -> Option<&PhishingSusceptibility> {
        self.user_scores.get(&user_id)
    }

    /// Get high-risk users
    pub fn get_high_risk_users(&self) -> Vec<&PhishingSusceptibility> {
        self.user_scores
            .values()
            .filter(|s| matches!(s.risk_level, RiskLevel::High | RiskLevel::Critical))
            .collect()
    }

    /// Update department statistics
    pub fn update_department_stats(
        &mut self,
        department: &str,
        user_ids: &[Uuid],
    ) -> Option<DepartmentPhishingStats> {
        let users: Vec<_> = user_ids
            .iter()
            .filter_map(|id| self.user_scores.get(id))
            .collect();

        if users.is_empty() {
            return None;
        }

        let user_count = users.len() as u32;
        let avg_susceptibility = users.iter().map(|u| u.score).sum::<f64>() / users.len() as f64;
        let total_clicks = 0u32; // Would come from campaign data
        let total_reports = 0u32;
        let campaigns_count = 0u32;

        let risk_level = score_to_risk_level(avg_susceptibility);

        let stats = DepartmentPhishingStats {
            id: Uuid::new_v4(),
            department: department.to_string(),
            user_count,
            avg_susceptibility,
            total_clicks,
            total_reports,
            campaigns_count,
            risk_level,
            updated_at: Utc::now(),
        };

        self.department_stats.insert(department.to_string(), stats.clone());
        Some(stats)
    }

    /// Get department statistics
    pub fn get_department_stats(&self, department: &str) -> Option<&DepartmentPhishingStats> {
        self.department_stats.get(department)
    }

    /// Get all department statistics
    pub fn get_all_department_stats(&self) -> Vec<&DepartmentPhishingStats> {
        self.department_stats.values().collect()
    }

    /// Get trend data for a user
    pub fn get_user_trend(&self, user_id: Uuid) -> Option<SusceptibilityTrend> {
        self.user_scores.get(&user_id).map(|score| SusceptibilityTrend {
            user_id,
            current_score: score.score,
            current_risk_level: score.risk_level,
            trend: TrendDirection::Stable, // Would need historical data
            change_percent: 0.0,
        })
    }
}

impl Default for PhishingAnalytics {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate susceptibility score from metrics
fn calculate_susceptibility_score(click_rate: f64, report_rate: f64, training_completion: f64) -> f64 {
    // Score from 0-100, higher = more susceptible
    // Click rate increases score, report rate and training decrease it
    let base_score = click_rate * 100.0;
    let report_reduction = report_rate * 30.0;
    let training_reduction = training_completion * 20.0;

    (base_score - report_reduction - training_reduction).max(0.0).min(100.0)
}

/// Convert score to risk level
fn score_to_risk_level(score: f64) -> RiskLevel {
    match score as u32 {
        0..=25 => RiskLevel::Low,
        26..=50 => RiskLevel::Medium,
        51..=75 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

/// Susceptibility trend data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SusceptibilityTrend {
    pub user_id: Uuid,
    pub current_score: f64,
    pub current_risk_level: RiskLevel,
    pub trend: TrendDirection,
    pub change_percent: f64,
}

/// Trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Improving,
    Stable,
    Worsening,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_susceptibility_calculation() {
        let score = calculate_susceptibility_score(0.3, 0.5, 0.8);
        assert!(score < 30.0); // Low susceptibility
    }

    #[test]
    fn test_risk_level() {
        assert_eq!(score_to_risk_level(20.0), RiskLevel::Low);
        assert_eq!(score_to_risk_level(40.0), RiskLevel::Medium);
        assert_eq!(score_to_risk_level(60.0), RiskLevel::High);
        assert_eq!(score_to_risk_level(80.0), RiskLevel::Critical);
    }
}
