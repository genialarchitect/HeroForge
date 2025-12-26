// Risk Management Module
//
// Provides comprehensive risk management capabilities:
// - Risk register management
// - Risk assessments
// - FAIR (Factor Analysis of Information Risk) methodology
// - Risk treatment planning
// - Risk reporting and heatmaps

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{
    AssessmentType, FairAnalysis, FrequencyRange, MoneyRange, Percentage, Risk,
    RiskAssessment, RiskCategory, RiskLevel, RiskRating, RiskStatus, TreatmentStrategy,
};

/// Risk management engine
pub struct RiskManager {
    risks: HashMap<String, Risk>,
    assessments: HashMap<String, Vec<RiskAssessment>>,
    risk_counter: u32,
}

impl RiskManager {
    pub fn new() -> Self {
        Self {
            risks: HashMap::new(),
            assessments: HashMap::new(),
            risk_counter: 0,
        }
    }

    /// Create a new risk
    pub fn create_risk(
        &mut self,
        title: String,
        description: String,
        category: RiskCategory,
        owner_id: String,
        inherent_likelihood: u8,
        inherent_impact: u8,
    ) -> Risk {
        self.risk_counter += 1;
        let id = uuid::Uuid::new_v4().to_string();
        let risk_id = format!("RISK-{:04}", self.risk_counter);
        let now = Utc::now();

        let inherent_risk_score = inherent_likelihood * inherent_impact;

        let risk = Risk {
            id: id.clone(),
            risk_id,
            title,
            description,
            category,
            status: RiskStatus::Open,
            source: None,
            owner_id,
            inherent_likelihood,
            inherent_impact,
            inherent_risk_score,
            residual_likelihood: None,
            residual_impact: None,
            residual_risk_score: None,
            fair_analysis: None,
            annualized_loss_expectancy: None,
            treatment_strategy: None,
            treatment_plan: None,
            target_date: None,
            related_controls: Vec::new(),
            related_assets: Vec::new(),
            tags: Vec::new(),
            last_assessed_at: None,
            next_review_date: None,
            created_at: now,
            updated_at: now,
        };

        self.risks.insert(id, risk.clone());
        risk
    }

    /// Perform a risk assessment
    pub fn assess_risk(
        &mut self,
        risk_id: &str,
        assessor_id: String,
        assessment_type: AssessmentType,
        likelihood: u8,
        impact: u8,
        likelihood_rationale: Option<String>,
        impact_rationale: Option<String>,
        threats: Vec<String>,
        vulnerabilities: Vec<String>,
        recommendations: Option<String>,
    ) -> Result<RiskAssessment, RiskError> {
        let risk = self.risks.get_mut(risk_id).ok_or(RiskError::NotFound)?;

        let risk_score = likelihood * impact;
        let now = Utc::now();

        let assessment = RiskAssessment {
            id: uuid::Uuid::new_v4().to_string(),
            risk_id: risk_id.to_string(),
            assessment_type,
            assessor_id,
            likelihood,
            impact,
            risk_score,
            likelihood_rationale,
            impact_rationale,
            threats_identified: threats,
            vulnerabilities_identified: vulnerabilities,
            recommendations,
            created_at: now,
        };

        // Update residual risk if this is a re-assessment
        risk.residual_likelihood = Some(likelihood);
        risk.residual_impact = Some(impact);
        risk.residual_risk_score = Some(risk_score);
        risk.last_assessed_at = Some(now);
        risk.updated_at = now;

        self.assessments
            .entry(risk_id.to_string())
            .or_default()
            .push(assessment.clone());

        Ok(assessment)
    }

    /// Perform FAIR analysis
    pub fn perform_fair_analysis(
        &mut self,
        risk_id: &str,
        threat_event_frequency: FrequencyRange,
        vulnerability: f64,
        loss_magnitude: MoneyRange,
        confidence_level: f64,
    ) -> Result<FairAnalysis, RiskError> {
        let risk = self.risks.get_mut(risk_id).ok_or(RiskError::NotFound)?;

        // Calculate Loss Event Frequency (LEF) = TEF × Vuln
        let lef_min = threat_event_frequency.min * vulnerability;
        let lef_likely = threat_event_frequency.most_likely * vulnerability;
        let lef_max = threat_event_frequency.max * vulnerability;

        // Calculate Annualized Loss Expectancy using PERT distribution approximation
        // ALE = LEF × Loss Magnitude (using most likely values for simplicity)
        let ale = lef_likely * loss_magnitude.most_likely;

        let analysis = FairAnalysis {
            threat_event_frequency,
            vulnerability: Percentage { value: vulnerability },
            loss_magnitude,
            annualized_loss_expectancy: ale,
            confidence_level: Percentage { value: confidence_level },
        };

        risk.fair_analysis = Some(analysis.clone());
        risk.annualized_loss_expectancy = Some(ale);
        risk.updated_at = Utc::now();

        Ok(analysis)
    }

    /// Set treatment strategy
    pub fn set_treatment(
        &mut self,
        risk_id: &str,
        strategy: TreatmentStrategy,
        plan: Option<String>,
        target_date: Option<NaiveDate>,
    ) -> Result<(), RiskError> {
        let risk = self.risks.get_mut(risk_id).ok_or(RiskError::NotFound)?;

        risk.treatment_strategy = Some(strategy.clone());
        risk.treatment_plan = plan;
        risk.target_date = target_date;
        risk.updated_at = Utc::now();

        // Update status based on strategy
        risk.status = match strategy {
            TreatmentStrategy::Mitigate => RiskStatus::Mitigating,
            TreatmentStrategy::Accept => RiskStatus::Accepted,
            TreatmentStrategy::Transfer => RiskStatus::Transferred,
            TreatmentStrategy::Avoid => RiskStatus::Closed,
        };

        Ok(())
    }

    /// Link controls to a risk
    pub fn link_controls(&mut self, risk_id: &str, control_ids: Vec<String>) -> Result<(), RiskError> {
        let risk = self.risks.get_mut(risk_id).ok_or(RiskError::NotFound)?;
        risk.related_controls.extend(control_ids);
        risk.related_controls.sort();
        risk.related_controls.dedup();
        risk.updated_at = Utc::now();
        Ok(())
    }

    /// Link assets to a risk
    pub fn link_assets(&mut self, risk_id: &str, asset_ids: Vec<String>) -> Result<(), RiskError> {
        let risk = self.risks.get_mut(risk_id).ok_or(RiskError::NotFound)?;
        risk.related_assets.extend(asset_ids);
        risk.related_assets.sort();
        risk.related_assets.dedup();
        risk.updated_at = Utc::now();
        Ok(())
    }

    /// Close a risk
    pub fn close_risk(&mut self, risk_id: &str) -> Result<(), RiskError> {
        let risk = self.risks.get_mut(risk_id).ok_or(RiskError::NotFound)?;
        risk.status = RiskStatus::Closed;
        risk.updated_at = Utc::now();
        Ok(())
    }

    /// Get risk by ID
    pub fn get_risk(&self, risk_id: &str) -> Option<&Risk> {
        self.risks.get(risk_id)
    }

    /// List all risks
    pub fn list_risks(&self, category: Option<RiskCategory>, status: Option<RiskStatus>) -> Vec<&Risk> {
        self.risks
            .values()
            .filter(|r| {
                category.as_ref().map_or(true, |c| &r.category == c)
                    && status.as_ref().map_or(true, |s| &r.status == s)
            })
            .collect()
    }

    /// Get assessments for a risk
    pub fn get_assessments(&self, risk_id: &str) -> Vec<&RiskAssessment> {
        self.assessments
            .get(risk_id)
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }

    /// Generate risk heatmap data
    pub fn generate_heatmap(&self) -> RiskHeatmap {
        let mut cells: HashMap<(u8, u8), Vec<String>> = HashMap::new();

        for risk in self.risks.values() {
            if risk.status == RiskStatus::Closed {
                continue;
            }

            let likelihood = risk.residual_likelihood.unwrap_or(risk.inherent_likelihood);
            let impact = risk.residual_impact.unwrap_or(risk.inherent_impact);

            cells
                .entry((likelihood, impact))
                .or_default()
                .push(risk.risk_id.clone());
        }

        RiskHeatmap { cells }
    }

    /// Get risk statistics
    pub fn get_statistics(&self) -> RiskStatistics {
        let mut total = 0;
        let mut open = 0;
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut by_category: HashMap<String, u32> = HashMap::new();
        let mut total_score = 0u32;
        let mut total_ale = 0.0;

        for risk in self.risks.values() {
            total += 1;

            if risk.status != RiskStatus::Closed {
                open += 1;
                let score = risk.residual_risk_score.unwrap_or(risk.inherent_risk_score);
                total_score += score as u32;

                let level = RiskRating::calculate(
                    risk.residual_likelihood.unwrap_or(risk.inherent_likelihood),
                    risk.residual_impact.unwrap_or(risk.inherent_impact),
                ).level;

                match level {
                    RiskLevel::Critical => critical += 1,
                    RiskLevel::High => high += 1,
                    RiskLevel::Medium => medium += 1,
                    RiskLevel::Low => low += 1,
                }
            }

            *by_category.entry(risk.category.to_string()).or_insert(0) += 1;

            if let Some(ale) = risk.annualized_loss_expectancy {
                total_ale += ale;
            }
        }

        let avg_score = if open > 0 {
            total_score as f64 / open as f64
        } else {
            0.0
        };

        RiskStatistics {
            total_risks: total,
            open_risks: open,
            critical_risks: critical,
            high_risks: high,
            medium_risks: medium,
            low_risks: low,
            risks_by_category: by_category,
            avg_risk_score: avg_score,
            total_ale,
        }
    }

    /// Get risks due for review
    pub fn get_risks_due_review(&self) -> Vec<&Risk> {
        let today = Utc::now().date_naive();
        self.risks
            .values()
            .filter(|r| {
                r.status != RiskStatus::Closed
                    && r.next_review_date.map_or(false, |d| d <= today)
            })
            .collect()
    }
}

impl Default for RiskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskHeatmap {
    /// Key: (likelihood, impact), Value: list of risk IDs
    pub cells: HashMap<(u8, u8), Vec<String>>,
}

impl RiskHeatmap {
    pub fn get_cell_color(&self, likelihood: u8, impact: u8) -> &str {
        let score = likelihood * impact;
        match score {
            1..=4 => "green",
            5..=9 => "yellow",
            10..=16 => "orange",
            _ => "red",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskStatistics {
    pub total_risks: u32,
    pub open_risks: u32,
    pub critical_risks: u32,
    pub high_risks: u32,
    pub medium_risks: u32,
    pub low_risks: u32,
    pub risks_by_category: HashMap<String, u32>,
    pub avg_risk_score: f64,
    pub total_ale: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskError {
    NotFound,
    ValidationError(String),
    InvalidRating(String),
}

impl std::fmt::Display for RiskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Risk not found"),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            Self::InvalidRating(msg) => write!(f, "Invalid rating: {}", msg),
        }
    }
}

impl std::error::Error for RiskError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_creation_and_assessment() {
        let mut manager = RiskManager::new();

        // Create risk
        let risk = manager.create_risk(
            "Data Breach Risk".to_string(),
            "Risk of unauthorized access to customer data".to_string(),
            RiskCategory::Cyber,
            "user-1".to_string(),
            4, // High likelihood
            5, // Critical impact
        );

        assert_eq!(risk.inherent_risk_score, 20);
        assert_eq!(risk.status, RiskStatus::Open);

        // Perform assessment
        let assessment = manager.assess_risk(
            &risk.id,
            "assessor-1".to_string(),
            AssessmentType::Initial,
            3, // Reduced likelihood after controls
            5, // Same impact
            Some("Implemented additional controls".to_string()),
            None,
            vec!["External attackers".to_string()],
            vec!["Weak authentication".to_string()],
            Some("Implement MFA".to_string()),
        ).unwrap();

        assert_eq!(assessment.risk_score, 15);

        // Check residual risk was updated
        let updated_risk = manager.get_risk(&risk.id).unwrap();
        assert_eq!(updated_risk.residual_risk_score, Some(15));
    }

    #[test]
    fn test_fair_analysis() {
        let mut manager = RiskManager::new();

        let risk = manager.create_risk(
            "Ransomware Risk".to_string(),
            "Risk of ransomware attack".to_string(),
            RiskCategory::Cyber,
            "user-1".to_string(),
            3,
            4,
        );

        let analysis = manager.perform_fair_analysis(
            &risk.id,
            FrequencyRange { min: 0.1, most_likely: 0.5, max: 2.0 },
            0.3, // 30% vulnerability
            MoneyRange {
                min: 100000.0,
                most_likely: 500000.0,
                max: 2000000.0,
                currency: "USD".to_string(),
            },
            0.8, // 80% confidence
        ).unwrap();

        // ALE = LEF × Loss Magnitude = (0.5 × 0.3) × 500000 = 75000
        assert!((analysis.annualized_loss_expectancy - 75000.0).abs() < 0.01);
    }

    #[test]
    fn test_risk_treatment() {
        let mut manager = RiskManager::new();

        let risk = manager.create_risk(
            "Test Risk".to_string(),
            "Description".to_string(),
            RiskCategory::Operational,
            "user-1".to_string(),
            2,
            3,
        );

        manager.set_treatment(
            &risk.id,
            TreatmentStrategy::Mitigate,
            Some("Implement controls".to_string()),
            Some(NaiveDate::from_ymd_opt(2025, 6, 30).unwrap()),
        ).unwrap();

        let updated = manager.get_risk(&risk.id).unwrap();
        assert_eq!(updated.status, RiskStatus::Mitigating);
        assert_eq!(updated.treatment_strategy, Some(TreatmentStrategy::Mitigate));
    }
}
