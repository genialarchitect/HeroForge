//! ML-based Alert Prioritization
//!
//! This module provides machine learning-based alert prioritization using
//! rule-based scoring initially, with the infrastructure ready for ML model integration.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Alert priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AlertPriority {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl AlertPriority {
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            90..=100 => AlertPriority::Critical,
            70..=89 => AlertPriority::High,
            40..=69 => AlertPriority::Medium,
            20..=39 => AlertPriority::Low,
            _ => AlertPriority::Info,
        }
    }

    pub fn numeric_value(&self) -> u32 {
        match self {
            AlertPriority::Critical => 10,
            AlertPriority::High => 7,
            AlertPriority::Medium => 4,
            AlertPriority::Low => 1,
            AlertPriority::Info => 0,
        }
    }
}

/// Features extracted from an alert for scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFeatures {
    /// Original severity from the alert source
    pub severity: String,
    /// Source type (SIEM, scanner, IDS, etc.)
    pub source_type: String,
    /// Target asset criticality (0-100)
    pub asset_criticality: f64,
    /// Is the target internet-facing?
    pub internet_facing: bool,
    /// Historical alert count for this type
    pub historical_count: u32,
    /// Known exploit availability
    pub exploit_available: bool,
    /// Associated CVE IDs
    pub cve_ids: Vec<String>,
    /// Affected service name
    pub service_name: Option<String>,
    /// Alert age in minutes
    pub age_minutes: i64,
    /// Number of similar alerts in last 24h
    pub similar_alerts_24h: u32,
    /// Whether alert matches known attack patterns
    pub matches_attack_pattern: bool,
    /// Business hours factor (0-1)
    pub business_hours_factor: f64,
    /// Geographic risk factor (0-1)
    pub geo_risk_factor: f64,
}

impl Default for AlertFeatures {
    fn default() -> Self {
        Self {
            severity: "medium".to_string(),
            source_type: "unknown".to_string(),
            asset_criticality: 50.0,
            internet_facing: false,
            historical_count: 0,
            exploit_available: false,
            cve_ids: Vec::new(),
            service_name: None,
            age_minutes: 0,
            similar_alerts_24h: 0,
            matches_attack_pattern: false,
            business_hours_factor: 1.0,
            geo_risk_factor: 0.5,
        }
    }
}

/// Alert priority score result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AlertPriorityScore {
    /// Alert ID
    pub alert_id: String,
    /// Calculated priority level
    pub priority: AlertPriority,
    /// Numeric score (0-100)
    pub score: f64,
    /// Factor breakdown
    pub factors: HashMap<String, FactorContribution>,
    /// Confidence in the score (0-100)
    pub confidence: f64,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// When the score was calculated
    pub calculated_at: DateTime<Utc>,
}

/// Contribution of a factor to the final score
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FactorContribution {
    /// Raw value of the factor
    pub raw_value: f64,
    /// Normalized value (0-100)
    pub normalized: f64,
    /// Weight applied
    pub weight: f64,
    /// Contribution to final score
    pub contribution: f64,
}

/// Configuration for alert priority scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPriorityConfig {
    /// Weight for base severity
    pub severity_weight: f64,
    /// Weight for asset criticality
    pub asset_criticality_weight: f64,
    /// Weight for exploit availability
    pub exploit_weight: f64,
    /// Weight for internet exposure
    pub exposure_weight: f64,
    /// Weight for attack pattern match
    pub attack_pattern_weight: f64,
    /// Weight for alert freshness
    pub freshness_weight: f64,
    /// Weight for alert volume (inverse)
    pub volume_weight: f64,
}

impl Default for AlertPriorityConfig {
    fn default() -> Self {
        Self {
            severity_weight: 0.25,
            asset_criticality_weight: 0.20,
            exploit_weight: 0.15,
            exposure_weight: 0.15,
            attack_pattern_weight: 0.10,
            freshness_weight: 0.10,
            volume_weight: 0.05,
        }
    }
}

/// Alert Priority Scorer
pub struct AlertPriorityScorer {
    config: AlertPriorityConfig,
}

impl AlertPriorityScorer {
    /// Create a new scorer with default configuration
    pub fn new() -> Self {
        Self {
            config: AlertPriorityConfig::default(),
        }
    }

    /// Create a scorer with custom configuration
    pub fn with_config(config: AlertPriorityConfig) -> Self {
        Self { config }
    }

    /// Calculate priority score for an alert
    pub fn calculate_score(&self, alert_id: &str, features: &AlertFeatures) -> Result<AlertPriorityScore> {
        let mut factors = HashMap::new();

        // 1. Base severity score
        let severity_score = self.severity_to_score(&features.severity);
        factors.insert("severity".to_string(), FactorContribution {
            raw_value: severity_score,
            normalized: severity_score,
            weight: self.config.severity_weight,
            contribution: severity_score * self.config.severity_weight,
        });

        // 2. Asset criticality
        let asset_score = features.asset_criticality;
        factors.insert("asset_criticality".to_string(), FactorContribution {
            raw_value: asset_score,
            normalized: asset_score,
            weight: self.config.asset_criticality_weight,
            contribution: asset_score * self.config.asset_criticality_weight,
        });

        // 3. Exploit availability
        let exploit_score = if features.exploit_available { 100.0 } else { 0.0 };
        factors.insert("exploit_available".to_string(), FactorContribution {
            raw_value: if features.exploit_available { 1.0 } else { 0.0 },
            normalized: exploit_score,
            weight: self.config.exploit_weight,
            contribution: exploit_score * self.config.exploit_weight,
        });

        // 4. Internet exposure
        let exposure_score = if features.internet_facing { 100.0 } else { 30.0 };
        factors.insert("internet_exposure".to_string(), FactorContribution {
            raw_value: if features.internet_facing { 1.0 } else { 0.0 },
            normalized: exposure_score,
            weight: self.config.exposure_weight,
            contribution: exposure_score * self.config.exposure_weight,
        });

        // 5. Attack pattern match
        let pattern_score = if features.matches_attack_pattern { 100.0 } else { 0.0 };
        factors.insert("attack_pattern".to_string(), FactorContribution {
            raw_value: if features.matches_attack_pattern { 1.0 } else { 0.0 },
            normalized: pattern_score,
            weight: self.config.attack_pattern_weight,
            contribution: pattern_score * self.config.attack_pattern_weight,
        });

        // 6. Freshness (newer alerts get higher scores)
        let freshness_score = self.calculate_freshness_score(features.age_minutes);
        factors.insert("freshness".to_string(), FactorContribution {
            raw_value: features.age_minutes as f64,
            normalized: freshness_score,
            weight: self.config.freshness_weight,
            contribution: freshness_score * self.config.freshness_weight,
        });

        // 7. Volume factor (many similar alerts may indicate noise)
        let volume_score = self.calculate_volume_score(features.similar_alerts_24h);
        factors.insert("volume".to_string(), FactorContribution {
            raw_value: features.similar_alerts_24h as f64,
            normalized: volume_score,
            weight: self.config.volume_weight,
            contribution: volume_score * self.config.volume_weight,
        });

        // Calculate weighted score
        let total_weight = self.config.severity_weight
            + self.config.asset_criticality_weight
            + self.config.exploit_weight
            + self.config.exposure_weight
            + self.config.attack_pattern_weight
            + self.config.freshness_weight
            + self.config.volume_weight;

        let weighted_sum: f64 = factors.values().map(|f| f.contribution).sum();
        let final_score = (weighted_sum / total_weight).min(100.0).max(0.0);

        // Calculate confidence
        let confidence = self.calculate_confidence(features);

        // Generate recommendations
        let recommendations = self.generate_recommendations(features, final_score);

        Ok(AlertPriorityScore {
            alert_id: alert_id.to_string(),
            priority: AlertPriority::from_score(final_score),
            score: final_score,
            factors,
            confidence,
            recommendations,
            calculated_at: Utc::now(),
        })
    }

    /// Batch score multiple alerts
    pub fn calculate_scores(&self, alerts: &[(String, AlertFeatures)]) -> Vec<AlertPriorityScore> {
        alerts
            .iter()
            .filter_map(|(id, features)| self.calculate_score(id, features).ok())
            .collect()
    }

    /// Convert severity string to numeric score
    fn severity_to_score(&self, severity: &str) -> f64 {
        match severity.to_lowercase().as_str() {
            "critical" => 100.0,
            "high" => 80.0,
            "medium" => 50.0,
            "low" => 25.0,
            "info" | "informational" => 10.0,
            _ => 50.0,
        }
    }

    /// Calculate freshness score based on alert age
    fn calculate_freshness_score(&self, age_minutes: i64) -> f64 {
        // Newer alerts get higher scores
        // 0 minutes = 100, 60 minutes = 75, 24 hours = 25, older = 10
        match age_minutes {
            0..=5 => 100.0,
            6..=30 => 90.0,
            31..=60 => 75.0,
            61..=360 => 50.0,
            361..=1440 => 25.0,
            _ => 10.0,
        }
    }

    /// Calculate volume score (inverse - high volume may indicate noise)
    fn calculate_volume_score(&self, similar_count: u32) -> f64 {
        // Few similar alerts = more important, many = potential noise
        match similar_count {
            0..=2 => 100.0,
            3..=10 => 75.0,
            11..=50 => 50.0,
            51..=100 => 25.0,
            _ => 10.0, // Likely noise
        }
    }

    /// Calculate confidence in the score
    fn calculate_confidence(&self, features: &AlertFeatures) -> f64 {
        let mut confidence: f64 = 80.0;

        // Reduce confidence for unknown sources
        if features.source_type == "unknown" {
            confidence -= 20.0;
        }

        // Increase confidence if CVEs are available
        if !features.cve_ids.is_empty() {
            confidence += 10.0;
        }

        // Reduce confidence for very new alerts (less context)
        if features.age_minutes < 5 {
            confidence -= 10.0;
        }

        // Reduce confidence if many similar alerts (unclear pattern)
        if features.similar_alerts_24h > 100 {
            confidence -= 15.0;
        }

        confidence.min(100.0_f64).max(0.0_f64)
    }

    /// Generate recommendations based on features and score
    fn generate_recommendations(&self, features: &AlertFeatures, score: f64) -> Vec<String> {
        let mut recommendations = Vec::new();

        if score >= 90.0 {
            recommendations.push("Immediate investigation required".to_string());
            recommendations.push("Consider isolating affected systems".to_string());
        } else if score >= 70.0 {
            recommendations.push("Prioritize investigation within 1 hour".to_string());
        } else if score >= 40.0 {
            recommendations.push("Schedule investigation within 24 hours".to_string());
        }

        if features.exploit_available {
            recommendations.push("Known exploit exists - patch immediately".to_string());
        }

        if features.internet_facing {
            recommendations.push("Internet-facing asset - verify firewall rules".to_string());
        }

        if features.matches_attack_pattern {
            recommendations.push("Matches known attack pattern - check for lateral movement".to_string());
        }

        if features.similar_alerts_24h > 50 {
            recommendations.push("High alert volume - consider tuning detection rules".to_string());
        }

        if !features.cve_ids.is_empty() {
            let cve_str = features.cve_ids.join(", ");
            recommendations.push(format!("Research CVEs: {}", cve_str));
        }

        recommendations
    }
}

impl Default for AlertPriorityScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_scoring() {
        let scorer = AlertPriorityScorer::new();

        let features = AlertFeatures {
            severity: "critical".to_string(),
            source_type: "siem".to_string(),
            asset_criticality: 100.0,
            internet_facing: true,
            exploit_available: true,
            ..Default::default()
        };

        let score = scorer.calculate_score("test-1", &features).unwrap();
        assert!(score.score >= 80.0);
        assert_eq!(score.priority, AlertPriority::Critical);
    }

    #[test]
    fn test_low_priority_alert() {
        let scorer = AlertPriorityScorer::new();

        let features = AlertFeatures {
            severity: "info".to_string(),
            source_type: "scanner".to_string(),
            asset_criticality: 10.0,
            internet_facing: false,
            similar_alerts_24h: 200,
            ..Default::default()
        };

        let score = scorer.calculate_score("test-2", &features).unwrap();
        assert!(score.score < 40.0);
        assert!(matches!(score.priority, AlertPriority::Low | AlertPriority::Info));
    }

    #[test]
    fn test_freshness_scoring() {
        let scorer = AlertPriorityScorer::new();

        // Very fresh alert
        assert!(scorer.calculate_freshness_score(0) > scorer.calculate_freshness_score(60));
        // Old alert
        assert!(scorer.calculate_freshness_score(60) > scorer.calculate_freshness_score(1500));
    }
}
