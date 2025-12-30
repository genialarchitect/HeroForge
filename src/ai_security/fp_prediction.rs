//! False Positive Prediction Module
//!
//! Provides ML-based false positive prediction for security findings.
//! Uses historical FP patterns, similar finding comparison, and confidence scoring.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Prediction result for false positive analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FPPredictionResult {
    /// Likely a true positive
    TruePositive,
    /// Possibly a false positive
    PossibleFP,
    /// Likely a false positive
    LikelyFP,
    /// Uncertain - needs manual review
    Uncertain,
}

impl FPPredictionResult {
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            0..=25 => FPPredictionResult::TruePositive,
            26..=50 => FPPredictionResult::PossibleFP,
            51..=75 => FPPredictionResult::LikelyFP,
            _ => FPPredictionResult::Uncertain,
        }
    }
}

/// Features for FP prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FPFeatures {
    /// Finding title
    pub title: String,
    /// Finding type/category
    pub finding_type: String,
    /// Severity level
    pub severity: String,
    /// Source of the finding (scanner, manual, etc.)
    pub source: String,
    /// Target asset
    pub target: String,
    /// Port number if applicable
    pub port: Option<u16>,
    /// Service name if applicable
    pub service: Option<String>,
    /// Associated CVE IDs
    pub cve_ids: Vec<String>,
    /// Historical FP rate for this finding type
    pub historical_fp_rate: Option<f64>,
    /// Number of similar findings previously marked as FP
    pub similar_fp_count: u32,
    /// Number of similar findings previously confirmed as TP
    pub similar_tp_count: u32,
    /// Whether this finding has been seen on this target before
    pub seen_on_target_before: bool,
    /// Confidence of the original detection
    pub detection_confidence: Option<f64>,
    /// Asset tags/labels
    pub asset_tags: Vec<String>,
    /// Environment type (production, staging, development)
    pub environment: Option<String>,
}

impl Default for FPFeatures {
    fn default() -> Self {
        Self {
            title: String::new(),
            finding_type: String::new(),
            severity: "medium".to_string(),
            source: "unknown".to_string(),
            target: String::new(),
            port: None,
            service: None,
            cve_ids: Vec::new(),
            historical_fp_rate: None,
            similar_fp_count: 0,
            similar_tp_count: 0,
            seen_on_target_before: false,
            detection_confidence: None,
            asset_tags: Vec::new(),
            environment: None,
        }
    }
}

/// False positive prediction result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FPPrediction {
    /// Finding ID
    pub finding_id: String,
    /// Prediction result
    pub prediction: FPPredictionResult,
    /// FP probability score (0-100)
    pub fp_probability: f64,
    /// Confidence in the prediction
    pub confidence: f64,
    /// Factors contributing to the prediction
    pub factors: Vec<FPFactor>,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Similar findings that influenced the prediction
    pub similar_findings: Vec<SimilarFinding>,
    /// When prediction was made
    pub predicted_at: DateTime<Utc>,
}

/// Factor contributing to FP prediction
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FPFactor {
    pub name: String,
    pub weight: f64,
    pub contribution: f64,
    pub description: String,
}

/// Similar finding used for comparison
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SimilarFinding {
    pub finding_id: String,
    pub title: String,
    pub similarity_score: f64,
    pub was_false_positive: bool,
    pub resolution: Option<String>,
}

/// Historical FP pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FPPattern {
    pub finding_type: String,
    pub source: String,
    pub total_occurrences: u32,
    pub false_positive_count: u32,
    pub true_positive_count: u32,
    pub fp_rate: f64,
    pub common_fp_reasons: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

/// Configuration for FP predictor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FPPredictorConfig {
    /// Weight for historical FP rate
    pub historical_rate_weight: f64,
    /// Weight for similar findings
    pub similar_findings_weight: f64,
    /// Weight for source reliability
    pub source_reliability_weight: f64,
    /// Weight for detection confidence
    pub detection_confidence_weight: f64,
    /// Weight for environment factor
    pub environment_weight: f64,
    /// Minimum similar findings for reliable prediction
    pub min_similar_findings: u32,
    /// Known high-FP finding types
    pub high_fp_types: Vec<String>,
    /// Known low-FP finding types
    pub low_fp_types: Vec<String>,
}

impl Default for FPPredictorConfig {
    fn default() -> Self {
        Self {
            historical_rate_weight: 0.30,
            similar_findings_weight: 0.25,
            source_reliability_weight: 0.15,
            detection_confidence_weight: 0.15,
            environment_weight: 0.15,
            min_similar_findings: 5,
            high_fp_types: vec![
                "ssl_certificate_issue".to_string(),
                "missing_header".to_string(),
                "information_disclosure".to_string(),
                "default_page".to_string(),
                "version_disclosure".to_string(),
            ],
            low_fp_types: vec![
                "sql_injection".to_string(),
                "remote_code_execution".to_string(),
                "authentication_bypass".to_string(),
                "critical_cve".to_string(),
            ],
        }
    }
}

/// False Positive Predictor
pub struct FPPredictor {
    config: FPPredictorConfig,
    patterns: HashMap<String, FPPattern>,
    source_reliability: HashMap<String, f64>,
}

impl FPPredictor {
    /// Create a new FP predictor
    pub fn new() -> Self {
        let mut source_reliability = HashMap::new();
        // Default source reliability scores (0 = unreliable, 1 = highly reliable)
        source_reliability.insert("manual".to_string(), 0.95);
        source_reliability.insert("exploit_verified".to_string(), 0.98);
        source_reliability.insert("authenticated_scan".to_string(), 0.85);
        source_reliability.insert("nessus".to_string(), 0.80);
        source_reliability.insert("qualys".to_string(), 0.80);
        source_reliability.insert("nuclei".to_string(), 0.75);
        source_reliability.insert("zap".to_string(), 0.70);
        source_reliability.insert("nikto".to_string(), 0.60);
        source_reliability.insert("banner_grab".to_string(), 0.40);

        Self {
            config: FPPredictorConfig::default(),
            patterns: HashMap::new(),
            source_reliability,
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: FPPredictorConfig) -> Self {
        let mut predictor = Self::new();
        predictor.config = config;
        predictor
    }

    /// Update FP patterns from historical data
    pub fn update_patterns(&mut self, patterns: Vec<FPPattern>) {
        for pattern in patterns {
            let key = format!("{}:{}", pattern.finding_type, pattern.source);
            self.patterns.insert(key, pattern);
        }
    }

    /// Add a single pattern
    pub fn add_pattern(&mut self, pattern: FPPattern) {
        let key = format!("{}:{}", pattern.finding_type, pattern.source);
        self.patterns.insert(key, pattern);
    }

    /// Predict false positive probability for a finding
    pub fn predict(&self, finding_id: &str, features: &FPFeatures) -> Result<FPPrediction> {
        let mut factors = Vec::new();
        let mut total_weight = 0.0;
        let mut weighted_score = 0.0;

        // 1. Historical FP rate
        let historical_factor = self.calculate_historical_factor(features);
        factors.push(historical_factor.clone());
        weighted_score += historical_factor.contribution;
        total_weight += self.config.historical_rate_weight;

        // 2. Similar findings factor
        let similar_factor = self.calculate_similar_findings_factor(features);
        factors.push(similar_factor.clone());
        weighted_score += similar_factor.contribution;
        total_weight += self.config.similar_findings_weight;

        // 3. Source reliability (inverse - more reliable = lower FP probability)
        let source_factor = self.calculate_source_factor(features);
        factors.push(source_factor.clone());
        weighted_score += source_factor.contribution;
        total_weight += self.config.source_reliability_weight;

        // 4. Detection confidence (inverse)
        let confidence_factor = self.calculate_detection_confidence_factor(features);
        factors.push(confidence_factor.clone());
        weighted_score += confidence_factor.contribution;
        total_weight += self.config.detection_confidence_weight;

        // 5. Environment factor
        let env_factor = self.calculate_environment_factor(features);
        factors.push(env_factor.clone());
        weighted_score += env_factor.contribution;
        total_weight += self.config.environment_weight;

        // Calculate final FP probability
        let fp_probability = if total_weight > 0.0 {
            (weighted_score / total_weight).min(100.0).max(0.0)
        } else {
            50.0 // Uncertain if no factors
        };

        // Calculate confidence
        let confidence = self.calculate_prediction_confidence(features, &factors);

        // Generate recommendations
        let recommendations = self.generate_recommendations(features, fp_probability, &factors);

        // Get similar findings (mock for now - would be populated from DB)
        let similar_findings = self.get_similar_findings(features);

        Ok(FPPrediction {
            finding_id: finding_id.to_string(),
            prediction: FPPredictionResult::from_score(fp_probability),
            fp_probability,
            confidence,
            factors,
            recommendations,
            similar_findings,
            predicted_at: Utc::now(),
        })
    }

    /// Batch predict for multiple findings
    pub fn predict_batch(&self, findings: &[(String, FPFeatures)]) -> Vec<FPPrediction> {
        findings
            .iter()
            .filter_map(|(id, features)| self.predict(id, features).ok())
            .collect()
    }

    fn calculate_historical_factor(&self, features: &FPFeatures) -> FPFactor {
        let key = format!("{}:{}", features.finding_type, features.source);
        let fp_rate = if let Some(pattern) = self.patterns.get(&key) {
            pattern.fp_rate
        } else if let Some(rate) = features.historical_fp_rate {
            rate
        } else {
            // Use finding type heuristics
            if self.config.high_fp_types.iter().any(|t| features.finding_type.contains(t)) {
                0.60
            } else if self.config.low_fp_types.iter().any(|t| features.finding_type.contains(t)) {
                0.10
            } else {
                0.30 // Default middle ground
            }
        };

        FPFactor {
            name: "historical_fp_rate".to_string(),
            weight: self.config.historical_rate_weight,
            contribution: fp_rate * 100.0 * self.config.historical_rate_weight,
            description: format!("Historical FP rate: {:.1}%", fp_rate * 100.0),
        }
    }

    fn calculate_similar_findings_factor(&self, features: &FPFeatures) -> FPFactor {
        let total_similar = features.similar_fp_count + features.similar_tp_count;

        let fp_ratio = if total_similar > 0 {
            features.similar_fp_count as f64 / total_similar as f64
        } else {
            0.5 // No similar findings, uncertain
        };

        // Reduce impact if not enough similar findings
        let impact_modifier = if total_similar >= self.config.min_similar_findings {
            1.0
        } else if total_similar > 0 {
            total_similar as f64 / self.config.min_similar_findings as f64
        } else {
            0.0
        };

        FPFactor {
            name: "similar_findings".to_string(),
            weight: self.config.similar_findings_weight * impact_modifier,
            contribution: fp_ratio * 100.0 * self.config.similar_findings_weight * impact_modifier,
            description: format!(
                "{} FP / {} TP in similar findings",
                features.similar_fp_count, features.similar_tp_count
            ),
        }
    }

    fn calculate_source_factor(&self, features: &FPFeatures) -> FPFactor {
        let reliability = self.source_reliability
            .get(&features.source.to_lowercase())
            .copied()
            .unwrap_or(0.5);

        // Invert: higher reliability = lower FP probability
        let fp_contribution = (1.0 - reliability) * 100.0;

        FPFactor {
            name: "source_reliability".to_string(),
            weight: self.config.source_reliability_weight,
            contribution: fp_contribution * self.config.source_reliability_weight,
            description: format!(
                "Source '{}' reliability: {:.0}%",
                features.source,
                reliability * 100.0
            ),
        }
    }

    fn calculate_detection_confidence_factor(&self, features: &FPFeatures) -> FPFactor {
        let confidence = features.detection_confidence.unwrap_or(0.7);

        // Invert: higher detection confidence = lower FP probability
        let fp_contribution = (1.0 - confidence) * 100.0;

        FPFactor {
            name: "detection_confidence".to_string(),
            weight: self.config.detection_confidence_weight,
            contribution: fp_contribution * self.config.detection_confidence_weight,
            description: format!("Detection confidence: {:.0}%", confidence * 100.0),
        }
    }

    fn calculate_environment_factor(&self, features: &FPFeatures) -> FPFactor {
        // Development/test environments have higher FP probability
        let env_fp_rate = match features.environment.as_deref() {
            Some("development") | Some("dev") => 0.50,
            Some("staging") | Some("test") => 0.40,
            Some("production") | Some("prod") => 0.15,
            _ => 0.30, // Unknown
        };

        FPFactor {
            name: "environment".to_string(),
            weight: self.config.environment_weight,
            contribution: env_fp_rate * 100.0 * self.config.environment_weight,
            description: format!(
                "Environment '{}' FP tendency: {:.0}%",
                features.environment.as_deref().unwrap_or("unknown"),
                env_fp_rate * 100.0
            ),
        }
    }

    fn calculate_prediction_confidence(&self, features: &FPFeatures, factors: &[FPFactor]) -> f64 {
        let mut confidence: f64 = 70.0;

        // Increase confidence if we have historical data
        let key = format!("{}:{}", features.finding_type, features.source);
        if self.patterns.contains_key(&key) {
            confidence += 15.0;
        }

        // Increase confidence if we have similar findings
        let total_similar = features.similar_fp_count + features.similar_tp_count;
        if total_similar >= self.config.min_similar_findings {
            confidence += 10.0;
        } else if total_similar > 0 {
            confidence += 5.0;
        }

        // Decrease confidence if detection confidence is low
        if features.detection_confidence.unwrap_or(0.7) < 0.5 {
            confidence -= 10.0;
        }

        // Decrease confidence if factors are conflicting
        let contributions: Vec<f64> = factors.iter().map(|f| f.contribution).collect();
        if !contributions.is_empty() {
            let mean: f64 = contributions.iter().sum::<f64>() / contributions.len() as f64;
            let variance: f64 = contributions.iter()
                .map(|c| (c - mean).powi(2))
                .sum::<f64>() / contributions.len() as f64;
            let stddev = variance.sqrt();

            // High variance in factors = lower confidence
            if stddev > 20.0 {
                confidence -= 15.0;
            } else if stddev > 10.0 {
                confidence -= 5.0;
            }
        }

        confidence.min(100.0_f64).max(0.0_f64)
    }

    fn generate_recommendations(&self, features: &FPFeatures, fp_probability: f64, _factors: &[FPFactor]) -> Vec<String> {
        let mut recommendations = Vec::new();

        if fp_probability > 75.0 {
            recommendations.push("High FP probability - consider suppressing or adding to allowlist".to_string());
            recommendations.push("Review similar findings that were confirmed as false positives".to_string());
        } else if fp_probability > 50.0 {
            recommendations.push("Moderate FP probability - manual verification recommended".to_string());
            recommendations.push("Check if this is a known issue for this asset".to_string());
        } else if fp_probability < 25.0 {
            recommendations.push("Low FP probability - prioritize investigation".to_string());
            if !features.cve_ids.is_empty() {
                recommendations.push(format!("Associated CVEs: {}", features.cve_ids.join(", ")));
            }
        }

        // Environment-specific recommendations
        if features.environment.as_deref() == Some("production") && fp_probability < 50.0 {
            recommendations.push("Production asset - escalate if confirmed".to_string());
        }

        // Source-specific recommendations
        let reliability = self.source_reliability
            .get(&features.source.to_lowercase())
            .copied()
            .unwrap_or(0.5);

        if reliability < 0.5 {
            recommendations.push(format!(
                "Source '{}' has low reliability - consider using additional verification",
                features.source
            ));
        }

        recommendations
    }

    fn get_similar_findings(&self, _features: &FPFeatures) -> Vec<SimilarFinding> {
        // In a real implementation, this would query the database for similar findings
        // For now, return an empty vector (populated by the caller from DB)
        Vec::new()
    }
}

impl Default for FPPredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_fp_prediction() {
        let predictor = FPPredictor::new();

        let features = FPFeatures {
            finding_type: "missing_header".to_string(),
            source: "banner_grab".to_string(),
            similar_fp_count: 10,
            similar_tp_count: 2,
            environment: Some("development".to_string()),
            ..Default::default()
        };

        let prediction = predictor.predict("finding-1", &features).unwrap();
        assert!(prediction.fp_probability > 50.0);
        assert!(matches!(
            prediction.prediction,
            FPPredictionResult::PossibleFP | FPPredictionResult::LikelyFP
        ));
    }

    #[test]
    fn test_low_fp_prediction() {
        let predictor = FPPredictor::new();

        let features = FPFeatures {
            finding_type: "sql_injection".to_string(),
            source: "manual".to_string(),
            similar_fp_count: 1,
            similar_tp_count: 20,
            environment: Some("production".to_string()),
            detection_confidence: Some(0.95),
            cve_ids: vec!["CVE-2023-1234".to_string()],
            ..Default::default()
        };

        let prediction = predictor.predict("finding-2", &features).unwrap();
        assert!(prediction.fp_probability < 40.0);
        assert!(matches!(
            prediction.prediction,
            FPPredictionResult::TruePositive | FPPredictionResult::PossibleFP
        ));
    }

    #[test]
    fn test_prediction_with_pattern() {
        let mut predictor = FPPredictor::new();

        // Add historical pattern
        predictor.add_pattern(FPPattern {
            finding_type: "test_finding".to_string(),
            source: "test_scanner".to_string(),
            total_occurrences: 100,
            false_positive_count: 80,
            true_positive_count: 20,
            fp_rate: 0.80,
            common_fp_reasons: vec!["test environment".to_string()],
            last_updated: Utc::now(),
        });

        let features = FPFeatures {
            finding_type: "test_finding".to_string(),
            source: "test_scanner".to_string(),
            ..Default::default()
        };

        let prediction = predictor.predict("finding-3", &features).unwrap();
        // Should reflect the 80% historical FP rate
        assert!(prediction.fp_probability > 40.0);
    }
}
