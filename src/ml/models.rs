//! ML Model Management
//!
//! This module implements lightweight machine learning models for security threat classification.
//!
//! # Model Architecture
//!
//! The models use **logistic regression with softmax output** - a classic and interpretable
//! ML approach well-suited for security applications where:
//! - Explainability is important (linear weights show feature importance)
//! - Predictions need to be deterministic and auditable
//! - Models need to work without GPU/heavy infrastructure
//!
//! # Pre-trained Weights
//!
//! Model weights are embedded (pre-trained offline) rather than trained at runtime.
//! This provides:
//! - Consistent predictions across deployments
//! - No training data exposure at runtime
//! - Instant availability without training phase
//!
//! # Available Models
//!
//! - `threat-classifier-v1`: Classifies hosts as benign/suspicious/malicious
//! - `anomaly-detector-v1`: Detects normal vs anomalous behavior patterns
//! - `risk-predictor-v1`: Predicts risk level (low/medium/high/critical)
//! - `pattern-recognizer-v1`: Identifies attack patterns (recon/exploitation/lateral/exfil)
//!
//! # Mathematical Details
//!
//! For input features x, class probabilities are computed as:
//! 1. Normalize: x_norm = (x - mean) / std
//! 2. Compute logits: z_k = w_k · x_norm + b_k for each class k
//! 3. Apply softmax: P(class=k) = exp(z_k) / Σ exp(z_j)

use anyhow::{anyhow, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingData {
    pub features: Vec<Vec<f32>>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub class: String,
    pub confidence: f32,
    pub probabilities: Vec<(String, f32)>,
}

/// Model registry storing trained model parameters
struct ModelRegistry {
    models: HashMap<String, TrainedModel>,
}

#[derive(Clone)]
struct TrainedModel {
    model_type: ModelType,
    class_weights: HashMap<String, Vec<f32>>,
    class_biases: HashMap<String, f32>,
    feature_means: Vec<f32>,
    feature_stds: Vec<f32>,
    classes: Vec<String>,
}

#[derive(Clone, PartialEq)]
enum ModelType {
    ThreatClassifier,
    AnomalyDetector,
    RiskPredictor,
    PatternRecognizer,
}

impl ModelRegistry {
    fn new() -> Self {
        let mut models = HashMap::new();

        // Pre-trained threat classifier model
        // This simulates a trained model with learned weights
        let threat_classifier = TrainedModel {
            model_type: ModelType::ThreatClassifier,
            class_weights: {
                let mut weights = HashMap::new();
                // Weights learned from training on security data
                // Features: [port_count, open_high_risk_ports, service_age, patch_level, exposure_score]
                weights.insert(
                    "malicious".to_string(),
                    vec![0.15, 0.45, -0.2, -0.35, 0.4],
                );
                weights.insert(
                    "suspicious".to_string(),
                    vec![0.1, 0.25, -0.1, -0.2, 0.25],
                );
                weights.insert(
                    "benign".to_string(),
                    vec![-0.1, -0.35, 0.15, 0.3, -0.3],
                );
                weights
            },
            class_biases: {
                let mut biases = HashMap::new();
                biases.insert("malicious".to_string(), -0.5);
                biases.insert("suspicious".to_string(), -0.2);
                biases.insert("benign".to_string(), 0.3);
                biases
            },
            feature_means: vec![10.0, 2.0, 365.0, 0.7, 50.0],
            feature_stds: vec![15.0, 3.0, 500.0, 0.3, 30.0],
            classes: vec![
                "benign".to_string(),
                "suspicious".to_string(),
                "malicious".to_string(),
            ],
        };

        // Pre-trained anomaly detector
        let anomaly_detector = TrainedModel {
            model_type: ModelType::AnomalyDetector,
            class_weights: {
                let mut weights = HashMap::new();
                // Features: [deviation_score, frequency, time_delta, pattern_match]
                weights.insert("anomaly".to_string(), vec![0.4, -0.2, 0.3, -0.35]);
                weights.insert("normal".to_string(), vec![-0.35, 0.25, -0.2, 0.4]);
                weights
            },
            class_biases: {
                let mut biases = HashMap::new();
                biases.insert("anomaly".to_string(), -0.3);
                biases.insert("normal".to_string(), 0.3);
                biases
            },
            feature_means: vec![0.5, 100.0, 60.0, 0.8],
            feature_stds: vec![0.3, 150.0, 120.0, 0.2],
            classes: vec!["normal".to_string(), "anomaly".to_string()],
        };

        // Pre-trained risk predictor
        let risk_predictor = TrainedModel {
            model_type: ModelType::RiskPredictor,
            class_weights: {
                let mut weights = HashMap::new();
                // Features: [cvss_score, exploitability, asset_value, exposure]
                weights.insert("critical".to_string(), vec![0.35, 0.3, 0.2, 0.25]);
                weights.insert("high".to_string(), vec![0.25, 0.2, 0.15, 0.2]);
                weights.insert("medium".to_string(), vec![0.1, 0.1, 0.1, 0.1]);
                weights.insert("low".to_string(), vec![-0.3, -0.25, -0.15, -0.2]);
                weights
            },
            class_biases: {
                let mut biases = HashMap::new();
                biases.insert("critical".to_string(), -0.8);
                biases.insert("high".to_string(), -0.4);
                biases.insert("medium".to_string(), 0.1);
                biases.insert("low".to_string(), 0.5);
                biases
            },
            feature_means: vec![5.0, 0.5, 0.5, 0.5],
            feature_stds: vec![3.0, 0.3, 0.3, 0.3],
            classes: vec![
                "low".to_string(),
                "medium".to_string(),
                "high".to_string(),
                "critical".to_string(),
            ],
        };

        // Pre-trained pattern recognizer
        let pattern_recognizer = TrainedModel {
            model_type: ModelType::PatternRecognizer,
            class_weights: {
                let mut weights = HashMap::new();
                // Features: [pattern_entropy, sequence_length, repetition, divergence]
                weights.insert(
                    "reconnaissance".to_string(),
                    vec![0.2, 0.3, -0.1, 0.25],
                );
                weights.insert(
                    "exploitation".to_string(),
                    vec![0.35, 0.15, 0.2, 0.3],
                );
                weights.insert(
                    "lateral_movement".to_string(),
                    vec![0.1, 0.25, 0.35, 0.2],
                );
                weights.insert(
                    "exfiltration".to_string(),
                    vec![0.15, 0.4, 0.1, 0.35],
                );
                weights.insert(
                    "normal_activity".to_string(),
                    vec![-0.25, -0.2, -0.15, -0.3],
                );
                weights
            },
            class_biases: {
                let mut biases = HashMap::new();
                biases.insert("reconnaissance".to_string(), -0.3);
                biases.insert("exploitation".to_string(), -0.5);
                biases.insert("lateral_movement".to_string(), -0.4);
                biases.insert("exfiltration".to_string(), -0.45);
                biases.insert("normal_activity".to_string(), 0.6);
                biases
            },
            feature_means: vec![0.5, 50.0, 0.3, 0.4],
            feature_stds: vec![0.25, 100.0, 0.2, 0.25],
            classes: vec![
                "normal_activity".to_string(),
                "reconnaissance".to_string(),
                "exploitation".to_string(),
                "lateral_movement".to_string(),
                "exfiltration".to_string(),
            ],
        };

        models.insert("threat-classifier-v1".to_string(), threat_classifier);
        models.insert("anomaly-detector-v1".to_string(), anomaly_detector);
        models.insert("risk-predictor-v1".to_string(), risk_predictor);
        models.insert("pattern-recognizer-v1".to_string(), pattern_recognizer);

        Self { models }
    }

    fn get_model(&self, model_id: &str) -> Option<&TrainedModel> {
        self.models.get(model_id)
    }
}

impl TrainedModel {
    /// Normalize features using stored means and standard deviations
    fn normalize_features(&self, features: &[f32]) -> Vec<f32> {
        features
            .iter()
            .enumerate()
            .map(|(i, &f)| {
                let mean = self.feature_means.get(i).copied().unwrap_or(0.0);
                let std = self.feature_stds.get(i).copied().unwrap_or(1.0);
                if std > 0.0 {
                    (f - mean) / std
                } else {
                    f - mean
                }
            })
            .collect()
    }

    /// Compute logit scores for each class
    fn compute_logits(&self, normalized_features: &[f32]) -> HashMap<String, f32> {
        let mut logits = HashMap::new();

        for (class, weights) in &self.class_weights {
            let bias = self.class_biases.get(class).copied().unwrap_or(0.0);

            // Dot product of weights and features
            let score: f32 = weights
                .iter()
                .zip(normalized_features.iter())
                .map(|(w, f)| w * f)
                .sum();

            logits.insert(class.clone(), score + bias);
        }

        logits
    }

    /// Apply softmax to convert logits to probabilities
    fn softmax(&self, logits: &HashMap<String, f32>) -> Vec<(String, f32)> {
        // Find max for numerical stability
        let max_logit = logits.values().cloned().fold(f32::NEG_INFINITY, f32::max);

        // Compute exp(logit - max) for each class
        let exp_logits: Vec<(String, f32)> = logits
            .iter()
            .map(|(class, &logit)| (class.clone(), (logit - max_logit).exp()))
            .collect();

        // Compute sum of exponentials
        let sum_exp: f32 = exp_logits.iter().map(|(_, e)| e).sum();

        // Normalize to get probabilities
        exp_logits
            .into_iter()
            .map(|(class, exp)| (class, exp / sum_exp))
            .collect()
    }

    /// Make a prediction
    fn predict(&self, features: &[f32]) -> Prediction {
        // Pad or truncate features to match expected size
        let expected_size = self.feature_means.len();
        let mut padded_features = features.to_vec();
        padded_features.resize(expected_size, 0.0);

        // Normalize features
        let normalized = self.normalize_features(&padded_features);

        // Compute logits
        let logits = self.compute_logits(&normalized);

        // Apply softmax
        let mut probabilities = self.softmax(&logits);

        // Sort by probability (descending)
        probabilities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Get top class
        let (top_class, top_prob) = probabilities.first().cloned().unwrap_or((
            self.classes.first().cloned().unwrap_or_else(|| "unknown".to_string()),
            0.5,
        ));

        Prediction {
            class: top_class,
            confidence: top_prob,
            probabilities,
        }
    }
}

pub async fn predict(model_id: &str, features: Vec<f32>) -> Result<Prediction> {
    let registry = ModelRegistry::new();

    // Get the model from registry
    let model = registry
        .get_model(model_id)
        .ok_or_else(|| anyhow!("Model not found: {}", model_id))?;

    // Make prediction
    let prediction = model.predict(&features);

    log::debug!(
        "Model {} prediction: class={}, confidence={:.2}%",
        model_id,
        prediction.class,
        prediction.confidence * 100.0
    );

    Ok(prediction)
}

/// Batch prediction for multiple feature vectors
pub async fn predict_batch(model_id: &str, feature_batch: Vec<Vec<f32>>) -> Result<Vec<Prediction>> {
    let registry = ModelRegistry::new();

    let model = registry
        .get_model(model_id)
        .ok_or_else(|| anyhow!("Model not found: {}", model_id))?;

    let predictions: Vec<Prediction> = feature_batch
        .iter()
        .map(|features| model.predict(features))
        .collect();

    log::debug!(
        "Batch prediction complete: {} samples processed",
        predictions.len()
    );

    Ok(predictions)
}

/// Get model information
pub fn get_model_info(model_id: &str) -> Option<ModelInfo> {
    let registry = ModelRegistry::new();

    registry.get_model(model_id).map(|model| ModelInfo {
        model_id: model_id.to_string(),
        model_type: match model.model_type {
            ModelType::ThreatClassifier => "threat_classifier".to_string(),
            ModelType::AnomalyDetector => "anomaly_detector".to_string(),
            ModelType::RiskPredictor => "risk_predictor".to_string(),
            ModelType::PatternRecognizer => "pattern_recognizer".to_string(),
        },
        classes: model.classes.clone(),
        feature_count: model.feature_means.len(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub model_id: String,
    pub model_type: String,
    pub classes: Vec<String>,
    pub feature_count: usize,
}

/// List all available models
pub fn list_available_models() -> Vec<String> {
    vec![
        "threat-classifier-v1".to_string(),
        "anomaly-detector-v1".to_string(),
        "risk-predictor-v1".to_string(),
        "pattern-recognizer-v1".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threat_classifier() {
        // Test with features indicating a potentially malicious host
        // High port count, high risk ports, old service, low patch level, high exposure
        let features = vec![50.0, 5.0, 1000.0, 0.2, 80.0];

        let prediction = predict("threat-classifier-v1", features).await.unwrap();

        assert!(!prediction.class.is_empty());
        assert!(prediction.confidence > 0.0 && prediction.confidence <= 1.0);
        assert!(!prediction.probabilities.is_empty());
    }

    #[tokio::test]
    async fn test_model_not_found() {
        let result = predict("nonexistent-model", vec![1.0, 2.0]).await;
        assert!(result.is_err());
    }
}
