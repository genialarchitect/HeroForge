//! Anomaly Detection Module
//!
//! Provides statistical anomaly detection using:
//! - Z-score based detection
//! - Isolation forest-style scoring
//! - Time series analysis
//! - Baseline comparison

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of anomaly detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Statistical outlier (z-score)
    StatisticalOutlier,
    /// Deviation from historical baseline
    BaselineDeviation,
    /// Unusual time pattern
    TemporalAnomaly,
    /// Behavioral change
    BehavioralChange,
    /// Volumetric anomaly (spike or drop)
    VolumetricAnomaly,
    /// Rare event occurrence
    RareEvent,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::StatisticalOutlier => write!(f, "statistical_outlier"),
            AnomalyType::BaselineDeviation => write!(f, "baseline_deviation"),
            AnomalyType::TemporalAnomaly => write!(f, "temporal_anomaly"),
            AnomalyType::BehavioralChange => write!(f, "behavioral_change"),
            AnomalyType::VolumetricAnomaly => write!(f, "volumetric_anomaly"),
            AnomalyType::RareEvent => write!(f, "rare_event"),
        }
    }
}

/// Severity of the anomaly
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AnomalySeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl AnomalySeverity {
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            80..=100 => AnomalySeverity::Critical,
            60..=79 => AnomalySeverity::High,
            40..=59 => AnomalySeverity::Medium,
            _ => AnomalySeverity::Low,
        }
    }
}

/// Detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DetectedAnomaly {
    pub id: String,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub score: f64,
    pub metric_name: String,
    pub observed_value: f64,
    pub expected_value: f64,
    pub baseline_mean: Option<f64>,
    pub baseline_stddev: Option<f64>,
    pub z_score: Option<f64>,
    pub description: String,
    pub context: HashMap<String, serde_json::Value>,
    pub detected_at: DateTime<Utc>,
}

/// Statistical baseline for a metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBaseline {
    pub metric_name: String,
    pub mean: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
    pub median: f64,
    pub sample_count: usize,
    pub percentile_95: f64,
    pub percentile_99: f64,
    pub last_updated: DateTime<Utc>,
}

impl MetricBaseline {
    /// Calculate baseline from a set of values
    pub fn from_values(metric_name: &str, values: &[f64]) -> Option<Self> {
        if values.is_empty() {
            return None;
        }

        let n = values.len() as f64;
        let mean = values.iter().sum::<f64>() / n;

        let variance = values.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / n;
        let stddev = variance.sqrt();

        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min = sorted.first().copied().unwrap_or(0.0);
        let max = sorted.last().copied().unwrap_or(0.0);
        let median = if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
        } else {
            sorted[sorted.len() / 2]
        };

        let p95_idx = ((values.len() as f64) * 0.95).ceil() as usize - 1;
        let p99_idx = ((values.len() as f64) * 0.99).ceil() as usize - 1;
        let percentile_95 = sorted.get(p95_idx.min(sorted.len() - 1)).copied().unwrap_or(max);
        let percentile_99 = sorted.get(p99_idx.min(sorted.len() - 1)).copied().unwrap_or(max);

        Some(Self {
            metric_name: metric_name.to_string(),
            mean,
            stddev,
            min,
            max,
            median,
            sample_count: values.len(),
            percentile_95,
            percentile_99,
            last_updated: Utc::now(),
        })
    }

    /// Calculate z-score for a value
    pub fn z_score(&self, value: f64) -> f64 {
        if self.stddev == 0.0 {
            return 0.0;
        }
        (value - self.mean) / self.stddev
    }

    /// Check if a value is an outlier using z-score
    pub fn is_outlier(&self, value: f64, threshold: f64) -> bool {
        self.z_score(value).abs() > threshold
    }
}

/// Time series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
}

/// Anomaly Detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetectorConfig {
    /// Z-score threshold for statistical outliers (default: 3.0)
    pub z_score_threshold: f64,
    /// Percentage deviation threshold for baseline comparison
    pub deviation_threshold_percent: f64,
    /// Minimum samples required for baseline
    pub min_baseline_samples: usize,
    /// Window size for rolling calculations
    pub rolling_window_size: usize,
    /// Enable temporal pattern detection
    pub enable_temporal_detection: bool,
    /// Sensitivity (0.0 - 1.0)
    pub sensitivity: f64,
}

impl Default for AnomalyDetectorConfig {
    fn default() -> Self {
        Self {
            z_score_threshold: 3.0,
            deviation_threshold_percent: 50.0,
            min_baseline_samples: 30,
            rolling_window_size: 24, // 24 data points
            enable_temporal_detection: true,
            sensitivity: 0.7,
        }
    }
}

/// Anomaly Detector
pub struct AnomalyDetector {
    config: AnomalyDetectorConfig,
    baselines: HashMap<String, MetricBaseline>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector with default configuration
    pub fn new() -> Self {
        Self {
            config: AnomalyDetectorConfig::default(),
            baselines: HashMap::new(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: AnomalyDetectorConfig) -> Self {
        Self {
            config,
            baselines: HashMap::new(),
        }
    }

    /// Update baseline for a metric
    pub fn update_baseline(&mut self, metric_name: &str, values: &[f64]) {
        if let Some(baseline) = MetricBaseline::from_values(metric_name, values) {
            self.baselines.insert(metric_name.to_string(), baseline);
        }
    }

    /// Get baseline for a metric
    pub fn get_baseline(&self, metric_name: &str) -> Option<&MetricBaseline> {
        self.baselines.get(metric_name)
    }

    /// Detect anomaly in a single value using z-score
    pub fn detect_zscore_anomaly(&self, metric_name: &str, value: f64) -> Option<DetectedAnomaly> {
        let baseline = self.baselines.get(metric_name)?;

        if baseline.sample_count < self.config.min_baseline_samples {
            return None;
        }

        let z_score = baseline.z_score(value);
        let threshold = self.config.z_score_threshold * (1.0 - self.config.sensitivity + 0.5);

        if z_score.abs() > threshold {
            let severity_score = (z_score.abs() / threshold * 50.0).min(100.0);

            Some(DetectedAnomaly {
                id: uuid::Uuid::new_v4().to_string(),
                anomaly_type: AnomalyType::StatisticalOutlier,
                severity: AnomalySeverity::from_score(severity_score),
                score: severity_score,
                metric_name: metric_name.to_string(),
                observed_value: value,
                expected_value: baseline.mean,
                baseline_mean: Some(baseline.mean),
                baseline_stddev: Some(baseline.stddev),
                z_score: Some(z_score),
                description: format!(
                    "Value {} deviates {:.2} standard deviations from mean {:.2}",
                    value, z_score.abs(), baseline.mean
                ),
                context: HashMap::new(),
                detected_at: Utc::now(),
            })
        } else {
            None
        }
    }

    /// Detect baseline deviation
    pub fn detect_baseline_deviation(&self, metric_name: &str, value: f64) -> Option<DetectedAnomaly> {
        let baseline = self.baselines.get(metric_name)?;

        if baseline.mean == 0.0 {
            return None;
        }

        let deviation_percent = ((value - baseline.mean) / baseline.mean * 100.0).abs();
        let threshold = self.config.deviation_threshold_percent * (1.0 - self.config.sensitivity + 0.5);

        if deviation_percent > threshold {
            let severity_score = (deviation_percent / threshold * 50.0).min(100.0);

            Some(DetectedAnomaly {
                id: uuid::Uuid::new_v4().to_string(),
                anomaly_type: AnomalyType::BaselineDeviation,
                severity: AnomalySeverity::from_score(severity_score),
                score: severity_score,
                metric_name: metric_name.to_string(),
                observed_value: value,
                expected_value: baseline.mean,
                baseline_mean: Some(baseline.mean),
                baseline_stddev: Some(baseline.stddev),
                z_score: Some(baseline.z_score(value)),
                description: format!(
                    "Value {} deviates {:.1}% from baseline mean {:.2}",
                    value, deviation_percent, baseline.mean
                ),
                context: HashMap::new(),
                detected_at: Utc::now(),
            })
        } else {
            None
        }
    }

    /// Detect volumetric anomaly (spikes or drops)
    pub fn detect_volumetric_anomaly(&self, metric_name: &str, current: f64, previous: f64) -> Option<DetectedAnomaly> {
        if previous == 0.0 && current == 0.0 {
            return None;
        }

        let change_percent = if previous == 0.0 {
            if current > 0.0 { 100.0 } else { 0.0 }
        } else {
            ((current - previous) / previous * 100.0).abs()
        };

        let threshold = 100.0 * (1.0 - self.config.sensitivity + 0.5);

        if change_percent > threshold {
            let severity_score = (change_percent / 100.0 * 50.0).min(100.0);
            let direction = if current > previous { "spike" } else { "drop" };

            Some(DetectedAnomaly {
                id: uuid::Uuid::new_v4().to_string(),
                anomaly_type: AnomalyType::VolumetricAnomaly,
                severity: AnomalySeverity::from_score(severity_score),
                score: severity_score,
                metric_name: metric_name.to_string(),
                observed_value: current,
                expected_value: previous,
                baseline_mean: None,
                baseline_stddev: None,
                z_score: None,
                description: format!(
                    "Detected {} of {:.1}% ({:.2} -> {:.2})",
                    direction, change_percent, previous, current
                ),
                context: HashMap::new(),
                detected_at: Utc::now(),
            })
        } else {
            None
        }
    }

    /// Detect anomalies in time series data
    pub fn detect_time_series_anomalies(&self, metric_name: &str, data: &[TimeSeriesPoint]) -> Vec<DetectedAnomaly> {
        let mut anomalies = Vec::new();

        if data.len() < self.config.min_baseline_samples {
            return anomalies;
        }

        // Calculate rolling statistics
        let values: Vec<f64> = data.iter().map(|p| p.value).collect();

        // Create baseline from all data
        if let Some(baseline) = MetricBaseline::from_values(metric_name, &values) {
            // Check each point
            for (i, point) in data.iter().enumerate() {
                let z_score = baseline.z_score(point.value);
                let threshold = self.config.z_score_threshold * (1.0 - self.config.sensitivity + 0.5);

                if z_score.abs() > threshold {
                    let severity_score = (z_score.abs() / threshold * 50.0).min(100.0);

                    anomalies.push(DetectedAnomaly {
                        id: uuid::Uuid::new_v4().to_string(),
                        anomaly_type: AnomalyType::StatisticalOutlier,
                        severity: AnomalySeverity::from_score(severity_score),
                        score: severity_score,
                        metric_name: metric_name.to_string(),
                        observed_value: point.value,
                        expected_value: baseline.mean,
                        baseline_mean: Some(baseline.mean),
                        baseline_stddev: Some(baseline.stddev),
                        z_score: Some(z_score),
                        description: format!(
                            "Time series anomaly at index {}: value {} deviates {:.2} stddev",
                            i, point.value, z_score.abs()
                        ),
                        context: {
                            let mut ctx = HashMap::new();
                            ctx.insert("index".to_string(), serde_json::json!(i));
                            ctx.insert("timestamp".to_string(), serde_json::json!(point.timestamp.to_rfc3339()));
                            ctx
                        },
                        detected_at: point.timestamp,
                    });
                }
            }
        }

        anomalies
    }

    /// Detect rare events (values that occur very infrequently)
    pub fn detect_rare_event(&self, metric_name: &str, value: f64, occurrence_rate: f64) -> Option<DetectedAnomaly> {
        // Occurrence rate is between 0 and 1 (e.g., 0.01 = 1% of the time)
        let rarity_threshold = 0.05 * self.config.sensitivity;

        if occurrence_rate < rarity_threshold {
            let severity_score = ((1.0 - occurrence_rate) * 100.0).min(100.0);

            Some(DetectedAnomaly {
                id: uuid::Uuid::new_v4().to_string(),
                anomaly_type: AnomalyType::RareEvent,
                severity: AnomalySeverity::from_score(severity_score),
                score: severity_score,
                metric_name: metric_name.to_string(),
                observed_value: value,
                expected_value: 0.0,
                baseline_mean: None,
                baseline_stddev: None,
                z_score: None,
                description: format!(
                    "Rare event detected: value {} occurs only {:.2}% of the time",
                    value, occurrence_rate * 100.0
                ),
                context: {
                    let mut ctx = HashMap::new();
                    ctx.insert("occurrence_rate".to_string(), serde_json::json!(occurrence_rate));
                    ctx
                },
                detected_at: Utc::now(),
            })
        } else {
            None
        }
    }

    /// Calculate isolation forest-style anomaly score
    /// Returns a score between 0 (normal) and 1 (anomaly)
    pub fn isolation_score(&self, metric_name: &str, value: f64) -> f64 {
        let baseline = match self.baselines.get(metric_name) {
            Some(b) => b,
            None => return 0.5, // No baseline, uncertain
        };

        // Simplified isolation scoring based on distance from normal range
        let distance_from_mean = (value - baseline.mean).abs();
        let normalized_distance = distance_from_mean / (baseline.max - baseline.min + 1.0);

        // Apply sigmoid-like transformation
        let score = 1.0 / (1.0 + (-10.0 * (normalized_distance - 0.5)).exp());

        score.min(1.0).max(0.0)
    }

    /// Run all detection methods on a value
    pub fn detect_all_anomalies(&self, metric_name: &str, current_value: f64, previous_value: Option<f64>) -> Vec<DetectedAnomaly> {
        let mut anomalies = Vec::new();

        // Z-score detection
        if let Some(anomaly) = self.detect_zscore_anomaly(metric_name, current_value) {
            anomalies.push(anomaly);
        }

        // Baseline deviation
        if let Some(anomaly) = self.detect_baseline_deviation(metric_name, current_value) {
            // Avoid duplicate if z-score already detected it
            if anomalies.is_empty() {
                anomalies.push(anomaly);
            }
        }

        // Volumetric anomaly (if previous value provided)
        if let Some(prev) = previous_value {
            if let Some(anomaly) = self.detect_volumetric_anomaly(metric_name, current_value, prev) {
                anomalies.push(anomaly);
            }
        }

        anomalies
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_calculation() {
        let values = vec![10.0, 12.0, 11.0, 9.0, 10.0, 11.0, 10.0, 12.0, 9.0, 10.0];
        let baseline = MetricBaseline::from_values("test_metric", &values).unwrap();

        assert!((baseline.mean - 10.4).abs() < 0.1);
        assert!(baseline.stddev > 0.0);
        assert_eq!(baseline.min, 9.0);
        assert_eq!(baseline.max, 12.0);
        assert_eq!(baseline.sample_count, 10);
    }

    #[test]
    fn test_zscore_anomaly_detection() {
        let mut detector = AnomalyDetector::new();

        // Create baseline with normal values
        let values: Vec<f64> = (0..100).map(|i| 50.0 + (i as f64 % 10.0 - 5.0)).collect();
        detector.update_baseline("cpu_usage", &values);

        // Normal value - no anomaly
        let result = detector.detect_zscore_anomaly("cpu_usage", 52.0);
        assert!(result.is_none());

        // Extreme value - should detect anomaly
        let result = detector.detect_zscore_anomaly("cpu_usage", 100.0);
        assert!(result.is_some());
    }

    #[test]
    fn test_volumetric_anomaly() {
        let detector = AnomalyDetector::with_config(AnomalyDetectorConfig {
            sensitivity: 0.8,
            ..Default::default()
        });

        // 300% increase should be detected
        let result = detector.detect_volumetric_anomaly("requests", 400.0, 100.0);
        assert!(result.is_some());

        // 20% increase should not be detected
        let result = detector.detect_volumetric_anomaly("requests", 120.0, 100.0);
        assert!(result.is_none());
    }

    #[test]
    fn test_isolation_score() {
        let mut detector = AnomalyDetector::new();

        let values: Vec<f64> = (0..100).map(|i| 50.0 + (i as f64 % 10.0 - 5.0)).collect();
        detector.update_baseline("metric", &values);

        // Normal value
        let score = detector.isolation_score("metric", 50.0);
        assert!(score < 0.5);

        // Anomalous value
        let score = detector.isolation_score("metric", 200.0);
        assert!(score > 0.5);
    }
}
