//! Business intelligence metrics

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub mttd: f64,  // Mean Time To Detect
    pub mttr: f64,  // Mean Time To Respond
    pub mttc: f64,  // Mean Time To Contain
    pub vulnerability_dwell_time: f64,
    pub patch_compliance_rate: f64,
}

pub struct MetricsCalculator {}

impl MetricsCalculator {
    pub fn new() -> Self {
        Self {}
    }

    pub fn calculate_mttd(&self, detections: &[(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)]) -> f64 {
        // TODO: Calculate MTTD from detection timestamps
        0.0
    }

    pub fn calculate_mttr(&self, incidents: &[(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)]) -> f64 {
        // TODO: Calculate MTTR
        0.0
    }
}

impl Default for MetricsCalculator {
    fn default() -> Self {
        Self::new()
    }
}
