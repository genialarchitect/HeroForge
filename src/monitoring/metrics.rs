//! Metrics collection and monitoring

use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Application metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    // Request metrics
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_response_time_ms: f64,

    // Scan metrics
    pub active_scans: u64,
    pub completed_scans: u64,
    pub failed_scans: u64,

    // Database metrics
    pub db_connections_active: u32,
    pub db_query_count: u64,
    pub db_slow_queries: u64,

    // System metrics
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub uptime_seconds: u64,

    pub last_updated: DateTime<Utc>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            average_response_time_ms: 0.0,
            active_scans: 0,
            completed_scans: 0,
            failed_scans: 0,
            db_connections_active: 0,
            db_query_count: 0,
            db_slow_queries: 0,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
            uptime_seconds: 0,
            last_updated: Utc::now(),
        }
    }
}

/// Metrics collector
pub struct MetricsCollector {
    metrics: Arc<RwLock<Metrics>>,
    counters: Arc<RwLock<HashMap<String, u64>>>,
    gauges: Arc<RwLock<HashMap<String, f64>>>,
    histograms: Arc<RwLock<HashMap<String, Vec<f64>>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Metrics::default())),
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_metrics(&self) -> Metrics {
        self.metrics.read().await.clone()
    }

    pub async fn increment_counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.write().await;
        *counters.entry(name.to_string()).or_insert(0) += value;
    }

    pub async fn set_gauge(&self, name: &str, value: f64) {
        let mut gauges = self.gauges.write().await;
        gauges.insert(name.to_string(), value);
    }

    pub async fn record_histogram(&self, name: &str, value: f64) {
        let mut histograms = self.histograms.write().await;
        histograms.entry(name.to_string()).or_insert_with(Vec::new).push(value);
    }

    pub async fn record_request(&self, duration_ms: f64, success: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.total_requests += 1;

        if success {
            metrics.successful_requests += 1;
        } else {
            metrics.failed_requests += 1;
        }

        // Update average response time
        let total = metrics.total_requests as f64;
        metrics.average_response_time_ms =
            (metrics.average_response_time_ms * (total - 1.0) + duration_ms) / total;

        metrics.last_updated = Utc::now();
    }

    pub async fn get_counter(&self, name: &str) -> u64 {
        self.counters.read().await.get(name).copied().unwrap_or(0)
    }

    pub async fn get_gauge(&self, name: &str) -> f64 {
        self.gauges.read().await.get(name).copied().unwrap_or(0.0)
    }

    pub async fn export_prometheus(&self) -> String {
        let metrics = self.metrics.read().await;
        let counters = self.counters.read().await;
        let gauges = self.gauges.read().await;

        let mut output = String::new();

        // Export core metrics
        output.push_str(&format!("heroforge_requests_total {}\n", metrics.total_requests));
        output.push_str(&format!("heroforge_requests_successful {}\n", metrics.successful_requests));
        output.push_str(&format!("heroforge_requests_failed {}\n", metrics.failed_requests));
        output.push_str(&format!("heroforge_response_time_avg_ms {}\n", metrics.average_response_time_ms));
        output.push_str(&format!("heroforge_scans_active {}\n", metrics.active_scans));
        output.push_str(&format!("heroforge_scans_completed {}\n", metrics.completed_scans));

        // Export custom counters
        for (name, value) in counters.iter() {
            output.push_str(&format!("heroforge_{}{{}} {}\n", name, value));
        }

        // Export gauges
        for (name, value) in gauges.iter() {
            output.push_str(&format!("heroforge_{}{{}} {}\n", name, value));
        }

        output
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
