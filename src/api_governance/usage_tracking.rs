//! Usage tracking and analytics for API governance

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Usage tracker for API calls and resource consumption
pub struct UsageTracker {
    metrics: Arc<RwLock<HashMap<String, UserMetrics>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserMetrics {
    /// Total API calls in current period
    api_calls: u64,
    /// API calls by endpoint
    endpoint_calls: HashMap<String, u64>,
    /// Data transferred (bytes)
    data_transferred: u64,
    /// Errors encountered
    errors: u64,
    /// Average response time (ms)
    avg_response_time: f64,
    /// Last activity timestamp
    last_activity: chrono::DateTime<chrono::Utc>,
    /// Period start
    period_start: chrono::DateTime<chrono::Utc>,
}

impl UsageTracker {
    /// Create a new usage tracker
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record an API call
    pub async fn record_call(
        &self,
        user_id: &str,
        endpoint: &str,
        response_time_ms: u64,
        bytes_transferred: u64,
        is_error: bool,
    ) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        let now = chrono::Utc::now();

        let user_metrics = metrics.entry(user_id.to_string()).or_insert_with(|| {
            UserMetrics {
                api_calls: 0,
                endpoint_calls: HashMap::new(),
                data_transferred: 0,
                errors: 0,
                avg_response_time: 0.0,
                last_activity: now,
                period_start: now,
            }
        });

        // Update metrics
        user_metrics.api_calls += 1;
        *user_metrics.endpoint_calls.entry(endpoint.to_string()).or_insert(0) += 1;
        user_metrics.data_transferred += bytes_transferred;
        if is_error {
            user_metrics.errors += 1;
        }

        // Update average response time (exponential moving average)
        let alpha = 0.1; // Smoothing factor
        user_metrics.avg_response_time = alpha * (response_time_ms as f64)
            + (1.0 - alpha) * user_metrics.avg_response_time;

        user_metrics.last_activity = now;

        Ok(())
    }

    /// Get usage metrics for a user
    pub async fn get_metrics(&self, user_id: &str) -> Result<Option<UsageMetrics>> {
        let metrics = self.metrics.read().await;
        Ok(metrics.get(user_id).map(|m| UsageMetrics {
            user_id: user_id.to_string(),
            api_calls: m.api_calls,
            data_transferred: m.data_transferred,
            errors: m.errors,
            error_rate: if m.api_calls > 0 {
                (m.errors as f64 / m.api_calls as f64) * 100.0
            } else {
                0.0
            },
            avg_response_time_ms: m.avg_response_time,
            last_activity: m.last_activity,
            period_start: m.period_start,
            top_endpoints: self.get_top_endpoints(&m.endpoint_calls, 10),
        }))
    }

    /// Get usage analytics for all users
    pub async fn get_analytics(&self) -> Result<UsageAnalytics> {
        let metrics = self.metrics.read().await;

        let total_calls: u64 = metrics.values().map(|m| m.api_calls).sum();
        let total_data: u64 = metrics.values().map(|m| m.data_transferred).sum();
        let total_errors: u64 = metrics.values().map(|m| m.errors).sum();
        let active_users = metrics.len();

        let avg_response_time = if !metrics.is_empty() {
            metrics.values().map(|m| m.avg_response_time).sum::<f64>() / metrics.len() as f64
        } else {
            0.0
        };

        Ok(UsageAnalytics {
            total_api_calls: total_calls,
            total_data_transferred: total_data,
            total_errors: total_errors,
            active_users,
            avg_response_time_ms: avg_response_time,
            error_rate: if total_calls > 0 {
                (total_errors as f64 / total_calls as f64) * 100.0
            } else {
                0.0
            },
        })
    }

    /// Reset metrics for a user
    pub async fn reset_metrics(&self, user_id: &str) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        metrics.remove(user_id);
        Ok(())
    }

    /// Reset all metrics
    pub async fn reset_all_metrics(&self) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        metrics.clear();
        Ok(())
    }

    /// Get top endpoints by call count
    fn get_top_endpoints(&self, endpoint_calls: &HashMap<String, u64>, limit: usize) -> Vec<EndpointStats> {
        let mut endpoints: Vec<_> = endpoint_calls
            .iter()
            .map(|(endpoint, count)| EndpointStats {
                endpoint: endpoint.clone(),
                calls: *count,
            })
            .collect();

        endpoints.sort_by(|a, b| b.calls.cmp(&a.calls));
        endpoints.truncate(limit);
        endpoints
    }

    /// Get cost attribution (if pricing is configured)
    pub async fn get_cost_attribution(&self, user_id: &str, pricing: &PricingConfig) -> Result<f64> {
        let metrics = self.metrics.read().await;
        let user_metrics = metrics.get(user_id).ok_or_else(|| {
            anyhow::anyhow!("No metrics found for user")
        })?;

        let mut total_cost = 0.0;

        // Calculate based on API calls
        total_cost += user_metrics.api_calls as f64 * pricing.cost_per_api_call;

        // Calculate based on data transfer
        total_cost += (user_metrics.data_transferred as f64 / 1_000_000_000.0) * pricing.cost_per_gb;

        Ok(total_cost)
    }
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Usage metrics for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetrics {
    pub user_id: String,
    pub api_calls: u64,
    pub data_transferred: u64,
    pub errors: u64,
    pub error_rate: f64,
    pub avg_response_time_ms: f64,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub period_start: chrono::DateTime<chrono::Utc>,
    pub top_endpoints: Vec<EndpointStats>,
}

/// Endpoint statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStats {
    pub endpoint: String,
    pub calls: u64,
}

/// System-wide usage analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageAnalytics {
    pub total_api_calls: u64,
    pub total_data_transferred: u64,
    pub total_errors: u64,
    pub active_users: usize,
    pub avg_response_time_ms: f64,
    pub error_rate: f64,
}

/// Pricing configuration for cost attribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    /// Cost per API call
    pub cost_per_api_call: f64,
    /// Cost per GB of data transfer
    pub cost_per_gb: f64,
    /// Cost per scan
    pub cost_per_scan: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_usage_tracking() {
        let tracker = UsageTracker::new();

        // Record some API calls
        tracker.record_call("user1", "/api/scans", 150, 1024, false).await.unwrap();
        tracker.record_call("user1", "/api/scans", 200, 2048, false).await.unwrap();
        tracker.record_call("user1", "/api/reports", 100, 512, false).await.unwrap();

        let metrics = tracker.get_metrics("user1").await.unwrap().unwrap();
        assert_eq!(metrics.api_calls, 3);
        assert_eq!(metrics.data_transferred, 3584);
        assert_eq!(metrics.errors, 0);
    }

    #[tokio::test]
    async fn test_error_rate_calculation() {
        let tracker = UsageTracker::new();

        tracker.record_call("user1", "/api/scans", 150, 1024, false).await.unwrap();
        tracker.record_call("user1", "/api/scans", 200, 2048, true).await.unwrap();
        tracker.record_call("user1", "/api/scans", 180, 1536, false).await.unwrap();
        tracker.record_call("user1", "/api/scans", 220, 2560, true).await.unwrap();

        let metrics = tracker.get_metrics("user1").await.unwrap().unwrap();
        assert_eq!(metrics.errors, 2);
        assert_eq!(metrics.error_rate, 50.0); // 2 errors out of 4 calls
    }

    #[tokio::test]
    async fn test_cost_attribution() {
        let tracker = UsageTracker::new();
        let pricing = PricingConfig {
            cost_per_api_call: 0.001,
            cost_per_gb: 0.10,
            cost_per_scan: 0.05,
        };

        // 100 API calls
        for _ in 0..100 {
            tracker.record_call("user1", "/api/scans", 150, 10_000_000, false).await.unwrap();
        }

        let cost = tracker.get_cost_attribution("user1", &pricing).await.unwrap();
        // 100 calls * $0.001 + (1GB / 1GB) * $0.10 = $0.10 + $0.10 = $0.20
        assert!((cost - 0.20).abs() < 0.01);
    }
}
