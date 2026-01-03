//! Quota management and enforcement

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Quota types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum QuotaType {
    /// API call quota
    ApiCalls,
    /// Data transfer quota (bytes)
    DataTransfer,
    /// Storage quota (bytes)
    Storage,
    /// Scan quota
    Scans,
    /// Report generation quota
    Reports,
    /// Custom quota type
    Custom,
}

/// Quota period
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QuotaPeriod {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl QuotaPeriod {
    /// Get the duration of the period
    pub fn duration(&self) -> chrono::Duration {
        match self {
            QuotaPeriod::Hourly => chrono::Duration::hours(1),
            QuotaPeriod::Daily => chrono::Duration::days(1),
            QuotaPeriod::Weekly => chrono::Duration::weeks(1),
            QuotaPeriod::Monthly => chrono::Duration::days(30), // Approximate
        }
    }
}

/// Quota configuration
#[derive(Debug, Clone)]
pub struct QuotaConfig {
    pub quota_type: QuotaType,
    pub limit: u64,
    pub period: QuotaPeriod,
    pub alert_threshold: f64, // 0.0-1.0, when to alert
}

/// Quota manager
pub struct QuotaManager {
    configs: Arc<RwLock<HashMap<String, Vec<QuotaConfig>>>>,
    usage: Arc<RwLock<HashMap<String, QuotaUsage>>>,
}

#[derive(Debug, Clone)]
struct QuotaUsage {
    /// Usage per quota type
    usage: HashMap<QuotaType, u64>,
    /// Period start
    period_start: chrono::DateTime<chrono::Utc>,
    /// Period end
    period_end: chrono::DateTime<chrono::Utc>,
}

impl QuotaManager {
    /// Create a new quota manager
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
            usage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set default quota for a quota type (used for all users without explicit quota)
    pub fn set_default_quota(&mut self, quota_type: QuotaType, limit: u64) {
        // Default quotas are stored under a special "_default" key
        // This is a synchronous method used during initialization
        let mut configs = self.configs.blocking_write();
        let default_configs = configs.entry("_default".to_string()).or_insert_with(Vec::new);

        // Remove existing default for this type
        default_configs.retain(|c| c.quota_type != quota_type);

        // Add new default
        default_configs.push(QuotaConfig {
            quota_type,
            limit,
            period: QuotaPeriod::Daily,
            alert_threshold: 0.8,
        });
    }

    /// Set quota for a user
    pub async fn set_quota(&self, user_id: &str, config: QuotaConfig) -> Result<()> {
        let mut configs = self.configs.write().await;
        configs.entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(config);
        Ok(())
    }

    /// Increment usage for a user
    pub async fn increment_usage(&mut self, user_id: &str, quota_type: &QuotaType, amount: u64) -> Result<()> {
        self.record_usage(user_id, *quota_type, amount).await
    }

    /// Check if quota allows the operation
    pub async fn check_quota(
        &self,
        user_id: &str,
        quota_type: QuotaType,
        amount: u64,
    ) -> Result<QuotaDecision> {
        let configs = self.configs.read().await;
        let mut usage = self.usage.write().await;

        // Get user's quota config for this type
        let config = configs
            .get(user_id)
            .and_then(|c| c.iter().find(|cfg| cfg.quota_type == quota_type));

        let config = match config {
            Some(c) => c,
            None => {
                // No quota configured - allow
                return Ok(QuotaDecision {
                    allowed: true,
                    quota_limit: None,
                    quota_used: 0,
                    quota_remaining: None,
                    period_end: None,
                    approaching_limit: false,
                });
            }
        };

        // Get or initialize usage tracking
        let now = chrono::Utc::now();
        let user_usage = usage.entry(user_id.to_string()).or_insert_with(|| {
            QuotaUsage {
                usage: HashMap::new(),
                period_start: now,
                period_end: now + config.period.duration(),
            }
        });

        // Reset if period has expired
        if now >= user_usage.period_end {
            user_usage.usage.clear();
            user_usage.period_start = now;
            user_usage.period_end = now + config.period.duration();
        }

        let current_usage = *user_usage.usage.get(&quota_type).unwrap_or(&0);
        let new_usage = current_usage + amount;

        let allowed = new_usage <= config.limit;
        let approaching_limit = (new_usage as f64 / config.limit as f64) >= config.alert_threshold;

        Ok(QuotaDecision {
            allowed,
            quota_limit: Some(config.limit),
            quota_used: current_usage,
            quota_remaining: Some(config.limit.saturating_sub(current_usage)),
            period_end: Some(user_usage.period_end),
            approaching_limit,
        })
    }

    /// Record quota usage
    pub async fn record_usage(
        &self,
        user_id: &str,
        quota_type: QuotaType,
        amount: u64,
    ) -> Result<()> {
        let mut usage = self.usage.write().await;
        let now = chrono::Utc::now();

        let user_usage = usage.entry(user_id.to_string()).or_insert_with(|| {
            QuotaUsage {
                usage: HashMap::new(),
                period_start: now,
                period_end: now + chrono::Duration::days(1), // Default daily
            }
        });

        *user_usage.usage.entry(quota_type).or_insert(0) += amount;

        Ok(())
    }

    /// Get current usage for a user
    pub async fn get_usage(&self, user_id: &str) -> Result<HashMap<QuotaType, u64>> {
        let usage = self.usage.read().await;
        Ok(usage
            .get(user_id)
            .map(|u| u.usage.clone())
            .unwrap_or_default())
    }

    /// Get usage statistics for a user
    pub async fn get_usage_stats(&self, user_id: &str) -> Result<Vec<QuotaStats>> {
        let configs = self.configs.read().await;
        let usage = self.usage.read().await;

        let user_configs = configs.get(user_id);
        let user_usage = usage.get(user_id);

        let mut stats = Vec::new();

        if let Some(configs) = user_configs {
            for config in configs {
                let current_usage = user_usage
                    .and_then(|u| u.usage.get(&config.quota_type))
                    .copied()
                    .unwrap_or(0);

                stats.push(QuotaStats {
                    quota_type: config.quota_type,
                    limit: config.limit,
                    used: current_usage,
                    remaining: config.limit.saturating_sub(current_usage),
                    percentage_used: (current_usage as f64 / config.limit as f64) * 100.0,
                    period: config.period,
                    period_end: user_usage.map(|u| u.period_end),
                });
            }
        }

        Ok(stats)
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Quota decision
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuotaDecision {
    pub allowed: bool,
    pub quota_limit: Option<u64>,
    pub quota_used: u64,
    pub quota_remaining: Option<u64>,
    pub period_end: Option<chrono::DateTime<chrono::Utc>>,
    pub approaching_limit: bool,
}

/// Quota statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuotaStats {
    pub quota_type: QuotaType,
    pub limit: u64,
    pub used: u64,
    pub remaining: u64,
    pub percentage_used: f64,
    pub period: QuotaPeriod,
    pub period_end: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quota_enforcement() {
        let manager = QuotaManager::new();

        // Set a quota of 100 API calls per day
        manager.set_quota("user1", QuotaConfig {
            quota_type: QuotaType::ApiCalls,
            limit: 100,
            period: QuotaPeriod::Daily,
            alert_threshold: 0.8,
        }).await.unwrap();

        // Check quota - should allow
        let decision = manager.check_quota("user1", QuotaType::ApiCalls, 50).await.unwrap();
        assert!(decision.allowed);

        // Record usage
        manager.record_usage("user1", QuotaType::ApiCalls, 50).await.unwrap();

        // Check again - should allow
        let decision = manager.check_quota("user1", QuotaType::ApiCalls, 40).await.unwrap();
        assert!(decision.allowed);

        manager.record_usage("user1", QuotaType::ApiCalls, 40).await.unwrap();

        // Check again - should deny (90 + 20 > 100)
        let decision = manager.check_quota("user1", QuotaType::ApiCalls, 20).await.unwrap();
        assert!(!decision.allowed);
    }

    #[tokio::test]
    async fn test_quota_stats() {
        let manager = QuotaManager::new();

        manager.set_quota("user1", QuotaConfig {
            quota_type: QuotaType::Scans,
            limit: 50,
            period: QuotaPeriod::Daily,
            alert_threshold: 0.9,
        }).await.unwrap();

        manager.record_usage("user1", QuotaType::Scans, 25).await.unwrap();

        let stats = manager.get_usage_stats("user1").await.unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].used, 25);
        assert_eq!(stats[0].remaining, 25);
        assert_eq!(stats[0].percentage_used, 50.0);
    }
}
