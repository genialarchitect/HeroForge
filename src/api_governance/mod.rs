//! API Governance Module
//!
//! This module provides comprehensive API governance capabilities including:
//! - Rate limiting with multiple algorithms (token bucket, leaky bucket, sliding window)
//! - Usage quotas and enforcement
//! - API versioning and deprecation management
//! - Usage tracking and analytics
//!
//! ## Features
//!
//! - **Rate Limiting**: Prevent API abuse with configurable rate limits
//! - **Quotas**: Enforce daily/monthly API call limits
//! - **Versioning**: URL-based and header-based API versioning
//! - **Usage Tracking**: Real-time usage analytics and cost attribution
//!
//! ## Example
//!
//! ```rust,ignore
//! use api_governance::{RateLimiter, TokenBucketConfig};
//!
//! let config = TokenBucketConfig {
//!     capacity: 100,
//!     refill_rate: 10,
//! };
//! let limiter = RateLimiter::token_bucket(config);
//! ```

#![allow(dead_code)]

pub mod rate_limiting;
pub mod quotas;
pub mod versioning;
pub mod usage_tracking;
pub mod types;

// Re-export commonly used types
pub use rate_limiting::RateLimiter;
pub use quotas::{QuotaManager, QuotaType};
pub use usage_tracking::UsageTracker;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::Duration;

/// Global rate limiter registry
static RATE_LIMITERS: once_cell::sync::Lazy<Arc<RwLock<HashMap<String, RateLimiter>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Global quota manager
static QUOTA_MANAGER: once_cell::sync::Lazy<Arc<RwLock<QuotaManager>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(QuotaManager::new())));

/// Global usage tracker
static USAGE_TRACKER: once_cell::sync::Lazy<Arc<RwLock<UsageTracker>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(UsageTracker::new())));

/// Initialize the API governance system
pub async fn init() -> Result<()> {
    log::info!("Initializing API governance system");

    // Initialize default rate limiters
    let mut limiters = RATE_LIMITERS.write().await;

    // Default rate limiter for general API endpoints (100 requests per minute)
    limiters.insert(
        "default".to_string(),
        RateLimiter::sliding_window(100, Duration::from_secs(60)),
    );

    // Rate limiter for authentication endpoints (10 requests per minute)
    limiters.insert(
        "auth".to_string(),
        RateLimiter::sliding_window(10, Duration::from_secs(60)),
    );

    // Rate limiter for scan endpoints (20 requests per hour)
    limiters.insert(
        "scan".to_string(),
        RateLimiter::sliding_window(20, Duration::from_secs(3600)),
    );

    // Rate limiter for report generation (10 requests per hour)
    limiters.insert(
        "report".to_string(),
        RateLimiter::sliding_window(10, Duration::from_secs(3600)),
    );

    drop(limiters);

    // Initialize default quota configurations
    let mut quota_manager = QUOTA_MANAGER.write().await;

    // Set default quotas for different plan tiers
    quota_manager.set_default_quota(QuotaType::ApiCalls, 10000); // 10k API calls per day
    quota_manager.set_default_quota(QuotaType::Scans, 100); // 100 scans per day
    quota_manager.set_default_quota(QuotaType::Reports, 50); // 50 reports per day
    quota_manager.set_default_quota(QuotaType::Storage, 1073741824); // 1GB storage

    drop(quota_manager);

    // Initialize usage tracker
    let mut tracker = USAGE_TRACKER.write().await;
    tracker.start_tracking();
    drop(tracker);

    log::info!("API governance system initialized successfully");
    Ok(())
}

/// Check if request should be rate limited
pub async fn check_rate_limit(
    user_id: &str,
    endpoint: &str,
    ip_address: &str,
) -> Result<RateLimitResult> {
    // Determine which rate limiter to use based on endpoint
    let limiter_key = if endpoint.starts_with("/api/auth") {
        "auth"
    } else if endpoint.starts_with("/api/scans") {
        "scan"
    } else if endpoint.starts_with("/api/reports") {
        "report"
    } else {
        "default"
    };

    // Create a composite key from user_id and ip_address for more granular rate limiting
    let rate_limit_key = format!("{}:{}", user_id, ip_address);

    let limiters = RATE_LIMITERS.read().await;
    let limiter = limiters.get(limiter_key).or_else(|| limiters.get("default"));

    match limiter {
        Some(limiter) => {
            let decision = limiter.check(&rate_limit_key).await?;

            // Track this API call for usage metrics
            let mut tracker = USAGE_TRACKER.write().await;
            tracker.record_request(user_id, endpoint);
            drop(tracker);

            // Calculate reset time based on decision
            let reset_at = chrono::Utc::now() + chrono::Duration::seconds(60);

            Ok(RateLimitResult {
                allowed: decision.allowed,
                limit: decision.limit,
                remaining: decision.remaining,
                reset_at,
            })
        }
        None => {
            // No limiter configured - allow by default
            Ok(RateLimitResult {
                allowed: true,
                limit: 100,
                remaining: 100,
                reset_at: chrono::Utc::now() + chrono::Duration::seconds(60),
            })
        }
    }
}

/// Check if request exceeds quota
pub async fn check_quota(
    user_id: &str,
    quota_type: QuotaType,
) -> Result<QuotaCheckResult> {
    let quota_manager = QUOTA_MANAGER.read().await;
    let decision = quota_manager.check_quota(user_id, quota_type, 1).await?;
    drop(quota_manager);

    // If allowed, record the usage
    if decision.allowed {
        let quota_manager = QUOTA_MANAGER.read().await;
        quota_manager.record_usage(user_id, quota_type, 1).await?;
    }

    // Convert QuotaDecision to QuotaCheckResult
    Ok(QuotaCheckResult {
        allowed: decision.allowed,
        quota_limit: decision.quota_limit.unwrap_or(0),
        quota_used: decision.quota_used,
        quota_remaining: decision.quota_remaining.unwrap_or(0),
        period_end: decision.period_end.unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(1)),
    })
}

/// Rate limit result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: chrono::DateTime<chrono::Utc>,
}

/// Quota check result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuotaCheckResult {
    pub allowed: bool,
    pub quota_limit: u64,
    pub quota_used: u64,
    pub quota_remaining: u64,
    pub period_end: chrono::DateTime<chrono::Utc>,
}
