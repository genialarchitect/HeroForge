//! Type definitions for API governance

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Algorithm to use for rate limiting
    pub algorithm: RateLimitAlgorithmType,
    /// Per-user rate limit
    pub per_user_limit: Option<RateLimitRule>,
    /// Per-IP rate limit
    pub per_ip_limit: Option<RateLimitRule>,
    /// Per-API-key rate limit
    pub per_api_key_limit: Option<RateLimitRule>,
    /// Endpoint-specific limits
    pub endpoint_limits: Vec<EndpointLimit>,
}

/// Rate limit algorithm type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitAlgorithmType {
    TokenBucket,
    LeakyBucket,
    SlidingWindow,
    FixedWindow,
}

/// Rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Maximum number of requests
    pub limit: u64,
    /// Time window for the limit
    pub window: Duration,
}

/// Endpoint-specific rate limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointLimit {
    /// Endpoint pattern (e.g., "/api/scans", "/api/auth/*")
    pub endpoint: String,
    /// Rate limit for this endpoint
    pub limit: RateLimitRule,
}

/// API version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVersionInfo {
    /// Version identifier (e.g., "v1", "v2")
    pub version: String,
    /// Human-readable version name
    pub name: String,
    /// Version status
    pub status: VersionStatus,
    /// Release date
    pub release_date: chrono::DateTime<chrono::Utc>,
    /// Deprecation date (if deprecated)
    pub deprecation_date: Option<chrono::DateTime<chrono::Utc>>,
    /// Sunset date (when version will be removed)
    pub sunset_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// API version status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionStatus {
    Active,
    Deprecated,
    Sunset,
}

/// Usage metrics for a specific period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageStats {
    /// User or tenant ID
    pub user_id: String,
    /// Total API calls
    pub total_calls: u64,
    /// Data transferred (bytes)
    pub data_transferred: u64,
    /// Storage used (bytes)
    pub storage_used: u64,
    /// Number of scans performed
    pub scans_performed: u64,
    /// Period start
    pub period_start: chrono::DateTime<chrono::Utc>,
    /// Period end
    pub period_end: chrono::DateTime<chrono::Utc>,
    /// Cost attribution (if applicable)
    pub estimated_cost: Option<f64>,
}

/// Quota configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaConfig {
    /// Quota type
    pub quota_type: String,
    /// Quota limit
    pub limit: u64,
    /// Quota period
    pub period: QuotaPeriod,
    /// Overage action
    pub overage_action: OverageAction,
    /// Alert threshold (0.0-1.0)
    pub alert_threshold: f64,
}

/// Quota period
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuotaPeriod {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

/// Action to take when quota is exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverageAction {
    /// Block requests
    Block,
    /// Allow with warning
    Warn,
    /// Charge overage fees
    Charge,
}
