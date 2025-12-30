//! TTL (Time-To-Live) management for cache entries

use std::time::Duration;

/// Recommended TTL values for different data types
pub struct TtlRecommendations;

impl TtlRecommendations {
    /// Scan results: 24 hours (relatively static)
    pub fn scan_results() -> Duration {
        Duration::from_secs(86400)
    }

    /// User sessions: 30 minutes (security-sensitive)
    pub fn user_sessions() -> Duration {
        Duration::from_secs(1800)
    }

    /// Vulnerability data: 6 hours (updates periodically)
    pub fn vulnerability_data() -> Duration {
        Duration::from_secs(21600)
    }

    /// API responses: 5 minutes (balance freshness and performance)
    pub fn api_responses() -> Duration {
        Duration::from_secs(300)
    }

    /// Threat intelligence: 1 hour (updates frequently)
    pub fn threat_intel() -> Duration {
        Duration::from_secs(3600)
    }

    /// Asset inventory: 12 hours (relatively stable)
    pub fn asset_inventory() -> Duration {
        Duration::from_secs(43200)
    }

    /// Compliance reports: 24 hours (generated periodically)
    pub fn compliance_reports() -> Duration {
        Duration::from_secs(86400)
    }

    /// Temporary data: 5 minutes
    pub fn temporary() -> Duration {
        Duration::from_secs(300)
    }

    /// Long-lived data: 7 days
    pub fn long_lived() -> Duration {
        Duration::from_secs(604800)
    }
}

/// Dynamic TTL calculator based on data access patterns
pub struct DynamicTtl;

impl DynamicTtl {
    /// Calculate TTL based on access frequency
    pub fn calculate_from_access_frequency(access_count: u64) -> Duration {
        match access_count {
            0..=10 => Duration::from_secs(300),      // 5 minutes - rarely accessed
            11..=100 => Duration::from_secs(3600),   // 1 hour - occasionally accessed
            101..=1000 => Duration::from_secs(21600), // 6 hours - frequently accessed
            _ => Duration::from_secs(86400),         // 24 hours - very frequently accessed
        }
    }

    /// Calculate TTL based on data size
    pub fn calculate_from_size(size_bytes: usize) -> Duration {
        match size_bytes {
            0..=1024 => Duration::from_secs(86400),     // 24 hours - small data
            1025..=102400 => Duration::from_secs(43200), // 12 hours - medium data
            102401..=1048576 => Duration::from_secs(21600), // 6 hours - large data
            _ => Duration::from_secs(3600),             // 1 hour - very large data
        }
    }
}
