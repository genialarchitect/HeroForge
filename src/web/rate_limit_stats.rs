//! Rate limit statistics tracking for the API Rate Limit Dashboard.
//!
//! Provides in-memory tracking of:
//! - Request counts by IP and endpoint category
//! - Rate limit events (blocked requests)
//! - Top requesting IPs
//!
//! Stats are kept in memory with a configurable retention period.

use chrono::{DateTime, Utc, Duration};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Maximum number of rate limit events to keep in history
const MAX_EVENTS: usize = 1000;

/// Maximum time to keep request count data (in hours)
const REQUEST_RETENTION_HOURS: i64 = 24;

/// Rate limit category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitCategory {
    Auth,
    Api,
    Scan,
}

impl std::fmt::Display for RateLimitCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitCategory::Auth => write!(f, "auth"),
            RateLimitCategory::Api => write!(f, "api"),
            RateLimitCategory::Scan => write!(f, "scan"),
        }
    }
}

/// A single rate limit event (when a request is blocked)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitEvent {
    pub id: String,
    pub ip: String,
    pub category: RateLimitCategory,
    pub endpoint: String,
    pub timestamp: DateTime<Utc>,
    pub user_agent: Option<String>,
}

/// Request count entry for tracking requests over time
#[derive(Debug, Clone)]
struct RequestEntry {
    timestamp: DateTime<Utc>,
    ip: String,
    category: RateLimitCategory,
}

/// IP statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpStats {
    pub ip: String,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub last_seen: DateTime<Utc>,
    pub requests_by_category: HashMap<String, u64>,
}

/// Current rate limit configuration for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub category: RateLimitCategory,
    pub name: String,
    pub requests_per_period: u32,
    pub period: String,
    pub burst_size: u32,
    pub description: String,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSummary {
    pub total_requests_24h: u64,
    pub blocked_requests_24h: u64,
    pub block_rate_percent: f64,
    pub unique_ips_24h: u64,
    pub requests_by_category: HashMap<String, u64>,
    pub blocked_by_category: HashMap<String, u64>,
}

/// Time series data point for requests over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTimePoint {
    pub timestamp: DateTime<Utc>,
    pub total_requests: u64,
    pub blocked_requests: u64,
}

/// Full dashboard response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitDashboardData {
    pub configs: Vec<RateLimitConfig>,
    pub summary: RateLimitSummary,
    pub recent_events: Vec<RateLimitEvent>,
    pub top_ips: Vec<IpStats>,
    pub requests_over_time: Vec<RequestTimePoint>,
}

/// In-memory rate limit statistics tracker
#[derive(Debug)]
pub struct RateLimitStats {
    /// Recent rate limit events (blocked requests)
    events: RwLock<VecDeque<RateLimitEvent>>,
    /// Request tracking for time-series data
    requests: RwLock<VecDeque<RequestEntry>>,
    /// Per-IP statistics
    ip_stats: RwLock<HashMap<String, IpStats>>,
}

impl Default for RateLimitStats {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitStats {
    /// Create a new rate limit stats tracker
    pub fn new() -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(MAX_EVENTS)),
            requests: RwLock::new(VecDeque::new()),
            ip_stats: RwLock::new(HashMap::new()),
        }
    }

    /// Record a request (successful or not)
    pub fn record_request(&self, ip: &str, category: RateLimitCategory) {
        let now = Utc::now();

        // Add to request history
        {
            let mut requests = self.requests.write();
            requests.push_back(RequestEntry {
                timestamp: now,
                ip: ip.to_string(),
                category,
            });

            // Clean up old entries
            let cutoff = now - Duration::hours(REQUEST_RETENTION_HOURS);
            while let Some(front) = requests.front() {
                if front.timestamp < cutoff {
                    requests.pop_front();
                } else {
                    break;
                }
            }
        }

        // Update IP stats
        {
            let mut ip_stats = self.ip_stats.write();
            let stats = ip_stats.entry(ip.to_string()).or_insert_with(|| IpStats {
                ip: ip.to_string(),
                total_requests: 0,
                blocked_requests: 0,
                last_seen: now,
                requests_by_category: HashMap::new(),
            });

            stats.total_requests += 1;
            stats.last_seen = now;
            *stats.requests_by_category.entry(category.to_string()).or_insert(0) += 1;
        }
    }

    /// Record a rate limit event (blocked request)
    pub fn record_rate_limit_event(
        &self,
        ip: &str,
        category: RateLimitCategory,
        endpoint: &str,
        user_agent: Option<&str>,
    ) {
        let now = Utc::now();
        let event = RateLimitEvent {
            id: uuid::Uuid::new_v4().to_string(),
            ip: ip.to_string(),
            category,
            endpoint: endpoint.to_string(),
            timestamp: now,
            user_agent: user_agent.map(|s| s.to_string()),
        };

        // Add to events
        {
            let mut events = self.events.write();
            events.push_back(event);

            // Trim to max size
            while events.len() > MAX_EVENTS {
                events.pop_front();
            }
        }

        // Update IP blocked count
        {
            let mut ip_stats = self.ip_stats.write();
            if let Some(stats) = ip_stats.get_mut(ip) {
                stats.blocked_requests += 1;
            }
        }
    }

    /// Get the current rate limit configurations
    pub fn get_configs() -> Vec<RateLimitConfig> {
        vec![
            RateLimitConfig {
                category: RateLimitCategory::Auth,
                name: "Authentication".to_string(),
                requests_per_period: 5,
                period: "minute".to_string(),
                burst_size: 5,
                description: "Login, register, and password reset endpoints".to_string(),
            },
            RateLimitConfig {
                category: RateLimitCategory::Api,
                name: "General API".to_string(),
                requests_per_period: 100,
                period: "minute".to_string(),
                burst_size: 100,
                description: "All protected API endpoints".to_string(),
            },
            RateLimitConfig {
                category: RateLimitCategory::Scan,
                name: "Scan Creation".to_string(),
                requests_per_period: 10,
                period: "hour".to_string(),
                burst_size: 10,
                description: "Creating new scans (resource intensive)".to_string(),
            },
        ]
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> RateLimitSummary {
        let now = Utc::now();
        let cutoff_24h = now - Duration::hours(24);

        let requests = self.requests.read();
        let events = self.events.read();

        let mut requests_by_category: HashMap<String, u64> = HashMap::new();
        let mut blocked_by_category: HashMap<String, u64> = HashMap::new();

        // Count requests in last 24h
        let recent_requests: Vec<_> = requests
            .iter()
            .filter(|r| r.timestamp >= cutoff_24h)
            .collect();

        let total_requests_24h = recent_requests.len() as u64;

        // Count unique IPs
        let unique_ips: std::collections::HashSet<_> = recent_requests
            .iter()
            .map(|r| &r.ip)
            .collect();
        let unique_ips_24h = unique_ips.len() as u64;

        // Count by category
        for req in &recent_requests {
            *requests_by_category.entry(req.category.to_string()).or_insert(0) += 1;
        }

        // Count blocked in last 24h
        let blocked_events: Vec<_> = events
            .iter()
            .filter(|e| e.timestamp >= cutoff_24h)
            .collect();

        let blocked_requests_24h = blocked_events.len() as u64;

        for event in &blocked_events {
            *blocked_by_category.entry(event.category.to_string()).or_insert(0) += 1;
        }

        let block_rate_percent = if total_requests_24h > 0 {
            (blocked_requests_24h as f64 / total_requests_24h as f64) * 100.0
        } else {
            0.0
        };

        RateLimitSummary {
            total_requests_24h,
            blocked_requests_24h,
            block_rate_percent,
            unique_ips_24h,
            requests_by_category,
            blocked_by_category,
        }
    }

    /// Get recent rate limit events
    pub fn get_recent_events(&self, limit: usize) -> Vec<RateLimitEvent> {
        let events = self.events.read();
        events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get top IPs by request count
    pub fn get_top_ips(&self, limit: usize) -> Vec<IpStats> {
        let now = Utc::now();
        let cutoff = now - Duration::hours(24);

        let ip_stats = self.ip_stats.read();
        let mut stats: Vec<_> = ip_stats
            .values()
            .filter(|s| s.last_seen >= cutoff)
            .cloned()
            .collect();

        stats.sort_by(|a, b| b.total_requests.cmp(&a.total_requests));
        stats.truncate(limit);
        stats
    }

    /// Get requests over time (hourly buckets for last 24h)
    pub fn get_requests_over_time(&self) -> Vec<RequestTimePoint> {
        let now = Utc::now();
        let requests = self.requests.read();
        let events = self.events.read();

        // Create hourly buckets for last 24 hours
        let mut buckets: Vec<RequestTimePoint> = Vec::with_capacity(24);

        for i in 0..24 {
            let bucket_start = now - Duration::hours(23 - i);
            let bucket_end = bucket_start + Duration::hours(1);

            let total = requests
                .iter()
                .filter(|req| req.timestamp >= bucket_start && req.timestamp < bucket_end)
                .count() as u64;

            let blocked = events
                .iter()
                .filter(|ev| ev.timestamp >= bucket_start && ev.timestamp < bucket_end)
                .count() as u64;

            buckets.push(RequestTimePoint {
                timestamp: bucket_start,
                total_requests: total,
                blocked_requests: blocked,
            });
        }

        buckets
    }

    /// Get full dashboard data
    pub fn get_dashboard_data(&self) -> RateLimitDashboardData {
        RateLimitDashboardData {
            configs: Self::get_configs(),
            summary: self.get_summary(),
            recent_events: self.get_recent_events(50),
            top_ips: self.get_top_ips(20),
            requests_over_time: self.get_requests_over_time(),
        }
    }

    /// Clean up old data (call periodically)
    pub fn cleanup(&self) {
        let now = Utc::now();
        let cutoff = now - Duration::hours(REQUEST_RETENTION_HOURS);

        // Clean old requests
        {
            let mut requests = self.requests.write();
            while let Some(front) = requests.front() {
                if front.timestamp < cutoff {
                    requests.pop_front();
                } else {
                    break;
                }
            }
        }

        // Clean old IP stats
        {
            let mut ip_stats = self.ip_stats.write();
            ip_stats.retain(|_, stats| stats.last_seen >= cutoff);
        }
    }
}

/// Global rate limit stats instance
pub static RATE_LIMIT_STATS: Lazy<Arc<RateLimitStats>> = Lazy::new(|| Arc::new(RateLimitStats::new()));

/// Record a request to the global stats tracker
pub fn record_request(ip: &str, category: RateLimitCategory) {
    RATE_LIMIT_STATS.record_request(ip, category);
}

/// Record a rate limit event to the global stats tracker
pub fn record_rate_limit_event(
    ip: &str,
    category: RateLimitCategory,
    endpoint: &str,
    user_agent: Option<&str>,
) {
    RATE_LIMIT_STATS.record_rate_limit_event(ip, category, endpoint, user_agent);
}

/// Get dashboard data from the global stats tracker
pub fn get_dashboard_data() -> RateLimitDashboardData {
    RATE_LIMIT_STATS.get_dashboard_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_stats_creation() {
        let stats = RateLimitStats::new();
        let summary = stats.get_summary();
        assert_eq!(summary.total_requests_24h, 0);
        assert_eq!(summary.blocked_requests_24h, 0);
    }

    #[test]
    fn test_record_request() {
        let stats = RateLimitStats::new();
        stats.record_request("192.168.1.1", RateLimitCategory::Api);
        stats.record_request("192.168.1.1", RateLimitCategory::Api);
        stats.record_request("192.168.1.2", RateLimitCategory::Auth);

        let summary = stats.get_summary();
        assert_eq!(summary.total_requests_24h, 3);
        assert_eq!(summary.unique_ips_24h, 2);
    }

    #[test]
    fn test_record_rate_limit_event() {
        let stats = RateLimitStats::new();
        stats.record_request("192.168.1.1", RateLimitCategory::Auth);
        stats.record_rate_limit_event(
            "192.168.1.1",
            RateLimitCategory::Auth,
            "/api/auth/login",
            Some("Mozilla/5.0"),
        );

        let events = stats.get_recent_events(10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ip, "192.168.1.1");
    }

    #[test]
    fn test_top_ips() {
        let stats = RateLimitStats::new();

        // IP 1 makes 5 requests
        for _ in 0..5 {
            stats.record_request("192.168.1.1", RateLimitCategory::Api);
        }

        // IP 2 makes 10 requests
        for _ in 0..10 {
            stats.record_request("192.168.1.2", RateLimitCategory::Api);
        }

        let top = stats.get_top_ips(10);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].ip, "192.168.1.2"); // Higher count first
        assert_eq!(top[0].total_requests, 10);
    }

    #[test]
    fn test_get_configs() {
        let configs = RateLimitStats::get_configs();
        assert_eq!(configs.len(), 3);
        assert!(configs.iter().any(|c| c.category == RateLimitCategory::Auth));
        assert!(configs.iter().any(|c| c.category == RateLimitCategory::Api));
        assert!(configs.iter().any(|c| c.category == RateLimitCategory::Scan));
    }
}
