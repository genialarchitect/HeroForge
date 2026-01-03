//! Rate limiting implementation with multiple algorithms

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiting algorithms supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitAlgorithm {
    /// Token bucket algorithm - allows bursts
    TokenBucket,
    /// Leaky bucket algorithm - smooth rate
    LeakyBucket,
    /// Sliding window algorithm - precise rate limiting
    SlidingWindow,
    /// Fixed window algorithm - simple but allows edge-case bursts
    FixedWindow,
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Algorithm to use
    pub algorithm: RateLimitAlgorithm,
    /// Maximum requests per window
    pub max_requests: u64,
    /// Time window for rate limiting
    pub window: Duration,
    /// Enable adaptive rate limiting based on server load
    pub adaptive: bool,
}

/// Rate limiter implementation
pub struct RateLimiter {
    config: RateLimiterConfig,
    state: Arc<RwLock<RateLimiterState>>,
}

#[derive(Debug)]
struct RateLimiterState {
    /// Per-key request tracking
    requests: HashMap<String, RequestTracker>,
    /// Last cleanup time
    last_cleanup: Instant,
}

#[derive(Debug, Clone)]
struct RequestTracker {
    /// Token bucket state
    tokens: f64,
    /// Last update time
    last_update: Instant,
    /// Request timestamps for sliding window
    request_times: Vec<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(RateLimiterState {
                requests: HashMap::new(),
                last_cleanup: Instant::now(),
            })),
        }
    }

    /// Create a token bucket rate limiter
    pub fn token_bucket(max_requests: u64, window: Duration) -> Self {
        Self::new(RateLimiterConfig {
            algorithm: RateLimitAlgorithm::TokenBucket,
            max_requests,
            window,
            adaptive: false,
        })
    }

    /// Create a sliding window rate limiter
    pub fn sliding_window(max_requests: u64, window: Duration) -> Self {
        Self::new(RateLimiterConfig {
            algorithm: RateLimitAlgorithm::SlidingWindow,
            max_requests,
            window,
            adaptive: false,
        })
    }

    /// Check if a request is allowed
    pub async fn check(&self, key: &str) -> Result<RateLimitDecision> {
        let mut state = self.state.write().await;

        // Periodic cleanup of old entries
        if state.last_cleanup.elapsed() > Duration::from_secs(60) {
            self.cleanup(&mut state);
        }

        let decision = match self.config.algorithm {
            RateLimitAlgorithm::TokenBucket => self.check_token_bucket(&mut state, key),
            RateLimitAlgorithm::SlidingWindow => self.check_sliding_window(&mut state, key),
            RateLimitAlgorithm::LeakyBucket => self.check_leaky_bucket(&mut state, key),
            RateLimitAlgorithm::FixedWindow => self.check_fixed_window(&mut state, key),
        };

        Ok(decision)
    }

    /// Token bucket algorithm implementation
    fn check_token_bucket(&self, state: &mut RateLimiterState, key: &str) -> RateLimitDecision {
        let now = Instant::now();
        let tracker = state.requests.entry(key.to_string()).or_insert_with(|| {
            RequestTracker {
                tokens: self.config.max_requests as f64,
                last_update: now,
                request_times: Vec::new(),
            }
        });

        // Refill tokens based on time elapsed
        let elapsed = now.duration_since(tracker.last_update).as_secs_f64();
        let refill_rate = self.config.max_requests as f64 / self.config.window.as_secs_f64();
        tracker.tokens = (tracker.tokens + elapsed * refill_rate).min(self.config.max_requests as f64);
        tracker.last_update = now;

        if tracker.tokens >= 1.0 {
            tracker.tokens -= 1.0;
            RateLimitDecision {
                allowed: true,
                limit: self.config.max_requests,
                remaining: tracker.tokens as u64,
                reset_at: now + self.config.window,
                retry_after: None,
            }
        } else {
            RateLimitDecision {
                allowed: false,
                limit: self.config.max_requests,
                remaining: 0,
                reset_at: now + Duration::from_secs_f64(1.0 / refill_rate),
                retry_after: Some(Duration::from_secs_f64(1.0 / refill_rate)),
            }
        }
    }

    /// Sliding window algorithm implementation
    fn check_sliding_window(&self, state: &mut RateLimiterState, key: &str) -> RateLimitDecision {
        let now = Instant::now();
        let tracker = state.requests.entry(key.to_string()).or_insert_with(|| {
            RequestTracker {
                tokens: self.config.max_requests as f64,
                last_update: now,
                request_times: Vec::new(),
            }
        });

        // Remove requests outside the window
        tracker.request_times.retain(|&t| now.duration_since(t) < self.config.window);

        let current_count = tracker.request_times.len() as u64;

        if current_count < self.config.max_requests {
            tracker.request_times.push(now);
            RateLimitDecision {
                allowed: true,
                limit: self.config.max_requests,
                remaining: self.config.max_requests - current_count - 1,
                reset_at: now + self.config.window,
                retry_after: None,
            }
        } else {
            // Calculate when the oldest request will expire
            let oldest = tracker.request_times.first().unwrap();
            let retry_after = self.config.window - now.duration_since(*oldest);

            RateLimitDecision {
                allowed: false,
                limit: self.config.max_requests,
                remaining: 0,
                reset_at: *oldest + self.config.window,
                retry_after: Some(retry_after),
            }
        }
    }

    /// Leaky bucket algorithm implementation
    ///
    /// The leaky bucket processes requests at a fixed rate. Incoming requests
    /// are queued and "leak" out at a steady rate. If the bucket overflows,
    /// requests are rejected.
    fn check_leaky_bucket(&self, state: &mut RateLimiterState, key: &str) -> RateLimitDecision {
        let now = Instant::now();
        let leak_rate = self.config.max_requests as f64 / self.config.window.as_secs_f64();

        let tracker = state.requests.entry(key.to_string()).or_insert_with(|| {
            RequestTracker {
                tokens: 0.0, // In leaky bucket, this represents the "water level"
                last_update: now,
                request_times: Vec::new(),
            }
        });

        // Calculate how much has "leaked" since last update
        let elapsed = now.duration_since(tracker.last_update).as_secs_f64();
        let leaked = elapsed * leak_rate;

        // Reduce the water level by the amount that leaked (but not below 0)
        tracker.tokens = (tracker.tokens - leaked).max(0.0);
        tracker.last_update = now;

        // Check if we can add a new request (1 unit of "water")
        if tracker.tokens < self.config.max_requests as f64 {
            tracker.tokens += 1.0;
            let remaining = (self.config.max_requests as f64 - tracker.tokens).max(0.0) as u64;

            RateLimitDecision {
                allowed: true,
                limit: self.config.max_requests,
                remaining,
                reset_at: now + self.config.window,
                retry_after: None,
            }
        } else {
            // Bucket is full - calculate when 1 unit will leak
            let time_to_leak_one = 1.0 / leak_rate;

            RateLimitDecision {
                allowed: false,
                limit: self.config.max_requests,
                remaining: 0,
                reset_at: now + Duration::from_secs_f64(time_to_leak_one),
                retry_after: Some(Duration::from_secs_f64(time_to_leak_one)),
            }
        }
    }

    /// Fixed window algorithm implementation
    ///
    /// Divides time into fixed windows and counts requests per window.
    /// Simple and efficient but allows bursts at window boundaries.
    fn check_fixed_window(&self, state: &mut RateLimiterState, key: &str) -> RateLimitDecision {
        let now = Instant::now();

        let tracker = state.requests.entry(key.to_string()).or_insert_with(|| {
            RequestTracker {
                tokens: 0.0, // In fixed window, this represents request count
                last_update: now,
                request_times: Vec::new(),
            }
        });

        // Calculate the elapsed time since window start
        let elapsed_since_start = now.duration_since(tracker.last_update);

        // Check if we've moved to a new window
        if elapsed_since_start >= self.config.window {
            // New window - reset the count
            tracker.tokens = 0.0;
            tracker.last_update = now;
        }

        // Check if we can make a request in this window
        let current_count = tracker.tokens as u64;

        if current_count < self.config.max_requests {
            tracker.tokens += 1.0;
            let remaining = self.config.max_requests - current_count - 1;

            // Calculate when this window ends
            let window_remaining = self.config.window.saturating_sub(elapsed_since_start);

            RateLimitDecision {
                allowed: true,
                limit: self.config.max_requests,
                remaining,
                reset_at: now + window_remaining,
                retry_after: None,
            }
        } else {
            // Window is full - must wait until next window
            let window_remaining = self.config.window.saturating_sub(elapsed_since_start);

            RateLimitDecision {
                allowed: false,
                limit: self.config.max_requests,
                remaining: 0,
                reset_at: now + window_remaining,
                retry_after: Some(window_remaining),
            }
        }
    }

    /// Clean up old entries
    fn cleanup(&self, state: &mut RateLimiterState) {
        let now = Instant::now();
        state.requests.retain(|_, tracker| {
            now.duration_since(tracker.last_update) < self.config.window * 2
        });
        state.last_cleanup = now;
    }
}

/// Rate limit decision
#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Rate limit maximum
    pub limit: u64,
    /// Remaining requests in current window
    pub remaining: u64,
    /// When the rate limit resets
    pub reset_at: Instant,
    /// Recommended retry-after duration
    pub retry_after: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket() {
        let limiter = RateLimiter::token_bucket(5, Duration::from_secs(10));

        // First 5 requests should succeed
        for _ in 0..5 {
            let decision = limiter.check("test-user").await.unwrap();
            assert!(decision.allowed);
        }

        // 6th request should be rate limited
        let decision = limiter.check("test-user").await.unwrap();
        assert!(!decision.allowed);
    }

    #[tokio::test]
    async fn test_sliding_window() {
        let limiter = RateLimiter::sliding_window(3, Duration::from_secs(5));

        // First 3 requests should succeed
        for i in 0..3 {
            let decision = limiter.check("test-user").await.unwrap();
            assert!(decision.allowed, "Request {} should be allowed", i);
        }

        // 4th request should be rate limited
        let decision = limiter.check("test-user").await.unwrap();
        assert!(!decision.allowed);
    }

    #[tokio::test]
    async fn test_per_key_isolation() {
        let limiter = RateLimiter::token_bucket(2, Duration::from_secs(10));

        // User 1 uses their quota
        for _ in 0..2 {
            let decision = limiter.check("user1").await.unwrap();
            assert!(decision.allowed);
        }

        // User 2 should still have their quota
        let decision = limiter.check("user2").await.unwrap();
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn test_leaky_bucket() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            algorithm: RateLimitAlgorithm::LeakyBucket,
            max_requests: 5,
            window: Duration::from_secs(10),
            adaptive: false,
        });

        // First 5 requests should succeed (filling the bucket)
        for i in 0..5 {
            let decision = limiter.check("test-user").await.unwrap();
            assert!(decision.allowed, "Request {} should be allowed", i);
        }

        // 6th request should be rate limited (bucket is full)
        let decision = limiter.check("test-user").await.unwrap();
        assert!(!decision.allowed, "Request 6 should be rate limited");
        assert!(decision.retry_after.is_some(), "Should have retry_after");
    }

    #[tokio::test]
    async fn test_fixed_window() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            algorithm: RateLimitAlgorithm::FixedWindow,
            max_requests: 3,
            window: Duration::from_secs(5),
            adaptive: false,
        });

        // First 3 requests should succeed
        for i in 0..3 {
            let decision = limiter.check("test-user").await.unwrap();
            assert!(decision.allowed, "Request {} should be allowed", i);
        }

        // 4th request should be rate limited
        let decision = limiter.check("test-user").await.unwrap();
        assert!(!decision.allowed, "Request 4 should be rate limited");
        assert!(decision.retry_after.is_some(), "Should have retry_after");
    }

    #[tokio::test]
    async fn test_leaky_bucket_different_users() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            algorithm: RateLimitAlgorithm::LeakyBucket,
            max_requests: 2,
            window: Duration::from_secs(10),
            adaptive: false,
        });

        // User 1 fills their bucket
        for _ in 0..2 {
            let decision = limiter.check("user1").await.unwrap();
            assert!(decision.allowed);
        }
        let decision = limiter.check("user1").await.unwrap();
        assert!(!decision.allowed);

        // User 2 should have their own bucket
        let decision = limiter.check("user2").await.unwrap();
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn test_fixed_window_different_users() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            algorithm: RateLimitAlgorithm::FixedWindow,
            max_requests: 2,
            window: Duration::from_secs(10),
            adaptive: false,
        });

        // User 1 uses their quota
        for _ in 0..2 {
            let decision = limiter.check("user1").await.unwrap();
            assert!(decision.allowed);
        }
        let decision = limiter.check("user1").await.unwrap();
        assert!(!decision.allowed);

        // User 2 should have their own window
        let decision = limiter.check("user2").await.unwrap();
        assert!(decision.allowed);
    }
}
