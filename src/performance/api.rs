//! API performance optimization

use super::types::*;
use anyhow::Result;
use std::collections::HashMap;

/// API optimization recommendation
#[derive(Debug, Clone)]
pub struct APIOptimization {
    pub category: APIOptimizationCategory,
    pub description: String,
    pub estimated_improvement: String,
    pub priority: Priority,
}

/// API optimization categories
#[derive(Debug, Clone)]
pub enum APIOptimizationCategory {
    DataFetching,
    Compression,
    Caching,
    RateLimiting,
    Protocol,
    Batching,
}

/// Priority level
#[derive(Debug, Clone)]
pub enum Priority {
    High,
    Medium,
    Low,
}

/// Rate limiter state (Token Bucket algorithm)
#[derive(Debug, Clone)]
pub struct TokenBucket {
    pub capacity: usize,
    pub tokens: usize,
    pub refill_rate: usize, // tokens per second
    pub last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(capacity: usize, refill_rate: usize) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs() as usize;
        let new_tokens = elapsed * self.refill_rate;

        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// Sliding window rate limiter
#[derive(Debug, Clone)]
pub struct SlidingWindowCounter {
    pub window_size_secs: u64,
    pub max_requests: usize,
    pub current_count: usize,
    pub previous_count: usize,
    pub window_start: std::time::Instant,
}

impl SlidingWindowCounter {
    fn new(window_size_secs: u64, max_requests: usize) -> Self {
        Self {
            window_size_secs,
            max_requests,
            current_count: 0,
            previous_count: 0,
            window_start: std::time::Instant::now(),
        }
    }

    fn is_allowed(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs();

        // Slide window if needed
        if elapsed >= self.window_size_secs {
            self.previous_count = self.current_count;
            self.current_count = 0;
            self.window_start = now;
        }

        // Calculate weighted count using sliding window
        let progress = (elapsed as f64) / (self.window_size_secs as f64);
        let weighted_count = ((1.0 - progress) * self.previous_count as f64) + self.current_count as f64;

        if weighted_count < self.max_requests as f64 {
            self.current_count += 1;
            true
        } else {
            false
        }
    }
}

/// Generate API optimization recommendations
fn generate_recommendations(config: &APIConfig) -> Vec<APIOptimization> {
    let mut recommendations = Vec::new();

    // GraphQL recommendation
    if config.enable_graphql {
        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::DataFetching,
            description: "GraphQL enables clients to request exactly the data they need".to_string(),
            estimated_improvement: "Reduce over-fetching by 40-60%".to_string(),
            priority: Priority::High,
        });

        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::DataFetching,
            description: "Implement DataLoader for N+1 query prevention".to_string(),
            estimated_improvement: "Reduce database queries by 80%".to_string(),
            priority: Priority::High,
        });
    }

    // Compression recommendations
    if config.enable_compression {
        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::Compression,
            description: "Enable Brotli compression for text responses".to_string(),
            estimated_improvement: "15-25% smaller than gzip".to_string(),
            priority: Priority::High,
        });

        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::Compression,
            description: "Use gzip for broader browser compatibility".to_string(),
            estimated_improvement: "60-80% size reduction".to_string(),
            priority: Priority::Medium,
        });
    }

    // Batching recommendations
    if config.enable_batching {
        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::Batching,
            description: "Implement request batching for multiple operations".to_string(),
            estimated_improvement: "Reduce round trips by 70%".to_string(),
            priority: Priority::Medium,
        });
    }

    // Caching recommendations
    if config.enable_caching {
        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::Caching,
            description: "Implement ETag-based caching for conditional requests".to_string(),
            estimated_improvement: "304 responses save bandwidth".to_string(),
            priority: Priority::High,
        });

        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::Caching,
            description: "Add Cache-Control headers for static responses".to_string(),
            estimated_improvement: "Reduce server load by 50%".to_string(),
            priority: Priority::High,
        });

        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::Caching,
            description: "Use Redis for API response caching".to_string(),
            estimated_improvement: "Sub-millisecond cache hits".to_string(),
            priority: Priority::Medium,
        });
    }

    // Rate limiting recommendations
    if config.rate_limiting.requests_per_second > 0 {
        recommendations.push(APIOptimization {
            category: APIOptimizationCategory::RateLimiting,
            description: format!(
                "Token bucket rate limiting: {} req/s, burst: {}",
                config.rate_limiting.requests_per_second,
                config.rate_limiting.burst_size
            ),
            estimated_improvement: "Protect against abuse and ensure fair usage".to_string(),
            priority: Priority::High,
        });

        if config.rate_limiting.per_user_limits {
            recommendations.push(APIOptimization {
                category: APIOptimizationCategory::RateLimiting,
                description: "Per-user rate limiting with Redis".to_string(),
                estimated_improvement: "Isolated limits prevent noisy neighbors".to_string(),
                priority: Priority::Medium,
            });
        }
    }

    // Protocol recommendations
    recommendations.push(APIOptimization {
        category: APIOptimizationCategory::Protocol,
        description: "Enable HTTP/2 for multiplexed requests".to_string(),
        estimated_improvement: "Multiple requests over single connection".to_string(),
        priority: Priority::High,
    });

    recommendations.push(APIOptimization {
        category: APIOptimizationCategory::Protocol,
        description: "Keep-alive connections to reduce handshake overhead".to_string(),
        estimated_improvement: "Save 100-200ms per request".to_string(),
        priority: Priority::Medium,
    });

    recommendations.push(APIOptimization {
        category: APIOptimizationCategory::Protocol,
        description: "Consider gRPC for internal service communication".to_string(),
        estimated_improvement: "Binary protocol, 10x faster than REST".to_string(),
        priority: Priority::Low,
    });

    recommendations
}

/// Estimate response time based on optimizations
fn estimate_response_time(config: &APIConfig) -> (f64, f64) {
    let mut avg_time = 150.0; // Base average response time in ms
    let mut p95_time = 500.0; // Base P95 response time in ms

    // GraphQL reduces over-fetching
    if config.enable_graphql {
        avg_time *= 0.7;
        p95_time *= 0.75;
    }

    // Caching dramatically improves response times
    if config.enable_caching {
        avg_time *= 0.4; // Cache hits are fast
        p95_time *= 0.5;
    }

    // Batching reduces per-request overhead
    if config.enable_batching {
        avg_time *= 0.85;
        p95_time *= 0.9;
    }

    (f64::max(avg_time, 5.0), f64::max(p95_time, 20.0))
}

/// Estimate throughput based on configuration
fn estimate_throughput(config: &APIConfig) -> f64 {
    let mut base_rps = 1000.0; // Base requests per second

    // GraphQL can handle more complex queries efficiently
    if config.enable_graphql {
        base_rps *= 0.8; // Slightly lower raw throughput but more efficient
    }

    // Caching increases effective throughput
    if config.enable_caching {
        base_rps *= 3.0; // Cache hits are much faster
    }

    // Batching improves throughput
    if config.enable_batching {
        base_rps *= 1.5;
    }

    // Rate limiting caps throughput (but protects the system)
    if config.rate_limiting.requests_per_second > 0 {
        base_rps = f64::min(base_rps, config.rate_limiting.requests_per_second as f64 * 10.0);
    }

    base_rps
}

/// Estimate compression ratio
fn estimate_compression_ratio(config: &APIConfig) -> f64 {
    if !config.enable_compression {
        return 1.0; // No compression
    }

    // Typical JSON compression ratios
    // Brotli: ~85% compression (0.15 ratio)
    // Gzip: ~75% compression (0.25 ratio)
    0.20 // Assume Brotli with good settings
}

/// Optimize API performance
pub async fn optimize_api(config: &APIConfig) -> Result<APIMetrics> {
    log::info!("Analyzing API performance configuration");

    // Generate recommendations
    let recommendations = generate_recommendations(config);

    for rec in &recommendations {
        log::info!(
            "API optimization ({:?}): {} - {} [{:?} priority]",
            rec.category,
            rec.description,
            rec.estimated_improvement,
            rec.priority
        );
    }

    // Demonstrate rate limiting algorithms
    log::debug!("Rate limiting algorithms available:");
    let _token_bucket = TokenBucket::new(
        config.rate_limiting.burst_size,
        config.rate_limiting.requests_per_second,
    );
    log::debug!(
        "  - Token bucket: {} capacity, {} refill/s",
        config.rate_limiting.burst_size,
        config.rate_limiting.requests_per_second
    );

    let _sliding_window = SlidingWindowCounter::new(60, config.rate_limiting.requests_per_second * 60);
    log::debug!(
        "  - Sliding window: {} requests per minute",
        config.rate_limiting.requests_per_second * 60
    );

    // Estimate metrics
    let (average_response_time_ms, p95_response_time_ms) = estimate_response_time(config);
    let throughput_rps = estimate_throughput(config);
    let compression_ratio = estimate_compression_ratio(config);

    log::info!(
        "Estimated performance: {:.1}ms avg, {:.1}ms P95, {:.0} RPS, {:.0}% compression",
        average_response_time_ms,
        p95_response_time_ms,
        throughput_rps,
        (1.0 - compression_ratio) * 100.0
    );

    // Additional protocol recommendations
    log::info!("Protocol recommendations:");
    log::info!("  - Enable HTTP/2 in Traefik/nginx configuration");
    log::info!("  - Set Connection: keep-alive with appropriate timeout");
    log::info!("  - Consider HTTP/3 (QUIC) for improved mobile performance");

    Ok(APIMetrics {
        average_response_time_ms,
        p95_response_time_ms,
        throughput_rps,
        compression_ratio,
    })
}
