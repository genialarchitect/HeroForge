//! Rate limiting configuration for API endpoints
//!
//! Implements rate limiting per OWASP guidelines and CIS Controls.
//! Different limits are applied based on endpoint sensitivity:
//!
//! - Authentication endpoints (login, register): Strict limits to prevent brute force
//! - General API endpoints: Moderate limits for normal usage
//! - Resource-intensive endpoints (scans): Stricter limits to prevent abuse

use actix_governor::{Governor, GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor};

/// Rate limiter for authentication endpoints (login, register)
/// Strict limits: 5 requests per minute per IP
pub fn auth_rate_limiter() -> Governor<PeerIpKeyExtractor, actix_governor::governor::middleware::NoOpMiddleware> {
    let config: GovernorConfig<PeerIpKeyExtractor, actix_governor::governor::middleware::NoOpMiddleware> = GovernorConfigBuilder::default()
        .per_second(12)   // ~5 requests per minute = 1 request per 12 seconds refill
        .burst_size(5)    // Allow burst of 5 requests
        .finish()
        .expect("Failed to create auth rate limiter config");

    Governor::new(&config)
}

/// Rate limiter for general API endpoints
/// Moderate limits: 100 requests per minute per IP
pub fn api_rate_limiter() -> Governor<PeerIpKeyExtractor, actix_governor::governor::middleware::NoOpMiddleware> {
    let config: GovernorConfig<PeerIpKeyExtractor, actix_governor::governor::middleware::NoOpMiddleware> = GovernorConfigBuilder::default()
        .per_millisecond(600)  // ~100 requests per minute = 1 request per 600ms refill
        .burst_size(100)       // Allow burst of 100 requests
        .finish()
        .expect("Failed to create API rate limiter config");

    Governor::new(&config)
}

/// Rate limiter for resource-intensive endpoints (scan creation)
/// Strict limits: 10 requests per hour per IP
pub fn scan_rate_limiter() -> Governor<PeerIpKeyExtractor, actix_governor::governor::middleware::NoOpMiddleware> {
    let config: GovernorConfig<PeerIpKeyExtractor, actix_governor::governor::middleware::NoOpMiddleware> = GovernorConfigBuilder::default()
        .per_second(360)  // ~10 requests per hour = 1 request per 360 seconds refill
        .burst_size(10)   // Allow burst of 10 requests
        .finish()
        .expect("Failed to create scan rate limiter config");

    Governor::new(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_rate_limiter_creation() {
        let _limiter = auth_rate_limiter();
    }

    #[test]
    fn test_api_rate_limiter_creation() {
        let _limiter = api_rate_limiter();
    }

    #[test]
    fn test_scan_rate_limiter_creation() {
        let _limiter = scan_rate_limiter();
    }
}
