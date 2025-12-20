//! Rate limiting configuration for API endpoints
//!
//! Implements rate limiting per OWASP guidelines and CIS Controls.
//! Different limits are applied based on endpoint sensitivity:
//!
//! - Authentication endpoints (login, register): Strict limits to prevent brute force
//! - General API endpoints: Moderate limits for normal usage
//! - Resource-intensive endpoints (scans): Stricter limits to prevent abuse

use actix_governor::{Governor, GovernorConfig, GovernorConfigBuilder, PeerIpKeyExtractor};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use std::future::{ready, Ready};
use std::pin::Pin;

use super::rate_limit_stats::{self, RateLimitCategory};

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

// ============================================================================
// Rate Limit Stats Middleware
// ============================================================================

/// Middleware that records rate limit statistics for the dashboard.
/// This should be applied after the Governor rate limiter to track requests.
#[derive(Clone)]
pub struct RateLimitStatsMiddleware {
    category: RateLimitCategory,
}

impl RateLimitStatsMiddleware {
    pub fn new(category: RateLimitCategory) -> Self {
        Self { category }
    }

    pub fn auth() -> Self {
        Self::new(RateLimitCategory::Auth)
    }

    pub fn api() -> Self {
        Self::new(RateLimitCategory::Api)
    }

    pub fn scan() -> Self {
        Self::new(RateLimitCategory::Scan)
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitStatsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitStatsMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitStatsMiddlewareService {
            service,
            category: self.category,
        }))
    }
}

pub struct RateLimitStatsMiddlewareService<S> {
    service: S,
    category: RateLimitCategory,
}

impl<S, B> Service<ServiceRequest> for RateLimitStatsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let category = self.category;
        let endpoint = req.path().to_string();
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        // Extract client IP address
        let ip = get_client_ip(&req);

        // Record the request
        rate_limit_stats::record_request(&ip, category);

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            // Check if the response is a rate limit error (429)
            if res.status() == actix_web::http::StatusCode::TOO_MANY_REQUESTS {
                rate_limit_stats::record_rate_limit_event(
                    &ip,
                    category,
                    &endpoint,
                    user_agent.as_deref(),
                );
            }

            Ok(res)
        })
    }
}

/// Extract client IP address from request headers or peer address
fn get_client_ip(req: &ServiceRequest) -> String {
    // Check X-Forwarded-For header first (for reverse proxy)
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP in the chain
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }
    // Check X-Real-IP header
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }
    // Fall back to peer address
    req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
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
