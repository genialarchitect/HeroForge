//! Rate Limiting Testing Module
//!
//! Tests for rate limiting bypass and resource exhaustion vulnerabilities:
//! - Missing rate limiting
//! - Weak rate limiting
//! - Rate limit bypass techniques

use anyhow::Result;
use log::{debug, info};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::{
    discovery::ApiEndpoint, ApiSecurityConfig, ApiSecurityFinding, ApiSecuritySeverity,
    ApiSecurityTestType, OwaspApiCategory,
};

/// Result of rate limit testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitTestResult {
    pub endpoint: String,
    pub requests_sent: u32,
    pub requests_succeeded: u32,
    pub rate_limited: bool,
    pub rate_limit_header: Option<String>,
    pub bypass_possible: bool,
}

/// Number of requests to send for rate limit testing
const RATE_LIMIT_TEST_COUNT: u32 = 20;

/// Threshold for considering rate limiting effective
const RATE_LIMIT_THRESHOLD: f32 = 0.8; // 80% of requests should succeed without rate limiting

/// Common rate limit headers to check
const RATE_LIMIT_HEADERS: &[&str] = &[
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
];

/// Headers that might bypass rate limiting
const BYPASS_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-For", "1.2.3.4"),
    ("X-Forwarded-For", "10.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "1.2.3.4"),
    ("X-Remote-IP", "1.2.3.4"),
    ("X-Client-IP", "1.2.3.4"),
    ("X-Originating-IP", "1.2.3.4"),
    ("True-Client-IP", "1.2.3.4"),
    ("CF-Connecting-IP", "1.2.3.4"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
];

/// Test rate limiting on an endpoint
pub async fn test_rate_limit(
    client: &Client,
    config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();

    info!(
        "Testing rate limiting on {} {}",
        endpoint.method, endpoint.path
    );

    let url = build_endpoint_url(&config.target_url, &endpoint.path);
    let method = endpoint.method.parse::<Method>().unwrap_or(Method::GET);

    // Phase 1: Check for rate limiting
    let (rate_limited, successful_requests, rate_limit_info) =
        test_basic_rate_limit(client, &method, &url).await?;

    if !rate_limited {
        findings.push(ApiSecurityFinding {
            finding_type: ApiSecurityTestType::RateLimitBypass,
            severity: ApiSecuritySeverity::Medium,
            title: format!(
                "Missing Rate Limiting on {} {}",
                endpoint.method, endpoint.path
            ),
            description: format!(
                "The endpoint {} {} does not appear to have rate limiting in place. {} out of {} requests succeeded without any throttling.",
                endpoint.method, endpoint.path, successful_requests, RATE_LIMIT_TEST_COUNT
            ),
            endpoint_path: Some(endpoint.path.clone()),
            endpoint_method: Some(endpoint.method.clone()),
            request: None,
            response: None,
            evidence: HashMap::from([
                (
                    "requests_sent".to_string(),
                    serde_json::json!(RATE_LIMIT_TEST_COUNT),
                ),
                (
                    "requests_succeeded".to_string(),
                    serde_json::json!(successful_requests),
                ),
                ("rate_limited".to_string(), serde_json::json!(false)),
            ]),
            remediation: "Implement rate limiting to protect against brute force attacks and DoS. Consider using a progressive rate limiting strategy that increases delays after repeated requests.".to_string(),
            cwe_ids: vec![770, 307],
            owasp_category: Some(OwaspApiCategory::UnrestrictedResourceConsumption),
        });
    } else {
        debug!(
            "Rate limiting detected: {} successful out of {}",
            successful_requests, RATE_LIMIT_TEST_COUNT
        );

        // Phase 2: Try to bypass rate limiting
        let bypass_findings =
            test_rate_limit_bypass(client, config, endpoint, &url, &method).await?;
        findings.extend(bypass_findings);
    }

    // Store rate limit header info if detected
    if let Some(info) = rate_limit_info {
        debug!("Rate limit headers detected: {:?}", info);
    }

    Ok(findings)
}

/// Test basic rate limiting by sending multiple requests quickly
async fn test_basic_rate_limit(
    client: &Client,
    method: &Method,
    url: &str,
) -> Result<(bool, u32, Option<HashMap<String, String>>)> {
    let mut successful_requests = 0;
    let mut rate_limit_info: Option<HashMap<String, String>> = None;
    let mut rate_limited = false;

    let start = Instant::now();

    for i in 0..RATE_LIMIT_TEST_COUNT {
        let req = match *method {
            Method::GET => client.get(url),
            Method::POST => client.post(url),
            Method::PUT => client.put(url),
            Method::DELETE => client.delete(url),
            _ => client.get(url),
        };

        match req.send().await {
            Ok(response) => {
                let status = response.status();

                // Check for rate limit headers
                let headers = response.headers();
                let mut found_headers = HashMap::new();
                for header_name in RATE_LIMIT_HEADERS {
                    if let Some(value) = headers.get(*header_name) {
                        if let Ok(v) = value.to_str() {
                            found_headers.insert(header_name.to_string(), v.to_string());
                        }
                    }
                }

                if !found_headers.is_empty() {
                    rate_limit_info = Some(found_headers);
                }

                // Check if rate limited
                if status.as_u16() == 429 {
                    rate_limited = true;
                    debug!("Rate limited at request {}", i + 1);
                } else if status.is_success() || status.is_client_error() {
                    successful_requests += 1;
                }
            }
            Err(e) => {
                debug!("Request {} failed: {}", i + 1, e);
            }
        }

        // Small delay between requests (but still fast enough to trigger rate limiting)
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let duration = start.elapsed();
    debug!(
        "Rate limit test completed in {:.2}s: {} successful, rate_limited={}",
        duration.as_secs_f64(),
        successful_requests,
        rate_limited
    );

    // Consider rate limiting effective if we got blocked or less than threshold succeeded
    let effective_rate_limiting = rate_limited
        || (successful_requests as f32 / RATE_LIMIT_TEST_COUNT as f32) < RATE_LIMIT_THRESHOLD;

    Ok((effective_rate_limiting, successful_requests, rate_limit_info))
}

/// Test for rate limit bypass techniques
async fn test_rate_limit_bypass(
    client: &Client,
    _config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
    url: &str,
    method: &Method,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();

    info!(
        "Testing rate limit bypass techniques on {} {}",
        endpoint.method, endpoint.path
    );

    // Test each bypass header
    for (header_name, header_value) in BYPASS_HEADERS {
        let mut bypass_succeeded = 0;
        let test_count = 10;

        for i in 0..test_count {
            let req = match *method {
                Method::GET => client.get(url),
                Method::POST => client.post(url),
                Method::PUT => client.put(url),
                Method::DELETE => client.delete(url),
                _ => client.get(url),
            };

            // Add varying IP addresses for X-Forwarded-For tests
            let value = if *header_name == "X-Forwarded-For" {
                format!("{}.{}", header_value.trim_end_matches(".4"), i + 10)
            } else {
                header_value.to_string()
            };

            let req = req.header(*header_name, &value);

            match req.send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() || (status.is_client_error() && status.as_u16() != 429) {
                        bypass_succeeded += 1;
                    }
                }
                Err(_) => {}
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // If most requests succeeded with this header, it might be a bypass
        if bypass_succeeded >= (test_count * 8 / 10) {
            findings.push(ApiSecurityFinding {
                finding_type: ApiSecurityTestType::RateLimitBypass,
                severity: ApiSecuritySeverity::High,
                title: format!(
                    "Rate Limit Bypass via {} header on {} {}",
                    header_name, endpoint.method, endpoint.path
                ),
                description: format!(
                    "The rate limiting on {} {} can be bypassed by manipulating the {} header. {} out of {} requests succeeded with this header.",
                    endpoint.method, endpoint.path, header_name, bypass_succeeded, test_count
                ),
                endpoint_path: Some(endpoint.path.clone()),
                endpoint_method: Some(endpoint.method.clone()),
                request: Some(format!("{}: {}", header_name, header_value)),
                response: None,
                evidence: HashMap::from([
                    ("bypass_header".to_string(), serde_json::json!(header_name)),
                    ("requests_sent".to_string(), serde_json::json!(test_count)),
                    ("requests_succeeded".to_string(), serde_json::json!(bypass_succeeded)),
                ]),
                remediation: format!(
                    "Do not trust the {} header for rate limiting decisions. Rate limiting should be based on authenticated user identity or a combination of factors that cannot be spoofed.",
                    header_name
                ),
                cwe_ids: vec![770, 290],
                owasp_category: Some(OwaspApiCategory::UnrestrictedResourceConsumption),
            });

            // Only report one bypass method
            break;
        }
    }

    // Test path-based bypass (adding trailing slash, etc.)
    let path_variations = [
        format!("{}/", url),
        format!("{}//", url),
        format!("{}?", url),
        format!("{}.", url),
        format!("{};", url),
    ];

    for variation in path_variations {
        let mut bypass_succeeded = 0;
        let test_count = 5;

        for _ in 0..test_count {
            let req = match *method {
                Method::GET => client.get(&variation),
                Method::POST => client.post(&variation),
                _ => client.get(&variation),
            };

            if let Ok(response) = req.send().await {
                if response.status().is_success() {
                    bypass_succeeded += 1;
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if bypass_succeeded >= (test_count * 8 / 10) {
            findings.push(ApiSecurityFinding {
                finding_type: ApiSecurityTestType::RateLimitBypass,
                severity: ApiSecuritySeverity::Medium,
                title: format!(
                    "Rate Limit Bypass via URL manipulation on {} {}",
                    endpoint.method, endpoint.path
                ),
                description: format!(
                    "The rate limiting on {} {} can be bypassed by modifying the URL path. The variation '{}' is not rate limited.",
                    endpoint.method, endpoint.path, variation
                ),
                endpoint_path: Some(endpoint.path.clone()),
                endpoint_method: Some(endpoint.method.clone()),
                request: Some(variation.clone()),
                response: None,
                evidence: HashMap::from([
                    ("bypass_url".to_string(), serde_json::json!(variation)),
                    ("requests_succeeded".to_string(), serde_json::json!(bypass_succeeded)),
                ]),
                remediation: "Normalize URLs before applying rate limiting. Remove trailing slashes, query strings, and other variations.".to_string(),
                cwe_ids: vec![770],
                owasp_category: Some(OwaspApiCategory::UnrestrictedResourceConsumption),
            });
            break;
        }
    }

    Ok(findings)
}

/// Build the full URL for an endpoint
fn build_endpoint_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    format!("{}{}", base, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_endpoint_url() {
        assert_eq!(
            build_endpoint_url("https://api.example.com", "/users"),
            "https://api.example.com/users"
        );
        assert_eq!(
            build_endpoint_url("https://api.example.com/", "/users"),
            "https://api.example.com/users"
        );
    }

    #[test]
    fn test_rate_limit_headers() {
        assert!(RATE_LIMIT_HEADERS.contains(&"x-ratelimit-limit"));
        assert!(RATE_LIMIT_HEADERS.contains(&"retry-after"));
    }

    #[test]
    fn test_bypass_headers() {
        assert!(BYPASS_HEADERS.iter().any(|(h, _)| *h == "X-Forwarded-For"));
        assert!(BYPASS_HEADERS.iter().any(|(h, _)| *h == "X-Real-IP"));
    }
}
