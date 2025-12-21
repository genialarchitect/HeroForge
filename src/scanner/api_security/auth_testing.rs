#![allow(dead_code)]
//! Authentication Bypass Testing Module
//!
//! Tests for common authentication bypass vulnerabilities including:
//! - Missing authentication on endpoints
//! - Broken Object Level Authorization (BOLA)
//! - JWT manipulation
//! - Authentication header manipulation

use anyhow::Result;
use log::{debug, info};
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    discovery::ApiEndpoint, ApiSecurityConfig, ApiSecurityFinding, ApiSecuritySeverity,
    ApiSecurityTestType, AuthConfig, AuthType, OwaspApiCategory,
};

/// Result of authentication bypass testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTestResult {
    pub endpoint: String,
    pub vulnerability_found: bool,
    pub bypass_method: Option<String>,
    pub details: String,
}

/// Common techniques for bypassing authentication
const AUTH_BYPASS_TECHNIQUES: &[(&str, &str)] = &[
    ("no_auth", "Accessing without any authentication"),
    ("empty_bearer", "Using empty Bearer token"),
    ("null_bearer", "Using 'null' as Bearer token"),
    ("undefined_bearer", "Using 'undefined' as Bearer token"),
    ("jwt_none_alg", "JWT with algorithm set to 'none'"),
    ("jwt_empty_sig", "JWT with empty signature"),
    ("removed_header", "Request without Authorization header"),
];

/// Test authentication bypass on an endpoint
pub async fn test_auth_bypass(
    client: &Client,
    config: &ApiSecurityConfig,
    endpoint: &ApiEndpoint,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();

    if !endpoint.auth_required {
        debug!(
            "Skipping auth bypass test for {} {} - no auth required",
            endpoint.method, endpoint.path
        );
        return Ok(findings);
    }

    info!(
        "Testing auth bypass on {} {}",
        endpoint.method, endpoint.path
    );

    let url = build_endpoint_url(&config.target_url, &endpoint.path);
    let method = endpoint.method.parse::<Method>().unwrap_or(Method::GET);

    // Get baseline authenticated response (if auth config provided)
    let baseline_status = if let Some(ref auth_config) = config.auth_config {
        let req = build_request(client, method.clone(), &url)
            .headers(build_auth_headers(auth_config)?);

        match req.send().await {
            Ok(resp) => Some(resp.status().as_u16()),
            Err(_) => None,
        }
    } else {
        None
    };

    // Test 1: Access without authentication
    let req = build_request(client, method.clone(), &url);
    if let Ok(response) = req.send().await {
        let status = response.status().as_u16();

        // If we get 2xx without auth on an auth-required endpoint, it's a vulnerability
        if status >= 200 && status < 300 {
            let response_text = response.text().await.unwrap_or_default();
            findings.push(ApiSecurityFinding {
                finding_type: ApiSecurityTestType::AuthBypass,
                severity: ApiSecuritySeverity::Critical,
                title: format!("Authentication Bypass on {} {}", endpoint.method, endpoint.path),
                description: format!(
                    "The endpoint {} {} is marked as requiring authentication but returned a successful response (HTTP {}) without any authentication credentials.",
                    endpoint.method, endpoint.path, status
                ),
                endpoint_path: Some(endpoint.path.clone()),
                endpoint_method: Some(endpoint.method.clone()),
                request: Some(format!("{} {} (no auth)", endpoint.method, url)),
                response: Some(truncate_response(&response_text, 500)),
                evidence: HashMap::from([
                    ("status_code".to_string(), serde_json::json!(status)),
                    ("auth_required".to_string(), serde_json::json!(true)),
                ]),
                remediation: "Ensure all endpoints that require authentication properly validate the presence and validity of authentication credentials before processing requests.".to_string(),
                cwe_ids: vec![306, 287],
                owasp_category: Some(OwaspApiCategory::BrokenAuthentication),
            });
        }
    }

    // Test 2: Empty Bearer token
    let req = build_request(client, method.clone(), &url)
        .header("Authorization", "Bearer ");
    if let Ok(response) = req.send().await {
        let status = response.status().as_u16();
        if status >= 200 && status < 300 {
            findings.push(create_auth_bypass_finding(
                endpoint,
                &url,
                "Empty Bearer Token",
                "The endpoint accepts requests with an empty Bearer token.",
                status,
            ));
        }
    }

    // Test 3: Bearer token = "null"
    let req = build_request(client, method.clone(), &url)
        .header("Authorization", "Bearer null");
    if let Ok(response) = req.send().await {
        let status = response.status().as_u16();
        if status >= 200 && status < 300 {
            findings.push(create_auth_bypass_finding(
                endpoint,
                &url,
                "Null Bearer Token",
                "The endpoint accepts requests with 'null' as the Bearer token value.",
                status,
            ));
        }
    }

    // Test 4: JWT with none algorithm
    let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.";
    let req = build_request(client, method.clone(), &url)
        .header("Authorization", format!("Bearer {}", none_jwt));
    if let Ok(response) = req.send().await {
        let status = response.status().as_u16();
        if status >= 200 && status < 300 {
            findings.push(ApiSecurityFinding {
                finding_type: ApiSecurityTestType::AuthBypass,
                severity: ApiSecuritySeverity::Critical,
                title: format!("JWT None Algorithm Bypass on {} {}", endpoint.method, endpoint.path),
                description: format!(
                    "The endpoint {} {} accepts JWTs with the algorithm set to 'none'. This allows attackers to forge arbitrary tokens without knowing the secret key.",
                    endpoint.method, endpoint.path
                ),
                endpoint_path: Some(endpoint.path.clone()),
                endpoint_method: Some(endpoint.method.clone()),
                request: Some(format!("Authorization: Bearer {}", none_jwt)),
                response: None,
                evidence: HashMap::from([
                    ("status_code".to_string(), serde_json::json!(status)),
                    ("jwt_algorithm".to_string(), serde_json::json!("none")),
                ]),
                remediation: "Configure the JWT library to reject tokens with algorithm 'none'. Always verify the algorithm matches the expected value before processing tokens.".to_string(),
                cwe_ids: vec![287, 347],
                owasp_category: Some(OwaspApiCategory::BrokenAuthentication),
            });
        }
    }

    // Test 5: Authorization header case sensitivity
    let variations = ["authorization", "AUTHORIZATION", "Authorization", "AuThOrIzAtIoN"];
    if let Some(ref auth_config) = config.auth_config {
        let auth_value = build_auth_value(auth_config)?;

        for variation in variations {
            let req = build_request(client, method.clone(), &url)
                .header(variation, &auth_value);

            if let Ok(response) = req.send().await {
                let status = response.status().as_u16();
                // Check if different casing results in different behavior
                if let Some(baseline) = baseline_status {
                    if status != baseline && status >= 200 && status < 300 {
                        findings.push(ApiSecurityFinding {
                            finding_type: ApiSecurityTestType::AuthBypass,
                            severity: ApiSecuritySeverity::Medium,
                            title: format!("Header Case Sensitivity Issue on {} {}", endpoint.method, endpoint.path),
                            description: format!(
                                "The endpoint handles the Authorization header '{}' differently than the standard casing, potentially bypassing authentication checks.",
                                variation
                            ),
                            endpoint_path: Some(endpoint.path.clone()),
                            endpoint_method: Some(endpoint.method.clone()),
                            request: None,
                            response: None,
                            evidence: HashMap::from([
                                ("header_variation".to_string(), serde_json::json!(variation)),
                                ("status_code".to_string(), serde_json::json!(status)),
                            ]),
                            remediation: "Ensure authentication header parsing is case-insensitive according to HTTP specification.".to_string(),
                            cwe_ids: vec![178],
                            owasp_category: Some(OwaspApiCategory::BrokenAuthentication),
                        });
                        break;
                    }
                }
            }
        }
    }

    // Test 6: X-Original-URL / X-Rewrite-URL bypass
    let bypass_headers: Vec<(&str, String)> = vec![
        ("X-Original-URL", endpoint.path.clone()),
        ("X-Rewrite-URL", endpoint.path.clone()),
        ("X-Forwarded-For", "127.0.0.1".to_string()),
        ("X-Custom-IP-Authorization", "127.0.0.1".to_string()),
    ];

    for (header, value) in bypass_headers {
        let req = build_request(client, method.clone(), &url)
            .header(header, &value);

        if let Ok(response) = req.send().await {
            let status = response.status().as_u16();
            if status >= 200 && status < 300 {
                findings.push(ApiSecurityFinding {
                    finding_type: ApiSecurityTestType::AuthBypass,
                    severity: ApiSecuritySeverity::High,
                    title: format!("Header-based Auth Bypass on {} {}", endpoint.method, endpoint.path),
                    description: format!(
                        "The endpoint may be vulnerable to authentication bypass using the {} header.",
                        header
                    ),
                    endpoint_path: Some(endpoint.path.clone()),
                    endpoint_method: Some(endpoint.method.clone()),
                    request: Some(format!("{}: {}", header, value)),
                    response: None,
                    evidence: HashMap::from([
                        ("bypass_header".to_string(), serde_json::json!(header)),
                        ("status_code".to_string(), serde_json::json!(status)),
                    ]),
                    remediation: "Do not trust proxy headers for authentication decisions. Validate authentication credentials directly.".to_string(),
                    cwe_ids: vec![287, 290],
                    owasp_category: Some(OwaspApiCategory::BrokenAuthentication),
                });
            }
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

/// Build a request with the appropriate method
fn build_request(client: &Client, method: Method, url: &str) -> RequestBuilder {
    match method {
        Method::GET => client.get(url),
        Method::POST => client.post(url),
        Method::PUT => client.put(url),
        Method::DELETE => client.delete(url),
        Method::PATCH => client.patch(url),
        Method::HEAD => client.head(url),
        _ => client.get(url),
    }
}

/// Build authentication headers from config
fn build_auth_headers(auth_config: &AuthConfig) -> Result<reqwest::header::HeaderMap> {
    let mut headers = reqwest::header::HeaderMap::new();

    match auth_config.auth_type {
        AuthType::Bearer => {
            if let Some(token) = auth_config.credentials.get("token") {
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Bearer {}", token).parse()?,
                );
            }
        }
        AuthType::Basic => {
            if let (Some(username), Some(password)) = (
                auth_config.credentials.get("username"),
                auth_config.credentials.get("password"),
            ) {
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{}:{}", username, password),
                );
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    format!("Basic {}", encoded).parse()?,
                );
            }
        }
        AuthType::ApiKey => {
            if let (Some(key), Some(value)) = (
                auth_config.credentials.get("key_name"),
                auth_config.credentials.get("key_value"),
            ) {
                let location = auth_config
                    .credentials
                    .get("key_location")
                    .map(|s| s.as_str())
                    .unwrap_or("header");

                if location == "header" {
                    headers.insert(
                        reqwest::header::HeaderName::from_bytes(key.as_bytes())?,
                        value.parse()?,
                    );
                }
            }
        }
        AuthType::Custom => {
            // Add all credentials as headers
            for (key, value) in &auth_config.credentials {
                if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                    if let Ok(header_value) = value.parse() {
                        headers.insert(header_name, header_value);
                    }
                }
            }
        }
        _ => {}
    }

    Ok(headers)
}

/// Build authentication header value from config
fn build_auth_value(auth_config: &AuthConfig) -> Result<String> {
    match auth_config.auth_type {
        AuthType::Bearer => {
            if let Some(token) = auth_config.credentials.get("token") {
                Ok(format!("Bearer {}", token))
            } else {
                Ok("Bearer ".to_string())
            }
        }
        AuthType::Basic => {
            if let (Some(username), Some(password)) = (
                auth_config.credentials.get("username"),
                auth_config.credentials.get("password"),
            ) {
                let encoded = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{}:{}", username, password),
                );
                Ok(format!("Basic {}", encoded))
            } else {
                Ok("Basic ".to_string())
            }
        }
        _ => Ok(String::new()),
    }
}

/// Create a standard auth bypass finding
fn create_auth_bypass_finding(
    endpoint: &ApiEndpoint,
    url: &str,
    technique: &str,
    description: &str,
    status: u16,
) -> ApiSecurityFinding {
    ApiSecurityFinding {
        finding_type: ApiSecurityTestType::AuthBypass,
        severity: ApiSecuritySeverity::Critical,
        title: format!(
            "{} Auth Bypass on {} {}",
            technique, endpoint.method, endpoint.path
        ),
        description: format!(
            "{} The endpoint returned HTTP {} indicating successful access.",
            description, status
        ),
        endpoint_path: Some(endpoint.path.clone()),
        endpoint_method: Some(endpoint.method.clone()),
        request: Some(format!("{} {}", endpoint.method, url)),
        response: None,
        evidence: HashMap::from([
            ("bypass_technique".to_string(), serde_json::json!(technique)),
            ("status_code".to_string(), serde_json::json!(status)),
        ]),
        remediation:
            "Validate all authentication tokens properly. Reject empty, null, or malformed tokens."
                .to_string(),
        cwe_ids: vec![287, 306],
        owasp_category: Some(OwaspApiCategory::BrokenAuthentication),
    }
}

/// Truncate response text for storage
fn truncate_response(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{}... [truncated]", &text[..max_len])
    }
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
        assert_eq!(
            build_endpoint_url("https://api.example.com", "users"),
            "https://api.example.com/users"
        );
    }

    #[test]
    fn test_truncate_response() {
        let short = "short response";
        assert_eq!(truncate_response(short, 100), short);

        let long = "a".repeat(1000);
        let truncated = truncate_response(&long, 100);
        assert!(truncated.len() < 200);
        assert!(truncated.ends_with("... [truncated]"));
    }
}
