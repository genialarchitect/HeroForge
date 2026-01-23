#![allow(dead_code)]
//! CORS Misconfiguration Testing Module
//!
//! Tests for Cross-Origin Resource Sharing (CORS) misconfigurations:
//! - Overly permissive CORS (Access-Control-Allow-Origin: *)
//! - Reflected origin
//! - Null origin acceptance
//! - Wildcard with credentials

use anyhow::Result;
use log::{debug, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    ApiSecurityConfig, ApiSecurityFinding, ApiSecuritySeverity, ApiSecurityTestType,
    OwaspApiCategory,
};

/// Result of CORS testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsTestResult {
    pub target: String,
    pub allows_all_origins: bool,
    pub reflects_origin: bool,
    pub allows_null: bool,
    pub allows_credentials_with_wildcard: bool,
    pub exposed_headers: Vec<String>,
}

/// Test origins to check CORS configuration
const TEST_ORIGINS: &[&str] = &[
    "https://evil.com",
    "https://attacker.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://test.evil.com",
];

/// Test CORS configuration on the target
pub async fn test_cors(
    client: &Client,
    config: &ApiSecurityConfig,
) -> Result<Vec<ApiSecurityFinding>> {
    let mut findings = Vec::new();
    let url = &config.target_url;

    info!("Testing CORS configuration on {}", url);

    // Test 1: Check for wildcard origin
    let wildcard_finding = test_wildcard_cors(client, url).await?;
    if let Some(finding) = wildcard_finding {
        findings.push(finding);
    }

    // Test 2: Check for reflected origin
    let reflected_finding = test_reflected_origin(client, url).await?;
    if let Some(finding) = reflected_finding {
        findings.push(finding);
    }

    // Test 3: Check for null origin acceptance
    let null_finding = test_null_origin(client, url).await?;
    if let Some(finding) = null_finding {
        findings.push(finding);
    }

    // Test 4: Check for credentials with wildcard
    let creds_finding = test_credentials_with_wildcard(client, url).await?;
    if let Some(finding) = creds_finding {
        findings.push(finding);
    }

    // Test 5: Check for subdomain wildcard
    let subdomain_finding = test_subdomain_wildcard(client, url).await?;
    if let Some(finding) = subdomain_finding {
        findings.push(finding);
    }

    Ok(findings)
}

/// Test for Access-Control-Allow-Origin: *
async fn test_wildcard_cors(client: &Client, url: &str) -> Result<Option<ApiSecurityFinding>> {
    debug!("Testing for wildcard CORS");

    let response = client
        .request(reqwest::Method::OPTIONS, url)
        .header("Origin", "https://evil.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await?;

    let headers = response.headers();

    if let Some(acao) = headers.get("access-control-allow-origin") {
        if acao.to_str().unwrap_or("") == "*" {
            return Ok(Some(ApiSecurityFinding {
                finding_type: ApiSecurityTestType::CorsMisconfiguration,
                severity: ApiSecuritySeverity::Medium,
                title: "CORS Wildcard Origin Allowed".to_string(),
                description: format!(
                    "The API at {} returns Access-Control-Allow-Origin: * which allows any website to make cross-origin requests. While this may be intentional for public APIs, it can be dangerous if the API handles sensitive data.",
                    url
                ),
                endpoint_path: None,
                endpoint_method: Some("OPTIONS".to_string()),
                request: Some(format!("OPTIONS {} with Origin: https://evil.com", url)),
                response: Some("Access-Control-Allow-Origin: *".to_string()),
                evidence: HashMap::from([
                    ("acao_header".to_string(), serde_json::json!("*")),
                ]),
                remediation: "If the API is not intended to be publicly accessible from any origin, specify explicit allowed origins instead of using a wildcard.".to_string(),
                cwe_ids: vec![942, 346],
                owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
            }));
        }
    }

    Ok(None)
}

/// Test for reflected Origin header
async fn test_reflected_origin(client: &Client, url: &str) -> Result<Option<ApiSecurityFinding>> {
    debug!("Testing for reflected origin");

    for test_origin in TEST_ORIGINS {
        let response = client
            .request(reqwest::Method::OPTIONS, url)
            .header("Origin", *test_origin)
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await?;

        let headers = response.headers();

        if let Some(acao) = headers.get("access-control-allow-origin") {
            let acao_value = acao.to_str().unwrap_or("");

            // Check if the origin is reflected back
            if acao_value == *test_origin {
                let allows_credentials = headers
                    .get("access-control-allow-credentials")
                    .map(|v| v.to_str().unwrap_or("") == "true")
                    .unwrap_or(false);

                let severity = if allows_credentials {
                    ApiSecuritySeverity::Critical
                } else {
                    ApiSecuritySeverity::High
                };

                return Ok(Some(ApiSecurityFinding {
                    finding_type: ApiSecurityTestType::CorsMisconfiguration,
                    severity,
                    title: "CORS Origin Reflection Vulnerability".to_string(),
                    description: format!(
                        "The API at {} reflects the Origin header value in Access-Control-Allow-Origin without validation. This allows any website to make cross-origin requests to this API.{}",
                        url,
                        if allows_credentials {
                            " CRITICAL: Credentials are also allowed, enabling cookie/session theft."
                        } else {
                            ""
                        }
                    ),
                    endpoint_path: None,
                    endpoint_method: Some("OPTIONS".to_string()),
                    request: Some(format!("OPTIONS {} with Origin: {}", url, test_origin)),
                    response: Some(format!("Access-Control-Allow-Origin: {}", acao_value)),
                    evidence: HashMap::from([
                        ("reflected_origin".to_string(), serde_json::json!(test_origin)),
                        ("allows_credentials".to_string(), serde_json::json!(allows_credentials)),
                    ]),
                    remediation: "Implement a whitelist of allowed origins and validate the Origin header against this list. Never reflect arbitrary origins.".to_string(),
                    cwe_ids: vec![942, 346],
                    owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
                }));
            }
        }
    }

    Ok(None)
}

/// Test for null origin acceptance
async fn test_null_origin(client: &Client, url: &str) -> Result<Option<ApiSecurityFinding>> {
    debug!("Testing for null origin acceptance");

    let response = client
        .request(reqwest::Method::OPTIONS, url)
        .header("Origin", "null")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await?;

    let headers = response.headers();

    if let Some(acao) = headers.get("access-control-allow-origin") {
        if acao.to_str().unwrap_or("") == "null" {
            let allows_credentials = headers
                .get("access-control-allow-credentials")
                .map(|v| v.to_str().unwrap_or("") == "true")
                .unwrap_or(false);

            return Ok(Some(ApiSecurityFinding {
                finding_type: ApiSecurityTestType::CorsMisconfiguration,
                severity: if allows_credentials {
                    ApiSecuritySeverity::Critical
                } else {
                    ApiSecuritySeverity::High
                },
                title: "CORS Null Origin Allowed".to_string(),
                description: format!(
                    "The API at {} allows the 'null' origin. The null origin can be triggered from sandboxed iframes, local HTML files, and other contexts, potentially allowing attackers to bypass CORS restrictions.",
                    url
                ),
                endpoint_path: None,
                endpoint_method: Some("OPTIONS".to_string()),
                request: Some(format!("OPTIONS {} with Origin: null", url)),
                response: Some("Access-Control-Allow-Origin: null".to_string()),
                evidence: HashMap::from([
                    ("allows_null".to_string(), serde_json::json!(true)),
                    ("allows_credentials".to_string(), serde_json::json!(allows_credentials)),
                ]),
                remediation: "Remove 'null' from the list of allowed origins. The null origin is often used in attack scenarios.".to_string(),
                cwe_ids: vec![942, 346],
                owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
            }));
        }
    }

    Ok(None)
}

/// Test for credentials allowed with wildcard (which is invalid but sometimes misconfigured)
async fn test_credentials_with_wildcard(client: &Client, url: &str) -> Result<Option<ApiSecurityFinding>> {
    debug!("Testing for credentials with wildcard");

    let response = client
        .request(reqwest::Method::OPTIONS, url)
        .header("Origin", "https://evil.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await?;

    let headers = response.headers();

    let acao = headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let acac = headers
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Browsers will reject this, but it indicates misconfiguration
    if acao == "*" && acac == "true" {
        return Ok(Some(ApiSecurityFinding {
            finding_type: ApiSecurityTestType::CorsMisconfiguration,
            severity: ApiSecuritySeverity::Medium,
            title: "CORS Misconfiguration: Wildcard with Credentials".to_string(),
            description: format!(
                "The API at {} returns both Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true. While browsers will reject this invalid combination, it indicates a misconfiguration that could lead to security issues if partially fixed.",
                url
            ),
            endpoint_path: None,
            endpoint_method: Some("OPTIONS".to_string()),
            request: None,
            response: Some("Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true".to_string()),
            evidence: HashMap::from([
                ("wildcard_origin".to_string(), serde_json::json!(true)),
                ("allows_credentials".to_string(), serde_json::json!(true)),
            ]),
            remediation: "When allowing credentials, you must specify explicit origins instead of using a wildcard.".to_string(),
            cwe_ids: vec![942],
            owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
        }));
    }

    Ok(None)
}

/// Test for subdomain wildcard acceptance
async fn test_subdomain_wildcard(client: &Client, url: &str) -> Result<Option<ApiSecurityFinding>> {
    debug!("Testing for subdomain wildcard acceptance");

    // Extract domain from URL
    let parsed = url::Url::parse(url)?;
    let host = parsed.host_str().unwrap_or("");

    // Create test subdomain origin
    let test_origins = vec![
        format!("https://evil.{}", host),
        format!("https://attacker.{}", host),
        format!("https://{}.evil.com", host.split('.').next().unwrap_or("test")),
    ];

    for test_origin in test_origins {
        let response = client
            .request(reqwest::Method::OPTIONS, url)
            .header("Origin", &test_origin)
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await?;

        let headers = response.headers();

        if let Some(acao) = headers.get("access-control-allow-origin") {
            let acao_value = acao.to_str().unwrap_or("");

            if acao_value == test_origin {
                return Ok(Some(ApiSecurityFinding {
                    finding_type: ApiSecurityTestType::CorsMisconfiguration,
                    severity: ApiSecuritySeverity::High,
                    title: "CORS Subdomain Wildcard Vulnerability".to_string(),
                    description: format!(
                        "The API at {} allows arbitrary subdomains of the target domain as origins. If an attacker can control a subdomain (via subdomain takeover or XSS), they can bypass CORS restrictions.",
                        url
                    ),
                    endpoint_path: None,
                    endpoint_method: Some("OPTIONS".to_string()),
                    request: Some(format!("OPTIONS {} with Origin: {}", url, test_origin)),
                    response: Some(format!("Access-Control-Allow-Origin: {}", acao_value)),
                    evidence: HashMap::from([
                        ("accepted_origin".to_string(), serde_json::json!(test_origin)),
                    ]),
                    remediation: "Use a strict whitelist of allowed origins. Avoid patterns that accept arbitrary subdomains.".to_string(),
                    cwe_ids: vec![942, 346],
                    owasp_category: Some(OwaspApiCategory::SecurityMisconfiguration),
                }));
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origins_list() {
        assert!(TEST_ORIGINS.iter().any(|o| o.contains("evil.com")));
    }
}
