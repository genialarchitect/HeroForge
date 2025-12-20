//! API Security Scanner Module
//!
//! This module provides comprehensive API security testing capabilities including:
//! - OpenAPI/Swagger endpoint discovery
//! - Authentication bypass testing
//! - SQL and command injection testing
//! - Rate limiting bypass detection
//! - CORS misconfiguration testing

pub mod auth_testing;
pub mod cors;
pub mod discovery;
pub mod injection;
pub mod rate_limit;

use anyhow::Result;
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub use discovery::ApiEndpoint;

/// OWASP API Security Top 10 categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OwaspApiCategory {
    #[serde(rename = "API1:2023")]
    BrokenObjectLevelAuth,
    #[serde(rename = "API2:2023")]
    BrokenAuthentication,
    #[serde(rename = "API3:2023")]
    BrokenObjectPropertyLevelAuth,
    #[serde(rename = "API4:2023")]
    UnrestrictedResourceConsumption,
    #[serde(rename = "API5:2023")]
    BrokenFunctionLevelAuth,
    #[serde(rename = "API6:2023")]
    UnrestrictedAccessToSensitiveFlows,
    #[serde(rename = "API7:2023")]
    ServerSideRequestForgery,
    #[serde(rename = "API8:2023")]
    SecurityMisconfiguration,
    #[serde(rename = "API9:2023")]
    ImproperInventoryManagement,
    #[serde(rename = "API10:2023")]
    UnsafeConsumptionOfApis,
}

impl std::fmt::Display for OwaspApiCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BrokenObjectLevelAuth => write!(f, "API1:2023 - Broken Object Level Authorization"),
            Self::BrokenAuthentication => write!(f, "API2:2023 - Broken Authentication"),
            Self::BrokenObjectPropertyLevelAuth => {
                write!(f, "API3:2023 - Broken Object Property Level Authorization")
            }
            Self::UnrestrictedResourceConsumption => {
                write!(f, "API4:2023 - Unrestricted Resource Consumption")
            }
            Self::BrokenFunctionLevelAuth => write!(f, "API5:2023 - Broken Function Level Authorization"),
            Self::UnrestrictedAccessToSensitiveFlows => {
                write!(f, "API6:2023 - Unrestricted Access to Sensitive Business Flows")
            }
            Self::ServerSideRequestForgery => write!(f, "API7:2023 - Server Side Request Forgery"),
            Self::SecurityMisconfiguration => write!(f, "API8:2023 - Security Misconfiguration"),
            Self::ImproperInventoryManagement => write!(f, "API9:2023 - Improper Inventory Management"),
            Self::UnsafeConsumptionOfApis => write!(f, "API10:2023 - Unsafe Consumption of APIs"),
        }
    }
}

/// Severity levels for API security findings
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ApiSecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ApiSecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Types of API security tests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiSecurityTestType {
    AuthBypass,
    SqlInjection,
    CommandInjection,
    RateLimitBypass,
    CorsMisconfiguration,
    BrokenObjectLevelAuth,
    BrokenFunctionLevelAuth,
    MassAssignment,
    ExcessiveDataExposure,
    ImproperAssetManagement,
}

/// A single API security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityFinding {
    pub finding_type: ApiSecurityTestType,
    pub severity: ApiSecuritySeverity,
    pub title: String,
    pub description: String,
    pub endpoint_path: Option<String>,
    pub endpoint_method: Option<String>,
    pub request: Option<String>,
    pub response: Option<String>,
    pub evidence: HashMap<String, serde_json::Value>,
    pub remediation: String,
    pub cwe_ids: Vec<u32>,
    pub owasp_category: Option<OwaspApiCategory>,
}

/// Configuration for API security scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityConfig {
    pub target_url: String,
    pub spec_type: Option<ApiSpecType>,
    pub spec_content: Option<String>,
    pub auth_config: Option<AuthConfig>,
    pub scan_options: ScanOptions,
    pub timeout: Duration,
    pub user_agent: String,
    pub rate_limit_delay: Duration,
}

impl Default for ApiSecurityConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            spec_type: None,
            spec_content: None,
            auth_config: None,
            scan_options: ScanOptions::default(),
            timeout: Duration::from_secs(30),
            user_agent: "HeroForge API Security Scanner/1.0".to_string(),
            rate_limit_delay: Duration::from_millis(200),
        }
    }
}

/// Type of API specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiSpecType {
    OpenApi3,
    Swagger2,
    Postman,
    None,
}

/// Authentication configuration for API testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_type: AuthType,
    pub credentials: HashMap<String, String>,
}

/// Type of authentication to use
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    None,
    Bearer,
    Basic,
    ApiKey,
    OAuth2,
    Custom,
}

/// Options for which security tests to run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub test_auth_bypass: bool,
    pub test_injection: bool,
    pub test_rate_limit: bool,
    pub test_cors: bool,
    pub test_bola: bool,
    pub test_bfla: bool,
    pub discover_endpoints: bool,
    pub aggressive_mode: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            test_auth_bypass: true,
            test_injection: true,
            test_rate_limit: true,
            test_cors: true,
            test_bola: true,
            test_bfla: false, // More intrusive, disabled by default
            discover_endpoints: true,
            aggressive_mode: false,
        }
    }
}

/// Result of an API security scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityScanResult {
    pub target_url: String,
    pub endpoints_discovered: usize,
    pub endpoints_tested: usize,
    pub findings: Vec<ApiSecurityFinding>,
    pub discovered_endpoints: Vec<ApiEndpoint>,
    pub scan_duration_secs: f64,
}

/// Run a comprehensive API security scan
pub async fn scan_api(config: ApiSecurityConfig) -> Result<ApiSecurityScanResult> {
    let start = std::time::Instant::now();
    info!("Starting API security scan for: {}", config.target_url);

    // Create HTTP client with custom settings
    let client = Client::builder()
        .timeout(config.timeout)
        .user_agent(&config.user_agent)
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(false)
        .build()?;

    let mut findings = Vec::new();
    let mut discovered_endpoints = Vec::new();

    // Phase 1: Endpoint Discovery
    if config.scan_options.discover_endpoints {
        info!("Phase 1: Discovering API endpoints");
        let discovery_result = discovery::discover_endpoints(&client, &config).await?;
        discovered_endpoints = discovery_result.endpoints;
        info!(
            "Discovered {} endpoints from {}",
            discovered_endpoints.len(),
            if discovery_result.spec_detected { "spec" } else { "crawling" }
        );
    }

    // If we have spec content, parse it for endpoints
    if let Some(ref spec_content) = config.spec_content {
        if let Some(ref spec_type) = config.spec_type {
            match discovery::parse_api_spec(spec_type, spec_content) {
                Ok(parsed) => {
                    info!("Parsed {} endpoints from provided spec", parsed.endpoints.len());
                    // Merge with discovered endpoints
                    for endpoint in parsed.endpoints {
                        if !discovered_endpoints
                            .iter()
                            .any(|e| e.path == endpoint.path && e.method == endpoint.method)
                        {
                            discovered_endpoints.push(endpoint);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to parse API spec: {}", e);
                }
            }
        }
    }

    let endpoints_discovered = discovered_endpoints.len();
    let mut endpoints_tested = 0;

    // Phase 2: Authentication Bypass Testing
    if config.scan_options.test_auth_bypass {
        info!("Phase 2: Testing for authentication bypass");
        for endpoint in &discovered_endpoints {
            if endpoint.auth_required {
                let auth_findings = auth_testing::test_auth_bypass(&client, &config, endpoint).await?;
                findings.extend(auth_findings);
                endpoints_tested += 1;
            }
            tokio::time::sleep(config.rate_limit_delay).await;
        }
    }

    // Phase 3: Injection Testing
    if config.scan_options.test_injection {
        info!("Phase 3: Testing for injection vulnerabilities");
        for endpoint in &discovered_endpoints {
            let injection_findings = injection::test_injection(&client, &config, endpoint).await?;
            findings.extend(injection_findings);
            endpoints_tested += 1;
            tokio::time::sleep(config.rate_limit_delay).await;
        }
    }

    // Phase 4: Rate Limit Testing
    if config.scan_options.test_rate_limit {
        info!("Phase 4: Testing rate limiting");
        for endpoint in discovered_endpoints.iter().take(5) {
            // Test a sample of endpoints
            let rate_findings = rate_limit::test_rate_limit(&client, &config, endpoint).await?;
            findings.extend(rate_findings);
            endpoints_tested += 1;
        }
    }

    // Phase 5: CORS Testing
    if config.scan_options.test_cors {
        info!("Phase 5: Testing CORS configuration");
        let cors_findings = cors::test_cors(&client, &config).await?;
        findings.extend(cors_findings);
    }

    let duration = start.elapsed();
    info!(
        "API security scan completed in {:.2}s. Found {} findings.",
        duration.as_secs_f64(),
        findings.len()
    );

    Ok(ApiSecurityScanResult {
        target_url: config.target_url,
        endpoints_discovered,
        endpoints_tested,
        findings,
        discovered_endpoints,
        scan_duration_secs: duration.as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(ApiSecuritySeverity::Critical > ApiSecuritySeverity::High);
        assert!(ApiSecuritySeverity::High > ApiSecuritySeverity::Medium);
        assert!(ApiSecuritySeverity::Medium > ApiSecuritySeverity::Low);
        assert!(ApiSecuritySeverity::Low > ApiSecuritySeverity::Info);
    }

    #[test]
    fn test_default_config() {
        let config = ApiSecurityConfig::default();
        assert!(config.scan_options.test_auth_bypass);
        assert!(config.scan_options.test_injection);
        assert!(config.scan_options.test_cors);
        assert!(!config.scan_options.aggressive_mode);
    }

    #[test]
    fn test_owasp_category_display() {
        let category = OwaspApiCategory::BrokenAuthentication;
        assert!(category.to_string().contains("API2:2023"));
    }
}
