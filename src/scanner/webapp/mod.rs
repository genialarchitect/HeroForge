pub mod crawler;
pub mod headers;
pub mod forms;
pub mod sqli;
pub mod xss;
pub mod info_disclosure;
pub mod secrets;

use anyhow::Result;
use log::info;
use reqwest::Client;
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

use crate::types::WebAppScanResult;

#[derive(Debug, Clone)]
pub struct WebAppScanConfig {
    pub target_url: String,
    pub max_depth: usize,
    pub max_pages: usize,
    pub respect_robots_txt: bool,
    pub checks_enabled: Vec<String>,
    pub timeout: Duration,
    pub user_agent: String,
    pub rate_limit_delay: Duration,
}

impl Default for WebAppScanConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            max_depth: 3,
            max_pages: 100,
            respect_robots_txt: true,
            checks_enabled: vec![
                "headers".to_string(),
                "forms".to_string(),
                "sqli".to_string(),
                "xss".to_string(),
                "info_disclosure".to_string(),
                "secrets".to_string(),
            ],
            timeout: Duration::from_secs(10),
            user_agent: "HeroForge WebApp Scanner/0.1".to_string(),
            rate_limit_delay: Duration::from_millis(500),
        }
    }
}

/// Run a comprehensive web application security scan
pub async fn scan_webapp(config: WebAppScanConfig) -> Result<WebAppScanResult> {
    info!("Starting web application scan for: {}", config.target_url);

    // Validate URL
    let base_url = Url::parse(&config.target_url)
        .map_err(|e| anyhow::anyhow!("Invalid URL: {}", e))?;

    // Create HTTP client with custom settings
    let client = Client::builder()
        .timeout(config.timeout)
        .user_agent(&config.user_agent)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    let mut findings = Vec::new();
    let mut pages_crawled = HashSet::new();

    // Phase 1: Crawl the website to discover pages
    info!("Phase 1: Crawling website");
    let discovered_urls = crawler::crawl_website(
        &client,
        &base_url,
        &config,
        &mut pages_crawled,
    ).await?;

    info!("Discovered {} unique URLs", discovered_urls.len());

    // Phase 2: Check security headers on main page
    if config.checks_enabled.contains(&"headers".to_string()) {
        info!("Phase 2: Checking security headers");
        let header_findings = headers::check_security_headers(&client, &base_url).await?;
        findings.extend(header_findings);
    }

    // Phase 3: Detect and analyze forms
    let forms_data = if config.checks_enabled.contains(&"forms".to_string()) {
        info!("Phase 3: Analyzing forms");
        let (form_findings, forms) = forms::detect_forms(&client, &discovered_urls).await?;
        findings.extend(form_findings);
        Some(forms)
    } else {
        None
    };

    // Phase 4: SQL Injection testing
    if config.checks_enabled.contains(&"sqli".to_string()) {
        info!("Phase 4: Testing for SQL injection");
        if let Some(ref forms) = forms_data {
            let sqli_findings = sqli::test_sql_injection(&client, &discovered_urls, forms).await?;
            findings.extend(sqli_findings);
        }
    }

    // Phase 5: XSS testing
    if config.checks_enabled.contains(&"xss".to_string()) {
        info!("Phase 5: Testing for XSS vulnerabilities");
        if let Some(ref forms) = forms_data {
            let xss_findings = xss::test_xss(&client, &discovered_urls, forms).await?;
            findings.extend(xss_findings);
        }
    }

    // Phase 6: Information disclosure
    if config.checks_enabled.contains(&"info_disclosure".to_string()) {
        info!("Phase 6: Checking for information disclosure");
        let info_findings = info_disclosure::check_info_disclosure(&client, &discovered_urls).await?;
        findings.extend(info_findings);
    }

    // Phase 7: Secret detection (API keys, passwords, tokens)
    if config.checks_enabled.contains(&"secrets".to_string()) {
        info!("Phase 7: Scanning for exposed secrets");
        let secret_findings = secrets::check_secrets(&client, &discovered_urls).await?;
        findings.extend(secret_findings);
    }

    info!("Web application scan completed. Found {} findings", findings.len());

    Ok(WebAppScanResult {
        url: config.target_url,
        pages_crawled: pages_crawled.len(),
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== WebAppScanConfig Default Tests ====================

    #[test]
    fn test_webapp_scan_config_default() {
        let config = WebAppScanConfig::default();

        assert!(config.target_url.is_empty());
        assert_eq!(config.max_depth, 3);
        assert_eq!(config.max_pages, 100);
        assert!(config.respect_robots_txt);
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.user_agent, "HeroForge WebApp Scanner/0.1");
        assert_eq!(config.rate_limit_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_webapp_scan_config_default_checks() {
        let config = WebAppScanConfig::default();

        assert!(config.checks_enabled.contains(&"headers".to_string()));
        assert!(config.checks_enabled.contains(&"forms".to_string()));
        assert!(config.checks_enabled.contains(&"sqli".to_string()));
        assert!(config.checks_enabled.contains(&"xss".to_string()));
        assert!(config.checks_enabled.contains(&"info_disclosure".to_string()));
        assert!(config.checks_enabled.contains(&"secrets".to_string()));
        assert_eq!(config.checks_enabled.len(), 6);
    }

    #[test]
    fn test_webapp_scan_config_custom() {
        let config = WebAppScanConfig {
            target_url: "https://example.com".to_string(),
            max_depth: 5,
            max_pages: 50,
            respect_robots_txt: false,
            checks_enabled: vec!["headers".to_string()],
            timeout: Duration::from_secs(30),
            user_agent: "Custom Agent".to_string(),
            rate_limit_delay: Duration::from_millis(1000),
        };

        assert_eq!(config.target_url, "https://example.com");
        assert_eq!(config.max_depth, 5);
        assert_eq!(config.max_pages, 50);
        assert!(!config.respect_robots_txt);
        assert_eq!(config.checks_enabled.len(), 1);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.user_agent, "Custom Agent");
        assert_eq!(config.rate_limit_delay, Duration::from_millis(1000));
    }

    #[test]
    fn test_webapp_scan_config_clone() {
        let config = WebAppScanConfig::default();
        let cloned = config.clone();

        assert_eq!(cloned.max_depth, config.max_depth);
        assert_eq!(cloned.max_pages, config.max_pages);
        assert_eq!(cloned.checks_enabled, config.checks_enabled);
    }

    #[test]
    fn test_webapp_scan_config_debug() {
        let config = WebAppScanConfig::default();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("WebAppScanConfig"));
        assert!(debug_str.contains("max_depth"));
        assert!(debug_str.contains("max_pages"));
    }

    // ==================== URL Validation Tests ====================

    #[test]
    fn test_url_parse_valid_https() {
        let url = Url::parse("https://example.com");
        assert!(url.is_ok());
    }

    #[test]
    fn test_url_parse_valid_http() {
        let url = Url::parse("http://example.com");
        assert!(url.is_ok());
    }

    #[test]
    fn test_url_parse_with_path() {
        let url = Url::parse("https://example.com/path/to/page");
        assert!(url.is_ok());
        assert_eq!(url.unwrap().path(), "/path/to/page");
    }

    #[test]
    fn test_url_parse_with_query() {
        let url = Url::parse("https://example.com/search?q=test&page=1");
        assert!(url.is_ok());
        assert!(url.unwrap().query().is_some());
    }

    #[test]
    fn test_url_parse_invalid() {
        let url = Url::parse("not a valid url");
        assert!(url.is_err());
    }

    #[test]
    fn test_url_parse_missing_scheme() {
        let url = Url::parse("example.com");
        assert!(url.is_err());
    }

    // ==================== Check Enabled Tests ====================

    #[test]
    fn test_checks_enabled_contains() {
        let config = WebAppScanConfig::default();

        assert!(config.checks_enabled.contains(&"headers".to_string()));
        assert!(!config.checks_enabled.contains(&"nonexistent".to_string()));
    }

    #[test]
    fn test_checks_enabled_empty() {
        let config = WebAppScanConfig {
            checks_enabled: vec![],
            ..Default::default()
        };

        assert!(config.checks_enabled.is_empty());
    }

    #[test]
    fn test_checks_enabled_single() {
        let config = WebAppScanConfig {
            checks_enabled: vec!["headers".to_string()],
            ..Default::default()
        };

        assert_eq!(config.checks_enabled.len(), 1);
        assert!(config.checks_enabled.contains(&"headers".to_string()));
    }
}
