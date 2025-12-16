pub mod crawler;
pub mod headers;
pub mod forms;
pub mod sqli;
pub mod xss;
pub mod info_disclosure;

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

    info!("Web application scan completed. Found {} findings", findings.len());

    Ok(WebAppScanResult {
        url: config.target_url,
        pages_crawled: pages_crawled.len(),
        findings,
    })
}
