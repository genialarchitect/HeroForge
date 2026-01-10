use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};
use log::{info, warn, debug};
use regex::Regex;
use once_cell::sync::Lazy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub name: String,
    pub feed_type: String,
    pub url: Option<String>,
    pub enabled: bool,
}

/// Aggregated IOC from multiple feeds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedIoc {
    pub ioc_type: String,
    pub value: String,
    pub sources: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence: f64,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Dark web finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DarkWebFinding {
    pub source: String,
    pub finding_type: String,  // credential_leak, data_breach, mention, sale
    pub title: String,
    pub content_preview: String,
    pub url: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub relevance_score: f64,
    pub entities_mentioned: Vec<String>,
}

/// Paste site finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasteFinding {
    pub site: String,
    pub paste_id: String,
    pub title: Option<String>,
    pub content_type: String,  // credential, code, config, data
    pub matches: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub discovered_at: DateTime<Utc>,
}

/// Code repository finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeRepoFinding {
    pub platform: String,  // github, gitlab, bitbucket
    pub repo_url: String,
    pub file_path: String,
    pub finding_type: String,  // api_key, password, token, secret
    pub secret_type: Option<String>,
    pub line_number: Option<u32>,
    pub content_preview: String,
    pub commit_sha: Option<String>,
    pub author: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

/// Feed format types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    Stix,
    Taxii,
    Csv,
    Json,
    PlainText,
    OpenIoc,
    Yara,
}

// IOC detection patterns
static IPV4_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap()
});

static IPV6_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$").unwrap()
});

static DOMAIN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

static MD5_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-fA-F0-9]{32}$").unwrap()
});

static SHA1_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-fA-F0-9]{40}$").unwrap()
});

static SHA256_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-fA-F0-9]{64}$").unwrap()
});

static URL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^https?://[^\s/$.?#].[^\s]*$").unwrap()
});

static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
});

// Secret detection patterns for code repos
static SECRET_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "aws_access_key"),
        (Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(), "github_pat"),
        (Regex::new(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}").unwrap(), "github_fine_grained_pat"),
        (Regex::new(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(), "slack_token"),
        (Regex::new(r"sk-[a-zA-Z0-9]{48}").unwrap(), "openai_api_key"),
        (Regex::new(r"sk-ant-api[a-zA-Z0-9-]{80,}").unwrap(), "anthropic_api_key"),
        (Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(), "google_api_key"),
        (Regex::new(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----").unwrap(), "private_key"),
        (Regex::new(r#"(?i)api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#).unwrap(), "generic_api_key"),
        (Regex::new(r#"(?i)password\s*[:=]\s*['"][^'"]+['"]"#).unwrap(), "password"),
        (Regex::new(r#"(?i)secret\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]"#).unwrap(), "generic_secret"),
    ]
});

/// Aggregate IOCs from multiple threat feeds
pub async fn aggregate_feeds(feeds: Vec<ThreatFeed>) -> Result<Vec<serde_json::Value>> {
    let mut aggregated_iocs: HashMap<String, AggregatedIoc> = HashMap::new();

    for feed in feeds {
        if !feed.enabled {
            continue;
        }

        // Fetch and parse feed based on type
        let iocs = fetch_feed(&feed).await?;

        // Merge IOCs
        for ioc in iocs {
            let key = format!("{}:{}", ioc.ioc_type, ioc.value);

            if let Some(existing) = aggregated_iocs.get_mut(&key) {
                // Update existing IOC
                if !existing.sources.contains(&feed.name) {
                    existing.sources.push(feed.name.clone());
                }
                if ioc.first_seen < existing.first_seen {
                    existing.first_seen = ioc.first_seen;
                }
                if ioc.last_seen > existing.last_seen {
                    existing.last_seen = ioc.last_seen;
                }
                // Increase confidence based on multiple sources
                existing.confidence = (existing.confidence + ioc.confidence) / 2.0;
                existing.confidence = (existing.confidence * existing.sources.len() as f64 / 3.0).min(1.0);
                // Merge tags
                for tag in ioc.tags {
                    if !existing.tags.contains(&tag) {
                        existing.tags.push(tag);
                    }
                }
            } else {
                aggregated_iocs.insert(key, ioc);
            }
        }
    }

    // Convert to JSON values
    let results: Vec<serde_json::Value> = aggregated_iocs
        .into_values()
        .map(|ioc| serde_json::to_value(ioc).unwrap_or_default())
        .collect();

    Ok(results)
}

/// Fetch and parse a single threat feed
async fn fetch_feed(feed: &ThreatFeed) -> Result<Vec<AggregatedIoc>> {
    let mut iocs = Vec::new();

    if let Some(url) = &feed.url {
        // Simulate fetching feed - in production would use HTTP client
        let format = detect_feed_format(&feed.feed_type, url);

        match format {
            FeedFormat::Stix => {
                iocs = parse_stix_feed(url, &feed.name).await?;
            }
            FeedFormat::Csv => {
                iocs = parse_csv_feed(url, &feed.name).await?;
            }
            FeedFormat::Json => {
                iocs = parse_json_feed(url, &feed.name).await?;
            }
            FeedFormat::PlainText => {
                iocs = parse_plaintext_feed(url, &feed.name).await?;
            }
            _ => {}
        }
    }

    Ok(iocs)
}

/// Detect feed format from type or URL
fn detect_feed_format(feed_type: &str, url: &str) -> FeedFormat {
    let type_lower = feed_type.to_lowercase();
    let url_lower = url.to_lowercase();

    if type_lower.contains("stix") || url_lower.contains("stix") {
        FeedFormat::Stix
    } else if type_lower.contains("taxii") || url_lower.contains("taxii") {
        FeedFormat::Taxii
    } else if url_lower.ends_with(".csv") || type_lower.contains("csv") {
        FeedFormat::Csv
    } else if url_lower.ends_with(".json") || type_lower.contains("json") {
        FeedFormat::Json
    } else if url_lower.ends_with(".yar") || type_lower.contains("yara") {
        FeedFormat::Yara
    } else {
        FeedFormat::PlainText
    }
}

/// Parse STIX 2.x feed
async fn parse_stix_feed(url: &str, source: &str) -> Result<Vec<AggregatedIoc>> {
    let mut iocs = Vec::new();

    // Fetch STIX bundle
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to fetch STIX feed from {}: {}", url, e);
            return Ok(iocs);
        }
    };

    if !response.status().is_success() {
        warn!("STIX feed returned non-success status: {}", response.status());
        return Ok(iocs);
    }

    let body = response.text().await?;
    let bundle: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to parse STIX JSON: {}", e);
            return Ok(iocs);
        }
    };

    // Parse STIX objects
    if let Some(objects) = bundle.get("objects").and_then(|o| o.as_array()) {
        for obj in objects {
            let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

            if obj_type == "indicator" {
                if let Some(ioc) = parse_stix_indicator(obj, source) {
                    iocs.push(ioc);
                }
            }
        }
    }

    info!("Parsed {} IOCs from STIX feed: {}", iocs.len(), url);
    Ok(iocs)
}

/// Parse a STIX indicator object
fn parse_stix_indicator(indicator: &serde_json::Value, source: &str) -> Option<AggregatedIoc> {
    let pattern = indicator.get("pattern")?.as_str()?;

    // Parse STIX pattern to extract IOC type and value
    let (ioc_type, value) = parse_stix_pattern(pattern)?;

    let confidence = indicator.get("confidence")
        .and_then(|c| c.as_f64())
        .map(|c| c / 100.0)  // STIX confidence is 0-100
        .unwrap_or(0.5);

    let labels = indicator.get("labels")
        .and_then(|l| l.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect())
        .unwrap_or_default();

    let created = indicator.get("created")
        .and_then(|c| c.as_str())
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);

    let modified = indicator.get("modified")
        .and_then(|m| m.as_str())
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        .unwrap_or_else(Utc::now);

    Some(AggregatedIoc {
        ioc_type,
        value,
        sources: vec![source.to_string()],
        first_seen: created,
        last_seen: modified,
        confidence,
        tags: labels,
        metadata: HashMap::new(),
    })
}

/// Parse STIX pattern to extract IOC type and value
fn parse_stix_pattern(pattern: &str) -> Option<(String, String)> {
    // Common STIX patterns:
    // [ipv4-addr:value = '1.2.3.4']
    // [domain-name:value = 'evil.com']
    // [file:hashes.'SHA-256' = 'abc123...']
    // [url:value = 'http://...']

    if pattern.contains("ipv4-addr:value") || pattern.contains("ipv6-addr:value") {
        let value = extract_pattern_value(pattern)?;
        return Some(("ip".to_string(), value));
    }

    if pattern.contains("domain-name:value") {
        let value = extract_pattern_value(pattern)?;
        return Some(("domain".to_string(), value));
    }

    if pattern.contains("file:hashes") {
        let value = extract_pattern_value(pattern)?;
        if value.len() == 32 {
            return Some(("md5".to_string(), value));
        } else if value.len() == 40 {
            return Some(("sha1".to_string(), value));
        } else if value.len() == 64 {
            return Some(("sha256".to_string(), value));
        }
    }

    if pattern.contains("url:value") {
        let value = extract_pattern_value(pattern)?;
        return Some(("url".to_string(), value));
    }

    if pattern.contains("email-addr:value") {
        let value = extract_pattern_value(pattern)?;
        return Some(("email".to_string(), value));
    }

    None
}

/// Extract value from STIX pattern
fn extract_pattern_value(pattern: &str) -> Option<String> {
    // Find value between single quotes
    let start = pattern.find('\'')?;
    let end = pattern.rfind('\'')?;
    if start < end {
        Some(pattern[start + 1..end].to_string())
    } else {
        None
    }
}

/// Parse CSV feed
async fn parse_csv_feed(url: &str, source: &str) -> Result<Vec<AggregatedIoc>> {
    let mut iocs = Vec::new();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to fetch CSV feed from {}: {}", url, e);
            return Ok(iocs);
        }
    };

    if !response.status().is_success() {
        return Ok(iocs);
    }

    let body = response.text().await?;
    let lines: Vec<&str> = body.lines().collect();

    if lines.is_empty() {
        return Ok(iocs);
    }

    // Try to detect CSV format
    let header = lines[0].to_lowercase();
    let has_header = header.contains("ip") || header.contains("domain") ||
                     header.contains("hash") || header.contains("ioc") ||
                     header.contains("indicator");

    let start_line = if has_header { 1 } else { 0 };

    for line in lines.iter().skip(start_line) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse CSV columns
        let columns: Vec<&str> = line.split(',').map(|s| s.trim().trim_matches('"')).collect();

        if columns.is_empty() {
            continue;
        }

        // Try to parse first column as IOC
        let value = columns[0];
        if let Some(ioc_type) = detect_ioc_type(value) {
            let confidence = if columns.len() > 1 {
                columns.get(1)
                    .and_then(|c| c.parse::<f64>().ok())
                    .map(|c| if c > 1.0 { c / 100.0 } else { c })
                    .unwrap_or(0.5)
            } else {
                0.5
            };

            let tags: Vec<String> = if columns.len() > 2 {
                columns[2..].iter()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            } else {
                Vec::new()
            };

            iocs.push(AggregatedIoc {
                ioc_type,
                value: value.to_string(),
                sources: vec![source.to_string()],
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                confidence,
                tags,
                metadata: HashMap::new(),
            });
        }
    }

    info!("Parsed {} IOCs from CSV feed: {}", iocs.len(), url);
    Ok(iocs)
}

/// Parse JSON feed
async fn parse_json_feed(url: &str, source: &str) -> Result<Vec<AggregatedIoc>> {
    let mut iocs = Vec::new();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to fetch JSON feed from {}: {}", url, e);
            return Ok(iocs);
        }
    };

    if !response.status().is_success() {
        return Ok(iocs);
    }

    let body = response.text().await?;
    let data: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to parse JSON feed: {}", e);
            return Ok(iocs);
        }
    };

    // Handle array of IOCs
    let ioc_array = if data.is_array() {
        data.as_array().cloned().unwrap_or_default()
    } else if let Some(arr) = data.get("iocs").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = data.get("data").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = data.get("indicators").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        Vec::new()
    };

    for item in ioc_array {
        // Try common field names for IOC value
        let value = item.get("value")
            .or_else(|| item.get("ioc"))
            .or_else(|| item.get("indicator"))
            .or_else(|| item.get("ip"))
            .or_else(|| item.get("domain"))
            .or_else(|| item.get("hash"))
            .and_then(|v| v.as_str());

        if let Some(value) = value {
            // Try to get type from JSON or detect it
            let ioc_type = item.get("type")
                .or_else(|| item.get("ioc_type"))
                .and_then(|t| t.as_str())
                .map(|t| normalize_ioc_type(t))
                .or_else(|| detect_ioc_type(value));

            if let Some(ioc_type) = ioc_type {
                let confidence = item.get("confidence")
                    .and_then(|c| c.as_f64())
                    .map(|c| if c > 1.0 { c / 100.0 } else { c })
                    .unwrap_or(0.5);

                let tags: Vec<String> = item.get("tags")
                    .and_then(|t| t.as_array())
                    .map(|arr| arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect())
                    .unwrap_or_default();

                let first_seen = item.get("first_seen")
                    .or_else(|| item.get("created"))
                    .and_then(|t| t.as_str())
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or_else(Utc::now);

                let last_seen = item.get("last_seen")
                    .or_else(|| item.get("modified"))
                    .and_then(|t| t.as_str())
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .unwrap_or_else(Utc::now);

                iocs.push(AggregatedIoc {
                    ioc_type,
                    value: value.to_string(),
                    sources: vec![source.to_string()],
                    first_seen,
                    last_seen,
                    confidence,
                    tags,
                    metadata: HashMap::new(),
                });
            }
        }
    }

    info!("Parsed {} IOCs from JSON feed: {}", iocs.len(), url);
    Ok(iocs)
}

/// Parse plain text feed (one IOC per line)
async fn parse_plaintext_feed(url: &str, source: &str) -> Result<Vec<AggregatedIoc>> {
    let mut iocs = Vec::new();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to fetch plaintext feed from {}: {}", url, e);
            return Ok(iocs);
        }
    };

    if !response.status().is_success() {
        return Ok(iocs);
    }

    let body = response.text().await?;

    for line in body.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        // Detect IOC type from value
        if let Some(ioc_type) = detect_ioc_type(line) {
            iocs.push(AggregatedIoc {
                ioc_type,
                value: line.to_string(),
                sources: vec![source.to_string()],
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                confidence: 0.5,
                tags: Vec::new(),
                metadata: HashMap::new(),
            });
        }
    }

    info!("Parsed {} IOCs from plaintext feed: {}", iocs.len(), url);
    Ok(iocs)
}

/// Detect IOC type from value
fn detect_ioc_type(value: &str) -> Option<String> {
    let value = value.trim();

    if IPV4_PATTERN.is_match(value) {
        return Some("ip".to_string());
    }

    if IPV6_PATTERN.is_match(value) {
        return Some("ipv6".to_string());
    }

    if SHA256_PATTERN.is_match(value) {
        return Some("sha256".to_string());
    }

    if SHA1_PATTERN.is_match(value) {
        return Some("sha1".to_string());
    }

    if MD5_PATTERN.is_match(value) {
        return Some("md5".to_string());
    }

    if URL_PATTERN.is_match(value) {
        return Some("url".to_string());
    }

    if EMAIL_PATTERN.is_match(value) {
        return Some("email".to_string());
    }

    if DOMAIN_PATTERN.is_match(value) {
        return Some("domain".to_string());
    }

    None
}

/// Normalize IOC type to standard format
fn normalize_ioc_type(ioc_type: &str) -> String {
    let lower = ioc_type.to_lowercase();

    match lower.as_str() {
        "ipv4" | "ipv4-addr" | "ip-address" | "ip_address" => "ip".to_string(),
        "ipv6" | "ipv6-addr" => "ipv6".to_string(),
        "domain-name" | "hostname" | "fqdn" => "domain".to_string(),
        "sha-256" | "sha256-hash" => "sha256".to_string(),
        "sha-1" | "sha1-hash" => "sha1".to_string(),
        "md5-hash" => "md5".to_string(),
        "uri" => "url".to_string(),
        "email-addr" | "email-address" => "email".to_string(),
        _ => lower,
    }
}

/// Monitor dark web for threats
pub async fn monitor_dark_web() -> Result<Vec<serde_json::Value>> {
    let mut findings = Vec::new();

    // Dark web sources to monitor
    let sources = [
        ("forums", monitor_dark_web_forums().await?),
        ("markets", monitor_dark_web_markets().await?),
        ("paste_services", monitor_onion_paste_sites().await?),
        ("breach_databases", monitor_breach_databases().await?),
    ];

    for (source_type, source_findings) in sources {
        for finding in source_findings {
            let finding_json = serde_json::json!({
                "source_type": source_type,
                "source": finding.source,
                "finding_type": finding.finding_type,
                "title": finding.title,
                "content_preview": finding.content_preview,
                "url": finding.url,
                "timestamp": finding.timestamp.to_rfc3339(),
                "relevance_score": finding.relevance_score,
                "entities_mentioned": finding.entities_mentioned,
            });
            findings.push(finding_json);
        }
    }

    Ok(findings)
}

/// Monitor dark web forums
async fn monitor_dark_web_forums() -> Result<Vec<DarkWebFinding>> {
    let findings = Vec::new();

    // In production, this would connect via Tor and scrape known forums
    // For now, we simulate with common forum patterns

    // Check configured monitoring keywords
    let keywords = get_monitoring_keywords();

    // Simulate forum monitoring results
    // In production: connect to Tor, scrape forums, search for keywords
    debug!("Monitoring dark web forums for {} keywords", keywords.len());

    // Example finding structure (would come from actual scraping)
    if !keywords.is_empty() {
        // Log that monitoring is active
        info!("Dark web forum monitoring active for {} keywords", keywords.len());
    }

    Ok(findings)
}

/// Monitor dark web marketplaces
async fn monitor_dark_web_markets() -> Result<Vec<DarkWebFinding>> {
    let findings = Vec::new();

    // In production, would monitor for:
    // - Stolen credentials for sale
    // - Company data listings
    // - Exploit sales mentioning target technologies
    // - RaaS offerings
    // - Initial access broker listings

    let keywords = get_monitoring_keywords();

    debug!("Monitoring dark web markets for {} keywords", keywords.len());

    // Simulate market monitoring
    // In production: connect via Tor, check known markets, search listings

    Ok(findings)
}

/// Monitor .onion paste sites
async fn monitor_onion_paste_sites() -> Result<Vec<DarkWebFinding>> {
    let findings = Vec::new();

    // Known .onion paste sites to monitor:
    // - stronghold paste variants
    // - zerobin clones
    // - other Tor-based paste services

    let keywords = get_monitoring_keywords();

    debug!("Monitoring onion paste sites for {} keywords", keywords.len());

    // In production: connect via Tor, scrape paste sites

    Ok(findings)
}

/// Monitor breach databases
async fn monitor_breach_databases() -> Result<Vec<DarkWebFinding>> {
    let findings = Vec::new();

    // Sources to check:
    // - Known breach compilation sites
    // - Combo list aggregators
    // - Database dump forums/sites
    // - Leak sites

    let domains = get_monitored_domains();

    debug!("Monitoring breach databases for {} domains", domains.len());

    // In production: check breach databases for organization domains

    Ok(findings)
}

/// Monitor paste sites for leaked data
pub async fn monitor_paste_sites() -> Result<Vec<serde_json::Value>> {
    let mut findings = Vec::new();

    // Clear web paste sites to monitor
    let paste_findings = vec![
        monitor_pastebin().await?,
        monitor_github_gists().await?,
        monitor_rentry().await?,
        monitor_dpaste().await?,
    ];

    for site_findings in paste_findings {
        for finding in site_findings {
            let finding_json = serde_json::json!({
                "site": finding.site,
                "paste_id": finding.paste_id,
                "title": finding.title,
                "content_type": finding.content_type,
                "matches": finding.matches,
                "created_at": finding.created_at.to_rfc3339(),
                "discovered_at": finding.discovered_at.to_rfc3339(),
            });
            findings.push(finding_json);
        }
    }

    Ok(findings)
}

/// Monitor Pastebin
async fn monitor_pastebin() -> Result<Vec<PasteFinding>> {
    let findings = Vec::new();

    let keywords = get_monitoring_keywords();

    // In production, would use Pastebin scraping API or custom scraper
    // Note: Pastebin has rate limits and ToS restrictions

    // Pastebin monitoring approaches:
    // 1. Use Pastebin PRO API (paid)
    // 2. Monitor Pastebin trending
    // 3. Use third-party paste monitoring services

    debug!("Monitoring Pastebin for {} keywords", keywords.len());

    // Simulate monitoring (in production, actual scraping)
    for keyword in keywords.iter().take(5) {
        debug!("Searching Pastebin for: {}", keyword);
    }

    Ok(findings)
}

/// Monitor GitHub Gists
async fn monitor_github_gists() -> Result<Vec<PasteFinding>> {
    let mut findings = Vec::new();

    let keywords = get_monitoring_keywords();

    // Use GitHub API to search public gists
    // Note: Requires GitHub token for higher rate limits

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("HeroForge-ThreatIntel/1.0")
        .build()?;

    for keyword in keywords.iter().take(3) {
        let search_url = format!(
            "https://api.github.com/gists/public?per_page=10"
        );

        match client.get(&search_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(gists) = response.json::<Vec<serde_json::Value>>().await {
                        for gist in gists {
                            // Check gist files for keyword matches
                            if let Some(files) = gist.get("files").and_then(|f| f.as_object()) {
                                for (filename, file_info) in files {
                                    let content = file_info.get("content")
                                        .and_then(|c| c.as_str())
                                        .unwrap_or("");

                                    if content.to_lowercase().contains(&keyword.to_lowercase()) {
                                        findings.push(PasteFinding {
                                            site: "github_gists".to_string(),
                                            paste_id: gist.get("id")
                                                .and_then(|i| i.as_str())
                                                .unwrap_or("")
                                                .to_string(),
                                            title: Some(filename.clone()),
                                            content_type: detect_content_type(content),
                                            matches: vec![keyword.clone()],
                                            created_at: gist.get("created_at")
                                                .and_then(|t| t.as_str())
                                                .and_then(|s| s.parse().ok())
                                                .unwrap_or_else(Utc::now),
                                            discovered_at: Utc::now(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to search GitHub Gists: {}", e);
            }
        }
    }

    Ok(findings)
}

/// Monitor rentry.co
async fn monitor_rentry() -> Result<Vec<PasteFinding>> {
    let findings = Vec::new();

    // rentry.co monitoring would require:
    // 1. Known paste IDs to check
    // 2. Or monitoring for new pastes (requires scraping)

    debug!("Monitoring rentry.co");

    Ok(findings)
}

/// Monitor dpaste.org
async fn monitor_dpaste() -> Result<Vec<PasteFinding>> {
    let findings = Vec::new();

    // dpaste.org monitoring similar to rentry

    debug!("Monitoring dpaste.org");

    Ok(findings)
}

/// Detect content type from paste content
fn detect_content_type(content: &str) -> String {
    let lower = content.to_lowercase();

    // Check for credentials
    if lower.contains("password") || lower.contains("username:") ||
       lower.contains("email:") && lower.contains("pass") {
        return "credential".to_string();
    }

    // Check for code
    if lower.contains("function ") || lower.contains("def ") ||
       lower.contains("class ") || lower.contains("import ") {
        return "code".to_string();
    }

    // Check for configuration
    if lower.contains("api_key") || lower.contains("secret") ||
       lower.contains("[database]") || lower.contains("connection_string") {
        return "config".to_string();
    }

    "data".to_string()
}

/// Monitor code repositories for leaked credentials
pub async fn monitor_code_repositories() -> Result<Vec<serde_json::Value>> {
    let mut findings = Vec::new();

    // Monitor major code hosting platforms
    let repo_findings = vec![
        monitor_github_repos().await?,
        monitor_gitlab_repos().await?,
        monitor_bitbucket_repos().await?,
    ];

    for platform_findings in repo_findings {
        for finding in platform_findings {
            let finding_json = serde_json::json!({
                "platform": finding.platform,
                "repo_url": finding.repo_url,
                "file_path": finding.file_path,
                "finding_type": finding.finding_type,
                "secret_type": finding.secret_type,
                "line_number": finding.line_number,
                "content_preview": finding.content_preview,
                "commit_sha": finding.commit_sha,
                "author": finding.author,
                "discovered_at": finding.discovered_at.to_rfc3339(),
            });
            findings.push(finding_json);
        }
    }

    Ok(findings)
}

/// Monitor GitHub repositories
async fn monitor_github_repos() -> Result<Vec<CodeRepoFinding>> {
    let mut findings = Vec::new();

    let keywords = get_monitoring_keywords();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("HeroForge-ThreatIntel/1.0")
        .build()?;

    // Search GitHub code for each keyword + secret patterns
    for keyword in keywords.iter().take(3) {
        // Search for potential secrets mentioning the keyword
        for (pattern, secret_type) in SECRET_PATTERNS.iter().take(5) {
            let query = format!("{} {}", keyword, secret_type);
            let search_url = format!(
                "https://api.github.com/search/code?q={}&per_page=5",
                urlencoding::encode(&query)
            );

            match client.get(&search_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        if let Ok(results) = response.json::<serde_json::Value>().await {
                            if let Some(items) = results.get("items").and_then(|i| i.as_array()) {
                                for item in items {
                                    let repo_url = item.get("repository")
                                        .and_then(|r| r.get("html_url"))
                                        .and_then(|u| u.as_str())
                                        .unwrap_or("")
                                        .to_string();

                                    let file_path = item.get("path")
                                        .and_then(|p| p.as_str())
                                        .unwrap_or("")
                                        .to_string();

                                    // Get file content to check for actual secrets
                                    if let Some(content_url) = item.get("url").and_then(|u| u.as_str()) {
                                        if let Ok(content_resp) = client.get(content_url).send().await {
                                            if let Ok(content_json) = content_resp.json::<serde_json::Value>().await {
                                                if let Some(content) = content_json.get("content")
                                                    .and_then(|c| c.as_str()) {
                                                    // Decode base64 content
                                                    if let Ok(decoded) = base64::Engine::decode(
                                                        &base64::engine::general_purpose::STANDARD,
                                                        content.replace('\n', "")
                                                    ) {
                                                        if let Ok(text) = String::from_utf8(decoded) {
                                                            // Check for actual secret patterns
                                                            if pattern.is_match(&text) {
                                                                let preview = text.lines()
                                                                    .find(|l| pattern.is_match(l))
                                                                    .map(|l| {
                                                                        if l.len() > 100 {
                                                                            format!("{}...", &l[..100])
                                                                        } else {
                                                                            l.to_string()
                                                                        }
                                                                    })
                                                                    .unwrap_or_default();

                                                                findings.push(CodeRepoFinding {
                                                                    platform: "github".to_string(),
                                                                    repo_url,
                                                                    file_path,
                                                                    finding_type: "secret".to_string(),
                                                                    secret_type: Some(secret_type.to_string()),
                                                                    line_number: None,
                                                                    content_preview: preview,
                                                                    commit_sha: None,
                                                                    author: None,
                                                                    discovered_at: Utc::now(),
                                                                });
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to search GitHub: {}", e);
                }
            }

            // Rate limiting
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    info!("Found {} potential secrets on GitHub", findings.len());
    Ok(findings)
}

/// Monitor GitLab repositories
async fn monitor_gitlab_repos() -> Result<Vec<CodeRepoFinding>> {
    let mut findings = Vec::new();

    let keywords = get_monitoring_keywords();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("HeroForge-ThreatIntel/1.0")
        .build()?;

    // GitLab API search (public projects only without token)
    for keyword in keywords.iter().take(2) {
        let search_url = format!(
            "https://gitlab.com/api/v4/search?scope=blobs&search={}",
            urlencoding::encode(keyword)
        );

        match client.get(&search_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(results) = response.json::<Vec<serde_json::Value>>().await {
                        for item in results.iter().take(5) {
                            let project_id = item.get("project_id")
                                .and_then(|p| p.as_i64())
                                .unwrap_or(0);

                            let file_path = item.get("path")
                                .and_then(|p| p.as_str())
                                .unwrap_or("")
                                .to_string();

                            let data = item.get("data")
                                .and_then(|d| d.as_str())
                                .unwrap_or("");

                            // Check for secrets in content
                            for (pattern, secret_type) in SECRET_PATTERNS.iter() {
                                if pattern.is_match(data) {
                                    findings.push(CodeRepoFinding {
                                        platform: "gitlab".to_string(),
                                        repo_url: format!("https://gitlab.com/projects/{}", project_id),
                                        file_path: file_path.clone(),
                                        finding_type: "secret".to_string(),
                                        secret_type: Some(secret_type.to_string()),
                                        line_number: None,
                                        content_preview: if data.len() > 100 {
                                            format!("{}...", &data[..100])
                                        } else {
                                            data.to_string()
                                        },
                                        commit_sha: item.get("ref")
                                            .and_then(|r| r.as_str())
                                            .map(String::from),
                                        author: None,
                                        discovered_at: Utc::now(),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to search GitLab: {}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    info!("Found {} potential secrets on GitLab", findings.len());
    Ok(findings)
}

/// Monitor Bitbucket repositories
async fn monitor_bitbucket_repos() -> Result<Vec<CodeRepoFinding>> {
    let mut findings = Vec::new();

    let keywords = get_monitoring_keywords();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("HeroForge-ThreatIntel/1.0")
        .build()?;

    // Bitbucket API search
    for keyword in keywords.iter().take(2) {
        let search_url = format!(
            "https://api.bitbucket.org/2.0/search/code?search_query={}",
            urlencoding::encode(keyword)
        );

        match client.get(&search_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(results) = response.json::<serde_json::Value>().await {
                        if let Some(values) = results.get("values").and_then(|v| v.as_array()) {
                            for item in values.iter().take(5) {
                                let file = item.get("file").unwrap_or(item);

                                let repo_url = file.get("links")
                                    .and_then(|l| l.get("self"))
                                    .and_then(|s| s.get("href"))
                                    .and_then(|h| h.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                let file_path = file.get("path")
                                    .and_then(|p| p.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                // Check content matches for secrets
                                if let Some(matches) = item.get("content_matches").and_then(|m| m.as_array()) {
                                    for match_item in matches {
                                        let lines = match_item.get("lines")
                                            .and_then(|l| l.as_array())
                                            .map(|arr| arr.iter()
                                                .filter_map(|l| l.get("text").and_then(|t| t.as_str()))
                                                .collect::<Vec<_>>()
                                                .join("\n"))
                                            .unwrap_or_default();

                                        for (pattern, secret_type) in SECRET_PATTERNS.iter() {
                                            if pattern.is_match(&lines) {
                                                findings.push(CodeRepoFinding {
                                                    platform: "bitbucket".to_string(),
                                                    repo_url: repo_url.clone(),
                                                    file_path: file_path.clone(),
                                                    finding_type: "secret".to_string(),
                                                    secret_type: Some(secret_type.to_string()),
                                                    line_number: None,
                                                    content_preview: if lines.len() > 100 {
                                                        format!("{}...", &lines[..100])
                                                    } else {
                                                        lines.clone()
                                                    },
                                                    commit_sha: None,
                                                    author: None,
                                                    discovered_at: Utc::now(),
                                                });
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to search Bitbucket: {}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    info!("Found {} potential secrets on Bitbucket", findings.len());
    Ok(findings)
}

/// Get monitoring keywords (organization names, domains, etc.)
fn get_monitoring_keywords() -> Vec<String> {
    // In production, would be loaded from configuration
    // For now, return empty to avoid unintended searches
    Vec::new()
}

/// Get monitored domains
fn get_monitored_domains() -> Vec<String> {
    // In production, would be loaded from configuration
    Vec::new()
}

/// Deduplicate IOCs based on value
pub fn deduplicate_iocs(iocs: Vec<AggregatedIoc>) -> Vec<AggregatedIoc> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut deduped = Vec::new();

    for ioc in iocs {
        let key = format!("{}:{}", ioc.ioc_type, ioc.value.to_lowercase());
        if !seen.contains(&key) {
            seen.insert(key);
            deduped.push(ioc);
        }
    }

    deduped
}

/// Score IOC quality based on various factors
pub fn score_ioc_quality(ioc: &AggregatedIoc) -> f64 {
    let mut score: f64 = 0.0;

    // Source count factor (more sources = higher quality)
    let source_score = (ioc.sources.len() as f64 / 5.0).min(1.0) * 0.3;
    score += source_score;

    // Age factor (recent IOCs more relevant)
    let age_days = (Utc::now() - ioc.last_seen).num_days();
    let age_score = if age_days <= 1 {
        0.3
    } else if age_days <= 7 {
        0.25
    } else if age_days <= 30 {
        0.15
    } else {
        0.05
    };
    score += age_score;

    // Confidence factor
    score += ioc.confidence * 0.3;

    // Tags factor (more context = higher quality)
    let tag_score = (ioc.tags.len() as f64 / 10.0).min(1.0) * 0.1;
    score += tag_score;

    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_feed_format() {
        assert_eq!(detect_feed_format("stix", "http://example.com/feed"), FeedFormat::Stix);
        assert_eq!(detect_feed_format("csv", "http://example.com/feed.csv"), FeedFormat::Csv);
        assert_eq!(detect_feed_format("json", "http://example.com/feed.json"), FeedFormat::Json);
        assert_eq!(detect_feed_format("text", "http://example.com/feed.txt"), FeedFormat::PlainText);
    }

    #[test]
    fn test_detect_ioc_type() {
        assert_eq!(detect_ioc_type("192.168.1.1"), Some("ip".to_string()));
        assert_eq!(detect_ioc_type("evil.com"), Some("domain".to_string()));
        assert_eq!(detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), Some("md5".to_string()));
        assert_eq!(detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), Some("sha256".to_string()));
        assert_eq!(detect_ioc_type("https://evil.com/malware"), Some("url".to_string()));
    }

    #[test]
    fn test_normalize_ioc_type() {
        assert_eq!(normalize_ioc_type("ipv4-addr"), "ip");
        assert_eq!(normalize_ioc_type("domain-name"), "domain");
        assert_eq!(normalize_ioc_type("SHA-256"), "sha256");
    }

    #[test]
    fn test_score_ioc_quality() {
        let ioc = AggregatedIoc {
            ioc_type: "ip".to_string(),
            value: "1.2.3.4".to_string(),
            sources: vec!["source1".to_string(), "source2".to_string()],
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            confidence: 0.8,
            tags: vec!["malware".to_string()],
            metadata: HashMap::new(),
        };

        let score = score_ioc_quality(&ioc);
        assert!(score > 0.5);
        assert!(score <= 1.0);
    }

    #[test]
    fn test_deduplicate_iocs() {
        let iocs = vec![
            AggregatedIoc {
                ioc_type: "ip".to_string(),
                value: "1.2.3.4".to_string(),
                sources: vec!["source1".to_string()],
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                confidence: 0.8,
                tags: vec![],
                metadata: HashMap::new(),
            },
            AggregatedIoc {
                ioc_type: "ip".to_string(),
                value: "1.2.3.4".to_string(),  // Duplicate
                sources: vec!["source2".to_string()],
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                confidence: 0.9,
                tags: vec![],
                metadata: HashMap::new(),
            },
        ];

        let deduped = deduplicate_iocs(iocs);
        assert_eq!(deduped.len(), 1);
    }

    #[tokio::test]
    async fn test_aggregate_feeds() {
        let feeds = vec![
            ThreatFeed {
                name: "test_feed".to_string(),
                feed_type: "stix".to_string(),
                url: Some("http://example.com/feed".to_string()),
                enabled: true,
            },
        ];

        let result = aggregate_feeds(feeds).await.unwrap();
        // Should return empty for unreachable feeds
        assert!(result.is_empty());
    }
}
