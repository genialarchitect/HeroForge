//! Threat Intelligence Feeds Module

#![allow(dead_code)]

pub mod feeds;
pub mod enrichment;
pub mod sharing;

use anyhow::Result;
use feeds::{FeedIngester, MispConfig, TaxiiConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Configuration for the threat feed aggregator
#[derive(Debug, Clone, Default)]
pub struct AggregatorConfig {
    pub misp: Option<MispConfig>,
    pub taxii: Option<TaxiiConfig>,
    pub custom_feeds: Vec<CustomFeedConfig>,
    pub dedup_enabled: bool,
    pub min_confidence: f32,
}

#[derive(Debug, Clone)]
pub struct CustomFeedConfig {
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub auth_header: Option<(String, String)>,
}

#[derive(Debug, Clone)]
pub enum FeedFormat {
    Csv,
    Json,
    PlainText,
    Stix,
}

pub struct ThreatFeedAggregator {
    config: AggregatorConfig,
    feed_ingester: FeedIngester,
    http_client: reqwest::Client,
}

impl ThreatFeedAggregator {
    pub fn new() -> Self {
        Self {
            config: AggregatorConfig::default(),
            feed_ingester: FeedIngester::new(),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn with_config(config: AggregatorConfig) -> Self {
        let mut ingester = FeedIngester::new();

        if let Some(misp) = &config.misp {
            ingester = ingester.with_misp(misp.clone());
        }

        if let Some(taxii) = &config.taxii {
            ingester = ingester.with_taxii(taxii.clone());
        }

        Self {
            config,
            feed_ingester: ingester,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Configure MISP feed source
    pub fn with_misp(mut self, config: MispConfig) -> Self {
        self.config.misp = Some(config.clone());
        self.feed_ingester = self.feed_ingester.with_misp(config);
        self
    }

    /// Configure TAXII feed source
    pub fn with_taxii(mut self, config: TaxiiConfig) -> Self {
        self.config.taxii = Some(config.clone());
        self.feed_ingester = self.feed_ingester.with_taxii(config);
        self
    }

    /// Add a custom feed source
    pub fn with_custom_feed(mut self, config: CustomFeedConfig) -> Self {
        self.config.custom_feeds.push(config);
        self
    }

    /// Set minimum confidence threshold
    pub fn with_min_confidence(mut self, confidence: f32) -> Self {
        self.config.min_confidence = confidence;
        self
    }

    /// Enable or disable deduplication
    pub fn with_dedup(mut self, enabled: bool) -> Self {
        self.config.dedup_enabled = enabled;
        self
    }

    pub async fn fetch_feeds(&self) -> Result<Vec<ThreatIndicator>> {
        let mut all_indicators = Vec::new();

        // Fetch from MISP and TAXII via the FeedIngester
        log::info!("Fetching threat indicators from configured feeds...");

        // Fetch from standard feeds (MISP, TAXII)
        match self.feed_ingester.ingest_all().await {
            Ok(indicators) => {
                log::info!("Fetched {} indicators from standard feeds", indicators.len());
                all_indicators.extend(indicators);
            }
            Err(e) => {
                log::warn!("Error fetching from standard feeds: {}", e);
            }
        }

        // Fetch from custom feeds in parallel
        let custom_results = self.fetch_custom_feeds().await;
        for result in custom_results {
            match result {
                Ok(indicators) => {
                    all_indicators.extend(indicators);
                }
                Err(e) => {
                    log::warn!("Error fetching custom feed: {}", e);
                }
            }
        }

        // Apply confidence filter
        if self.config.min_confidence > 0.0 {
            let before_count = all_indicators.len();
            all_indicators.retain(|i| i.confidence >= self.config.min_confidence);
            log::debug!(
                "Filtered {} indicators below confidence threshold {}",
                before_count - all_indicators.len(),
                self.config.min_confidence
            );
        }

        // Deduplicate if enabled
        if self.config.dedup_enabled {
            all_indicators = self.deduplicate(all_indicators);
        }

        log::info!("Total aggregated indicators: {}", all_indicators.len());
        Ok(all_indicators)
    }

    /// Fetch indicators from custom feeds
    async fn fetch_custom_feeds(&self) -> Vec<Result<Vec<ThreatIndicator>>> {
        let mut results = Vec::new();

        for feed in &self.config.custom_feeds {
            let result = self.fetch_custom_feed(feed).await;
            results.push(result);
        }

        results
    }

    /// Fetch a single custom feed
    async fn fetch_custom_feed(&self, feed: &CustomFeedConfig) -> Result<Vec<ThreatIndicator>> {
        log::debug!("Fetching custom feed: {}", feed.name);

        let mut request = self.http_client.get(&feed.url);

        if let Some((header, value)) = &feed.auth_header {
            request = request.header(header, value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Custom feed {} returned status: {}",
                feed.name,
                response.status()
            ));
        }

        let text = response.text().await?;

        match feed.format {
            FeedFormat::Csv => self.parse_csv_feed(&text, &feed.name),
            FeedFormat::Json => self.parse_json_feed(&text, &feed.name),
            FeedFormat::PlainText => self.parse_plaintext_feed(&text, &feed.name),
            FeedFormat::Stix => self.parse_stix_feed(&text, &feed.name),
        }
    }

    /// Parse CSV format feed (one IOC per line, optionally with metadata)
    fn parse_csv_feed(&self, text: &str, source: &str) -> Result<Vec<ThreatIndicator>> {
        let mut indicators = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.is_empty() {
                continue;
            }

            let value = parts[0].trim().to_string();
            let ioc_type = detect_ioc_type(&value);

            // Try to get confidence from second column if present
            let confidence = parts
                .get(1)
                .and_then(|s| s.trim().parse::<f32>().ok())
                .unwrap_or(0.7);

            indicators.push(ThreatIndicator {
                ioc_type,
                value,
                confidence,
                source: source.to_string(),
            });
        }

        log::debug!("Parsed {} indicators from CSV feed {}", indicators.len(), source);
        Ok(indicators)
    }

    /// Parse JSON format feed
    fn parse_json_feed(&self, text: &str, source: &str) -> Result<Vec<ThreatIndicator>> {
        // Try to parse as array of indicators
        if let Ok(items) = serde_json::from_str::<Vec<JsonIndicator>>(text) {
            let indicators = items
                .into_iter()
                .map(|item| ThreatIndicator {
                    ioc_type: item.ioc_type.unwrap_or_else(|| detect_ioc_type(&item.value)),
                    value: item.value,
                    confidence: item.confidence.unwrap_or(0.7),
                    source: source.to_string(),
                })
                .collect();
            return Ok(indicators);
        }

        // Try to parse as object with "indicators" key
        if let Ok(wrapper) = serde_json::from_str::<JsonFeedWrapper>(text) {
            let indicators = wrapper
                .indicators
                .into_iter()
                .map(|item| ThreatIndicator {
                    ioc_type: item.ioc_type.unwrap_or_else(|| detect_ioc_type(&item.value)),
                    value: item.value,
                    confidence: item.confidence.unwrap_or(0.7),
                    source: source.to_string(),
                })
                .collect();
            return Ok(indicators);
        }

        Err(anyhow::anyhow!("Failed to parse JSON feed"))
    }

    /// Parse plain text feed (one IOC per line)
    fn parse_plaintext_feed(&self, text: &str, source: &str) -> Result<Vec<ThreatIndicator>> {
        let mut indicators = Vec::new();

        for line in text.lines() {
            let value = line.trim().to_string();
            if value.is_empty() || value.starts_with('#') || value.starts_with("//") {
                continue;
            }

            let ioc_type = detect_ioc_type(&value);

            indicators.push(ThreatIndicator {
                ioc_type,
                value,
                confidence: 0.7, // Default confidence for plain text feeds
                source: source.to_string(),
            });
        }

        log::debug!("Parsed {} indicators from plain text feed {}", indicators.len(), source);
        Ok(indicators)
    }

    /// Parse STIX 2.1 bundle
    fn parse_stix_feed(&self, text: &str, source: &str) -> Result<Vec<ThreatIndicator>> {
        let bundle: StixBundle = serde_json::from_str(text)?;
        let mut indicators = Vec::new();

        for object in bundle.objects {
            if object.get("type").and_then(|t| t.as_str()) == Some("indicator") {
                if let Some(pattern) = object.get("pattern").and_then(|p| p.as_str()) {
                    let (ioc_type, value) = parse_stix_pattern(pattern);
                    let confidence = object
                        .get("confidence")
                        .and_then(|c| c.as_f64())
                        .map(|c| c as f32 / 100.0)
                        .unwrap_or(0.7);

                    if !value.is_empty() {
                        indicators.push(ThreatIndicator {
                            ioc_type,
                            value,
                            confidence,
                            source: source.to_string(),
                        });
                    }
                }
            }
        }

        log::debug!("Parsed {} indicators from STIX feed {}", indicators.len(), source);
        Ok(indicators)
    }

    /// Deduplicate indicators by value, keeping the one with highest confidence
    fn deduplicate(&self, indicators: Vec<ThreatIndicator>) -> Vec<ThreatIndicator> {
        let mut best: HashMap<String, ThreatIndicator> = HashMap::new();

        for indicator in indicators {
            let key = format!("{}:{}", indicator.ioc_type, indicator.value.to_lowercase());

            if let Some(existing) = best.get(&key) {
                if indicator.confidence > existing.confidence {
                    best.insert(key, indicator);
                }
            } else {
                best.insert(key, indicator);
            }
        }

        let deduped: Vec<_> = best.into_values().collect();
        log::debug!("Deduplicated to {} unique indicators", deduped.len());
        deduped
    }

    /// Get indicators by type
    pub async fn fetch_by_type(&self, ioc_type: &str) -> Result<Vec<ThreatIndicator>> {
        let all = self.fetch_feeds().await?;
        Ok(all.into_iter().filter(|i| i.ioc_type == ioc_type).collect())
    }

    /// Get high-confidence indicators
    pub async fn fetch_high_confidence(&self, threshold: f32) -> Result<Vec<ThreatIndicator>> {
        let all = self.fetch_feeds().await?;
        Ok(all.into_iter().filter(|i| i.confidence >= threshold).collect())
    }
}

impl Default for ThreatFeedAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub ioc_type: String,
    pub value: String,
    pub confidence: f32,
    pub source: String,
}

#[derive(Debug, Deserialize)]
struct JsonIndicator {
    value: String,
    #[serde(rename = "type")]
    ioc_type: Option<String>,
    confidence: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct JsonFeedWrapper {
    indicators: Vec<JsonIndicator>,
}

#[derive(Debug, Deserialize)]
struct StixBundle {
    objects: Vec<serde_json::Value>,
}

/// Detect IOC type from value
fn detect_ioc_type(value: &str) -> String {
    use std::net::IpAddr;

    if value.parse::<IpAddr>().is_ok() {
        return "ip".to_string();
    }

    let value_lower = value.to_lowercase();
    if (value_lower.len() == 32 || value_lower.len() == 40 || value_lower.len() == 64)
        && value_lower.chars().all(|c| c.is_ascii_hexdigit())
    {
        return "hash".to_string();
    }

    if value.starts_with("http://") || value.starts_with("https://") {
        return "url".to_string();
    }

    if value.contains('@') && value.contains('.') {
        return "email".to_string();
    }

    "domain".to_string()
}

/// Parse STIX pattern to extract IOC type and value
fn parse_stix_pattern(pattern: &str) -> (String, String) {
    let ioc_type = if pattern.contains("ipv4-addr") || pattern.contains("ipv6-addr") {
        "ip"
    } else if pattern.contains("domain-name") {
        "domain"
    } else if pattern.contains("url:value") {
        "url"
    } else if pattern.contains("file:hashes") {
        "hash"
    } else if pattern.contains("email-addr") {
        "email"
    } else {
        "unknown"
    };

    // Extract the value from the pattern
    let value = pattern
        .split('=')
        .nth(1)
        .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"' || c == ']' || c == ' '))
        .unwrap_or("")
        .to_string();

    (ioc_type.to_string(), value)
}
