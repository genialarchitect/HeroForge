#![allow(dead_code)]
//! Shodan API integration for exposed service detection
//!
//! This module provides integration with the Shodan API to look up
//! information about IP addresses and detect exposed services.

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use super::types::{ShodanHostInfo, ShodanService};

const SHODAN_API_BASE: &str = "https://api.shodan.io";
const REQUEST_TIMEOUT_SECS: u64 = 15;

/// Shodan API client
pub struct ShodanClient {
    client: Client,
    api_key: String,
}

/// Shodan API response for host lookup
#[derive(Debug, Deserialize)]
struct ShodanHostResponse {
    ip_str: String,
    hostnames: Option<Vec<String>>,
    country_name: Option<String>,
    city: Option<String>,
    org: Option<String>,
    isp: Option<String>,
    asn: Option<String>,
    ports: Option<Vec<u16>>,
    vulns: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    data: Option<Vec<ShodanServiceData>>,
    last_update: Option<String>,
}

/// Shodan service data in host response
#[derive(Debug, Deserialize)]
struct ShodanServiceData {
    port: u16,
    transport: Option<String>,
    product: Option<String>,
    version: Option<String>,
    #[serde(rename = "data")]
    banner: Option<String>,
    cpe: Option<Vec<String>>,
    vulns: Option<std::collections::HashMap<String, serde_json::Value>>,
}

/// Shodan search result
#[derive(Debug, Deserialize)]
struct ShodanSearchResponse {
    matches: Vec<ShodanSearchMatch>,
    total: i64,
}

/// Individual search match
#[derive(Debug, Deserialize)]
struct ShodanSearchMatch {
    ip_str: String,
    port: u16,
    product: Option<String>,
    version: Option<String>,
}

/// Shodan API info response
#[derive(Debug, Deserialize)]
pub struct ShodanApiInfo {
    pub query_credits: i32,
    pub scan_credits: i32,
    pub plan: String,
}

impl ShodanClient {
    /// Create a new Shodan client with API key
    pub fn new(api_key: String) -> Result<Self> {
        if api_key.is_empty() {
            return Err(anyhow!("Shodan API key is required"));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("HeroForge/0.1.0 (Security Scanner)")
            .build()?;

        Ok(Self { client, api_key })
    }

    /// Create a Shodan client from environment variable
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("SHODAN_API_KEY")
            .map_err(|_| anyhow!("SHODAN_API_KEY environment variable not set"))?;
        Self::new(api_key)
    }

    /// Get API info (quota, plan, etc.)
    pub async fn get_api_info(&self) -> Result<ShodanApiInfo> {
        let url = format!("{}/api-info?key={}", SHODAN_API_BASE, self.api_key);

        debug!("Fetching Shodan API info");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan API error: {} - {}", status, body));
        }

        let info: ShodanApiInfo = response.json().await?;
        Ok(info)
    }

    /// Look up host information by IP address
    pub async fn lookup_host(&self, ip: &str) -> Result<ShodanHostInfo> {
        let url = format!("{}/shodan/host/{}?key={}", SHODAN_API_BASE, ip, self.api_key);

        info!("Looking up host {} on Shodan", ip);
        debug!("Shodan URL: {}", url.replace(&self.api_key, "***"));

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("Host {} not found in Shodan database", ip));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!("Shodan API error for {}: {} - {}", ip, status, body);
            return Err(anyhow!("Shodan API error: {} - {}", status, body));
        }

        let host_data: ShodanHostResponse = response.json().await?;

        Ok(convert_host_response(host_data))
    }

    /// Search for hosts matching a query
    pub async fn search(&self, query: &str, page: Option<u32>) -> Result<Vec<ShodanHostInfo>> {
        let page = page.unwrap_or(1);
        let url = format!(
            "{}/shodan/host/search?key={}&query={}&page={}",
            SHODAN_API_BASE,
            self.api_key,
            urlencoding::encode(query),
            page
        );

        info!("Searching Shodan: {}", query);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan search error: {} - {}", status, body));
        }

        let search_response: ShodanSearchResponse = response.json().await?;

        info!("Shodan search returned {} total results", search_response.total);

        // For each unique IP, fetch full host details
        let unique_ips: Vec<String> = search_response
            .matches
            .iter()
            .map(|m| m.ip_str.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .take(10) // Limit to avoid rate limiting
            .collect();

        let mut hosts = Vec::new();
        for ip in unique_ips {
            match self.lookup_host(&ip).await {
                Ok(host) => hosts.push(host),
                Err(e) => warn!("Failed to fetch details for {}: {}", ip, e),
            }
        }

        Ok(hosts)
    }

    /// Search for hosts with specific CVE
    pub async fn search_by_cve(&self, cve_id: &str) -> Result<Vec<ShodanHostInfo>> {
        let query = format!("vuln:{}", cve_id);
        self.search(&query, None).await
    }

    /// Search for hosts with specific product/service
    pub async fn search_by_product(&self, product: &str, version: Option<&str>) -> Result<Vec<ShodanHostInfo>> {
        let query = if let Some(ver) = version {
            format!("product:{} version:{}", product, ver)
        } else {
            format!("product:{}", product)
        };
        self.search(&query, None).await
    }
}

/// Convert Shodan API response to our internal type
fn convert_host_response(resp: ShodanHostResponse) -> ShodanHostInfo {
    let services: Vec<ShodanService> = resp
        .data
        .unwrap_or_default()
        .into_iter()
        .map(|svc| {
            let vulns: Vec<String> = svc
                .vulns
                .map(|v| v.keys().cloned().collect())
                .unwrap_or_default();

            ShodanService {
                port: svc.port,
                protocol: svc.transport.unwrap_or_else(|| "tcp".to_string()),
                product: svc.product,
                version: svc.version,
                banner: svc.banner.map(|b| truncate_banner(&b, 500)),
                cpe: svc.cpe.unwrap_or_default(),
                vulns,
            }
        })
        .collect();

    let last_update = resp.last_update.and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    });

    ShodanHostInfo {
        ip: resp.ip_str,
        hostnames: resp.hostnames.unwrap_or_default(),
        country: resp.country_name,
        city: resp.city,
        org: resp.org,
        isp: resp.isp,
        asn: resp.asn,
        ports: resp.ports.unwrap_or_default(),
        vulns: resp.vulns.unwrap_or_default(),
        tags: resp.tags.unwrap_or_default(),
        services,
        last_update,
    }
}

/// Truncate banner to max length
fn truncate_banner(banner: &str, max_len: usize) -> String {
    if banner.len() <= max_len {
        banner.to_string()
    } else {
        format!("{}...", &banner[..max_len])
    }
}

/// Check if an IP is in Shodan without using API credits
/// Uses the /shodan/host/count endpoint which is free
pub async fn check_ip_indexed(ip: &str, api_key: &str) -> Result<bool> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let url = format!(
        "{}/shodan/host/count?key={}&query=ip:{}",
        SHODAN_API_BASE,
        api_key,
        ip
    );

    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        #[derive(Deserialize)]
        struct CountResponse {
            total: i64,
        }
        let count: CountResponse = response.json().await?;
        Ok(count.total > 0)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_banner() {
        assert_eq!(truncate_banner("short", 100), "short");
        assert_eq!(truncate_banner("a".repeat(100).as_str(), 10), "aaaaaaaaaa...");
    }

    #[tokio::test]
    async fn test_shodan_client_requires_key() {
        let result = ShodanClient::new(String::new());
        assert!(result.is_err());
    }
}
