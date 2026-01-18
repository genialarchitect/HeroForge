//! SecurityTrails API Client
//!
//! Queries SecurityTrails API for DNS history, subdomains, and WHOIS data.

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{PassiveDnsRecord, SubdomainResult};

/// SecurityTrails subdomain response
#[derive(Debug, Deserialize)]
struct SubdomainResponse {
    subdomains: Vec<String>,
    #[serde(default)]
    subdomain_count: u64,
}

/// SecurityTrails DNS history response
#[derive(Debug, Deserialize)]
struct DnsHistoryResponse {
    records: Vec<DnsHistoryRecord>,
    #[serde(default)]
    pages: u32,
}

/// DNS history record
#[derive(Debug, Deserialize)]
struct DnsHistoryRecord {
    #[serde(rename = "type")]
    record_type: Option<String>,
    values: Vec<DnsValue>,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

/// DNS value
#[derive(Debug, Deserialize)]
struct DnsValue {
    ip: Option<String>,
    ip_organization: Option<String>,
}

/// WHOIS response
#[derive(Debug, Deserialize)]
struct WhoisResponse {
    result: Option<WhoisResult>,
}

/// WHOIS result
#[derive(Debug, Deserialize)]
struct WhoisResult {
    registrar: Option<String>,
    created_date: Option<String>,
    expires_date: Option<String>,
    updated_date: Option<String>,
    name_servers: Option<Vec<String>>,
    contacts: Option<serde_json::Value>,
}

/// SecurityTrails client
pub struct SecurityTrailsClient {
    client: Client,
    api_key: String,
    base_url: String,
}

impl SecurityTrailsClient {
    /// Create a new SecurityTrails client
    pub fn new(api_key: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("HeroForge Security Scanner")
            .build()?;

        Ok(Self {
            client,
            api_key,
            base_url: "https://api.securitytrails.com/v1".to_string(),
        })
    }

    /// Get subdomains for a domain
    pub async fn get_subdomains(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        info!("Querying SecurityTrails for subdomains of: {}", domain);

        let url = format!("{}/domain/{}/subdomains", self.base_url, domain);

        let response = self
            .client
            .get(&url)
            .header("apikey", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow::anyhow!("Invalid SecurityTrails API key"));
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            warn!("SecurityTrails rate limit exceeded");
            return Err(anyhow::anyhow!("SecurityTrails rate limit exceeded"));
        }

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "SecurityTrails API error {}: {}",
                status,
                text
            ));
        }

        let data: SubdomainResponse = response.json().await?;

        let results: Vec<SubdomainResult> = data
            .subdomains
            .into_iter()
            .map(|sub| SubdomainResult {
                subdomain: format!("{}.{}", sub, domain),
                source: "SecurityTrails".to_string(),
                first_seen: None,
                last_seen: None,
                additional_info: None,
            })
            .collect();

        info!(
            "Found {} subdomains from SecurityTrails for {}",
            results.len(),
            domain
        );

        Ok(results)
    }

    /// Get DNS history for a domain
    pub async fn get_dns_history(
        &self,
        domain: &str,
        record_type: &str,
    ) -> Result<Vec<PassiveDnsRecord>> {
        debug!(
            "Getting DNS history for {} (type: {})",
            domain, record_type
        );

        let url = format!(
            "{}/history/{}/dns/{}",
            self.base_url, domain, record_type.to_lowercase()
        );

        let response = self
            .client
            .get(&url)
            .header("apikey", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let data: DnsHistoryResponse = response.json().await?;

        let mut records: Vec<PassiveDnsRecord> = Vec::new();

        for record in data.records {
            for value in record.values {
                if let Some(ip) = value.ip {
                    records.push(PassiveDnsRecord {
                        record_type: record_type.to_uppercase(),
                        value: ip,
                        first_seen: record
                            .first_seen
                            .as_ref()
                            .and_then(|s| parse_date(s)),
                        last_seen: record
                            .last_seen
                            .as_ref()
                            .and_then(|s| parse_date(s)),
                        source: "SecurityTrails".to_string(),
                    });
                }
            }
        }

        Ok(records)
    }

    /// Get all DNS history types
    pub async fn get_full_dns_history(&self, domain: &str) -> Result<Vec<PassiveDnsRecord>> {
        let types = ["a", "aaaa", "mx", "ns", "txt", "soa"];

        let mut all_records: Vec<PassiveDnsRecord> = Vec::new();

        for record_type in &types {
            match self.get_dns_history(domain, record_type).await {
                Ok(records) => {
                    all_records.extend(records);
                }
                Err(e) => {
                    debug!("Failed to get {} history for {}: {}", record_type, domain, e);
                }
            }

            // Rate limiting
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(all_records)
    }

    /// Get WHOIS information
    pub async fn get_whois(&self, domain: &str) -> Result<WhoisInfo> {
        debug!("Getting WHOIS info for {}", domain);

        let url = format!("{}/domain/{}/whois", self.base_url, domain);

        let response = self
            .client
            .get(&url)
            .header("apikey", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to get WHOIS data"));
        }

        let data: WhoisResponse = response.json().await?;

        if let Some(result) = data.result {
            Ok(WhoisInfo {
                registrar: result.registrar,
                created_date: result.created_date.as_ref().and_then(|s| parse_date(s)),
                expires_date: result.expires_date.as_ref().and_then(|s| parse_date(s)),
                updated_date: result.updated_date.as_ref().and_then(|s| parse_date(s)),
                name_servers: result.name_servers.unwrap_or_default(),
            })
        } else {
            Err(anyhow::anyhow!("No WHOIS data available"))
        }
    }

    /// Get domain info summary
    pub async fn get_domain_info(&self, domain: &str) -> Result<DomainInfo> {
        let url = format!("{}/domain/{}", self.base_url, domain);

        let response = self
            .client
            .get(&url)
            .header("apikey", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to get domain info"));
        }

        let data: serde_json::Value = response.json().await?;

        let current_dns = data.get("current_dns").cloned();
        let alexa_rank = data
            .get("alexa_rank")
            .and_then(|v| v.as_i64())
            .map(|v| v as u64);
        let hostname = data
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(DomainInfo {
            domain: domain.to_string(),
            hostname,
            alexa_rank,
            current_dns,
        })
    }

    /// Get associated domains (by IP, NS, MX, etc.)
    pub async fn get_associated_domains(&self, domain: &str) -> Result<Vec<String>> {
        let url = format!("{}/domain/{}/associated", self.base_url, domain);

        let response = self
            .client
            .get(&url)
            .header("apikey", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let data: serde_json::Value = response.json().await?;

        let records = data
            .get("records")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("hostname").and_then(|h| h.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(records)
    }

    /// Search domains by IP
    pub async fn search_by_ip(&self, ip: &str) -> Result<Vec<String>> {
        let url = format!("{}/search/list", self.base_url);

        let body = serde_json::json!({
            "filter": {
                "ipv4": ip
            }
        });

        let response = self
            .client
            .post(&url)
            .header("apikey", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let data: serde_json::Value = response.json().await?;

        let records = data
            .get("records")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("hostname").and_then(|h| h.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(records)
    }
}

/// WHOIS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub registrar: Option<String>,
    pub created_date: Option<DateTime<Utc>>,
    pub expires_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,
    pub name_servers: Vec<String>,
}

/// Domain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain: String,
    pub hostname: Option<String>,
    pub alexa_rank: Option<u64>,
    pub current_dns: Option<serde_json::Value>,
}

/// Parse date string
fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    // Try ISO 8601 first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // Try simple date format
    let formats = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"];

    for fmt in &formats {
        if let Ok(naive) = chrono::NaiveDate::parse_from_str(s, fmt) {
            let datetime = naive.and_hms_opt(0, 0, 0)?;
            return Some(DateTime::from_naive_utc_and_offset(datetime, Utc));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_date() {
        let dt = parse_date("2024-01-15");
        assert!(dt.is_some());

        let dt = parse_date("2024-01-15T12:30:45Z");
        assert!(dt.is_some());
    }
}
