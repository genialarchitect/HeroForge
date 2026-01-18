//! Certificate Transparency Log Search via crt.sh
//!
//! Queries crt.sh to find subdomains from SSL/TLS certificate transparency logs.

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

use super::SubdomainResult;

/// crt.sh API response entry
#[derive(Debug, Clone, Deserialize)]
pub struct CrtshEntry {
    pub issuer_ca_id: Option<i64>,
    pub issuer_name: Option<String>,
    pub common_name: Option<String>,
    pub name_value: Option<String>,
    pub id: Option<i64>,
    pub entry_timestamp: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub serial_number: Option<String>,
}

/// Client for querying crt.sh certificate transparency logs
pub struct CrtshClient {
    client: Client,
    base_url: String,
}

impl CrtshClient {
    /// Create a new crt.sh client
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("HeroForge Security Scanner")
            .build()?;

        Ok(Self {
            client,
            base_url: "https://crt.sh".to_string(),
        })
    }

    /// Search for subdomains using certificate transparency logs
    pub async fn find_subdomains(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        info!("Querying crt.sh for domain: {}", domain);

        let url = format!("{}/?q=%.{}&output=json", self.base_url, domain);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            warn!("crt.sh returned status: {}", response.status());
            return Ok(Vec::new());
        }

        let text = response.text().await?;

        // crt.sh sometimes returns empty response or HTML error page
        if text.is_empty() || text.starts_with("<!DOCTYPE") || text.starts_with("<html") {
            debug!("No results from crt.sh for {}", domain);
            return Ok(Vec::new());
        }

        let entries: Vec<CrtshEntry> = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to parse crt.sh response: {}", e);
                return Ok(Vec::new());
            }
        };

        // Extract unique subdomains
        let mut seen: HashSet<String> = HashSet::new();
        let mut results: Vec<SubdomainResult> = Vec::new();

        for entry in entries {
            if let Some(name_value) = &entry.name_value {
                // name_value can contain multiple domains separated by newlines
                for name in name_value.lines() {
                    let name = name.trim().to_lowercase();

                    // Skip wildcards and already seen
                    if name.starts_with('*') || seen.contains(&name) {
                        continue;
                    }

                    // Validate it's a subdomain of the target
                    if !name.ends_with(domain) && name != domain {
                        continue;
                    }

                    seen.insert(name.clone());

                    let first_seen = entry
                        .not_before
                        .as_ref()
                        .and_then(|s| parse_crtsh_timestamp(s));
                    let last_seen = entry
                        .not_after
                        .as_ref()
                        .and_then(|s| parse_crtsh_timestamp(s));

                    results.push(SubdomainResult {
                        subdomain: name,
                        source: "crt.sh".to_string(),
                        first_seen,
                        last_seen,
                        additional_info: Some(serde_json::json!({
                            "issuer": entry.issuer_name,
                            "cert_id": entry.id,
                        })),
                    });
                }
            }

            // Also check common_name
            if let Some(cn) = &entry.common_name {
                let cn = cn.trim().to_lowercase();
                if !cn.starts_with('*') && !seen.contains(&cn) {
                    if cn.ends_with(domain) || cn == domain {
                        seen.insert(cn.clone());

                        let first_seen = entry
                            .not_before
                            .as_ref()
                            .and_then(|s| parse_crtsh_timestamp(s));

                        results.push(SubdomainResult {
                            subdomain: cn,
                            source: "crt.sh".to_string(),
                            first_seen,
                            last_seen: None,
                            additional_info: None,
                        });
                    }
                }
            }
        }

        info!(
            "Found {} unique subdomains from crt.sh for {}",
            results.len(),
            domain
        );

        Ok(results)
    }

    /// Get certificate details by ID
    pub async fn get_certificate(&self, cert_id: i64) -> Result<Option<CertificateDetails>> {
        let url = format!("{}/?id={}&output=json", self.base_url, cert_id);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let text = response.text().await?;

        if text.is_empty() || text.starts_with("<!DOCTYPE") {
            return Ok(None);
        }

        let entries: Vec<CrtshEntry> = serde_json::from_str(&text)?;

        if let Some(entry) = entries.first() {
            Ok(Some(CertificateDetails {
                id: entry.id.unwrap_or(cert_id),
                issuer_name: entry.issuer_name.clone().unwrap_or_default(),
                common_name: entry.common_name.clone().unwrap_or_default(),
                san_entries: entry
                    .name_value
                    .as_ref()
                    .map(|nv| nv.lines().map(|s| s.to_string()).collect())
                    .unwrap_or_default(),
                not_before: entry
                    .not_before
                    .as_ref()
                    .and_then(|s| parse_crtsh_timestamp(s)),
                not_after: entry
                    .not_after
                    .as_ref()
                    .and_then(|s| parse_crtsh_timestamp(s)),
                serial_number: entry.serial_number.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Find certificates for organization name
    pub async fn find_by_organization(&self, org: &str) -> Result<Vec<SubdomainResult>> {
        info!("Querying crt.sh for organization: {}", org);

        let url = format!("{}/?O={}&output=json", self.base_url, urlencoding::encode(org));

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let text = response.text().await?;

        if text.is_empty() || text.starts_with("<!DOCTYPE") {
            return Ok(Vec::new());
        }

        let entries: Vec<CrtshEntry> = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(_) => return Ok(Vec::new()),
        };

        let mut seen: HashSet<String> = HashSet::new();
        let mut results: Vec<SubdomainResult> = Vec::new();

        for entry in entries {
            if let Some(name_value) = &entry.name_value {
                for name in name_value.lines() {
                    let name = name.trim().to_lowercase();
                    if name.starts_with('*') || seen.contains(&name) {
                        continue;
                    }
                    seen.insert(name.clone());

                    results.push(SubdomainResult {
                        subdomain: name,
                        source: "crt.sh".to_string(),
                        first_seen: entry
                            .not_before
                            .as_ref()
                            .and_then(|s| parse_crtsh_timestamp(s)),
                        last_seen: None,
                        additional_info: Some(serde_json::json!({
                            "organization": org,
                            "issuer": entry.issuer_name,
                        })),
                    });
                }
            }
        }

        info!("Found {} domains for organization {}", results.len(), org);
        Ok(results)
    }
}

impl Default for CrtshClient {
    fn default() -> Self {
        Self::new().expect("Failed to create CrtshClient")
    }
}

/// Certificate details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDetails {
    pub id: i64,
    pub issuer_name: String,
    pub common_name: String,
    pub san_entries: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub serial_number: Option<String>,
}

/// Parse crt.sh timestamp format
fn parse_crtsh_timestamp(s: &str) -> Option<DateTime<Utc>> {
    // Try multiple formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
    ];

    for fmt in &formats {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_timestamp() {
        let ts = parse_crtsh_timestamp("2024-01-15T12:30:45");
        assert!(ts.is_some());

        let ts = parse_crtsh_timestamp("2024-01-15 12:30:45");
        assert!(ts.is_some());
    }
}
