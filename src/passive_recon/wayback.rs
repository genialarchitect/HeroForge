//! Wayback Machine (archive.org) Client
//!
//! Queries the Internet Archive's Wayback Machine to find historical URLs
//! and content for a domain.

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

use super::HistoricalUrl;

/// Wayback Machine CDX API response
#[derive(Debug, Clone, Deserialize)]
pub struct CdxResponse(Vec<Vec<String>>);

/// Wayback Machine client
pub struct WaybackClient {
    client: Client,
    base_url: String,
}

impl WaybackClient {
    /// Create a new Wayback Machine client
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent("HeroForge Security Scanner")
            .build()?;

        Ok(Self {
            client,
            base_url: "https://web.archive.org".to_string(),
        })
    }

    /// Get historical URLs for a domain
    pub async fn get_urls(&self, domain: &str, limit: Option<usize>) -> Result<Vec<HistoricalUrl>> {
        info!("Querying Wayback Machine for domain: {}", domain);

        let mut params = vec![
            ("url", format!("*.{}/*", domain)),
            ("output", "json".to_string()),
            ("fl", "timestamp,original,mimetype,statuscode".to_string()),
            ("collapse", "urlkey".to_string()),
        ];

        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }

        let url = format!("{}/cdx/search/cdx", self.base_url);

        let response = self.client.get(&url).query(&params).send().await?;

        if !response.status().is_success() {
            warn!("Wayback Machine returned status: {}", response.status());
            return Ok(Vec::new());
        }

        let text = response.text().await?;

        if text.is_empty() {
            return Ok(Vec::new());
        }

        let rows: Vec<Vec<String>> = match serde_json::from_str(&text) {
            Ok(r) => r,
            Err(e) => {
                // Try line-by-line parsing
                debug!("JSON parsing failed, trying line parsing: {}", e);
                return self.parse_cdx_lines(&text);
            }
        };

        // Skip header row
        let mut results: Vec<HistoricalUrl> = Vec::new();
        for (i, row) in rows.iter().enumerate() {
            if i == 0 {
                continue; // Skip header
            }

            if row.len() >= 4 {
                let timestamp = parse_wayback_timestamp(&row[0]);
                let url = row[1].clone();
                let mime_type = if row[2].is_empty() {
                    None
                } else {
                    Some(row[2].clone())
                };
                let status_code = row[3].parse::<u16>().ok();

                if let Some(ts) = timestamp {
                    results.push(HistoricalUrl {
                        url,
                        timestamp: ts,
                        mime_type,
                        status_code,
                    });
                }
            }
        }

        info!(
            "Found {} historical URLs from Wayback Machine for {}",
            results.len(),
            domain
        );

        Ok(results)
    }

    /// Parse CDX lines (fallback for non-JSON output)
    fn parse_cdx_lines(&self, text: &str) -> Result<Vec<HistoricalUrl>> {
        let mut results: Vec<HistoricalUrl> = Vec::new();

        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let timestamp = parse_wayback_timestamp(parts[0]);
                let url = parts[1].to_string();
                let mime_type = Some(parts[2].to_string());
                let status_code = parts[3].parse::<u16>().ok();

                if let Some(ts) = timestamp {
                    results.push(HistoricalUrl {
                        url,
                        timestamp: ts,
                        mime_type,
                        status_code,
                    });
                }
            }
        }

        Ok(results)
    }

    /// Get subdomains from Wayback Machine URLs
    pub async fn get_subdomains(&self, domain: &str) -> Result<Vec<String>> {
        let urls = self.get_urls(domain, Some(10000)).await?;

        let mut subdomains: HashSet<String> = HashSet::new();

        for url_record in urls {
            if let Ok(parsed) = reqwest::Url::parse(&url_record.url) {
                if let Some(host) = parsed.host_str() {
                    let host = host.to_lowercase();
                    if host.ends_with(domain) || host == domain {
                        subdomains.insert(host);
                    }
                }
            }
        }

        Ok(subdomains.into_iter().collect())
    }

    /// Find sensitive files/paths from historical URLs
    pub async fn find_sensitive_paths(&self, domain: &str) -> Result<Vec<SensitivePath>> {
        let urls = self.get_urls(domain, Some(50000)).await?;

        let sensitive_patterns = [
            (".git", "Git repository"),
            (".env", "Environment file"),
            ("config", "Configuration file"),
            ("backup", "Backup file"),
            (".bak", "Backup file"),
            (".old", "Old file"),
            ("admin", "Admin panel"),
            ("phpinfo", "PHP info"),
            (".sql", "SQL dump"),
            (".zip", "Archive"),
            (".tar", "Archive"),
            ("wp-config", "WordPress config"),
            (".htaccess", "Apache config"),
            (".htpasswd", "Apache passwords"),
            ("web.config", "IIS config"),
            ("robots.txt", "Robots file"),
            ("sitemap.xml", "Sitemap"),
            ("/api/", "API endpoint"),
            ("swagger", "API documentation"),
            ("graphql", "GraphQL endpoint"),
            (".json", "JSON file"),
            (".xml", "XML file"),
            ("credentials", "Credentials file"),
            ("password", "Password related"),
            ("secret", "Secret file"),
            ("private", "Private file"),
            ("debug", "Debug endpoint"),
            ("test", "Test endpoint"),
            ("staging", "Staging environment"),
            ("dev", "Development environment"),
        ];

        let mut sensitive: Vec<SensitivePath> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for url_record in urls {
            let lower_url = url_record.url.to_lowercase();

            for (pattern, description) in &sensitive_patterns {
                if lower_url.contains(pattern) && !seen.contains(&url_record.url) {
                    seen.insert(url_record.url.clone());

                    sensitive.push(SensitivePath {
                        url: url_record.url.clone(),
                        pattern: pattern.to_string(),
                        description: description.to_string(),
                        last_seen: url_record.timestamp,
                        status_code: url_record.status_code,
                    });
                    break;
                }
            }
        }

        info!("Found {} sensitive paths for {}", sensitive.len(), domain);

        Ok(sensitive)
    }

    /// Get snapshots for a specific URL
    pub async fn get_snapshots(&self, url: &str) -> Result<Vec<Snapshot>> {
        let params = [
            ("url", url),
            ("output", "json"),
            ("fl", "timestamp,statuscode,digest"),
        ];

        let api_url = format!("{}/cdx/search/cdx", self.base_url);

        let response = self.client.get(&api_url).query(&params).send().await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let text = response.text().await?;

        if text.is_empty() {
            return Ok(Vec::new());
        }

        let rows: Vec<Vec<String>> = match serde_json::from_str(&text) {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        let mut snapshots: Vec<Snapshot> = Vec::new();

        for (i, row) in rows.iter().enumerate() {
            if i == 0 || row.len() < 3 {
                continue;
            }

            if let Some(ts) = parse_wayback_timestamp(&row[0]) {
                snapshots.push(Snapshot {
                    timestamp: ts,
                    archive_url: format!(
                        "{}/web/{}/{}",
                        self.base_url, row[0], url
                    ),
                    status_code: row[1].parse().ok(),
                    digest: row[2].clone(),
                });
            }
        }

        Ok(snapshots)
    }
}

impl Default for WaybackClient {
    fn default() -> Self {
        Self::new().expect("Failed to create WaybackClient")
    }
}

/// Sensitive path found in historical URLs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivePath {
    pub url: String,
    pub pattern: String,
    pub description: String,
    pub last_seen: DateTime<Utc>,
    pub status_code: Option<u16>,
}

/// Archive snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub archive_url: String,
    pub status_code: Option<u16>,
    pub digest: String,
}

/// Parse Wayback Machine timestamp (YYYYMMDDHHmmss format)
fn parse_wayback_timestamp(s: &str) -> Option<DateTime<Utc>> {
    if s.len() >= 14 {
        let fmt = "%Y%m%d%H%M%S";
        if let Ok(naive) = NaiveDateTime::parse_from_str(&s[..14], fmt) {
            return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_parse_wayback_timestamp() {
        let ts = parse_wayback_timestamp("20240115123045");
        assert!(ts.is_some());

        let ts = ts.unwrap();
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 1);
        assert_eq!(ts.day(), 15);
    }
}
