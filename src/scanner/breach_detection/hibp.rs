//! Have I Been Pwned API client
//!
//! Implements the HIBP v3 API for checking email breaches and paste exposures.
//! API documentation: https://haveibeenpwned.com/API/v3

use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDate, Utc};
use log::{debug, info};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

use super::types::{BreachInfo, BreachSeverity, BreachSource};

/// HIBP API base URL
const HIBP_API_URL: &str = "https://haveibeenpwned.com/api/v3";

/// User agent required by HIBP API
const HIBP_USER_AGENT: &str = "HeroForge-Security-Scanner";

/// Minimum delay between requests (HIBP rate limit)
const MIN_REQUEST_DELAY_MS: u64 = 1500;

/// HIBP API client
pub struct HibpClient {
    client: reqwest::Client,
    api_key: Option<String>,
    rate_limit_delay: Duration,
}

impl HibpClient {
    /// Create a new HIBP client
    pub fn new(api_key: Option<String>, timeout_secs: u64) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(HIBP_USER_AGENT));

        if let Some(ref key) = api_key {
            headers.insert(
                "hibp-api-key",
                HeaderValue::from_str(key).map_err(|e| anyhow!("Invalid API key: {}", e))?,
            );
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;

        Ok(Self {
            client,
            api_key,
            rate_limit_delay: Duration::from_millis(MIN_REQUEST_DELAY_MS),
        })
    }

    /// Check if the client has an API key configured
    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// Get all breaches for an email address
    pub async fn get_breaches_for_account(&self, email: &str) -> Result<Vec<HibpBreach>> {
        // Rate limiting
        sleep(self.rate_limit_delay).await;

        let url = format!("{}/breachedaccount/{}", HIBP_API_URL, urlencoding::encode(email));
        debug!("Checking HIBP for email: {}", email);

        let response = self.client.get(&url).query(&[("truncateResponse", "false")]).send().await;

        match response {
            Ok(resp) => {
                match resp.status().as_u16() {
                    200 => {
                        let breaches: Vec<HibpBreach> = resp.json().await?;
                        info!("Found {} breaches for {}", breaches.len(), email);
                        Ok(breaches)
                    }
                    404 => {
                        debug!("No breaches found for {}", email);
                        Ok(Vec::new())
                    }
                    401 => Err(anyhow!("HIBP API key required for account lookups")),
                    403 => Err(anyhow!("HIBP API key invalid or access forbidden")),
                    429 => Err(anyhow!("HIBP rate limit exceeded")),
                    status => Err(anyhow!("HIBP API error: HTTP {}", status)),
                }
            }
            Err(e) => Err(anyhow!("HIBP request failed: {}", e)),
        }
    }

    /// Get all breaches for a domain (requires API key)
    pub async fn get_breaches_for_domain(&self, domain: &str) -> Result<Vec<HibpDomainBreach>> {
        if !self.has_api_key() {
            return Err(anyhow!("HIBP API key required for domain searches"));
        }

        // Rate limiting
        sleep(self.rate_limit_delay).await;

        let url = format!("{}/breacheddomain/{}", HIBP_API_URL, urlencoding::encode(domain));
        debug!("Checking HIBP for domain: {}", domain);

        let response = self.client.get(&url).send().await;

        match response {
            Ok(resp) => {
                match resp.status().as_u16() {
                    200 => {
                        let breaches: Vec<HibpDomainBreach> = resp.json().await?;
                        info!("Found {} breach entries for domain {}", breaches.len(), domain);
                        Ok(breaches)
                    }
                    404 => {
                        debug!("No breaches found for domain {}", domain);
                        Ok(Vec::new())
                    }
                    401 => Err(anyhow!("HIBP API key required for domain lookups")),
                    403 => Err(anyhow!("HIBP API key invalid or access forbidden")),
                    429 => Err(anyhow!("HIBP rate limit exceeded")),
                    status => Err(anyhow!("HIBP API error: HTTP {}", status)),
                }
            }
            Err(e) => Err(anyhow!("HIBP request failed: {}", e)),
        }
    }

    /// Get information about a specific breach
    pub async fn get_breach(&self, breach_name: &str) -> Result<Option<HibpBreach>> {
        sleep(self.rate_limit_delay).await;

        let url = format!("{}/breach/{}", HIBP_API_URL, urlencoding::encode(breach_name));
        debug!("Getting breach details for: {}", breach_name);

        let response = self.client.get(&url).send().await;

        match response {
            Ok(resp) => {
                match resp.status().as_u16() {
                    200 => {
                        let breach: HibpBreach = resp.json().await?;
                        Ok(Some(breach))
                    }
                    404 => Ok(None),
                    status => Err(anyhow!("HIBP API error: HTTP {}", status)),
                }
            }
            Err(e) => Err(anyhow!("HIBP request failed: {}", e)),
        }
    }

    /// Get all known breaches in the HIBP database
    pub async fn get_all_breaches(&self) -> Result<Vec<HibpBreach>> {
        sleep(self.rate_limit_delay).await;

        let url = format!("{}/breaches", HIBP_API_URL);
        debug!("Fetching all HIBP breaches");

        let response = self.client.get(&url).send().await?;

        if response.status().is_success() {
            let breaches: Vec<HibpBreach> = response.json().await?;
            info!("Retrieved {} breaches from HIBP", breaches.len());
            Ok(breaches)
        } else {
            Err(anyhow!("Failed to get breaches: HTTP {}", response.status()))
        }
    }

    /// Get all pastes for an email address
    pub async fn get_pastes_for_account(&self, email: &str) -> Result<Vec<HibpPaste>> {
        if !self.has_api_key() {
            return Err(anyhow!("HIBP API key required for paste lookups"));
        }

        sleep(self.rate_limit_delay).await;

        let url = format!("{}/pasteaccount/{}", HIBP_API_URL, urlencoding::encode(email));
        debug!("Checking HIBP pastes for: {}", email);

        let response = self.client.get(&url).send().await;

        match response {
            Ok(resp) => {
                match resp.status().as_u16() {
                    200 => {
                        let pastes: Vec<HibpPaste> = resp.json().await?;
                        info!("Found {} pastes for {}", pastes.len(), email);
                        Ok(pastes)
                    }
                    404 => {
                        debug!("No pastes found for {}", email);
                        Ok(Vec::new())
                    }
                    401 | 403 => Err(anyhow!("HIBP API key required for paste lookups")),
                    429 => Err(anyhow!("HIBP rate limit exceeded")),
                    status => Err(anyhow!("HIBP API error: HTTP {}", status)),
                }
            }
            Err(e) => Err(anyhow!("HIBP request failed: {}", e)),
        }
    }
}

/// HIBP breach response from the API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HibpBreach {
    /// The name of the breach
    pub name: String,
    /// Human-readable title
    pub title: String,
    /// Domain of the breached site
    pub domain: String,
    /// Date the breach occurred (YYYY-MM-DD format)
    pub breach_date: String,
    /// Date the breach was added to HIBP
    pub added_date: String,
    /// Date the breach was last modified
    pub modified_date: String,
    /// Number of accounts in the breach
    pub pwn_count: u64,
    /// Description of the breach (HTML)
    pub description: String,
    /// URL to the logo
    pub logo_path: String,
    /// Data classes exposed in the breach
    pub data_classes: Vec<String>,
    /// Whether the breach is verified
    pub is_verified: bool,
    /// Whether the breach contains fabricated data
    pub is_fabricated: bool,
    /// Whether the breach is sensitive
    pub is_sensitive: bool,
    /// Whether the breach is retired
    pub is_retired: bool,
    /// Whether the breach is from a spam list
    pub is_spam_list: bool,
    /// Whether the breach is a subscription list
    #[serde(default)]
    pub is_subscription_free: bool,
}

impl HibpBreach {
    /// Convert to our internal BreachInfo type
    pub fn to_breach_info(&self) -> BreachInfo {
        let breach_date = NaiveDate::parse_from_str(&self.breach_date, "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));

        let added_date = DateTime::parse_from_rfc3339(&self.added_date)
            .ok()
            .map(|dt| dt.with_timezone(&Utc));

        let modified_date = DateTime::parse_from_rfc3339(&self.modified_date)
            .ok()
            .map(|dt| dt.with_timezone(&Utc));

        let severity = BreachSeverity::from_data_types(&self.data_classes);

        BreachInfo {
            name: self.name.clone(),
            title: self.title.clone(),
            domain: self.domain.clone(),
            breach_date,
            added_date,
            modified_date,
            pwn_count: Some(self.pwn_count),
            description: Some(strip_html_tags(&self.description)),
            data_classes: self.data_classes.clone(),
            is_verified: self.is_verified,
            is_fabricated: self.is_fabricated,
            is_sensitive: self.is_sensitive,
            is_spam_list: self.is_spam_list,
            logo_path: Some(self.logo_path.clone()),
            source: BreachSource::Hibp,
            severity,
        }
    }
}

/// Domain breach response from HIBP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HibpDomainBreach {
    /// Email alias (the part before @)
    pub alias: String,
    /// List of breach names affecting this email
    pub breaches: Vec<String>,
}

/// HIBP paste response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HibpPaste {
    /// The source of the paste (Pastebin, Ghostbin, etc.)
    pub source: String,
    /// Unique ID of the paste
    pub id: String,
    /// Title of the paste (if available)
    pub title: Option<String>,
    /// Date the paste was found
    pub date: Option<String>,
    /// Number of emails in the paste
    pub email_count: u32,
}

/// Strip HTML tags from a string
fn strip_html_tags(html: &str) -> String {
    // Simple HTML tag stripping - in production, use a proper HTML parser
    let mut result = String::new();
    let mut in_tag = false;

    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }

    // Decode common HTML entities
    result
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_html_tags() {
        let html = "<p>This is a <strong>test</strong> with &amp; entities.</p>";
        let stripped = strip_html_tags(html);
        assert_eq!(stripped, "This is a test with & entities.");
    }

    #[test]
    fn test_hibp_breach_to_breach_info() {
        let hibp = HibpBreach {
            name: "TestBreach".to_string(),
            title: "Test Breach".to_string(),
            domain: "test.com".to_string(),
            breach_date: "2021-01-15".to_string(),
            added_date: "2021-02-01T00:00:00Z".to_string(),
            modified_date: "2021-02-01T00:00:00Z".to_string(),
            pwn_count: 1000000,
            description: "<p>A test breach</p>".to_string(),
            logo_path: "https://example.com/logo.png".to_string(),
            data_classes: vec!["Email addresses".to_string(), "Passwords".to_string()],
            is_verified: true,
            is_fabricated: false,
            is_sensitive: false,
            is_retired: false,
            is_spam_list: false,
            is_subscription_free: false,
        };

        let info = hibp.to_breach_info();
        assert_eq!(info.name, "TestBreach");
        assert_eq!(info.severity, BreachSeverity::Critical);
        assert_eq!(info.source, BreachSource::Hibp);
    }
}
