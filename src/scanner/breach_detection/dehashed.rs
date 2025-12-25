//! Dehashed API client
//!
//! Implements the Dehashed API for more detailed breach data lookups.
//! API documentation: https://www.dehashed.com/docs

use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, info};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

use super::types::{BreachInfo, BreachSeverity, BreachSource, ExposedCredential};

/// Dehashed API base URL
const DEHASHED_API_URL: &str = "https://api.dehashed.com/search";

/// Minimum delay between requests (to be safe with rate limits)
const MIN_REQUEST_DELAY_MS: u64 = 1000;

/// Dehashed API client
pub struct DehashedClient {
    client: reqwest::Client,
    email: String,
    api_key: String,
    rate_limit_delay: Duration,
}

impl DehashedClient {
    /// Create a new Dehashed client
    pub fn new(email: String, api_key: String, timeout_secs: u64) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        // Dehashed uses Basic Auth with email:api_key
        let auth_string = format!("{}:{}", email, api_key);
        let auth_value = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, auth_string));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_value).map_err(|e| anyhow!("Invalid auth: {}", e))?,
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;

        Ok(Self {
            client,
            email,
            api_key,
            rate_limit_delay: Duration::from_millis(MIN_REQUEST_DELAY_MS),
        })
    }

    /// Search for breaches by email
    pub async fn search_by_email(&self, email: &str) -> Result<DehashedResponse> {
        self.search(&format!("email:{}", email)).await
    }

    /// Search for breaches by domain
    pub async fn search_by_domain(&self, domain: &str) -> Result<DehashedResponse> {
        self.search(&format!("email:*@{}", domain)).await
    }

    /// Search for breaches by username
    pub async fn search_by_username(&self, username: &str) -> Result<DehashedResponse> {
        self.search(&format!("username:{}", username)).await
    }

    /// Perform a search query
    async fn search(&self, query: &str) -> Result<DehashedResponse> {
        // Rate limiting
        sleep(self.rate_limit_delay).await;

        debug!("Searching Dehashed: {}", query);

        let response = self
            .client
            .get(DEHASHED_API_URL)
            .query(&[("query", query), ("size", "10000")])
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    let result: DehashedResponse = resp.json().await?;
                    info!(
                        "Dehashed search found {} entries (balance: {})",
                        result.total, result.balance
                    );
                    Ok(result)
                } else if status.as_u16() == 401 {
                    Err(anyhow!("Dehashed API authentication failed"))
                } else if status.as_u16() == 429 {
                    Err(anyhow!("Dehashed rate limit exceeded"))
                } else if status.as_u16() == 402 {
                    Err(anyhow!("Dehashed API: Insufficient balance"))
                } else {
                    let error_text = resp.text().await.unwrap_or_default();
                    Err(anyhow!("Dehashed API error ({}): {}", status, error_text))
                }
            }
            Err(e) => Err(anyhow!("Dehashed request failed: {}", e)),
        }
    }

    /// Convert Dehashed entries to our internal format
    pub fn entries_to_exposures(&self, entries: &[DehashedEntry]) -> Vec<ExposedCredential> {
        entries
            .iter()
            .filter_map(|entry| {
                // Skip entries without email
                let email = entry.email.as_ref()?;
                if email.is_empty() {
                    return None;
                }

                let domain = email.split('@').nth(1).unwrap_or("").to_string();
                let database = entry.database.as_deref().unwrap_or("Unknown");

                // Determine data types exposed
                let mut data_classes = Vec::new();
                if entry.email.is_some() {
                    data_classes.push("Email addresses".to_string());
                }
                if entry.password.is_some() {
                    data_classes.push("Passwords".to_string());
                }
                if entry.hashed_password.is_some() {
                    data_classes.push("Password hashes".to_string());
                }
                if entry.username.is_some() {
                    data_classes.push("Usernames".to_string());
                }
                if entry.name.is_some() {
                    data_classes.push("Names".to_string());
                }
                if entry.phone.is_some() {
                    data_classes.push("Phone numbers".to_string());
                }
                if entry.address.is_some() {
                    data_classes.push("Physical addresses".to_string());
                }
                if entry.ip_address.is_some() {
                    data_classes.push("IP addresses".to_string());
                }

                let breach = BreachInfo {
                    name: database.to_string(),
                    title: database.to_string(),
                    domain: domain.clone(),
                    breach_date: None,
                    added_date: None,
                    modified_date: None,
                    pwn_count: None,
                    description: Some(format!("Data from {} database", database)),
                    data_classes: data_classes.clone(),
                    is_verified: false,
                    is_fabricated: false,
                    is_sensitive: false,
                    is_spam_list: false,
                    logo_path: None,
                    source: BreachSource::Dehashed,
                    severity: BreachSeverity::from_data_types(&data_classes),
                };

                // Check for password hash type
                let (password_hash_exposed, hash_type) = if entry.hashed_password.is_some() {
                    let hash = entry.hashed_password.as_deref().unwrap_or("");
                    let hash_type = detect_hash_type(hash);
                    (true, hash_type)
                } else if entry.password.is_some() {
                    // Plaintext password - even worse
                    (true, Some("plaintext".to_string()))
                } else {
                    (false, None)
                };

                Some(ExposedCredential {
                    email: email.clone(),
                    domain,
                    breach: breach,
                    password_hash_exposed,
                    hash_type,
                    discovered_at: Utc::now(),
                    source: BreachSource::Dehashed,
                })
            })
            .collect()
    }
}

/// Response from Dehashed API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehashedResponse {
    /// Current API balance
    pub balance: i32,
    /// Total number of entries found
    pub total: u64,
    /// Returned entries (may be paginated)
    #[serde(default)]
    pub entries: Vec<DehashedEntry>,
    /// Error message if any
    pub message: Option<String>,
}

/// Single entry from Dehashed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehashedEntry {
    /// Entry ID
    pub id: Option<String>,
    /// Email address
    pub email: Option<String>,
    /// Username
    pub username: Option<String>,
    /// Plaintext password (if exposed - NEVER store this!)
    pub password: Option<String>,
    /// Hashed password
    pub hashed_password: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// Full name
    pub name: Option<String>,
    /// Phone number
    pub phone: Option<String>,
    /// Physical address
    pub address: Option<String>,
    /// VIN number
    pub vin: Option<String>,
    /// Database/breach name
    pub database: Option<String>,
}

/// Detect the type of password hash
fn detect_hash_type(hash: &str) -> Option<String> {
    let hash = hash.trim();
    let len = hash.len();

    // Check for common hash patterns
    if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
        return Some("bcrypt".to_string());
    }
    if hash.starts_with("$argon2") {
        return Some("argon2".to_string());
    }
    if hash.starts_with("$5$") {
        return Some("sha256crypt".to_string());
    }
    if hash.starts_with("$6$") {
        return Some("sha512crypt".to_string());
    }
    if hash.starts_with("$1$") {
        return Some("md5crypt".to_string());
    }
    if hash.starts_with("$pbkdf2") {
        return Some("pbkdf2".to_string());
    }

    // Check by length (hex-encoded hashes)
    if hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return match len {
            32 => Some("md5".to_string()),
            40 => Some("sha1".to_string()),
            64 => Some("sha256".to_string()),
            128 => Some("sha512".to_string()),
            _ => Some(format!("unknown-{}", len)),
        };
    }

    // Base64-encoded might be various things
    if hash.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        return Some("base64-encoded".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hash_type() {
        assert_eq!(detect_hash_type("$2a$12$abcdef"), Some("bcrypt".to_string()));
        assert_eq!(detect_hash_type("$argon2id$v=19$"), Some("argon2".to_string()));
        assert_eq!(
            detect_hash_type("5d41402abc4b2a76b9719d911017c592"),
            Some("md5".to_string())
        );
        assert_eq!(
            detect_hash_type("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            Some("sha1".to_string())
        );
    }
}
