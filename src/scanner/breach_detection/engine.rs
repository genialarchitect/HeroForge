//! Breach Detection Engine
//!
//! Coordinates breach checking across multiple data sources:
//! - Have I Been Pwned (HIBP)
//! - Dehashed
//! - Local breach database
//!
//! Provides unified interface for email, domain, and password breach checking.

use anyhow::{anyhow, Result};
use chrono::Utc;
use log::{debug, error, info, warn};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use uuid::Uuid;

use super::dehashed::DehashedClient;
use super::hibp::HibpClient;
use super::local_db::LocalBreachDb;
use super::types::*;

/// Password checking client using HIBP k-anonymity model
pub struct PasswordCheckClient {
    client: reqwest::Client,
}

impl PasswordCheckClient {
    /// Create a new password check client
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self { client })
    }

    /// Check if a password has been compromised using k-anonymity
    ///
    /// This method uses the HIBP Passwords API which implements k-anonymity:
    /// 1. Hash the password with SHA-1
    /// 2. Send only the first 5 characters of the hash to the API
    /// 3. API returns all hash suffixes matching that prefix
    /// 4. Check locally if the full hash is in the returned list
    ///
    /// This ensures the full password hash is never transmitted.
    pub async fn check_password(&self, password: &str) -> Result<PasswordBreachResult> {
        // Hash the password with SHA-1
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = format!("{:X}", hash);

        // Split into prefix (first 5 chars) and suffix (rest)
        let prefix = &hash_hex[..5];
        let suffix = &hash_hex[5..];

        // Query the HIBP API with just the prefix
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);
        debug!("Checking password hash prefix: {}", prefix);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "HIBP Passwords API error: HTTP {}",
                response.status()
            ));
        }

        let body = response.text().await?;

        // Parse the response and look for our suffix
        for line in body.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 {
                let returned_suffix = parts[0];
                if returned_suffix.eq_ignore_ascii_case(suffix) {
                    let count: u64 = parts[1].parse().unwrap_or(0);
                    info!("Password found in {} breaches", count);
                    return Ok(PasswordBreachResult {
                        compromised: true,
                        count,
                        hash_prefix: prefix.to_string(),
                    });
                }
            }
        }

        debug!("Password not found in breach database");
        Ok(PasswordBreachResult {
            compromised: false,
            count: 0,
            hash_prefix: prefix.to_string(),
        })
    }
}

/// Result of password breach check
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PasswordBreachResult {
    /// Whether the password was found in any breach
    pub compromised: bool,
    /// Number of times the password appeared in breaches
    pub count: u64,
    /// The SHA-1 hash prefix that was queried (for transparency)
    pub hash_prefix: String,
}

/// Main breach detection engine
pub struct BreachDetectionEngine {
    /// HIBP client
    hibp: Option<HibpClient>,
    /// Dehashed client
    dehashed: Option<DehashedClient>,
    /// Local breach database
    local_db: Option<LocalBreachDb>,
    /// Password check client
    password_client: PasswordCheckClient,
    /// Configuration
    config: BreachDetectionConfig,
}

impl BreachDetectionEngine {
    /// Create a new breach detection engine with the given configuration
    pub fn new(config: BreachDetectionConfig) -> Result<Self> {
        let hibp = if let Some(ref api_key) = config.hibp_api_key {
            Some(HibpClient::new(Some(api_key.clone()), config.timeout_secs)?)
        } else {
            Some(HibpClient::new(None, config.timeout_secs)?)
        };

        let dehashed = if let (Some(ref email), Some(ref api_key)) =
            (&config.dehashed_email, &config.dehashed_api_key)
        {
            Some(DehashedClient::new(
                email.clone(),
                api_key.clone(),
                config.timeout_secs,
            )?)
        } else {
            None
        };

        let local_db = if config.use_local_db {
            LocalBreachDb::new().ok()
        } else {
            None
        };

        let password_client = PasswordCheckClient::new()?;

        Ok(Self {
            hibp,
            dehashed,
            local_db,
            password_client,
            config,
        })
    }

    /// Create engine with default configuration from environment variables
    pub fn from_env() -> Result<Self> {
        Self::new(BreachDetectionConfig::default())
    }

    /// Check if HIBP API key is configured
    pub fn has_hibp_key(&self) -> bool {
        self.hibp.as_ref().map(|h| h.has_api_key()).unwrap_or(false)
    }

    /// Check if Dehashed is configured
    pub fn has_dehashed(&self) -> bool {
        self.dehashed.is_some()
    }

    /// Check a single email for breaches
    pub async fn check_email(&self, email: &str, include_unverified: bool) -> Result<BreachCheckResult> {
        let check_id = Uuid::new_v4().to_string();
        let mut breaches = Vec::new();
        let mut exposures = Vec::new();
        let mut errors = Vec::new();
        let mut sources_checked = Vec::new();

        // Check HIBP
        if let Some(ref hibp) = self.hibp {
            sources_checked.push(BreachSource::Hibp);
            match hibp.get_breaches_for_account(email).await {
                Ok(hibp_breaches) => {
                    for breach in hibp_breaches {
                        if !include_unverified && !breach.is_verified {
                            continue;
                        }
                        let info = breach.to_breach_info();
                        let domain = email.split('@').nth(1).unwrap_or("").to_string();

                        exposures.push(ExposedCredential {
                            email: email.to_string(),
                            domain: domain.clone(),
                            breach: info.clone(),
                            password_hash_exposed: info
                                .data_classes
                                .iter()
                                .any(|dc| dc.to_lowercase().contains("password")),
                            hash_type: None,
                            discovered_at: Utc::now(),
                            source: BreachSource::Hibp,
                        });

                        if !breaches.iter().any(|b: &BreachInfo| b.name == info.name) {
                            breaches.push(info);
                        }
                    }
                }
                Err(e) => {
                    error!("HIBP check failed for {}: {}", email, e);
                    errors.push(format!("HIBP: {}", e));
                }
            }
        }

        // Check Dehashed if configured
        if let Some(ref dehashed) = self.dehashed {
            sources_checked.push(BreachSource::Dehashed);
            match dehashed.search_by_email(email).await {
                Ok(response) => {
                    let dh_exposures = dehashed.entries_to_exposures(&response.entries);
                    for exp in dh_exposures {
                        if !breaches.iter().any(|b: &BreachInfo| b.name == exp.breach.name) {
                            breaches.push(exp.breach.clone());
                        }
                        exposures.push(exp);
                    }
                }
                Err(e) => {
                    warn!("Dehashed check failed for {}: {}", email, e);
                    errors.push(format!("Dehashed: {}", e));
                }
            }
        }

        // Check local database
        if let Some(ref local_db) = self.local_db {
            sources_checked.push(BreachSource::LocalDatabase);
            if let Some(local_exposures) = local_db.check_email(email) {
                for exp in local_exposures {
                    if !breaches.iter().any(|b: &BreachInfo| b.name == exp.breach.name) {
                        breaches.push(exp.breach.clone());
                    }
                    exposures.push(exp);
                }
            }
        }

        // Calculate statistics
        let stats = self.calculate_stats(&exposures, &breaches);

        Ok(BreachCheckResult {
            id: check_id,
            check_type: BreachCheckType::Email,
            target: email.to_string(),
            checked_at: Utc::now(),
            exposures,
            breaches,
            stats,
            errors,
            sources_checked,
        })
    }

    /// Check a domain for breaches (all emails at that domain)
    pub async fn check_domain(&self, domain: &str) -> Result<BreachCheckResult> {
        let check_id = Uuid::new_v4().to_string();
        let mut breaches = Vec::new();
        let mut exposures = Vec::new();
        let mut errors = Vec::new();
        let mut sources_checked = Vec::new();

        // Check HIBP domain search (requires API key)
        if let Some(ref hibp) = self.hibp {
            if hibp.has_api_key() {
                sources_checked.push(BreachSource::Hibp);
                match hibp.get_breaches_for_domain(domain).await {
                    Ok(domain_breaches) => {
                        // Domain breaches return aliases and breach names
                        // We need to fetch breach details for each
                        for domain_breach in domain_breaches {
                            let email = format!("{}@{}", domain_breach.alias, domain);
                            for breach_name in &domain_breach.breaches {
                                if let Ok(Some(breach)) = hibp.get_breach(breach_name).await {
                                    let info = breach.to_breach_info();
                                    exposures.push(ExposedCredential {
                                        email: email.clone(),
                                        domain: domain.to_string(),
                                        breach: info.clone(),
                                        password_hash_exposed: info
                                            .data_classes
                                            .iter()
                                            .any(|dc| dc.to_lowercase().contains("password")),
                                        hash_type: None,
                                        discovered_at: Utc::now(),
                                        source: BreachSource::Hibp,
                                    });
                                    if !breaches.iter().any(|b: &BreachInfo| b.name == info.name) {
                                        breaches.push(info);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("HIBP domain check failed for {}: {}", domain, e);
                        errors.push(format!("HIBP: {}", e));
                    }
                }
            } else {
                errors.push("HIBP API key required for domain searches".to_string());
            }
        }

        // Check Dehashed for domain
        if let Some(ref dehashed) = self.dehashed {
            sources_checked.push(BreachSource::Dehashed);
            match dehashed.search_by_domain(domain).await {
                Ok(response) => {
                    let dh_exposures = dehashed.entries_to_exposures(&response.entries);
                    for exp in dh_exposures {
                        if !breaches.iter().any(|b: &BreachInfo| b.name == exp.breach.name) {
                            breaches.push(exp.breach.clone());
                        }
                        exposures.push(exp);
                    }
                }
                Err(e) => {
                    warn!("Dehashed domain check failed for {}: {}", domain, e);
                    errors.push(format!("Dehashed: {}", e));
                }
            }
        }

        // Check local database for domain
        if let Some(ref local_db) = self.local_db {
            sources_checked.push(BreachSource::LocalDatabase);
            if let Some(local_exposures) = local_db.check_domain(domain) {
                for exp in local_exposures {
                    if !breaches.iter().any(|b: &BreachInfo| b.name == exp.breach.name) {
                        breaches.push(exp.breach.clone());
                    }
                    exposures.push(exp);
                }
            }
        }

        // Calculate statistics
        let stats = self.calculate_stats(&exposures, &breaches);

        Ok(BreachCheckResult {
            id: check_id,
            check_type: BreachCheckType::Domain,
            target: domain.to_string(),
            checked_at: Utc::now(),
            exposures,
            breaches,
            stats,
            errors,
            sources_checked,
        })
    }

    /// Check if a password has been compromised
    pub async fn check_password(&self, password: &str) -> Result<PasswordBreachResult> {
        self.password_client.check_password(password).await
    }

    /// Calculate statistics from exposures and breaches
    fn calculate_stats(&self, exposures: &[ExposedCredential], breaches: &[BreachInfo]) -> BreachCheckStats {
        let mut by_severity = SeverityBreakdown::default();
        let mut data_type_counts: HashMap<String, usize> = HashMap::new();

        for breach in breaches {
            match breach.severity {
                BreachSeverity::Critical => by_severity.critical += 1,
                BreachSeverity::High => by_severity.high += 1,
                BreachSeverity::Medium => by_severity.medium += 1,
                BreachSeverity::Low => by_severity.low += 1,
                BreachSeverity::Info => by_severity.info += 1,
            }

            for data_class in &breach.data_classes {
                *data_type_counts.entry(data_class.clone()).or_insert(0) += 1;
            }
        }

        let mut top_data_types: Vec<(String, usize)> = data_type_counts.into_iter().collect();
        top_data_types.sort_by(|a, b| b.1.cmp(&a.1));
        top_data_types.truncate(10);

        let earliest_breach = breaches
            .iter()
            .filter_map(|b| b.breach_date)
            .min();

        let latest_breach = breaches
            .iter()
            .filter_map(|b| b.breach_date)
            .max();

        BreachCheckStats {
            total_exposures: exposures.len(),
            unique_breaches: breaches.len(),
            password_exposures: exposures.iter().filter(|e| e.password_hash_exposed).count(),
            by_severity,
            earliest_breach,
            latest_breach,
            top_data_types,
        }
    }

    /// Get engine status
    pub fn get_status(&self) -> BreachEngineStatus {
        BreachEngineStatus {
            hibp_available: self.hibp.is_some(),
            hibp_api_key_configured: self.has_hibp_key(),
            dehashed_available: self.dehashed.is_some(),
            local_db_available: self.local_db.is_some(),
            password_check_available: true,
        }
    }
}

/// Status of the breach detection engine
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BreachEngineStatus {
    pub hibp_available: bool,
    pub hibp_api_key_configured: bool,
    pub dehashed_available: bool,
    pub local_db_available: bool,
    pub password_check_available: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_client_creation() {
        let client = PasswordCheckClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_engine_status() {
        let config = BreachDetectionConfig {
            hibp_api_key: None,
            dehashed_email: None,
            dehashed_api_key: None,
            use_local_db: false,
            cache_ttl_hours: 24,
            timeout_secs: 30,
            rate_limit_delay_ms: 1500,
            max_retries: 3,
        };
        let engine = BreachDetectionEngine::new(config).unwrap();
        let status = engine.get_status();

        assert!(status.hibp_available);
        assert!(!status.hibp_api_key_configured);
        assert!(!status.dehashed_available);
        assert!(!status.local_db_available);
        assert!(status.password_check_available);
    }
}
