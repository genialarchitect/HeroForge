//! Encrypted credential storage
//!
//! Provides secure storage for credentials with encryption at rest,
//! automatic reuse capabilities, and health monitoring.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use base64::{Engine, engine::general_purpose::STANDARD};

use super::types::*;

/// Encrypted credential store
pub struct CredentialStore {
    /// In-memory credential cache (encrypted values are stored encrypted)
    credentials: Arc<RwLock<HashMap<String, StoredCredential>>>,
    /// Encryption key (AES-256-GCM)
    encryption_key: [u8; 32],
    /// Store configuration
    config: StoreConfig,
}

/// Store configuration
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Days before expiration to trigger warning
    pub expiry_warning_days: i32,
    /// Days of inactivity before credential is stale
    pub stale_after_days: i32,
    /// Enable automatic health monitoring
    pub auto_health_check: bool,
    /// Maximum credentials to store
    pub max_credentials: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            expiry_warning_days: 30,
            stale_after_days: 90,
            auto_health_check: true,
            max_credentials: 100000,
        }
    }
}

impl CredentialStore {
    /// Create a new credential store with the given encryption key
    pub fn new(encryption_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            encryption_key: *encryption_key,
            config: StoreConfig::default(),
        })
    }

    /// Create with custom config
    pub fn with_config(encryption_key: &[u8; 32], config: StoreConfig) -> Result<Self> {
        Ok(Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            encryption_key: *encryption_key,
            config,
        })
    }

    /// Store a new credential
    pub fn store(&self, mut credential: StoredCredential) -> Result<String> {
        let credentials = self.credentials.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if credentials.len() >= self.config.max_credentials {
            return Err(anyhow!("Maximum credential limit reached"));
        }
        drop(credentials);

        // Generate ID if not set
        if credential.id.is_empty() {
            credential.id = Uuid::new_v4().to_string();
        }

        // Set discovered time if not set
        if credential.discovered_at.timestamp() == 0 {
            credential.discovered_at = Utc::now();
        }

        // Encrypt the secret before storing
        credential.secret = self.encrypt_secret(&credential.secret)?;

        // Calculate health
        credential.health = self.calculate_health(&credential);

        let id = credential.id.clone();

        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;
        credentials.insert(id.clone(), credential);

        Ok(id)
    }

    /// Get a credential by ID
    pub fn get(&self, id: &str) -> Result<Option<StoredCredential>> {
        let credentials = self.credentials.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        match credentials.get(id).cloned() {
            Some(mut cred) => {
                // Decrypt the secret
                cred.secret = self.decrypt_secret(&cred.secret)?;
                Ok(Some(cred))
            }
            None => Ok(None),
        }
    }

    /// Update a credential
    pub fn update(&self, credential: StoredCredential) -> Result<()> {
        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if !credentials.contains_key(&credential.id) {
            return Err(anyhow!("Credential not found"));
        }

        let mut updated = credential;
        updated.secret = self.encrypt_secret(&updated.secret)?;
        updated.health = self.calculate_health(&updated);

        credentials.insert(updated.id.clone(), updated);
        Ok(())
    }

    /// Delete a credential
    pub fn delete(&self, id: &str) -> Result<bool> {
        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(credentials.remove(id).is_some())
    }

    /// Search credentials by filter
    pub fn search(&self, filter: &CredentialFilter) -> Result<Vec<StoredCredential>> {
        let credentials = self.credentials.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        let mut results: Vec<StoredCredential> = credentials.values()
            .filter(|cred| self.matches_filter(cred, filter))
            .cloned()
            .collect();

        // Sort by discovered_at descending
        results.sort_by(|a, b| b.discovered_at.cmp(&a.discovered_at));

        // Apply pagination
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(100);

        let results: Vec<StoredCredential> = results.into_iter()
            .skip(offset)
            .take(limit)
            .map(|mut cred| {
                // Decrypt secrets for results
                if let Ok(decrypted) = self.decrypt_secret(&cred.secret) {
                    cred.secret = decrypted;
                }
                cred
            })
            .collect();

        Ok(results)
    }

    /// Find credentials for a specific target/host
    pub fn find_for_target(&self, target: &str) -> Result<Vec<StoredCredential>> {
        self.search(&CredentialFilter {
            target: Some(target.to_string()),
            ..Default::default()
        })
    }

    /// Find credentials by identity
    pub fn find_by_identity(&self, identity: &str, domain: Option<&str>) -> Result<Vec<StoredCredential>> {
        self.search(&CredentialFilter {
            identity: Some(identity.to_string()),
            domain: domain.map(|d| d.to_string()),
            ..Default::default()
        })
    }

    /// Get credentials expiring soon
    pub fn get_expiring_soon(&self) -> Result<Vec<StoredCredential>> {
        self.search(&CredentialFilter {
            expiring_soon: true,
            ..Default::default()
        })
    }

    /// Get all uncracked hashes
    pub fn get_uncracked_hashes(&self) -> Result<Vec<StoredCredential>> {
        self.search(&CredentialFilter {
            uncracked_only: true,
            ..Default::default()
        })
    }

    /// Mark a credential as verified
    pub fn mark_verified(&self, id: &str, success: bool) -> Result<()> {
        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if let Some(cred) = credentials.get_mut(id) {
            cred.last_verified_at = Some(Utc::now());
            cred.health.verified = Some(success);
            cred.health = self.calculate_health(cred);
        }

        Ok(())
    }

    /// Mark a credential as used
    pub fn mark_used(&self, id: &str) -> Result<()> {
        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if let Some(cred) = credentials.get_mut(id) {
            cred.last_used_at = Some(Utc::now());
        }

        Ok(())
    }

    /// Update hash with cracked password
    pub fn update_cracked(&self, id: &str, plaintext: &str) -> Result<()> {
        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if let Some(cred) = credentials.get_mut(id) {
            // Change from hash to plaintext
            cred.secret = CredentialSecret::Plaintext(plaintext.to_string());
            cred.secret = self.encrypt_secret(&cred.secret)?;
            cred.credential_type = CredentialType::Password;
            cred.health = self.calculate_health(cred);
        }

        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> Result<CredentialStats> {
        let credentials = self.credentials.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        let mut stats = CredentialStats {
            total: credentials.len(),
            ..Default::default()
        };

        let now = Utc::now();
        let expiry_threshold = now + Duration::days(30);

        for cred in credentials.values() {
            // By type
            let type_name = cred.credential_type.name().to_string();
            *stats.by_type.entry(type_name).or_insert(0) += 1;

            // By source
            let source_type = cred.source.source_type().to_string();
            *stats.by_source.entry(source_type).or_insert(0) += 1;

            // By health
            let health_name = format!("{:?}", cred.health.status).to_lowercase();
            *stats.by_health.entry(health_name).or_insert(0) += 1;

            // Expiring soon
            if let Some(expires) = cred.expires_at {
                if expires <= expiry_threshold && expires > now {
                    stats.expiring_soon += 1;
                }
            }

            // Cracked/uncracked
            match &cred.secret {
                CredentialSecret::Hash { .. } => stats.uncracked += 1,
                CredentialSecret::Plaintext(_) if cred.credential_type.is_hash() => {
                    stats.cracked += 1;
                }
                _ => {}
            }
        }

        Ok(stats)
    }

    /// Check if filter matches credential
    fn matches_filter(&self, cred: &StoredCredential, filter: &CredentialFilter) -> bool {
        // Identity filter
        if let Some(ref identity) = filter.identity {
            if !cred.identity.to_lowercase().contains(&identity.to_lowercase()) {
                return false;
            }
        }

        // Domain filter
        if let Some(ref domain) = filter.domain {
            match &cred.domain {
                Some(d) if d.to_lowercase() == domain.to_lowercase() => {}
                _ => return false,
            }
        }

        // Credential type
        if let Some(ref cred_type) = filter.credential_type {
            if cred.credential_type != *cred_type {
                return false;
            }
        }

        // Source type
        if let Some(ref source_type) = filter.source_type {
            if cred.source.source_type() != source_type {
                return false;
            }
        }

        // Health status
        if let Some(ref status) = filter.health_status {
            if cred.health.status != *status {
                return false;
            }
        }

        // Tags
        if let Some(ref tags) = filter.tags {
            let has_all_tags = tags.iter()
                .all(|tag| cred.tags.iter().any(|t| t.to_lowercase() == tag.to_lowercase()));
            if !has_all_tags {
                return false;
            }
        }

        // Target
        if let Some(ref target) = filter.target {
            let has_target = cred.targets.iter()
                .any(|t| t.to_lowercase().contains(&target.to_lowercase()));
            if !has_target {
                return false;
            }
        }

        // Cracked only
        if filter.cracked_only {
            if let CredentialSecret::Hash { .. } = cred.secret {
                return false;
            }
        }

        // Uncracked only
        if filter.uncracked_only {
            if !matches!(cred.secret, CredentialSecret::Hash { .. }) {
                return false;
            }
        }

        // Expiring soon
        if filter.expiring_soon {
            let now = Utc::now();
            let threshold = now + Duration::days(30);
            match cred.expires_at {
                Some(expires) if expires <= threshold && expires > now => {}
                _ => return false,
            }
        }

        true
    }

    /// Calculate health for a credential
    fn calculate_health(&self, cred: &StoredCredential) -> CredentialHealth {
        let mut health = CredentialHealth::default();
        let now = Utc::now();

        // Check expiration
        if let Some(expires) = cred.expires_at {
            let days = (expires - now).num_days() as i32;
            health.days_until_expiry = Some(days);

            if days < 0 {
                health.status = HealthStatus::Critical;
                health.issues.push(CredentialIssue {
                    severity: IssueSeverity::Critical,
                    code: "EXPIRED".to_string(),
                    message: format!("Credential expired {} days ago", -days),
                    recommendation: Some("Obtain new credentials".to_string()),
                });
            } else if days < self.config.expiry_warning_days {
                if health.status != HealthStatus::Critical {
                    health.status = HealthStatus::Warning;
                }
                health.issues.push(CredentialIssue {
                    severity: IssueSeverity::Medium,
                    code: "EXPIRING_SOON".to_string(),
                    message: format!("Credential expires in {} days", days),
                    recommendation: Some("Plan credential rotation".to_string()),
                });
            }
        }

        // Check verification
        if let Some(verified) = cred.health.verified {
            health.verified = Some(verified);
            if !verified {
                if health.status == HealthStatus::Unknown {
                    health.status = HealthStatus::Warning;
                }
                health.issues.push(CredentialIssue {
                    severity: IssueSeverity::Medium,
                    code: "VERIFY_FAILED".to_string(),
                    message: "Credential failed verification".to_string(),
                    recommendation: Some("Check if credential is still valid".to_string()),
                });
            }
        }

        // Check for weak passwords
        if let CredentialSecret::Plaintext(ref password) = cred.secret {
            let score = self.assess_password_strength(password);
            health.strength_score = Some(score);

            if score < 30 {
                health.status = HealthStatus::Critical;
                health.issues.push(CredentialIssue {
                    severity: IssueSeverity::High,
                    code: "WEAK_PASSWORD".to_string(),
                    message: "Password is extremely weak".to_string(),
                    recommendation: Some("Use a strong, unique password".to_string()),
                });
            } else if score < 60 {
                if health.status == HealthStatus::Unknown {
                    health.status = HealthStatus::Warning;
                }
                health.issues.push(CredentialIssue {
                    severity: IssueSeverity::Medium,
                    code: "MODERATE_PASSWORD".to_string(),
                    message: "Password could be stronger".to_string(),
                    recommendation: Some("Consider using a longer password with more character variety".to_string()),
                });
            }
        }

        // Check for stale credentials
        if let Some(last_used) = cred.last_used_at {
            let days_unused = (now - last_used).num_days() as i32;
            if days_unused > self.config.stale_after_days {
                health.issues.push(CredentialIssue {
                    severity: IssueSeverity::Low,
                    code: "STALE".to_string(),
                    message: format!("Credential unused for {} days", days_unused),
                    recommendation: Some("Verify if credential is still needed".to_string()),
                });
            }
        }

        // Check compromised status
        if cred.health.compromised {
            health.compromised = true;
            health.status = HealthStatus::Critical;
            health.issues.push(CredentialIssue {
                severity: IssueSeverity::Critical,
                code: "COMPROMISED".to_string(),
                message: "Credential has been flagged as compromised".to_string(),
                recommendation: Some("Immediately rotate this credential".to_string()),
            });
        }

        // If no issues, status is good
        if health.issues.is_empty() && health.status == HealthStatus::Unknown {
            health.status = HealthStatus::Good;
        }

        health
    }

    /// Assess password strength (0-100)
    fn assess_password_strength(&self, password: &str) -> u8 {
        let mut score = 0u8;
        let len = password.len();

        // Length score (up to 30 points)
        score += std::cmp::min(30, (len * 3) as u8);

        // Character variety (up to 40 points)
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        let variety_count = [has_lower, has_upper, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
        score += (variety_count * 10) as u8;

        // Penalize common patterns (up to -30 points)
        let common_passwords = ["password", "123456", "admin", "letmein", "welcome", "qwerty"];
        let lower = password.to_lowercase();
        if common_passwords.iter().any(|p| lower.contains(p)) {
            score = score.saturating_sub(30);
        }

        // Penalize sequential patterns
        if lower.contains("123") || lower.contains("abc") || lower.contains("qwe") {
            score = score.saturating_sub(10);
        }

        // Bonus for entropy (up to 30 points)
        let unique_chars: std::collections::HashSet<char> = password.chars().collect();
        let uniqueness = (unique_chars.len() as f32) / (len as f32);
        score += (uniqueness * 30.0) as u8;

        std::cmp::min(100, score)
    }

    /// Encrypt a credential secret
    fn encrypt_secret(&self, secret: &CredentialSecret) -> Result<CredentialSecret> {
        let plaintext = serde_json::to_vec(secret)?;

        // Generate nonce (96 bits for AES-GCM)
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| anyhow!("Failed to create cipher"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);

        // Return as a generic secret (storing the encrypted data)
        Ok(CredentialSecret::Generic({
            let mut map = HashMap::new();
            map.insert("_encrypted".to_string(), STANDARD.encode(&result));
            map
        }))
    }

    /// Decrypt a credential secret
    fn decrypt_secret(&self, secret: &CredentialSecret) -> Result<CredentialSecret> {
        let encrypted_data = match secret {
            CredentialSecret::Generic(map) => {
                match map.get("_encrypted") {
                    Some(data) => STANDARD.decode(data)?,
                    None => return Ok(secret.clone()), // Not encrypted
                }
            }
            _ => return Ok(secret.clone()), // Not encrypted
        };

        if encrypted_data.len() < 12 + 16 {
            return Err(anyhow!("Invalid encrypted data"));
        }

        // Extract nonce
        let nonce_bytes = &encrypted_data[..12];
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|_| anyhow!("Failed to create cipher"))?;

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, &encrypted_data[12..])
            .map_err(|_| anyhow!("Decryption failed"))?;

        // Deserialize
        let secret: CredentialSecret = serde_json::from_slice(&plaintext)?;
        Ok(secret)
    }

    /// Export credentials (encrypted for backup)
    pub fn export(&self) -> Result<Vec<u8>> {
        let credentials = self.credentials.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        let data: Vec<&StoredCredential> = credentials.values().collect();
        let json = serde_json::to_vec(&data)?;

        // Already encrypted individually, just return JSON
        Ok(json)
    }

    /// Import credentials from backup
    pub fn import(&self, data: &[u8]) -> Result<usize> {
        let imported: Vec<StoredCredential> = serde_json::from_slice(data)?;
        let count = imported.len();

        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        for cred in imported {
            credentials.insert(cred.id.clone(), cred);
        }

        Ok(count)
    }

    /// Clear all credentials
    pub fn clear(&self) -> Result<()> {
        let mut credentials = self.credentials.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        credentials.clear();
        Ok(())
    }

    /// Count total credentials
    pub fn count(&self) -> Result<usize> {
        let credentials = self.credentials.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(credentials.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_store_and_retrieve() {
        let store = CredentialStore::new(&test_key()).unwrap();

        let cred = StoredCredential {
            id: String::new(),
            credential_type: CredentialType::Password,
            identity: "testuser".to_string(),
            domain: Some("TESTDOMAIN".to_string()),
            secret: CredentialSecret::Plaintext("password123".to_string()),
            source: CredentialSource::Manual,
            health: CredentialHealth::default(),
            targets: vec!["192.168.1.100".to_string()],
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
            discovered_at: Utc::now(),
            last_verified_at: None,
            expires_at: None,
            last_used_at: None,
        };

        let id = store.store(cred).unwrap();
        let retrieved = store.get(&id).unwrap().unwrap();

        assert_eq!(retrieved.identity, "testuser");
        assert_eq!(retrieved.domain, Some("TESTDOMAIN".to_string()));

        match retrieved.secret {
            CredentialSecret::Plaintext(p) => assert_eq!(p, "password123"),
            _ => panic!("Expected plaintext"),
        }
    }

    #[test]
    fn test_search() {
        let store = CredentialStore::new(&test_key()).unwrap();

        // Add test credentials
        for i in 0..5 {
            let cred = StoredCredential {
                id: String::new(),
                credential_type: CredentialType::Password,
                identity: format!("user{}", i),
                domain: Some("DOMAIN".to_string()),
                secret: CredentialSecret::Plaintext("pass".to_string()),
                source: CredentialSource::Manual,
                health: CredentialHealth::default(),
                targets: vec!["192.168.1.100".to_string()],
                tags: vec![],
                metadata: HashMap::new(),
                discovered_at: Utc::now(),
                last_verified_at: None,
                expires_at: None,
                last_used_at: None,
            };
            store.store(cred).unwrap();
        }

        let results = store.search(&CredentialFilter {
            identity: Some("user".to_string()),
            ..Default::default()
        }).unwrap();

        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_password_strength() {
        let store = CredentialStore::new(&test_key()).unwrap();

        // Weak password
        assert!(store.assess_password_strength("123456") < 40);

        // Strong password
        assert!(store.assess_password_strength("MyStr0ng!P@ssw0rd") > 70);
    }
}
