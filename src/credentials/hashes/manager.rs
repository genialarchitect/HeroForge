//! Hash job management
//!
//! Manage hash cracking jobs and correlate results.

use anyhow::{anyhow, Result};
use chrono::Utc;
use log::info;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

use super::identifier::{HashIdentifier, HashIdentification};
use crate::credentials::types::*;

/// Hash manager
pub struct HashManager {
    /// Managed hashes
    hashes: Arc<RwLock<HashMap<String, ManagedHash>>>,
    /// Hash identifier
    identifier: HashIdentifier,
    /// Configuration
    config: HashManagerConfig,
}

/// Manager configuration
#[derive(Debug, Clone)]
pub struct HashManagerConfig {
    /// Auto-identify hash types
    pub auto_identify: bool,
    /// Auto-queue cracking jobs
    pub auto_crack: bool,
    /// Default wordlist for auto-crack
    pub default_wordlist: Option<String>,
    /// Maximum hashes to auto-crack
    pub max_auto_crack: usize,
}

impl Default for HashManagerConfig {
    fn default() -> Self {
        Self {
            auto_identify: true,
            auto_crack: false,
            default_wordlist: None,
            max_auto_crack: 1000,
        }
    }
}

impl HashManager {
    /// Create new hash manager
    pub fn new() -> Self {
        Self {
            hashes: Arc::new(RwLock::new(HashMap::new())),
            identifier: HashIdentifier::new(),
            config: HashManagerConfig::default(),
        }
    }

    /// Create with config
    pub fn with_config(config: HashManagerConfig) -> Self {
        Self {
            hashes: Arc::new(RwLock::new(HashMap::new())),
            identifier: HashIdentifier::new(),
            config,
        }
    }

    /// Add a hash
    pub fn add_hash(&self, hash: &str, source: CredentialSource) -> Result<String> {
        let hash = hash.trim().to_string();

        if hash.is_empty() {
            return Err(anyhow!("Empty hash"));
        }

        // Check for duplicate
        {
            let hashes = self.hashes.read()
                .map_err(|_| anyhow!("Lock poisoned"))?;

            if let Some(existing) = hashes.values().find(|h| h.hash == hash) {
                return Ok(existing.id.clone());
            }
        }

        // Identify hash type
        let hash_type = if self.config.auto_identify {
            self.identifier.identify(&hash)
                .map(|id| id.hash_type)
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        let id = Uuid::new_v4().to_string();

        let managed = ManagedHash {
            id: id.clone(),
            hash: hash.clone(),
            hash_type,
            username: None,
            domain: None,
            source,
            cracked_password: None,
            cracking_job_id: None,
            crack_attempts: 0,
            added_at: Utc::now(),
            cracked_at: None,
        };

        let mut hashes = self.hashes.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        hashes.insert(id.clone(), managed);

        Ok(id)
    }

    /// Add hash with username
    pub fn add_hash_with_user(
        &self,
        hash: &str,
        username: &str,
        domain: Option<&str>,
        source: CredentialSource,
    ) -> Result<String> {
        let id = self.add_hash(hash, source)?;

        // Update with username
        let mut hashes = self.hashes.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if let Some(h) = hashes.get_mut(&id) {
            h.username = Some(username.to_string());
            h.domain = domain.map(|d| d.to_string());
        }

        Ok(id)
    }

    /// Add multiple hashes
    pub fn add_hashes(&self, hash_list: &[(String, Option<String>, Option<String>)], source: CredentialSource) -> Vec<String> {
        hash_list.iter()
            .filter_map(|(hash, username, domain)| {
                match username {
                    Some(u) => self.add_hash_with_user(hash, u, domain.as_deref(), source.clone()).ok(),
                    None => self.add_hash(hash, source.clone()).ok(),
                }
            })
            .collect()
    }

    /// Get a hash by ID
    pub fn get(&self, id: &str) -> Result<Option<ManagedHash>> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.get(id).cloned())
    }

    /// Get hash by value
    pub fn get_by_hash(&self, hash: &str) -> Result<Option<ManagedHash>> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.values().find(|h| h.hash == hash).cloned())
    }

    /// Get all uncracked hashes
    pub fn get_uncracked(&self) -> Result<Vec<ManagedHash>> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.values()
            .filter(|h| h.cracked_password.is_none())
            .cloned()
            .collect())
    }

    /// Get all cracked hashes
    pub fn get_cracked(&self) -> Result<Vec<ManagedHash>> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.values()
            .filter(|h| h.cracked_password.is_some())
            .cloned()
            .collect())
    }

    /// Get hashes by type
    pub fn get_by_type(&self, hash_type: &str) -> Result<Vec<ManagedHash>> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.values()
            .filter(|h| h.hash_type == hash_type)
            .cloned()
            .collect())
    }

    /// Update hash with cracked password
    pub fn mark_cracked(&self, id: &str, password: &str) -> Result<()> {
        let mut hashes = self.hashes.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if let Some(h) = hashes.get_mut(id) {
            h.cracked_password = Some(password.to_string());
            h.cracked_at = Some(Utc::now());
            info!("Hash {} cracked: {}", id, password);
        }

        Ok(())
    }

    /// Mark hash as cracked by hash value
    pub fn mark_cracked_by_hash(&self, hash: &str, password: &str) -> Result<()> {
        let mut hashes = self.hashes.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        for h in hashes.values_mut() {
            if h.hash == hash {
                h.cracked_password = Some(password.to_string());
                h.cracked_at = Some(Utc::now());
                info!("Hash cracked: {} -> {}", hash, password);
            }
        }

        Ok(())
    }

    /// Associate cracking job
    pub fn set_cracking_job(&self, id: &str, job_id: &str) -> Result<()> {
        let mut hashes = self.hashes.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        if let Some(h) = hashes.get_mut(id) {
            h.cracking_job_id = Some(job_id.to_string());
            h.crack_attempts += 1;
        }

        Ok(())
    }

    /// Identify hash type
    pub fn identify(&self, hash: &str) -> Option<HashIdentification> {
        self.identifier.identify(hash)
    }

    /// Get statistics
    pub fn get_stats(&self) -> Result<HashStats> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        let total = hashes.len();
        let cracked = hashes.values().filter(|h| h.cracked_password.is_some()).count();
        let uncracked = total - cracked;
        let in_progress = hashes.values()
            .filter(|h| h.cracking_job_id.is_some() && h.cracked_password.is_none())
            .count();

        let mut by_type: HashMap<String, usize> = HashMap::new();
        for h in hashes.values() {
            *by_type.entry(h.hash_type.clone()).or_insert(0) += 1;
        }

        Ok(HashStats {
            total,
            cracked,
            uncracked,
            in_progress,
            by_type,
            crack_rate: if total > 0 {
                (cracked as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        })
    }

    /// Export hashes for cracking tool
    pub fn export_for_cracking(&self, hash_type: Option<&str>) -> Result<String> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        let lines: Vec<String> = hashes.values()
            .filter(|h| h.cracked_password.is_none())
            .filter(|h| hash_type.map(|t| h.hash_type == t).unwrap_or(true))
            .map(|h| {
                if let Some(ref user) = h.username {
                    format!("{}:{}", user, h.hash)
                } else {
                    h.hash.clone()
                }
            })
            .collect();

        Ok(lines.join("\n"))
    }

    /// Import cracked results (potfile format)
    pub fn import_cracked(&self, potfile: &str) -> Result<usize> {
        let mut count = 0;

        for line in potfile.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Format: hash:password or user:hash:password
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let hash = parts[0];
                let password = parts[1];

                if self.mark_cracked_by_hash(hash, password).is_ok() {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Convert to stored credentials
    pub fn to_credentials(&self) -> Result<Vec<StoredCredential>> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.values()
            .filter(|h| h.cracked_password.is_some())
            .map(|h| StoredCredential {
                id: String::new(),
                credential_type: CredentialType::Password,
                identity: h.username.clone().unwrap_or_else(|| "unknown".to_string()),
                domain: h.domain.clone(),
                secret: CredentialSecret::Plaintext(
                    h.cracked_password.clone().unwrap_or_default()
                ),
                source: h.source.clone(),
                health: CredentialHealth::default(),
                targets: Vec::new(),
                tags: vec!["cracked".to_string(), h.hash_type.clone()],
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("original_hash".to_string(), h.hash.clone());
                    m
                },
                discovered_at: h.added_at,
                last_verified_at: h.cracked_at,
                expires_at: None,
                last_used_at: None,
            })
            .collect())
    }

    /// Delete a hash
    pub fn delete(&self, id: &str) -> Result<bool> {
        let mut hashes = self.hashes.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.remove(id).is_some())
    }

    /// Clear all hashes
    pub fn clear(&self) -> Result<()> {
        let mut hashes = self.hashes.write()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        hashes.clear();
        Ok(())
    }

    /// Count total hashes
    pub fn count(&self) -> Result<usize> {
        let hashes = self.hashes.read()
            .map_err(|_| anyhow!("Lock poisoned"))?;

        Ok(hashes.len())
    }
}

impl Default for HashManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash statistics
#[derive(Debug, Clone)]
pub struct HashStats {
    /// Total hashes
    pub total: usize,
    /// Cracked hashes
    pub cracked: usize,
    /// Uncracked hashes
    pub uncracked: usize,
    /// Currently being cracked
    pub in_progress: usize,
    /// By hash type
    pub by_type: HashMap<String, usize>,
    /// Overall crack rate (percentage)
    pub crack_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_hash() {
        let manager = HashManager::new();

        let id = manager.add_hash(
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            CredentialSource::Manual,
        ).unwrap();

        let hash = manager.get(&id).unwrap();
        assert!(hash.is_some());
        assert_eq!(hash.unwrap().hash, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_mark_cracked() {
        let manager = HashManager::new();

        let id = manager.add_hash(
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            CredentialSource::Manual,
        ).unwrap();

        manager.mark_cracked(&id, "password").unwrap();

        let hash = manager.get(&id).unwrap().unwrap();
        assert_eq!(hash.cracked_password, Some("password".to_string()));
    }

    #[test]
    fn test_stats() {
        let manager = HashManager::new();

        manager.add_hash("hash1", CredentialSource::Manual).unwrap();
        manager.add_hash("hash2", CredentialSource::Manual).unwrap();

        let stats = manager.get_stats().unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.uncracked, 2);
    }
}
