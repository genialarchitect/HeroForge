//! Unified Credential Management
//!
//! Centralized credential handling across all HeroForge modules.
//!
//! # Features
//!
//! ## Credential Store
//! - Encrypted credential storage (ChaCha20-Poly1305)
//! - Automatic credential reuse
//! - Health monitoring and expiration tracking
//! - Password strength assessment
//!
//! ## Credential Discovery
//! - Extract credentials from network scans
//! - Memory dump credential extraction
//! - Config file credential discovery
//! - Browser credential extraction
//! - Hash parsing (secretsdump, mimikatz formats)
//!
//! ## Credential Attacks
//! - Password spraying (LDAP, SMB, Kerberos, SSH, RDP, WinRM, databases)
//! - Kerberoasting (native TGS-REQ)
//! - AS-REP roasting
//! - Golden/Silver ticket forging
//!
//! ## Hash Management
//! - Automatic hash type identification
//! - Cracking job management
//! - Result correlation
//! - Integration with native cracking engine
//!
//! # Example
//!
//! ```rust,ignore
//! use heroforge::credentials::*;
//!
//! // Create credential store
//! let key = [0x42u8; 32]; // Use proper key derivation in production
//! let store = CredentialStore::new(&key)?;
//!
//! // Store a credential
//! let cred = StoredCredential {
//!     credential_type: CredentialType::Password,
//!     identity: "admin".to_string(),
//!     domain: Some("CORP".to_string()),
//!     secret: CredentialSecret::Plaintext("P@ssw0rd".to_string()),
//!     source: CredentialSource::Manual,
//!     // ... other fields
//! };
//! let id = store.store(cred)?;
//!
//! // Find credentials for a target
//! let creds = store.find_for_target("192.168.1.100")?;
//!
//! // Password spraying
//! let mut sprayer = PasswordSprayer::new(SprayConfig {
//!     domain: Some("CORP".to_string()),
//!     protocols: vec![SprayProtocol::Ldap, SprayProtocol::Smb],
//!     delay_secs: 30,
//!     ..Default::default()
//! });
//! let results = sprayer.spray_password(&users, "Summer2024!", "campaign-1").await;
//!
//! // Kerberoasting
//! let kerberoaster = Kerberoaster::new(KerberoastConfig {
//!     kdc: "dc01.corp.local".to_string(),
//!     realm: "CORP.LOCAL".to_string(),
//!     user_principal: Some("user@CORP.LOCAL".to_string()),
//!     password: Some("password".to_string()),
//!     ..Default::default()
//! });
//! let hashes = kerberoaster.roast(&spns).await;
//!
//! // Hash management
//! let manager = HashManager::new();
//! manager.add_hash("$krb5tgs$23$*user$...", source)?;
//! let identification = manager.identify(&hash);
//! ```

pub mod types;
pub mod store;
pub mod discovery;
pub mod attacks;
pub mod hashes;

// Re-export main types
pub use types::*;

pub use store::{
    CredentialStore,
    StoreConfig,
};

pub use discovery::{
    CredentialDiscovery,
    DiscoveryConfig,
    ScanHost,
    ScanService,
};

pub use attacks::{
    PasswordSprayer,
    SprayConfig,
    SprayProtocol,
    SprayCampaign,
    CampaignStatus,
    SprayProgress,
    Kerberoaster,
    KerberoastConfig,
    KerberoastResult,
    ServicePrincipal,
    AsrepRoaster,
    AsrepConfig,
    AsrepResult,
    enumerate_asrep_users,
    TicketForge,
    TicketConfig,
    GoldenTicketParams,
    SilverTicketParams,
    DiamondTicketParams,
    ForgedTicket,
    TicketType,
    TicketInfo,
};

pub use hashes::{
    HashIdentifier,
    HashIdentification,
    IdentifyConfidence,
    AlternativeMatch,
    identify_hash,
    get_hashcat_mode,
    HashManager,
    HashManagerConfig,
    HashStats,
};

use anyhow::Result;
use std::sync::Arc;

/// Unified credential management system
pub struct CredentialManager {
    /// Credential store
    pub store: Arc<CredentialStore>,
    /// Discovery engine
    pub discovery: CredentialDiscovery,
    /// Hash manager
    pub hash_manager: HashManager,
}

impl CredentialManager {
    /// Create new credential manager
    pub fn new(encryption_key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            store: Arc::new(CredentialStore::new(encryption_key)?),
            discovery: CredentialDiscovery::new(),
            hash_manager: HashManager::new(),
        })
    }

    /// Create with custom configs
    pub fn with_config(
        encryption_key: &[u8; 32],
        store_config: StoreConfig,
        discovery_config: DiscoveryConfig,
        hash_config: HashManagerConfig,
    ) -> Result<Self> {
        Ok(Self {
            store: Arc::new(CredentialStore::with_config(encryption_key, store_config)?),
            discovery: CredentialDiscovery::with_config(discovery_config),
            hash_manager: HashManager::with_config(hash_config),
        })
    }

    /// Import credentials from discovery
    pub fn import_discovered(&self) -> Result<usize> {
        let creds = self.discovery.take_credentials();
        let count = creds.len();

        for cred in creds {
            self.store.store(cred)?;
        }

        Ok(count)
    }

    /// Import hashes as credentials
    pub fn import_hashes(&self) -> Result<usize> {
        let creds = self.hash_manager.to_credentials()?;
        let count = creds.len();

        for cred in creds {
            self.store.store(cred)?;
        }

        Ok(count)
    }

    /// Get credential by ID
    pub fn get_credential(&self, id: &str) -> Result<Option<StoredCredential>> {
        self.store.get(id)
    }

    /// Find credentials for target
    pub fn find_for_target(&self, target: &str) -> Result<Vec<StoredCredential>> {
        self.store.find_for_target(target)
    }

    /// Find credentials by identity
    pub fn find_by_identity(&self, identity: &str, domain: Option<&str>) -> Result<Vec<StoredCredential>> {
        self.store.find_by_identity(identity, domain)
    }

    /// Get overall statistics
    pub fn get_stats(&self) -> Result<ManagerStats> {
        let cred_stats = self.store.get_stats()?;
        let hash_stats = self.hash_manager.get_stats()?;

        Ok(ManagerStats {
            credentials: cred_stats,
            hashes: hash_stats,
        })
    }
}

/// Combined statistics
#[derive(Debug, Clone)]
pub struct ManagerStats {
    pub credentials: CredentialStats,
    pub hashes: HashStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_manager_creation() {
        let key = [0x42u8; 32];
        let manager = CredentialManager::new(&key);
        assert!(manager.is_ok());
    }
}
