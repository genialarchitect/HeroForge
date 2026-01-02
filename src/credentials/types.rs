//! Credential types and data structures
//!
//! Core types for the unified credential management system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A stored credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Unique identifier
    pub id: String,
    /// Credential type
    pub credential_type: CredentialType,
    /// Username or identity
    pub identity: String,
    /// Domain (for AD credentials)
    pub domain: Option<String>,
    /// Secret (password, hash, key, etc.) - encrypted at rest
    pub secret: CredentialSecret,
    /// Source of this credential
    pub source: CredentialSource,
    /// Health status
    pub health: CredentialHealth,
    /// Associated target hosts/services
    pub targets: Vec<String>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// When credential was discovered
    pub discovered_at: DateTime<Utc>,
    /// When credential was last verified
    pub last_verified_at: Option<DateTime<Utc>>,
    /// When credential expires (if known)
    pub expires_at: Option<DateTime<Utc>>,
    /// When credential was last used
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Types of credentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Username and password
    Password,
    /// NTLM hash
    NtlmHash,
    /// LM hash (legacy)
    LmHash,
    /// Kerberos TGT
    KerberosTgt,
    /// Kerberos TGS
    KerberosTgs,
    /// SSH private key
    SshKey,
    /// API key or token
    ApiKey,
    /// Certificate with private key
    Certificate,
    /// Database connection string
    DatabaseConnection,
    /// AWS credentials
    AwsCredentials,
    /// Azure credentials
    AzureCredentials,
    /// GCP credentials
    GcpCredentials,
    /// Generic secret
    Generic,
}

impl CredentialType {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::NtlmHash => "NTLM Hash",
            Self::LmHash => "LM Hash",
            Self::KerberosTgt => "Kerberos TGT",
            Self::KerberosTgs => "Kerberos TGS",
            Self::SshKey => "SSH Key",
            Self::ApiKey => "API Key",
            Self::Certificate => "Certificate",
            Self::DatabaseConnection => "Database Connection",
            Self::AwsCredentials => "AWS Credentials",
            Self::AzureCredentials => "Azure Credentials",
            Self::GcpCredentials => "GCP Credentials",
            Self::Generic => "Generic Secret",
        }
    }

    /// Check if this is a hash type
    pub fn is_hash(&self) -> bool {
        matches!(self, Self::NtlmHash | Self::LmHash)
    }

    /// Check if this is a Kerberos ticket
    pub fn is_kerberos(&self) -> bool {
        matches!(self, Self::KerberosTgt | Self::KerberosTgs)
    }
}

/// The secret value of a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum CredentialSecret {
    /// Plaintext password
    Plaintext(String),
    /// Hash value with type
    Hash { hash_type: String, value: String },
    /// Kerberos ticket (Base64 encoded)
    KerberosTicket { ticket_data: String, key_type: i32 },
    /// SSH key (PEM format)
    SshKey { private_key: String, passphrase: Option<String> },
    /// API key/token
    ApiKey(String),
    /// Certificate with key (PEM format)
    Certificate { cert: String, key: String, passphrase: Option<String> },
    /// AWS credentials
    Aws { access_key_id: String, secret_access_key: String, session_token: Option<String> },
    /// Azure credentials
    Azure { client_id: String, client_secret: String, tenant_id: String },
    /// GCP credentials (JSON service account key)
    Gcp { service_account_json: String },
    /// Generic key-value secret
    Generic(HashMap<String, String>),
}

impl CredentialSecret {
    /// Check if this contains a hash that can be cracked
    pub fn is_crackable(&self) -> bool {
        matches!(self, Self::Hash { .. })
    }

    /// Get the hash value if this is a hash secret
    pub fn hash_value(&self) -> Option<&str> {
        match self {
            Self::Hash { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Get the plaintext password if available
    pub fn plaintext(&self) -> Option<&str> {
        match self {
            Self::Plaintext(p) => Some(p),
            _ => None,
        }
    }
}

/// Source of a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialSource {
    /// Manually entered
    Manual,
    /// From network scan
    NetworkScan { scan_id: String, host: String, port: Option<u16> },
    /// From memory dump extraction
    MemoryDump { dump_id: String, process: Option<String> },
    /// From config file
    ConfigFile { file_path: String, host: Option<String> },
    /// From browser credential extraction
    Browser { browser: String, profile: Option<String> },
    /// From Kerberoasting attack
    Kerberoasting { spn: String },
    /// From AS-REP roasting
    AsrepRoasting { user_principal: String },
    /// From password spray success
    PasswordSpray { campaign_id: String },
    /// From DCSync attack
    DcSync { domain_controller: String },
    /// From secrets dump
    SecretsDump { host: String },
    /// Imported from external source
    Import { source_name: String, import_id: String },
}

impl CredentialSource {
    /// Get source type as string
    pub fn source_type(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::NetworkScan { .. } => "network_scan",
            Self::MemoryDump { .. } => "memory_dump",
            Self::ConfigFile { .. } => "config_file",
            Self::Browser { .. } => "browser",
            Self::Kerberoasting { .. } => "kerberoasting",
            Self::AsrepRoasting { .. } => "asrep_roasting",
            Self::PasswordSpray { .. } => "password_spray",
            Self::DcSync { .. } => "dcsync",
            Self::SecretsDump { .. } => "secrets_dump",
            Self::Import { .. } => "import",
        }
    }
}

/// Health status of a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialHealth {
    /// Overall health status
    pub status: HealthStatus,
    /// Last verification result
    pub verified: Option<bool>,
    /// Days until expiration (negative if expired)
    pub days_until_expiry: Option<i32>,
    /// Is this credential known to be compromised/leaked?
    pub compromised: bool,
    /// Password strength score (0-100)
    pub strength_score: Option<u8>,
    /// Issues with this credential
    pub issues: Vec<CredentialIssue>,
}

impl Default for CredentialHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Unknown,
            verified: None,
            days_until_expiry: None,
            compromised: false,
            strength_score: None,
            issues: Vec::new(),
        }
    }
}

/// Health status levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Good health
    Good,
    /// Has warnings
    Warning,
    /// Critical issues
    Critical,
    /// Status unknown
    Unknown,
}

/// Issues with a credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssue {
    /// Issue severity
    pub severity: IssueSeverity,
    /// Issue code
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Recommendation
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A credential set (user with multiple credentials)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSet {
    /// Primary identity
    pub identity: String,
    /// Domain
    pub domain: Option<String>,
    /// All credentials for this identity
    pub credentials: Vec<StoredCredential>,
    /// Notes
    pub notes: Option<String>,
}

/// Result of credential verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Was verification successful
    pub success: bool,
    /// Protocol used for verification
    pub protocol: String,
    /// Target verified against
    pub target: String,
    /// Error message if failed
    pub error: Option<String>,
    /// Additional info
    pub info: HashMap<String, String>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
}

/// Credential usage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialStats {
    /// Total credentials
    pub total: usize,
    /// By type breakdown
    pub by_type: HashMap<String, usize>,
    /// By source breakdown
    pub by_source: HashMap<String, usize>,
    /// By health status
    pub by_health: HashMap<String, usize>,
    /// Credentials expiring soon (next 30 days)
    pub expiring_soon: usize,
    /// Cracked hashes
    pub cracked: usize,
    /// Uncracked hashes
    pub uncracked: usize,
}

/// Password spray result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayResult {
    /// Campaign ID
    pub campaign_id: String,
    /// Target user
    pub username: String,
    /// Target domain
    pub domain: Option<String>,
    /// Password tried
    pub password: String,
    /// Was login successful
    pub success: bool,
    /// Error or status message
    pub message: Option<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Kerberos ticket data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosTicket {
    /// Ticket type (TGT or TGS)
    pub ticket_type: KerberosTicketType,
    /// Client principal
    pub client_principal: String,
    /// Service principal
    pub service_principal: String,
    /// Realm
    pub realm: String,
    /// Encryption type
    pub encryption_type: i32,
    /// Ticket data (Base64)
    pub ticket_data: String,
    /// Key data (encrypted, for forging)
    pub key_data: Option<String>,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: DateTime<Utc>,
    /// Renew until
    pub renew_until: Option<DateTime<Utc>>,
    /// Ticket flags
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KerberosTicketType {
    Tgt,
    Tgs,
}

/// Hash for cracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedHash {
    /// Unique ID
    pub id: String,
    /// The hash value
    pub hash: String,
    /// Detected or specified hash type
    pub hash_type: String,
    /// Associated username
    pub username: Option<String>,
    /// Associated domain
    pub domain: Option<String>,
    /// Source of this hash
    pub source: CredentialSource,
    /// Cracked password (if cracked)
    pub cracked_password: Option<String>,
    /// Cracking job ID (if in progress)
    pub cracking_job_id: Option<String>,
    /// Cracking attempts
    pub crack_attempts: u32,
    /// When hash was added
    pub added_at: DateTime<Utc>,
    /// When hash was cracked
    pub cracked_at: Option<DateTime<Utc>>,
}

/// Credential search filter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialFilter {
    /// Search in identity/username
    pub identity: Option<String>,
    /// Filter by domain
    pub domain: Option<String>,
    /// Filter by credential type
    pub credential_type: Option<CredentialType>,
    /// Filter by source type
    pub source_type: Option<String>,
    /// Filter by health status
    pub health_status: Option<HealthStatus>,
    /// Filter by tags
    pub tags: Option<Vec<String>>,
    /// Filter by target
    pub target: Option<String>,
    /// Only cracked credentials
    pub cracked_only: bool,
    /// Only uncracked hashes
    pub uncracked_only: bool,
    /// Only expiring soon
    pub expiring_soon: bool,
    /// Limit results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_type_name() {
        assert_eq!(CredentialType::Password.name(), "Password");
        assert_eq!(CredentialType::NtlmHash.name(), "NTLM Hash");
        assert_eq!(CredentialType::KerberosTgt.name(), "Kerberos TGT");
    }

    #[test]
    fn test_credential_secret_is_crackable() {
        let hash = CredentialSecret::Hash {
            hash_type: "ntlm".to_string(),
            value: "31d6cfe0d16ae931b73c59d7e0c089c0".to_string(),
        };
        assert!(hash.is_crackable());

        let plaintext = CredentialSecret::Plaintext("password".to_string());
        assert!(!plaintext.is_crackable());
    }
}
