//! Password cracking types and data structures
//!
//! This module defines the core types for the password cracking integration,
//! including hash types, job configurations, and results.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Supported hash types for password cracking
/// Values correspond to hashcat mode numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashType {
    /// MD5 (mode 0)
    Md5 = 0,
    /// SHA-1 (mode 100)
    Sha1 = 100,
    /// SHA-256 (mode 1400)
    Sha256 = 1400,
    /// SHA-512 (mode 1700)
    Sha512 = 1700,
    /// NTLM (mode 1000)
    Ntlm = 1000,
    /// LM (mode 3000)
    Lm = 3000,
    /// NetNTLMv1 (mode 5500)
    NetNtlmv1 = 5500,
    /// NetNTLMv2 (mode 5600)
    NetNtlmv2 = 5600,
    /// Kerberos 5 TGS-REP etype 23 (mode 13100) - Kerberoasting
    KerberosTgs = 13100,
    /// Kerberos 5 AS-REP etype 23 (mode 18200) - AS-REP Roasting
    KerberosAsrep = 18200,
    /// bcrypt (mode 3200)
    Bcrypt = 3200,
    /// MySQL323 (mode 200)
    MySQL323 = 200,
    /// MySQL 4.1+ (mode 300)
    MySQL41 = 300,
    /// MSSQL 2000 (mode 131)
    Mssql2000 = 131,
    /// MSSQL 2005 (mode 132)
    Mssql2005 = 132,
    /// Oracle 11g (mode 112)
    Oracle11g = 112,
    /// PostgreSQL (mode 12)
    Postgresql = 12,
    /// WPA-PMKID-PBKDF2 (mode 22000)
    WpaPmkid = 22000,
    /// Cisco-ASA MD5 (mode 2410)
    CiscoAsa = 2410,
    /// SHA-256 crypt (mode 7400)
    Sha256Crypt = 7400,
    /// SHA-512 crypt (mode 1800)
    Sha512Crypt = 1800,
    /// descrypt (mode 1500)
    Descrypt = 1500,
    /// LDAP SSHA (mode 111)
    LdapSsha = 111,
    /// Office 2013 (mode 9600)
    Office2013 = 9600,
    /// PDF 1.4-1.6 (mode 10500)
    Pdf14 = 10500,
    /// 7-Zip (mode 11600)
    SevenZip = 11600,
    /// RAR5 (mode 13000)
    Rar5 = 13000,
    /// Custom/other mode specified by number
    #[serde(other)]
    Custom,
}

impl HashType {
    /// Get the hashcat mode number for this hash type
    pub fn mode(&self) -> i32 {
        *self as i32
    }

    /// Get a human-readable name for this hash type
    pub fn name(&self) -> &'static str {
        match self {
            HashType::Md5 => "MD5",
            HashType::Sha1 => "SHA-1",
            HashType::Sha256 => "SHA-256",
            HashType::Sha512 => "SHA-512",
            HashType::Ntlm => "NTLM",
            HashType::Lm => "LM",
            HashType::NetNtlmv1 => "NetNTLMv1",
            HashType::NetNtlmv2 => "NetNTLMv2",
            HashType::KerberosTgs => "Kerberos 5 TGS (Kerberoasting)",
            HashType::KerberosAsrep => "Kerberos 5 AS-REP",
            HashType::Bcrypt => "bcrypt",
            HashType::MySQL323 => "MySQL323",
            HashType::MySQL41 => "MySQL 4.1+",
            HashType::Mssql2000 => "MSSQL 2000",
            HashType::Mssql2005 => "MSSQL 2005",
            HashType::Oracle11g => "Oracle 11g",
            HashType::Postgresql => "PostgreSQL",
            HashType::WpaPmkid => "WPA-PMKID-PBKDF2",
            HashType::CiscoAsa => "Cisco-ASA MD5",
            HashType::Sha256Crypt => "SHA-256 crypt",
            HashType::Sha512Crypt => "SHA-512 crypt",
            HashType::Descrypt => "descrypt",
            HashType::LdapSsha => "LDAP SSHA",
            HashType::Office2013 => "Office 2013",
            HashType::Pdf14 => "PDF 1.4-1.6",
            HashType::SevenZip => "7-Zip",
            HashType::Rar5 => "RAR5",
            HashType::Custom => "Custom",
        }
    }

    /// Try to detect hash type from a hash string
    pub fn detect(hash: &str) -> Option<Self> {
        let hash = hash.trim();

        // Kerberos TGS (Kerberoasting)
        if hash.starts_with("$krb5tgs$") {
            return Some(HashType::KerberosTgs);
        }

        // Kerberos AS-REP
        if hash.starts_with("$krb5asrep$") {
            return Some(HashType::KerberosAsrep);
        }

        // bcrypt
        if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
            return Some(HashType::Bcrypt);
        }

        // SHA-512 crypt
        if hash.starts_with("$6$") {
            return Some(HashType::Sha512Crypt);
        }

        // SHA-256 crypt
        if hash.starts_with("$5$") {
            return Some(HashType::Sha256Crypt);
        }

        // NTLM (32 hex chars)
        if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(HashType::Ntlm);
        }

        // NetNTLMv2 (contains ::)
        if hash.contains("::") && hash.split(':').count() >= 6 {
            return Some(HashType::NetNtlmv2);
        }

        // MD5 (32 hex chars) - same as NTLM, but NTLM is more common in pentesting
        // SHA-1 (40 hex chars)
        if hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(HashType::Sha1);
        }

        // SHA-256 (64 hex chars)
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(HashType::Sha256);
        }

        // SHA-512 (128 hex chars)
        if hash.len() == 128 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(HashType::Sha512);
        }

        // LM (32 hex chars, typically uppercase)
        if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) && hash.to_uppercase() == hash {
            return Some(HashType::Lm);
        }

        None
    }
}

/// Cracker type - which tool to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrackerType {
    /// Hashcat GPU-accelerated password cracker
    Hashcat,
    /// John the Ripper CPU-based cracker
    John,
}

impl Default for CrackerType {
    fn default() -> Self {
        CrackerType::Hashcat
    }
}

/// Status of a cracking job
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrackingJobStatus {
    /// Job is queued but not started
    Pending,
    /// Job is currently running
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed with an error
    Failed,
    /// Job was cancelled by user
    Cancelled,
    /// Job is paused
    Paused,
}

impl Default for CrackingJobStatus {
    fn default() -> Self {
        CrackingJobStatus::Pending
    }
}

/// Attack mode for hashcat
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    /// Dictionary attack (mode 0)
    Dictionary = 0,
    /// Combinator attack (mode 1)
    Combinator = 1,
    /// Brute-force/Mask attack (mode 3)
    BruteForce = 3,
    /// Hybrid wordlist + mask (mode 6)
    HybridWordlistMask = 6,
    /// Hybrid mask + wordlist (mode 7)
    HybridMaskWordlist = 7,
    /// Association attack (mode 9)
    Association = 9,
}

impl Default for AttackMode {
    fn default() -> Self {
        AttackMode::Dictionary
    }
}

/// A hash entry to crack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    /// The hash value
    pub hash: String,
    /// Optional username associated with the hash
    pub username: Option<String>,
    /// Optional domain for AD hashes
    pub domain: Option<String>,
    /// Source of this hash (e.g., "kerberoasting", "secretsdump", "manual")
    pub source: Option<String>,
    /// Optional asset ID this hash is associated with
    pub asset_id: Option<String>,
}

/// Configuration for a cracking job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackingJobConfig {
    /// Attack mode
    #[serde(default)]
    pub attack_mode: AttackMode,
    /// IDs of wordlists to use
    #[serde(default)]
    pub wordlist_ids: Vec<String>,
    /// IDs of rule files to use
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Mask for brute-force attacks (e.g., "?a?a?a?a?a?a")
    pub mask: Option<String>,
    /// Minimum password length for incremental mode
    pub min_length: Option<u32>,
    /// Maximum password length for incremental mode
    pub max_length: Option<u32>,
    /// Custom charsets (?1, ?2, ?3, ?4)
    #[serde(default)]
    pub custom_charsets: Vec<String>,
    /// Additional hashcat/john arguments
    #[serde(default)]
    pub extra_args: Vec<String>,
    /// Device types to use (1=CPU, 2=GPU, 3=FPGA)
    pub device_types: Option<Vec<u32>>,
    /// Specific device IDs to use
    pub devices: Option<Vec<u32>>,
    /// Workload profile (1-4, 4 is highest)
    pub workload_profile: Option<u32>,
    /// Whether to use optimized kernels
    #[serde(default = "default_optimized")]
    pub optimized_kernels: bool,
}

fn default_optimized() -> bool {
    true
}

impl Default for CrackingJobConfig {
    fn default() -> Self {
        Self {
            attack_mode: AttackMode::Dictionary,
            wordlist_ids: vec![],
            rule_ids: vec![],
            mask: None,
            min_length: None,
            max_length: None,
            custom_charsets: vec![],
            extra_args: vec![],
            device_types: None,
            devices: None,
            workload_profile: Some(3),
            optimized_kernels: true,
        }
    }
}

/// Progress information for a running cracking job
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrackingProgress {
    /// Total number of hashes in the job
    pub total_hashes: usize,
    /// Number of hashes cracked so far
    pub cracked: usize,
    /// Current speed (e.g., "12.5 MH/s")
    pub speed: String,
    /// Estimated time remaining
    pub estimated_time: String,
    /// Progress percentage (0-100)
    pub progress_percent: f32,
    /// Number of candidates tested
    pub candidates_tested: u64,
    /// Total candidates to test (if known)
    pub candidates_total: Option<u64>,
    /// Current status message
    pub status_message: String,
    /// GPU/device temperatures (if available)
    #[serde(default)]
    pub temperatures: Vec<u32>,
    /// GPU/device utilization (if available)
    #[serde(default)]
    pub utilization: Vec<u32>,
}

/// A cracked credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedCredential {
    /// Unique ID
    pub id: String,
    /// The original hash
    pub hash: String,
    /// The cracked plaintext password
    pub plaintext: String,
    /// Hash type that was cracked
    pub hash_type: i32,
    /// Username if known
    pub username: Option<String>,
    /// Domain if known
    pub domain: Option<String>,
    /// Asset ID if correlated
    pub asset_id: Option<String>,
    /// When this was cracked
    pub cracked_at: DateTime<Utc>,
}

/// A cracking job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackingJob {
    /// Unique job ID
    pub id: String,
    /// User who created the job
    pub user_id: String,
    /// Job name
    pub name: Option<String>,
    /// Current status
    pub status: CrackingJobStatus,
    /// Hash type (hashcat mode)
    pub hash_type: i32,
    /// Cracker type (hashcat or john)
    pub cracker_type: CrackerType,
    /// Hashes to crack (JSON)
    pub hashes_json: String,
    /// Job configuration (JSON)
    pub config_json: String,
    /// Current progress (JSON)
    pub progress_json: Option<String>,
    /// Results - cracked credentials (JSON)
    pub results_json: Option<String>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Source campaign ID (e.g., exploitation campaign)
    pub source_campaign_id: Option<String>,
    /// Customer ID if associated with CRM
    pub customer_id: Option<String>,
    /// Engagement ID if associated
    pub engagement_id: Option<String>,
    /// When the job was created
    pub created_at: DateTime<Utc>,
    /// When the job started running
    pub started_at: Option<DateTime<Utc>>,
    /// When the job completed
    pub completed_at: Option<DateTime<Utc>>,
}

/// A wordlist for password cracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wordlist {
    /// Unique ID
    pub id: String,
    /// User ID (null for built-in)
    pub user_id: Option<String>,
    /// Wordlist name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// File path on disk
    pub file_path: String,
    /// File size in bytes
    pub size_bytes: i64,
    /// Number of lines/words
    pub line_count: i64,
    /// Whether this is a built-in wordlist
    pub is_builtin: bool,
    /// Category (common, leaked, custom, language-specific)
    pub category: String,
    /// When the wordlist was added
    pub created_at: DateTime<Utc>,
}

/// A rule file for hashcat/john
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    /// Unique ID
    pub id: String,
    /// User ID (null for built-in)
    pub user_id: Option<String>,
    /// Rule file name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// File path on disk
    pub file_path: String,
    /// Number of rules
    pub rule_count: i32,
    /// Cracker type this is for
    pub cracker_type: CrackerType,
    /// Whether this is a built-in rule file
    pub is_builtin: bool,
    /// When the rule file was added
    pub created_at: DateTime<Utc>,
}

/// Request to create a cracking job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCrackingJobRequest {
    /// Job name
    pub name: Option<String>,
    /// Hash type (hashcat mode number)
    pub hash_type: i32,
    /// Cracker to use
    #[serde(default)]
    pub cracker_type: CrackerType,
    /// Hashes to crack
    pub hashes: Vec<HashEntry>,
    /// Job configuration
    #[serde(default)]
    pub config: CrackingJobConfig,
    /// Source campaign ID
    pub source_campaign_id: Option<String>,
    /// Customer ID
    pub customer_id: Option<String>,
    /// Engagement ID
    pub engagement_id: Option<String>,
}

/// Request to upload a wordlist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWordlistRequest {
    /// Wordlist name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Category
    pub category: Option<String>,
}

/// Request to upload a rule file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRuleFileRequest {
    /// Rule file name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// Cracker type
    pub cracker_type: CrackerType,
}

/// Request to detect hash type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectHashRequest {
    /// Hashes to detect
    pub hashes: Vec<String>,
}

/// Response from hash detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectHashResponse {
    /// Detected hash type mode
    pub hash_type: Option<i32>,
    /// Human-readable name
    pub hash_type_name: Option<String>,
    /// Confidence level (high, medium, low)
    pub confidence: String,
    /// Alternative possible types
    pub alternatives: Vec<HashTypeInfo>,
}

/// Information about a hash type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashTypeInfo {
    /// Hashcat mode number
    pub mode: i32,
    /// Human-readable name
    pub name: String,
    /// Example hash format
    pub example: Option<String>,
}

/// WebSocket message for cracking progress
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CrackingProgressMessage {
    /// Job has started
    JobStarted {
        job_id: String,
        total_hashes: usize,
    },
    /// Progress update
    ProgressUpdate {
        job_id: String,
        cracked: usize,
        total: usize,
        speed: String,
        eta: String,
        progress_percent: f32,
    },
    /// A hash was cracked
    HashCracked {
        job_id: String,
        hash: String,
        plaintext: String,
        username: Option<String>,
    },
    /// Job completed
    JobCompleted {
        job_id: String,
        total_cracked: usize,
        duration_secs: u64,
    },
    /// Job failed
    JobFailed {
        job_id: String,
        error: String,
    },
    /// Job was cancelled
    JobCancelled {
        job_id: String,
    },
}

/// Statistics for cracking overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackingStats {
    /// Total jobs
    pub total_jobs: i64,
    /// Jobs currently running
    pub running_jobs: i64,
    /// Total hashes processed
    pub total_hashes: i64,
    /// Total hashes cracked
    pub total_cracked: i64,
    /// Overall success rate
    pub success_rate: f64,
    /// Most common hash types
    pub top_hash_types: Vec<(String, i64)>,
    /// Most common passwords found
    pub top_passwords: Vec<(String, i64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_detection() {
        // NTLM hash
        assert_eq!(
            HashType::detect("31d6cfe0d16ae931b73c59d7e0c089c0"),
            Some(HashType::Ntlm)
        );

        // Kerberoasting hash
        assert_eq!(
            HashType::detect("$krb5tgs$23$*user$domain$spn*$hash"),
            Some(HashType::KerberosTgs)
        );

        // bcrypt
        assert_eq!(
            HashType::detect("$2a$10$abcdefghijklmnopqrstuvwxyz12345678901234567890"),
            Some(HashType::Bcrypt)
        );

        // SHA-256
        assert_eq!(
            HashType::detect("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Some(HashType::Sha256)
        );
    }
}
