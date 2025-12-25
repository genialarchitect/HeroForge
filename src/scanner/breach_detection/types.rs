//! Types for breach detection module

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity of a data breach based on exposed data types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BreachSeverity {
    /// Critical: Passwords, financial data, or SSN exposed
    Critical,
    /// High: Password hashes or security questions exposed
    High,
    /// Medium: Email addresses with personal data exposed
    Medium,
    /// Low: Only email addresses or usernames exposed
    Low,
    /// Info: Minor exposure, public data only
    Info,
}

impl BreachSeverity {
    /// Calculate severity from exposed data types
    pub fn from_data_types(data_types: &[String]) -> Self {
        let data_types_lower: Vec<String> = data_types.iter().map(|s| s.to_lowercase()).collect();

        // Critical: plaintext passwords, financial data, SSN
        if data_types_lower.iter().any(|dt| {
            dt.contains("password") && !dt.contains("hash") ||
            dt.contains("plaintext") ||
            dt.contains("credit card") ||
            dt.contains("bank") ||
            dt.contains("ssn") ||
            dt.contains("social security")
        }) {
            return Self::Critical;
        }

        // High: password hashes, security questions, private keys
        if data_types_lower.iter().any(|dt| {
            dt.contains("hash") ||
            dt.contains("security question") ||
            dt.contains("private key") ||
            dt.contains("api key") ||
            dt.contains("auth token")
        }) {
            return Self::High;
        }

        // Medium: personal data like phone, address, DOB
        if data_types_lower.iter().any(|dt| {
            dt.contains("phone") ||
            dt.contains("address") ||
            dt.contains("date of birth") ||
            dt.contains("dob") ||
            dt.contains("ip address") ||
            dt.contains("physical address")
        }) {
            return Self::Medium;
        }

        // Low: email addresses, usernames, names
        if data_types_lower.iter().any(|dt| {
            dt.contains("email") ||
            dt.contains("username") ||
            dt.contains("name")
        }) {
            return Self::Low;
        }

        Self::Info
    }
}

impl std::fmt::Display for BreachSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

/// Source of breach data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BreachSource {
    /// Have I Been Pwned API
    Hibp,
    /// Dehashed API
    Dehashed,
    /// Local imported breach database
    LocalDatabase,
    /// Manual entry
    Manual,
}

impl std::fmt::Display for BreachSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hibp => write!(f, "Have I Been Pwned"),
            Self::Dehashed => write!(f, "Dehashed"),
            Self::LocalDatabase => write!(f, "Local Database"),
            Self::Manual => write!(f, "Manual"),
        }
    }
}

/// Information about a specific data breach
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachInfo {
    /// Unique identifier for the breach
    pub name: String,
    /// Human-readable title
    pub title: String,
    /// Domain that was breached
    pub domain: String,
    /// When the breach occurred
    pub breach_date: Option<DateTime<Utc>>,
    /// When the breach was added to the database
    pub added_date: Option<DateTime<Utc>>,
    /// When the breach was last modified
    pub modified_date: Option<DateTime<Utc>>,
    /// Approximate number of accounts in the breach
    pub pwn_count: Option<u64>,
    /// Description of the breach
    pub description: Option<String>,
    /// List of data types that were exposed
    pub data_classes: Vec<String>,
    /// Whether the breach has been verified
    pub is_verified: bool,
    /// Whether the breach is fabricated (fake data)
    pub is_fabricated: bool,
    /// Whether the breach is sensitive (hidden in public queries)
    pub is_sensitive: bool,
    /// Whether the breach is from a spam list
    pub is_spam_list: bool,
    /// URL to the breach logo
    pub logo_path: Option<String>,
    /// Source of this breach information
    pub source: BreachSource,
    /// Calculated severity
    pub severity: BreachSeverity,
}

impl BreachInfo {
    /// Create a new breach info with calculated severity
    pub fn new(
        name: String,
        title: String,
        domain: String,
        data_classes: Vec<String>,
        source: BreachSource,
    ) -> Self {
        let severity = BreachSeverity::from_data_types(&data_classes);
        Self {
            name,
            title,
            domain,
            breach_date: None,
            added_date: None,
            modified_date: None,
            pwn_count: None,
            description: None,
            data_classes,
            is_verified: false,
            is_fabricated: false,
            is_sensitive: false,
            is_spam_list: false,
            logo_path: None,
            source,
            severity,
        }
    }
}

/// An exposed credential found in a breach
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedCredential {
    /// The email address that was exposed
    pub email: String,
    /// Domain of the email (e.g., company.com)
    pub domain: String,
    /// Information about the breach
    pub breach: BreachInfo,
    /// Whether a password hash was exposed
    pub password_hash_exposed: bool,
    /// Type of password hash if known (e.g., "bcrypt", "md5", "sha1")
    pub hash_type: Option<String>,
    /// When this exposure was discovered
    pub discovered_at: DateTime<Utc>,
    /// Source of this finding
    pub source: BreachSource,
}

/// Result of a breach check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachCheckResult {
    /// The check ID
    pub id: String,
    /// Type of check (domain or email)
    pub check_type: BreachCheckType,
    /// The domain or email that was checked
    pub target: String,
    /// When the check was performed
    pub checked_at: DateTime<Utc>,
    /// All exposed credentials found
    pub exposures: Vec<ExposedCredential>,
    /// Unique breaches affecting the target
    pub breaches: Vec<BreachInfo>,
    /// Summary statistics
    pub stats: BreachCheckStats,
    /// Any errors that occurred during the check
    pub errors: Vec<String>,
    /// Sources that were checked
    pub sources_checked: Vec<BreachSource>,
}

/// Type of breach check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachCheckType {
    /// Check a single email address
    Email,
    /// Check all emails for a domain
    Domain,
}

impl std::fmt::Display for BreachCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Email => write!(f, "email"),
            Self::Domain => write!(f, "domain"),
        }
    }
}

/// Summary statistics for a breach check
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BreachCheckStats {
    /// Total number of exposed accounts
    pub total_exposures: usize,
    /// Number of unique breaches affecting the target
    pub unique_breaches: usize,
    /// Number of exposures with password hashes
    pub password_exposures: usize,
    /// Breakdown by severity
    pub by_severity: SeverityBreakdown,
    /// Earliest breach date
    pub earliest_breach: Option<DateTime<Utc>>,
    /// Most recent breach date
    pub latest_breach: Option<DateTime<Utc>>,
    /// Most common data types exposed
    pub top_data_types: Vec<(String, usize)>,
}

/// Breakdown of findings by severity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Configuration for breach detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachDetectionConfig {
    /// Have I Been Pwned API key
    pub hibp_api_key: Option<String>,
    /// Dehashed API email
    pub dehashed_email: Option<String>,
    /// Dehashed API key
    pub dehashed_api_key: Option<String>,
    /// Whether to use local breach database
    pub use_local_db: bool,
    /// Cache TTL in hours
    pub cache_ttl_hours: i64,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Rate limit delay between requests (milliseconds)
    pub rate_limit_delay_ms: u64,
    /// Maximum retries for failed requests
    pub max_retries: u32,
}

impl Default for BreachDetectionConfig {
    fn default() -> Self {
        Self {
            hibp_api_key: std::env::var("HIBP_API_KEY").ok(),
            dehashed_email: std::env::var("DEHASHED_EMAIL").ok(),
            dehashed_api_key: std::env::var("DEHASHED_API_KEY").ok(),
            use_local_db: true,
            cache_ttl_hours: 24,
            timeout_secs: 30,
            rate_limit_delay_ms: 1500, // HIBP requires 1.5s between requests
            max_retries: 3,
        }
    }
}

/// Request to check a domain for breaches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainCheckRequest {
    /// Domain to check (e.g., company.com)
    pub domain: String,
    /// Optional list of specific emails to check
    pub emails: Option<Vec<String>>,
    /// Whether to include all known emails for the domain
    pub include_all_domain_emails: bool,
}

/// Request to check an email for breaches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailCheckRequest {
    /// Email address to check
    pub email: String,
    /// Whether to include unverified breaches
    pub include_unverified: bool,
}

/// Scheduled monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachMonitorConfig {
    /// ID of this monitoring job
    pub id: String,
    /// Domain or email to monitor
    pub target: String,
    /// Type of monitoring (domain or email)
    pub check_type: BreachCheckType,
    /// Check interval in hours
    pub interval_hours: u32,
    /// Whether monitoring is enabled
    pub enabled: bool,
    /// When the last check was performed
    pub last_check: Option<DateTime<Utc>>,
    /// When the next check is scheduled
    pub next_check: DateTime<Utc>,
    /// User who created this monitor
    pub user_id: String,
    /// When this monitor was created
    pub created_at: DateTime<Utc>,
}
