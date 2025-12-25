//! Indicator of Compromise (IOC) Management
//!
//! Provides comprehensive IOC handling including:
//! - Multiple IOC types (IP, domain, hash, URL, email, filename, registry key)
//! - Source tracking (manual, feed import, scan results)
//! - Status management (active, expired, false_positive)
//! - Bulk import/export in CSV, STIX, and OpenIOC formats

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

/// Types of Indicators of Compromise
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    /// IP address (IPv4 or IPv6)
    Ip,
    /// Domain name
    Domain,
    /// MD5 hash
    Md5,
    /// SHA1 hash
    Sha1,
    /// SHA256 hash
    Sha256,
    /// URL
    Url,
    /// Email address
    Email,
    /// Filename or file path
    Filename,
    /// Windows registry key
    RegistryKey,
}

impl IocType {
    /// Get all IOC types
    pub fn all() -> Vec<IocType> {
        vec![
            IocType::Ip,
            IocType::Domain,
            IocType::Md5,
            IocType::Sha1,
            IocType::Sha256,
            IocType::Url,
            IocType::Email,
            IocType::Filename,
            IocType::RegistryKey,
        ]
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            IocType::Ip => "IP Address",
            IocType::Domain => "Domain",
            IocType::Md5 => "MD5 Hash",
            IocType::Sha1 => "SHA1 Hash",
            IocType::Sha256 => "SHA256 Hash",
            IocType::Url => "URL",
            IocType::Email => "Email Address",
            IocType::Filename => "Filename",
            IocType::RegistryKey => "Registry Key",
        }
    }

    /// Convert from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ip" | "ip_address" | "ipv4" | "ipv6" => Some(IocType::Ip),
            "domain" | "hostname" | "fqdn" => Some(IocType::Domain),
            "md5" | "hash_md5" => Some(IocType::Md5),
            "sha1" | "hash_sha1" => Some(IocType::Sha1),
            "sha256" | "hash_sha256" => Some(IocType::Sha256),
            "url" | "uri" => Some(IocType::Url),
            "email" | "email_address" => Some(IocType::Email),
            "filename" | "file" | "filepath" | "file_path" => Some(IocType::Filename),
            "registry" | "registry_key" | "regkey" => Some(IocType::RegistryKey),
            _ => None,
        }
    }
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IocType::Ip => "ip",
            IocType::Domain => "domain",
            IocType::Md5 => "md5",
            IocType::Sha1 => "sha1",
            IocType::Sha256 => "sha256",
            IocType::Url => "url",
            IocType::Email => "email",
            IocType::Filename => "filename",
            IocType::RegistryKey => "registry_key",
        };
        write!(f, "{}", s)
    }
}

/// Source of an IOC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocSource {
    /// Manually entered
    Manual,
    /// Imported from threat feed
    FeedImport,
    /// Discovered during scan
    ScanResult,
    /// From STIX feed
    Stix,
    /// From OpenIOC format
    OpenIoc,
    /// From MISP platform
    Misp,
    /// From CSV import
    CsvImport,
}

impl std::fmt::Display for IocSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IocSource::Manual => "manual",
            IocSource::FeedImport => "feed_import",
            IocSource::ScanResult => "scan_result",
            IocSource::Stix => "stix",
            IocSource::OpenIoc => "open_ioc",
            IocSource::Misp => "misp",
            IocSource::CsvImport => "csv_import",
        };
        write!(f, "{}", s)
    }
}

impl IocSource {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "manual" => Some(IocSource::Manual),
            "feed_import" | "feed" => Some(IocSource::FeedImport),
            "scan_result" | "scan" => Some(IocSource::ScanResult),
            "stix" => Some(IocSource::Stix),
            "open_ioc" | "openioc" => Some(IocSource::OpenIoc),
            "misp" => Some(IocSource::Misp),
            "csv_import" | "csv" => Some(IocSource::CsvImport),
            _ => None,
        }
    }
}

/// Status of an IOC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocStatus {
    /// Currently active indicator
    Active,
    /// Expired (no longer relevant)
    Expired,
    /// Marked as false positive
    FalsePositive,
}

impl std::fmt::Display for IocStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IocStatus::Active => "active",
            IocStatus::Expired => "expired",
            IocStatus::FalsePositive => "false_positive",
        };
        write!(f, "{}", s)
    }
}

impl IocStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" => Some(IocStatus::Active),
            "expired" => Some(IocStatus::Expired),
            "false_positive" | "falsepositive" | "fp" => Some(IocStatus::FalsePositive),
            _ => None,
        }
    }
}

/// Severity level of an IOC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IocSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for IocSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IocSeverity::Info => "info",
            IocSeverity::Low => "low",
            IocSeverity::Medium => "medium",
            IocSeverity::High => "high",
            IocSeverity::Critical => "critical",
        };
        write!(f, "{}", s)
    }
}

impl IocSeverity {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Some(IocSeverity::Info),
            "low" => Some(IocSeverity::Low),
            "medium" | "med" => Some(IocSeverity::Medium),
            "high" => Some(IocSeverity::High),
            "critical" | "crit" => Some(IocSeverity::Critical),
            _ => None,
        }
    }
}

/// An Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub description: Option<String>,
    pub source: IocSource,
    pub status: IocStatus,
    pub severity: IocSeverity,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub tags: Vec<String>,
    pub user_id: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Related threat actor or campaign
    pub threat_actor: Option<String>,
    /// Related MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Expiration date for time-limited indicators
    pub expires_at: Option<DateTime<Utc>>,
}

/// IOC match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub id: String,
    pub ioc_id: String,
    pub source_type: String,
    pub source_id: String,
    pub matched_at: DateTime<Utc>,
    pub context: Option<serde_json::Value>,
    /// The matched IOC details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc: Option<Ioc>,
}

/// Request to create a new IOC
#[derive(Debug, Clone, Deserialize)]
pub struct CreateIocRequest {
    pub ioc_type: IocType,
    pub value: String,
    pub description: Option<String>,
    pub source: Option<IocSource>,
    pub severity: Option<IocSeverity>,
    pub tags: Option<Vec<String>>,
    pub threat_actor: Option<String>,
    pub mitre_techniques: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

/// Request to update an IOC
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateIocRequest {
    pub description: Option<String>,
    pub status: Option<IocStatus>,
    pub severity: Option<IocSeverity>,
    pub tags: Option<Vec<String>>,
    pub threat_actor: Option<String>,
    pub mitre_techniques: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter for querying IOCs
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IocFilter {
    pub ioc_type: Option<IocType>,
    pub status: Option<IocStatus>,
    pub severity: Option<IocSeverity>,
    pub source: Option<IocSource>,
    pub tag: Option<String>,
    pub threat_actor: Option<String>,
    pub mitre_technique: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Bulk import result
#[derive(Debug, Clone, Serialize)]
pub struct BulkImportResult {
    pub total: usize,
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// IOC export format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Csv,
    Stix,
    OpenIoc,
    Json,
}

/// IOC Validator
pub struct IocValidator;

impl IocValidator {
    /// Validate an IOC value based on its type
    pub fn validate(ioc_type: IocType, value: &str) -> Result<String> {
        let value = value.trim();

        if value.is_empty() {
            return Err(anyhow!("IOC value cannot be empty"));
        }

        match ioc_type {
            IocType::Ip => Self::validate_ip(value),
            IocType::Domain => Self::validate_domain(value),
            IocType::Md5 => Self::validate_md5(value),
            IocType::Sha1 => Self::validate_sha1(value),
            IocType::Sha256 => Self::validate_sha256(value),
            IocType::Url => Self::validate_url(value),
            IocType::Email => Self::validate_email(value),
            IocType::Filename => Self::validate_filename(value),
            IocType::RegistryKey => Self::validate_registry_key(value),
        }
    }

    /// Auto-detect IOC type from value
    pub fn detect_type(value: &str) -> Option<IocType> {
        let value = value.trim();

        // Check for hashes first (most specific)
        if Self::validate_md5(value).is_ok() && value.len() == 32 {
            return Some(IocType::Md5);
        }
        if Self::validate_sha1(value).is_ok() && value.len() == 40 {
            return Some(IocType::Sha1);
        }
        if Self::validate_sha256(value).is_ok() && value.len() == 64 {
            return Some(IocType::Sha256);
        }

        // Check for URL
        if Self::validate_url(value).is_ok() {
            return Some(IocType::Url);
        }

        // Check for email
        if Self::validate_email(value).is_ok() {
            return Some(IocType::Email);
        }

        // Check for IP address
        if Self::validate_ip(value).is_ok() {
            return Some(IocType::Ip);
        }

        // Check for registry key
        if Self::validate_registry_key(value).is_ok() {
            return Some(IocType::RegistryKey);
        }

        // Check for domain
        if Self::validate_domain(value).is_ok() {
            return Some(IocType::Domain);
        }

        // Default to filename for paths
        if value.contains('/') || value.contains('\\') {
            return Some(IocType::Filename);
        }

        None
    }

    fn validate_ip(value: &str) -> Result<String> {
        // Handle CIDR notation
        let ip_part = if let Some(idx) = value.find('/') {
            &value[..idx]
        } else {
            value
        };

        // Try parsing as IPv4 or IPv6
        if ip_part.parse::<std::net::IpAddr>().is_ok() {
            Ok(value.to_lowercase())
        } else {
            Err(anyhow!("Invalid IP address format"))
        }
    }

    fn validate_domain(value: &str) -> Result<String> {
        let domain_regex = Regex::new(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        ).unwrap();

        if domain_regex.is_match(value) {
            Ok(value.to_lowercase())
        } else {
            Err(anyhow!("Invalid domain format"))
        }
    }

    fn validate_md5(value: &str) -> Result<String> {
        let value = value.to_lowercase();
        let md5_regex = Regex::new(r"^[a-f0-9]{32}$").unwrap();

        if md5_regex.is_match(&value) {
            Ok(value)
        } else {
            Err(anyhow!("Invalid MD5 hash format (expected 32 hex characters)"))
        }
    }

    fn validate_sha1(value: &str) -> Result<String> {
        let value = value.to_lowercase();
        let sha1_regex = Regex::new(r"^[a-f0-9]{40}$").unwrap();

        if sha1_regex.is_match(&value) {
            Ok(value)
        } else {
            Err(anyhow!("Invalid SHA1 hash format (expected 40 hex characters)"))
        }
    }

    fn validate_sha256(value: &str) -> Result<String> {
        let value = value.to_lowercase();
        let sha256_regex = Regex::new(r"^[a-f0-9]{64}$").unwrap();

        if sha256_regex.is_match(&value) {
            Ok(value)
        } else {
            Err(anyhow!("Invalid SHA256 hash format (expected 64 hex characters)"))
        }
    }

    fn validate_url(value: &str) -> Result<String> {
        // Simple URL validation
        if value.starts_with("http://") || value.starts_with("https://") || value.starts_with("ftp://") {
            // Check for valid URL structure
            if value.contains('.') || value.contains("localhost") {
                return Ok(value.to_string());
            }
        }
        Err(anyhow!("Invalid URL format (must start with http://, https://, or ftp://)"))
    }

    fn validate_email(value: &str) -> Result<String> {
        let email_regex = Regex::new(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ).unwrap();

        if email_regex.is_match(value) {
            Ok(value.to_lowercase())
        } else {
            Err(anyhow!("Invalid email address format"))
        }
    }

    fn validate_filename(value: &str) -> Result<String> {
        // Allow any non-empty string for filenames
        if !value.is_empty() {
            Ok(value.to_string())
        } else {
            Err(anyhow!("Filename cannot be empty"))
        }
    }

    fn validate_registry_key(value: &str) -> Result<String> {
        // Windows registry key validation
        let valid_roots = [
            "HKEY_LOCAL_MACHINE",
            "HKEY_CURRENT_USER",
            "HKEY_CLASSES_ROOT",
            "HKEY_USERS",
            "HKEY_CURRENT_CONFIG",
            "HKLM",
            "HKCU",
            "HKCR",
            "HKU",
            "HKCC",
        ];

        let upper = value.to_uppercase();
        if valid_roots.iter().any(|root| upper.starts_with(root)) {
            Ok(value.to_string())
        } else {
            Err(anyhow!("Invalid registry key format (must start with a valid root key)"))
        }
    }
}

/// CSV parser for IOC import
pub struct CsvIocParser;

impl CsvIocParser {
    /// Parse CSV content into IOC requests
    pub fn parse(content: &str) -> Result<Vec<CreateIocRequest>> {
        let mut result = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        if lines.is_empty() {
            return Err(anyhow!("Empty CSV content"));
        }

        // Parse header
        let header: Vec<String> = lines[0].split(',').map(|s| s.trim().to_lowercase()).collect();

        // Find column indices
        let value_idx = Self::find_column(&header, &["value", "ioc", "indicator", "ioc_value"])
            .ok_or_else(|| anyhow!("Missing required column: value/ioc/indicator"))?;
        let type_idx = Self::find_column(&header, &["type", "ioc_type", "indicator_type"]);
        let desc_idx = Self::find_column(&header, &["description", "desc", "comment"]);
        let severity_idx = Self::find_column(&header, &["severity", "level", "risk"]);
        let tags_idx = Self::find_column(&header, &["tags", "labels", "categories"]);
        let threat_actor_idx = Self::find_column(&header, &["threat_actor", "actor", "attribution"]);

        // Parse data rows
        for (line_num, line) in lines.iter().skip(1).enumerate() {
            if line.trim().is_empty() {
                continue;
            }

            let fields: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

            if fields.len() <= value_idx {
                continue;
            }

            let value = fields[value_idx].trim_matches('"').to_string();
            if value.is_empty() {
                continue;
            }

            // Determine IOC type
            let ioc_type = if let Some(idx) = type_idx {
                if fields.len() > idx {
                    IocType::from_str(fields[idx].trim_matches('"'))
                } else {
                    None
                }
            } else {
                None
            }.or_else(|| IocValidator::detect_type(&value));

            let ioc_type = match ioc_type {
                Some(t) => t,
                None => {
                    log::warn!("Could not determine IOC type for value at line {}: {}", line_num + 2, value);
                    continue;
                }
            };

            // Parse other fields
            let description = desc_idx.and_then(|idx| {
                if fields.len() > idx {
                    let d = fields[idx].trim_matches('"').to_string();
                    if !d.is_empty() { Some(d) } else { None }
                } else {
                    None
                }
            });

            let severity = severity_idx.and_then(|idx| {
                if fields.len() > idx {
                    IocSeverity::from_str(fields[idx].trim_matches('"'))
                } else {
                    None
                }
            });

            let tags = tags_idx.and_then(|idx| {
                if fields.len() > idx {
                    let tags_str = fields[idx].trim_matches('"');
                    if !tags_str.is_empty() {
                        Some(tags_str.split(';').map(|s| s.trim().to_string()).collect())
                    } else {
                        None
                    }
                } else {
                    None
                }
            });

            let threat_actor = threat_actor_idx.and_then(|idx| {
                if fields.len() > idx {
                    let actor = fields[idx].trim_matches('"').to_string();
                    if !actor.is_empty() { Some(actor) } else { None }
                } else {
                    None
                }
            });

            result.push(CreateIocRequest {
                ioc_type,
                value,
                description,
                source: Some(IocSource::CsvImport),
                severity,
                tags,
                threat_actor,
                mitre_techniques: None,
                expires_at: None,
                metadata: None,
            });
        }

        Ok(result)
    }

    fn find_column(header: &[String], candidates: &[&str]) -> Option<usize> {
        for (idx, col) in header.iter().enumerate() {
            let col_lower = col.to_lowercase();
            if candidates.iter().any(|c| col_lower.contains(c)) {
                return Some(idx);
            }
        }
        None
    }
}

/// STIX 2.1 parser for IOC import
pub struct StixIocParser;

impl StixIocParser {
    /// Parse STIX 2.1 JSON content into IOC requests
    pub fn parse(content: &str) -> Result<Vec<CreateIocRequest>> {
        let json: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| anyhow!("Invalid STIX JSON: {}", e))?;

        let mut result = Vec::new();

        // Get objects array
        let objects = json.get("objects")
            .and_then(|o| o.as_array())
            .ok_or_else(|| anyhow!("STIX bundle must contain 'objects' array"))?;

        for obj in objects {
            let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

            if obj_type != "indicator" {
                continue;
            }

            // Parse pattern
            let pattern = match obj.get("pattern").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => continue,
            };

            // Extract IOC from STIX pattern
            if let Some((ioc_type, value)) = Self::parse_pattern(pattern) {
                let description = obj.get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string());

                let name = obj.get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());

                let labels = obj.get("labels")
                    .and_then(|l| l.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

                result.push(CreateIocRequest {
                    ioc_type,
                    value,
                    description: description.or(name),
                    source: Some(IocSource::Stix),
                    severity: None,
                    tags: labels,
                    threat_actor: None,
                    mitre_techniques: None,
                    expires_at: None,
                    metadata: Some(serde_json::json!({
                        "stix_id": obj.get("id"),
                        "stix_created": obj.get("created"),
                    })),
                });
            }
        }

        Ok(result)
    }

    fn parse_pattern(pattern: &str) -> Option<(IocType, String)> {
        // Parse STIX 2.1 pattern format
        // Examples:
        // [ipv4-addr:value = '192.168.1.1']
        // [domain-name:value = 'evil.com']
        // [file:hashes.MD5 = 'abc123...']
        // [url:value = 'http://evil.com/malware']
        // [email-addr:value = 'bad@evil.com']

        let pattern = pattern.trim();

        if pattern.contains("ipv4-addr:value") || pattern.contains("ipv6-addr:value") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Ip, value));
            }
        }

        if pattern.contains("domain-name:value") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Domain, value));
            }
        }

        if pattern.contains("file:hashes.MD5") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Md5, value));
            }
        }

        if pattern.contains("file:hashes.'SHA-1'") || pattern.contains("file:hashes.SHA1") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Sha1, value));
            }
        }

        if pattern.contains("file:hashes.'SHA-256'") || pattern.contains("file:hashes.SHA256") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Sha256, value));
            }
        }

        if pattern.contains("url:value") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Url, value));
            }
        }

        if pattern.contains("email-addr:value") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Email, value));
            }
        }

        if pattern.contains("file:name") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::Filename, value));
            }
        }

        if pattern.contains("windows-registry-key") {
            if let Some(value) = Self::extract_value(pattern) {
                return Some((IocType::RegistryKey, value));
            }
        }

        None
    }

    fn extract_value(pattern: &str) -> Option<String> {
        // Extract value between quotes after '='
        let parts: Vec<&str> = pattern.split('=').collect();
        if parts.len() >= 2 {
            let value_part = parts[1].trim();
            // Remove quotes and brackets
            let value = value_part
                .trim_start_matches(|c| c == '\'' || c == '"' || c == '[' || c == ' ')
                .trim_end_matches(|c| c == '\'' || c == '"' || c == ']' || c == ' ');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        None
    }
}

/// Export IOCs to CSV format
pub fn export_to_csv(iocs: &[Ioc]) -> String {
    let mut csv = String::new();

    // Header
    csv.push_str("type,value,description,severity,status,source,tags,threat_actor,first_seen,last_seen\n");

    for ioc in iocs {
        let tags = ioc.tags.join(";");
        let description = ioc.description.as_deref().unwrap_or("").replace(',', ";");
        let threat_actor = ioc.threat_actor.as_deref().unwrap_or("");

        csv.push_str(&format!(
            "{},{},\"{}\",{},{},{},\"{}\",\"{}\",{},{}\n",
            ioc.ioc_type,
            ioc.value,
            description,
            ioc.severity,
            ioc.status,
            ioc.source,
            tags,
            threat_actor,
            ioc.first_seen.to_rfc3339(),
            ioc.last_seen.to_rfc3339()
        ));
    }

    csv
}

/// Export IOCs to STIX 2.1 format
pub fn export_to_stix(iocs: &[Ioc]) -> serde_json::Value {
    let mut objects = Vec::new();

    for ioc in iocs {
        let pattern = match ioc.ioc_type {
            IocType::Ip => format!("[ipv4-addr:value = '{}']", ioc.value),
            IocType::Domain => format!("[domain-name:value = '{}']", ioc.value),
            IocType::Md5 => format!("[file:hashes.MD5 = '{}']", ioc.value),
            IocType::Sha1 => format!("[file:hashes.'SHA-1' = '{}']", ioc.value),
            IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{}']", ioc.value),
            IocType::Url => format!("[url:value = '{}']", ioc.value),
            IocType::Email => format!("[email-addr:value = '{}']", ioc.value),
            IocType::Filename => format!("[file:name = '{}']", ioc.value),
            IocType::RegistryKey => format!("[windows-registry-key:key = '{}']", ioc.value),
        };

        let indicator = serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": format!("indicator--{}", ioc.id),
            "created": ioc.created_at.to_rfc3339(),
            "modified": ioc.updated_at.to_rfc3339(),
            "name": ioc.description.as_deref().unwrap_or(&ioc.value),
            "description": ioc.description.as_deref().unwrap_or(""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.first_seen.to_rfc3339(),
            "valid_until": ioc.expires_at.map(|d| d.to_rfc3339()),
            "labels": ioc.tags.clone(),
            "x_heroforge_severity": ioc.severity.to_string(),
            "x_heroforge_status": ioc.status.to_string(),
        });

        objects.push(indicator);
    }

    serde_json::json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid::Uuid::new_v4()),
        "spec_version": "2.1",
        "objects": objects
    })
}

/// Export IOCs to OpenIOC format (XML)
pub fn export_to_openioc(iocs: &[Ioc]) -> String {
    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<ioc xmlns="http://openioc.org/schemas/OpenIOC_1.1" id="heroforge-export" last-modified="">"#);

    xml.push_str("\n  <short_description>HeroForge IOC Export</short_description>\n");
    xml.push_str("  <definition>\n");
    xml.push_str("    <Indicator operator=\"OR\">\n");

    for ioc in iocs {
        let (indicator_type, search_context) = match ioc.ioc_type {
            IocType::Ip => ("Network", "Network/RemoteIP"),
            IocType::Domain => ("Network", "Network/DNS"),
            IocType::Md5 => ("File", "FileItem/Md5sum"),
            IocType::Sha1 => ("File", "FileItem/Sha1sum"),
            IocType::Sha256 => ("File", "FileItem/Sha256sum"),
            IocType::Url => ("Network", "UrlHistoryItem/URL"),
            IocType::Email => ("Email", "Email/From"),
            IocType::Filename => ("File", "FileItem/FileName"),
            IocType::RegistryKey => ("Registry", "RegistryItem/Path"),
        };

        xml.push_str(&format!(
            r#"      <IndicatorItem id="{}" condition="is">
        <Context document="{}" search="{}" type="mir"/>
        <Content type="string">{}</Content>
      </IndicatorItem>
"#,
            ioc.id,
            indicator_type,
            search_context,
            ioc.value
        ));
    }

    xml.push_str("    </Indicator>\n");
    xml.push_str("  </definition>\n");
    xml.push_str("</ioc>");

    xml
}

/// Match IOCs against provided data
pub struct IocMatcher {
    /// Compiled patterns for each IOC type
    patterns: HashMap<String, (IocType, String, Regex)>,
}

impl IocMatcher {
    /// Create a new IOC matcher from a list of IOCs
    pub fn new(iocs: &[Ioc]) -> Self {
        let mut patterns = HashMap::new();

        for ioc in iocs {
            if ioc.status != IocStatus::Active {
                continue;
            }

            // Create a regex pattern for each IOC
            let pattern = match ioc.ioc_type {
                IocType::Ip | IocType::Domain | IocType::Email | IocType::Url => {
                    // Escape special regex characters for exact matching
                    regex::escape(&ioc.value)
                }
                IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
                    // Case-insensitive hash matching
                    format!("(?i){}", ioc.value)
                }
                IocType::Filename | IocType::RegistryKey => {
                    // Case-insensitive matching for paths
                    format!("(?i){}", regex::escape(&ioc.value))
                }
            };

            if let Ok(regex) = Regex::new(&pattern) {
                patterns.insert(ioc.id.clone(), (ioc.ioc_type, ioc.value.clone(), regex));
            }
        }

        Self { patterns }
    }

    /// Match text against all IOCs
    pub fn match_text(&self, text: &str) -> Vec<(String, IocType, String)> {
        let mut matches = Vec::new();

        for (ioc_id, (ioc_type, value, regex)) in &self.patterns {
            if regex.is_match(text) {
                matches.push((ioc_id.clone(), *ioc_type, value.clone()));
            }
        }

        matches
    }

    /// Match structured data against IOCs
    pub fn match_data(&self, data: &serde_json::Value) -> Vec<(String, IocType, String, String)> {
        let mut matches = Vec::new();

        self.match_value_recursive(data, "", &mut matches);

        matches
    }

    fn match_value_recursive(
        &self,
        value: &serde_json::Value,
        path: &str,
        matches: &mut Vec<(String, IocType, String, String)>,
    ) {
        match value {
            serde_json::Value::String(s) => {
                for (ioc_id, (ioc_type, ioc_value, regex)) in &self.patterns {
                    if regex.is_match(s) {
                        matches.push((ioc_id.clone(), *ioc_type, ioc_value.clone(), path.to_string()));
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    let new_path = format!("{}[{}]", path, idx);
                    self.match_value_recursive(item, &new_path, matches);
                }
            }
            serde_json::Value::Object(obj) => {
                for (key, val) in obj {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    self.match_value_recursive(val, &new_path, matches);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioc_type_detection() {
        assert_eq!(IocValidator::detect_type("192.168.1.1"), Some(IocType::Ip));
        assert_eq!(IocValidator::detect_type("example.com"), Some(IocType::Domain));
        assert_eq!(IocValidator::detect_type("d41d8cd98f00b204e9800998ecf8427e"), Some(IocType::Md5));
        assert_eq!(IocValidator::detect_type("https://example.com/malware.exe"), Some(IocType::Url));
        assert_eq!(IocValidator::detect_type("test@example.com"), Some(IocType::Email));
        assert_eq!(IocValidator::detect_type("HKEY_LOCAL_MACHINE\\SOFTWARE\\Evil"), Some(IocType::RegistryKey));
    }

    #[test]
    fn test_ioc_validation() {
        assert!(IocValidator::validate(IocType::Ip, "192.168.1.1").is_ok());
        assert!(IocValidator::validate(IocType::Ip, "invalid").is_err());
        assert!(IocValidator::validate(IocType::Md5, "d41d8cd98f00b204e9800998ecf8427e").is_ok());
        assert!(IocValidator::validate(IocType::Md5, "invalid").is_err());
        assert!(IocValidator::validate(IocType::Email, "test@example.com").is_ok());
        assert!(IocValidator::validate(IocType::Email, "invalid").is_err());
    }

    #[test]
    fn test_csv_parsing() {
        let csv = r#"type,value,description,severity
ip,192.168.1.1,Malicious IP,high
domain,evil.com,C2 domain,critical
md5,d41d8cd98f00b204e9800998ecf8427e,Malware hash,medium"#;

        let result = CsvIocParser::parse(csv).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].ioc_type, IocType::Ip);
        assert_eq!(result[1].ioc_type, IocType::Domain);
        assert_eq!(result[2].ioc_type, IocType::Md5);
    }
}
