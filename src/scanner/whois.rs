//! WHOIS lookup module for domain intelligence
//!
//! This module provides WHOIS lookup functionality for domains,
//! parsing structured data from WHOIS server responses.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// WHOIS data for a domain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoisData {
    /// The queried domain name
    pub domain: String,
    /// Registrar name
    pub registrar: Option<String>,
    /// Registrar WHOIS server
    pub registrar_whois_server: Option<String>,
    /// Registrar URL
    pub registrar_url: Option<String>,
    /// Registrant name (often redacted for privacy)
    pub registrant_name: Option<String>,
    /// Registrant organization
    pub registrant_org: Option<String>,
    /// Registrant email (often redacted)
    pub registrant_email: Option<String>,
    /// Registrant country
    pub registrant_country: Option<String>,
    /// Admin contact name
    pub admin_name: Option<String>,
    /// Admin contact email
    pub admin_email: Option<String>,
    /// Tech contact name
    pub tech_name: Option<String>,
    /// Tech contact email
    pub tech_email: Option<String>,
    /// Domain creation date
    pub creation_date: Option<String>,
    /// Domain expiration date
    pub expiry_date: Option<String>,
    /// Last update date
    pub updated_date: Option<String>,
    /// Parsed creation date (ISO 8601)
    pub creation_date_parsed: Option<DateTime<Utc>>,
    /// Parsed expiration date (ISO 8601)
    pub expiry_date_parsed: Option<DateTime<Utc>>,
    /// Parsed update date (ISO 8601)
    pub updated_date_parsed: Option<DateTime<Utc>>,
    /// Days until domain expires
    pub days_until_expiry: Option<i64>,
    /// Domain nameservers
    pub nameservers: Vec<String>,
    /// Domain status codes (EPP status)
    pub status_codes: Vec<String>,
    /// DNSSEC status
    pub dnssec: Option<String>,
    /// Raw WHOIS response
    pub raw_data: String,
    /// WHOIS server used for lookup
    pub whois_server: Option<String>,
    /// Lookup timestamp
    pub lookup_timestamp: DateTime<Utc>,
}

impl Default for WhoisData {
    fn default() -> Self {
        Self {
            domain: String::new(),
            registrar: None,
            registrar_whois_server: None,
            registrar_url: None,
            registrant_name: None,
            registrant_org: None,
            registrant_email: None,
            registrant_country: None,
            admin_name: None,
            admin_email: None,
            tech_name: None,
            tech_email: None,
            creation_date: None,
            expiry_date: None,
            updated_date: None,
            creation_date_parsed: None,
            expiry_date_parsed: None,
            updated_date_parsed: None,
            days_until_expiry: None,
            nameservers: Vec::new(),
            status_codes: Vec::new(),
            dnssec: None,
            raw_data: String::new(),
            whois_server: None,
            lookup_timestamp: Utc::now(),
        }
    }
}

/// Perform WHOIS lookup for a domain
///
/// # Arguments
/// * `domain` - The domain name to look up
///
/// # Returns
/// * `Result<WhoisData>` - Parsed WHOIS data or error
pub async fn lookup_domain(domain: &str) -> Result<WhoisData> {
    lookup_domain_with_timeout(domain, 30).await
}

/// Perform WHOIS lookup for a domain with custom timeout
///
/// # Arguments
/// * `domain` - The domain name to look up
/// * `timeout_secs` - Timeout in seconds for the WHOIS query
///
/// # Returns
/// * `Result<WhoisData>` - Parsed WHOIS data or error
pub async fn lookup_domain_with_timeout(domain: &str, timeout_secs: u64) -> Result<WhoisData> {
    info!("Performing WHOIS lookup for domain: {}", domain);

    // Validate domain format
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err(anyhow!("Domain cannot be empty"));
    }

    // Execute whois command with timeout
    let result = timeout(
        Duration::from_secs(timeout_secs),
        execute_whois_command(&domain),
    )
    .await
    .map_err(|_| anyhow!("WHOIS lookup timed out after {} seconds", timeout_secs))??;

    Ok(result)
}

/// Execute the whois command asynchronously
async fn execute_whois_command(domain: &str) -> Result<WhoisData> {
    let output = Command::new("whois")
        .arg(domain)
        .output()
        .await
        .map_err(|e| anyhow!("Failed to execute whois command: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("whois command failed for {}: {}", domain, stderr);
        // Still try to parse - some whois servers return non-zero but valid data
    }

    let raw_data = String::from_utf8_lossy(&output.stdout).to_string();
    debug!("WHOIS raw output length for {}: {} bytes", domain, raw_data.len());

    if raw_data.is_empty() {
        return Err(anyhow!("WHOIS query returned empty response"));
    }

    parse_whois_output(domain, &raw_data)
}

/// Parse WHOIS output into structured data
///
/// Handles multiple WHOIS server formats including:
/// - ICANN/Verisign format (.com, .net)
/// - IANA format
/// - ccTLD formats (.uk, .de, .io, etc.)
fn parse_whois_output(domain: &str, raw_data: &str) -> Result<WhoisData> {
    let mut data = WhoisData {
        domain: domain.to_string(),
        raw_data: raw_data.to_string(),
        lookup_timestamp: Utc::now(),
        ..Default::default()
    };

    for line in raw_data.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') || line.starts_with(">>>") {
            continue;
        }

        // Parse key-value pairs
        if let Some((key, value)) = parse_whois_line(line) {
            let key_lower = key.to_lowercase();
            let value = value.trim();

            if value.is_empty() {
                continue;
            }

            // Match various WHOIS field formats
            match key_lower.as_str() {
                // Registrar fields
                "registrar" | "sponsoring registrar" | "registrar name" => {
                    if data.registrar.is_none() {
                        data.registrar = Some(value.to_string());
                    }
                }
                "registrar whois server" => {
                    data.registrar_whois_server = Some(value.to_string());
                }
                "registrar url" => {
                    data.registrar_url = Some(value.to_string());
                }
                "whois server" | "whois" => {
                    if data.whois_server.is_none() {
                        data.whois_server = Some(value.to_string());
                    }
                }

                // Registrant fields
                "registrant name" | "registrant" => {
                    if data.registrant_name.is_none() {
                        data.registrant_name = Some(mask_personal_data(value));
                    }
                }
                "registrant organization" | "registrant org" | "org" | "organization" => {
                    if data.registrant_org.is_none() {
                        data.registrant_org = Some(value.to_string());
                    }
                }
                "registrant email" | "registrant e-mail" => {
                    if data.registrant_email.is_none() {
                        data.registrant_email = Some(mask_email(value));
                    }
                }
                "registrant country" | "registrant country/economy" => {
                    if data.registrant_country.is_none() {
                        data.registrant_country = Some(value.to_string());
                    }
                }

                // Admin contact fields
                "admin name" | "admin contact name" | "administrative contact name" => {
                    if data.admin_name.is_none() {
                        data.admin_name = Some(mask_personal_data(value));
                    }
                }
                "admin email" | "admin e-mail" | "administrative contact email" => {
                    if data.admin_email.is_none() {
                        data.admin_email = Some(mask_email(value));
                    }
                }

                // Tech contact fields
                "tech name" | "tech contact name" | "technical contact name" => {
                    if data.tech_name.is_none() {
                        data.tech_name = Some(mask_personal_data(value));
                    }
                }
                "tech email" | "tech e-mail" | "technical contact email" => {
                    if data.tech_email.is_none() {
                        data.tech_email = Some(mask_email(value));
                    }
                }

                // Date fields
                "creation date" | "created" | "registered" | "domain registration date"
                | "created on" | "registration date" | "created date" => {
                    if data.creation_date.is_none() {
                        data.creation_date = Some(value.to_string());
                        data.creation_date_parsed = parse_date(value);
                    }
                }
                "expiration date" | "expiry date" | "expires" | "registry expiry date"
                | "registrar registration expiration date" | "paid-till" | "expire date" => {
                    if data.expiry_date.is_none() {
                        data.expiry_date = Some(value.to_string());
                        data.expiry_date_parsed = parse_date(value);
                        if let Some(expiry) = data.expiry_date_parsed {
                            let now = Utc::now();
                            data.days_until_expiry = Some((expiry - now).num_days());
                        }
                    }
                }
                "updated date" | "last updated" | "last modified" | "last update"
                | "modified" | "changed" => {
                    if data.updated_date.is_none() {
                        data.updated_date = Some(value.to_string());
                        data.updated_date_parsed = parse_date(value);
                    }
                }

                // Nameserver fields
                "name server" | "nameserver" | "nserver" | "ns" | "nameservers" => {
                    let ns = value.to_lowercase();
                    // Some formats include IP after nameserver, extract just the hostname
                    let ns = ns.split_whitespace().next().unwrap_or(&ns);
                    if !data.nameservers.contains(&ns.to_string()) {
                        data.nameservers.push(ns.to_string());
                    }
                }

                // Status fields
                "domain status" | "status" => {
                    // Status may contain URL, extract just the status code
                    let status = value.split_whitespace().next().unwrap_or(value);
                    if !data.status_codes.contains(&status.to_string()) {
                        data.status_codes.push(status.to_string());
                    }
                }

                // DNSSEC
                "dnssec" | "dnssec signed" => {
                    if data.dnssec.is_none() {
                        data.dnssec = Some(value.to_string());
                    }
                }

                _ => {}
            }
        }
    }

    info!(
        "Parsed WHOIS for {}: registrar={:?}, created={:?}, expires={:?}, {} nameservers, {} status codes",
        domain,
        data.registrar,
        data.creation_date,
        data.expiry_date,
        data.nameservers.len(),
        data.status_codes.len()
    );

    Ok(data)
}

/// Parse a single WHOIS line into key-value pair
fn parse_whois_line(line: &str) -> Option<(String, String)> {
    // Try common delimiters: ":", then "="
    if let Some(pos) = line.find(':') {
        let key = line[..pos].trim();
        let value = line[pos + 1..].trim();
        if !key.is_empty() {
            return Some((key.to_string(), value.to_string()));
        }
    }
    None
}

/// Parse various date formats commonly found in WHOIS responses
fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
    let date_str = date_str.trim();

    // Common date formats in WHOIS responses
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",  // ISO 8601 with Z
        "%Y-%m-%dT%H:%M:%SZ",     // ISO 8601 without fractional
        "%Y-%m-%dT%H:%M:%S%z",    // ISO 8601 with timezone
        "%Y-%m-%d %H:%M:%S",      // Standard datetime
        "%Y-%m-%d",               // Date only
        "%d-%b-%Y",               // UK format (14-Aug-2024)
        "%d-%B-%Y",               // UK format with full month
        "%d.%m.%Y",               // European format
        "%Y/%m/%d",               // Asian format
        "%d/%m/%Y",               // European slash format
        "%Y%m%d",                 // Compact format
    ];

    // Try each format
    for format in &formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, format) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
        }
        // Also try parsing just date
        if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, format) {
            let dt = date.and_hms_opt(0, 0, 0)?;
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
        }
    }

    // Try parsing with chrono's flexible parser
    if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
        return Some(dt.with_timezone(&Utc));
    }

    debug!("Failed to parse date: {}", date_str);
    None
}

/// Mask email address for privacy (show domain only)
fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let domain = &email[at_pos..];
        format!("***{}", domain)
    } else {
        email.to_string()
    }
}

/// Mask personal data (show first character only)
fn mask_personal_data(data: &str) -> String {
    if data.len() > 1 {
        let first_char = data.chars().next().unwrap_or('*');
        format!("{}***", first_char)
    } else {
        data.to_string()
    }
}

/// Check if whois command is available on the system
pub fn is_whois_available() -> bool {
    std::process::Command::new("which")
        .arg("whois")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if a domain is expiring soon (within 30 days by default)
pub fn is_expiring_soon(data: &WhoisData, days: i64) -> bool {
    data.days_until_expiry.map_or(false, |d| d >= 0 && d <= days)
}

/// Check if a domain is expired
pub fn is_expired(data: &WhoisData) -> bool {
    data.days_until_expiry.map_or(false, |d| d < 0)
}

/// Get EPP status code descriptions
pub fn get_status_description(status: &str) -> &'static str {
    match status.to_lowercase().as_str() {
        "clienttransferprohibited" => "Transfer prohibited by registrant",
        "servertransferprohibited" => "Transfer prohibited by registry",
        "clientupdateprohibited" => "Updates prohibited by registrant",
        "serverupdateprohibited" => "Updates prohibited by registry",
        "clientdeleteprohibited" => "Deletion prohibited by registrant",
        "serverdeleteprohibited" => "Deletion prohibited by registry",
        "clienthold" => "Domain on hold by registrant",
        "serverhold" => "Domain on hold by registry",
        "clientrenewprohibited" => "Renewal prohibited by registrant",
        "serverrenewprohibited" => "Renewal prohibited by registry",
        "ok" | "active" => "Domain is active and operational",
        "inactive" => "Domain is inactive",
        "pendingtransfer" => "Transfer pending",
        "pendingdelete" => "Scheduled for deletion",
        "pendingcreate" => "Creation pending",
        "pendingupdate" => "Update pending",
        "pendingrenew" => "Renewal pending",
        "redemptionperiod" => "In redemption period after expiration",
        "addperiod" => "In add grace period",
        "renewperiod" => "In renewal grace period",
        "autoredeemperiod" => "Auto-redemption period",
        "transferperiod" => "In transfer grace period",
        _ => "Unknown status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_email() {
        assert_eq!(mask_email("test@example.com"), "***@example.com");
        assert_eq!(mask_email("admin@domain.org"), "***@domain.org");
        assert_eq!(mask_email("noemail"), "noemail");
    }

    #[test]
    fn test_mask_personal_data() {
        assert_eq!(mask_personal_data("John Doe"), "J***");
        assert_eq!(mask_personal_data("A"), "A");
        assert_eq!(mask_personal_data(""), "");
    }

    #[test]
    fn test_parse_date() {
        // ISO 8601 format
        let dt = parse_date("2024-08-14T04:00:00Z");
        assert!(dt.is_some());

        // Date only
        let dt = parse_date("2024-08-14");
        assert!(dt.is_some());

        // UK format
        let dt = parse_date("14-Aug-2024");
        assert!(dt.is_some());
    }

    #[test]
    fn test_parse_whois_line() {
        let (key, value) = parse_whois_line("Registrar: Example Registrar Inc.").unwrap();
        assert_eq!(key, "Registrar");
        assert_eq!(value, "Example Registrar Inc.");

        let (key, value) = parse_whois_line("Name Server: ns1.example.com").unwrap();
        assert_eq!(key, "Name Server");
        assert_eq!(value, "ns1.example.com");
    }

    #[test]
    fn test_parse_whois_output() {
        let raw = r#"
Domain Name: EXAMPLE.COM
Registrar: Example Registrar Inc.
Registrar URL: http://www.example-registrar.com
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Updated Date: 2023-08-14T00:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
Domain Status: clientDeleteProhibited
DNSSEC: unsigned
Registrant Email: admin@example.com
"#;
        let data = parse_whois_output("example.com", raw).unwrap();

        assert_eq!(data.registrar, Some("Example Registrar Inc.".to_string()));
        assert_eq!(data.registrar_url, Some("http://www.example-registrar.com".to_string()));
        assert_eq!(data.nameservers.len(), 2);
        assert!(data.nameservers.contains(&"ns1.example.com".to_string()));
        assert!(data.nameservers.contains(&"ns2.example.com".to_string()));
        assert_eq!(data.status_codes.len(), 2);
        assert!(data.status_codes.contains(&"clientTransferProhibited".to_string()));
        assert_eq!(data.dnssec, Some("unsigned".to_string()));
        assert!(data.creation_date_parsed.is_some());
        assert!(data.expiry_date_parsed.is_some());
    }

    #[test]
    fn test_get_status_description() {
        assert_eq!(get_status_description("clientTransferProhibited"), "Transfer prohibited by registrant");
        assert_eq!(get_status_description("ok"), "Domain is active and operational");
        assert_eq!(get_status_description("pendingDelete"), "Scheduled for deletion");
        assert_eq!(get_status_description("unknown_status"), "Unknown status");
    }

    #[test]
    fn test_is_expiring_soon() {
        let mut data = WhoisData::default();

        // Not expiring (100 days left)
        data.days_until_expiry = Some(100);
        assert!(!is_expiring_soon(&data, 30));

        // Expiring soon (15 days left)
        data.days_until_expiry = Some(15);
        assert!(is_expiring_soon(&data, 30));

        // Already expired
        data.days_until_expiry = Some(-5);
        assert!(!is_expiring_soon(&data, 30));

        // No expiry info
        data.days_until_expiry = None;
        assert!(!is_expiring_soon(&data, 30));
    }

    #[test]
    fn test_is_expired() {
        let mut data = WhoisData::default();

        data.days_until_expiry = Some(-5);
        assert!(is_expired(&data));

        data.days_until_expiry = Some(30);
        assert!(!is_expired(&data));

        data.days_until_expiry = None;
        assert!(!is_expired(&data));
    }
}
