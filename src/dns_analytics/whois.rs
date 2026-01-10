//! WHOIS Lookup Module
//!
//! Provides WHOIS lookup functionality for domain registration information.
//! Supports major TLD registrars and parses common WHOIS response formats.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// WHOIS lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResult {
    /// Domain name
    pub domain: String,
    /// Registrar name
    pub registrar: Option<String>,
    /// Registrar WHOIS server
    pub registrar_whois_server: Option<String>,
    /// Registration date
    pub creation_date: Option<DateTime<Utc>>,
    /// Last updated date
    pub updated_date: Option<DateTime<Utc>>,
    /// Expiration date
    pub expiration_date: Option<DateTime<Utc>>,
    /// Domain status codes
    pub status: Vec<String>,
    /// Name servers
    pub name_servers: Vec<String>,
    /// Registrant organization
    pub registrant_org: Option<String>,
    /// Registrant country
    pub registrant_country: Option<String>,
    /// Admin email (often redacted)
    pub admin_email: Option<String>,
    /// DNSSEC enabled
    pub dnssec: Option<bool>,
    /// Raw WHOIS response
    pub raw_data: String,
    /// Lookup timestamp
    pub queried_at: DateTime<Utc>,
    /// Domain age in days
    pub domain_age_days: Option<i64>,
}

/// WHOIS server configuration
#[derive(Debug, Clone)]
pub struct WhoisConfig {
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Maximum response size in bytes
    pub max_response_size: usize,
    /// Enable caching
    pub enable_cache: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for WhoisConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_response_size: 65536,
            enable_cache: true,
            cache_ttl_secs: 3600,
        }
    }
}

/// WHOIS lookup client
pub struct WhoisClient {
    config: WhoisConfig,
    /// TLD to WHOIS server mapping
    whois_servers: HashMap<String, String>,
}

impl WhoisClient {
    /// Create a new WHOIS client with default configuration
    pub fn new() -> Self {
        Self::with_config(WhoisConfig::default())
    }

    /// Create a new WHOIS client with custom configuration
    pub fn with_config(config: WhoisConfig) -> Self {
        let mut whois_servers = HashMap::new();

        // Major TLD WHOIS servers
        whois_servers.insert("com".to_string(), "whois.verisign-grs.com".to_string());
        whois_servers.insert("net".to_string(), "whois.verisign-grs.com".to_string());
        whois_servers.insert("org".to_string(), "whois.pir.org".to_string());
        whois_servers.insert("info".to_string(), "whois.afilias.net".to_string());
        whois_servers.insert("biz".to_string(), "whois.biz".to_string());
        whois_servers.insert("us".to_string(), "whois.nic.us".to_string());
        whois_servers.insert("co".to_string(), "whois.nic.co".to_string());
        whois_servers.insert("io".to_string(), "whois.nic.io".to_string());
        whois_servers.insert("me".to_string(), "whois.nic.me".to_string());
        whois_servers.insert("tv".to_string(), "whois.nic.tv".to_string());
        whois_servers.insert("cc".to_string(), "ccwhois.verisign-grs.com".to_string());
        whois_servers.insert("xyz".to_string(), "whois.nic.xyz".to_string());
        whois_servers.insert("top".to_string(), "whois.nic.top".to_string());
        whois_servers.insert("club".to_string(), "whois.nic.club".to_string());
        whois_servers.insert("online".to_string(), "whois.nic.online".to_string());
        whois_servers.insert("site".to_string(), "whois.nic.site".to_string());
        whois_servers.insert("store".to_string(), "whois.nic.store".to_string());
        whois_servers.insert("tech".to_string(), "whois.nic.tech".to_string());
        whois_servers.insert("app".to_string(), "whois.nic.google".to_string());
        whois_servers.insert("dev".to_string(), "whois.nic.google".to_string());
        whois_servers.insert("page".to_string(), "whois.nic.google".to_string());

        // Country code TLDs
        whois_servers.insert("uk".to_string(), "whois.nic.uk".to_string());
        whois_servers.insert("de".to_string(), "whois.denic.de".to_string());
        whois_servers.insert("fr".to_string(), "whois.nic.fr".to_string());
        whois_servers.insert("nl".to_string(), "whois.domain-registry.nl".to_string());
        whois_servers.insert("eu".to_string(), "whois.eu".to_string());
        whois_servers.insert("ru".to_string(), "whois.tcinet.ru".to_string());
        whois_servers.insert("cn".to_string(), "whois.cnnic.cn".to_string());
        whois_servers.insert("jp".to_string(), "whois.jprs.jp".to_string());
        whois_servers.insert("au".to_string(), "whois.auda.org.au".to_string());
        whois_servers.insert("ca".to_string(), "whois.cira.ca".to_string());
        whois_servers.insert("br".to_string(), "whois.registro.br".to_string());
        whois_servers.insert("in".to_string(), "whois.registry.in".to_string());
        whois_servers.insert("pl".to_string(), "whois.dns.pl".to_string());
        whois_servers.insert("it".to_string(), "whois.nic.it".to_string());
        whois_servers.insert("es".to_string(), "whois.nic.es".to_string());
        whois_servers.insert("ch".to_string(), "whois.nic.ch".to_string());
        whois_servers.insert("at".to_string(), "whois.nic.at".to_string());
        whois_servers.insert("be".to_string(), "whois.dns.be".to_string());
        whois_servers.insert("dk".to_string(), "whois.punktum.dk".to_string());
        whois_servers.insert("se".to_string(), "whois.iis.se".to_string());
        whois_servers.insert("no".to_string(), "whois.norid.no".to_string());
        whois_servers.insert("fi".to_string(), "whois.fi".to_string());

        // Free TLDs (often used maliciously)
        whois_servers.insert("tk".to_string(), "whois.dot.tk".to_string());
        whois_servers.insert("ml".to_string(), "whois.nic.ml".to_string());
        whois_servers.insert("ga".to_string(), "whois.nic.ga".to_string());
        whois_servers.insert("cf".to_string(), "whois.nic.cf".to_string());
        whois_servers.insert("gq".to_string(), "whois.nic.gq".to_string());

        Self {
            config,
            whois_servers,
        }
    }

    /// Lookup WHOIS information for a domain
    pub fn lookup(&self, domain: &str) -> Result<WhoisResult, WhoisError> {
        let domain = domain.to_lowercase().trim().to_string();

        // Extract TLD
        let tld = domain.split('.').last()
            .ok_or(WhoisError::InvalidDomain)?;

        // Get WHOIS server for TLD
        let whois_server = self.whois_servers.get(tld)
            .cloned()
            .unwrap_or_else(|| format!("whois.nic.{}", tld));

        // Query WHOIS server
        let raw_data = self.query_whois_server(&whois_server, &domain)?;

        // Check for referral to another WHOIS server
        if let Some(referral_server) = self.extract_referral_server(&raw_data) {
            if referral_server != whois_server {
                // Follow referral
                let referral_data = self.query_whois_server(&referral_server, &domain)
                    .unwrap_or_default();
                if !referral_data.is_empty() {
                    return self.parse_whois_response(&domain, &referral_data);
                }
            }
        }

        self.parse_whois_response(&domain, &raw_data)
    }

    /// Async WHOIS lookup
    pub async fn lookup_async(&self, domain: &str) -> Result<WhoisResult, WhoisError> {
        let domain = domain.to_lowercase().trim().to_string();
        let config = self.config.clone();
        let whois_servers = self.whois_servers.clone();

        // Run in blocking task
        tokio::task::spawn_blocking(move || {
            let client = WhoisClient {
                config,
                whois_servers,
            };
            client.lookup(&domain)
        })
        .await
        .map_err(|_| WhoisError::Timeout)?
    }

    /// Query a WHOIS server
    fn query_whois_server(&self, server: &str, domain: &str) -> Result<String, WhoisError> {
        let addr = format!("{}:43", server);
        let timeout = Duration::from_secs(self.config.timeout_secs);

        let mut stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|_| WhoisError::ConnectionFailed)?,
            timeout,
        ).map_err(|_| WhoisError::ConnectionFailed)?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        // Send query
        let query = format!("{}\r\n", domain);
        stream.write_all(query.as_bytes())
            .map_err(|_| WhoisError::QueryFailed)?;

        // Read response
        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buffer[..n]);
                    if response.len() > self.config.max_response_size {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(_) => break,
            }
        }

        Ok(String::from_utf8_lossy(&response).to_string())
    }

    /// Extract referral WHOIS server from response
    fn extract_referral_server(&self, response: &str) -> Option<String> {
        let response_lower = response.to_lowercase();

        // Look for referral patterns
        let patterns = [
            "whois server:",
            "registrar whois server:",
            "whois:",
            "refer:",
        ];

        for pattern in &patterns {
            if let Some(pos) = response_lower.find(pattern) {
                let after = &response[pos + pattern.len()..];
                if let Some(end) = after.find('\n') {
                    let server = after[..end].trim().to_string();
                    if !server.is_empty() && server.contains('.') && !server.contains(' ') {
                        return Some(server);
                    }
                }
            }
        }

        None
    }

    /// Parse WHOIS response into structured data
    fn parse_whois_response(&self, domain: &str, raw_data: &str) -> Result<WhoisResult, WhoisError> {
        let now = Utc::now();

        let mut result = WhoisResult {
            domain: domain.to_string(),
            registrar: None,
            registrar_whois_server: None,
            creation_date: None,
            updated_date: None,
            expiration_date: None,
            status: Vec::new(),
            name_servers: Vec::new(),
            registrant_org: None,
            registrant_country: None,
            admin_email: None,
            dnssec: None,
            raw_data: raw_data.to_string(),
            queried_at: now,
            domain_age_days: None,
        };

        let lower_data = raw_data.to_lowercase();

        // Parse each line
        for line in raw_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
                continue;
            }

            // Split on : or =
            let (key, value) = if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_lowercase();
                let value = line[pos + 1..].trim();
                (key, value)
            } else if let Some(pos) = line.find('=') {
                let key = line[..pos].trim().to_lowercase();
                let value = line[pos + 1..].trim();
                (key, value)
            } else {
                continue;
            };

            if value.is_empty() {
                continue;
            }

            // Parse fields
            match key.as_str() {
                "registrar" | "sponsoring registrar" | "registrar name" => {
                    if result.registrar.is_none() {
                        result.registrar = Some(value.to_string());
                    }
                }
                "registrar whois server" | "whois server" => {
                    result.registrar_whois_server = Some(value.to_string());
                }
                "creation date" | "created" | "created date" | "created on" |
                "registration date" | "domain registration date" | "registered" |
                "registration time" | "created at" => {
                    if result.creation_date.is_none() {
                        result.creation_date = self.parse_date(value);
                    }
                }
                "updated date" | "last updated" | "last modified" | "changed" |
                "modified" | "updated" | "update date" | "last update" => {
                    if result.updated_date.is_none() {
                        result.updated_date = self.parse_date(value);
                    }
                }
                "registry expiry date" | "expiration date" | "expires" | "expires on" |
                "expiry date" | "expire date" | "paid-till" | "renewal date" |
                "registrar registration expiration date" => {
                    if result.expiration_date.is_none() {
                        result.expiration_date = self.parse_date(value);
                    }
                }
                "domain status" | "status" => {
                    // Extract just the status code, ignore URL
                    let status = value.split_whitespace().next().unwrap_or(value);
                    if !status.is_empty() {
                        result.status.push(status.to_string());
                    }
                }
                "name server" | "nserver" | "nameserver" | "name servers" => {
                    let ns = value.split_whitespace().next().unwrap_or(value);
                    if !ns.is_empty() && ns.contains('.') {
                        result.name_servers.push(ns.to_lowercase());
                    }
                }
                "registrant organization" | "registrant org" | "org" | "organization" => {
                    if result.registrant_org.is_none() && !value.to_lowercase().contains("redacted") {
                        result.registrant_org = Some(value.to_string());
                    }
                }
                "registrant country" | "country" | "registrant country/economy" => {
                    if result.registrant_country.is_none() {
                        result.registrant_country = Some(value.to_uppercase());
                    }
                }
                "admin email" | "administrative contact email" | "tech email" => {
                    if result.admin_email.is_none() && value.contains('@') && !value.contains("redacted") {
                        result.admin_email = Some(value.to_string());
                    }
                }
                "dnssec" => {
                    let val_lower = value.to_lowercase();
                    result.dnssec = Some(
                        val_lower == "signeddelegation" ||
                        val_lower == "signed" ||
                        val_lower == "yes" ||
                        val_lower == "true"
                    );
                }
                _ => {}
            }
        }

        // Calculate domain age
        if let Some(creation) = result.creation_date {
            result.domain_age_days = Some((now - creation).num_days());
        }

        // Deduplicate name servers
        result.name_servers.sort();
        result.name_servers.dedup();

        // Deduplicate status
        result.status.sort();
        result.status.dedup();

        Ok(result)
    }

    /// Parse various date formats
    fn parse_date(&self, date_str: &str) -> Option<DateTime<Utc>> {
        // Common date formats
        let formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%.fZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%d-%B-%Y",
            "%d.%m.%Y",
            "%d/%m/%Y",
            "%Y/%m/%d",
            "%b %d %Y",
            "%d %b %Y",
            "%Y%m%d",
        ];

        let date_str = date_str.trim();

        // Try each format
        for format in &formats {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(date_str, format) {
                return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
            }
            if let Ok(d) = chrono::NaiveDate::parse_from_str(date_str, format) {
                return Some(DateTime::from_naive_utc_and_offset(
                    d.and_hms_opt(0, 0, 0).unwrap(),
                    Utc,
                ));
            }
        }

        // Try ISO 8601 with timezone
        if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
            return Some(dt.with_timezone(&Utc));
        }

        // Try removing timezone suffix
        let cleaned = date_str
            .replace(" UTC", "")
            .replace(" GMT", "")
            .replace("Z", "");

        for format in &formats {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&cleaned, format) {
                return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
            }
        }

        None
    }

    /// Check if a domain is newly registered (less than N days old)
    pub fn is_newly_registered(&self, whois: &WhoisResult, max_age_days: i64) -> bool {
        whois.domain_age_days
            .map(|age| age < max_age_days)
            .unwrap_or(false)
    }

    /// Calculate risk score based on WHOIS data
    pub fn calculate_whois_risk_score(&self, whois: &WhoisResult) -> i32 {
        let mut score = 0;

        // Very new domain (less than 7 days)
        if let Some(age) = whois.domain_age_days {
            if age < 7 {
                score += 30;
            } else if age < 30 {
                score += 20;
            } else if age < 90 {
                score += 10;
            }
        }

        // No registrar info
        if whois.registrar.is_none() {
            score += 10;
        }

        // No name servers
        if whois.name_servers.is_empty() {
            score += 15;
        }

        // Privacy protected / redacted data
        if whois.registrant_org.is_none() && whois.admin_email.is_none() {
            score += 5; // Common for privacy, slight indicator
        }

        // High-risk registrars (free or low-cost)
        if let Some(ref registrar) = whois.registrar {
            let registrar_lower = registrar.to_lowercase();
            let risky_registrars = [
                "freenom", "dot tk", "namecheap", "pdr ltd",
                "1api", "eranet", "alibaba",
            ];
            for risky in &risky_registrars {
                if registrar_lower.contains(risky) {
                    score += 10;
                    break;
                }
            }
        }

        // Expiring soon (less than 30 days)
        if let Some(expiry) = whois.expiration_date {
            let days_until_expiry = (expiry - Utc::now()).num_days();
            if days_until_expiry < 30 && days_until_expiry > 0 {
                score += 10;
            }
        }

        // DNSSEC not enabled
        if whois.dnssec == Some(false) {
            score += 5;
        }

        // Suspicious status codes
        for status in &whois.status {
            let status_lower = status.to_lowercase();
            if status_lower.contains("clienthold") ||
               status_lower.contains("serverhold") ||
               status_lower.contains("pendingdelete") {
                score += 20;
                break;
            }
        }

        score.min(100)
    }
}

impl Default for WhoisClient {
    fn default() -> Self {
        Self::new()
    }
}

/// WHOIS lookup errors
#[derive(Debug, Clone)]
pub enum WhoisError {
    /// Invalid domain name
    InvalidDomain,
    /// Connection to WHOIS server failed
    ConnectionFailed,
    /// Query to WHOIS server failed
    QueryFailed,
    /// Response parsing failed
    ParseFailed,
    /// Request timed out
    Timeout,
    /// No WHOIS server for TLD
    NoWhoisServer,
}

impl std::fmt::Display for WhoisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WhoisError::InvalidDomain => write!(f, "Invalid domain name"),
            WhoisError::ConnectionFailed => write!(f, "Connection to WHOIS server failed"),
            WhoisError::QueryFailed => write!(f, "WHOIS query failed"),
            WhoisError::ParseFailed => write!(f, "Failed to parse WHOIS response"),
            WhoisError::Timeout => write!(f, "WHOIS lookup timed out"),
            WhoisError::NoWhoisServer => write!(f, "No WHOIS server for TLD"),
        }
    }
}

impl std::error::Error for WhoisError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_date() {
        let client = WhoisClient::new();

        // ISO 8601
        assert!(client.parse_date("2023-01-15T10:30:00Z").is_some());

        // Simple date
        assert!(client.parse_date("2023-01-15").is_some());

        // With time
        assert!(client.parse_date("2023-01-15 10:30:00").is_some());

        // European format
        assert!(client.parse_date("15-Jan-2023").is_some());
    }

    #[test]
    fn test_risk_score() {
        let client = WhoisClient::new();

        // New domain
        let whois = WhoisResult {
            domain: "newdomain.xyz".to_string(),
            registrar: Some("Freenom".to_string()),
            registrar_whois_server: None,
            creation_date: Some(Utc::now() - chrono::Duration::days(3)),
            updated_date: None,
            expiration_date: None,
            status: vec![],
            name_servers: vec![],
            registrant_org: None,
            registrant_country: None,
            admin_email: None,
            dnssec: Some(false),
            raw_data: String::new(),
            queried_at: Utc::now(),
            domain_age_days: Some(3),
        };

        let score = client.calculate_whois_risk_score(&whois);
        assert!(score > 50); // Should be high risk
    }
}
