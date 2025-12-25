//! Domain Intelligence Aggregation Module
//!
//! This module provides comprehensive domain intelligence by aggregating
//! WHOIS data, DNS history, related domain discovery hints, and more.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use super::dns_recon::{self, DnsReconResult};
use super::whois::{self, WhoisData};

/// DNS history entry representing a historical DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsHistoryEntry {
    /// Record type (A, AAAA, MX, NS, etc.)
    pub record_type: String,
    /// Record value
    pub value: String,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Source of the record
    pub source: String,
}

/// Related domain with relationship type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedDomain {
    /// The related domain name
    pub domain: String,
    /// Type of relationship
    pub relationship: RelationshipType,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// How the relationship was discovered
    pub discovery_method: String,
}

/// Types of domain relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Same registrant organization
    SameRegistrant,
    /// Same nameservers
    SameNameservers,
    /// Same mail servers
    SameMailServers,
    /// Similar name/typosquat
    SimilarName,
    /// Subdomain
    Subdomain,
    /// Parent domain
    ParentDomain,
    /// Same IP address
    SameIp,
    /// Same ASN
    SameAsn,
    /// Linked via certificate SAN
    CertificateSan,
    /// Unknown relationship
    Unknown,
}

/// Security indicators for a domain
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityIndicators {
    /// Whether the domain uses DNSSEC
    pub dnssec_enabled: bool,
    /// Whether the domain has secure registrar locks
    pub registrar_lock: bool,
    /// Domain age in days
    pub domain_age_days: Option<i64>,
    /// Whether the domain is newly registered (< 30 days)
    pub is_newly_registered: bool,
    /// Whether the domain is expiring soon (< 30 days)
    pub is_expiring_soon: bool,
    /// Whether the domain has expired
    pub is_expired: bool,
    /// Whether WHOIS privacy is enabled
    pub whois_privacy: bool,
    /// SPF record present
    pub has_spf: bool,
    /// DMARC record present
    pub has_dmarc: bool,
    /// DKIM selector found
    pub has_dkim: bool,
    /// MX records configured
    pub has_mx: bool,
    /// Zone transfer vulnerability
    pub zone_transfer_vulnerable: bool,
    /// Risk score (0-100)
    pub risk_score: u8,
    /// Risk factors contributing to the score
    pub risk_factors: Vec<String>,
}

impl Default for SecurityIndicators {
    fn default() -> Self {
        Self {
            dnssec_enabled: false,
            registrar_lock: false,
            domain_age_days: None,
            is_newly_registered: false,
            is_expiring_soon: false,
            is_expired: false,
            whois_privacy: false,
            has_spf: false,
            has_dmarc: false,
            has_dkim: false,
            has_mx: false,
            zone_transfer_vulnerable: false,
            risk_score: 0,
            risk_factors: Vec::new(),
        }
    }
}

/// Comprehensive domain intelligence data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainIntel {
    /// The queried domain
    pub domain: String,
    /// WHOIS data for the domain
    pub whois: Option<WhoisData>,
    /// Current DNS records
    pub dns: Option<DnsReconResult>,
    /// Historical DNS records (if available)
    pub dns_history: Vec<DnsHistoryEntry>,
    /// Related domains discovered
    pub related_domains: Vec<RelatedDomain>,
    /// Discovered subdomains
    pub subdomains: Vec<String>,
    /// IP addresses associated with the domain
    pub ip_addresses: Vec<IpAddr>,
    /// Autonomous System information
    pub asn_info: Option<AsnInfo>,
    /// Security indicators
    pub security: SecurityIndicators,
    /// Technologies detected (from HTTP headers, etc.)
    pub technologies: Vec<String>,
    /// Open ports discovered
    pub open_ports: Vec<u16>,
    /// Timestamp of the intelligence gathering
    pub gathered_at: DateTime<Utc>,
    /// Duration of the gathering process in milliseconds
    pub gathering_duration_ms: u64,
    /// Errors encountered during gathering
    pub errors: Vec<String>,
}

/// ASN (Autonomous System Number) information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsnInfo {
    /// ASN number
    pub asn: String,
    /// Organization name
    pub organization: String,
    /// Country code
    pub country: Option<String>,
    /// IP ranges announced
    pub ip_ranges: Vec<String>,
}

impl Default for DomainIntel {
    fn default() -> Self {
        Self {
            domain: String::new(),
            whois: None,
            dns: None,
            dns_history: Vec::new(),
            related_domains: Vec::new(),
            subdomains: Vec::new(),
            ip_addresses: Vec::new(),
            asn_info: None,
            security: SecurityIndicators::default(),
            technologies: Vec::new(),
            open_ports: Vec::new(),
            gathered_at: Utc::now(),
            gathering_duration_ms: 0,
            errors: Vec::new(),
        }
    }
}

/// Domain intelligence gathering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainIntelConfig {
    /// Include WHOIS lookup
    pub include_whois: bool,
    /// Include DNS reconnaissance
    pub include_dns: bool,
    /// Include subdomain enumeration
    pub include_subdomains: bool,
    /// Custom subdomain wordlist
    pub subdomain_wordlist: Option<Vec<String>>,
    /// Timeout for each operation in seconds
    pub timeout_secs: u64,
    /// Find related domains
    pub find_related: bool,
    /// Calculate security indicators
    pub calculate_security: bool,
}

impl Default for DomainIntelConfig {
    fn default() -> Self {
        Self {
            include_whois: true,
            include_dns: true,
            include_subdomains: true,
            subdomain_wordlist: None,
            timeout_secs: 30,
            find_related: true,
            calculate_security: true,
        }
    }
}

/// Gather comprehensive domain intelligence
///
/// # Arguments
/// * `domain` - The domain name to investigate
///
/// # Returns
/// * `Result<DomainIntel>` - Comprehensive domain intelligence or error
pub async fn gather_domain_intel(domain: &str) -> Result<DomainIntel> {
    gather_domain_intel_with_config(domain, &DomainIntelConfig::default()).await
}

/// Gather domain intelligence with custom configuration
///
/// # Arguments
/// * `domain` - The domain name to investigate
/// * `config` - Configuration options for the intelligence gathering
///
/// # Returns
/// * `Result<DomainIntel>` - Comprehensive domain intelligence or error
pub async fn gather_domain_intel_with_config(
    domain: &str,
    config: &DomainIntelConfig,
) -> Result<DomainIntel> {
    let start = std::time::Instant::now();
    info!("Gathering domain intelligence for: {}", domain);

    let domain = domain.trim().to_lowercase();
    let mut intel = DomainIntel {
        domain: domain.clone(),
        gathered_at: Utc::now(),
        ..Default::default()
    };

    // Gather WHOIS data
    if config.include_whois {
        match whois::lookup_domain_with_timeout(&domain, config.timeout_secs).await {
            Ok(whois_data) => {
                intel.whois = Some(whois_data);
                debug!("WHOIS lookup successful for {}", domain);
            }
            Err(e) => {
                let msg = format!("WHOIS lookup failed: {}", e);
                warn!("{}", msg);
                intel.errors.push(msg);
            }
        }
    }

    // Gather DNS data
    if config.include_dns {
        match dns_recon::perform_dns_recon(
            &domain,
            config.include_subdomains,
            config.subdomain_wordlist.clone(),
            config.timeout_secs,
        )
        .await
        {
            Ok(dns_result) => {
                // Extract subdomains
                intel.subdomains = dns_result.subdomains_found.clone();

                // Extract IP addresses from A records
                if let Some(a_records) = dns_result.records.get("A") {
                    for record in a_records {
                        if let Ok(ip) = record.value.parse::<IpAddr>() {
                            if !intel.ip_addresses.contains(&ip) {
                                intel.ip_addresses.push(ip);
                            }
                        }
                    }
                }

                // Extract IP addresses from AAAA records
                if let Some(aaaa_records) = dns_result.records.get("AAAA") {
                    for record in aaaa_records {
                        if let Ok(ip) = record.value.parse::<IpAddr>() {
                            if !intel.ip_addresses.contains(&ip) {
                                intel.ip_addresses.push(ip);
                            }
                        }
                    }
                }

                intel.dns = Some(dns_result);
                debug!("DNS reconnaissance successful for {}", domain);
            }
            Err(e) => {
                let msg = format!("DNS reconnaissance failed: {}", e);
                warn!("{}", msg);
                intel.errors.push(msg);
            }
        }
    }

    // Find related domains
    if config.find_related {
        intel.related_domains = find_related_domains(&intel);
    }

    // Calculate security indicators
    if config.calculate_security {
        intel.security = calculate_security_indicators(&intel);
    }

    // Convert DNS records to history entries (current snapshot)
    if let Some(ref dns) = intel.dns {
        intel.dns_history = create_dns_history_snapshot(dns);
    }

    let duration = start.elapsed();
    intel.gathering_duration_ms = duration.as_millis() as u64;

    info!(
        "Domain intelligence gathered for {} in {}ms (WHOIS: {}, DNS: {}, {} subdomains, {} IPs)",
        domain,
        intel.gathering_duration_ms,
        intel.whois.is_some(),
        intel.dns.is_some(),
        intel.subdomains.len(),
        intel.ip_addresses.len()
    );

    Ok(intel)
}

/// Find related domains based on WHOIS and DNS data
fn find_related_domains(intel: &DomainIntel) -> Vec<RelatedDomain> {
    let mut related = Vec::new();

    // Add parent domain if this is a subdomain
    let parts: Vec<&str> = intel.domain.split('.').collect();
    if parts.len() > 2 {
        let parent = parts[1..].join(".");
        related.push(RelatedDomain {
            domain: parent,
            relationship: RelationshipType::ParentDomain,
            confidence: 1.0,
            discovery_method: "Domain parsing".to_string(),
        });
    }

    // Add common variations/typosquats (hints only)
    let base_name = parts.first().unwrap_or(&"");
    if !base_name.is_empty() {
        // Common TLD variations
        let common_tlds = ["com", "net", "org", "io", "co", "biz", "info"];
        let current_tld = parts.last().unwrap_or(&"");

        for tld in &common_tlds {
            if *tld != *current_tld && parts.len() >= 2 {
                let variation = format!("{}.{}", parts[..parts.len() - 1].join("."), tld);
                if variation != intel.domain {
                    related.push(RelatedDomain {
                        domain: variation,
                        relationship: RelationshipType::SimilarName,
                        confidence: 0.3,
                        discovery_method: "TLD variation hint".to_string(),
                    });
                }
            }
        }
    }

    // Subdomains as related domains
    for subdomain in &intel.subdomains {
        related.push(RelatedDomain {
            domain: subdomain.clone(),
            relationship: RelationshipType::Subdomain,
            confidence: 1.0,
            discovery_method: "DNS enumeration".to_string(),
        });
    }

    // Same nameserver domains (hint - would need external data for actual lookup)
    if let Some(ref whois) = intel.whois {
        for ns in &whois.nameservers {
            // Extract the domain from the nameserver
            let ns_parts: Vec<&str> = ns.split('.').collect();
            if ns_parts.len() >= 2 {
                let ns_domain = ns_parts[ns_parts.len() - 2..].join(".");
                if ns_domain != intel.domain && !related.iter().any(|r| r.domain == ns_domain) {
                    related.push(RelatedDomain {
                        domain: ns_domain,
                        relationship: RelationshipType::SameNameservers,
                        confidence: 0.5,
                        discovery_method: "Nameserver analysis".to_string(),
                    });
                }
            }
        }
    }

    related
}

/// Calculate security indicators from gathered intelligence
fn calculate_security_indicators(intel: &DomainIntel) -> SecurityIndicators {
    let mut security = SecurityIndicators::default();
    let mut risk_factors = Vec::new();

    // DNSSEC check
    if let Some(ref dns) = intel.dns {
        security.dnssec_enabled = dns.dnssec_enabled;
        if !dns.dnssec_enabled {
            risk_factors.push("DNSSEC not enabled".to_string());
        }

        // Zone transfer vulnerability
        security.zone_transfer_vulnerable = dns.zone_transfer_vulnerable;
        if dns.zone_transfer_vulnerable {
            risk_factors.push("Zone transfer vulnerability detected".to_string());
        }

        // Check for MX records
        security.has_mx = dns.records.contains_key("MX");

        // Check for SPF
        if let Some(txt_records) = dns.records.get("TXT") {
            for record in txt_records {
                let value_lower = record.value.to_lowercase();
                if value_lower.starts_with("v=spf1") {
                    security.has_spf = true;
                }
                if value_lower.starts_with("v=dmarc1") {
                    security.has_dmarc = true;
                }
            }
        }

        // Check for DKIM (common selectors)
        // Note: Full DKIM check would require querying selector._domainkey.domain
        security.has_dkim = false; // Would need separate DNS lookups for DKIM selectors
    }

    // WHOIS-based indicators
    if let Some(ref whois) = intel.whois {
        // Registrar lock check
        let locked_statuses = ["clienttransferprohibited", "clientdeleteprohibited", "clientupdateprohibited"];
        security.registrar_lock = whois.status_codes.iter().any(|s| {
            locked_statuses.contains(&s.to_lowercase().as_str())
        });

        if !security.registrar_lock {
            risk_factors.push("Registrar lock not enabled".to_string());
        }

        // Domain age
        if let Some(creation) = whois.creation_date_parsed {
            let now = Utc::now();
            let age = (now - creation).num_days();
            security.domain_age_days = Some(age);
            security.is_newly_registered = age < 30;

            if security.is_newly_registered {
                risk_factors.push("Newly registered domain (< 30 days)".to_string());
            }
        }

        // Expiration check
        security.is_expiring_soon = whois::is_expiring_soon(whois, 30);
        security.is_expired = whois::is_expired(whois);

        if security.is_expiring_soon {
            risk_factors.push("Domain expiring soon (< 30 days)".to_string());
        }
        if security.is_expired {
            risk_factors.push("Domain has expired".to_string());
        }

        // WHOIS privacy detection
        let privacy_indicators = ["redacted", "privacy", "proxy", "whoisguard", "domains by proxy"];
        if let Some(ref registrant) = whois.registrant_name {
            if privacy_indicators.iter().any(|p| registrant.to_lowercase().contains(p)) {
                security.whois_privacy = true;
            }
        }
        if let Some(ref org) = whois.registrant_org {
            if privacy_indicators.iter().any(|p| org.to_lowercase().contains(p)) {
                security.whois_privacy = true;
            }
        }
    }

    // Email security checks
    if security.has_mx {
        if !security.has_spf {
            risk_factors.push("SPF record not configured".to_string());
        }
        if !security.has_dmarc {
            risk_factors.push("DMARC record not configured".to_string());
        }
    }

    // Calculate risk score (0-100)
    let mut score: u8 = 0;
    if !security.dnssec_enabled {
        score += 10;
    }
    if security.zone_transfer_vulnerable {
        score += 25;
    }
    if !security.registrar_lock {
        score += 10;
    }
    if security.is_newly_registered {
        score += 20;
    }
    if security.is_expiring_soon {
        score += 15;
    }
    if security.is_expired {
        score += 30;
    }
    if security.has_mx && !security.has_spf {
        score += 10;
    }
    if security.has_mx && !security.has_dmarc {
        score += 10;
    }

    security.risk_score = score.min(100);
    security.risk_factors = risk_factors;

    security
}

/// Create a DNS history snapshot from current DNS data
fn create_dns_history_snapshot(dns: &DnsReconResult) -> Vec<DnsHistoryEntry> {
    let mut history = Vec::new();
    let now = Utc::now();

    for (record_type, records) in &dns.records {
        for record in records {
            history.push(DnsHistoryEntry {
                record_type: record_type.clone(),
                value: record.value.clone(),
                first_seen: now,
                last_seen: now,
                source: "Current DNS".to_string(),
            });
        }
    }

    history
}

/// Get a summary of domain intelligence for quick overview
pub fn get_intel_summary(intel: &DomainIntel) -> HashMap<String, String> {
    let mut summary = HashMap::new();

    summary.insert("domain".to_string(), intel.domain.clone());

    if let Some(ref whois) = intel.whois {
        if let Some(ref registrar) = whois.registrar {
            summary.insert("registrar".to_string(), registrar.clone());
        }
        if let Some(ref creation) = whois.creation_date {
            summary.insert("created".to_string(), creation.clone());
        }
        if let Some(ref expiry) = whois.expiry_date {
            summary.insert("expires".to_string(), expiry.clone());
        }
        if let Some(days) = whois.days_until_expiry {
            summary.insert("days_until_expiry".to_string(), days.to_string());
        }
        summary.insert("nameserver_count".to_string(), whois.nameservers.len().to_string());
    }

    summary.insert("subdomain_count".to_string(), intel.subdomains.len().to_string());
    summary.insert("ip_count".to_string(), intel.ip_addresses.len().to_string());
    summary.insert("risk_score".to_string(), intel.security.risk_score.to_string());
    summary.insert("dnssec".to_string(), intel.security.dnssec_enabled.to_string());
    summary.insert("registrar_lock".to_string(), intel.security.registrar_lock.to_string());

    if let Some(ref dns) = intel.dns {
        summary.insert(
            "zone_transfer_vulnerable".to_string(),
            dns.zone_transfer_vulnerable.to_string(),
        );
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_intel_default() {
        let intel = DomainIntel::default();
        assert!(intel.domain.is_empty());
        assert!(intel.whois.is_none());
        assert!(intel.dns.is_none());
        assert!(intel.subdomains.is_empty());
        assert_eq!(intel.security.risk_score, 0);
    }

    #[test]
    fn test_domain_intel_config_default() {
        let config = DomainIntelConfig::default();
        assert!(config.include_whois);
        assert!(config.include_dns);
        assert!(config.include_subdomains);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_find_related_domains_parent() {
        let intel = DomainIntel {
            domain: "sub.example.com".to_string(),
            ..Default::default()
        };

        let related = find_related_domains(&intel);
        assert!(related.iter().any(|r| r.domain == "example.com" && r.relationship == RelationshipType::ParentDomain));
    }

    #[test]
    fn test_security_indicators_default() {
        let security = SecurityIndicators::default();
        assert!(!security.dnssec_enabled);
        assert!(!security.registrar_lock);
        assert!(!security.is_newly_registered);
        assert_eq!(security.risk_score, 0);
        assert!(security.risk_factors.is_empty());
    }

    #[test]
    fn test_get_intel_summary() {
        let mut intel = DomainIntel::default();
        intel.domain = "example.com".to_string();
        intel.subdomains = vec!["www.example.com".to_string()];
        intel.security.risk_score = 25;

        let summary = get_intel_summary(&intel);
        assert_eq!(summary.get("domain"), Some(&"example.com".to_string()));
        assert_eq!(summary.get("subdomain_count"), Some(&"1".to_string()));
        assert_eq!(summary.get("risk_score"), Some(&"25".to_string()));
    }

    #[test]
    fn test_relationship_type_serialization() {
        let rel = RelationshipType::SameNameservers;
        let json = serde_json::to_string(&rel).unwrap();
        assert_eq!(json, "\"same_nameservers\"");
    }
}
