use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Asset discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDiscoveryConfig {
    /// Target domain to discover assets for
    pub domain: String,
    /// Include Certificate Transparency log search
    pub include_ct_logs: bool,
    /// Include DNS enumeration
    pub include_dns: bool,
    /// Include Shodan API lookup
    pub include_shodan: bool,
    /// Include Censys API lookup
    pub include_censys: bool,
    /// Include WHOIS lookup
    pub include_whois: bool,
    /// Enable active subdomain enumeration (brute-force)
    pub active_enum: bool,
    /// Custom wordlist for subdomain enumeration
    pub wordlist: Option<Vec<String>>,
    /// Shodan API key (if using Shodan)
    pub shodan_api_key: Option<String>,
    /// Censys API ID (if using Censys)
    pub censys_api_id: Option<String>,
    /// Censys API secret (if using Censys)
    pub censys_api_secret: Option<String>,
    /// Maximum concurrent requests
    pub concurrency: usize,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for AssetDiscoveryConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            include_ct_logs: true,
            include_dns: true,
            include_shodan: false,
            include_censys: false,
            include_whois: true,
            active_enum: false,
            wordlist: None,
            shodan_api_key: None,
            censys_api_id: None,
            censys_api_secret: None,
            concurrency: 10,
            timeout_secs: 30,
        }
    }
}

/// Source of asset discovery
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DiscoverySource {
    CertificateTransparency,
    DnsEnumeration,
    Shodan,
    Censys,
    Whois,
    PassiveDns,
    SecurityTrails,
    VirusTotal,
    Manual,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateTransparency => write!(f, "CT Logs"),
            Self::DnsEnumeration => write!(f, "DNS"),
            Self::Shodan => write!(f, "Shodan"),
            Self::Censys => write!(f, "Censys"),
            Self::Whois => write!(f, "WHOIS"),
            Self::PassiveDns => write!(f, "Passive DNS"),
            Self::SecurityTrails => write!(f, "SecurityTrails"),
            Self::VirusTotal => write!(f, "VirusTotal"),
            Self::Manual => write!(f, "Manual"),
        }
    }
}

/// Discovered port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPort {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// Technology fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyFingerprint {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: f32,
}

/// SSL/TLS certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub sans: Vec<String>,
    pub fingerprint_sha256: String,
}

/// Discovered asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    pub id: String,
    pub hostname: String,
    pub ip_addresses: Vec<IpAddr>,
    pub sources: Vec<DiscoverySource>,
    pub ports: Vec<DiscoveredPort>,
    pub technologies: Vec<TechnologyFingerprint>,
    pub certificates: Vec<CertificateInfo>,
    pub dns_records: HashMap<String, Vec<String>>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub asn: Option<String>,
    pub asn_org: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub tags: Vec<String>,
}

impl DiscoveredAsset {
    pub fn new(hostname: String, source: DiscoverySource) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            hostname,
            ip_addresses: Vec::new(),
            sources: vec![source],
            ports: Vec::new(),
            technologies: Vec::new(),
            certificates: Vec::new(),
            dns_records: HashMap::new(),
            first_seen: now,
            last_seen: now,
            asn: None,
            asn_org: None,
            country: None,
            city: None,
            tags: Vec::new(),
        }
    }

    /// Merge data from another asset into this one
    pub fn merge(&mut self, other: &DiscoveredAsset) {
        // Merge IP addresses
        for ip in &other.ip_addresses {
            if !self.ip_addresses.contains(ip) {
                self.ip_addresses.push(*ip);
            }
        }

        // Merge sources
        for source in &other.sources {
            if !self.sources.contains(source) {
                self.sources.push(source.clone());
            }
        }

        // Merge ports
        for port in &other.ports {
            if !self.ports.iter().any(|p| p.port == port.port && p.protocol == port.protocol) {
                self.ports.push(port.clone());
            }
        }

        // Merge technologies
        for tech in &other.technologies {
            if !self.technologies.iter().any(|t| t.name == tech.name) {
                self.technologies.push(tech.clone());
            }
        }

        // Merge certificates
        for cert in &other.certificates {
            if !self.certificates.iter().any(|c| c.fingerprint_sha256 == cert.fingerprint_sha256) {
                self.certificates.push(cert.clone());
            }
        }

        // Merge DNS records
        for (rtype, values) in &other.dns_records {
            let entry = self.dns_records.entry(rtype.clone()).or_default();
            for val in values {
                if !entry.contains(val) {
                    entry.push(val.clone());
                }
            }
        }

        // Merge tags
        for tag in &other.tags {
            if !self.tags.contains(tag) {
                self.tags.push(tag.clone());
            }
        }

        // Update last_seen
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }

        // Fill in missing geo data
        if self.asn.is_none() && other.asn.is_some() {
            self.asn = other.asn.clone();
            self.asn_org = other.asn_org.clone();
        }
        if self.country.is_none() {
            self.country = other.country.clone();
        }
        if self.city.is_none() {
            self.city = other.city.clone();
        }
    }
}

/// WHOIS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrant_name: Option<String>,
    pub registrant_org: Option<String>,
    pub registrant_email: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub raw_data: String,
}

/// Asset discovery scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDiscoveryResult {
    pub id: String,
    pub domain: String,
    pub config: AssetDiscoveryConfig,
    pub status: AssetDiscoveryStatus,
    pub assets: Vec<DiscoveredAsset>,
    pub whois: Option<WhoisInfo>,
    pub statistics: DiscoveryStatistics,
    pub errors: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Discovery scan status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AssetDiscoveryStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Statistics from the discovery scan
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiscoveryStatistics {
    pub total_assets: usize,
    pub unique_hostnames: usize,
    pub unique_ips: usize,
    pub subdomains_from_ct: usize,
    pub subdomains_from_dns: usize,
    pub subdomains_from_shodan: usize,
    pub subdomains_from_censys: usize,
    pub open_ports_found: usize,
    pub technologies_identified: usize,
    pub certificates_found: usize,
}
