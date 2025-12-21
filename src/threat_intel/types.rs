#![allow(dead_code)]
//! Common types for threat intelligence data
//!
//! This module defines the core data structures used across all threat intelligence
//! integrations including Shodan, ExploitDB, and CVE feeds.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Severity levels for threat intelligence alerts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Info => write!(f, "info"),
            ThreatSeverity::Low => write!(f, "low"),
            ThreatSeverity::Medium => write!(f, "medium"),
            ThreatSeverity::High => write!(f, "high"),
            ThreatSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl From<f32> for ThreatSeverity {
    fn from(cvss: f32) -> Self {
        match cvss {
            s if s >= 9.0 => ThreatSeverity::Critical,
            s if s >= 7.0 => ThreatSeverity::High,
            s if s >= 4.0 => ThreatSeverity::Medium,
            s if s >= 0.1 => ThreatSeverity::Low,
            _ => ThreatSeverity::Info,
        }
    }
}

/// Type of threat intelligence source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSource {
    Shodan,
    ExploitDb,
    NvdCve,
    CisaKev,
    Manual,
}

impl std::fmt::Display for ThreatSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSource::Shodan => write!(f, "Shodan"),
            ThreatSource::ExploitDb => write!(f, "ExploitDB"),
            ThreatSource::NvdCve => write!(f, "NVD CVE"),
            ThreatSource::CisaKev => write!(f, "CISA KEV"),
            ThreatSource::Manual => write!(f, "Manual"),
        }
    }
}

/// Shodan host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanHostInfo {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub ports: Vec<u16>,
    pub vulns: Vec<String>,
    pub tags: Vec<String>,
    pub services: Vec<ShodanService>,
    pub last_update: Option<DateTime<Utc>>,
}

/// Shodan service/port information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanService {
    pub port: u16,
    pub protocol: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Vec<String>,
    pub vulns: Vec<String>,
}

/// ExploitDB exploit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitInfo {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub exploit_type: String,
    pub platform: Option<String>,
    pub author: Option<String>,
    pub date_published: Option<String>,
    pub cve_ids: Vec<String>,
    pub verified: bool,
    pub url: String,
    pub source_url: Option<String>,
}

/// Enriched CVE information from multiple sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedCve {
    pub cve_id: String,
    pub title: String,
    pub description: String,
    pub severity: ThreatSeverity,
    pub cvss_v3_score: Option<f32>,
    pub cvss_v2_score: Option<f32>,
    pub published_date: Option<DateTime<Utc>>,
    pub last_modified: Option<DateTime<Utc>>,
    pub affected_products: Vec<AffectedProduct>,
    pub exploits: Vec<ExploitInfo>,
    pub in_cisa_kev: bool,
    pub kev_due_date: Option<String>,
    pub references: Vec<String>,
    pub attack_vector: Option<String>,
    pub attack_complexity: Option<String>,
    pub epss_score: Option<f32>,
}

/// Affected product/version for a CVE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    pub cpe: Option<String>,
}

/// CISA Known Exploited Vulnerability entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisaKevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    pub known_ransomware_campaign_use: bool,
    pub notes: Option<String>,
}

/// Threat alert generated from intelligence correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: ThreatSeverity,
    pub title: String,
    pub description: String,
    pub source: ThreatSource,
    pub affected_assets: Vec<AffectedAsset>,
    pub cve_ids: Vec<String>,
    pub exploit_available: bool,
    pub in_cisa_kev: bool,
    pub recommendations: Vec<String>,
    pub references: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub scan_id: Option<String>,
}

/// Type of threat alert
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    /// Exposed service detected on Shodan
    ExposedService,
    /// Known exploit available for detected vulnerability
    ExploitAvailable,
    /// CVE in CISA KEV catalog
    KnownExploitedVulnerability,
    /// Critical CVE affecting detected service
    CriticalCve,
    /// New CVE published for detected service
    NewCve,
    /// Ransomware campaign using this vulnerability
    RansomwareThreat,
    /// Misconfiguration detected
    Misconfiguration,
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertType::ExposedService => write!(f, "Exposed Service"),
            AlertType::ExploitAvailable => write!(f, "Exploit Available"),
            AlertType::KnownExploitedVulnerability => write!(f, "Known Exploited Vulnerability"),
            AlertType::CriticalCve => write!(f, "Critical CVE"),
            AlertType::NewCve => write!(f, "New CVE"),
            AlertType::RansomwareThreat => write!(f, "Ransomware Threat"),
            AlertType::Misconfiguration => write!(f, "Misconfiguration"),
        }
    }
}

/// Asset affected by a threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedAsset {
    pub ip: String,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub version: Option<String>,
}

/// IP lookup result combining multiple threat intel sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpThreatIntel {
    pub ip: String,
    pub shodan_info: Option<ShodanHostInfo>,
    pub associated_cves: Vec<EnrichedCve>,
    pub available_exploits: Vec<ExploitInfo>,
    pub threat_score: u8,  // 0-100
    pub risk_factors: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

/// Request to enrich scan results with threat intel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentRequest {
    pub scan_id: String,
    pub enable_shodan: bool,
    pub enable_exploit_db: bool,
    pub enable_cve_enrichment: bool,
}

/// Result of threat intel enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    pub scan_id: String,
    pub alerts_generated: Vec<ThreatAlert>,
    pub enriched_hosts: usize,
    pub total_exploits_found: usize,
    pub critical_findings: usize,
    pub kev_matches: usize,
    pub enriched_at: DateTime<Utc>,
}

/// Configuration for threat intel sources
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    pub shodan_api_key: Option<String>,
    pub nvd_api_key: Option<String>,
    pub cache_ttl_hours: i64,
    pub enable_shodan: bool,
    pub enable_exploit_db: bool,
    pub enable_cisa_kev: bool,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            shodan_api_key: std::env::var("SHODAN_API_KEY").ok(),
            nvd_api_key: std::env::var("NVD_API_KEY").ok(),
            cache_ttl_hours: 24,
            enable_shodan: true,
            enable_exploit_db: true,
            enable_cisa_kev: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_severity_from_cvss() {
        assert_eq!(ThreatSeverity::from(9.8), ThreatSeverity::Critical);
        assert_eq!(ThreatSeverity::from(9.0), ThreatSeverity::Critical);
        assert_eq!(ThreatSeverity::from(7.5), ThreatSeverity::High);
        assert_eq!(ThreatSeverity::from(5.0), ThreatSeverity::Medium);
        assert_eq!(ThreatSeverity::from(2.0), ThreatSeverity::Low);
        assert_eq!(ThreatSeverity::from(0.0), ThreatSeverity::Info);
    }

    #[test]
    fn test_threat_severity_display() {
        assert_eq!(ThreatSeverity::Critical.to_string(), "critical");
        assert_eq!(ThreatSeverity::High.to_string(), "high");
    }
}
