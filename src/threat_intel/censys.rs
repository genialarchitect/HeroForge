#![allow(dead_code)]
//! Censys API integration for internet-wide scanning data
//!
//! This module provides integration with the Censys Search API to look up
//! information about hosts, certificates, and exposed services.
//!
//! Censys provides complementary data to Shodan with focus on:
//! - SSL/TLS certificate intelligence
//! - Internet-wide scanning data
//! - Host and service enumeration
//! - Historical data access

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const CENSYS_API_BASE: &str = "https://search.censys.io/api/v2";
const REQUEST_TIMEOUT_SECS: u64 = 30;

// =============================================================================
// Censys Client
// =============================================================================

/// Censys API client
pub struct CensysClient {
    client: Client,
    api_id: String,
    api_secret: String,
}

impl CensysClient {
    /// Create a new Censys client with API credentials
    pub fn new(api_id: String, api_secret: String) -> Result<Self> {
        if api_id.is_empty() || api_secret.is_empty() {
            return Err(anyhow!("Censys API ID and Secret are required"));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("HeroForge/0.2.0 (Security Scanner)")
            .build()?;

        Ok(Self {
            client,
            api_id,
            api_secret,
        })
    }

    /// Create a Censys client from environment variables
    pub fn from_env() -> Result<Self> {
        let api_id = std::env::var("CENSYS_API_ID")
            .map_err(|_| anyhow!("CENSYS_API_ID environment variable not set"))?;
        let api_secret = std::env::var("CENSYS_API_SECRET")
            .map_err(|_| anyhow!("CENSYS_API_SECRET environment variable not set"))?;
        Self::new(api_id, api_secret)
    }

    /// Get account info (quota, etc.)
    pub async fn get_account_info(&self) -> Result<CensysAccountInfo> {
        let url = format!("{}/account", CENSYS_API_BASE);

        let response = self.client
            .get(&url)
            .basic_auth(&self.api_id, Some(&self.api_secret))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Censys API error: {} - {}", status, body));
        }

        let account: CensysAccountResponse = response.json().await?;
        Ok(CensysAccountInfo {
            email: account.email,
            login: account.login,
            quota: CensysQuota {
                used: account.quota.used,
                resets_at: account.quota.resets_at,
                allowance: account.quota.allowance,
            },
        })
    }

    /// Look up a host by IP address
    pub async fn lookup_host(&self, ip: &str) -> Result<CensysHostInfo> {
        info!("Censys lookup for IP: {}", ip);
        let url = format!("{}/hosts/{}", CENSYS_API_BASE, ip);

        let response = self.client
            .get(&url)
            .basic_auth(&self.api_id, Some(&self.api_secret))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Censys API error: {} - {}", status, body));
        }

        let host_response: CensysHostResponse = response.json().await?;
        self.convert_host_response(host_response)
    }

    /// Search hosts with a query
    pub async fn search_hosts(&self, query: &str, per_page: u32) -> Result<CensysSearchResults> {
        info!("Censys host search: {}", query);
        let url = format!("{}/hosts/search", CENSYS_API_BASE);

        let request_body = CensysSearchRequest {
            q: query.to_string(),
            per_page: per_page.min(100), // Max 100 per page
            cursor: None,
        };

        let response = self.client
            .post(&url)
            .basic_auth(&self.api_id, Some(&self.api_secret))
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Censys API error: {} - {}", status, body));
        }

        let search_response: CensysSearchResponse = response.json().await?;
        Ok(CensysSearchResults {
            total: search_response.result.total,
            hosts: search_response.result.hits.into_iter()
                .map(|h| CensysSearchHit {
                    ip: h.ip,
                    services: h.services.into_iter()
                        .map(|s| CensysServiceSummary {
                            port: s.port,
                            service_name: s.service_name,
                            transport_protocol: s.transport_protocol,
                        })
                        .collect(),
                    location: h.location.map(|l| CensysLocation {
                        country: l.country,
                        country_code: l.country_code,
                        city: l.city,
                        latitude: l.latitude,
                        longitude: l.longitude,
                    }),
                    autonomous_system: h.autonomous_system.map(|a| CensysAS {
                        asn: a.asn,
                        name: a.name,
                        country_code: a.country_code,
                    }),
                    last_updated_at: h.last_updated_at,
                })
                .collect(),
            cursor: search_response.result.links.next,
        })
    }

    /// Search for certificates
    pub async fn search_certificates(&self, query: &str, per_page: u32) -> Result<CensysCertSearchResults> {
        info!("Censys certificate search: {}", query);
        let url = format!("{}/certificates/search", CENSYS_API_BASE);

        let request_body = CensysSearchRequest {
            q: query.to_string(),
            per_page: per_page.min(100),
            cursor: None,
        };

        let response = self.client
            .post(&url)
            .basic_auth(&self.api_id, Some(&self.api_secret))
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Censys API error: {} - {}", status, body));
        }

        let cert_response: CensysCertSearchResponse = response.json().await?;
        Ok(CensysCertSearchResults {
            total: cert_response.result.total,
            certificates: cert_response.result.hits.into_iter()
                .map(|c| CensysCertHit {
                    fingerprint_sha256: c.fingerprint_sha256,
                    names: c.names,
                    issuer: c.parsed.issuer.common_name.clone(),
                    subject: c.parsed.subject.common_name.clone(),
                    validity_start: c.parsed.validity.start,
                    validity_end: c.parsed.validity.end,
                    signature_algorithm: c.parsed.signature.signature_algorithm.name,
                    key_algorithm: c.parsed.subject_key_info.key_algorithm.name,
                    key_size: c.parsed.subject_key_info.key_algorithm.key_size,
                    is_trusted: c.parsed.validation.is_trusted,
                    hosts: c.hosts,
                })
                .collect(),
            cursor: cert_response.result.links.next,
        })
    }

    /// Get certificate by fingerprint
    pub async fn get_certificate(&self, fingerprint_sha256: &str) -> Result<CensysCertificate> {
        info!("Censys certificate lookup: {}", fingerprint_sha256);
        let url = format!("{}/certificates/{}", CENSYS_API_BASE, fingerprint_sha256);

        let response = self.client
            .get(&url)
            .basic_auth(&self.api_id, Some(&self.api_secret))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Censys API error: {} - {}", status, body));
        }

        let cert_response: CensysCertDetailResponse = response.json().await?;
        Ok(CensysCertificate {
            fingerprint_sha256: cert_response.result.fingerprint_sha256,
            fingerprint_sha1: cert_response.result.fingerprint_sha1,
            fingerprint_md5: cert_response.result.fingerprint_md5,
            names: cert_response.result.names,
            issuer_dn: cert_response.result.issuer_dn,
            subject_dn: cert_response.result.subject_dn,
            serial_number: cert_response.result.serial_number,
            validity_start: cert_response.result.parsed.validity.start,
            validity_end: cert_response.result.parsed.validity.end,
            is_ca: cert_response.result.parsed.extensions.basic_constraints.is_ca,
            is_trusted: cert_response.result.parsed.validation.is_trusted,
            hosts: cert_response.result.hosts,
        })
    }

    /// Get host history (aggregate data)
    pub async fn get_host_history(&self, ip: &str) -> Result<CensysHostHistory> {
        info!("Censys host history for: {}", ip);
        let url = format!("{}/hosts/{}/diff", CENSYS_API_BASE, ip);

        let response = self.client
            .get(&url)
            .basic_auth(&self.api_id, Some(&self.api_secret))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Censys API error: {} - {}", status, body));
        }

        let history: CensysHostHistoryResponse = response.json().await?;
        Ok(CensysHostHistory {
            ip: ip.to_string(),
            observations: history.result.observations.into_iter()
                .map(|o| CensysObservation {
                    timestamp: o.timestamp,
                    services_added: o.services_added.into_iter()
                        .map(|s| CensysServiceSummary {
                            port: s.port,
                            service_name: s.service_name,
                            transport_protocol: s.transport_protocol,
                        })
                        .collect(),
                    services_removed: o.services_removed.into_iter()
                        .map(|s| CensysServiceSummary {
                            port: s.port,
                            service_name: s.service_name,
                            transport_protocol: s.transport_protocol,
                        })
                        .collect(),
                })
                .collect(),
        })
    }

    /// Convert API response to our internal type
    fn convert_host_response(&self, response: CensysHostResponse) -> Result<CensysHostInfo> {
        let result = response.result;

        Ok(CensysHostInfo {
            ip: result.ip,
            last_updated_at: result.last_updated_at,
            services: result.services.into_iter()
                .map(|s| CensysService {
                    port: s.port,
                    service_name: s.service_name.unwrap_or_else(|| "unknown".to_string()),
                    transport_protocol: s.transport_protocol,
                    extended_service_name: s.extended_service_name,
                    software: s.software.into_iter()
                        .map(|sw| CensysSoftware {
                            vendor: sw.vendor,
                            product: sw.product,
                            version: sw.version,
                            cpe: sw.cpe,
                        })
                        .collect(),
                    tls: s.tls.map(|t| CensysTLS {
                        version_selected: t.version_selected,
                        cipher_selected: t.cipher_selected,
                        certificate: t.certificates.leaf_data.map(|c| CensysCertSummary {
                            fingerprint: c.fingerprint,
                            issuer_dn: c.issuer_dn,
                            subject_dn: c.subject_dn,
                            names: c.names,
                        }),
                    }),
                    banner: s.banner,
                    http: s.http.map(|h| CensysHTTP {
                        status_code: h.response.status_code,
                        body_hash: h.response.body_hash,
                        headers: h.response.headers,
                        title: h.response.html_title,
                    }),
                    vulnerabilities: s.cves.into_iter()
                        .map(|v| CensysVulnerability {
                            cve_id: v.cve_id,
                            severity: v.severity,
                            cvss_score: v.cvss_score,
                        })
                        .collect(),
                })
                .collect(),
            location: result.location.map(|l| CensysLocation {
                country: l.country,
                country_code: l.country_code,
                city: l.city,
                latitude: l.latitude,
                longitude: l.longitude,
            }),
            autonomous_system: result.autonomous_system.map(|a| CensysAS {
                asn: a.asn,
                name: a.name,
                country_code: a.country_code,
            }),
            operating_system: result.operating_system.map(|os| CensysOS {
                vendor: os.vendor,
                product: os.product,
                version: os.version,
                cpe: os.cpe,
            }),
            dns: result.dns.map(|d| CensysDNS {
                reverse_dns: d.reverse_dns,
                names: d.names,
            }),
        })
    }
}

// =============================================================================
// Public Types
// =============================================================================

/// Censys account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysAccountInfo {
    pub email: String,
    pub login: String,
    pub quota: CensysQuota,
}

/// API quota information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysQuota {
    pub used: i64,
    pub resets_at: String,
    pub allowance: i64,
}

/// Censys host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysHostInfo {
    pub ip: String,
    pub last_updated_at: String,
    pub services: Vec<CensysService>,
    pub location: Option<CensysLocation>,
    pub autonomous_system: Option<CensysAS>,
    pub operating_system: Option<CensysOS>,
    pub dns: Option<CensysDNS>,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysService {
    pub port: u16,
    pub service_name: String,
    pub transport_protocol: String,
    pub extended_service_name: Option<String>,
    pub software: Vec<CensysSoftware>,
    pub tls: Option<CensysTLS>,
    pub banner: Option<String>,
    pub http: Option<CensysHTTP>,
    pub vulnerabilities: Vec<CensysVulnerability>,
}

/// Software information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysSoftware {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
}

/// TLS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysTLS {
    pub version_selected: Option<String>,
    pub cipher_selected: Option<String>,
    pub certificate: Option<CensysCertSummary>,
}

/// Certificate summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysCertSummary {
    pub fingerprint: String,
    pub issuer_dn: String,
    pub subject_dn: String,
    pub names: Vec<String>,
}

/// HTTP service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysHTTP {
    pub status_code: Option<u16>,
    pub body_hash: Option<String>,
    pub headers: Option<std::collections::HashMap<String, Vec<String>>>,
    pub title: Option<String>,
}

/// Vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysVulnerability {
    pub cve_id: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f64>,
}

/// Location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysLocation {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Autonomous System information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysAS {
    pub asn: u32,
    pub name: Option<String>,
    pub country_code: Option<String>,
}

/// Operating System information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysOS {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
}

/// DNS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysDNS {
    pub reverse_dns: Option<Vec<String>>,
    pub names: Option<Vec<String>>,
}

/// Search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysSearchResults {
    pub total: i64,
    pub hosts: Vec<CensysSearchHit>,
    pub cursor: Option<String>,
}

/// Search hit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysSearchHit {
    pub ip: String,
    pub services: Vec<CensysServiceSummary>,
    pub location: Option<CensysLocation>,
    pub autonomous_system: Option<CensysAS>,
    pub last_updated_at: String,
}

/// Service summary for search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysServiceSummary {
    pub port: u16,
    pub service_name: Option<String>,
    pub transport_protocol: String,
}

/// Certificate search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysCertSearchResults {
    pub total: i64,
    pub certificates: Vec<CensysCertHit>,
    pub cursor: Option<String>,
}

/// Certificate search hit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysCertHit {
    pub fingerprint_sha256: String,
    pub names: Vec<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub validity_start: String,
    pub validity_end: String,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub key_size: Option<u32>,
    pub is_trusted: bool,
    pub hosts: Vec<String>,
}

/// Full certificate details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysCertificate {
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub fingerprint_md5: String,
    pub names: Vec<String>,
    pub issuer_dn: String,
    pub subject_dn: String,
    pub serial_number: String,
    pub validity_start: String,
    pub validity_end: String,
    pub is_ca: bool,
    pub is_trusted: bool,
    pub hosts: Vec<String>,
}

/// Host history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysHostHistory {
    pub ip: String,
    pub observations: Vec<CensysObservation>,
}

/// Historical observation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysObservation {
    pub timestamp: String,
    pub services_added: Vec<CensysServiceSummary>,
    pub services_removed: Vec<CensysServiceSummary>,
}

// =============================================================================
// Internal API Response Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct CensysAccountResponse {
    email: String,
    login: String,
    quota: CensysQuotaResponse,
}

#[derive(Debug, Deserialize)]
struct CensysQuotaResponse {
    used: i64,
    resets_at: String,
    allowance: i64,
}

#[derive(Debug, Deserialize)]
struct CensysHostResponse {
    result: CensysHostResult,
}

#[derive(Debug, Deserialize)]
struct CensysHostResult {
    ip: String,
    last_updated_at: String,
    services: Vec<CensysServiceResponse>,
    location: Option<CensysLocationResponse>,
    autonomous_system: Option<CensysASResponse>,
    operating_system: Option<CensysOSResponse>,
    dns: Option<CensysDNSResponse>,
}

#[derive(Debug, Deserialize)]
struct CensysServiceResponse {
    port: u16,
    service_name: Option<String>,
    transport_protocol: String,
    extended_service_name: Option<String>,
    #[serde(default)]
    software: Vec<CensysSoftwareResponse>,
    tls: Option<CensysTLSResponse>,
    banner: Option<String>,
    http: Option<CensysHTTPResponse>,
    #[serde(default)]
    cves: Vec<CensysCVEResponse>,
}

#[derive(Debug, Deserialize)]
struct CensysSoftwareResponse {
    vendor: Option<String>,
    product: Option<String>,
    version: Option<String>,
    cpe: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysTLSResponse {
    version_selected: Option<String>,
    cipher_selected: Option<String>,
    certificates: CensysCertificatesResponse,
}

#[derive(Debug, Deserialize)]
struct CensysCertificatesResponse {
    leaf_data: Option<CensysLeafCertResponse>,
}

#[derive(Debug, Deserialize)]
struct CensysLeafCertResponse {
    fingerprint: String,
    issuer_dn: String,
    subject_dn: String,
    names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CensysHTTPResponse {
    response: CensysHTTPResponseDetails,
}

#[derive(Debug, Deserialize)]
struct CensysHTTPResponseDetails {
    status_code: Option<u16>,
    body_hash: Option<String>,
    headers: Option<std::collections::HashMap<String, Vec<String>>>,
    html_title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysCVEResponse {
    #[serde(rename = "id")]
    cve_id: String,
    severity: Option<String>,
    #[serde(rename = "cvss")]
    cvss_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct CensysLocationResponse {
    country: Option<String>,
    country_code: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct CensysASResponse {
    asn: u32,
    name: Option<String>,
    country_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysOSResponse {
    vendor: Option<String>,
    product: Option<String>,
    version: Option<String>,
    cpe: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysDNSResponse {
    reverse_dns: Option<Vec<String>>,
    names: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct CensysSearchRequest {
    q: String,
    per_page: u32,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysSearchResponse {
    result: CensysSearchResult,
}

#[derive(Debug, Deserialize)]
struct CensysSearchResult {
    total: i64,
    hits: Vec<CensysSearchHitResponse>,
    links: CensysLinks,
}

#[derive(Debug, Deserialize)]
struct CensysSearchHitResponse {
    ip: String,
    services: Vec<CensysServiceSummaryResponse>,
    location: Option<CensysLocationResponse>,
    autonomous_system: Option<CensysASResponse>,
    last_updated_at: String,
}

#[derive(Debug, Deserialize)]
struct CensysServiceSummaryResponse {
    port: u16,
    service_name: Option<String>,
    transport_protocol: String,
}

#[derive(Debug, Deserialize)]
struct CensysLinks {
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysCertSearchResponse {
    result: CensysCertSearchResult,
}

#[derive(Debug, Deserialize)]
struct CensysCertSearchResult {
    total: i64,
    hits: Vec<CensysCertHitResponse>,
    links: CensysLinks,
}

#[derive(Debug, Deserialize)]
struct CensysCertHitResponse {
    fingerprint_sha256: String,
    names: Vec<String>,
    parsed: CensysCertParsed,
    #[serde(default)]
    hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CensysCertParsed {
    issuer: CensysCertDN,
    subject: CensysCertDN,
    validity: CensysCertValidity,
    signature: CensysCertSignature,
    subject_key_info: CensysSubjectKeyInfo,
    validation: CensysCertValidation,
    #[serde(default)]
    extensions: CensysCertExtensions,
}

#[derive(Debug, Deserialize, Default)]
struct CensysCertExtensions {
    #[serde(default)]
    basic_constraints: CensysBasicConstraints,
}

#[derive(Debug, Deserialize, Default)]
struct CensysBasicConstraints {
    #[serde(default)]
    is_ca: bool,
}

#[derive(Debug, Deserialize)]
struct CensysCertDN {
    common_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysCertValidity {
    start: String,
    end: String,
}

#[derive(Debug, Deserialize)]
struct CensysCertSignature {
    signature_algorithm: CensysAlgorithm,
}

#[derive(Debug, Deserialize)]
struct CensysSubjectKeyInfo {
    key_algorithm: CensysKeyAlgorithm,
}

#[derive(Debug, Deserialize)]
struct CensysAlgorithm {
    name: String,
}

#[derive(Debug, Deserialize)]
struct CensysKeyAlgorithm {
    name: String,
    key_size: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct CensysCertValidation {
    #[serde(default)]
    is_trusted: bool,
}

#[derive(Debug, Deserialize)]
struct CensysCertDetailResponse {
    result: CensysCertDetail,
}

#[derive(Debug, Deserialize)]
struct CensysCertDetail {
    fingerprint_sha256: String,
    fingerprint_sha1: String,
    fingerprint_md5: String,
    names: Vec<String>,
    issuer_dn: String,
    subject_dn: String,
    serial_number: String,
    parsed: CensysCertParsed,
    #[serde(default)]
    hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CensysHostHistoryResponse {
    result: CensysHostHistoryResult,
}

#[derive(Debug, Deserialize)]
struct CensysHostHistoryResult {
    observations: Vec<CensysObservationResponse>,
}

#[derive(Debug, Deserialize)]
struct CensysObservationResponse {
    timestamp: String,
    #[serde(default)]
    services_added: Vec<CensysServiceSummaryResponse>,
    #[serde(default)]
    services_removed: Vec<CensysServiceSummaryResponse>,
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Combine Shodan and Censys data for comprehensive host intel
pub fn merge_host_intel(
    shodan: Option<&super::types::ShodanHostInfo>,
    censys: Option<&CensysHostInfo>,
) -> MergedHostIntel {
    let mut ports = std::collections::HashSet::new();
    let mut services = Vec::new();
    let mut vulns = std::collections::HashSet::new();

    // Add Shodan data
    if let Some(s) = shodan {
        for port in &s.ports {
            ports.insert(*port);
        }
        for svc in &s.services {
            services.push(MergedService {
                port: svc.port,
                product: svc.product.clone(),
                version: svc.version.clone(),
                source: "shodan".to_string(),
            });
        }
        for v in &s.vulns {
            vulns.insert(v.clone());
        }
    }

    // Add Censys data
    if let Some(c) = censys {
        for svc in &c.services {
            ports.insert(svc.port);
            services.push(MergedService {
                port: svc.port,
                product: svc.software.first().and_then(|s| s.product.clone()),
                version: svc.software.first().and_then(|s| s.version.clone()),
                source: "censys".to_string(),
            });
            for v in &svc.vulnerabilities {
                vulns.insert(v.cve_id.clone());
            }
        }
    }

    MergedHostIntel {
        ports: ports.into_iter().collect(),
        services,
        vulnerabilities: vulns.into_iter().collect(),
        location: censys.and_then(|c| c.location.as_ref().map(|l| l.country.clone().unwrap_or_default()))
            .or_else(|| shodan.and_then(|s| s.country.clone())),
        asn: censys.and_then(|c| c.autonomous_system.as_ref().map(|a| a.asn))
            .or_else(|| shodan.and_then(|s| s.asn.as_ref().and_then(|a| a.parse().ok()))),
    }
}

/// Merged host intelligence from multiple sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedHostIntel {
    pub ports: Vec<u16>,
    pub services: Vec<MergedService>,
    pub vulnerabilities: Vec<String>,
    pub location: Option<String>,
    pub asn: Option<u32>,
}

/// Merged service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedService {
    pub port: u16,
    pub product: Option<String>,
    pub version: Option<String>,
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_censys_client_creation() {
        // Should fail with empty credentials
        let result = CensysClient::new("".to_string(), "".to_string());
        assert!(result.is_err());

        // Should succeed with valid credentials
        let result = CensysClient::new("test-id".to_string(), "test-secret".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn test_merge_host_intel() {
        let censys_host = CensysHostInfo {
            ip: "1.2.3.4".to_string(),
            last_updated_at: "2025-01-01".to_string(),
            services: vec![
                CensysService {
                    port: 443,
                    service_name: "HTTPS".to_string(),
                    transport_protocol: "TCP".to_string(),
                    extended_service_name: None,
                    software: vec![],
                    tls: None,
                    banner: None,
                    http: None,
                    vulnerabilities: vec![
                        CensysVulnerability {
                            cve_id: "CVE-2023-1234".to_string(),
                            severity: Some("HIGH".to_string()),
                            cvss_score: Some(8.5),
                        }
                    ],
                }
            ],
            location: Some(CensysLocation {
                country: Some("United States".to_string()),
                country_code: Some("US".to_string()),
                city: Some("New York".to_string()),
                latitude: None,
                longitude: None,
            }),
            autonomous_system: Some(CensysAS {
                asn: 12345,
                name: Some("Example ASN".to_string()),
                country_code: Some("US".to_string()),
            }),
            operating_system: None,
            dns: None,
        };

        let merged = merge_host_intel(None, Some(&censys_host));
        assert!(merged.ports.contains(&443));
        assert!(merged.vulnerabilities.contains(&"CVE-2023-1234".to_string()));
        assert_eq!(merged.location, Some("United States".to_string()));
        assert_eq!(merged.asn, Some(12345));
    }
}
