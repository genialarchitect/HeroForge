//! Real-time CVE announcement feeds (NVD, CISA KEV)
//!
//! This module provides integration with CVE data sources including:
//! - NIST National Vulnerability Database (NVD)
//! - CISA Known Exploited Vulnerabilities (KEV) catalog

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

use super::types::{AffectedProduct, CisaKevEntry, EnrichedCve, ThreatSeverity};

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CISA_KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// CVE Feeds client for fetching vulnerability data
pub struct CveFeedsClient {
    client: Client,
    nvd_api_key: Option<String>,
}

/// NVD API response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    results_per_page: Option<i32>,
    start_index: Option<i32>,
    total_results: Option<i32>,
    vulnerabilities: Vec<NvdVulnerability>,
}

/// NVD vulnerability wrapper
#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

/// NVD CVE data
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
    published: Option<String>,
    last_modified: Option<String>,
    configurations: Option<Vec<NvdConfiguration>>,
    references: Option<Vec<NvdReference>>,
}

/// NVD description
#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

/// NVD metrics
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v31: Option<Vec<CvssMetricV31>>,
    cvss_metric_v30: Option<Vec<CvssMetricV30>>,
    cvss_metric_v2: Option<Vec<CvssMetricV2>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssMetricV31 {
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssMetricV30 {
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssMetricV2 {
    cvss_data: CvssDataV2,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    base_score: f32,
    base_severity: Option<String>,
    attack_vector: Option<String>,
    attack_complexity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssDataV2 {
    base_score: f32,
}

/// NVD configuration (for affected products)
#[derive(Debug, Deserialize)]
struct NvdConfiguration {
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdNode {
    cpe_match: Option<Vec<CpeMatch>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    criteria: String,
    vulnerable: bool,
}

/// NVD reference
#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
}

/// CISA KEV catalog response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CisaKevCatalog {
    title: String,
    catalog_version: String,
    date_released: String,
    count: i32,
    vulnerabilities: Vec<CisaKevVulnerability>,
}

/// CISA KEV vulnerability entry
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CisaKevVulnerability {
    cve_id: String,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    short_description: String,
    required_action: String,
    due_date: String,
    known_ransomware_campaign_use: Option<String>,
    notes: Option<String>,
}

impl CveFeedsClient {
    /// Create a new CVE feeds client
    pub fn new(nvd_api_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("HeroForge/0.1.0 (Security Scanner)")
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            nvd_api_key,
        }
    }

    /// Create client from environment
    pub fn from_env() -> Self {
        let nvd_api_key = std::env::var("NVD_API_KEY").ok();
        Self::new(nvd_api_key)
    }

    /// Get enriched CVE details by ID
    pub async fn get_cve(&self, cve_id: &str) -> Result<EnrichedCve> {
        let url = format!("{}?cveId={}", NVD_API_BASE, cve_id);

        info!("Fetching CVE details: {}", cve_id);
        debug!("NVD URL: {}", url);

        let mut request = self.client.get(&url);
        if let Some(ref key) = self.nvd_api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("NVD API error: {} - {}", status, body));
        }

        let nvd_response: NvdResponse = response.json().await?;

        let cve = nvd_response
            .vulnerabilities
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("CVE {} not found", cve_id))?;

        // Check CISA KEV status
        let kev_entry = self.check_cisa_kev(cve_id).await.ok().flatten();

        Ok(convert_nvd_to_enriched(cve, kev_entry))
    }

    /// Search for CVEs by keyword
    pub async fn search_cves(&self, keyword: &str, limit: Option<i32>) -> Result<Vec<EnrichedCve>> {
        let limit = limit.unwrap_or(20);
        let url = format!(
            "{}?keywordSearch={}&resultsPerPage={}",
            NVD_API_BASE,
            urlencoding::encode(keyword),
            limit
        );

        info!("Searching NVD for: {}", keyword);

        let mut request = self.client.get(&url);
        if let Some(ref key) = self.nvd_api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("NVD search error: {} - {}", status, body));
        }

        let nvd_response: NvdResponse = response.json().await?;
        info!("NVD search returned {} results", nvd_response.total_results.unwrap_or(0));

        let cves: Vec<EnrichedCve> = nvd_response
            .vulnerabilities
            .into_iter()
            .map(|v| convert_nvd_to_enriched(v, None))
            .collect();

        Ok(cves)
    }

    /// Get recent CVEs (last N days)
    pub async fn get_recent_cves(&self, days: i32) -> Result<Vec<EnrichedCve>> {
        let now = Utc::now();
        let start = now - chrono::Duration::days(days as i64);

        let url = format!(
            "{}?pubStartDate={}&pubEndDate={}&resultsPerPage=50",
            NVD_API_BASE,
            start.format("%Y-%m-%dT00:00:00.000"),
            now.format("%Y-%m-%dT23:59:59.999")
        );

        info!("Fetching CVEs from last {} days", days);

        let mut request = self.client.get(&url);
        if let Some(ref key) = self.nvd_api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("NVD recent CVEs error: {} - {}", status, body));
        }

        let nvd_response: NvdResponse = response.json().await?;
        info!("Found {} recent CVEs", nvd_response.total_results.unwrap_or(0));

        let cves: Vec<EnrichedCve> = nvd_response
            .vulnerabilities
            .into_iter()
            .map(|v| convert_nvd_to_enriched(v, None))
            .collect();

        Ok(cves)
    }

    /// Fetch the complete CISA KEV catalog
    pub async fn get_cisa_kev_catalog(&self) -> Result<Vec<CisaKevEntry>> {
        info!("Fetching CISA KEV catalog");

        let response = self.client.get(CISA_KEV_URL).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(anyhow!("CISA KEV API error: {}", status));
        }

        let catalog: CisaKevCatalog = response.json().await?;
        info!("CISA KEV catalog contains {} entries", catalog.count);

        let entries: Vec<CisaKevEntry> = catalog
            .vulnerabilities
            .into_iter()
            .map(convert_kev_entry)
            .collect();

        Ok(entries)
    }

    /// Check if a CVE is in the CISA KEV catalog
    pub async fn check_cisa_kev(&self, cve_id: &str) -> Result<Option<CisaKevEntry>> {
        // Use cached catalog if available, otherwise fetch
        let catalog = self.get_cisa_kev_catalog().await?;

        Ok(catalog.into_iter().find(|e| e.cve_id == cve_id))
    }

    /// Get CVEs affecting a specific product
    pub async fn get_cves_for_product(&self, vendor: &str, product: &str, version: Option<&str>) -> Result<Vec<EnrichedCve>> {
        let query = if let Some(ver) = version {
            format!("{}:{}:{}", vendor, product, ver)
        } else {
            format!("{}:{}", vendor, product)
        };

        self.search_cves(&query, Some(50)).await
    }
}

/// Convert NVD response to EnrichedCve
fn convert_nvd_to_enriched(nvd: NvdVulnerability, kev_entry: Option<CisaKevEntry>) -> EnrichedCve {
    let cve = nvd.cve;

    // Get English description
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_else(|| "No description available.".to_string());

    // Extract CVSS scores and severity
    let (cvss_v3_score, cvss_v2_score, severity, attack_vector, attack_complexity) =
        extract_cvss_info(&cve.metrics);

    // Extract affected products from CPE
    let affected_products = extract_affected_products(&cve.configurations);

    // Extract references
    let references: Vec<String> = cve
        .references
        .map(|refs| refs.into_iter().map(|r| r.url).collect())
        .unwrap_or_default();

    // Parse dates
    let published_date = cve
        .published
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let last_modified = cve
        .last_modified
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    // Create title from first line of description
    let title = format!(
        "{}: {}",
        cve.id,
        description
            .lines()
            .next()
            .unwrap_or("Unknown")
            .chars()
            .take(100)
            .collect::<String>()
    );

    // KEV information
    let (in_cisa_kev, kev_due_date) = match kev_entry {
        Some(ref entry) => (true, Some(entry.due_date.clone())),
        None => (is_in_offline_kev(&cve.id), None),
    };

    EnrichedCve {
        cve_id: cve.id,
        title,
        description,
        severity,
        cvss_v3_score,
        cvss_v2_score,
        published_date,
        last_modified,
        affected_products,
        exploits: Vec::new(), // Will be populated by exploit_db
        in_cisa_kev,
        kev_due_date,
        references,
        attack_vector,
        attack_complexity,
        epss_score: None, // Would require separate API
    }
}

/// Extract CVSS information from NVD metrics
fn extract_cvss_info(
    metrics: &Option<NvdMetrics>,
) -> (Option<f32>, Option<f32>, ThreatSeverity, Option<String>, Option<String>) {
    if let Some(m) = metrics {
        // Try CVSS v3.1 first
        if let Some(cvss31) = &m.cvss_metric_v31 {
            if let Some(first) = cvss31.first() {
                let score = first.cvss_data.base_score;
                return (
                    Some(score),
                    None,
                    ThreatSeverity::from(score),
                    first.cvss_data.attack_vector.clone(),
                    first.cvss_data.attack_complexity.clone(),
                );
            }
        }

        // Try CVSS v3.0
        if let Some(cvss30) = &m.cvss_metric_v30 {
            if let Some(first) = cvss30.first() {
                let score = first.cvss_data.base_score;
                return (
                    Some(score),
                    None,
                    ThreatSeverity::from(score),
                    first.cvss_data.attack_vector.clone(),
                    first.cvss_data.attack_complexity.clone(),
                );
            }
        }

        // Fall back to CVSS v2
        if let Some(cvss2) = &m.cvss_metric_v2 {
            if let Some(first) = cvss2.first() {
                let score = first.cvss_data.base_score;
                return (
                    None,
                    Some(score),
                    ThreatSeverity::from(score),
                    None,
                    None,
                );
            }
        }
    }

    (None, None, ThreatSeverity::Info, None, None)
}

/// Extract affected products from NVD configurations
fn extract_affected_products(configurations: &Option<Vec<NvdConfiguration>>) -> Vec<AffectedProduct> {
    let mut products = Vec::new();

    if let Some(configs) = configurations {
        for config in configs {
            for node in &config.nodes {
                if let Some(cpe_matches) = &node.cpe_match {
                    for cpe_match in cpe_matches {
                        if cpe_match.vulnerable {
                            if let Some(product) = parse_cpe(&cpe_match.criteria) {
                                products.push(product);
                            }
                        }
                    }
                }
            }
        }
    }

    products
}

/// Parse CPE string to extract vendor/product/version
fn parse_cpe(cpe: &str) -> Option<AffectedProduct> {
    // CPE format: cpe:2.3:a:vendor:product:version:...
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() >= 5 {
        Some(AffectedProduct {
            vendor: parts[3].to_string(),
            product: parts[4].to_string(),
            version: parts.get(5).filter(|v| **v != "*" && !v.is_empty()).map(|v| v.to_string()),
            cpe: Some(cpe.to_string()),
        })
    } else {
        None
    }
}

/// Convert CISA KEV response entry
fn convert_kev_entry(kev: CisaKevVulnerability) -> CisaKevEntry {
    let ransomware_use = kev
        .known_ransomware_campaign_use
        .map(|s| s.to_lowercase() == "known")
        .unwrap_or(false);

    CisaKevEntry {
        cve_id: kev.cve_id,
        vendor_project: kev.vendor_project,
        product: kev.product,
        vulnerability_name: kev.vulnerability_name,
        date_added: kev.date_added,
        short_description: kev.short_description,
        required_action: kev.required_action,
        due_date: kev.due_date,
        known_ransomware_campaign_use: ransomware_use,
        notes: kev.notes,
    }
}

/// Offline list of high-priority KEV CVEs for quick lookup
fn is_in_offline_kev(cve_id: &str) -> bool {
    const PRIORITY_KEV_CVES: &[&str] = &[
        "CVE-2021-44228", // Log4Shell
        "CVE-2021-41773", // Apache Path Traversal
        "CVE-2021-34473", // ProxyShell
        "CVE-2017-0144",  // EternalBlue
        "CVE-2019-0708",  // BlueKeep
        "CVE-2022-22965", // Spring4Shell
        "CVE-2021-26855", // ProxyLogon
        "CVE-2020-1472",  // Zerologon
        "CVE-2023-23397", // Outlook Elevation
        "CVE-2023-0669",  // GoAnywhere MFT
        "CVE-2022-41040", // ProxyNotShell
        "CVE-2022-41082", // ProxyNotShell
        "CVE-2023-27350", // PaperCut
        "CVE-2023-44487", // HTTP/2 Rapid Reset
        "CVE-2023-4966",  // Citrix Bleed
        "CVE-2024-1709",  // ScreenConnect
        "CVE-2024-21887", // Ivanti VPN
        "CVE-2024-0012",  // Palo Alto PAN-OS
        "CVE-2024-9474",  // Palo Alto PAN-OS
    ];

    PRIORITY_KEV_CVES.contains(&cve_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpe() {
        let cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*";
        let product = parse_cpe(cpe).unwrap();
        assert_eq!(product.vendor, "apache");
        assert_eq!(product.product, "http_server");
        assert_eq!(product.version, Some("2.4.49".to_string()));
    }

    #[test]
    fn test_is_in_offline_kev() {
        assert!(is_in_offline_kev("CVE-2021-44228"));
        assert!(is_in_offline_kev("CVE-2017-0144"));
        assert!(!is_in_offline_kev("CVE-2000-0000"));
    }

    #[test]
    fn test_threat_severity_from_cvss() {
        assert_eq!(ThreatSeverity::from(9.8), ThreatSeverity::Critical);
        assert_eq!(ThreatSeverity::from(7.5), ThreatSeverity::High);
        assert_eq!(ThreatSeverity::from(5.0), ThreatSeverity::Medium);
    }
}
