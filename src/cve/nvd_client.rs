#![allow(dead_code)]

use crate::types::{Severity, Vulnerability};
use anyhow::Result;
use log::{debug, info, warn};
use serde::Deserialize;
use std::time::Duration;

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const REQUEST_TIMEOUT_SECS: u64 = 15;

/// NVD API response structures
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdResponse {
    pub results_per_page: Option<i32>,
    pub start_index: Option<i32>,
    pub total_results: Option<i32>,
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCve {
    pub id: String,
    pub descriptions: Vec<NvdDescription>,
    pub metrics: Option<NvdMetrics>,
    pub published: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NvdDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdMetrics {
    pub cvss_metric_v31: Option<Vec<NvdCvssV31>>,
    pub cvss_metric_v30: Option<Vec<NvdCvssV30>>,
    pub cvss_metric_v2: Option<Vec<NvdCvssV2>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV31 {
    pub cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV30 {
    pub cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NvdCvssV2 {
    pub cvss_data: CvssDataV2,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssData {
    pub base_score: f32,
    pub base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssDataV2 {
    pub base_score: f32,
}

/// Query the NVD API for CVEs related to a product
pub async fn query_nvd_api(
    product: &str,
    version: Option<&str>,
    api_key: Option<&str>,
) -> Result<Vec<Vulnerability>> {
    let client = build_client()?;

    // Build search query
    let keyword = if let Some(ver) = version {
        format!("{} {}", product, ver)
    } else {
        product.to_string()
    };

    let url = format!("{}?keywordSearch={}", NVD_API_BASE, urlencoding::encode(&keyword));

    info!("Querying NVD API for: {}", keyword);
    debug!("NVD API URL: {}", url);

    let mut request = client.get(&url);

    // Add API key header if provided (increases rate limit)
    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        warn!("NVD API error: {} - {}", status, body);
        anyhow::bail!("NVD API returned status {}", status);
    }

    let nvd_response: NvdResponse = response.json().await?;

    info!(
        "NVD API returned {} results for {}",
        nvd_response.vulnerabilities.len(),
        product
    );

    // Convert to our Vulnerability format
    let vulns = nvd_response
        .vulnerabilities
        .into_iter()
        .filter_map(|v| convert_nvd_cve(v, product))
        .collect();

    Ok(vulns)
}

/// Query NVD for a specific CVE ID
pub async fn query_cve_by_id(cve_id: &str, api_key: Option<&str>) -> Result<Option<Vulnerability>> {
    let client = build_client()?;
    let url = format!("{}?cveId={}", NVD_API_BASE, cve_id);

    debug!("Querying NVD for CVE: {}", cve_id);

    let mut request = client.get(&url);
    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let nvd_response: NvdResponse = response.json().await?;

    Ok(nvd_response
        .vulnerabilities
        .into_iter()
        .next()
        .and_then(|v| convert_nvd_cve(v, "unknown")))
}

fn build_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent("HeroForge/0.1.0 (Security Scanner)")
        .build()?)
}

fn convert_nvd_cve(nvd_vuln: NvdVulnerability, product: &str) -> Option<Vulnerability> {
    let cve = nvd_vuln.cve;

    // Get English description
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_else(|| "No description available.".to_string());

    // Get CVSS score and severity
    let (_cvss_score, severity) = extract_cvss(&cve.metrics);

    // Create title from CVE ID and first line of description
    let title = format!(
        "{}: {}",
        cve.id,
        description
            .lines()
            .next()
            .unwrap_or("Unknown vulnerability")
            .chars()
            .take(80)
            .collect::<String>()
    );

    Some(Vulnerability {
        cve_id: Some(cve.id),
        title,
        severity,
        description,
        affected_service: Some(product.to_string()),
    })
}

fn extract_cvss(metrics: &Option<NvdMetrics>) -> (f32, Severity) {
    if let Some(m) = metrics {
        // Try CVSS v3.1 first
        if let Some(cvss31) = &m.cvss_metric_v31 {
            if let Some(first) = cvss31.first() {
                let score = first.cvss_data.base_score;
                return (score, cvss_to_severity(score));
            }
        }

        // Try CVSS v3.0
        if let Some(cvss30) = &m.cvss_metric_v30 {
            if let Some(first) = cvss30.first() {
                let score = first.cvss_data.base_score;
                return (score, cvss_to_severity(score));
            }
        }

        // Fall back to CVSS v2
        if let Some(cvss2) = &m.cvss_metric_v2 {
            if let Some(first) = cvss2.first() {
                let score = first.cvss_data.base_score;
                return (score, cvss_to_severity(score));
            }
        }
    }

    (0.0, Severity::Low)
}

fn cvss_to_severity(score: f32) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_to_severity() {
        assert_eq!(cvss_to_severity(9.8), Severity::Critical);
        assert_eq!(cvss_to_severity(9.0), Severity::Critical);
        assert_eq!(cvss_to_severity(8.5), Severity::High);
        assert_eq!(cvss_to_severity(7.0), Severity::High);
        assert_eq!(cvss_to_severity(5.5), Severity::Medium);
        assert_eq!(cvss_to_severity(4.0), Severity::Medium);
        assert_eq!(cvss_to_severity(2.0), Severity::Low);
    }
}
