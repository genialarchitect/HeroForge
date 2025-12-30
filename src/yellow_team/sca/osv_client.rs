//! OSV (Open Source Vulnerabilities) Client
//!
//! Queries the OSV.dev API for vulnerability data about packages.
//! OSV is a distributed vulnerability database for open source.

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const OSV_API_URL: &str = "https://api.osv.dev/v1";
const REQUEST_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// OSV API Types
// ============================================================================

/// OSV vulnerability response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

/// OSV severity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

/// OSV affected package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    pub package: OsvPackage,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

/// OSV package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub purl: Option<String>,
}

/// OSV version range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

/// OSV range event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

/// OSV reference link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

/// Query request for OSV API
#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvQueryPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

/// Package info for query
#[derive(Debug, Serialize)]
struct OsvQueryPackage {
    name: String,
    ecosystem: String,
}

/// Query response from OSV API
#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

/// Batch query request for OSV API
#[derive(Debug, Serialize)]
struct OsvBatchQueryRequest {
    queries: Vec<OsvQueryRequest>,
}

/// Batch query response from OSV API
#[derive(Debug, Deserialize)]
struct OsvBatchQueryResponse {
    results: Vec<OsvBatchResult>,
}

/// Single batch query result
#[derive(Debug, Deserialize)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

// ============================================================================
// OSV Client
// ============================================================================

/// Client for querying the OSV API
pub struct OsvClient {
    client: Client,
    api_url: String,
}

impl OsvClient {
    /// Create a new OSV client
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("HeroForge-SCA/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_url: OSV_API_URL.to_string(),
        }
    }

    /// Create a new OSV client with custom API URL (for testing)
    pub fn with_url(api_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("HeroForge-SCA/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_url: api_url.to_string(),
        }
    }

    /// Query vulnerabilities for a specific package version
    pub async fn query_package(
        &self,
        name: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<OsvVulnerability>> {
        let request = OsvQueryRequest {
            package: OsvQueryPackage {
                name: name.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: Some(version.to_string()),
        };

        let response = self.client
            .post(format!("{}/query", self.api_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to query OSV API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("OSV API error ({}): {}", status, body));
        }

        let osv_response: OsvQueryResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse OSV response: {}", e))?;

        Ok(osv_response.vulns)
    }

    /// Query vulnerabilities for a package (all versions)
    pub async fn query_package_all_versions(
        &self,
        name: &str,
        ecosystem: &str,
    ) -> Result<Vec<OsvVulnerability>> {
        let request = OsvQueryRequest {
            package: OsvQueryPackage {
                name: name.to_string(),
                ecosystem: ecosystem.to_string(),
            },
            version: None,
        };

        let response = self.client
            .post(format!("{}/query", self.api_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to query OSV API: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("OSV API error ({}): {}", status, body));
        }

        let osv_response: OsvQueryResponse = response.json().await
            .map_err(|e| anyhow!("Failed to parse OSV response: {}", e))?;

        Ok(osv_response.vulns)
    }

    /// Batch query for multiple packages
    pub async fn query_batch(
        &self,
        packages: &[(String, String, String)], // (name, version, ecosystem)
    ) -> Result<Vec<Vec<OsvVulnerability>>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }

        // OSV batch limit is 1000 queries
        const BATCH_SIZE: usize = 1000;
        let mut all_results = Vec::new();

        for chunk in packages.chunks(BATCH_SIZE) {
            let queries: Vec<OsvQueryRequest> = chunk
                .iter()
                .map(|(name, version, ecosystem)| OsvQueryRequest {
                    package: OsvQueryPackage {
                        name: name.clone(),
                        ecosystem: ecosystem.clone(),
                    },
                    version: Some(version.clone()),
                })
                .collect();

            let request = OsvBatchQueryRequest { queries };

            let response = self.client
                .post(format!("{}/querybatch", self.api_url))
                .json(&request)
                .send()
                .await
                .map_err(|e| anyhow!("Failed to batch query OSV API: {}", e))?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(anyhow!("OSV API batch error ({}): {}", status, body));
            }

            let osv_response: OsvBatchQueryResponse = response.json().await
                .map_err(|e| anyhow!("Failed to parse OSV batch response: {}", e))?;

            for result in osv_response.results {
                all_results.push(result.vulns);
            }
        }

        Ok(all_results)
    }

    /// Get a specific vulnerability by ID
    pub async fn get_vulnerability(&self, vuln_id: &str) -> Result<OsvVulnerability> {
        let response = self.client
            .get(format!("{}/vulns/{}", self.api_url, vuln_id))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to get vulnerability from OSV: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("OSV API error ({}): {}", status, body));
        }

        let vuln: OsvVulnerability = response.json().await
            .map_err(|e| anyhow!("Failed to parse vulnerability: {}", e))?;

        Ok(vuln)
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

impl OsvVulnerability {
    /// Get the CVE ID if available
    pub fn cve_id(&self) -> Option<&str> {
        // Check if the ID itself is a CVE
        if self.id.starts_with("CVE-") {
            return Some(&self.id);
        }

        // Check aliases
        for alias in &self.aliases {
            if alias.starts_with("CVE-") {
                return Some(alias);
            }
        }

        None
    }

    /// Get the GHSA ID if available
    pub fn ghsa_id(&self) -> Option<&str> {
        // Check if the ID itself is a GHSA
        if self.id.starts_with("GHSA-") {
            return Some(&self.id);
        }

        // Check aliases
        for alias in &self.aliases {
            if alias.starts_with("GHSA-") {
                return Some(alias);
            }
        }

        None
    }

    /// Extract CVSS score from severity
    pub fn cvss_score(&self) -> Option<f64> {
        for sev in &self.severity {
            if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
                // The score might be in the score field directly or need parsing
                if let Ok(score) = sev.score.parse::<f64>() {
                    return Some(score);
                }
                // Try to extract from CVSS vector string
                if let Some(score) = extract_cvss_base_score(&sev.score) {
                    return Some(score);
                }
            }
        }
        None
    }

    /// Get severity level from CVSS score
    pub fn severity_level(&self) -> &'static str {
        match self.cvss_score() {
            Some(score) if score >= 9.0 => "critical",
            Some(score) if score >= 7.0 => "high",
            Some(score) if score >= 4.0 => "medium",
            Some(score) if score > 0.0 => "low",
            _ => "unknown",
        }
    }

    /// Get the fixed version for a specific ecosystem/package
    pub fn fixed_version(&self, ecosystem: &str, package_name: &str) -> Option<String> {
        for affected in &self.affected {
            if affected.package.ecosystem.to_lowercase() == ecosystem.to_lowercase()
                && affected.package.name.to_lowercase() == package_name.to_lowercase()
            {
                for range in &affected.ranges {
                    for event in &range.events {
                        if let Some(fixed) = &event.fixed {
                            return Some(fixed.clone());
                        }
                    }
                }
            }
        }
        None
    }

    /// Get reference URLs
    pub fn reference_urls(&self) -> Vec<&str> {
        self.references.iter().map(|r| r.url.as_str()).collect()
    }
}

/// Extract base score from CVSS vector string
fn extract_cvss_base_score(vector: &str) -> Option<f64> {
    // CVSS v3 vectors look like: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    // CVSS v2 vectors look like: AV:N/AC:L/Au:N/C:P/I:P/A:P
    // Some responses might just have a score like "9.8"

    // Try direct parse first
    if let Ok(score) = vector.parse::<f64>() {
        return Some(score);
    }

    // Otherwise we'd need to calculate from the vector, which is complex
    // For now, return None and rely on other sources
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osv_vulnerability_cve_id() {
        let vuln = OsvVulnerability {
            id: "GHSA-xxxx-xxxx-xxxx".to_string(),
            aliases: vec!["CVE-2021-12345".to_string()],
            summary: None,
            details: None,
            severity: vec![],
            affected: vec![],
            references: vec![],
            published: None,
            modified: None,
            withdrawn: None,
            database_specific: None,
        };

        assert_eq!(vuln.cve_id(), Some("CVE-2021-12345"));
        assert_eq!(vuln.ghsa_id(), Some("GHSA-xxxx-xxxx-xxxx"));
    }

    #[test]
    fn test_cvss_severity_level() {
        let mut vuln = OsvVulnerability {
            id: "TEST-001".to_string(),
            aliases: vec![],
            summary: None,
            details: None,
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "9.8".to_string(),
            }],
            affected: vec![],
            references: vec![],
            published: None,
            modified: None,
            withdrawn: None,
            database_specific: None,
        };

        assert_eq!(vuln.severity_level(), "critical");

        vuln.severity[0].score = "7.5".to_string();
        assert_eq!(vuln.severity_level(), "high");

        vuln.severity[0].score = "5.0".to_string();
        assert_eq!(vuln.severity_level(), "medium");

        vuln.severity[0].score = "2.0".to_string();
        assert_eq!(vuln.severity_level(), "low");
    }
}
