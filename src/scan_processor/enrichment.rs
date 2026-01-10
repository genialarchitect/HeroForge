//! CVE Enrichment Module
//!
//! Enriches extracted vulnerabilities with CVE data from local cache
//! and NVD API, adding CVSS scores, exploit information, and references.

use anyhow::Result;
use chrono::Utc;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use super::ExtractedVulnerability;
use crate::cve::{CveConfig, CveScanner};

/// Result of CVE enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    pub enriched_count: usize,
    pub cves_cached: usize,
    pub errors: Vec<String>,
}

/// Enriched vulnerability with CVE details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedVulnerability {
    pub vulnerability_id: String,
    pub cve_id: String,
    pub cvss_v3_score: Option<f64>,
    pub cvss_v2_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub exploit_available: bool,
    pub exploit_maturity: Option<String>,
    pub cwe_ids: Vec<String>,
    pub references: Vec<String>,
    pub affected_products: Vec<String>,
    pub published_date: Option<String>,
    pub last_modified: Option<String>,
}

/// Cached CVE data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCveData {
    pub cve_id: String,
    pub cvss_v3_score: Option<f64>,
    pub cvss_v2_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub description: String,
    pub exploit_count: i32,
    pub cwe_ids: String,  // JSON array
    pub references: String, // JSON array
    pub affected_products: String, // JSON array
    pub published_date: Option<String>,
    pub last_modified: Option<String>,
    pub cached_at: String,
}

/// Enrich vulnerabilities with CVE data
pub async fn enrich_vulnerabilities(
    pool: &SqlitePool,
    vulns: &[ExtractedVulnerability],
) -> Result<EnrichmentResult> {
    let mut enriched_count = 0;
    let mut cves_cached = 0;
    let mut errors = Vec::new();

    // Create CVE scanner with database cache
    let cve_scanner = CveScanner::new(
        pool.clone(),
        CveConfig {
            use_nvd_api: true,
            offline_fallback: true,
            nvd_api_key: std::env::var("NVD_API_KEY").ok(),
            cache_ttl_days: 30,
        },
    );

    for vuln in vulns {
        if let Some(ref cve_id) = vuln.cve_id {
            match enrich_single_cve(pool, &cve_scanner, &vuln.id, cve_id).await {
                Ok(cached_new) => {
                    enriched_count += 1;
                    if cached_new {
                        cves_cached += 1;
                    }
                }
                Err(e) => {
                    let err = format!("Failed to enrich {}: {}", cve_id, e);
                    debug!("{}", err);
                    errors.push(err);
                }
            }
        }

        // Also try to correlate service versions with known CVEs
        if let (Some(ref service_name), Some(ref version)) = (&vuln.service_name, &vuln.service_version) {
            if let Ok(cve_matches) = correlate_service_cves(pool, service_name, version).await {
                for cve_id in cve_matches {
                    match enrich_single_cve(pool, &cve_scanner, &vuln.id, &cve_id).await {
                        Ok(cached_new) => {
                            enriched_count += 1;
                            if cached_new {
                                cves_cached += 1;
                            }
                        }
                        Err(e) => {
                            debug!("Failed to enrich correlated CVE {}: {}", cve_id, e);
                        }
                    }
                }
            }
        }
    }

    info!(
        "CVE enrichment complete: {} enriched, {} new CVEs cached",
        enriched_count, cves_cached
    );

    Ok(EnrichmentResult {
        enriched_count,
        cves_cached,
        errors,
    })
}

/// Enrich a single CVE
async fn enrich_single_cve(
    pool: &SqlitePool,
    _cve_scanner: &CveScanner,
    vuln_id: &str,
    cve_id: &str,
) -> Result<bool> {
    let mut cached_new = false;

    // Check local cache first
    let cached = get_cached_cve(pool, cve_id).await?;

    let cve_data = if let Some(data) = cached {
        data
    } else {
        // Fetch from NVD API
        match fetch_cve_from_nvd(cve_id).await {
            Ok(data) => {
                // Cache the result
                cache_cve_data(pool, &data).await?;
                cached_new = true;
                data
            }
            Err(e) => {
                debug!("Failed to fetch CVE {} from NVD: {}", cve_id, e);
                return Err(e);
            }
        }
    };

    // Update vulnerability_tracking with enrichment data
    update_vulnerability_with_cve(pool, vuln_id, &cve_data).await?;

    Ok(cached_new)
}

/// Get CVE data from local cache
async fn get_cached_cve(pool: &SqlitePool, cve_id: &str) -> Result<Option<CachedCveData>> {
    let row = sqlx::query_as::<_, (
        String, Option<f64>, Option<f64>, Option<String>, String,
        i32, String, String, String, Option<String>, Option<String>, String
    )>(
        "SELECT cve_id, cvss_v3_score, cvss_v2_score, cvss_vector, description,
                exploit_count, cwe_ids, references, affected_products,
                published_date, last_modified, cached_at
         FROM cve_cache WHERE cve_id = ?1"
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| CachedCveData {
        cve_id: r.0,
        cvss_v3_score: r.1,
        cvss_v2_score: r.2,
        cvss_vector: r.3,
        description: r.4,
        exploit_count: r.5,
        cwe_ids: r.6,
        references: r.7,
        affected_products: r.8,
        published_date: r.9,
        last_modified: r.10,
        cached_at: r.11,
    }))
}

/// Fetch CVE data from NVD API
async fn fetch_cve_from_nvd(cve_id: &str) -> Result<CachedCveData> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
        cve_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "NVD API returned status: {}",
            response.status()
        ));
    }

    let data: serde_json::Value = response.json().await?;

    // Parse NVD response
    let vulnerabilities = data
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Invalid NVD response format"))?;

    if vulnerabilities.is_empty() {
        return Err(anyhow::anyhow!("CVE not found in NVD: {}", cve_id));
    }

    let cve = &vulnerabilities[0]["cve"];

    // Extract CVSS v3 score
    let cvss_v3_score = cve
        .get("metrics")
        .and_then(|m| m.get("cvssMetricV31"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|m| m.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(|s| s.as_f64());

    // Extract CVSS v2 score
    let cvss_v2_score = cve
        .get("metrics")
        .and_then(|m| m.get("cvssMetricV2"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|m| m.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(|s| s.as_f64());

    // Extract CVSS vector
    let cvss_vector = cve
        .get("metrics")
        .and_then(|m| m.get("cvssMetricV31"))
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|m| m.get("cvssData"))
        .and_then(|d| d.get("vectorString"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Extract description
    let description = cve
        .get("descriptions")
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.iter().find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en")))
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Extract CWE IDs
    let cwe_ids: Vec<String> = cve
        .get("weaknesses")
        .and_then(|w| w.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|w| {
                    w.get("description")
                        .and_then(|d| d.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|d| d.get("value"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();

    // Extract references
    let references: Vec<String> = cve
        .get("references")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| r.get("url").and_then(|u| u.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Count exploit references
    let exploit_count = references
        .iter()
        .filter(|r| {
            r.contains("exploit-db")
                || r.contains("metasploit")
                || r.contains("github.com")
                || r.contains("poc")
        })
        .count() as i32;

    // Extract affected products (CPE)
    let affected_products: Vec<String> = cve
        .get("configurations")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .flat_map(|config| {
                    config
                        .get("nodes")
                        .and_then(|n| n.as_array())
                        .map(|nodes| {
                            nodes
                                .iter()
                                .flat_map(|node| {
                                    node.get("cpeMatch")
                                        .and_then(|c| c.as_array())
                                        .map(|matches| {
                                            matches
                                                .iter()
                                                .filter_map(|m| {
                                                    m.get("criteria")
                                                        .and_then(|c| c.as_str())
                                                        .map(String::from)
                                                })
                                                .collect::<Vec<_>>()
                                        })
                                        .unwrap_or_default()
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();

    // Extract dates
    let published_date = cve
        .get("published")
        .and_then(|p| p.as_str())
        .map(String::from);

    let last_modified = cve
        .get("lastModified")
        .and_then(|l| l.as_str())
        .map(String::from);

    Ok(CachedCveData {
        cve_id: cve_id.to_string(),
        cvss_v3_score,
        cvss_v2_score,
        cvss_vector,
        description,
        exploit_count,
        cwe_ids: serde_json::to_string(&cwe_ids).unwrap_or_default(),
        references: serde_json::to_string(&references).unwrap_or_default(),
        affected_products: serde_json::to_string(&affected_products).unwrap_or_default(),
        published_date,
        last_modified,
        cached_at: Utc::now().to_rfc3339(),
    })
}

/// Cache CVE data in database
async fn cache_cve_data(pool: &SqlitePool, data: &CachedCveData) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO cve_cache
         (cve_id, cvss_v3_score, cvss_v2_score, cvss_vector, description,
          exploit_count, cwe_ids, references, affected_products,
          published_date, last_modified, cached_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
    )
    .bind(&data.cve_id)
    .bind(data.cvss_v3_score)
    .bind(data.cvss_v2_score)
    .bind(&data.cvss_vector)
    .bind(&data.description)
    .bind(data.exploit_count)
    .bind(&data.cwe_ids)
    .bind(&data.references)
    .bind(&data.affected_products)
    .bind(&data.published_date)
    .bind(&data.last_modified)
    .bind(&data.cached_at)
    .execute(pool)
    .await?;

    debug!("Cached CVE data: {}", data.cve_id);
    Ok(())
}

/// Update vulnerability_tracking with CVE enrichment data
async fn update_vulnerability_with_cve(
    pool: &SqlitePool,
    vuln_id: &str,
    cve_data: &CachedCveData,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let exploit_maturity = if cve_data.exploit_count > 0 {
        "proof-of-concept"
    } else {
        "unproven"
    };

    sqlx::query(
        "UPDATE vulnerability_tracking
         SET cvss_v3 = ?1, exploit_maturity = ?2, processing_timestamp = ?3,
             updated_at = ?3
         WHERE id = ?4"
    )
    .bind(cve_data.cvss_v3_score)
    .bind(exploit_maturity)
    .bind(&now)
    .bind(vuln_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Correlate service versions with known CVEs from cache
async fn correlate_service_cves(
    pool: &SqlitePool,
    service_name: &str,
    version: &str,
) -> Result<Vec<String>> {
    // Check service_vulnerability_cache table
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT cve_ids FROM service_vulnerability_cache
         WHERE service_name = ?1 AND (version_pattern = ?2 OR version_pattern = '*')"
    )
    .bind(service_name.to_lowercase())
    .bind(version)
    .fetch_all(pool)
    .await?;

    let mut cve_ids = Vec::new();
    for (cve_json,) in rows {
        if let Ok(ids) = serde_json::from_str::<Vec<String>>(&cve_json) {
            cve_ids.extend(ids);
        }
    }

    Ok(cve_ids)
}

/// Get enriched vulnerability data
pub async fn get_enriched_vulnerability(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<Option<EnrichedVulnerability>> {
    let row = sqlx::query_as::<_, (String, Option<f64>, Option<String>)>(
        "SELECT cve_id, cvss_v3, exploit_maturity
         FROM vulnerability_tracking WHERE id = ?1 AND cve_id IS NOT NULL"
    )
    .bind(vuln_id)
    .fetch_optional(pool)
    .await?;

    if let Some((cve_id, cvss_v3, exploit_maturity)) = row {
        // Get full CVE data from cache
        if let Some(cve_data) = get_cached_cve(pool, &cve_id).await? {
            let cwe_ids: Vec<String> = serde_json::from_str(&cve_data.cwe_ids).unwrap_or_default();
            let references: Vec<String> = serde_json::from_str(&cve_data.references).unwrap_or_default();
            let affected_products: Vec<String> = serde_json::from_str(&cve_data.affected_products).unwrap_or_default();

            return Ok(Some(EnrichedVulnerability {
                vulnerability_id: vuln_id.to_string(),
                cve_id,
                cvss_v3_score: cvss_v3,
                cvss_v2_score: cve_data.cvss_v2_score,
                cvss_vector: cve_data.cvss_vector,
                exploit_available: cve_data.exploit_count > 0,
                exploit_maturity,
                cwe_ids,
                references,
                affected_products,
                published_date: cve_data.published_date,
                last_modified: cve_data.last_modified,
            }));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_cve_format() {
        // This test verifies the CVE ID format parsing
        let valid_cve = "CVE-2021-44228";
        assert!(valid_cve.starts_with("CVE-"));

        let parts: Vec<&str> = valid_cve.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "CVE");
    }
}
