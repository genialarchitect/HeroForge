//! EPSS (Exploit Prediction Scoring System) Client
//!
//! This module provides integration with the FIRST EPSS API for retrieving
//! exploit probability scores for CVEs.
//!
//! EPSS provides a daily estimate of the probability (0-1) that a vulnerability
//! will be exploited in the wild in the next 30 days.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

const EPSS_API_BASE: &str = "https://api.first.org/data/v1/epss";
const CACHE_TTL_DAYS: i64 = 30;

/// EPSS score data for a CVE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScore {
    /// CVE identifier
    pub cve: String,
    /// Probability score (0.0 - 1.0)
    pub epss: f64,
    /// Percentile (0.0 - 1.0)
    pub percentile: f64,
    /// Date of the score
    pub date: String,
}

/// Response from EPSS API
#[derive(Debug, Deserialize)]
struct EpssApiResponse {
    status: String,
    #[serde(rename = "status-code")]
    status_code: u32,
    version: String,
    total: u32,
    offset: u32,
    limit: u32,
    data: Vec<EpssDataItem>,
}

#[derive(Debug, Deserialize)]
struct EpssDataItem {
    cve: String,
    epss: String,
    percentile: String,
    date: String,
}

/// EPSS Client for fetching exploit probability scores
pub struct EpssClient {
    client: reqwest::Client,
    pool: Option<Arc<SqlitePool>>,
}

impl EpssClient {
    /// Create a new EPSS client
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
            pool: None,
        }
    }

    /// Create a new EPSS client with database caching
    pub fn with_database(pool: Arc<SqlitePool>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
            pool: Some(pool),
        }
    }

    /// Get EPSS score for a single CVE
    pub async fn get_score(&self, cve_id: &str) -> Result<Option<EpssScore>> {
        // Check cache first
        if let Some(ref pool) = self.pool {
            if let Ok(Some(cached)) = self.get_cached_score(pool, cve_id).await {
                debug!("Using cached EPSS score for {}", cve_id);
                return Ok(Some(cached));
            }
        }

        // Fetch from API
        let scores = self.fetch_scores(&[cve_id.to_string()]).await?;
        let score = scores.into_iter().next();

        // Cache the result
        if let (Some(ref pool), Some(ref s)) = (&self.pool, &score) {
            if let Err(e) = self.cache_score(pool, s).await {
                warn!("Failed to cache EPSS score: {}", e);
            }
        }

        Ok(score)
    }

    /// Get EPSS scores for multiple CVEs
    pub async fn get_scores(&self, cve_ids: &[String]) -> Result<Vec<EpssScore>> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut missing = Vec::new();

        // Check cache first
        if let Some(ref pool) = self.pool {
            for cve_id in cve_ids {
                match self.get_cached_score(pool, cve_id).await {
                    Ok(Some(cached)) => {
                        debug!("Using cached EPSS score for {}", cve_id);
                        results.push(cached);
                    }
                    _ => missing.push(cve_id.clone()),
                }
            }
        } else {
            missing = cve_ids.to_vec();
        }

        // Fetch missing from API
        if !missing.is_empty() {
            info!("Fetching EPSS scores for {} CVEs", missing.len());
            let fetched = self.fetch_scores(&missing).await?;

            // Cache fetched results
            if let Some(ref pool) = self.pool {
                for score in &fetched {
                    if let Err(e) = self.cache_score(pool, score).await {
                        warn!("Failed to cache EPSS score for {}: {}", score.cve, e);
                    }
                }
            }

            results.extend(fetched);
        }

        Ok(results)
    }

    /// Fetch EPSS scores from the API
    async fn fetch_scores(&self, cve_ids: &[String]) -> Result<Vec<EpssScore>> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        // EPSS API accepts comma-separated CVE IDs
        let cve_list = cve_ids.join(",");
        let url = format!("{}?cve={}", EPSS_API_BASE, cve_list);

        debug!("Fetching EPSS scores from: {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send EPSS API request")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("EPSS API returned error {}: {}", status, text);
        }

        let api_response: EpssApiResponse = response
            .json()
            .await
            .context("Failed to parse EPSS API response")?;

        let scores: Vec<EpssScore> = api_response
            .data
            .into_iter()
            .filter_map(|item| {
                let epss = item.epss.parse::<f64>().ok()?;
                let percentile = item.percentile.parse::<f64>().ok()?;
                Some(EpssScore {
                    cve: item.cve,
                    epss,
                    percentile,
                    date: item.date,
                })
            })
            .collect();

        Ok(scores)
    }

    /// Get cached EPSS score from database
    async fn get_cached_score(&self, pool: &SqlitePool, cve_id: &str) -> Result<Option<EpssScore>> {
        let cutoff = Utc::now() - Duration::days(CACHE_TTL_DAYS);

        let row = sqlx::query_as::<_, (String, f64, f64, String, String)>(
            r#"
            SELECT cve_id, epss_score, epss_percentile, score_date, cached_at
            FROM epss_cache
            WHERE cve_id = ? AND cached_at > ?
            "#,
        )
        .bind(cve_id)
        .bind(cutoff.to_rfc3339())
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|(cve, epss, percentile, date, _)| EpssScore {
            cve,
            epss,
            percentile,
            date,
        }))
    }

    /// Cache an EPSS score in the database
    async fn cache_score(&self, pool: &SqlitePool, score: &EpssScore) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO epss_cache (cve_id, epss_score, epss_percentile, score_date, cached_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                epss_score = excluded.epss_score,
                epss_percentile = excluded.epss_percentile,
                score_date = excluded.score_date,
                cached_at = excluded.cached_at
            "#,
        )
        .bind(&score.cve)
        .bind(score.epss)
        .bind(score.percentile)
        .bind(&score.date)
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await?;

        Ok(())
    }
}

impl Default for EpssClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize the EPSS cache table
pub async fn init_epss_cache_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS epss_cache (
            cve_id TEXT PRIMARY KEY,
            epss_score REAL NOT NULL,
            epss_percentile REAL NOT NULL,
            score_date TEXT NOT NULL,
            cached_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for cache expiry queries
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_epss_cache_cached_at ON epss_cache(cached_at)
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Clean up expired cache entries
pub async fn cleanup_expired_cache(pool: &SqlitePool) -> Result<u64> {
    let cutoff = Utc::now() - Duration::days(CACHE_TTL_DAYS);

    let result = sqlx::query("DELETE FROM epss_cache WHERE cached_at < ?")
        .bind(cutoff.to_rfc3339())
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epss_score_serialization() {
        let score = EpssScore {
            cve: "CVE-2024-1234".to_string(),
            epss: 0.5,
            percentile: 0.9,
            date: "2024-01-01".to_string(),
        };

        let json = serde_json::to_string(&score).unwrap();
        assert!(json.contains("CVE-2024-1234"));
        assert!(json.contains("0.5"));
        assert!(json.contains("0.9"));
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = EpssClient::new();
        // Just verify the client was created successfully
        assert!(client.pool.is_none());
    }
}
