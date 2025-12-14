use crate::types::{Severity, Vulnerability};
use anyhow::Result;
use chrono::{Duration, Utc};
use log::debug;
use sqlx::SqlitePool;

/// Get cached CVEs for a product/version combination
pub async fn get_cached_cves(
    pool: &SqlitePool,
    product: &str,
    version: Option<&str>,
) -> Result<Vec<Vulnerability>> {
    let now = Utc::now().to_rfc3339();

    let rows: Vec<(String, String, String, String, Option<f64>)> = if let Some(ver) = version {
        sqlx::query_as(
            r#"
            SELECT cve_id, title, description, severity, cvss_score
            FROM cve_cache
            WHERE product = ?1
            AND (version_pattern IS NULL OR version_pattern = ?2 OR version_pattern = '')
            AND expires_at > ?3
            "#,
        )
        .bind(product)
        .bind(ver)
        .bind(&now)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT cve_id, title, description, severity, cvss_score
            FROM cve_cache
            WHERE product = ?1
            AND expires_at > ?2
            "#,
        )
        .bind(product)
        .bind(&now)
        .fetch_all(pool)
        .await?
    };

    debug!("Found {} cached CVEs for product={}", rows.len(), product);

    let vulns = rows
        .into_iter()
        .map(|(cve_id, title, description, severity, _cvss)| Vulnerability {
            cve_id: Some(cve_id),
            title,
            severity: parse_severity(&severity),
            description,
            affected_service: Some(product.to_string()),
        })
        .collect();

    Ok(vulns)
}

/// Cache a CVE entry from API response
pub async fn cache_cve(
    pool: &SqlitePool,
    product: &str,
    version: Option<&str>,
    vuln: &Vulnerability,
    ttl_days: i64,
) -> Result<()> {
    let now = Utc::now();
    let expires_at = now + Duration::days(ttl_days);

    let cve_id = vuln.cve_id.as_deref().unwrap_or("UNKNOWN");
    let severity_str = format!("{:?}", vuln.severity);

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO cve_cache
        (cve_id, product, version_pattern, severity, cvss_score, title, description, last_updated, expires_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(cve_id)
    .bind(product)
    .bind(version.unwrap_or(""))
    .bind(&severity_str)
    .bind(severity_to_cvss(&vuln.severity))
    .bind(&vuln.title)
    .bind(&vuln.description)
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Cached CVE {} for product={}", cve_id, product);
    Ok(())
}

/// Remove expired CVE cache entries
pub async fn cleanup_expired_cves(pool: &SqlitePool) -> Result<u64> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query("DELETE FROM cve_cache WHERE expires_at < ?1")
        .bind(&now)
        .execute(pool)
        .await?;

    let deleted = result.rows_affected();
    if deleted > 0 {
        debug!("Cleaned up {} expired CVE cache entries", deleted);
    }

    Ok(deleted)
}

/// Get cache statistics
pub async fn get_cache_stats(pool: &SqlitePool) -> Result<CacheStats> {
    let now = Utc::now().to_rfc3339();

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM cve_cache")
        .fetch_one(pool)
        .await?;

    let active: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM cve_cache WHERE expires_at > ?1")
        .bind(&now)
        .fetch_one(pool)
        .await?;

    let expired: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM cve_cache WHERE expires_at <= ?1")
        .bind(&now)
        .fetch_one(pool)
        .await?;

    let products: (i64,) =
        sqlx::query_as("SELECT COUNT(DISTINCT product) FROM cve_cache WHERE expires_at > ?1")
            .bind(&now)
            .fetch_one(pool)
            .await?;

    Ok(CacheStats {
        total_entries: total.0 as u64,
        active_entries: active.0 as u64,
        expired_entries: expired.0 as u64,
        unique_products: products.0 as u64,
    })
}

/// Invalidate cache for a specific product
pub async fn invalidate_product_cache(pool: &SqlitePool, product: &str) -> Result<u64> {
    let result = sqlx::query("DELETE FROM cve_cache WHERE product = ?1")
        .bind(product)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Invalidate entire cache
pub async fn invalidate_all_cache(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM cve_cache").execute(pool).await?;
    Ok(result.rows_affected())
}

#[derive(Debug)]
pub struct CacheStats {
    pub total_entries: u64,
    pub active_entries: u64,
    pub expired_entries: u64,
    pub unique_products: u64,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn severity_to_cvss(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.0,
        Severity::High => 7.0,
        Severity::Medium => 4.0,
        Severity::Low => 2.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("Critical"), Severity::Critical);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("medium"), Severity::Medium);
        assert_eq!(parse_severity("low"), Severity::Low);
        assert_eq!(parse_severity("unknown"), Severity::Low);
    }
}
