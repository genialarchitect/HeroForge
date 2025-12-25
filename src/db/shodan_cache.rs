//! Database operations for Shodan API result caching
//!
//! This module provides caching functionality for Shodan API responses
//! with a configurable TTL (default 24 hours) to reduce API calls and costs.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use log::{debug, info};
use sqlx::SqlitePool;

use crate::integrations::shodan::{ShodanHost, ShodanSearchResult};

/// Default cache TTL in hours
pub const DEFAULT_CACHE_TTL_HOURS: i64 = 24;

/// Cache entry type for distinguishing between different cached data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    /// Host lookup result
    Host,
    /// Search result
    Search,
    /// DNS resolve result
    DnsResolve,
    /// DNS reverse result
    DnsReverse,
}

impl CacheType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CacheType::Host => "host",
            CacheType::Search => "search",
            CacheType::DnsResolve => "dns_resolve",
            CacheType::DnsReverse => "dns_reverse",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "host" => Some(CacheType::Host),
            "search" => Some(CacheType::Search),
            "dns_resolve" => Some(CacheType::DnsResolve),
            "dns_reverse" => Some(CacheType::DnsReverse),
            _ => None,
        }
    }
}

/// Initialize Shodan cache tables
pub async fn create_shodan_cache_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS shodan_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_or_query TEXT NOT NULL,
            result_type TEXT NOT NULL,
            data TEXT NOT NULL,
            cached_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            UNIQUE(ip_or_query, result_type)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes for efficient lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_shodan_cache_lookup ON shodan_cache(ip_or_query, result_type)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_shodan_cache_expires ON shodan_cache(expires_at)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Get cached host lookup result
///
/// Returns None if not found or expired
pub async fn get_cached_host(pool: &SqlitePool, ip: &str) -> Result<Option<ShodanHost>> {
    let row = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT data, expires_at
        FROM shodan_cache
        WHERE ip_or_query = ? AND result_type = ?
        AND expires_at > datetime('now')
        "#,
    )
    .bind(ip)
    .bind(CacheType::Host.as_str())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((data, _expires)) => {
            debug!("Cache hit for Shodan host: {}", ip);
            let host: ShodanHost = serde_json::from_str(&data)?;
            Ok(Some(host))
        }
        None => {
            debug!("Cache miss for Shodan host: {}", ip);
            Ok(None)
        }
    }
}

/// Cache a host lookup result
pub async fn cache_host(pool: &SqlitePool, ip: &str, data: &ShodanHost) -> Result<()> {
    cache_host_with_ttl(pool, ip, data, DEFAULT_CACHE_TTL_HOURS).await
}

/// Cache a host lookup result with custom TTL
pub async fn cache_host_with_ttl(
    pool: &SqlitePool,
    ip: &str,
    data: &ShodanHost,
    ttl_hours: i64,
) -> Result<()> {
    let now = Utc::now();
    let expires_at = now + Duration::hours(ttl_hours);
    let data_json = serde_json::to_string(data)?;

    sqlx::query(
        r#"
        INSERT INTO shodan_cache (ip_or_query, result_type, data, cached_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_or_query, result_type) DO UPDATE SET
            data = excluded.data,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at
        "#,
    )
    .bind(ip)
    .bind(CacheType::Host.as_str())
    .bind(&data_json)
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Cached Shodan host: {} (expires: {})", ip, expires_at);
    Ok(())
}

/// Get cached search result
///
/// The query is used as the cache key (normalized)
pub async fn get_cached_search(
    pool: &SqlitePool,
    query: &str,
    page: u32,
) -> Result<Option<ShodanSearchResult>> {
    let cache_key = format!("{}:page:{}", query.to_lowercase().trim(), page);

    let row = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT data, expires_at
        FROM shodan_cache
        WHERE ip_or_query = ? AND result_type = ?
        AND expires_at > datetime('now')
        "#,
    )
    .bind(&cache_key)
    .bind(CacheType::Search.as_str())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((data, _expires)) => {
            debug!("Cache hit for Shodan search: {}", cache_key);
            let result: ShodanSearchResult = serde_json::from_str(&data)?;
            Ok(Some(result))
        }
        None => {
            debug!("Cache miss for Shodan search: {}", cache_key);
            Ok(None)
        }
    }
}

/// Cache a search result
pub async fn cache_search(
    pool: &SqlitePool,
    query: &str,
    page: u32,
    data: &ShodanSearchResult,
) -> Result<()> {
    cache_search_with_ttl(pool, query, page, data, DEFAULT_CACHE_TTL_HOURS).await
}

/// Cache a search result with custom TTL
pub async fn cache_search_with_ttl(
    pool: &SqlitePool,
    query: &str,
    page: u32,
    data: &ShodanSearchResult,
    ttl_hours: i64,
) -> Result<()> {
    let cache_key = format!("{}:page:{}", query.to_lowercase().trim(), page);
    let now = Utc::now();
    let expires_at = now + Duration::hours(ttl_hours);
    let data_json = serde_json::to_string(data)?;

    sqlx::query(
        r#"
        INSERT INTO shodan_cache (ip_or_query, result_type, data, cached_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_or_query, result_type) DO UPDATE SET
            data = excluded.data,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at
        "#,
    )
    .bind(&cache_key)
    .bind(CacheType::Search.as_str())
    .bind(&data_json)
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Cached Shodan search: {} (expires: {})", cache_key, expires_at);
    Ok(())
}

/// Get cached DNS resolve result
pub async fn get_cached_dns_resolve(
    pool: &SqlitePool,
    hostname: &str,
) -> Result<Option<Vec<String>>> {
    let row = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT data, expires_at
        FROM shodan_cache
        WHERE ip_or_query = ? AND result_type = ?
        AND expires_at > datetime('now')
        "#,
    )
    .bind(hostname.to_lowercase())
    .bind(CacheType::DnsResolve.as_str())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((data, _expires)) => {
            debug!("Cache hit for DNS resolve: {}", hostname);
            let ips: Vec<String> = serde_json::from_str(&data)?;
            Ok(Some(ips))
        }
        None => {
            debug!("Cache miss for DNS resolve: {}", hostname);
            Ok(None)
        }
    }
}

/// Cache DNS resolve result
pub async fn cache_dns_resolve(
    pool: &SqlitePool,
    hostname: &str,
    ips: &[String],
) -> Result<()> {
    cache_dns_resolve_with_ttl(pool, hostname, ips, DEFAULT_CACHE_TTL_HOURS).await
}

/// Cache DNS resolve result with custom TTL
pub async fn cache_dns_resolve_with_ttl(
    pool: &SqlitePool,
    hostname: &str,
    ips: &[String],
    ttl_hours: i64,
) -> Result<()> {
    let now = Utc::now();
    let expires_at = now + Duration::hours(ttl_hours);
    let data_json = serde_json::to_string(ips)?;

    sqlx::query(
        r#"
        INSERT INTO shodan_cache (ip_or_query, result_type, data, cached_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_or_query, result_type) DO UPDATE SET
            data = excluded.data,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at
        "#,
    )
    .bind(hostname.to_lowercase())
    .bind(CacheType::DnsResolve.as_str())
    .bind(&data_json)
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Cached DNS resolve: {} (expires: {})", hostname, expires_at);
    Ok(())
}

/// Get cached DNS reverse result
pub async fn get_cached_dns_reverse(
    pool: &SqlitePool,
    ip: &str,
) -> Result<Option<Vec<String>>> {
    let row = sqlx::query_as::<_, (String, String)>(
        r#"
        SELECT data, expires_at
        FROM shodan_cache
        WHERE ip_or_query = ? AND result_type = ?
        AND expires_at > datetime('now')
        "#,
    )
    .bind(ip)
    .bind(CacheType::DnsReverse.as_str())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((data, _expires)) => {
            debug!("Cache hit for DNS reverse: {}", ip);
            let hostnames: Vec<String> = serde_json::from_str(&data)?;
            Ok(Some(hostnames))
        }
        None => {
            debug!("Cache miss for DNS reverse: {}", ip);
            Ok(None)
        }
    }
}

/// Cache DNS reverse result
pub async fn cache_dns_reverse(
    pool: &SqlitePool,
    ip: &str,
    hostnames: &[String],
) -> Result<()> {
    cache_dns_reverse_with_ttl(pool, ip, hostnames, DEFAULT_CACHE_TTL_HOURS).await
}

/// Cache DNS reverse result with custom TTL
pub async fn cache_dns_reverse_with_ttl(
    pool: &SqlitePool,
    ip: &str,
    hostnames: &[String],
    ttl_hours: i64,
) -> Result<()> {
    let now = Utc::now();
    let expires_at = now + Duration::hours(ttl_hours);
    let data_json = serde_json::to_string(hostnames)?;

    sqlx::query(
        r#"
        INSERT INTO shodan_cache (ip_or_query, result_type, data, cached_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_or_query, result_type) DO UPDATE SET
            data = excluded.data,
            cached_at = excluded.cached_at,
            expires_at = excluded.expires_at
        "#,
    )
    .bind(ip)
    .bind(CacheType::DnsReverse.as_str())
    .bind(&data_json)
    .bind(now.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .execute(pool)
    .await?;

    debug!("Cached DNS reverse: {} (expires: {})", ip, expires_at);
    Ok(())
}

/// Delete a cached entry
pub async fn invalidate_cache(
    pool: &SqlitePool,
    ip_or_query: &str,
    cache_type: CacheType,
) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM shodan_cache WHERE ip_or_query = ? AND result_type = ?",
    )
    .bind(ip_or_query)
    .bind(cache_type.as_str())
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete all cached entries for an IP
pub async fn invalidate_cache_for_ip(pool: &SqlitePool, ip: &str) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM shodan_cache WHERE ip_or_query = ?",
    )
    .bind(ip)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Clean up expired cache entries
pub async fn cleanup_expired_cache(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM shodan_cache WHERE expires_at < datetime('now')",
    )
    .execute(pool)
    .await?;

    let deleted = result.rows_affected();
    if deleted > 0 {
        info!("Cleaned up {} expired Shodan cache entries", deleted);
    }

    Ok(deleted)
}

/// Get cache statistics
#[derive(Debug, Clone)]
pub struct ShodanCacheStats {
    pub total_entries: i64,
    pub host_entries: i64,
    pub search_entries: i64,
    pub dns_resolve_entries: i64,
    pub dns_reverse_entries: i64,
    pub expired_entries: i64,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
}

pub async fn get_cache_stats(pool: &SqlitePool) -> Result<ShodanCacheStats> {
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM shodan_cache")
        .fetch_one(pool)
        .await?;

    let host: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shodan_cache WHERE result_type = ?",
    )
    .bind(CacheType::Host.as_str())
    .fetch_one(pool)
    .await?;

    let search: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shodan_cache WHERE result_type = ?",
    )
    .bind(CacheType::Search.as_str())
    .fetch_one(pool)
    .await?;

    let dns_resolve: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shodan_cache WHERE result_type = ?",
    )
    .bind(CacheType::DnsResolve.as_str())
    .fetch_one(pool)
    .await?;

    let dns_reverse: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shodan_cache WHERE result_type = ?",
    )
    .bind(CacheType::DnsReverse.as_str())
    .fetch_one(pool)
    .await?;

    let expired: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shodan_cache WHERE expires_at < datetime('now')",
    )
    .fetch_one(pool)
    .await?;

    let oldest: Option<(String,)> = sqlx::query_as(
        "SELECT MIN(cached_at) FROM shodan_cache",
    )
    .fetch_optional(pool)
    .await?;

    let newest: Option<(String,)> = sqlx::query_as(
        "SELECT MAX(cached_at) FROM shodan_cache",
    )
    .fetch_optional(pool)
    .await?;

    let oldest_entry = oldest.and_then(|(s,)| {
        DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    });

    let newest_entry = newest.and_then(|(s,)| {
        DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    });

    Ok(ShodanCacheStats {
        total_entries: total.0,
        host_entries: host.0,
        search_entries: search.0,
        dns_resolve_entries: dns_resolve.0,
        dns_reverse_entries: dns_reverse.0,
        expired_entries: expired.0,
        oldest_entry,
        newest_entry,
    })
}

// ============================================================================
// Shodan Query History
// ============================================================================

/// A single Shodan query record
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShodanQueryRecord {
    pub id: i64,
    pub user_id: String,
    pub query_type: String,
    pub query: String,
    pub result_count: Option<i64>,
    pub cached: bool,
    pub created_at: DateTime<Utc>,
}

/// Create the shodan_queries table for tracking user query history
pub async fn create_shodan_queries_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS shodan_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            query_type TEXT NOT NULL,
            query TEXT NOT NULL,
            result_count INTEGER,
            cached BOOLEAN NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index for efficient user-based lookups
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_shodan_queries_user ON shodan_queries(user_id, created_at DESC)",
    )
    .execute(pool)
    .await?;

    // Create index for query type filtering
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_shodan_queries_type ON shodan_queries(query_type)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Record a Shodan query to history
pub async fn record_shodan_query(
    pool: &SqlitePool,
    user_id: &str,
    query_type: &str,
    query: &str,
    result_count: Option<i64>,
    cached: bool,
) -> Result<i64> {
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        INSERT INTO shodan_queries (user_id, query_type, query, result_count, cached, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(user_id)
    .bind(query_type)
    .bind(query)
    .bind(result_count)
    .bind(cached)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

/// Get query history for a user
pub async fn get_user_shodan_queries(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<ShodanQueryRecord>> {
    let rows = sqlx::query_as::<_, (i64, String, String, String, Option<i64>, bool, String)>(
        r#"
        SELECT id, user_id, query_type, query, result_count, cached, created_at
        FROM shodan_queries
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    let records: Vec<ShodanQueryRecord> = rows
        .into_iter()
        .filter_map(|(id, user_id, query_type, query, result_count, cached, created_at)| {
            DateTime::parse_from_rfc3339(&created_at)
                .ok()
                .map(|dt| ShodanQueryRecord {
                    id,
                    user_id,
                    query_type,
                    query,
                    result_count,
                    cached,
                    created_at: dt.with_timezone(&Utc),
                })
        })
        .collect();

    Ok(records)
}

/// Get total count of queries for a user
pub async fn get_user_shodan_query_count(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM shodan_queries WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Delete old query history entries (older than specified days)
pub async fn cleanup_old_query_history(pool: &SqlitePool, days: i64) -> Result<u64> {
    let cutoff = Utc::now() - Duration::days(days);

    let result = sqlx::query(
        "DELETE FROM shodan_queries WHERE created_at < ?",
    )
    .bind(cutoff.to_rfc3339())
    .execute(pool)
    .await?;

    let deleted = result.rows_affected();
    if deleted > 0 {
        info!("Cleaned up {} old Shodan query history entries", deleted);
    }

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_type_conversion() {
        assert_eq!(CacheType::Host.as_str(), "host");
        assert_eq!(CacheType::Search.as_str(), "search");
        assert_eq!(CacheType::DnsResolve.as_str(), "dns_resolve");
        assert_eq!(CacheType::DnsReverse.as_str(), "dns_reverse");

        assert_eq!(CacheType::from_str("host"), Some(CacheType::Host));
        assert_eq!(CacheType::from_str("search"), Some(CacheType::Search));
        assert_eq!(CacheType::from_str("invalid"), None);
    }
}
