//! Database query optimization utilities and caching layer

use anyhow::{Result, Context};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use log::{debug, info, warn};

/// Query cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Cached data (JSON string)
    data: String,

    /// When this entry was cached
    cached_at: DateTime<Utc>,

    /// Time-to-live in seconds
    ttl_seconds: i64,

    /// Number of times this entry was accessed
    hit_count: u64,
}

impl CacheEntry {
    fn new(data: String, ttl_seconds: i64) -> Self {
        Self {
            data,
            cached_at: Utc::now(),
            ttl_seconds,
            hit_count: 0,
        }
    }

    fn is_expired(&self) -> bool {
        let now = Utc::now();
        let age = now.signed_duration_since(self.cached_at);
        age.num_seconds() > self.ttl_seconds
    }

    fn increment_hit(&mut self) {
        self.hit_count += 1;
    }
}

/// In-memory query cache
pub struct QueryCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    default_ttl_seconds: i64,
}

impl QueryCache {
    /// Create a new query cache
    pub fn new(default_ttl_seconds: i64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl_seconds,
        }
    }

    /// Get cached data
    pub async fn get(&self, key: &str) -> Option<String> {
        let mut cache = self.cache.write().await;

        if let Some(entry) = cache.get_mut(key) {
            if entry.is_expired() {
                debug!("Cache entry expired for key: {}", key);
                cache.remove(key);
                None
            } else {
                entry.increment_hit();
                debug!("Cache hit for key: {} (hits: {})", key, entry.hit_count);
                Some(entry.data.clone())
            }
        } else {
            debug!("Cache miss for key: {}", key);
            None
        }
    }

    /// Set cached data
    pub async fn set(&self, key: String, data: String, ttl_seconds: Option<i64>) {
        let ttl = ttl_seconds.unwrap_or(self.default_ttl_seconds);
        let entry = CacheEntry::new(data, ttl);

        let mut cache = self.cache.write().await;
        cache.insert(key.clone(), entry);
        debug!("Cached data for key: {} (TTL: {}s)", key, ttl);
    }

    /// Invalidate a specific cache key
    pub async fn invalidate(&self, key: &str) {
        let mut cache = self.cache.write().await;
        if cache.remove(key).is_some() {
            debug!("Invalidated cache for key: {}", key);
        }
    }

    /// Invalidate all cache entries matching a pattern
    pub async fn invalidate_pattern(&self, pattern: &str) {
        let mut cache = self.cache.write().await;
        let keys_to_remove: Vec<String> = cache
            .keys()
            .filter(|k| k.contains(pattern))
            .cloned()
            .collect();

        for key in keys_to_remove {
            cache.remove(&key);
        }
        debug!("Invalidated cache entries matching pattern: {}", pattern);
    }

    /// Clear all cached data
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        let count = cache.len();
        cache.clear();
        info!("Cleared {} cache entries", count);
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) -> usize {
        let mut cache = self.cache.write().await;
        let initial_count = cache.len();

        cache.retain(|_, entry| !entry.is_expired());

        let removed = initial_count - cache.len();
        if removed > 0 {
            info!("Cleaned up {} expired cache entries", removed);
        }
        removed
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;

        let total_entries = cache.len();
        let total_hits: u64 = cache.values().map(|e| e.hit_count).sum();
        let expired_entries = cache.values().filter(|e| e.is_expired()).count();

        CacheStats {
            total_entries,
            expired_entries,
            total_hits,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub total_hits: u64,
}

/// Database query optimizer
pub struct QueryOptimizer {
    pool: SqlitePool,
    cache: QueryCache,
}

impl QueryOptimizer {
    /// Create a new query optimizer
    pub fn new(pool: SqlitePool, cache_ttl_seconds: i64) -> Self {
        Self {
            pool,
            cache: QueryCache::new(cache_ttl_seconds),
        }
    }

    /// Analyze query performance
    pub async fn analyze_query(&self, query: &str) -> Result<QueryAnalysis> {
        let explain_query = format!("EXPLAIN QUERY PLAN {}", query);

        let rows: Vec<(i32, i32, i32, String)> = sqlx::query_as(&explain_query)
            .fetch_all(&self.pool)
            .await
            .context("Failed to analyze query")?;

        let uses_index = rows.iter().any(|(_, _, _, detail)| {
            detail.to_lowercase().contains("using index")
        });

        let uses_temp = rows.iter().any(|(_, _, _, detail)| {
            detail.to_lowercase().contains("using temporary")
        });

        let scan_type = if uses_index {
            "index_scan"
        } else if rows.iter().any(|(_, _, _, d)| d.to_lowercase().contains("scan")) {
            "table_scan"
        } else {
            "unknown"
        };

        Ok(QueryAnalysis {
            query: query.to_string(),
            uses_index,
            uses_temp,
            scan_type: scan_type.to_string(),
            execution_plan: rows.iter().map(|(_, _, _, d)| d.clone()).collect(),
        })
    }

    /// Optimize database indexes
    pub async fn optimize_indexes(&self) -> Result<()> {
        info!("Optimizing database indexes...");

        // Analyze all tables
        sqlx::query("ANALYZE").execute(&self.pool).await?;

        // Rebuild indexes if needed
        sqlx::query("REINDEX").execute(&self.pool).await?;

        info!("Database indexes optimized");
        Ok(())
    }

    /// Vacuum database to reclaim space
    pub async fn vacuum_database(&self) -> Result<()> {
        info!("Vacuuming database...");
        sqlx::query("VACUUM").execute(&self.pool).await?;
        info!("Database vacuumed successfully");
        Ok(())
    }

    /// Get database statistics
    pub async fn get_db_stats(&self) -> Result<DatabaseStats> {
        // Get database size
        let page_count: (i64,) = sqlx::query_as("PRAGMA page_count")
            .fetch_one(&self.pool)
            .await?;

        let page_size: (i64,) = sqlx::query_as("PRAGMA page_size")
            .fetch_one(&self.pool)
            .await?;

        let db_size_bytes = page_count.0 * page_size.0;

        // Get table count
        let table_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        )
        .fetch_one(&self.pool)
        .await?;

        // Get index count
        let index_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(DatabaseStats {
            size_bytes: db_size_bytes,
            table_count: table_count.0 as usize,
            index_count: index_count.0 as usize,
            page_size: page_size.0 as usize,
        })
    }

    /// Suggest missing indexes based on query patterns
    pub async fn suggest_indexes(&self) -> Result<Vec<IndexSuggestion>> {
        // This is a simplified version - in production, you'd analyze query logs
        let suggestions = vec![
            IndexSuggestion {
                table: "scan_results".to_string(),
                columns: vec!["status".to_string(), "created_at".to_string()],
                reason: "Frequently used in WHERE clauses for filtering".to_string(),
            },
            IndexSuggestion {
                table: "vulnerabilities".to_string(),
                columns: vec!["severity".to_string(), "status".to_string()],
                reason: "Common filter combination for vulnerability queries".to_string(),
            },
        ];

        Ok(suggestions)
    }

    /// Get cache instance
    pub fn cache(&self) -> &QueryCache {
        &self.cache
    }

    /// Execute cached query
    pub async fn query_cached<T>(&self,
        cache_key: &str,
        query: &str,
        ttl_seconds: Option<i64>,
        mapper: impl Fn(String) -> Result<T>
    ) -> Result<T>
    where
        T: Serialize,
    {
        // Try to get from cache
        if let Some(cached_data) = self.cache.get(cache_key).await {
            return mapper(cached_data);
        }

        // Execute query
        let result_json = self.execute_and_serialize(query).await?;

        // Cache the result
        self.cache.set(cache_key.to_string(), result_json.clone(), ttl_seconds).await;

        mapper(result_json)
    }

    /// Execute query and serialize result
    async fn execute_and_serialize(&self, query: &str) -> Result<String> {
        // This is a placeholder - actual implementation would depend on query type
        // For now, return empty JSON array
        Ok("[]".to_string())
    }
}

/// Query analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAnalysis {
    pub query: String,
    pub uses_index: bool,
    pub uses_temp: bool,
    pub scan_type: String,
    pub execution_plan: Vec<String>,
}

/// Database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub size_bytes: i64,
    pub table_count: usize,
    pub index_count: usize,
    pub page_size: usize,
}

impl DatabaseStats {
    pub fn size_mb(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0)
    }

    pub fn size_gb(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }
}

/// Index suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSuggestion {
    pub table: String,
    pub columns: Vec<String>,
    pub reason: String,
}

/// Query performance monitoring
pub struct QueryMonitor {
    slow_query_threshold_ms: u64,
}

impl QueryMonitor {
    pub fn new(slow_query_threshold_ms: u64) -> Self {
        Self {
            slow_query_threshold_ms,
        }
    }

    /// Monitor query execution time
    pub async fn monitor_query<F, T>(&self, query_name: &str, f: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let start = std::time::Instant::now();
        let result = f.await;
        let duration = start.elapsed();

        if duration.as_millis() as u64 > self.slow_query_threshold_ms {
            warn!(
                "Slow query detected: {} took {}ms (threshold: {}ms)",
                query_name,
                duration.as_millis(),
                self.slow_query_threshold_ms
            );
        } else {
            debug!("Query {} completed in {}ms", query_name, duration.as_millis());
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let cache = QueryCache::new(60);

        // Test set and get
        cache.set("key1".to_string(), "value1".to_string(), None).await;
        let result = cache.get("key1").await;
        assert_eq!(result, Some("value1".to_string()));

        // Test invalidation
        cache.invalidate("key1").await;
        let result = cache.get("key1").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = QueryCache::new(1); // 1 second TTL

        cache.set("key1".to_string(), "value1".to_string(), Some(1)).await;

        // Should be available immediately
        assert!(cache.get("key1").await.is_some());

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Should be expired
        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = QueryCache::new(60);

        cache.set("key1".to_string(), "value1".to_string(), None).await;
        cache.set("key2".to_string(), "value2".to_string(), None).await;

        cache.get("key1").await;
        cache.get("key1").await;
        cache.get("key2").await;

        let stats = cache.get_stats().await;
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.total_hits, 3);
    }
}
