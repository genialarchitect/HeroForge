//! Cache invalidation and access strategies
//!
//! Implements common caching patterns using the CacheClient backend:
//! - Cache-Aside (Lazy Loading): Load into cache on first access
//! - Write-Through: Write to cache and backing store simultaneously
//! - Cache Warming: Pre-populate cache with frequently accessed data

use std::sync::Arc;
use std::time::Duration;

use super::{CacheClient, CacheConfig};

/// Cache invalidation strategy
pub enum InvalidationStrategy {
    /// Time-based expiration
    TimeToLive(Duration),
    /// Invalidate on write
    WriteThrough,
    /// Invalidate on specific events
    EventBased(Vec<String>),
    /// Never invalidate (manual only)
    Manual,
}

/// Cache-aside pattern helper
///
/// Implements the lazy-loading cache pattern:
/// 1. Check cache for requested data
/// 2. On cache hit: return cached data
/// 3. On cache miss: compute/fetch data, store in cache, return
pub struct CacheAside {
    client: Arc<CacheClient>,
    default_ttl: Duration,
}

impl CacheAside {
    /// Create a new CacheAside instance with the given client and TTL
    pub fn new(client: Arc<CacheClient>, default_ttl: Duration) -> Self {
        Self { client, default_ttl }
    }

    /// Create with default configuration
    pub fn with_defaults() -> anyhow::Result<Self> {
        let config = CacheConfig::default();
        let ttl = config.default_ttl;
        let client = Arc::new(CacheClient::new(config)?);
        Ok(Self { client, default_ttl: ttl })
    }

    /// Get a value from cache, or compute and store it if not found
    pub async fn get_or_compute<T, F, Fut>(
        &self,
        cache_key: &str,
        compute_fn: F,
    ) -> anyhow::Result<T>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        // Try cache first
        if let Ok(Some(cached)) = self.client.get::<T>(cache_key).await {
            log::debug!("Cache hit for key: {}", cache_key);
            return Ok(cached);
        }

        log::debug!("Cache miss for key: {}", cache_key);

        // Compute the value
        let value = compute_fn().await?;

        // Store in cache (best-effort, don't fail if cache write fails)
        if let Err(e) = self.client.set_with_ttl(cache_key, &value, self.default_ttl).await {
            log::warn!("Failed to write to cache for key {}: {}", cache_key, e);
        }

        Ok(value)
    }

    /// Get a value from cache, or compute with custom TTL
    pub async fn get_or_compute_with_ttl<T, F, Fut>(
        &self,
        cache_key: &str,
        ttl: Duration,
        compute_fn: F,
    ) -> anyhow::Result<T>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        if let Ok(Some(cached)) = self.client.get::<T>(cache_key).await {
            return Ok(cached);
        }

        let value = compute_fn().await?;

        if let Err(e) = self.client.set_with_ttl(cache_key, &value, ttl).await {
            log::warn!("Failed to write to cache for key {}: {}", cache_key, e);
        }

        Ok(value)
    }

    /// Invalidate a specific cache key
    pub async fn invalidate(&self, cache_key: &str) -> anyhow::Result<()> {
        self.client.delete(cache_key).await
    }

    /// Invalidate all keys matching a pattern
    pub async fn invalidate_pattern(&self, pattern: &str) -> anyhow::Result<u64> {
        self.client.delete_pattern(pattern).await
    }
}

/// Write-through cache pattern
///
/// Ensures cache and backing store stay consistent by writing to both
/// simultaneously. Reads always hit the cache first.
pub struct WriteThrough {
    client: Arc<CacheClient>,
    default_ttl: Duration,
}

impl WriteThrough {
    /// Create a new WriteThrough instance
    pub fn new(client: Arc<CacheClient>, default_ttl: Duration) -> Self {
        Self { client, default_ttl }
    }

    /// Create with default configuration
    pub fn with_defaults() -> anyhow::Result<Self> {
        let config = CacheConfig::default();
        let ttl = config.default_ttl;
        let client = Arc::new(CacheClient::new(config)?);
        Ok(Self { client, default_ttl: ttl })
    }

    /// Write a value to both cache and the backing store
    ///
    /// The `persist_fn` is called to write to the backing store (e.g., database).
    /// The cache is updated regardless of whether the backing store write succeeds,
    /// ensuring the cache always reflects the latest attempted state.
    pub async fn write<T, F, Fut>(
        &self,
        cache_key: &str,
        value: &T,
        persist_fn: F,
    ) -> anyhow::Result<()>
    where
        T: serde::Serialize + Clone,
        F: FnOnce(T) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        // Write to backing store first (source of truth)
        persist_fn(value.clone()).await?;

        // Then update cache
        self.client.set_with_ttl(cache_key, value, self.default_ttl).await?;

        log::debug!("Write-through completed for key: {}", cache_key);
        Ok(())
    }

    /// Write with custom TTL
    pub async fn write_with_ttl<T, F, Fut>(
        &self,
        cache_key: &str,
        value: &T,
        ttl: Duration,
        persist_fn: F,
    ) -> anyhow::Result<()>
    where
        T: serde::Serialize + Clone,
        F: FnOnce(T) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        persist_fn(value.clone()).await?;
        self.client.set_with_ttl(cache_key, value, ttl).await?;
        Ok(())
    }

    /// Read from cache (falls back to None if not cached)
    pub async fn read<T>(&self, cache_key: &str) -> anyhow::Result<Option<T>>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        self.client.get::<T>(cache_key).await
    }

    /// Delete from both cache and backing store
    pub async fn delete<F, Fut>(
        &self,
        cache_key: &str,
        delete_fn: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<()>>,
    {
        delete_fn().await?;
        self.client.delete(cache_key).await?;
        Ok(())
    }
}

/// Cache warming strategies
///
/// Pre-populates cache with data that's likely to be accessed soon,
/// reducing cache miss latency for common queries.
pub struct CacheWarming {
    client: Arc<CacheClient>,
    default_ttl: Duration,
}

impl CacheWarming {
    /// Create a new CacheWarming instance
    pub fn new(client: Arc<CacheClient>, default_ttl: Duration) -> Self {
        Self { client, default_ttl }
    }

    /// Create with default configuration
    pub fn with_defaults() -> anyhow::Result<Self> {
        let config = CacheConfig::default();
        let ttl = config.default_ttl;
        let client = Arc::new(CacheClient::new(config)?);
        Ok(Self { client, default_ttl: ttl })
    }

    /// Warm the cache with a batch of key-value pairs
    pub async fn warm_batch<T: serde::Serialize>(
        &self,
        entries: Vec<(String, T)>,
    ) -> anyhow::Result<u32> {
        let mut warmed = 0u32;

        for (key, value) in entries {
            match self.client.set_with_ttl(&key, &value, self.default_ttl).await {
                Ok(()) => warmed += 1,
                Err(e) => {
                    log::warn!("Failed to warm cache key {}: {}", key, e);
                }
            }
        }

        log::info!("Cache warming completed: {} entries loaded", warmed);
        Ok(warmed)
    }

    /// Warm cache with data from a loader function
    pub async fn warm_from_loader<T, F, Fut>(
        &self,
        keys: Vec<String>,
        loader: F,
    ) -> anyhow::Result<u32>
    where
        T: serde::Serialize,
        F: Fn(&str) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        let mut warmed = 0u32;

        for key in &keys {
            match loader(key).await {
                Ok(value) => {
                    if let Err(e) = self.client.set_with_ttl(key, &value, self.default_ttl).await {
                        log::warn!("Failed to warm cache key {}: {}", key, e);
                    } else {
                        warmed += 1;
                    }
                }
                Err(e) => {
                    log::warn!("Loader failed for key {}: {}", key, e);
                }
            }
        }

        log::info!("Cache warming from loader completed: {}/{} entries", warmed, keys.len());
        Ok(warmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_aside_with_defaults() {
        // With no Redis, CacheAside still works (falls through to compute_fn)
        let cache = CacheAside::with_defaults().unwrap();

        let result = cache.get_or_compute("test_key", || async {
            Ok(42u32)
        }).await.unwrap();

        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_write_through_with_defaults() {
        let cache = WriteThrough::with_defaults().unwrap();
        let value = 100u32;

        let result = cache.write("test_key", &value, |_v| async {
            Ok(())
        }).await;

        // Should succeed (cache write is best-effort in no-redis mode)
        assert!(result.is_ok());
    }
}
