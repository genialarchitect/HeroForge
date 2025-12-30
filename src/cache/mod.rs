//! Redis-based caching layer for HeroForge
//!
//! Provides intelligent caching for:
//! - Scan results
//! - User sessions
//! - Vulnerability data
//! - API responses
//! - Threat intelligence data

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(feature = "redis")]
use redis::{AsyncCommands, Client};

pub mod strategies;
pub mod ttl;

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub redis_url: String,
    pub default_ttl: Duration,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            default_ttl: Duration::from_secs(3600), // 1 hour
            max_retries: 3,
            retry_delay_ms: 100,
        }
    }
}

/// Cache key prefix for different data types
pub enum CacheKeyPrefix {
    ScanResult,
    UserSession,
    Vulnerability,
    ApiResponse,
    ThreatIntel,
    AssetInventory,
    ComplianceReport,
}

impl CacheKeyPrefix {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ScanResult => "scan:",
            Self::UserSession => "session:",
            Self::Vulnerability => "vuln:",
            Self::ApiResponse => "api:",
            Self::ThreatIntel => "ti:",
            Self::AssetInventory => "asset:",
            Self::ComplianceReport => "compliance:",
        }
    }

    pub fn build_key(&self, id: &str) -> String {
        format!("{}{}", self.as_str(), id)
    }
}

/// Redis cache client wrapper
#[cfg(feature = "redis")]
pub struct CacheClient {
    client: Client,
    config: CacheConfig,
}

#[cfg(feature = "redis")]
impl CacheClient {
    /// Create a new cache client
    pub fn new(config: CacheConfig) -> Result<Self> {
        let client = Client::open(config.redis_url.as_str())
            .context("Failed to create Redis client")?;

        Ok(Self { client, config })
    }

    /// Get a value from cache
    pub async fn get<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let mut conn = self.client.get_async_connection().await?;
        let value: Option<String> = conn.get(key).await?;

        match value {
            Some(v) => {
                let deserialized = serde_json::from_str(&v)?;
                Ok(Some(deserialized))
            }
            None => Ok(None),
        }
    }

    /// Set a value in cache with default TTL
    pub async fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.set_with_ttl(key, value, self.config.default_ttl).await
    }

    /// Set a value in cache with custom TTL
    pub async fn set_with_ttl<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Duration,
    ) -> Result<()> {
        let mut conn = self.client.get_async_connection().await?;
        let serialized = serde_json::to_string(value)?;

        conn.set_ex(key, serialized, ttl.as_secs()).await?;
        Ok(())
    }

    /// Delete a value from cache
    pub async fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self.client.get_async_connection().await?;
        conn.del(key).await?;
        Ok(())
    }

    /// Delete multiple keys matching a pattern
    pub async fn delete_pattern(&self, pattern: &str) -> Result<u64> {
        let mut conn = self.client.get_async_connection().await?;
        let keys: Vec<String> = conn.keys(pattern).await?;

        if keys.is_empty() {
            return Ok(0);
        }

        let deleted: u64 = conn.del(&keys).await?;
        Ok(deleted)
    }

    /// Check if a key exists
    pub async fn exists(&self, key: &str) -> Result<bool> {
        let mut conn = self.client.get_async_connection().await?;
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }

    /// Increment a counter
    pub async fn incr(&self, key: &str) -> Result<i64> {
        let mut conn = self.client.get_async_connection().await?;
        let value: i64 = conn.incr(key, 1).await?;
        Ok(value)
    }

    /// Decrement a counter
    pub async fn decr(&self, key: &str) -> Result<i64> {
        let mut conn = self.client.get_async_connection().await?;
        let value: i64 = conn.decr(key, 1).await?;
        Ok(value)
    }

    /// Set expiration time for a key
    pub async fn expire(&self, key: &str, ttl: Duration) -> Result<()> {
        let mut conn = self.client.get_async_connection().await?;
        conn.expire(key, ttl.as_secs() as usize).await?;
        Ok(())
    }

    /// Get time-to-live for a key
    pub async fn ttl(&self, key: &str) -> Result<Option<Duration>> {
        let mut conn = self.client.get_async_connection().await?;
        let ttl: i64 = conn.ttl(key).await?;

        if ttl < 0 {
            Ok(None)
        } else {
            Ok(Some(Duration::from_secs(ttl as u64)))
        }
    }
}

/// Fallback cache client when Redis is not available (in-memory)
#[cfg(not(feature = "redis"))]
pub struct CacheClient {
    config: CacheConfig,
}

#[cfg(not(feature = "redis"))]
impl CacheClient {
    pub fn new(config: CacheConfig) -> Result<Self> {
        log::warn!("Redis not enabled, cache operations will be no-ops");
        Ok(Self { config })
    }

    pub async fn get<T: for<'de> Deserialize<'de>>(&self, _key: &str) -> Result<Option<T>> {
        Ok(None)
    }

    pub async fn set<T: Serialize>(&self, _key: &str, _value: &T) -> Result<()> {
        Ok(())
    }

    pub async fn set_with_ttl<T: Serialize>(
        &self,
        _key: &str,
        _value: &T,
        _ttl: Duration,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn delete(&self, _key: &str) -> Result<()> {
        Ok(())
    }

    pub async fn delete_pattern(&self, _pattern: &str) -> Result<u64> {
        Ok(0)
    }

    pub async fn exists(&self, _key: &str) -> Result<bool> {
        Ok(false)
    }

    pub async fn incr(&self, _key: &str) -> Result<i64> {
        Ok(0)
    }

    pub async fn decr(&self, _key: &str) -> Result<i64> {
        Ok(0)
    }

    pub async fn expire(&self, _key: &str, _ttl: Duration) -> Result<()> {
        Ok(())
    }

    pub async fn ttl(&self, _key: &str) -> Result<Option<Duration>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_key_prefix() {
        let key = CacheKeyPrefix::ScanResult.build_key("scan123");
        assert_eq!(key, "scan:scan123");
    }
}
