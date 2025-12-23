//! Permission caching layer
//!
//! Caches permission check results to improve performance.
//! Cache entries expire after a configurable TTL.

use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

/// Default cache TTL in minutes
const DEFAULT_CACHE_TTL_MINUTES: i64 = 5;

/// Get a cached permission result
pub async fn get_cached_permission(
    pool: &SqlitePool,
    ctx: &PermissionContext,
) -> Result<Option<PermissionResult>> {
    let cache_key = PermissionCache::build_key(
        &ctx.user_id,
        &ctx.organization_id,
        &ctx.action,
        &ctx.resource_type,
    );

    let cached = sqlx::query_as::<_, PermissionCache>(
        r#"
        SELECT * FROM permission_cache
        WHERE user_id = ? AND organization_id = ? AND cache_key = ?
        AND expires_at > datetime('now')
        "#,
    )
    .bind(&ctx.user_id)
    .bind(&ctx.organization_id)
    .bind(&cache_key)
    .fetch_optional(pool)
    .await?;

    match cached {
        Some(entry) => {
            let result: PermissionResult = serde_json::from_str(&entry.effective_permissions)?;
            Ok(Some(result.cached()))
        }
        None => Ok(None),
    }
}

/// Cache a permission result
pub async fn cache_permission(
    pool: &SqlitePool,
    ctx: &PermissionContext,
    result: &PermissionResult,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires = now + Duration::minutes(DEFAULT_CACHE_TTL_MINUTES);

    let cache_key = PermissionCache::build_key(
        &ctx.user_id,
        &ctx.organization_id,
        &ctx.action,
        &ctx.resource_type,
    );

    let result_json = serde_json::to_string(result)?;

    // Upsert the cache entry
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO permission_cache (id, user_id, organization_id, cache_key, effective_permissions, computed_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&ctx.user_id)
    .bind(&ctx.organization_id)
    .bind(&cache_key)
    .bind(&result_json)
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Invalidate all cache entries for a user in an organization
pub async fn invalidate_user_cache(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM permission_cache WHERE user_id = ? AND organization_id = ?")
        .bind(user_id)
        .bind(org_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Invalidate all cache entries for an organization
pub async fn invalidate_org_cache(pool: &SqlitePool, org_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM permission_cache WHERE organization_id = ?")
        .bind(org_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Invalidate cache entries for a specific permission
pub async fn invalidate_permission_cache(pool: &SqlitePool, permission_name: &str) -> Result<()> {
    // Permission name format: "resource_type:action"
    sqlx::query("DELETE FROM permission_cache WHERE cache_key LIKE ?")
        .bind(format!("%:{}%", permission_name))
        .execute(pool)
        .await?;

    Ok(())
}

/// Clear all expired cache entries
pub async fn cleanup_expired_cache(pool: &SqlitePool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM permission_cache WHERE expires_at < datetime('now')")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Get cached effective permissions for a user
pub async fn get_cached_effective_permissions(
    pool: &SqlitePool,
    user_id: &str,
    org_id: &str,
) -> Result<Option<EffectivePermissions>> {
    let cache_key = PermissionCache::build_effective_key(user_id, org_id);

    let cached = sqlx::query_as::<_, PermissionCache>(
        r#"
        SELECT * FROM permission_cache
        WHERE user_id = ? AND organization_id = ? AND cache_key = ?
        AND expires_at > datetime('now')
        "#,
    )
    .bind(user_id)
    .bind(org_id)
    .bind(&cache_key)
    .fetch_optional(pool)
    .await?;

    match cached {
        Some(entry) => {
            let result: EffectivePermissions = serde_json::from_str(&entry.effective_permissions)?;
            Ok(Some(result))
        }
        None => Ok(None),
    }
}

/// Cache effective permissions for a user
pub async fn cache_effective_permissions(
    pool: &SqlitePool,
    permissions: &EffectivePermissions,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires = now + Duration::minutes(DEFAULT_CACHE_TTL_MINUTES);

    let cache_key = PermissionCache::build_effective_key(&permissions.user_id, &permissions.organization_id);
    let result_json = serde_json::to_string(permissions)?;

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO permission_cache (id, user_id, organization_id, cache_key, effective_permissions, computed_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&permissions.user_id)
    .bind(&permissions.organization_id)
    .bind(&cache_key)
    .bind(&result_json)
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Get cache statistics
pub async fn get_cache_stats(pool: &SqlitePool) -> Result<CacheStats> {
    let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permission_cache")
        .fetch_one(pool)
        .await?;

    let active = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM permission_cache WHERE expires_at > datetime('now')",
    )
    .fetch_one(pool)
    .await?;

    let expired = total - active;

    let orgs = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT organization_id) FROM permission_cache WHERE expires_at > datetime('now')",
    )
    .fetch_one(pool)
    .await?;

    let users = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT user_id) FROM permission_cache WHERE expires_at > datetime('now')",
    )
    .fetch_one(pool)
    .await?;

    Ok(CacheStats {
        total_entries: total as usize,
        active_entries: active as usize,
        expired_entries: expired as usize,
        organizations_cached: orgs as usize,
        users_cached: users as usize,
    })
}

/// Cache statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub active_entries: usize,
    pub expired_entries: usize,
    pub organizations_cached: usize,
    pub users_cached: usize,
}

/// Warm up cache for a user by pre-computing common permissions
pub async fn warmup_user_cache(pool: &SqlitePool, user_id: &str, org_id: &str) -> Result<()> {
    // Common resource types and actions to pre-cache
    let common_checks = vec![
        ("scans", "create"),
        ("scans", "read"),
        ("scans", "execute"),
        ("reports", "create"),
        ("reports", "read"),
        ("assets", "read"),
        ("assets", "create"),
        ("vulnerabilities", "read"),
        ("settings", "read"),
    ];

    for (resource_type, action) in common_checks {
        let ctx = PermissionContext::new(user_id, org_id, action, resource_type);
        // This will populate the cache as a side effect
        let _ = super::evaluation::check_permission(pool, &ctx).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_format() {
        let key = PermissionCache::build_key("user1", "org1", "read", "scans");
        assert_eq!(key, "user1:org1:read:scans");
    }

    #[test]
    fn test_effective_cache_key_format() {
        let key = PermissionCache::build_effective_key("user1", "org1");
        assert_eq!(key, "effective:user1:org1");
    }
}
