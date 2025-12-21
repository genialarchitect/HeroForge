#![allow(dead_code)]
//! Database operations for push notification device tokens
//!
//! This module handles CRUD operations for mobile device push notification tokens.
//! Supports both iOS (APNS) and Android (FCM) devices via Expo Push API.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use utoipa::ToSchema;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Platform types for push notifications
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Android,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ios" => Some(Platform::Ios),
            "android" => Some(Platform::Android),
            _ => None,
        }
    }
}

/// Push device token stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PushDeviceToken {
    pub id: String,
    pub user_id: String,
    pub device_token: String,
    pub platform: String,
    pub device_name: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Response type for device token (excludes internal fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDeviceTokenResponse {
    pub id: String,
    pub device_token: String,
    pub platform: String,
    pub device_name: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PushDeviceToken> for PushDeviceTokenResponse {
    fn from(token: PushDeviceToken) -> Self {
        Self {
            id: token.id,
            device_token: token.device_token,
            platform: token.platform,
            device_name: token.device_name,
            is_active: token.is_active,
            created_at: token.created_at,
            updated_at: token.updated_at,
        }
    }
}

/// Request to register a new device token
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterDeviceRequest {
    /// Expo push token (e.g., "ExponentPushToken[xxxx]")
    pub device_token: String,
    /// Platform: "ios" or "android"
    pub platform: String,
    /// Optional friendly device name
    pub device_name: Option<String>,
}

// ============================================================================
// Database Operations
// ============================================================================

/// Register or update a push device token
///
/// If a device token already exists for this user, it will be updated.
/// If the same token exists for a different user, the old registration is removed.
pub async fn register_device_token(
    pool: &SqlitePool,
    user_id: &str,
    device_token: &str,
    platform: &str,
    device_name: Option<&str>,
) -> Result<PushDeviceToken> {
    let now = Utc::now();

    // Check if this token already exists for this user
    let existing = sqlx::query_as::<_, PushDeviceToken>(
        "SELECT * FROM push_device_tokens WHERE user_id = ? AND device_token = ?",
    )
    .bind(user_id)
    .bind(device_token)
    .fetch_optional(pool)
    .await?;

    if let Some(mut token) = existing {
        // Update existing token
        sqlx::query(
            r#"
            UPDATE push_device_tokens
            SET platform = ?, device_name = ?, is_active = 1, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(platform)
        .bind(device_name)
        .bind(now)
        .bind(&token.id)
        .execute(pool)
        .await?;

        token.platform = platform.to_string();
        token.device_name = device_name.map(String::from);
        token.is_active = true;
        token.updated_at = now;

        log::info!(
            "Updated push device token for user {} (platform: {})",
            user_id,
            platform
        );
        return Ok(token);
    }

    // Remove this token from any other users (device transferred)
    sqlx::query("DELETE FROM push_device_tokens WHERE device_token = ? AND user_id != ?")
        .bind(device_token)
        .bind(user_id)
        .execute(pool)
        .await?;

    // Create new token
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO push_device_tokens (id, user_id, device_token, platform, device_name, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(device_token)
    .bind(platform)
    .bind(device_name)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    log::info!(
        "Registered new push device token for user {} (platform: {})",
        user_id,
        platform
    );

    Ok(PushDeviceToken {
        id,
        user_id: user_id.to_string(),
        device_token: device_token.to_string(),
        platform: platform.to_string(),
        device_name: device_name.map(String::from),
        is_active: true,
        created_at: now,
        updated_at: now,
    })
}

/// Unregister a device token by ID
pub async fn unregister_device_token(pool: &SqlitePool, user_id: &str, token_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM push_device_tokens WHERE id = ? AND user_id = ?")
        .bind(token_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    if result.rows_affected() > 0 {
        log::info!("Unregistered push device token {} for user {}", token_id, user_id);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Unregister a device by its token string
pub async fn unregister_device_by_token(
    pool: &SqlitePool,
    user_id: &str,
    device_token: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM push_device_tokens WHERE device_token = ? AND user_id = ?")
        .bind(device_token)
        .bind(user_id)
        .execute(pool)
        .await?;

    if result.rows_affected() > 0 {
        log::info!("Unregistered push device token for user {}", user_id);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Get all active device tokens for a user
pub async fn get_user_device_tokens(pool: &SqlitePool, user_id: &str) -> Result<Vec<PushDeviceToken>> {
    let tokens = sqlx::query_as::<_, PushDeviceToken>(
        r#"
        SELECT * FROM push_device_tokens
        WHERE user_id = ? AND is_active = 1
        ORDER BY updated_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(tokens)
}

/// Get all active device tokens for multiple users
pub async fn get_tokens_for_users(pool: &SqlitePool, user_ids: &[String]) -> Result<Vec<PushDeviceToken>> {
    if user_ids.is_empty() {
        return Ok(vec![]);
    }

    // Build placeholders for the IN clause
    let placeholders: Vec<String> = user_ids.iter().map(|_| "?".to_string()).collect();
    let placeholders_str = placeholders.join(",");

    let query = format!(
        r#"
        SELECT * FROM push_device_tokens
        WHERE user_id IN ({}) AND is_active = 1
        ORDER BY user_id, updated_at DESC
        "#,
        placeholders_str
    );

    let mut query_builder = sqlx::query_as::<_, PushDeviceToken>(&query);
    for user_id in user_ids {
        query_builder = query_builder.bind(user_id);
    }

    let tokens = query_builder.fetch_all(pool).await?;
    Ok(tokens)
}

/// Mark a device token as inactive (e.g., when push fails with invalid token)
pub async fn deactivate_device_token(pool: &SqlitePool, device_token: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        "UPDATE push_device_tokens SET is_active = 0, updated_at = ? WHERE device_token = ?",
    )
    .bind(now)
    .bind(device_token)
    .execute(pool)
    .await?;

    log::info!("Deactivated push device token");
    Ok(())
}

/// Mark multiple device tokens as inactive
pub async fn deactivate_device_tokens(pool: &SqlitePool, device_tokens: &[String]) -> Result<()> {
    if device_tokens.is_empty() {
        return Ok(());
    }

    let now = Utc::now();
    let placeholders: Vec<String> = device_tokens.iter().map(|_| "?".to_string()).collect();
    let placeholders_str = placeholders.join(",");

    let query = format!(
        "UPDATE push_device_tokens SET is_active = 0, updated_at = ? WHERE device_token IN ({})",
        placeholders_str
    );

    let mut query_builder = sqlx::query(&query);
    query_builder = query_builder.bind(now);
    for token in device_tokens {
        query_builder = query_builder.bind(token);
    }

    query_builder.execute(pool).await?;

    log::info!(
        "Deactivated {} push device tokens",
        device_tokens.len()
    );
    Ok(())
}

/// Get a specific device token by ID
pub async fn get_device_token_by_id(
    pool: &SqlitePool,
    user_id: &str,
    token_id: &str,
) -> Result<Option<PushDeviceToken>> {
    let token = sqlx::query_as::<_, PushDeviceToken>(
        "SELECT * FROM push_device_tokens WHERE id = ? AND user_id = ?",
    )
    .bind(token_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(token)
}

/// Clean up inactive tokens older than the specified number of days
pub async fn cleanup_inactive_tokens(pool: &SqlitePool, days_old: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(days_old);

    let result = sqlx::query(
        "DELETE FROM push_device_tokens WHERE is_active = 0 AND updated_at < ?",
    )
    .bind(cutoff)
    .execute(pool)
    .await?;

    let count = result.rows_affected();
    if count > 0 {
        log::info!("Cleaned up {} inactive push device tokens", count);
    }

    Ok(count)
}

/// Get count of active tokens per platform for a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TokenCountByPlatform {
    pub platform: String,
    pub count: i64,
}

pub async fn get_token_stats_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<TokenCountByPlatform>> {
    let stats = sqlx::query_as::<_, TokenCountByPlatform>(
        r#"
        SELECT platform, COUNT(*) as count
        FROM push_device_tokens
        WHERE user_id = ? AND is_active = 1
        GROUP BY platform
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_from_str() {
        assert_eq!(Platform::from_str("ios"), Some(Platform::Ios));
        assert_eq!(Platform::from_str("IOS"), Some(Platform::Ios));
        assert_eq!(Platform::from_str("android"), Some(Platform::Android));
        assert_eq!(Platform::from_str("Android"), Some(Platform::Android));
        assert_eq!(Platform::from_str("unknown"), None);
    }

    #[test]
    fn test_platform_as_str() {
        assert_eq!(Platform::Ios.as_str(), "ios");
        assert_eq!(Platform::Android.as_str(), "android");
    }
}
