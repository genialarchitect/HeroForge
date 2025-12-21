//! Database operations for plugins
//!
//! This module provides CRUD operations for plugin records and settings.

#![allow(dead_code)]

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::plugins::registry::PluginCount;
use crate::plugins::types::{InstalledPlugin, PluginManifest, PluginSettings, PluginStatus, PluginType};

// ============================================================================
// Plugin CRUD Operations
// ============================================================================

/// Install a new plugin
pub async fn install_plugin(
    pool: &SqlitePool,
    manifest: &PluginManifest,
    install_path: &str,
    installed_by: &str,
    status: PluginStatus,
    checksum: &str,
) -> Result<InstalledPlugin> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let manifest_json = serde_json::to_string(manifest)?;

    sqlx::query(
        r#"
        INSERT INTO plugins (
            id, plugin_id, name, version, plugin_type, status, manifest,
            install_path, installed_by, installed_at, updated_at, checksum
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&id)
    .bind(&manifest.plugin.id)
    .bind(&manifest.plugin.name)
    .bind(&manifest.plugin.version)
    .bind(manifest.plugin.plugin_type.to_string())
    .bind(status.to_string())
    .bind(&manifest_json)
    .bind(install_path)
    .bind(installed_by)
    .bind(now)
    .bind(now)
    .bind(checksum)
    .execute(pool)
    .await?;

    get_plugin_by_id(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve installed plugin"))
}

/// Get a plugin by database ID
pub async fn get_plugin_by_id(pool: &SqlitePool, id: &str) -> Result<Option<InstalledPlugin>> {
    let plugin = sqlx::query_as::<_, InstalledPlugin>(
        r#"
        SELECT id, plugin_id, name, version, plugin_type, status, manifest,
               install_path, installed_by, installed_at, updated_at, error_message, checksum
        FROM plugins
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(plugin)
}

/// Get a plugin by plugin ID (from manifest)
pub async fn get_plugin_by_plugin_id(pool: &SqlitePool, plugin_id: &str) -> Result<Option<InstalledPlugin>> {
    let plugin = sqlx::query_as::<_, InstalledPlugin>(
        r#"
        SELECT id, plugin_id, name, version, plugin_type, status, manifest,
               install_path, installed_by, installed_at, updated_at, error_message, checksum
        FROM plugins
        WHERE plugin_id = ?1
        "#,
    )
    .bind(plugin_id)
    .fetch_optional(pool)
    .await?;

    Ok(plugin)
}

/// List all installed plugins
pub async fn list_plugins(pool: &SqlitePool) -> Result<Vec<InstalledPlugin>> {
    let plugins = sqlx::query_as::<_, InstalledPlugin>(
        r#"
        SELECT id, plugin_id, name, version, plugin_type, status, manifest,
               install_path, installed_by, installed_at, updated_at, error_message, checksum
        FROM plugins
        ORDER BY name ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(plugins)
}

/// List plugins by type
pub async fn list_plugins_by_type(pool: &SqlitePool, plugin_type: PluginType) -> Result<Vec<InstalledPlugin>> {
    let plugins = sqlx::query_as::<_, InstalledPlugin>(
        r#"
        SELECT id, plugin_id, name, version, plugin_type, status, manifest,
               install_path, installed_by, installed_at, updated_at, error_message, checksum
        FROM plugins
        WHERE plugin_type = ?1
        ORDER BY name ASC
        "#,
    )
    .bind(plugin_type.to_string())
    .fetch_all(pool)
    .await?;

    Ok(plugins)
}

/// Get all enabled plugins
pub async fn get_enabled_plugins(pool: &SqlitePool) -> Result<Vec<InstalledPlugin>> {
    let plugins = sqlx::query_as::<_, InstalledPlugin>(
        r#"
        SELECT id, plugin_id, name, version, plugin_type, status, manifest,
               install_path, installed_by, installed_at, updated_at, error_message, checksum
        FROM plugins
        WHERE status = 'enabled'
        ORDER BY name ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(plugins)
}

/// Get enabled plugins by type
pub async fn get_enabled_plugins_by_type(pool: &SqlitePool, plugin_type: PluginType) -> Result<Vec<InstalledPlugin>> {
    let plugins = sqlx::query_as::<_, InstalledPlugin>(
        r#"
        SELECT id, plugin_id, name, version, plugin_type, status, manifest,
               install_path, installed_by, installed_at, updated_at, error_message, checksum
        FROM plugins
        WHERE status = 'enabled' AND plugin_type = ?1
        ORDER BY name ASC
        "#,
    )
    .bind(plugin_type.to_string())
    .fetch_all(pool)
    .await?;

    Ok(plugins)
}

/// Update a plugin (after reinstall/update)
pub async fn update_plugin(
    pool: &SqlitePool,
    id: &str,
    manifest: &PluginManifest,
    install_path: &str,
    checksum: &str,
) -> Result<InstalledPlugin> {
    let now = Utc::now();
    let manifest_json = serde_json::to_string(manifest)?;

    sqlx::query(
        r#"
        UPDATE plugins
        SET name = ?1, version = ?2, plugin_type = ?3, manifest = ?4,
            install_path = ?5, updated_at = ?6, checksum = ?7, error_message = NULL
        WHERE id = ?8
        "#,
    )
    .bind(&manifest.plugin.name)
    .bind(&manifest.plugin.version)
    .bind(manifest.plugin.plugin_type.to_string())
    .bind(&manifest_json)
    .bind(install_path)
    .bind(now)
    .bind(checksum)
    .bind(id)
    .execute(pool)
    .await?;

    get_plugin_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve updated plugin"))
}

/// Update plugin status
pub async fn update_plugin_status(pool: &SqlitePool, id: &str, status: PluginStatus) -> Result<InstalledPlugin> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE plugins
        SET status = ?1, updated_at = ?2, error_message = NULL
        WHERE id = ?3
        "#,
    )
    .bind(status.to_string())
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    get_plugin_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Plugin not found"))
}

/// Set plugin error status
pub async fn set_plugin_error(pool: &SqlitePool, id: &str, error_message: &str) -> Result<InstalledPlugin> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE plugins
        SET status = 'error', updated_at = ?1, error_message = ?2
        WHERE id = ?3
        "#,
    )
    .bind(now)
    .bind(error_message)
    .bind(id)
    .execute(pool)
    .await?;

    get_plugin_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Plugin not found"))
}

/// Delete a plugin
pub async fn delete_plugin(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete plugin settings first
    sqlx::query("DELETE FROM plugin_settings WHERE plugin_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    // Delete the plugin
    sqlx::query("DELETE FROM plugins WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get plugin count statistics
pub async fn get_plugin_count(pool: &SqlitePool) -> Result<PluginCount> {
    // Total count
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM plugins")
        .fetch_one(pool)
        .await?;

    // Enabled count
    let (enabled,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM plugins WHERE status = 'enabled'")
        .fetch_one(pool)
        .await?;

    // Disabled count
    let (disabled,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM plugins WHERE status = 'disabled'")
        .fetch_one(pool)
        .await?;

    // Error count
    let (error,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM plugins WHERE status = 'error'")
        .fetch_one(pool)
        .await?;

    // Count by type
    let type_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT plugin_type, COUNT(*) as count FROM plugins GROUP BY plugin_type",
    )
    .fetch_all(pool)
    .await?;

    let by_type: HashMap<String, i64> = type_counts.into_iter().collect();

    Ok(PluginCount {
        total,
        enabled,
        disabled,
        error,
        by_type,
    })
}

// ============================================================================
// Plugin Settings Operations
// ============================================================================

/// Update plugin settings for a user
pub async fn update_plugin_settings(
    pool: &SqlitePool,
    plugin_id: &str,
    user_id: &str,
    settings: serde_json::Value,
) -> Result<()> {
    let now = Utc::now();
    let settings_json = serde_json::to_string(&settings)?;

    // Use upsert
    sqlx::query(
        r#"
        INSERT INTO plugin_settings (id, plugin_id, user_id, settings, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT (plugin_id, user_id) DO UPDATE SET
            settings = ?4,
            updated_at = ?6
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(plugin_id)
    .bind(user_id)
    .bind(&settings_json)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get plugin settings for a user
pub async fn get_plugin_settings(
    pool: &SqlitePool,
    plugin_id: &str,
    user_id: &str,
) -> Result<Option<serde_json::Value>> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT settings FROM plugin_settings
        WHERE plugin_id = ?1 AND user_id = ?2
        "#,
    )
    .bind(plugin_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((settings_json,)) => {
            let settings: serde_json::Value = serde_json::from_str(&settings_json)?;
            Ok(Some(settings))
        }
        None => Ok(None),
    }
}

/// Delete plugin settings for a user
pub async fn delete_plugin_settings(pool: &SqlitePool, plugin_id: &str, user_id: &str) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM plugin_settings
        WHERE plugin_id = ?1 AND user_id = ?2
        "#,
    )
    .bind(plugin_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get all settings for a plugin (admin use)
pub async fn get_all_plugin_settings(pool: &SqlitePool, plugin_id: &str) -> Result<Vec<PluginSettings>> {
    let settings = sqlx::query_as::<_, PluginSettings>(
        r#"
        SELECT id, plugin_id, user_id, settings, created_at, updated_at
        FROM plugin_settings
        WHERE plugin_id = ?1
        ORDER BY updated_at DESC
        "#,
    )
    .bind(plugin_id)
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

/// Search plugins by name or description
pub async fn search_plugins(pool: &SqlitePool, query: &str) -> Result<Vec<InstalledPlugin>> {
    let search_term = format!("%{}%", query);

    let plugins = sqlx::query_as::<_, InstalledPlugin>(
        r#"
        SELECT id, plugin_id, name, version, plugin_type, status, manifest,
               install_path, installed_by, installed_at, updated_at, error_message, checksum
        FROM plugins
        WHERE name LIKE ?1 OR manifest LIKE ?1
        ORDER BY name ASC
        "#,
    )
    .bind(&search_term)
    .fetch_all(pool)
    .await?;

    Ok(plugins)
}
