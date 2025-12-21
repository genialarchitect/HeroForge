//! Plugin Registry for managing installed plugins
//!
//! This module provides:
//! - Tracking of installed plugins
//! - Plugin enable/disable functionality
//! - Plugin status management
//! - Plugin settings management

#![allow(dead_code)]

use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::loader::{LoadedPlugin, PluginLoader};
use super::types::{InstalledPlugin, PluginManifest, PluginStatus, PluginType};

/// Plugin registry for managing installed plugins
pub struct PluginRegistry {
    /// Database pool
    pool: SqlitePool,

    /// Plugin loader
    loader: PluginLoader,

    /// In-memory cache of loaded plugins (plugin_id -> manifest)
    cache: Arc<RwLock<HashMap<String, PluginManifest>>>,
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new(pool: SqlitePool, loader: PluginLoader) -> Self {
        Self {
            pool,
            loader,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a plugin registry with default loader
    pub fn with_default_loader(pool: SqlitePool) -> Self {
        Self::new(pool, PluginLoader::new())
    }

    /// Initialize the registry by loading all enabled plugins into cache
    pub async fn initialize(&self) -> Result<()> {
        self.loader.ensure_directories().await?;

        // Load all enabled plugins from database
        let plugins = crate::db::plugins::get_enabled_plugins(&self.pool).await?;

        let mut cache = self.cache.write().await;
        for plugin in plugins {
            if let Ok(manifest) = serde_json::from_str::<PluginManifest>(&plugin.manifest) {
                cache.insert(plugin.plugin_id, manifest);
            }
        }

        log::info!("Plugin registry initialized with {} plugins", cache.len());
        Ok(())
    }

    /// Install a plugin from a file
    pub async fn install_from_file(
        &self,
        path: &std::path::Path,
        user_id: &str,
        enable: bool,
    ) -> Result<InstalledPlugin> {
        // Load and validate the plugin
        let loaded = self.loader.load_from_file(path).await?;

        // Check if plugin is already installed
        if let Some(existing) = crate::db::plugins::get_plugin_by_plugin_id(&self.pool, &loaded.manifest.plugin.id).await? {
            // Update existing plugin
            return self.update_plugin(&existing.id, loaded, user_id).await;
        }

        // Insert into database
        let status = if enable {
            PluginStatus::Enabled
        } else {
            PluginStatus::Disabled
        };

        let plugin = crate::db::plugins::install_plugin(
            &self.pool,
            &loaded.manifest,
            loaded.install_path.to_string_lossy().as_ref(),
            user_id,
            status,
            &loaded.checksum,
        )
        .await?;

        // Add to cache if enabled
        if enable {
            let mut cache = self.cache.write().await;
            cache.insert(loaded.manifest.plugin.id.clone(), loaded.manifest);
        }

        log::info!("Installed plugin: {}", plugin.plugin_id);
        Ok(plugin)
    }

    /// Install a plugin from a URL
    pub async fn install_from_url(
        &self,
        url: &str,
        user_id: &str,
        enable: bool,
    ) -> Result<InstalledPlugin> {
        // Download and load the plugin
        let loaded = self.loader.load_from_url(url).await?;

        // Check if plugin is already installed
        if let Some(existing) = crate::db::plugins::get_plugin_by_plugin_id(&self.pool, &loaded.manifest.plugin.id).await? {
            // Update existing plugin
            return self.update_plugin(&existing.id, loaded, user_id).await;
        }

        // Insert into database
        let status = if enable {
            PluginStatus::Enabled
        } else {
            PluginStatus::Disabled
        };

        let plugin = crate::db::plugins::install_plugin(
            &self.pool,
            &loaded.manifest,
            loaded.install_path.to_string_lossy().as_ref(),
            user_id,
            status,
            &loaded.checksum,
        )
        .await?;

        // Add to cache if enabled
        if enable {
            let mut cache = self.cache.write().await;
            cache.insert(loaded.manifest.plugin.id.clone(), loaded.manifest);
        }

        log::info!("Installed plugin from URL: {}", plugin.plugin_id);
        Ok(plugin)
    }

    /// Update an existing plugin
    async fn update_plugin(
        &self,
        id: &str,
        loaded: LoadedPlugin,
        user_id: &str,
    ) -> Result<InstalledPlugin> {
        // Update database record
        let plugin = crate::db::plugins::update_plugin(
            &self.pool,
            id,
            &loaded.manifest,
            loaded.install_path.to_string_lossy().as_ref(),
            &loaded.checksum,
        )
        .await?;

        // Update cache
        let mut cache = self.cache.write().await;
        if plugin.status == PluginStatus::Enabled.to_string() {
            cache.insert(loaded.manifest.plugin.id.clone(), loaded.manifest);
        }

        log::info!("Updated plugin: {} by user {}", plugin.plugin_id, user_id);
        Ok(plugin)
    }

    /// Uninstall a plugin
    pub async fn uninstall(&self, id: &str) -> Result<()> {
        // Get the plugin first
        let plugin = crate::db::plugins::get_plugin_by_id(&self.pool, id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Plugin not found"))?;

        // Remove from disk
        self.loader.uninstall(&plugin.plugin_id).await?;

        // Remove from database
        crate::db::plugins::delete_plugin(&self.pool, id).await?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(&plugin.plugin_id);

        log::info!("Uninstalled plugin: {}", plugin.plugin_id);
        Ok(())
    }

    /// Enable a plugin
    pub async fn enable(&self, id: &str) -> Result<InstalledPlugin> {
        let plugin = crate::db::plugins::update_plugin_status(&self.pool, id, PluginStatus::Enabled).await?;

        // Load manifest into cache
        if let Ok(manifest) = serde_json::from_str::<PluginManifest>(&plugin.manifest) {
            let mut cache = self.cache.write().await;
            cache.insert(plugin.plugin_id.clone(), manifest);
        }

        log::info!("Enabled plugin: {}", plugin.plugin_id);
        Ok(plugin)
    }

    /// Disable a plugin
    pub async fn disable(&self, id: &str) -> Result<InstalledPlugin> {
        let plugin = crate::db::plugins::update_plugin_status(&self.pool, id, PluginStatus::Disabled).await?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(&plugin.plugin_id);

        log::info!("Disabled plugin: {}", plugin.plugin_id);
        Ok(plugin)
    }

    /// Set plugin error status
    pub async fn set_error(&self, id: &str, error_message: &str) -> Result<InstalledPlugin> {
        let plugin = crate::db::plugins::set_plugin_error(&self.pool, id, error_message).await?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(&plugin.plugin_id);

        log::warn!("Plugin {} error: {}", plugin.plugin_id, error_message);
        Ok(plugin)
    }

    /// Get a plugin by ID
    pub async fn get(&self, id: &str) -> Result<Option<InstalledPlugin>> {
        crate::db::plugins::get_plugin_by_id(&self.pool, id).await
    }

    /// Get a plugin by plugin ID (from manifest)
    pub async fn get_by_plugin_id(&self, plugin_id: &str) -> Result<Option<InstalledPlugin>> {
        crate::db::plugins::get_plugin_by_plugin_id(&self.pool, plugin_id).await
    }

    /// List all installed plugins
    pub async fn list(&self) -> Result<Vec<InstalledPlugin>> {
        crate::db::plugins::list_plugins(&self.pool).await
    }

    /// List plugins by type
    pub async fn list_by_type(&self, plugin_type: PluginType) -> Result<Vec<InstalledPlugin>> {
        crate::db::plugins::list_plugins_by_type(&self.pool, plugin_type).await
    }

    /// List enabled plugins
    pub async fn list_enabled(&self) -> Result<Vec<InstalledPlugin>> {
        crate::db::plugins::get_enabled_plugins(&self.pool).await
    }

    /// List enabled plugins by type
    pub async fn list_enabled_by_type(&self, plugin_type: PluginType) -> Result<Vec<InstalledPlugin>> {
        crate::db::plugins::get_enabled_plugins_by_type(&self.pool, plugin_type).await
    }

    /// Get the manifest for an enabled plugin from cache
    pub async fn get_manifest(&self, plugin_id: &str) -> Option<PluginManifest> {
        let cache = self.cache.read().await;
        cache.get(plugin_id).cloned()
    }

    /// Get all enabled plugin manifests from cache
    pub async fn get_all_manifests(&self) -> HashMap<String, PluginManifest> {
        let cache = self.cache.read().await;
        cache.clone()
    }

    /// Get plugin count
    pub async fn count(&self) -> Result<PluginCount> {
        crate::db::plugins::get_plugin_count(&self.pool).await
    }

    /// Update plugin settings for a user
    pub async fn update_settings(
        &self,
        plugin_id: &str,
        user_id: &str,
        settings: serde_json::Value,
    ) -> Result<()> {
        crate::db::plugins::update_plugin_settings(&self.pool, plugin_id, user_id, settings).await
    }

    /// Get plugin settings for a user
    pub async fn get_settings(
        &self,
        plugin_id: &str,
        user_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        crate::db::plugins::get_plugin_settings(&self.pool, plugin_id, user_id).await
    }

    /// Delete plugin settings for a user
    pub async fn delete_settings(&self, plugin_id: &str, user_id: &str) -> Result<()> {
        crate::db::plugins::delete_plugin_settings(&self.pool, plugin_id, user_id).await
    }
}

/// Plugin count statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginCount {
    pub total: i64,
    pub enabled: i64,
    pub disabled: i64,
    pub error: i64,
    pub by_type: HashMap<String, i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests would require a database setup
    // These are unit tests for basic functionality

    #[test]
    fn test_plugin_count_serialization() {
        let count = PluginCount {
            total: 5,
            enabled: 3,
            disabled: 1,
            error: 1,
            by_type: HashMap::from([
                ("scanner".to_string(), 2),
                ("detector".to_string(), 2),
                ("integration".to_string(), 1),
            ]),
        };

        let json = serde_json::to_string(&count).unwrap();
        let parsed: PluginCount = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total, 5);
        assert_eq!(parsed.enabled, 3);
    }
}
