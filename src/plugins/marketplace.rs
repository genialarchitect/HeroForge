//! Plugin marketplace for discovery and installation
//!
//! This module provides:
//! - Searching the HeroForge plugin marketplace
//! - Installing plugins from the marketplace
//! - Updating plugins to the latest version
//! - Marketplace metadata and statistics

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default marketplace URL
const DEFAULT_MARKETPLACE_URL: &str = "https://marketplace.heroforge.io/api/v1";

/// Marketplace plugin listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePlugin {
    /// Unique plugin identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Current version (semver)
    pub version: String,
    /// Plugin author or organization
    pub author: String,
    /// Short description
    pub description: String,
    /// Average user rating (0.0 - 5.0)
    pub rating: f32,
    /// Total download count
    pub downloads: u64,
    /// Whether the plugin is HeroForge certified
    pub certified: bool,
    /// Plugin type (scanner, detector, reporter, integration)
    #[serde(default)]
    pub plugin_type: String,
    /// Search tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Plugin homepage URL
    #[serde(default)]
    pub homepage: Option<String>,
    /// Plugin repository URL
    #[serde(default)]
    pub repository: Option<String>,
    /// Plugin license
    #[serde(default)]
    pub license: Option<String>,
    /// Download URL for the plugin package
    #[serde(default)]
    pub download_url: Option<String>,
    /// Last updated timestamp
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    /// Creation timestamp
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

/// Search filters for marketplace queries
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MarketplaceSearchFilters {
    /// Filter by plugin type
    pub plugin_type: Option<String>,
    /// Filter by certified status
    pub certified_only: Option<bool>,
    /// Minimum rating threshold
    pub min_rating: Option<f32>,
    /// Filter by tags (any match)
    pub tags: Option<Vec<String>>,
    /// Filter by author
    pub author: Option<String>,
    /// Sort field
    pub sort_by: Option<MarketplaceSortField>,
    /// Sort direction
    pub sort_order: Option<SortOrder>,
    /// Page number (1-indexed)
    pub page: Option<u32>,
    /// Results per page
    pub per_page: Option<u32>,
}

/// Sort fields for marketplace search
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceSortField {
    Downloads,
    Rating,
    UpdatedAt,
    CreatedAt,
    Name,
}

/// Sort order
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    Asc,
    Desc,
}

/// Marketplace search response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceSearchResponse {
    /// List of matching plugins
    pub plugins: Vec<MarketplacePlugin>,
    /// Total number of results
    pub total: u64,
    /// Current page
    pub page: u32,
    /// Results per page
    pub per_page: u32,
    /// Total pages
    pub total_pages: u32,
}

/// Marketplace plugin details (extended info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePluginDetails {
    /// Base plugin info
    #[serde(flatten)]
    pub plugin: MarketplacePlugin,
    /// Full description (markdown)
    pub full_description: Option<String>,
    /// Screenshots URLs
    pub screenshots: Vec<String>,
    /// Changelog
    pub changelog: Option<String>,
    /// Version history
    pub versions: Vec<MarketplacePluginVersion>,
    /// Dependencies
    pub dependencies: Vec<String>,
    /// Required permissions
    pub permissions: Vec<String>,
    /// Minimum HeroForge version
    pub min_heroforge_version: Option<String>,
}

/// Plugin version entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePluginVersion {
    /// Version string
    pub version: String,
    /// Download URL
    pub download_url: String,
    /// Release date
    pub released_at: DateTime<Utc>,
    /// Changelog for this version
    pub changelog: Option<String>,
    /// File checksum (SHA256)
    pub checksum: String,
    /// File size in bytes
    pub size: u64,
}

/// Marketplace statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceStats {
    /// Total plugins available
    pub total_plugins: u64,
    /// Total downloads across all plugins
    pub total_downloads: u64,
    /// Number of certified plugins
    pub certified_plugins: u64,
    /// Number of unique authors
    pub unique_authors: u64,
    /// Popular tags
    pub popular_tags: Vec<TagStats>,
    /// Recently updated plugins
    pub recently_updated: Vec<MarketplacePlugin>,
    /// Most popular plugins
    pub most_popular: Vec<MarketplacePlugin>,
}

/// Tag statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagStats {
    pub tag: String,
    pub count: u64,
}

/// Plugin marketplace client
pub struct PluginMarketplace {
    /// HTTP client
    client: Client,
    /// Base URL for marketplace API
    base_url: String,
    /// API key for authenticated requests
    api_key: Option<String>,
}

impl PluginMarketplace {
    /// Create a new marketplace client with default URL
    pub fn new() -> Self {
        Self::with_url(DEFAULT_MARKETPLACE_URL)
    }

    /// Create a marketplace client with a custom URL
    pub fn with_url(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(format!("HeroForge/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: None,
        }
    }

    /// Set API key for authenticated marketplace access
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Search the marketplace for plugins
    pub async fn search(&self, query: &str) -> Result<Vec<MarketplacePlugin>> {
        self.search_with_filters(query, MarketplaceSearchFilters::default())
            .await
            .map(|r| r.plugins)
    }

    /// Search marketplace with filters
    pub async fn search_with_filters(
        &self,
        query: &str,
        filters: MarketplaceSearchFilters,
    ) -> Result<MarketplaceSearchResponse> {
        let mut url = format!("{}/plugins/search", self.base_url);

        // Build query parameters
        let mut params = vec![("q", query.to_string())];

        if let Some(plugin_type) = filters.plugin_type {
            params.push(("type", plugin_type));
        }
        if let Some(certified) = filters.certified_only {
            params.push(("certified", certified.to_string()));
        }
        if let Some(rating) = filters.min_rating {
            params.push(("min_rating", rating.to_string()));
        }
        if let Some(author) = filters.author {
            params.push(("author", author));
        }
        if let Some(tags) = filters.tags {
            params.push(("tags", tags.join(",")));
        }
        if let Some(sort_by) = filters.sort_by {
            params.push((
                "sort_by",
                match sort_by {
                    MarketplaceSortField::Downloads => "downloads",
                    MarketplaceSortField::Rating => "rating",
                    MarketplaceSortField::UpdatedAt => "updated_at",
                    MarketplaceSortField::CreatedAt => "created_at",
                    MarketplaceSortField::Name => "name",
                }
                .to_string(),
            ));
        }
        if let Some(order) = filters.sort_order {
            params.push((
                "order",
                match order {
                    SortOrder::Asc => "asc",
                    SortOrder::Desc => "desc",
                }
                .to_string(),
            ));
        }
        if let Some(page) = filters.page {
            params.push(("page", page.to_string()));
        }
        if let Some(per_page) = filters.per_page {
            params.push(("per_page", per_page.to_string()));
        }

        let mut request = self.client.get(&url).query(&params);

        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .send()
            .await
            .context("Failed to connect to marketplace")?;

        if !response.status().is_success() {
            // If marketplace is unavailable, return empty results with offline fallback
            if response.status().as_u16() == 503 || response.status().as_u16() == 502 {
                log::warn!("Marketplace unavailable, returning empty results");
                return Ok(MarketplaceSearchResponse {
                    plugins: vec![],
                    total: 0,
                    page: 1,
                    per_page: 20,
                    total_pages: 0,
                });
            }
            anyhow::bail!(
                "Marketplace search failed: {} - {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }

        response
            .json::<MarketplaceSearchResponse>()
            .await
            .context("Failed to parse marketplace response")
    }

    /// Get detailed information about a specific plugin
    pub async fn get_plugin_details(&self, plugin_id: &str) -> Result<MarketplacePluginDetails> {
        let url = format!("{}/plugins/{}", self.base_url, plugin_id);

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await.context("Failed to get plugin details")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to get plugin details: {} - {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }

        response
            .json::<MarketplacePluginDetails>()
            .await
            .context("Failed to parse plugin details")
    }

    /// Download plugin package to a temporary file
    pub async fn download_plugin(&self, plugin_id: &str, version: Option<&str>) -> Result<Vec<u8>> {
        // Get plugin details to find download URL
        let details = self.get_plugin_details(plugin_id).await?;

        let download_url = if let Some(ver) = version {
            // Find specific version
            details
                .versions
                .iter()
                .find(|v| v.version == ver)
                .map(|v| v.download_url.clone())
                .ok_or_else(|| anyhow::anyhow!("Version {} not found for plugin {}", ver, plugin_id))?
        } else {
            // Use latest version (first in list) or fallback to base plugin URL
            details
                .versions
                .first()
                .map(|v| v.download_url.clone())
                .or(details.plugin.download_url)
                .ok_or_else(|| anyhow::anyhow!("No download URL available for plugin {}", plugin_id))?
        };

        let mut request = self.client.get(&download_url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .send()
            .await
            .context("Failed to download plugin")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to download plugin: {} - {}",
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }

        let bytes = response.bytes().await.context("Failed to read plugin data")?;
        Ok(bytes.to_vec())
    }

    /// Install a plugin from the marketplace
    pub async fn install(&self, plugin_id: &str) -> Result<()> {
        self.install_version(plugin_id, None).await
    }

    /// Install a specific version of a plugin from the marketplace
    pub async fn install_version(&self, plugin_id: &str, version: Option<&str>) -> Result<()> {
        // Download the plugin package
        let package_data = self.download_plugin(plugin_id, version).await?;

        // Write to temporary file
        let temp_dir = std::env::temp_dir().join("heroforge_marketplace");
        tokio::fs::create_dir_all(&temp_dir).await?;

        let temp_file = temp_dir.join(format!("{}.zip", plugin_id));
        tokio::fs::write(&temp_file, &package_data).await?;

        // Use the plugin loader to install
        let loader = super::loader::PluginLoader::new();
        loader.load_from_file(&temp_file).await?;

        // Clean up
        let _ = tokio::fs::remove_file(&temp_file).await;

        log::info!("Successfully installed plugin {} from marketplace", plugin_id);
        Ok(())
    }

    /// Update a plugin to the latest version
    pub async fn update(&self, plugin_id: &str) -> Result<()> {
        // Get current installed version
        let loader = super::loader::PluginLoader::new();
        let current_manifest = loader.load_installed_manifest(plugin_id)?;
        let current_version = &current_manifest.plugin.version;

        // Get latest version from marketplace
        let details = self.get_plugin_details(plugin_id).await?;
        let latest_version = details
            .versions
            .first()
            .map(|v| &v.version)
            .unwrap_or(&details.plugin.version);

        // Compare versions
        if latest_version == current_version {
            log::info!("Plugin {} is already at latest version {}", plugin_id, current_version);
            return Ok(());
        }

        if !is_newer_version(latest_version, current_version) {
            log::info!(
                "Installed version {} is newer than marketplace version {}",
                current_version,
                latest_version
            );
            return Ok(());
        }

        // Install the new version
        log::info!(
            "Updating plugin {} from {} to {}",
            plugin_id,
            current_version,
            latest_version
        );
        self.install(plugin_id).await?;

        log::info!("Successfully updated plugin {} to version {}", plugin_id, latest_version);
        Ok(())
    }

    /// Check for updates for installed plugins
    pub async fn check_updates(&self, installed_plugins: &[(&str, &str)]) -> Result<Vec<PluginUpdate>> {
        let mut updates = Vec::new();

        for (plugin_id, current_version) in installed_plugins {
            match self.get_plugin_details(plugin_id).await {
                Ok(details) => {
                    let latest_version = details
                        .versions
                        .first()
                        .map(|v| v.version.as_str())
                        .unwrap_or(&details.plugin.version);

                    if is_newer_version(latest_version, current_version) {
                        updates.push(PluginUpdate {
                            plugin_id: plugin_id.to_string(),
                            current_version: current_version.to_string(),
                            latest_version: latest_version.to_string(),
                            changelog: details
                                .versions
                                .first()
                                .and_then(|v| v.changelog.clone()),
                        });
                    }
                }
                Err(e) => {
                    log::warn!("Failed to check updates for plugin {}: {}", plugin_id, e);
                }
            }
        }

        Ok(updates)
    }

    /// Get marketplace statistics
    pub async fn get_stats(&self) -> Result<MarketplaceStats> {
        let url = format!("{}/stats", self.base_url);

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await.context("Failed to get marketplace stats")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to get marketplace stats: {}",
                response.status()
            );
        }

        response
            .json::<MarketplaceStats>()
            .await
            .context("Failed to parse marketplace stats")
    }

    /// Get featured/recommended plugins
    pub async fn get_featured(&self) -> Result<Vec<MarketplacePlugin>> {
        let url = format!("{}/plugins/featured", self.base_url);

        let mut request = self.client.get(&url);

        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await.context("Failed to get featured plugins")?;

        if !response.status().is_success() {
            return Ok(vec![]); // Return empty on error for featured plugins
        }

        response
            .json::<Vec<MarketplacePlugin>>()
            .await
            .context("Failed to parse featured plugins")
    }

    /// Get plugins by category/tag
    pub async fn get_by_tag(&self, tag: &str) -> Result<Vec<MarketplacePlugin>> {
        self.search_with_filters(
            "",
            MarketplaceSearchFilters {
                tags: Some(vec![tag.to_string()]),
                sort_by: Some(MarketplaceSortField::Downloads),
                sort_order: Some(SortOrder::Desc),
                ..Default::default()
            },
        )
        .await
        .map(|r| r.plugins)
    }
}

impl Default for PluginMarketplace {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin update information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginUpdate {
    pub plugin_id: String,
    pub current_version: String,
    pub latest_version: String,
    pub changelog: Option<String>,
}

/// Compare two semver versions, returns true if v1 > v2
fn is_newer_version(v1: &str, v2: &str) -> bool {
    let parse_version = |v: &str| -> (u32, u32, u32) {
        let parts: Vec<&str> = v.split('.').collect();
        let major = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let patch = parts
            .get(2)
            .and_then(|p| p.split('-').next())
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        (major, minor, patch)
    };

    let v1_parts = parse_version(v1);
    let v2_parts = parse_version(v2);

    v1_parts > v2_parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("2.0.0", "1.0.0"));
        assert!(is_newer_version("1.1.0", "1.0.0"));
        assert!(is_newer_version("1.0.1", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "1.0.0"));
        assert!(!is_newer_version("1.0.0", "2.0.0"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(is_newer_version("2.1.0-alpha", "2.0.0"));
    }

    #[test]
    fn test_marketplace_plugin_serialization() {
        let plugin = MarketplacePlugin {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "Test Author".to_string(),
            description: "A test plugin".to_string(),
            rating: 4.5,
            downloads: 1000,
            certified: true,
            plugin_type: "scanner".to_string(),
            tags: vec!["network".to_string(), "security".to_string()],
            homepage: Some("https://example.com".to_string()),
            repository: None,
            license: Some("MIT".to_string()),
            download_url: Some("https://example.com/plugin.zip".to_string()),
            updated_at: None,
            created_at: None,
        };

        let json = serde_json::to_string(&plugin).unwrap();
        let parsed: MarketplacePlugin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test-plugin");
        assert_eq!(parsed.rating, 4.5);
    }

    #[test]
    fn test_search_filters_default() {
        let filters = MarketplaceSearchFilters::default();
        assert!(filters.plugin_type.is_none());
        assert!(filters.certified_only.is_none());
        assert!(filters.min_rating.is_none());
    }
}
