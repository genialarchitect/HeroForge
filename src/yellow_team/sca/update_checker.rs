//! Update Checker
//!
//! Checks for available updates from package registries and
//! provides recommendations for updating dependencies.

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 15;

// ============================================================================
// Types
// ============================================================================

/// Type of update available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateType {
    Patch,  // Bug fixes only (1.2.3 -> 1.2.4)
    Minor,  // New features, backward compatible (1.2.3 -> 1.3.0)
    Major,  // Breaking changes (1.2.3 -> 2.0.0)
    None,   // Already at latest
}

impl std::fmt::Display for UpdateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateType::Patch => write!(f, "patch"),
            UpdateType::Minor => write!(f, "minor"),
            UpdateType::Major => write!(f, "major"),
            UpdateType::None => write!(f, "none"),
        }
    }
}

/// Recommendation for updating a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRecommendation {
    pub package_name: String,
    pub current_version: String,
    pub latest_version: String,
    pub update_type: UpdateType,
    pub fixes_vulnerabilities: bool,
    pub vulnerability_count: i32,
    pub breaking_changes: bool,
    pub changelog_url: Option<String>,
    pub release_date: Option<String>,
}

// ============================================================================
// Registry Response Types
// ============================================================================

/// NPM registry response
#[derive(Debug, Deserialize)]
struct NpmPackageInfo {
    #[serde(rename = "dist-tags")]
    dist_tags: Option<NpmDistTags>,
    #[serde(default)]
    versions: std::collections::HashMap<String, serde_json::Value>,
    time: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

/// PyPI registry response
#[derive(Debug, Deserialize)]
struct PypiPackageInfo {
    info: PypiInfo,
    releases: std::collections::HashMap<String, Vec<PypiRelease>>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PypiRelease {
    upload_time: Option<String>,
}

/// crates.io registry response
#[derive(Debug, Deserialize)]
struct CratesIoResponse {
    #[serde(rename = "crate")]
    crate_info: CrateInfo,
    versions: Vec<CrateVersion>,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    max_version: Option<String>,
    max_stable_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CrateVersion {
    num: String,
    created_at: Option<String>,
    yanked: bool,
}

/// RubyGems response
#[derive(Debug, Deserialize)]
struct RubyGemsInfo {
    version: Option<String>,
    version_created_at: Option<String>,
}

/// NuGet response
#[derive(Debug, Deserialize)]
struct NuGetSearchResponse {
    data: Vec<NuGetPackage>,
}

#[derive(Debug, Deserialize)]
struct NuGetPackage {
    version: Option<String>,
}

// ============================================================================
// Update Checker
// ============================================================================

/// Checks for available updates from package registries
pub struct UpdateChecker {
    client: Client,
}

impl UpdateChecker {
    /// Create a new update checker
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .user_agent("HeroForge-SCA/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    /// Check the latest version for a package
    pub async fn check_latest_version(
        &self,
        package_name: &str,
        ecosystem: &str,
    ) -> Result<Option<String>> {
        match ecosystem.to_lowercase().as_str() {
            "npm" => self.check_npm_latest(package_name).await,
            "pypi" => self.check_pypi_latest(package_name).await,
            "crates.io" | "cargo" => self.check_crates_io_latest(package_name).await,
            "rubygems" | "gem" => self.check_rubygems_latest(package_name).await,
            "nuget" => self.check_nuget_latest(package_name).await,
            "maven" => self.check_maven_latest(package_name).await,
            "go" => self.check_go_latest(package_name).await,
            "packagist" | "composer" => self.check_packagist_latest(package_name).await,
            _ => Ok(None),
        }
    }

    /// Get update recommendation for a package
    pub async fn get_update_recommendation(
        &self,
        package_name: &str,
        current_version: &str,
        ecosystem: &str,
    ) -> Result<Option<UpdateRecommendation>> {
        let latest = match self.check_latest_version(package_name, ecosystem).await? {
            Some(v) => v,
            None => return Ok(None),
        };

        // Determine update type
        let update_type = determine_update_type(current_version, &latest);

        if update_type == UpdateType::None {
            return Ok(None);
        }

        Ok(Some(UpdateRecommendation {
            package_name: package_name.to_string(),
            current_version: current_version.to_string(),
            latest_version: latest,
            update_type,
            fixes_vulnerabilities: false, // Would need to check against vulns
            vulnerability_count: 0,
            breaking_changes: update_type == UpdateType::Major,
            changelog_url: None,
            release_date: None,
        }))
    }

    /// Check NPM registry for latest version
    async fn check_npm_latest(&self, package_name: &str) -> Result<Option<String>> {
        let url = format!("https://registry.npmjs.org/{}", urlencoding::encode(package_name));

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let info: NpmPackageInfo = response.json().await?;
        Ok(info.dist_tags.and_then(|d| d.latest))
    }

    /// Check PyPI registry for latest version
    async fn check_pypi_latest(&self, package_name: &str) -> Result<Option<String>> {
        let url = format!("https://pypi.org/pypi/{}/json", urlencoding::encode(package_name));

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let info: PypiPackageInfo = response.json().await?;
        Ok(info.info.version)
    }

    /// Check crates.io for latest version
    async fn check_crates_io_latest(&self, package_name: &str) -> Result<Option<String>> {
        let url = format!("https://crates.io/api/v1/crates/{}", urlencoding::encode(package_name));

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let info: CratesIoResponse = response.json().await?;

        // Prefer max_stable_version over max_version
        Ok(info.crate_info.max_stable_version.or(info.crate_info.max_version))
    }

    /// Check RubyGems for latest version
    async fn check_rubygems_latest(&self, package_name: &str) -> Result<Option<String>> {
        let url = format!("https://rubygems.org/api/v1/gems/{}.json", urlencoding::encode(package_name));

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let info: RubyGemsInfo = response.json().await?;
        Ok(info.version)
    }

    /// Check NuGet for latest version
    async fn check_nuget_latest(&self, package_name: &str) -> Result<Option<String>> {
        let url = format!(
            "https://api.nuget.org/v3/registration5-gz-semver2/{}/index.json",
            package_name.to_lowercase()
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            // Try search API as fallback
            return self.check_nuget_latest_search(package_name).await;
        }

        // Parse the registration index for latest version
        let json: serde_json::Value = response.json().await?;

        // Navigate the catalog to find latest version
        if let Some(items) = json.get("items").and_then(|v| v.as_array()) {
            if let Some(last_page) = items.last() {
                if let Some(page_items) = last_page.get("items").and_then(|v| v.as_array()) {
                    if let Some(last_item) = page_items.last() {
                        if let Some(catalog_entry) = last_item.get("catalogEntry") {
                            if let Some(version) = catalog_entry.get("version").and_then(|v| v.as_str()) {
                                return Ok(Some(version.to_string()));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Fallback NuGet search
    async fn check_nuget_latest_search(&self, package_name: &str) -> Result<Option<String>> {
        let url = format!(
            "https://api.nuget.org/v3/query?q=packageid:{}&take=1",
            urlencoding::encode(package_name)
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let info: NuGetSearchResponse = response.json().await?;
        Ok(info.data.first().and_then(|p| p.version.clone()))
    }

    /// Check Maven Central for latest version
    async fn check_maven_latest(&self, package_name: &str) -> Result<Option<String>> {
        // Maven coordinates are usually group:artifact
        let parts: Vec<&str> = package_name.split(':').collect();
        let (group_id, artifact_id) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            // Try to use as artifact ID with common group patterns
            return Ok(None);
        };

        let url = format!(
            "https://search.maven.org/solrsearch/select?q=g:{}+AND+a:{}&rows=1&wt=json",
            urlencoding::encode(group_id),
            urlencoding::encode(artifact_id)
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let json: serde_json::Value = response.json().await?;

        if let Some(docs) = json.pointer("/response/docs").and_then(|v| v.as_array()) {
            if let Some(first) = docs.first() {
                if let Some(version) = first.get("latestVersion").and_then(|v| v.as_str()) {
                    return Ok(Some(version.to_string()));
                }
            }
        }

        Ok(None)
    }

    /// Check Go module proxy for latest version
    async fn check_go_latest(&self, package_name: &str) -> Result<Option<String>> {
        // Go modules use proxy.golang.org
        let url = format!("https://proxy.golang.org/{}/@latest", package_name);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let json: serde_json::Value = response.json().await?;

        if let Some(version) = json.get("Version").and_then(|v| v.as_str()) {
            return Ok(Some(version.trim_start_matches('v').to_string()));
        }

        Ok(None)
    }

    /// Check Packagist for latest version
    async fn check_packagist_latest(&self, package_name: &str) -> Result<Option<String>> {
        let url = format!("https://repo.packagist.org/p2/{}.json", package_name);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let json: serde_json::Value = response.json().await?;

        // Packagist returns packages.vendor/name array
        if let Some(packages) = json.get("packages").and_then(|p| p.get(package_name)).and_then(|v| v.as_array()) {
            // Find the latest non-dev version
            for pkg in packages {
                if let Some(version) = pkg.get("version").and_then(|v| v.as_str()) {
                    // Skip dev versions
                    if !version.contains("dev") {
                        return Ok(Some(version.trim_start_matches('v').to_string()));
                    }
                }
            }
        }

        Ok(None)
    }
}

impl Default for UpdateChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Version Comparison Helpers
// ============================================================================

/// Determine the type of update based on version comparison
fn determine_update_type(current: &str, latest: &str) -> UpdateType {
    let current = current.trim_start_matches('v');
    let latest = latest.trim_start_matches('v');

    if current == latest {
        return UpdateType::None;
    }

    // Parse versions
    let current_parts: Vec<u32> = current
        .split('.')
        .filter_map(|s| s.split('-').next())
        .filter_map(|s| s.parse().ok())
        .collect();

    let latest_parts: Vec<u32> = latest
        .split('.')
        .filter_map(|s| s.split('-').next())
        .filter_map(|s| s.parse().ok())
        .collect();

    if current_parts.is_empty() || latest_parts.is_empty() {
        // Can't parse, assume major
        return UpdateType::Major;
    }

    let cur_major = current_parts.first().copied().unwrap_or(0);
    let lat_major = latest_parts.first().copied().unwrap_or(0);
    let cur_minor = current_parts.get(1).copied().unwrap_or(0);
    let lat_minor = latest_parts.get(1).copied().unwrap_or(0);

    if lat_major > cur_major {
        UpdateType::Major
    } else if lat_minor > cur_minor {
        UpdateType::Minor
    } else {
        UpdateType::Patch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_update_type() {
        assert_eq!(determine_update_type("1.0.0", "1.0.0"), UpdateType::None);
        assert_eq!(determine_update_type("1.0.0", "1.0.1"), UpdateType::Patch);
        assert_eq!(determine_update_type("1.0.0", "1.1.0"), UpdateType::Minor);
        assert_eq!(determine_update_type("1.0.0", "2.0.0"), UpdateType::Major);
        assert_eq!(determine_update_type("v1.0.0", "v2.0.0"), UpdateType::Major);
    }

    #[tokio::test]
    async fn test_update_checker_creation() {
        let checker = UpdateChecker::new();
        // Just verify it can be created
        assert!(true);
    }
}
