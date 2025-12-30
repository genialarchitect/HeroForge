//! API versioning and deprecation management

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// API version identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ApiVersion {
    /// Create a new API version
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Parse version from string (e.g., "v1", "v2.1", "v1.2.3")
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim_start_matches('v');
        let parts: Vec<&str> = s.split('.').collect();

        match parts.len() {
            1 => Ok(Self::new(parts[0].parse()?, 0, 0)),
            2 => Ok(Self::new(parts[0].parse()?, parts[1].parse()?, 0)),
            3 => Ok(Self::new(parts[0].parse()?, parts[1].parse()?, parts[2].parse()?)),
            _ => Err(anyhow!("Invalid version format: {}", s)),
        }
    }

    /// Convert to path component (e.g., "v1", "v2")
    pub fn to_path(&self) -> String {
        format!("v{}", self.major)
    }

    /// Convert to full version string
    pub fn to_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// API version status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionStatus {
    /// Active and fully supported
    Active,
    /// Deprecated but still functional
    Deprecated,
    /// Scheduled for removal
    Sunset,
    /// Removed
    Removed,
}

/// API version metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub version: ApiVersion,
    pub status: VersionStatus,
    pub release_date: chrono::DateTime<chrono::Utc>,
    pub deprecation_date: Option<chrono::DateTime<chrono::Utc>>,
    pub sunset_date: Option<chrono::DateTime<chrono::Utc>>,
    pub removal_date: Option<chrono::DateTime<chrono::Utc>>,
    pub migration_guide_url: Option<String>,
    pub changelog_url: Option<String>,
    pub breaking_changes: Vec<String>,
}

/// Version manager
pub struct VersionManager {
    versions: Arc<RwLock<HashMap<ApiVersion, VersionMetadata>>>,
    default_version: Arc<RwLock<ApiVersion>>,
}

impl VersionManager {
    /// Create a new version manager
    pub fn new() -> Self {
        Self {
            versions: Arc::new(RwLock::new(HashMap::new())),
            default_version: Arc::new(RwLock::new(ApiVersion::new(1, 0, 0))),
        }
    }

    /// Register a new API version
    pub async fn register_version(&self, metadata: VersionMetadata) -> Result<()> {
        let mut versions = self.versions.write().await;
        versions.insert(metadata.version.clone(), metadata);
        Ok(())
    }

    /// Get version metadata
    pub async fn get_version(&self, version: &ApiVersion) -> Result<VersionMetadata> {
        let versions = self.versions.read().await;
        versions.get(version)
            .cloned()
            .ok_or_else(|| anyhow!("Version not found: {}", version.to_string()))
    }

    /// Set default version
    pub async fn set_default_version(&self, version: ApiVersion) -> Result<()> {
        let mut default = self.default_version.write().await;
        *default = version;
        Ok(())
    }

    /// Get default version
    pub async fn get_default_version(&self) -> ApiVersion {
        self.default_version.read().await.clone()
    }

    /// Get all active versions
    pub async fn get_active_versions(&self) -> Vec<VersionMetadata> {
        let versions = self.versions.read().await;
        versions.values()
            .filter(|v| v.status == VersionStatus::Active)
            .cloned()
            .collect()
    }

    /// Get all versions
    pub async fn get_all_versions(&self) -> Vec<VersionMetadata> {
        let versions = self.versions.read().await;
        versions.values().cloned().collect()
    }

    /// Deprecate a version
    pub async fn deprecate_version(
        &self,
        version: &ApiVersion,
        deprecation_date: chrono::DateTime<chrono::Utc>,
        sunset_date: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let mut versions = self.versions.write().await;
        let metadata = versions.get_mut(version)
            .ok_or_else(|| anyhow!("Version not found"))?;

        metadata.status = VersionStatus::Deprecated;
        metadata.deprecation_date = Some(deprecation_date);
        metadata.sunset_date = Some(sunset_date);

        Ok(())
    }

    /// Mark version as sunset (scheduled for removal)
    pub async fn sunset_version(
        &self,
        version: &ApiVersion,
        removal_date: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let mut versions = self.versions.write().await;
        let metadata = versions.get_mut(version)
            .ok_or_else(|| anyhow!("Version not found"))?;

        metadata.status = VersionStatus::Sunset;
        metadata.removal_date = Some(removal_date);

        Ok(())
    }

    /// Check if a version is available
    pub async fn is_version_available(&self, version: &ApiVersion) -> bool {
        let versions = self.versions.read().await;
        versions.get(version)
            .map(|v| v.status != VersionStatus::Removed)
            .unwrap_or(false)
    }

    /// Parse version from request headers
    pub fn parse_version_from_header(&self, header_value: &str) -> Result<ApiVersion> {
        ApiVersion::parse(header_value)
    }

    /// Parse version from URL path
    pub fn parse_version_from_path(&self, path: &str) -> Result<ApiVersion> {
        // Extract version from path like "/api/v2/scans"
        if let Some(start) = path.find("/v") {
            let version_part = &path[start + 1..];
            let version_str = version_part
                .split('/')
                .next()
                .ok_or_else(|| anyhow!("Invalid version path"))?;
            ApiVersion::parse(version_str)
        } else {
            Err(anyhow!("No version found in path"))
        }
    }
}

impl Default for VersionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Versioning strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersioningStrategy {
    /// Version in URL path (/api/v1/resource)
    UrlPath,
    /// Version in Accept header (Accept: application/vnd.heroforge.v1+json)
    AcceptHeader,
    /// Version in custom header (X-API-Version: 1)
    CustomHeader,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        assert_eq!(ApiVersion::parse("v1").unwrap(), ApiVersion::new(1, 0, 0));
        assert_eq!(ApiVersion::parse("v2.1").unwrap(), ApiVersion::new(2, 1, 0));
        assert_eq!(ApiVersion::parse("v1.2.3").unwrap(), ApiVersion::new(1, 2, 3));
    }

    #[tokio::test]
    async fn test_version_registration() {
        let manager = VersionManager::new();

        let metadata = VersionMetadata {
            version: ApiVersion::new(1, 0, 0),
            status: VersionStatus::Active,
            release_date: chrono::Utc::now(),
            deprecation_date: None,
            sunset_date: None,
            removal_date: None,
            migration_guide_url: None,
            changelog_url: None,
            breaking_changes: vec![],
        };

        manager.register_version(metadata.clone()).await.unwrap();

        let retrieved = manager.get_version(&ApiVersion::new(1, 0, 0)).await.unwrap();
        assert_eq!(retrieved.status, VersionStatus::Active);
    }

    #[tokio::test]
    async fn test_version_deprecation() {
        let manager = VersionManager::new();

        let metadata = VersionMetadata {
            version: ApiVersion::new(1, 0, 0),
            status: VersionStatus::Active,
            release_date: chrono::Utc::now(),
            deprecation_date: None,
            sunset_date: None,
            removal_date: None,
            migration_guide_url: None,
            changelog_url: None,
            breaking_changes: vec![],
        };

        manager.register_version(metadata).await.unwrap();

        let now = chrono::Utc::now();
        let sunset = now + chrono::Duration::days(90);

        manager.deprecate_version(&ApiVersion::new(1, 0, 0), now, sunset).await.unwrap();

        let retrieved = manager.get_version(&ApiVersion::new(1, 0, 0)).await.unwrap();
        assert_eq!(retrieved.status, VersionStatus::Deprecated);
        assert!(retrieved.deprecation_date.is_some());
    }
}
