//! Plugin types and data structures
//!
//! This module defines the core types used throughout the plugin system.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Plugin type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    /// Scanner plugins that discover hosts, ports, or services
    Scanner,
    /// Detector plugins that identify vulnerabilities or misconfigurations
    Detector,
    /// Reporter plugins that generate custom report formats
    Reporter,
    /// Integration plugins that connect to external services
    Integration,
}

impl std::fmt::Display for PluginType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginType::Scanner => write!(f, "scanner"),
            PluginType::Detector => write!(f, "detector"),
            PluginType::Reporter => write!(f, "reporter"),
            PluginType::Integration => write!(f, "integration"),
        }
    }
}

impl std::str::FromStr for PluginType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "scanner" => Ok(PluginType::Scanner),
            "detector" => Ok(PluginType::Detector),
            "reporter" => Ok(PluginType::Reporter),
            "integration" => Ok(PluginType::Integration),
            _ => Err(anyhow::anyhow!("Unknown plugin type: {}", s)),
        }
    }
}

/// Plugin status in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginStatus {
    /// Plugin is installed and enabled
    Enabled,
    /// Plugin is installed but disabled
    Disabled,
    /// Plugin failed to load
    Error,
    /// Plugin is being installed
    Installing,
    /// Plugin is being updated
    Updating,
}

impl Default for PluginStatus {
    fn default() -> Self {
        PluginStatus::Disabled
    }
}

impl std::fmt::Display for PluginStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginStatus::Enabled => write!(f, "enabled"),
            PluginStatus::Disabled => write!(f, "disabled"),
            PluginStatus::Error => write!(f, "error"),
            PluginStatus::Installing => write!(f, "installing"),
            PluginStatus::Updating => write!(f, "updating"),
        }
    }
}

impl std::str::FromStr for PluginStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "enabled" => Ok(PluginStatus::Enabled),
            "disabled" => Ok(PluginStatus::Disabled),
            "error" => Ok(PluginStatus::Error),
            "installing" => Ok(PluginStatus::Installing),
            "updating" => Ok(PluginStatus::Updating),
            _ => Err(anyhow::anyhow!("Unknown plugin status: {}", s)),
        }
    }
}

/// Plugin permissions that define what capabilities the plugin has access to
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginPermissions {
    /// Can make network connections
    #[serde(default)]
    pub network: bool,

    /// Can access the filesystem
    #[serde(default)]
    pub filesystem: bool,

    /// Can access environment variables
    #[serde(default)]
    pub environment: bool,

    /// Can spawn child processes
    #[serde(default)]
    pub subprocess: bool,

    /// Can access scan results
    #[serde(default)]
    pub scan_results: bool,

    /// Can access vulnerability data
    #[serde(default)]
    pub vulnerabilities: bool,

    /// Can access asset inventory
    #[serde(default)]
    pub assets: bool,

    /// Can write to reports
    #[serde(default)]
    pub reports: bool,
}

/// Plugin entrypoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginEntrypoint {
    /// WebAssembly module (sandboxed)
    Wasm(String),
    /// Native shared library (requires elevated trust)
    Native(String),
}

impl PluginEntrypoint {
    /// Get the path to the entrypoint file
    pub fn path(&self) -> &str {
        match self {
            PluginEntrypoint::Wasm(path) => path,
            PluginEntrypoint::Native(path) => path,
        }
    }

    /// Check if this is a WASM entrypoint
    pub fn is_wasm(&self) -> bool {
        matches!(self, PluginEntrypoint::Wasm(_))
    }

    /// Check if this is a native entrypoint
    pub fn is_native(&self) -> bool {
        matches!(self, PluginEntrypoint::Native(_))
    }
}

/// Plugin manifest parsed from plugin.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin metadata
    pub plugin: PluginInfo,

    /// Plugin permissions
    #[serde(default)]
    pub permissions: PluginPermissions,

    /// Plugin entrypoint
    pub entrypoint: PluginEntrypoint,

    /// Plugin dependencies (other plugin IDs)
    #[serde(default)]
    pub dependencies: Vec<String>,

    /// Plugin configuration schema (JSON Schema)
    #[serde(default)]
    pub config_schema: Option<serde_json::Value>,
}

/// Plugin metadata information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique plugin identifier (e.g., "example-scanner")
    pub id: String,

    /// Human-readable plugin name
    pub name: String,

    /// Plugin version (semver)
    pub version: String,

    /// Plugin type
    #[serde(rename = "type")]
    pub plugin_type: PluginType,

    /// Plugin author
    pub author: String,

    /// Plugin description
    pub description: String,

    /// Plugin homepage URL
    #[serde(default)]
    pub homepage: Option<String>,

    /// Plugin repository URL
    #[serde(default)]
    pub repository: Option<String>,

    /// Plugin license
    #[serde(default)]
    pub license: Option<String>,

    /// Minimum HeroForge version required
    #[serde(default)]
    pub min_heroforge_version: Option<String>,

    /// Plugin tags for marketplace search
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Installed plugin record stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct InstalledPlugin {
    /// Database ID
    pub id: String,

    /// Plugin identifier from manifest
    pub plugin_id: String,

    /// Plugin name from manifest
    pub name: String,

    /// Plugin version
    pub version: String,

    /// Plugin type
    pub plugin_type: String,

    /// Current status
    pub status: String,

    /// Serialized manifest JSON
    pub manifest: String,

    /// Installation path on disk
    pub install_path: String,

    /// User ID who installed the plugin
    pub installed_by: String,

    /// Installation timestamp
    pub installed_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Error message if status is "error"
    pub error_message: Option<String>,

    /// Plugin checksum for integrity verification
    pub checksum: Option<String>,
}

/// Plugin settings for a specific user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PluginSettings {
    /// Database ID
    pub id: String,

    /// Plugin database ID
    pub plugin_id: String,

    /// User ID
    pub user_id: String,

    /// User-specific settings (JSON)
    pub settings: String,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Plugin response for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResponse {
    pub id: String,
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub plugin_type: PluginType,
    pub status: PluginStatus,
    pub description: String,
    pub author: String,
    pub permissions: PluginPermissions,
    pub installed_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub error_message: Option<String>,
}

impl TryFrom<InstalledPlugin> for PluginResponse {
    type Error = anyhow::Error;

    fn try_from(plugin: InstalledPlugin) -> Result<Self, Self::Error> {
        let manifest: PluginManifest = serde_json::from_str(&plugin.manifest)?;
        let plugin_type: PluginType = plugin.plugin_type.parse()?;
        let status: PluginStatus = plugin.status.parse()?;

        Ok(PluginResponse {
            id: plugin.id,
            plugin_id: plugin.plugin_id,
            name: plugin.name,
            version: plugin.version,
            plugin_type,
            status,
            description: manifest.plugin.description,
            author: manifest.plugin.author,
            permissions: manifest.permissions,
            installed_at: plugin.installed_at,
            updated_at: plugin.updated_at,
            error_message: plugin.error_message,
        })
    }
}

/// Request to install a plugin
#[derive(Debug, Deserialize)]
pub struct InstallPluginRequest {
    /// URL to download the plugin from (mutually exclusive with file_path)
    pub url: Option<String>,

    /// Local file path for the plugin package
    pub file_path: Option<String>,

    /// Whether to enable the plugin after installation
    #[serde(default = "default_enable_after_install")]
    pub enable: bool,
}

fn default_enable_after_install() -> bool {
    true
}

/// Request to update plugin settings
#[derive(Debug, Deserialize)]
pub struct UpdatePluginSettingsRequest {
    /// Settings JSON object
    pub settings: serde_json::Value,
}

/// Plugin validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl PluginValidationResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            valid: false,
            errors: vec![message.into()],
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, message: impl Into<String>) {
        self.valid = false;
        self.errors.push(message.into());
    }

    pub fn add_warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_type_from_str() {
        assert_eq!(
            "scanner".parse::<PluginType>().unwrap(),
            PluginType::Scanner
        );
        assert_eq!(
            "detector".parse::<PluginType>().unwrap(),
            PluginType::Detector
        );
        assert_eq!(
            "reporter".parse::<PluginType>().unwrap(),
            PluginType::Reporter
        );
        assert_eq!(
            "integration".parse::<PluginType>().unwrap(),
            PluginType::Integration
        );
    }

    #[test]
    fn test_plugin_status_from_str() {
        assert_eq!(
            "enabled".parse::<PluginStatus>().unwrap(),
            PluginStatus::Enabled
        );
        assert_eq!(
            "disabled".parse::<PluginStatus>().unwrap(),
            PluginStatus::Disabled
        );
        assert_eq!(
            "error".parse::<PluginStatus>().unwrap(),
            PluginStatus::Error
        );
    }

    #[test]
    fn test_plugin_permissions_default() {
        let perms = PluginPermissions::default();
        assert!(!perms.network);
        assert!(!perms.filesystem);
        assert!(!perms.environment);
        assert!(!perms.subprocess);
    }
}
