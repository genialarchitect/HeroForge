//! Plugin loader for reading, validating, and loading plugins
//!
//! This module handles:
//! - Loading plugins from disk or URL
//! - Validating plugin manifests and contents
//! - Computing checksums for integrity verification
//! - Extracting plugin packages

#![allow(dead_code)]

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tokio::fs;
use zip::ZipArchive;

use super::manifest::{parse_manifest_file, validate_manifest};
use super::types::{PluginManifest, PluginValidationResult};

/// Plugin loader for installing and validating plugins
pub struct PluginLoader {
    /// Base directory for installed plugins
    plugins_dir: PathBuf,

    /// Temporary directory for downloads/extraction
    temp_dir: PathBuf,

    /// Whether to allow native plugins (requires elevated trust)
    allow_native: bool,
}

impl PluginLoader {
    /// Create a new plugin loader with default paths
    pub fn new() -> Self {
        let base_dir = std::env::var("HEROFORGE_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));

        Self {
            plugins_dir: base_dir.join("plugins"),
            temp_dir: std::env::temp_dir().join("heroforge_plugins"),
            allow_native: false,
        }
    }

    /// Create a plugin loader with custom paths
    pub fn with_paths(plugins_dir: PathBuf, temp_dir: PathBuf) -> Self {
        Self {
            plugins_dir,
            temp_dir,
            allow_native: false,
        }
    }

    /// Enable native plugin support (requires elevated trust)
    pub fn allow_native_plugins(mut self, allow: bool) -> Self {
        self.allow_native = allow;
        self
    }

    /// Get the plugins directory
    pub fn plugins_dir(&self) -> &Path {
        &self.plugins_dir
    }

    /// Ensure required directories exist
    pub async fn ensure_directories(&self) -> Result<()> {
        fs::create_dir_all(&self.plugins_dir).await?;
        fs::create_dir_all(&self.temp_dir).await?;
        Ok(())
    }

    /// Load a plugin from a local zip file
    pub async fn load_from_file(&self, path: &Path) -> Result<LoadedPlugin> {
        self.ensure_directories().await?;

        // Compute checksum before extraction
        let checksum = compute_file_checksum(path)?;

        // Create temp extraction directory
        let extract_dir = self.temp_dir.join(format!("extract_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&extract_dir).await?;

        // Extract the plugin package
        extract_zip(path, &extract_dir)?;

        // Parse and validate the manifest
        let manifest_path = extract_dir.join("plugin.toml");
        if !manifest_path.exists() {
            fs::remove_dir_all(&extract_dir).await?;
            anyhow::bail!("Plugin package missing plugin.toml manifest");
        }

        let manifest = parse_manifest_file(&manifest_path)?;
        let validation = validate_manifest(&manifest);

        if !validation.valid {
            fs::remove_dir_all(&extract_dir).await?;
            anyhow::bail!(
                "Plugin manifest validation failed: {}",
                validation.errors.join(", ")
            );
        }

        // Check native plugin permissions
        if manifest.entrypoint.is_native() && !self.allow_native {
            fs::remove_dir_all(&extract_dir).await?;
            anyhow::bail!(
                "Native plugins are not allowed. Enable with allow_native_plugins(true)"
            );
        }

        // Verify entrypoint file exists
        let entrypoint_path = extract_dir.join(manifest.entrypoint.path());
        if !entrypoint_path.exists() {
            fs::remove_dir_all(&extract_dir).await?;
            anyhow::bail!(
                "Plugin entrypoint file not found: {}",
                manifest.entrypoint.path()
            );
        }

        // Move to permanent installation directory
        let install_dir = self.plugins_dir.join(&manifest.plugin.id);
        if install_dir.exists() {
            // Plugin already installed - this will be handled as an update
            fs::remove_dir_all(&install_dir).await?;
        }
        fs::rename(&extract_dir, &install_dir).await?;

        Ok(LoadedPlugin {
            manifest,
            install_path: install_dir,
            checksum,
            validation,
        })
    }

    /// Load a plugin from a URL
    pub async fn load_from_url(&self, url: &str) -> Result<LoadedPlugin> {
        self.ensure_directories().await?;

        // Download to temp file
        let temp_file = self
            .temp_dir
            .join(format!("download_{}.zip", uuid::Uuid::new_v4()));

        download_file(url, &temp_file).await?;

        // Load from the downloaded file
        let result = self.load_from_file(&temp_file).await;

        // Clean up temp file
        let _ = fs::remove_file(&temp_file).await;

        result
    }

    /// Validate a plugin package without installing
    pub async fn validate_package(&self, path: &Path) -> Result<PluginValidationResult> {
        // Create temp extraction directory
        let extract_dir = self
            .temp_dir
            .join(format!("validate_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&extract_dir).await?;

        // Extract the plugin package
        if let Err(e) = extract_zip(path, &extract_dir) {
            fs::remove_dir_all(&extract_dir).await?;
            return Ok(PluginValidationResult::error(format!(
                "Failed to extract package: {}",
                e
            )));
        }

        // Parse the manifest
        let manifest_path = extract_dir.join("plugin.toml");
        if !manifest_path.exists() {
            fs::remove_dir_all(&extract_dir).await?;
            return Ok(PluginValidationResult::error(
                "Plugin package missing plugin.toml manifest",
            ));
        }

        let manifest = match parse_manifest_file(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                fs::remove_dir_all(&extract_dir).await?;
                return Ok(PluginValidationResult::error(format!(
                    "Failed to parse manifest: {}",
                    e
                )));
            }
        };

        // Validate manifest
        let mut validation = validate_manifest(&manifest);

        // Verify entrypoint file exists
        let entrypoint_path = extract_dir.join(manifest.entrypoint.path());
        if !entrypoint_path.exists() {
            validation.add_error(format!(
                "Entrypoint file not found: {}",
                manifest.entrypoint.path()
            ));
        }

        // Check for native plugin if not allowed
        if manifest.entrypoint.is_native() && !self.allow_native {
            validation.add_warning("Native plugins require elevated trust and are currently disabled");
        }

        // Clean up
        fs::remove_dir_all(&extract_dir).await?;

        Ok(validation)
    }

    /// Get the installation path for a plugin
    pub fn get_install_path(&self, plugin_id: &str) -> PathBuf {
        self.plugins_dir.join(plugin_id)
    }

    /// Check if a plugin is installed
    pub async fn is_installed(&self, plugin_id: &str) -> bool {
        self.get_install_path(plugin_id).exists()
    }

    /// Uninstall a plugin by removing its directory
    pub async fn uninstall(&self, plugin_id: &str) -> Result<()> {
        let install_path = self.get_install_path(plugin_id);
        if install_path.exists() {
            fs::remove_dir_all(&install_path).await?;
        }
        Ok(())
    }

    /// List installed plugin directories
    pub async fn list_installed(&self) -> Result<Vec<String>> {
        let mut plugins = Vec::new();

        if !self.plugins_dir.exists() {
            return Ok(plugins);
        }

        let mut entries = fs::read_dir(&self.plugins_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    // Check if it has a valid manifest
                    let manifest_path = entry.path().join("plugin.toml");
                    if manifest_path.exists() {
                        plugins.push(name.to_string());
                    }
                }
            }
        }

        Ok(plugins)
    }

    /// Load manifest for an installed plugin
    pub fn load_installed_manifest(&self, plugin_id: &str) -> Result<PluginManifest> {
        let manifest_path = self.get_install_path(plugin_id).join("plugin.toml");
        parse_manifest_file(&manifest_path)
    }
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of loading a plugin
#[derive(Debug)]
pub struct LoadedPlugin {
    /// Parsed manifest
    pub manifest: PluginManifest,

    /// Installation path
    pub install_path: PathBuf,

    /// Package checksum (SHA256)
    pub checksum: String,

    /// Validation result
    pub validation: PluginValidationResult,
}

/// Compute SHA256 checksum of a file
fn compute_file_checksum(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Extract a zip file to a directory
fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest_dir.join(file.name());

        // Security: prevent path traversal attacks
        if !outpath.starts_with(dest_dir) {
            anyhow::bail!("Invalid path in zip archive: {}", file.name());
        }

        if file.is_dir() {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }

    Ok(())
}

/// Download a file from a URL
async fn download_file(url: &str, dest: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to download plugin")?;

    if !response.status().is_success() {
        anyhow::bail!("Download failed with status: {}", response.status());
    }

    let bytes = response.bytes().await?;
    let mut file = std::fs::File::create(dest)?;
    file.write_all(&bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_plugin_zip(dir: &Path) -> PathBuf {
        let manifest = r#"
[plugin]
id = "test-plugin"
name = "Test Plugin"
version = "1.0.0"
type = "scanner"
author = "Test"
description = "A test plugin"

[entrypoint]
wasm = "plugin.wasm"
"#;

        // Create plugin files
        let plugin_dir = dir.join("plugin_source");
        std::fs::create_dir_all(&plugin_dir).unwrap();

        // Write manifest
        let manifest_path = plugin_dir.join("plugin.toml");
        std::fs::write(&manifest_path, manifest).unwrap();

        // Write dummy WASM file
        let wasm_path = plugin_dir.join("plugin.wasm");
        std::fs::write(&wasm_path, &[0x00, 0x61, 0x73, 0x6d]).unwrap(); // WASM magic bytes

        // Create zip
        let zip_path = dir.join("test-plugin.zip");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        zip.start_file("plugin.toml", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();

        zip.start_file("plugin.wasm", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&[0x00, 0x61, 0x73, 0x6d]).unwrap();

        zip.finish().unwrap();

        zip_path
    }

    #[tokio::test]
    async fn test_validate_package() {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = create_test_plugin_zip(temp_dir.path());

        let loader = PluginLoader::with_paths(
            temp_dir.path().join("plugins"),
            temp_dir.path().join("temp"),
        );

        let result = loader.validate_package(&zip_path).await.unwrap();
        assert!(result.valid);
    }

    #[tokio::test]
    async fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = create_test_plugin_zip(temp_dir.path());

        let loader = PluginLoader::with_paths(
            temp_dir.path().join("plugins"),
            temp_dir.path().join("temp"),
        );

        let loaded = loader.load_from_file(&zip_path).await.unwrap();
        assert_eq!(loaded.manifest.plugin.id, "test-plugin");
        assert!(loaded.install_path.exists());
        assert!(!loaded.checksum.is_empty());
    }

    #[tokio::test]
    async fn test_list_installed() {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = create_test_plugin_zip(temp_dir.path());

        let loader = PluginLoader::with_paths(
            temp_dir.path().join("plugins"),
            temp_dir.path().join("temp"),
        );

        // No plugins initially
        let list = loader.list_installed().await.unwrap();
        assert!(list.is_empty());

        // Install a plugin
        loader.load_from_file(&zip_path).await.unwrap();

        // Now there should be one
        let list = loader.list_installed().await.unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains(&"test-plugin".to_string()));
    }

    #[tokio::test]
    async fn test_uninstall() {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = create_test_plugin_zip(temp_dir.path());

        let loader = PluginLoader::with_paths(
            temp_dir.path().join("plugins"),
            temp_dir.path().join("temp"),
        );

        loader.load_from_file(&zip_path).await.unwrap();
        assert!(loader.is_installed("test-plugin").await);

        loader.uninstall("test-plugin").await.unwrap();
        assert!(!loader.is_installed("test-plugin").await);
    }

    #[test]
    fn test_compute_checksum() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, "hello world").unwrap();

        let checksum = compute_file_checksum(&test_file).unwrap();
        // SHA256 of "hello world"
        assert_eq!(
            checksum,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
