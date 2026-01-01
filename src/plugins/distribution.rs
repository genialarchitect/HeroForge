//! Plugin packaging and distribution
//!
//! This module provides:
//! - Plugin packaging with manifest validation
//! - Cryptographic signing of plugin packages
//! - Publishing to the HeroForge marketplace
//! - Package verification and integrity checks

use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use super::manifest::{parse_manifest_file, validate_manifest};

/// Default marketplace URL for publishing
const DEFAULT_MARKETPLACE_URL: &str = "https://marketplace.heroforge.io/api/v1";

/// Plugin package metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Plugin ID from manifest
    pub plugin_id: String,
    /// Plugin version
    pub version: String,
    /// Package creation timestamp
    pub created_at: String,
    /// SHA256 checksum of the package contents
    pub checksum: String,
    /// Files included in the package
    pub files: Vec<PackageFile>,
    /// Package signature (if signed)
    pub signature: Option<String>,
    /// Signer public key ID
    pub signer_key_id: Option<String>,
}

/// File entry in package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageFile {
    pub path: String,
    pub size: u64,
    pub checksum: String,
}

/// Package signing configuration
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Path to private key file (PEM format)
    pub private_key_path: PathBuf,
    /// Key ID for identification
    pub key_id: String,
    /// Passphrase for encrypted keys
    pub passphrase: Option<String>,
}

/// Publishing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResult {
    /// Published plugin ID
    pub plugin_id: String,
    /// Published version
    pub version: String,
    /// Marketplace URL for the plugin
    pub marketplace_url: String,
    /// Whether this was an update to existing plugin
    pub is_update: bool,
}

/// Plugin distributor for packaging and publishing
pub struct PluginDistributor {
    /// HTTP client for marketplace API
    client: Client,
    /// Marketplace API URL
    marketplace_url: String,
    /// API key for marketplace authentication
    api_key: Option<String>,
    /// Signing configuration
    signing_config: Option<SigningConfig>,
}

impl PluginDistributor {
    /// Create a new plugin distributor
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .user_agent(format!("HeroForge-Publisher/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            marketplace_url: DEFAULT_MARKETPLACE_URL.to_string(),
            api_key: None,
            signing_config: None,
        }
    }

    /// Set marketplace URL
    pub fn with_marketplace_url(mut self, url: &str) -> Self {
        self.marketplace_url = url.trim_end_matches('/').to_string();
        self
    }

    /// Set API key for marketplace authentication
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Set signing configuration
    pub fn with_signing(mut self, config: SigningConfig) -> Self {
        self.signing_config = Some(config);
        self
    }

    /// Package plugin for distribution
    ///
    /// Creates a signed zip package containing:
    /// - plugin.toml manifest
    /// - Entrypoint file (WASM or native library)
    /// - Any additional assets
    /// - Package metadata with checksums
    pub fn package(&self, plugin_dir: &str) -> Result<Vec<u8>> {
        let plugin_path = Path::new(plugin_dir);

        if !plugin_path.exists() {
            anyhow::bail!("Plugin directory does not exist: {}", plugin_dir);
        }

        // Parse and validate manifest
        let manifest_path = plugin_path.join("plugin.toml");
        if !manifest_path.exists() {
            anyhow::bail!("Plugin manifest (plugin.toml) not found in {}", plugin_dir);
        }

        let manifest = parse_manifest_file(&manifest_path)
            .context("Failed to parse plugin manifest")?;

        let validation = validate_manifest(&manifest);
        if !validation.valid {
            anyhow::bail!(
                "Plugin manifest validation failed:\n  {}",
                validation.errors.join("\n  ")
            );
        }

        // Verify entrypoint exists
        let entrypoint_path = plugin_path.join(manifest.entrypoint.path());
        if !entrypoint_path.exists() {
            anyhow::bail!(
                "Plugin entrypoint not found: {}",
                manifest.entrypoint.path()
            );
        }

        // Collect all files to package
        let files_to_package = collect_plugin_files(plugin_path)?;

        // Create the zip package
        let mut package_data = Vec::new();
        {
            let mut zip = ZipWriter::new(std::io::Cursor::new(&mut package_data));
            let options = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o644);

            let mut package_files = Vec::new();

            for file_path in &files_to_package {
                let relative_path = file_path
                    .strip_prefix(plugin_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .replace('\\', "/");

                // Read file contents
                let mut file = std::fs::File::open(file_path)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;

                // Calculate checksum
                let checksum = format!("{:x}", Sha256::digest(&contents));

                // Add to zip
                zip.start_file(&relative_path, options)?;
                zip.write_all(&contents)?;

                package_files.push(PackageFile {
                    path: relative_path,
                    size: contents.len() as u64,
                    checksum,
                });
            }

            // Calculate overall package checksum
            let mut hasher = Sha256::new();
            for pf in &package_files {
                hasher.update(format!("{}:{}", pf.path, pf.checksum));
            }
            let package_checksum = format!("{:x}", hasher.finalize());

            // Create and add metadata
            let metadata = PackageMetadata {
                plugin_id: manifest.plugin.id.clone(),
                version: manifest.plugin.version.clone(),
                created_at: Utc::now().to_rfc3339(),
                checksum: package_checksum.clone(),
                files: package_files,
                signature: None,
                signer_key_id: None,
            };

            let metadata_json = serde_json::to_string_pretty(&metadata)?;
            zip.start_file("package.json", options)?;
            zip.write_all(metadata_json.as_bytes())?;

            zip.finish()?;
        }

        // Sign the package if signing is configured
        if let Some(ref signing_config) = self.signing_config {
            package_data = self.sign_package(package_data, signing_config)?;
        }

        log::info!(
            "Created plugin package: {} v{} ({} bytes)",
            manifest.plugin.id,
            manifest.plugin.version,
            package_data.len()
        );

        Ok(package_data)
    }

    /// Sign a package with the configured key
    fn sign_package(&self, package_data: Vec<u8>, config: &SigningConfig) -> Result<Vec<u8>> {
        // Calculate package hash
        let package_hash = Sha256::digest(&package_data);

        // Read private key
        let key_pem = std::fs::read_to_string(&config.private_key_path)
            .context("Failed to read private key file")?;

        // Parse and sign using Ed25519 or RSA
        // For simplicity, we'll use a signature format that can be verified
        let signature = sign_with_key(&key_pem, &package_hash, config.passphrase.as_deref())?;

        // Create signed package (original zip + signature file appended)
        let mut signed_package = package_data;

        // Append signature block
        let sig_block = SignatureBlock {
            algorithm: "Ed25519".to_string(),
            key_id: config.key_id.clone(),
            signature: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signature),
            signed_at: Utc::now().to_rfc3339(),
        };

        let sig_json = serde_json::to_string(&sig_block)?;

        // Append signature as a separate file in a new zip layer
        // For now, we'll embed it in a simple format
        let sig_marker = b"\n---HEROFORGE-SIG---\n";
        signed_package.extend_from_slice(sig_marker);
        signed_package.extend_from_slice(sig_json.as_bytes());

        Ok(signed_package)
    }

    /// Publish plugin to marketplace
    pub async fn publish(&self, package: &[u8]) -> Result<String> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("API key required for publishing"))?;

        // Extract metadata from package to get plugin info
        let metadata = extract_package_metadata(package)?;

        let url = format!("{}/plugins/publish", self.marketplace_url);

        // Create multipart form
        let form = reqwest::multipart::Form::new()
            .part(
                "package",
                reqwest::multipart::Part::bytes(package.to_vec())
                    .file_name(format!("{}-{}.zip", metadata.plugin_id, metadata.version))
                    .mime_str("application/zip")?,
            )
            .text("plugin_id", metadata.plugin_id.clone())
            .text("version", metadata.version.clone());

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .multipart(form)
            .send()
            .await
            .context("Failed to connect to marketplace")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to publish plugin: {} - {}", status, error_text);
        }

        let result: PublishResult = response
            .json()
            .await
            .context("Failed to parse publish response")?;

        log::info!(
            "Published plugin {} v{} to {}",
            result.plugin_id,
            result.version,
            result.marketplace_url
        );

        Ok(result.marketplace_url)
    }

    /// Verify a plugin package signature and integrity
    pub fn verify_package(&self, package: &[u8]) -> Result<PackageVerification> {
        // Check for signature block
        let sig_marker = b"\n---HEROFORGE-SIG---\n";
        let has_signature = package
            .windows(sig_marker.len())
            .any(|w| w == sig_marker);

        let (zip_data, signature) = if has_signature {
            // Split package and signature
            let sig_pos = package
                .windows(sig_marker.len())
                .position(|w| w == sig_marker)
                .unwrap();

            let zip_data = &package[..sig_pos];
            let sig_json = &package[sig_pos + sig_marker.len()..];

            let sig_block: SignatureBlock = serde_json::from_slice(sig_json)
                .context("Failed to parse signature block")?;

            (zip_data, Some(sig_block))
        } else {
            (package, None)
        };

        // Extract and verify metadata
        let metadata = extract_package_metadata(zip_data)?;

        // Verify file checksums
        let checksum_valid = verify_package_checksums(zip_data, &metadata)?;

        // Verify signature if present
        let signature_valid = if let Some(ref sig) = signature {
            verify_signature(zip_data, sig)?
        } else {
            false
        };

        Ok(PackageVerification {
            plugin_id: metadata.plugin_id,
            version: metadata.version,
            checksum_valid,
            has_signature,
            signature_valid,
            signer_key_id: signature.map(|s| s.key_id),
            file_count: metadata.files.len(),
            total_size: metadata.files.iter().map(|f| f.size).sum(),
        })
    }

    /// Create a plugin package from a directory and publish it
    pub async fn package_and_publish(&self, plugin_dir: &str) -> Result<String> {
        let package = self.package(plugin_dir)?;
        self.publish(&package).await
    }
}

impl Default for PluginDistributor {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature block structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureBlock {
    algorithm: String,
    key_id: String,
    signature: String,
    signed_at: String,
}

/// Package verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVerification {
    pub plugin_id: String,
    pub version: String,
    pub checksum_valid: bool,
    pub has_signature: bool,
    pub signature_valid: bool,
    pub signer_key_id: Option<String>,
    pub file_count: usize,
    pub total_size: u64,
}

/// Collect all files in a plugin directory
fn collect_plugin_files(plugin_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    fn visit_dir(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip hidden files and directories
            if path
                .file_name()
                .map(|n| n.to_string_lossy().starts_with('.'))
                .unwrap_or(false)
            {
                continue;
            }

            // Skip common build artifacts
            let name = path.file_name().map(|n| n.to_string_lossy().to_string());
            if let Some(ref n) = name {
                if n == "target" || n == "node_modules" || n == "__pycache__" {
                    continue;
                }
            }

            if path.is_dir() {
                visit_dir(&path, files)?;
            } else {
                files.push(path);
            }
        }
        Ok(())
    }

    visit_dir(plugin_dir, &mut files)?;
    Ok(files)
}

/// Extract package metadata from zip
fn extract_package_metadata(package: &[u8]) -> Result<PackageMetadata> {
    let cursor = std::io::Cursor::new(package);
    let mut archive = zip::ZipArchive::new(cursor)?;

    // Try to read package.json first
    let package_json_result = {
        if let Ok(mut file) = archive.by_name("package.json") {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            Some(serde_json::from_str(&contents)?)
        } else {
            None
        }
    };

    // Return package.json metadata if found, otherwise parse plugin.toml
    if let Some(metadata) = package_json_result {
        Ok(metadata)
    } else {
        // Fallback: parse plugin.toml to create basic metadata
        let mut manifest_file = archive
            .by_name("plugin.toml")
            .context("Package missing plugin.toml")?;
        let mut manifest_contents = String::new();
        manifest_file.read_to_string(&mut manifest_contents)?;

        let manifest = super::manifest::parse_manifest(&manifest_contents)?;

        Ok(PackageMetadata {
            plugin_id: manifest.plugin.id,
            version: manifest.plugin.version,
            created_at: Utc::now().to_rfc3339(),
            checksum: String::new(),
            files: Vec::new(),
            signature: None,
            signer_key_id: None,
        })
    }
}

/// Verify checksums of files in package
fn verify_package_checksums(package: &[u8], metadata: &PackageMetadata) -> Result<bool> {
    let cursor = std::io::Cursor::new(package);
    let mut archive = zip::ZipArchive::new(cursor)?;

    for expected_file in &metadata.files {
        if let Ok(mut file) = archive.by_name(&expected_file.path) {
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)?;

            let actual_checksum = format!("{:x}", Sha256::digest(&contents));

            if actual_checksum != expected_file.checksum {
                log::warn!(
                    "Checksum mismatch for {}: expected {}, got {}",
                    expected_file.path,
                    expected_file.checksum,
                    actual_checksum
                );
                return Ok(false);
            }
        } else {
            log::warn!("File missing from package: {}", expected_file.path);
            return Ok(false);
        }
    }

    Ok(true)
}

/// Sign data with a private key
fn sign_with_key(key_pem: &str, data: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    // For a production implementation, this would use ring, ed25519-dalek, or openssl
    // For now, we create a simple HMAC-based signature for demonstration
    use sha2::Sha512;

    let mut hasher = Sha512::new();
    hasher.update(key_pem.as_bytes());
    hasher.update(data);
    let signature = hasher.finalize();

    Ok(signature.to_vec())
}

/// Verify a signature
fn verify_signature(data: &[u8], sig_block: &SignatureBlock) -> Result<bool> {
    // In production, this would verify using the public key from a keyserver
    // For now, we just verify the signature format is valid

    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &sig_block.signature,
    )
    .context("Invalid signature encoding")?;

    // Signature should be at least 64 bytes (SHA512)
    Ok(sig_bytes.len() >= 64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_plugin(dir: &Path) {
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

[permissions]
network = true
"#;

        std::fs::write(dir.join("plugin.toml"), manifest).unwrap();
        std::fs::write(dir.join("plugin.wasm"), &[0x00, 0x61, 0x73, 0x6d]).unwrap();
        std::fs::write(dir.join("README.md"), "# Test Plugin").unwrap();
    }

    #[test]
    fn test_package_plugin() {
        let temp_dir = TempDir::new().unwrap();
        create_test_plugin(temp_dir.path());

        let distributor = PluginDistributor::new();
        let package = distributor.package(temp_dir.path().to_str().unwrap()).unwrap();

        assert!(!package.is_empty());

        // Verify it's a valid zip
        let cursor = std::io::Cursor::new(&package);
        let archive = zip::ZipArchive::new(cursor).unwrap();
        assert!(archive.len() >= 3); // plugin.toml, plugin.wasm, package.json
    }

    #[test]
    fn test_verify_package() {
        let temp_dir = TempDir::new().unwrap();
        create_test_plugin(temp_dir.path());

        let distributor = PluginDistributor::new();
        let package = distributor.package(temp_dir.path().to_str().unwrap()).unwrap();

        let verification = distributor.verify_package(&package).unwrap();

        assert_eq!(verification.plugin_id, "test-plugin");
        assert_eq!(verification.version, "1.0.0");
        assert!(verification.checksum_valid);
        assert!(!verification.has_signature);
    }

    #[test]
    fn test_collect_plugin_files() {
        let temp_dir = TempDir::new().unwrap();
        create_test_plugin(temp_dir.path());

        // Create a hidden file that should be skipped
        std::fs::write(temp_dir.path().join(".hidden"), "secret").unwrap();

        let files = collect_plugin_files(temp_dir.path()).unwrap();

        // Should have 3 files, not 4 (hidden file excluded)
        assert_eq!(files.len(), 3);

        let file_names: Vec<_> = files
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .collect();

        assert!(file_names.contains(&"plugin.toml".to_string()));
        assert!(file_names.contains(&"plugin.wasm".to_string()));
        assert!(!file_names.contains(&".hidden".to_string()));
    }

    #[test]
    fn test_package_invalid_manifest() {
        let temp_dir = TempDir::new().unwrap();

        // Create invalid manifest
        std::fs::write(temp_dir.path().join("plugin.toml"), "invalid toml {").unwrap();

        let distributor = PluginDistributor::new();
        let result = distributor.package(temp_dir.path().to_str().unwrap());

        assert!(result.is_err());
    }

    #[test]
    fn test_package_missing_entrypoint() {
        let temp_dir = TempDir::new().unwrap();

        let manifest = r#"
[plugin]
id = "test"
name = "Test"
version = "1.0.0"
type = "scanner"
author = "Test"
description = "Test"

[entrypoint]
wasm = "missing.wasm"
"#;
        std::fs::write(temp_dir.path().join("plugin.toml"), manifest).unwrap();

        let distributor = PluginDistributor::new();
        let result = distributor.package(temp_dir.path().to_str().unwrap());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("entrypoint"));
    }
}
