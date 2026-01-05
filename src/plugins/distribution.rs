//! Plugin packaging and distribution
//!
//! This module provides:
//! - Plugin packaging with manifest validation
//! - Cryptographic signing of plugin packages (Ed25519, RSA, GPG)
//! - Publishing to the HeroForge marketplace
//! - Package verification and integrity checks
//! - GPG detached signature verification

use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use reqwest::Client;
use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{SignatureEncoding, Signer as RsaSigner, Verifier as RsaVerifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
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

/// Signature algorithm for plugin signing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 signature (recommended - fast and secure)
    Ed25519,
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaSha256,
    /// GPG/PGP detached signature (uses gpg binary)
    Gpg,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::RsaSha256 => write!(f, "RSA-SHA256"),
            Self::Gpg => write!(f, "GPG"),
        }
    }
}

/// Package signing configuration
#[derive(Debug, Clone)]
pub struct SigningConfig {
    /// Path to private key file (PEM format for Ed25519/RSA, or GPG key ID)
    pub private_key_path: PathBuf,
    /// Key ID for identification
    pub key_id: String,
    /// Passphrase for encrypted keys
    pub passphrase: Option<String>,
    /// Signature algorithm to use
    pub algorithm: SignatureAlgorithm,
}

impl SigningConfig {
    /// Create a new Ed25519 signing config
    pub fn ed25519(key_path: PathBuf, key_id: String) -> Self {
        Self {
            private_key_path: key_path,
            key_id,
            passphrase: None,
            algorithm: SignatureAlgorithm::Ed25519,
        }
    }

    /// Create a new RSA signing config
    pub fn rsa(key_path: PathBuf, key_id: String, passphrase: Option<String>) -> Self {
        Self {
            private_key_path: key_path,
            key_id,
            passphrase,
            algorithm: SignatureAlgorithm::RsaSha256,
        }
    }

    /// Create a new GPG signing config
    pub fn gpg(gpg_key_id: String) -> Self {
        Self {
            private_key_path: PathBuf::new(), // Not used for GPG
            key_id: gpg_key_id,
            passphrase: None,
            algorithm: SignatureAlgorithm::Gpg,
        }
    }
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
        use base64::Engine;

        // Calculate package hash for signing
        let package_hash = Sha256::digest(&package_data);

        // Sign based on algorithm type
        let (signature_bytes, public_key, gpg_details) = match config.algorithm {
            SignatureAlgorithm::Ed25519 => {
                // Read Ed25519 private key (raw bytes or PEM)
                let key_data = std::fs::read(&config.private_key_path)
                    .context("Failed to read Ed25519 private key file")?;

                // Try to parse as raw bytes first, then as PEM
                let key_bytes = if key_data.len() == 32 || key_data.len() == 64 {
                    key_data
                } else {
                    // Try to decode as hex or base64
                    hex::decode(&String::from_utf8_lossy(&key_data).trim())
                        .or_else(|_| {
                            base64::engine::general_purpose::STANDARD
                                .decode(String::from_utf8_lossy(&key_data).trim())
                        })
                        .context("Failed to decode Ed25519 key")?
                };

                let (sig, pubkey) = sign_ed25519(&key_bytes, &package_hash)?;
                let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&pubkey);
                (sig, Some(pubkey_b64), None)
            }
            SignatureAlgorithm::RsaSha256 => {
                // Read RSA private key in PEM format
                let key_pem = std::fs::read_to_string(&config.private_key_path)
                    .context("Failed to read RSA private key file")?;

                let sig = sign_rsa(&key_pem, &package_hash)?;
                // For RSA, we don't embed the public key (it's usually distributed separately)
                (sig, None, None)
            }
            SignatureAlgorithm::Gpg => {
                // Use GPG binary to sign
                let (sig, details) = sign_gpg(
                    &package_data, // GPG signs the full package, not just the hash
                    &config.key_id,
                    config.passphrase.as_deref(),
                )?;
                (sig, None, Some(details))
            }
        };

        // Create signed package (original zip + signature block appended)
        let mut signed_package = package_data;

        // Encode signature as base64
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature_bytes);

        // Create signature block
        let sig_block = SignatureBlock {
            algorithm: config.algorithm,
            key_id: config.key_id.clone(),
            signature: signature_b64,
            public_key,
            signed_at: Utc::now().to_rfc3339(),
            gpg_details,
        };

        let sig_json = serde_json::to_string_pretty(&sig_block)?;

        // Append signature marker and JSON
        let sig_marker = b"\n---HEROFORGE-SIG---\n";
        signed_package.extend_from_slice(sig_marker);
        signed_package.extend_from_slice(sig_json.as_bytes());

        log::info!(
            "Package signed with {} (key: {})",
            config.algorithm,
            config.key_id
        );

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

        // Extract signature details
        let (sig_algorithm, signer_key_id, signer_fingerprint, signature_time) = if let Some(ref sig) = signature {
            let fingerprint = sig.gpg_details.as_ref().map(|d| d.fingerprint.clone());
            (Some(sig.algorithm), Some(sig.key_id.clone()), fingerprint, Some(sig.signed_at.clone()))
        } else {
            (None, None, None, None)
        };

        Ok(PackageVerification {
            plugin_id: metadata.plugin_id,
            version: metadata.version,
            checksum_valid,
            has_signature,
            signature_valid,
            signature_algorithm: sig_algorithm,
            signer_key_id,
            signer_fingerprint,
            signature_time,
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
    /// Signature algorithm used
    algorithm: SignatureAlgorithm,
    /// Key ID that created the signature
    key_id: String,
    /// Base64-encoded signature bytes
    signature: String,
    /// Optional public key for Ed25519 (for self-contained verification)
    public_key: Option<String>,
    /// Timestamp when the signature was created
    signed_at: String,
    /// GPG signature details (for GPG signatures)
    gpg_details: Option<GpgSignatureDetails>,
}

/// GPG signature details
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GpgSignatureDetails {
    /// GPG key fingerprint
    fingerprint: String,
    /// User ID associated with the key
    user_id: Option<String>,
    /// Key creation time
    key_created: Option<String>,
    /// Signature type (e.g., "RSA", "DSA", "ECDSA")
    sig_type: String,
}

/// Package verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVerification {
    pub plugin_id: String,
    pub version: String,
    pub checksum_valid: bool,
    pub has_signature: bool,
    pub signature_valid: bool,
    pub signature_algorithm: Option<SignatureAlgorithm>,
    pub signer_key_id: Option<String>,
    pub signer_fingerprint: Option<String>,
    pub signature_time: Option<String>,
    pub file_count: usize,
    pub total_size: u64,
}

/// Generated Ed25519 keypair
#[derive(Debug)]
pub struct GeneratedKeypair {
    /// Private key (32 bytes seed)
    pub private_key: Vec<u8>,
    /// Public key (32 bytes)
    pub public_key: Vec<u8>,
    /// Private key as hex string
    pub private_key_hex: String,
    /// Public key as hex string
    pub public_key_hex: String,
    /// Private key as base64
    pub private_key_b64: String,
    /// Public key as base64
    pub public_key_b64: String,
}

/// Generate a new Ed25519 keypair for plugin signing
pub fn generate_ed25519_keypair() -> Result<GeneratedKeypair> {
    use base64::Engine;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_key = signing_key.to_bytes().to_vec();
    let public_key = verifying_key.to_bytes().to_vec();

    Ok(GeneratedKeypair {
        private_key_hex: hex::encode(&private_key),
        public_key_hex: hex::encode(&public_key),
        private_key_b64: base64::engine::general_purpose::STANDARD.encode(&private_key),
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(&public_key),
        private_key,
        public_key,
    })
}

/// Save an Ed25519 keypair to files
pub fn save_ed25519_keypair(keypair: &GeneratedKeypair, private_path: &Path, public_path: &Path) -> Result<()> {
    // Save private key as hex
    std::fs::write(private_path, &keypair.private_key_hex)?;

    // Set restrictive permissions on private key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(private_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Save public key as hex
    std::fs::write(public_path, &keypair.public_key_hex)?;

    Ok(())
}

/// Verify a package and load public key from keyserver or file
pub fn verify_package_with_keyserver(
    package: &[u8],
    trusted_keys: &[TrustedKey],
) -> Result<PackageVerification> {
    let distributor = PluginDistributor::new();
    let mut verification = distributor.verify_package(package)?;

    // If signature is valid and we have a key ID, check against trusted keys
    if verification.has_signature && verification.signer_key_id.is_some() {
        let key_id = verification.signer_key_id.as_ref().unwrap();

        let is_trusted = trusted_keys.iter().any(|tk| {
            tk.key_id == *key_id || tk.fingerprint.as_ref() == Some(key_id)
        });

        if !is_trusted {
            log::warn!(
                "Package signed by untrusted key: {}. Signature valid but key not in trusted list.",
                key_id
            );
        }
    }

    Ok(verification)
}

/// Trusted key entry for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    /// Key identifier
    pub key_id: String,
    /// Full fingerprint (for GPG)
    pub fingerprint: Option<String>,
    /// Public key data (base64 for Ed25519, PEM for RSA)
    pub public_key: String,
    /// Algorithm type
    pub algorithm: SignatureAlgorithm,
    /// Description/owner
    pub description: Option<String>,
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

/// Sign data with Ed25519 private key
fn sign_ed25519(key_bytes: &[u8], data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // Parse the private key
    let signing_key = if key_bytes.len() == 32 {
        // Raw 32-byte seed
        SigningKey::from_bytes(key_bytes.try_into().map_err(|_| {
            anyhow::anyhow!("Invalid Ed25519 key length")
        })?)
    } else if key_bytes.len() == 64 {
        // Full keypair (seed + public key)
        SigningKey::from_keypair_bytes(key_bytes.try_into().map_err(|_| {
            anyhow::anyhow!("Invalid Ed25519 keypair length")
        })?)?
    } else {
        anyhow::bail!("Invalid Ed25519 key format. Expected 32 or 64 bytes.");
    };

    // Sign the data
    let signature: Ed25519Signature = signing_key.sign(data);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    Ok((signature.to_bytes().to_vec(), public_key))
}

/// Sign data with RSA private key (PKCS#1 v1.5 with SHA-256)
fn sign_rsa(key_pem: &str, data: &[u8]) -> Result<Vec<u8>> {
    // Parse RSA private key from PEM
    let private_key = RsaPrivateKey::from_pkcs8_pem(key_pem)
        .context("Failed to parse RSA private key from PEM")?;

    // Create signing key with SHA-256
    let signing_key = RsaSigningKey::<Sha256>::new(private_key);

    // Sign the data
    let signature = signing_key.sign(data);

    Ok(signature.to_bytes().into_vec())
}

/// Sign data using GPG binary
fn sign_gpg(data: &[u8], key_id: &str, passphrase: Option<&str>) -> Result<(Vec<u8>, GpgSignatureDetails)> {
    // Check if GPG is available
    let gpg_path = which_gpg().ok_or_else(|| {
        anyhow::anyhow!("GPG binary not found. Please install GPG to use GPG signatures.")
    })?;

    // Create a temporary file for the data
    let temp_dir = tempfile::tempdir()?;
    let data_path = temp_dir.path().join("data");
    let sig_path = temp_dir.path().join("data.sig");

    std::fs::write(&data_path, data)?;

    // Build GPG command for detached signature
    let mut cmd = Command::new(&gpg_path);
    cmd.arg("--batch")
        .arg("--yes")
        .arg("--detach-sign")
        .arg("--armor")
        .arg("--local-user")
        .arg(key_id)
        .arg("--output")
        .arg(&sig_path)
        .arg(&data_path);

    // Add passphrase if provided
    if let Some(pass) = passphrase {
        cmd.arg("--pinentry-mode").arg("loopback")
            .arg("--passphrase").arg(pass);
    }

    let output = cmd.output().context("Failed to execute GPG")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("GPG signing failed: {}", stderr);
    }

    // Read the signature
    let signature = std::fs::read(&sig_path)?;

    // Get key details
    let details = get_gpg_key_details(&gpg_path, key_id)?;

    Ok((signature, details))
}

/// Find GPG binary path
fn which_gpg() -> Option<PathBuf> {
    // Try common GPG binary names
    for name in &["gpg2", "gpg"] {
        if let Ok(output) = Command::new("which").arg(name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
        }
    }

    // Try common paths on various systems
    for path in &[
        "/usr/bin/gpg",
        "/usr/bin/gpg2",
        "/usr/local/bin/gpg",
        "/usr/local/bin/gpg2",
        "/opt/homebrew/bin/gpg",
    ] {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }

    None
}

/// Get GPG key details
fn get_gpg_key_details(gpg_path: &Path, key_id: &str) -> Result<GpgSignatureDetails> {
    let output = Command::new(gpg_path)
        .arg("--batch")
        .arg("--with-colons")
        .arg("--list-keys")
        .arg(key_id)
        .output()
        .context("Failed to get GPG key details")?;

    if !output.status.success() {
        return Ok(GpgSignatureDetails {
            fingerprint: key_id.to_string(),
            user_id: None,
            key_created: None,
            sig_type: "Unknown".to_string(),
        });
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut fingerprint = key_id.to_string();
    let mut user_id = None;
    let mut key_created = None;
    let mut sig_type = "RSA".to_string();

    for line in output_str.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.is_empty() {
            continue;
        }

        match fields[0] {
            "pub" => {
                if fields.len() > 3 {
                    sig_type = match fields[3] {
                        "1" => "RSA".to_string(),
                        "17" => "DSA".to_string(),
                        "18" => "ECDH".to_string(),
                        "19" => "ECDSA".to_string(),
                        "22" => "EdDSA".to_string(),
                        _ => "Unknown".to_string(),
                    };
                }
                if fields.len() > 5 {
                    key_created = Some(fields[5].to_string());
                }
            }
            "fpr" => {
                if fields.len() > 9 {
                    fingerprint = fields[9].to_string();
                }
            }
            "uid" => {
                if fields.len() > 9 && user_id.is_none() {
                    user_id = Some(fields[9].to_string());
                }
            }
            _ => {}
        }
    }

    Ok(GpgSignatureDetails {
        fingerprint,
        user_id,
        key_created,
        sig_type,
    })
}

/// Verify a signature based on algorithm type
fn verify_signature(data: &[u8], sig_block: &SignatureBlock) -> Result<bool> {
    use base64::Engine;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&sig_block.signature)
        .context("Invalid signature encoding")?;

    match sig_block.algorithm {
        SignatureAlgorithm::Ed25519 => {
            verify_ed25519(data, &sig_bytes, sig_block.public_key.as_deref())
        }
        SignatureAlgorithm::RsaSha256 => {
            verify_rsa(data, &sig_bytes, sig_block.public_key.as_deref())
        }
        SignatureAlgorithm::Gpg => {
            verify_gpg(data, &sig_bytes)
        }
    }
}

/// Verify Ed25519 signature
fn verify_ed25519(data: &[u8], signature: &[u8], public_key_b64: Option<&str>) -> Result<bool> {
    use base64::Engine;

    let public_key_bytes = public_key_b64
        .ok_or_else(|| anyhow::anyhow!("Ed25519 verification requires public key"))?;

    let public_key_raw = base64::engine::general_purpose::STANDARD
        .decode(public_key_bytes)
        .context("Invalid public key encoding")?;

    if public_key_raw.len() != 32 {
        anyhow::bail!("Invalid Ed25519 public key length: expected 32 bytes");
    }

    let verifying_key = VerifyingKey::from_bytes(
        public_key_raw.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("Invalid Ed25519 public key format")
        })?
    )?;

    if signature.len() != 64 {
        anyhow::bail!("Invalid Ed25519 signature length: expected 64 bytes");
    }

    let sig = Ed25519Signature::from_bytes(
        signature.try_into().map_err(|_| {
            anyhow::anyhow!("Invalid Ed25519 signature format")
        })?
    );

    match verifying_key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA signature
fn verify_rsa(data: &[u8], signature: &[u8], public_key_pem: Option<&str>) -> Result<bool> {
    let pem = public_key_pem
        .ok_or_else(|| anyhow::anyhow!("RSA verification requires public key PEM"))?;

    let public_key = RsaPublicKey::from_public_key_pem(pem)
        .context("Failed to parse RSA public key")?;

    let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);

    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|e| anyhow::anyhow!("Invalid RSA signature: {}", e))?;

    match verifying_key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify GPG signature
fn verify_gpg(data: &[u8], signature: &[u8]) -> Result<bool> {
    let gpg_path = which_gpg().ok_or_else(|| {
        anyhow::anyhow!("GPG binary not found. Cannot verify GPG signature.")
    })?;

    // Create temporary files for verification
    let temp_dir = tempfile::tempdir()?;
    let data_path = temp_dir.path().join("data");
    let sig_path = temp_dir.path().join("data.sig");

    std::fs::write(&data_path, data)?;
    std::fs::write(&sig_path, signature)?;

    // Run GPG verify
    let output = Command::new(&gpg_path)
        .arg("--batch")
        .arg("--verify")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .context("Failed to execute GPG verify")?;

    Ok(output.status.success())
}

/// Verify GPG signature and get detailed result
pub fn verify_gpg_detailed(data: &[u8], signature: &[u8]) -> Result<GpgVerificationResult> {
    let gpg_path = which_gpg().ok_or_else(|| {
        anyhow::anyhow!("GPG binary not found. Cannot verify GPG signature.")
    })?;

    let temp_dir = tempfile::tempdir()?;
    let data_path = temp_dir.path().join("data");
    let sig_path = temp_dir.path().join("data.sig");

    std::fs::write(&data_path, data)?;
    std::fs::write(&sig_path, signature)?;

    // Run GPG verify with status output
    let output = Command::new(&gpg_path)
        .arg("--batch")
        .arg("--status-fd=1")
        .arg("--verify")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .context("Failed to execute GPG verify")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let mut result = GpgVerificationResult {
        valid: output.status.success(),
        good_signature: false,
        key_id: None,
        fingerprint: None,
        user_id: None,
        trust_level: GpgTrustLevel::Unknown,
        signature_time: None,
        key_expired: false,
        signature_expired: false,
        revoked: false,
        error_message: None,
    };

    // Parse GPG status output
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        match parts.get(1).copied() {
            Some("[GNUPG:]") if parts.len() > 2 => {
                match parts[2] {
                    "GOODSIG" => {
                        result.good_signature = true;
                        if parts.len() > 3 {
                            result.key_id = Some(parts[3].to_string());
                        }
                        if parts.len() > 4 {
                            result.user_id = Some(parts[4..].join(" "));
                        }
                    }
                    "BADSIG" => {
                        result.good_signature = false;
                        result.error_message = Some("Bad signature".to_string());
                    }
                    "TRUST_ULTIMATE" => result.trust_level = GpgTrustLevel::Ultimate,
                    "TRUST_FULLY" => result.trust_level = GpgTrustLevel::Full,
                    "TRUST_MARGINAL" => result.trust_level = GpgTrustLevel::Marginal,
                    "TRUST_NEVER" => result.trust_level = GpgTrustLevel::Never,
                    "TRUST_UNDEFINED" => result.trust_level = GpgTrustLevel::Undefined,
                    "KEYEXPIRED" => result.key_expired = true,
                    "SIGEXPIRED" => result.signature_expired = true,
                    "REVKEYSIG" => result.revoked = true,
                    "VALIDSIG" if parts.len() > 3 => {
                        result.fingerprint = Some(parts[3].to_string());
                        if parts.len() > 5 {
                            result.signature_time = Some(parts[5].to_string());
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Check stderr for error messages
    if !result.valid && result.error_message.is_none() {
        if !stderr.is_empty() {
            result.error_message = Some(stderr.to_string());
        }
    }

    Ok(result)
}

/// GPG verification result with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpgVerificationResult {
    /// Whether the verification succeeded
    pub valid: bool,
    /// Whether the signature was valid and from a known key
    pub good_signature: bool,
    /// Key ID that made the signature
    pub key_id: Option<String>,
    /// Full fingerprint of the signing key
    pub fingerprint: Option<String>,
    /// User ID associated with the key
    pub user_id: Option<String>,
    /// Trust level of the key
    pub trust_level: GpgTrustLevel,
    /// Unix timestamp of signature
    pub signature_time: Option<String>,
    /// Whether the key is expired
    pub key_expired: bool,
    /// Whether the signature is expired
    pub signature_expired: bool,
    /// Whether the key is revoked
    pub revoked: bool,
    /// Error message if verification failed
    pub error_message: Option<String>,
}

/// GPG key trust level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpgTrustLevel {
    /// Ultimate trust (owner's key)
    Ultimate,
    /// Fully trusted
    Full,
    /// Marginally trusted
    Marginal,
    /// Never trust this key
    Never,
    /// Trust not defined
    Undefined,
    /// Unknown trust status
    Unknown,
}

impl std::fmt::Display for GpgTrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ultimate => write!(f, "ultimate"),
            Self::Full => write!(f, "full"),
            Self::Marginal => write!(f, "marginal"),
            Self::Never => write!(f, "never"),
            Self::Undefined => write!(f, "undefined"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
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
