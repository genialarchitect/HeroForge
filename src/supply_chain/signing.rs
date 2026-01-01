//! Code signing with Sigstore/Cosign
//!
//! This module provides:
//! - Binary signing using Sigstore/Cosign
//! - Container image signing
//! - Signature verification
//! - Keyless signing support (OIDC-based)

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::process::Command;

/// Check if a command exists in PATH
fn find_command(name: &str) -> Option<String> {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {}", name)])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
}

/// Code signing service
pub struct CodeSigner {
    /// Path to cosign binary (auto-detected if not specified)
    cosign_path: Option<String>,
    /// Private key path for key-based signing
    private_key: Option<String>,
    /// Use keyless signing (OIDC-based with Fulcio)
    keyless: bool,
    /// Rekor transparency log URL
    rekor_url: Option<String>,
}

impl CodeSigner {
    pub fn new() -> Self {
        Self {
            cosign_path: find_command("cosign"),
            private_key: None,
            keyless: true, // Default to keyless for ease of use
            rekor_url: Some("https://rekor.sigstore.dev".to_string()),
        }
    }

    /// Configure key-based signing
    pub fn with_key(mut self, private_key_path: &str) -> Self {
        self.private_key = Some(private_key_path.to_string());
        self.keyless = false;
        self
    }

    /// Configure keyless signing (OIDC-based)
    pub fn with_keyless(mut self) -> Self {
        self.keyless = true;
        self.private_key = None;
        self
    }

    /// Set custom Rekor URL
    pub fn with_rekor(mut self, url: &str) -> Self {
        self.rekor_url = Some(url.to_string());
        self
    }

    /// Sign binary file with Sigstore/Cosign
    ///
    /// Returns the signature in base64 format
    pub async fn sign_binary(&self, binary_path: &str) -> Result<String> {
        let path = Path::new(binary_path);
        if !path.exists() {
            anyhow::bail!("Binary file not found: {}", binary_path);
        }

        // Check for cosign availability
        let cosign = self.cosign_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Cosign not found. Install it from https://github.com/sigstore/cosign"))?;

        // Calculate file hash
        let file_content = tokio::fs::read(path).await?;
        let file_hash = format!("{:x}", Sha256::digest(&file_content));

        let mut cmd = Command::new(cosign);
        cmd.arg("sign-blob");
        cmd.arg("--yes"); // Non-interactive

        if self.keyless {
            // Keyless signing - requires OIDC provider (Google, GitHub, Microsoft)
            // In CI/CD, this uses workload identity
            // For local dev, it opens a browser for authentication
        } else if let Some(ref key) = self.private_key {
            cmd.arg("--key").arg(key);
        }

        // Output signature to stdout
        cmd.arg("--output-signature").arg("-");

        // Add Rekor transparency log
        if let Some(ref rekor) = self.rekor_url {
            cmd.arg("--rekor-url").arg(rekor);
        }

        cmd.arg(binary_path);

        let output = cmd.output().await.context("Failed to run cosign")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If cosign fails but we can still provide a hash, create a simple signature record
            if stderr.contains("no provider") || stderr.contains("OIDC") {
                log::warn!("Keyless signing unavailable, creating hash-based signature record");
                return self.create_hash_signature(binary_path, &file_hash).await;
            }
            anyhow::bail!("Cosign signing failed: {}", stderr);
        }

        let signature = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Create signature bundle
        let bundle = SignatureBundle {
            artifact_path: binary_path.to_string(),
            artifact_hash: file_hash,
            signature,
            signed_at: Utc::now().to_rfc3339(),
            signer_type: if self.keyless { "keyless" } else { "key" }.to_string(),
            rekor_url: self.rekor_url.clone(),
        };

        serde_json::to_string_pretty(&bundle)
            .context("Failed to serialize signature bundle")
    }

    /// Sign container image
    ///
    /// Returns the signature reference
    pub async fn sign_container(&self, image: &str) -> Result<String> {
        let cosign = self.cosign_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Cosign not found"))?;

        // Validate image format
        if !image.contains('/') && !image.contains(':') {
            anyhow::bail!("Invalid image format. Use: registry/image:tag or image:tag");
        }

        let mut cmd = Command::new(cosign);
        cmd.arg("sign");
        cmd.arg("--yes");

        if self.keyless {
            // Keyless signing
        } else if let Some(ref key) = self.private_key {
            cmd.arg("--key").arg(key);
        }

        if let Some(ref rekor) = self.rekor_url {
            cmd.arg("--rekor-url").arg(rekor);
        }

        cmd.arg(image);

        let output = cmd.output().await.context("Failed to run cosign")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Check for common errors
            if stderr.contains("UNAUTHORIZED") || stderr.contains("denied") {
                anyhow::bail!("Authentication required. Run 'docker login' or 'cosign login' first");
            }
            if stderr.contains("no provider") || stderr.contains("OIDC") {
                log::warn!("Keyless signing unavailable in current environment");
                return self.create_container_signature_record(image).await;
            }
            anyhow::bail!("Container signing failed: {}", stderr);
        }

        // Get the signature reference
        let sig_ref = format!("{}:sha256-{}.sig",
            image.split('@').next().unwrap_or(image),
            Sha256::digest(image.as_bytes()).iter().take(8).map(|b| format!("{:02x}", b)).collect::<String>()
        );

        let result = ContainerSignature {
            image: image.to_string(),
            signature_ref: sig_ref.clone(),
            signed_at: Utc::now().to_rfc3339(),
            signer_type: if self.keyless { "keyless" } else { "key" }.to_string(),
        };

        serde_json::to_string_pretty(&result)
            .context("Failed to serialize container signature")
    }

    /// Verify signature of a binary or container
    pub async fn verify_signature(&self, artifact: &str) -> Result<bool> {
        let cosign = self.cosign_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Cosign not found"))?;

        // Determine if it's a file or container image
        let is_file = Path::new(artifact).exists();

        let mut cmd = Command::new(cosign);

        if is_file {
            cmd.arg("verify-blob");

            // Look for signature file
            let sig_file = format!("{}.sig", artifact);
            if Path::new(&sig_file).exists() {
                cmd.arg("--signature").arg(&sig_file);
            } else {
                // Try to find signature bundle
                let bundle_file = format!("{}.sigbundle.json", artifact);
                if Path::new(&bundle_file).exists() {
                    let bundle_content = tokio::fs::read_to_string(&bundle_file).await?;
                    let bundle: SignatureBundle = serde_json::from_str(&bundle_content)?;

                    // Write signature to temp file
                    let temp_sig = std::env::temp_dir().join("temp.sig");
                    tokio::fs::write(&temp_sig, &bundle.signature).await?;
                    cmd.arg("--signature").arg(&temp_sig);
                } else {
                    anyhow::bail!("No signature file found for {}", artifact);
                }
            }

            // For keyless verification
            if self.keyless {
                cmd.arg("--certificate-identity-regexp").arg(".*");
                cmd.arg("--certificate-oidc-issuer-regexp").arg(".*");
            } else if let Some(ref key) = self.private_key {
                // Derive public key path from private key
                let pub_key = key.replace(".key", ".pub");
                if Path::new(&pub_key).exists() {
                    cmd.arg("--key").arg(&pub_key);
                }
            }

            cmd.arg(artifact);
        } else {
            // Container image verification
            cmd.arg("verify");

            if self.keyless {
                cmd.arg("--certificate-identity-regexp").arg(".*");
                cmd.arg("--certificate-oidc-issuer-regexp").arg(".*");
            } else if let Some(ref key) = self.private_key {
                let pub_key = key.replace(".key", ".pub");
                if Path::new(&pub_key).exists() {
                    cmd.arg("--key").arg(&pub_key);
                }
            }

            cmd.arg(artifact);
        }

        let output = cmd.output().await.context("Failed to run cosign verify")?;

        if output.status.success() {
            log::info!("Signature verified successfully for {}", artifact);
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Signature verification failed: {}", stderr);
            Ok(false)
        }
    }

    /// Create a hash-based signature record when cosign is unavailable
    async fn create_hash_signature(&self, path: &str, hash: &str) -> Result<String> {
        let record = SignatureBundle {
            artifact_path: path.to_string(),
            artifact_hash: hash.to_string(),
            signature: format!("sha256:{}", hash), // Use hash as signature placeholder
            signed_at: Utc::now().to_rfc3339(),
            signer_type: "hash-only".to_string(),
            rekor_url: None,
        };

        serde_json::to_string_pretty(&record)
            .context("Failed to serialize hash signature")
    }

    /// Create a container signature record when cosign is unavailable
    async fn create_container_signature_record(&self, image: &str) -> Result<String> {
        let result = ContainerSignature {
            image: image.to_string(),
            signature_ref: format!("pending:{}", Uuid::new_v4()),
            signed_at: Utc::now().to_rfc3339(),
            signer_type: "pending".to_string(),
        };

        serde_json::to_string_pretty(&result)
            .context("Failed to serialize container signature record")
    }

    /// Sign multiple artifacts in batch
    pub async fn sign_batch(&self, artifacts: &[&str]) -> Result<Vec<SignResult>> {
        let mut results = Vec::new();

        for artifact in artifacts {
            let is_container = artifact.contains('/') || artifact.contains('@');

            let result = if is_container {
                match self.sign_container(artifact).await {
                    Ok(sig) => SignResult {
                        artifact: artifact.to_string(),
                        success: true,
                        signature: Some(sig),
                        error: None,
                    },
                    Err(e) => SignResult {
                        artifact: artifact.to_string(),
                        success: false,
                        signature: None,
                        error: Some(e.to_string()),
                    },
                }
            } else {
                match self.sign_binary(artifact).await {
                    Ok(sig) => SignResult {
                        artifact: artifact.to_string(),
                        success: true,
                        signature: Some(sig),
                        error: None,
                    },
                    Err(e) => SignResult {
                        artifact: artifact.to_string(),
                        success: false,
                        signature: None,
                        error: Some(e.to_string()),
                    },
                }
            };

            results.push(result);
        }

        Ok(results)
    }

    /// Check if signing is available
    pub fn is_available(&self) -> bool {
        self.cosign_path.is_some()
    }

    /// Get signing status
    pub fn status(&self) -> SignerStatus {
        SignerStatus {
            cosign_available: self.cosign_path.is_some(),
            cosign_path: self.cosign_path.clone(),
            keyless_enabled: self.keyless,
            has_private_key: self.private_key.is_some(),
            rekor_url: self.rekor_url.clone(),
        }
    }
}

impl Default for CodeSigner {
    fn default() -> Self {
        Self::new()
    }
}

use uuid::Uuid;

/// Signature bundle for binary artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBundle {
    pub artifact_path: String,
    pub artifact_hash: String,
    pub signature: String,
    pub signed_at: String,
    pub signer_type: String,
    pub rekor_url: Option<String>,
}

/// Container image signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSignature {
    pub image: String,
    pub signature_ref: String,
    pub signed_at: String,
    pub signer_type: String,
}

/// Batch signing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub artifact: String,
    pub success: bool,
    pub signature: Option<String>,
    pub error: Option<String>,
}

/// Signer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerStatus {
    pub cosign_available: bool,
    pub cosign_path: Option<String>,
    pub keyless_enabled: bool,
    pub has_private_key: bool,
    pub rekor_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_signer_creation() {
        let signer = CodeSigner::new();
        // Cosign may or may not be installed
        let status = signer.status();
        assert!(status.keyless_enabled);
    }

    #[test]
    fn test_signer_with_key() {
        let signer = CodeSigner::new().with_key("/path/to/key.pem");
        let status = signer.status();
        assert!(!status.keyless_enabled);
        assert!(status.has_private_key);
    }

    #[test]
    fn test_signature_bundle_serialization() {
        let bundle = SignatureBundle {
            artifact_path: "/path/to/binary".to_string(),
            artifact_hash: "abc123".to_string(),
            signature: "sig123".to_string(),
            signed_at: "2024-01-01T00:00:00Z".to_string(),
            signer_type: "keyless".to_string(),
            rekor_url: Some("https://rekor.sigstore.dev".to_string()),
        };

        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: SignatureBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.artifact_path, bundle.artifact_path);
        assert_eq!(parsed.signature, bundle.signature);
    }

    #[tokio::test]
    async fn test_hash_signature_fallback() {
        let signer = CodeSigner::new();
        let result = signer.create_hash_signature("/test/path", "abc123def456").await.unwrap();

        let bundle: SignatureBundle = serde_json::from_str(&result).unwrap();
        assert_eq!(bundle.signer_type, "hash-only");
        assert!(bundle.signature.contains("sha256:"));
    }
}
