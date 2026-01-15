//! eMASS PKI Authentication
//!
//! Handles PKI/CAC certificate authentication for eMASS API.

use anyhow::{Result, bail, Context};
use reqwest::Identity;
use std::path::Path;

/// PKI certificate loader
pub struct PkiAuth;

impl PkiAuth {
    /// Load identity from PKCS#12 file
    pub fn load_pkcs12(path: &str, password: &str) -> Result<Identity> {
        let cert_data = std::fs::read(path)
            .with_context(|| format!("Failed to read certificate file: {}", path))?;

        let identity = Identity::from_pkcs12_der(&cert_data, password)
            .context("Failed to parse PKCS#12 certificate")?;

        Ok(identity)
    }

    /// Load identity from PEM files (certificate + key)
    pub fn load_pem(cert_path: &str, key_path: &str) -> Result<Identity> {
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read certificate: {}", cert_path))?;
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("Failed to read key: {}", key_path))?;

        let identity = Identity::from_pem(&[cert_pem, key_pem].concat())
            .context("Failed to parse PEM certificate/key")?;

        Ok(identity)
    }

    /// Check if a certificate file exists and is readable
    pub fn validate_certificate(path: &str) -> Result<bool> {
        let path = Path::new(path);
        if !path.exists() {
            return Ok(false);
        }
        if !path.is_file() {
            bail!("Certificate path is not a file: {}", path.display());
        }
        // Try to read the file
        std::fs::read(path)?;
        Ok(true)
    }
}
