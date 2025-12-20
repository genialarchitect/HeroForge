//! VPN credential encryption using AES-256-GCM
//!
//! Provides secure storage for VPN usernames and passwords.
//! Uses the VPN_ENCRYPTION_KEY environment variable for encryption.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::Result;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// VPN credentials (username/password for OpenVPN auth)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnCredentials {
    pub username: String,
    pub password: String,
}

impl VpnCredentials {
    /// Create new credentials
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// Get the VPN encryption key from environment
fn get_vpn_encryption_key() -> Result<[u8; 32]> {
    let key_str = std::env::var("VPN_ENCRYPTION_KEY")
        .map_err(|_| anyhow::anyhow!(
            "VPN_ENCRYPTION_KEY environment variable not set. \
             Generate one with: openssl rand -hex 32"
        ))?;

    if key_str.len() != 64 {
        return Err(anyhow::anyhow!(
            "VPN_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes)"
        ));
    }

    // Decode hex key to bytes
    let key_bytes = hex::decode(&key_str)
        .map_err(|_| anyhow::anyhow!(
            "VPN_ENCRYPTION_KEY must be a valid hex string (64 characters)"
        ))?;

    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "VPN_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)"
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Encrypt VPN credentials with AES-256-GCM
///
/// Returns base64-encoded string containing nonce + ciphertext
pub fn encrypt_vpn_credentials(credentials: &VpnCredentials) -> Result<String> {
    let key_bytes = get_vpn_encryption_key()?;
    let cipher = Aes256Gcm::new(key_bytes.as_ref().into());

    // Serialize credentials to JSON
    let json = serde_json::to_string(credentials)
        .map_err(|e| anyhow::anyhow!("Failed to serialize credentials: {}", e))?;

    // Generate random nonce (12 bytes for AES-GCM)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the JSON
    let ciphertext = cipher.encrypt(nonce, json.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt VPN credentials with AES-256-GCM
///
/// Takes base64-encoded string containing nonce + ciphertext
pub fn decrypt_vpn_credentials(encrypted: &str) -> Result<VpnCredentials> {
    let key_bytes = get_vpn_encryption_key()?;
    let cipher = Aes256Gcm::new(key_bytes.as_ref().into());

    // Decode from base64
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| anyhow::anyhow!("Failed to decode encrypted credentials: {}", e))?;

    if combined.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted credentials: too short"));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    // Parse JSON
    let json_str = String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted credentials: {}", e))?;

    let credentials: VpnCredentials = serde_json::from_str(&json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse credentials JSON: {}", e))?;

    Ok(credentials)
}

/// Check if VPN encryption key is configured
pub fn is_vpn_encryption_configured() -> bool {
    get_vpn_encryption_key().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_credentials_roundtrip() {
        // Set up test key
        std::env::set_var("VPN_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let original = VpnCredentials::new("testuser", "testpass123");
        let encrypted = encrypt_vpn_credentials(&original).unwrap();
        let decrypted = decrypt_vpn_credentials(&encrypted).unwrap();

        assert_eq!(original.username, decrypted.username);
        assert_eq!(original.password, decrypted.password);
    }

    #[test]
    #[serial]
    fn test_encryption_produces_different_ciphertext() {
        std::env::set_var("VPN_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let creds = VpnCredentials::new("user", "pass");
        let encrypted1 = encrypt_vpn_credentials(&creds).unwrap();
        let encrypted2 = encrypt_vpn_credentials(&creds).unwrap();

        // Due to random nonce, same plaintext should produce different ciphertext
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    #[serial]
    fn test_invalid_key_length() {
        std::env::set_var("VPN_ENCRYPTION_KEY", "tooshort");

        let creds = VpnCredentials::new("user", "pass");
        assert!(encrypt_vpn_credentials(&creds).is_err());
    }
}
