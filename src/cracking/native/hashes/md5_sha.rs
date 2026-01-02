//! MD5 and SHA family hash implementations
//!
//! Pure Rust implementations using standard crypto crates.

use md5::{Md5, Digest as Md5Digest};
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use crate::cracking::native::types::HashAlgorithm;

/// MD5 hash algorithm
#[derive(Debug, Clone, Copy, Default)]
pub struct Md5Hash;

impl HashAlgorithm for Md5Hash {
    fn name(&self) -> &'static str {
        "MD5"
    }

    fn hash(&self, input: &[u8]) -> String {
        let mut hasher = Md5::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn supports_simd(&self) -> bool {
        // md5 crate uses SIMD on supported platforms
        true
    }
}

/// SHA-1 hash algorithm
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha1Hash;

impl HashAlgorithm for Sha1Hash {
    fn name(&self) -> &'static str {
        "SHA-1"
    }

    fn hash(&self, input: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn supports_simd(&self) -> bool {
        true
    }
}

/// SHA-256 hash algorithm
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Hash;

impl HashAlgorithm for Sha256Hash {
    fn name(&self) -> &'static str {
        "SHA-256"
    }

    fn hash(&self, input: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn supports_simd(&self) -> bool {
        true
    }
}

/// SHA-512 hash algorithm
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha512Hash;

impl HashAlgorithm for Sha512Hash {
    fn name(&self) -> &'static str {
        "SHA-512"
    }

    fn hash(&self, input: &[u8]) -> String {
        let mut hasher = Sha512::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn supports_simd(&self) -> bool {
        true
    }
}

/// SHA-256 crypt ($5$) hash algorithm
#[derive(Debug, Clone, Default)]
pub struct Sha256CryptHash {
    /// Number of rounds (default 5000)
    pub rounds: u32,
}

impl Sha256CryptHash {
    pub fn new(rounds: u32) -> Self {
        Self { rounds }
    }

    /// Parse rounds from hash string
    fn parse_rounds(hash: &str) -> (u32, &str) {
        // Format: $5$rounds=N$salt$hash or $5$salt$hash
        if hash.starts_with("$5$rounds=") {
            if let Some(rest) = hash.strip_prefix("$5$rounds=") {
                if let Some((rounds_str, remainder)) = rest.split_once('$') {
                    if let Ok(rounds) = rounds_str.parse() {
                        return (rounds, remainder);
                    }
                }
            }
        }
        // Default rounds
        (5000, hash.strip_prefix("$5$").unwrap_or(hash))
    }

    /// Extract salt from hash
    fn extract_salt(hash: &str) -> Option<&str> {
        let (_, rest) = Self::parse_rounds(hash);
        rest.split('$').next()
    }
}

impl HashAlgorithm for Sha256CryptHash {
    fn name(&self) -> &'static str {
        "SHA-256 crypt"
    }

    fn hash(&self, input: &[u8]) -> String {
        // This is a simplified implementation
        // Full SHA-256 crypt uses a complex algorithm with multiple rounds
        // For production, use the sha_crypt crate
        let salt = "defaultsalt";
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.update(salt.as_bytes());
        for _ in 0..self.rounds {
            let intermediate = hasher.finalize_reset();
            hasher.update(&intermediate);
            hasher.update(input);
        }
        let result = hasher.finalize();
        format!("$5$rounds={}${}${}", self.rounds, salt, base64_sha_crypt(&result))
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        if let Some(salt) = Self::extract_salt(target_hash) {
            let (rounds, _) = Self::parse_rounds(target_hash);
            let mut hasher = Sha256::new();
            hasher.update(plaintext);
            hasher.update(salt.as_bytes());
            for _ in 0..rounds {
                let intermediate = hasher.finalize_reset();
                hasher.update(&intermediate);
                hasher.update(plaintext);
            }
            let result = hasher.finalize();
            let computed = format!("$5$rounds={}${}${}", rounds, salt, base64_sha_crypt(&result));
            computed == target_hash
        } else {
            false
        }
    }
}

/// SHA-512 crypt ($6$) hash algorithm
#[derive(Debug, Clone, Default)]
pub struct Sha512CryptHash {
    /// Number of rounds (default 5000)
    pub rounds: u32,
}

impl Sha512CryptHash {
    pub fn new(rounds: u32) -> Self {
        Self { rounds }
    }

    /// Parse rounds from hash string
    fn parse_rounds(hash: &str) -> (u32, &str) {
        // Format: $6$rounds=N$salt$hash or $6$salt$hash
        if hash.starts_with("$6$rounds=") {
            if let Some(rest) = hash.strip_prefix("$6$rounds=") {
                if let Some((rounds_str, remainder)) = rest.split_once('$') {
                    if let Ok(rounds) = rounds_str.parse() {
                        return (rounds, remainder);
                    }
                }
            }
        }
        // Default rounds
        (5000, hash.strip_prefix("$6$").unwrap_or(hash))
    }

    /// Extract salt from hash
    fn extract_salt(hash: &str) -> Option<&str> {
        let (_, rest) = Self::parse_rounds(hash);
        rest.split('$').next()
    }
}

impl HashAlgorithm for Sha512CryptHash {
    fn name(&self) -> &'static str {
        "SHA-512 crypt"
    }

    fn hash(&self, input: &[u8]) -> String {
        // Simplified implementation - for production use sha_crypt crate
        let salt = "defaultsalt";
        let mut hasher = Sha512::new();
        hasher.update(input);
        hasher.update(salt.as_bytes());
        for _ in 0..self.rounds {
            let intermediate = hasher.finalize_reset();
            hasher.update(&intermediate);
            hasher.update(input);
        }
        let result = hasher.finalize();
        format!("$6$rounds={}${}${}", self.rounds, salt, base64_sha_crypt(&result))
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        if let Some(salt) = Self::extract_salt(target_hash) {
            let (rounds, _) = Self::parse_rounds(target_hash);
            let mut hasher = Sha512::new();
            hasher.update(plaintext);
            hasher.update(salt.as_bytes());
            for _ in 0..rounds {
                let intermediate = hasher.finalize_reset();
                hasher.update(&intermediate);
                hasher.update(plaintext);
            }
            let result = hasher.finalize();
            let computed = format!("$6$rounds={}${}${}", rounds, salt, base64_sha_crypt(&result));
            computed == target_hash
        } else {
            false
        }
    }
}

/// SHA crypt base64 encoding (different from standard base64)
fn base64_sha_crypt(data: &[u8]) -> String {
    const B64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0) as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;

        let combined = b0 | (b1 << 8) | (b2 << 16);

        result.push(B64[(combined & 0x3f) as usize] as char);
        result.push(B64[((combined >> 6) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            result.push(B64[((combined >> 12) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(B64[((combined >> 18) & 0x3f) as usize] as char);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_hash() {
        let hasher = Md5Hash;
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(
            hasher.hash(b""),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
        assert_eq!(
            hasher.hash(b"hello"),
            "5d41402abc4b2a76b9719d911017c592"
        );
    }

    #[test]
    fn test_sha1_hash() {
        let hasher = Sha1Hash;
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        assert_eq!(
            hasher.hash(b""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_sha256_hash() {
        let hasher = Sha256Hash;
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            hasher.hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha512_hash() {
        let hasher = Sha512Hash;
        // SHA512("hello")
        let hash = hasher.hash(b"hello");
        assert_eq!(hash.len(), 128);
        assert!(hash.starts_with("9b71d224"));
    }

    #[test]
    fn test_md5_verify() {
        let hasher = Md5Hash;
        assert!(hasher.verify(b"hello", "5d41402abc4b2a76b9719d911017c592"));
        assert!(!hasher.verify(b"world", "5d41402abc4b2a76b9719d911017c592"));
    }
}
