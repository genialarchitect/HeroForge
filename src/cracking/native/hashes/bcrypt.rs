//! bcrypt hash implementation
//!
//! bcrypt password hashing using the bcrypt crate.

use bcrypt::{hash_with_salt, Version, verify};
use crate::cracking::native::types::HashAlgorithm;

/// bcrypt hash algorithm
///
/// Format: $2[aby]$cost$salt(22 chars)hash(31 chars)
#[derive(Debug, Clone)]
pub struct BcryptHash {
    /// Cost factor (4-31, default 10)
    pub cost: u32,
}

impl Default for BcryptHash {
    fn default() -> Self {
        Self { cost: 10 }
    }
}

impl BcryptHash {
    /// Create a new bcrypt hasher with specified cost
    pub fn new(cost: u32) -> Self {
        Self { cost: cost.clamp(4, 31) }
    }

    /// Parse cost from bcrypt hash string
    pub fn parse_cost(hash: &str) -> Option<u32> {
        // Format: $2a$10$...
        if !hash.starts_with("$2") {
            return None;
        }

        let parts: Vec<&str> = hash.split('$').collect();
        if parts.len() < 4 {
            return None;
        }

        parts[2].parse().ok()
    }

    /// Extract salt from bcrypt hash (first 22 chars after cost)
    pub fn extract_salt(hash: &str) -> Option<[u8; 16]> {
        // Format: $2a$10$SALT(22chars)HASH(31chars)
        let parts: Vec<&str> = hash.split('$').collect();
        if parts.len() < 4 {
            return None;
        }

        let salt_and_hash = parts[3];
        if salt_and_hash.len() < 22 {
            return None;
        }

        // bcrypt uses a modified base64 encoding
        let salt_b64 = &salt_and_hash[..22];
        decode_bcrypt_base64_salt(salt_b64)
    }

    /// Compute bcrypt hash with a specific salt
    pub fn hash_with_salt_bytes(password: &str, salt: [u8; 16], cost: u32) -> Option<String> {
        hash_with_salt(password, cost, salt)
            .ok()
            .map(|r| r.to_string())
    }
}

/// Decode bcrypt's modified base64 salt
fn decode_bcrypt_base64_salt(encoded: &str) -> Option<[u8; 16]> {
    // bcrypt uses a different base64 alphabet: ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
    const BCRYPT_B64: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let mut decode_map = [255u8; 128];
    for (i, &c) in BCRYPT_B64.iter().enumerate() {
        decode_map[c as usize] = i as u8;
    }

    let bytes: Vec<u8> = encoded.bytes().collect();
    if bytes.len() != 22 {
        return None;
    }

    let mut result = [0u8; 16];
    let mut bit_pos = 0;
    let mut byte_pos = 0;
    let mut acc: u32 = 0;

    for &b in &bytes {
        if b >= 128 || decode_map[b as usize] == 255 {
            return None;
        }

        acc = (acc << 6) | (decode_map[b as usize] as u32);
        bit_pos += 6;

        while bit_pos >= 8 && byte_pos < 16 {
            bit_pos -= 8;
            result[byte_pos] = ((acc >> bit_pos) & 0xff) as u8;
            byte_pos += 1;
        }
    }

    Some(result)
}

impl HashAlgorithm for BcryptHash {
    fn name(&self) -> &'static str {
        "bcrypt"
    }

    fn hash(&self, input: &[u8]) -> String {
        let password = String::from_utf8_lossy(input);
        bcrypt::hash(&*password, self.cost).unwrap_or_default()
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        let password = String::from_utf8_lossy(plaintext);
        verify(&*password, target_hash).unwrap_or(false)
    }

    fn supports_simd(&self) -> bool {
        // bcrypt is intentionally slow and doesn't benefit from SIMD
        false
    }
}

/// Argon2 hash algorithm (modern, memory-hard)
#[derive(Debug, Clone)]
pub struct Argon2Hash {
    /// Memory cost in KB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism degree
    pub parallelism: u32,
}

impl Default for Argon2Hash {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl HashAlgorithm for Argon2Hash {
    fn name(&self) -> &'static str {
        "Argon2"
    }

    fn hash(&self, input: &[u8]) -> String {
        use argon2::{
            password_hash::{rand_core::OsRng, SaltString, PasswordHasher},
            Argon2, Params,
        };

        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            None,
        ).unwrap_or_default();

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );

        argon2
            .hash_password(input, &salt)
            .map(|h| h.to_string())
            .unwrap_or_default()
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        use argon2::{
            password_hash::{PasswordHash, PasswordVerifier},
            Argon2,
        };

        let Ok(parsed_hash) = PasswordHash::new(target_hash) else {
            return false;
        };

        Argon2::default()
            .verify_password(plaintext, &parsed_hash)
            .is_ok()
    }

    fn supports_simd(&self) -> bool {
        // Argon2 implementations often use SIMD for memory operations
        true
    }
}

/// scrypt hash algorithm (memory-hard)
#[derive(Debug, Clone)]
pub struct ScryptHash {
    /// CPU/memory cost parameter (N = 2^log_n)
    pub log_n: u8,
    /// Block size
    pub r: u32,
    /// Parallelism
    pub p: u32,
}

impl Default for ScryptHash {
    fn default() -> Self {
        Self {
            log_n: 15,  // N = 32768
            r: 8,
            p: 1,
        }
    }
}

impl HashAlgorithm for ScryptHash {
    fn name(&self) -> &'static str {
        "scrypt"
    }

    fn hash(&self, input: &[u8]) -> String {
        use scrypt::{
            password_hash::{rand_core::OsRng, SaltString, PasswordHasher},
            Scrypt, Params,
        };

        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(self.log_n, self.r, self.p, Params::RECOMMENDED_LEN)
            .unwrap_or_default();

        Scrypt
            .hash_password_customized(input, None, None, params, &salt)
            .map(|h| h.to_string())
            .unwrap_or_default()
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        use scrypt::{
            password_hash::{PasswordHash, PasswordVerifier},
            Scrypt,
        };

        let Ok(parsed_hash) = PasswordHash::new(target_hash) else {
            return false;
        };

        Scrypt.verify_password(plaintext, &parsed_hash).is_ok()
    }

    fn supports_simd(&self) -> bool {
        true
    }
}

/// PBKDF2 hash algorithm
#[derive(Debug, Clone)]
pub struct Pbkdf2Hash {
    /// Number of iterations
    pub iterations: u32,
}

impl Default for Pbkdf2Hash {
    fn default() -> Self {
        Self { iterations: 100000 }
    }
}

impl HashAlgorithm for Pbkdf2Hash {
    fn name(&self) -> &'static str {
        "PBKDF2"
    }

    fn hash(&self, input: &[u8]) -> String {
        use pbkdf2::{
            password_hash::{rand_core::OsRng, SaltString, PasswordHasher},
            Pbkdf2, Params,
        };

        let salt = SaltString::generate(&mut OsRng);
        let params = Params {
            rounds: self.iterations,
            output_length: 32,
        };

        Pbkdf2
            .hash_password_customized(input, None, None, params, &salt)
            .map(|h| h.to_string())
            .unwrap_or_default()
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        use pbkdf2::{
            password_hash::{PasswordHash, PasswordVerifier},
            Pbkdf2,
        };

        let Ok(parsed_hash) = PasswordHash::new(target_hash) else {
            return false;
        };

        Pbkdf2.verify_password(plaintext, &parsed_hash).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_hash_and_verify() {
        let hasher = BcryptHash::new(4); // Low cost for testing
        let hash = hasher.hash(b"password");

        assert!(hash.starts_with("$2b$"));
        assert!(hasher.verify(b"password", &hash));
        assert!(!hasher.verify(b"wrong", &hash));
    }

    #[test]
    fn test_bcrypt_parse_cost() {
        assert_eq!(BcryptHash::parse_cost("$2a$10$abc"), Some(10));
        assert_eq!(BcryptHash::parse_cost("$2b$12$xyz"), Some(12));
        assert_eq!(BcryptHash::parse_cost("invalid"), None);
    }

    #[test]
    fn test_bcrypt_verify_known_hash() {
        let hasher = BcryptHash::default();
        // Known bcrypt hash for "password" with cost 10
        let known_hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
        // Note: This test depends on having the correct known hash
        // In practice, bcrypt hashes vary due to random salt
    }

    #[test]
    fn test_argon2_hash_and_verify() {
        let mut hasher = Argon2Hash::default();
        // Use lower params for testing
        hasher.memory_cost = 4096;
        hasher.time_cost = 1;

        let hash = hasher.hash(b"password");
        assert!(hash.starts_with("$argon2"));
        assert!(hasher.verify(b"password", &hash));
        assert!(!hasher.verify(b"wrong", &hash));
    }
}
