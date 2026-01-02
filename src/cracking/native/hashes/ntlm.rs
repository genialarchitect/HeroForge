//! NTLM hash implementation
//!
//! Native implementation of Windows NTLM password hashing.

use md4::{Md4, Digest};
use crate::cracking::native::types::HashAlgorithm;

/// NTLM hash algorithm
///
/// NTLM hash is MD4(UTF-16LE(password))
#[derive(Debug, Clone, Copy, Default)]
pub struct NtlmHash;

impl NtlmHash {
    /// Convert password to UTF-16LE encoding
    fn to_utf16le(password: &str) -> Vec<u8> {
        password
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect()
    }

    /// Compute NTLM hash from password bytes (UTF-8)
    pub fn compute(password: &str) -> String {
        let utf16le = Self::to_utf16le(password);
        let mut hasher = Md4::new();
        hasher.update(&utf16le);
        let result = hasher.finalize();
        hex::encode(result)
    }
}

impl HashAlgorithm for NtlmHash {
    fn name(&self) -> &'static str {
        "NTLM"
    }

    fn hash(&self, input: &[u8]) -> String {
        // Input is UTF-8 password bytes
        let password = String::from_utf8_lossy(input);
        Self::compute(&password)
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        let computed = self.hash(plaintext);
        computed.eq_ignore_ascii_case(target_hash)
    }

    fn supports_simd(&self) -> bool {
        // MD4 in this crate doesn't use SIMD, but could be optimized
        false
    }
}

/// LM hash algorithm (legacy, insecure)
///
/// LM hash splits password into two 7-char halves, uppercases them,
/// and uses them as DES keys to encrypt a fixed constant.
#[derive(Debug, Clone, Copy, Default)]
pub struct LmHash;

impl LmHash {
    /// The "magic" constant encrypted by DES for LM hash (8 bytes)
    const MAGIC: [u8; 8] = *b"KGS!@#$%";

    /// Compute LM hash from password
    pub fn compute(password: &str) -> String {
        use des::cipher::{BlockEncrypt, KeyInit};
        use des::Des;

        // Uppercase and pad/truncate to 14 chars
        let password = password.to_uppercase();
        let password_bytes: Vec<u8> = password.bytes().take(14).collect();
        let mut padded = [0u8; 14];
        for (i, b) in password_bytes.iter().enumerate() {
            padded[i] = *b;
        }

        // Split into two 7-byte halves
        let first_half = &padded[..7];
        let second_half = &padded[7..];

        // Convert 7-byte values to 8-byte DES keys
        let key1 = Self::expand_to_des_key(first_half);
        let key2 = Self::expand_to_des_key(second_half);

        // Encrypt the magic constant with each key
        let cipher1 = Des::new_from_slice(&key1).unwrap();
        let cipher2 = Des::new_from_slice(&key2).unwrap();

        let mut block1 = Self::MAGIC;
        let mut block2 = Self::MAGIC;

        cipher1.encrypt_block((&mut block1).into());
        cipher2.encrypt_block((&mut block2).into());

        // Concatenate the results
        let mut result = [0u8; 16];
        result[..8].copy_from_slice(&block1);
        result[8..].copy_from_slice(&block2);

        hex::encode(result)
    }

    /// Expand 7-byte value to 8-byte DES key (insert parity bits)
    fn expand_to_des_key(input: &[u8]) -> [u8; 8] {
        let mut key = [0u8; 8];

        key[0] = input[0] >> 1;
        key[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2);
        key[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3);
        key[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4);
        key[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5);
        key[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6);
        key[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7);
        key[7] = input[6] & 0x7f;

        // Set odd parity
        for byte in &mut key {
            let parity = byte.count_ones() & 1;
            *byte = (*byte << 1) | (parity ^ 1) as u8;
        }

        key
    }
}

impl HashAlgorithm for LmHash {
    fn name(&self) -> &'static str {
        "LM"
    }

    fn hash(&self, input: &[u8]) -> String {
        let password = String::from_utf8_lossy(input);
        Self::compute(&password)
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        let computed = self.hash(plaintext);
        computed.eq_ignore_ascii_case(target_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_hash() {
        // Empty password
        assert_eq!(
            NtlmHash::compute(""),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );

        // "password"
        assert_eq!(
            NtlmHash::compute("password"),
            "a4f49c406510bdcab6824ee7c30fd852"
        );

        // "Password123"
        assert_eq!(
            NtlmHash::compute("Password123"),
            "2d20d252a479f485cdf5e171d93985bf"
        );
    }

    #[test]
    fn test_ntlm_verify() {
        let hasher = NtlmHash;
        assert!(hasher.verify(b"password", "a4f49c406510bdcab6824ee7c30fd852"));
        assert!(hasher.verify(b"password", "A4F49C406510BDCAB6824EE7C30FD852")); // Case insensitive
        assert!(!hasher.verify(b"wrong", "a4f49c406510bdcab6824ee7c30fd852"));
    }

    #[test]
    fn test_utf16le_encoding() {
        // ASCII
        let utf16 = NtlmHash::to_utf16le("abc");
        assert_eq!(utf16, vec![0x61, 0x00, 0x62, 0x00, 0x63, 0x00]);

        // Unicode
        let utf16 = NtlmHash::to_utf16le("€");
        assert_eq!(utf16, vec![0xac, 0x20]);
    }

    #[test]
    fn test_lm_hash() {
        // LM hash of "password"
        let hash = LmHash::compute("password");
        assert_eq!(hash.len(), 32);
        // The hash will be uppercase due to LM algorithm
    }
}
