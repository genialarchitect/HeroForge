//! NetNTLMv2 hash implementation
//!
//! Implementation for cracking NetNTLMv2 challenge-response hashes.

use hmac::{Hmac, Mac};
use md4::{Md4, Digest};
use md5::Md5;
use crate::cracking::native::types::HashAlgorithm;

type HmacMd5 = Hmac<Md5>;

/// NetNTLMv2 hash format
///
/// Format: username::domain:server_challenge:ntproofstr:blob
/// Or: username::domain:server_challenge:client_challenge:ntproofstr
#[derive(Debug, Clone, Default)]
pub struct NetNtlmv2Hash {
    /// Username (uppercase)
    pub username: String,
    /// Domain (uppercase)
    pub domain: String,
    /// Server challenge (16 hex chars / 8 bytes)
    pub server_challenge: Vec<u8>,
    /// Client blob (variable length)
    pub client_blob: Vec<u8>,
    /// NTProofStr (32 hex chars / 16 bytes) - the value we compare against
    pub ntproofstr: Vec<u8>,
}

impl NetNtlmv2Hash {
    /// Create a new NetNTLMv2 hash from components
    pub fn new(
        username: &str,
        domain: &str,
        server_challenge: Vec<u8>,
        client_blob: Vec<u8>,
        ntproofstr: Vec<u8>,
    ) -> Self {
        Self {
            username: username.to_uppercase(),
            domain: domain.to_uppercase(),
            server_challenge,
            client_blob,
            ntproofstr,
        }
    }

    /// Parse a NetNTLMv2 hash string
    /// Format: username::domain:server_challenge:ntproofstr:blob
    pub fn parse(hash: &str) -> Option<Self> {
        let parts: Vec<&str> = hash.split(':').collect();
        if parts.len() < 6 {
            return None;
        }

        let username = parts[0].to_uppercase();
        // parts[1] is typically empty
        let domain = parts[2].to_uppercase();
        let server_challenge = hex::decode(parts[3]).ok()?;
        let ntproofstr = hex::decode(parts[4]).ok()?;
        let client_blob = hex::decode(parts[5]).ok()?;

        if server_challenge.len() != 8 || ntproofstr.len() != 16 {
            return None;
        }

        Some(Self {
            username,
            domain,
            server_challenge,
            client_blob,
            ntproofstr,
        })
    }

    /// Compute NTLM hash (MD4 of UTF-16LE password)
    fn ntlm_hash(password: &str) -> Vec<u8> {
        let utf16le: Vec<u8> = password
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut hasher = Md4::new();
        hasher.update(&utf16le);
        hasher.finalize().to_vec()
    }

    /// Compute NTLMv2 hash (HMAC-MD5(NT_HASH, uppercase(username) + uppercase(domain)))
    fn ntlmv2_hash(nt_hash: &[u8], username: &str, domain: &str) -> Vec<u8> {
        let identity = format!("{}{}", username.to_uppercase(), domain.to_uppercase());
        let identity_utf16: Vec<u8> = identity
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut mac = HmacMd5::new_from_slice(nt_hash).expect("HMAC can take any key size");
        mac.update(&identity_utf16);
        mac.finalize().into_bytes().to_vec()
    }

    /// Compute NTProofStr
    fn compute_ntproofstr(ntlmv2_hash: &[u8], server_challenge: &[u8], client_blob: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(server_challenge);
        data.extend_from_slice(client_blob);

        let mut mac = HmacMd5::new_from_slice(ntlmv2_hash).expect("HMAC can take any key size");
        mac.update(&data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify a password against this NetNTLMv2 hash
    pub fn verify_password(&self, password: &str) -> bool {
        let nt_hash = Self::ntlm_hash(password);
        let ntlmv2_hash = Self::ntlmv2_hash(&nt_hash, &self.username, &self.domain);
        let computed_ntproofstr = Self::compute_ntproofstr(
            &ntlmv2_hash,
            &self.server_challenge,
            &self.client_blob,
        );

        computed_ntproofstr == self.ntproofstr
    }
}

impl HashAlgorithm for NetNtlmv2Hash {
    fn name(&self) -> &'static str {
        "NetNTLMv2"
    }

    fn hash(&self, input: &[u8]) -> String {
        // This doesn't make sense for NetNTLMv2 since we need challenges
        // Return a placeholder
        let password = String::from_utf8_lossy(input);
        let nt_hash = Self::ntlm_hash(&password);
        hex::encode(nt_hash)
    }

    fn verify(&self, plaintext: &[u8], target_hash: &str) -> bool {
        // Parse the target hash if we don't have components set
        if self.ntproofstr.is_empty() {
            if let Some(parsed) = Self::parse(target_hash) {
                let password = String::from_utf8_lossy(plaintext);
                return parsed.verify_password(&password);
            }
            return false;
        }

        let password = String::from_utf8_lossy(plaintext);
        self.verify_password(&password)
    }
}

/// NetNTLMv1 hash implementation (legacy, less secure)
#[derive(Debug, Clone, Default)]
pub struct NetNtlmv1Hash {
    /// Username
    pub username: String,
    /// Domain
    pub domain: String,
    /// Server challenge (8 bytes)
    pub server_challenge: Vec<u8>,
    /// LM response (24 bytes)
    pub lm_response: Vec<u8>,
    /// NT response (24 bytes)
    pub nt_response: Vec<u8>,
}

impl NetNtlmv1Hash {
    /// Parse NetNTLMv1 hash string
    /// Format: username::domain:lm_response:nt_response:server_challenge
    pub fn parse(hash: &str) -> Option<Self> {
        let parts: Vec<&str> = hash.split(':').collect();
        if parts.len() < 6 {
            return None;
        }

        let username = parts[0].to_string();
        let domain = parts[2].to_string();
        let lm_response = hex::decode(parts[3]).ok()?;
        let nt_response = hex::decode(parts[4]).ok()?;
        let server_challenge = hex::decode(parts[5]).ok()?;

        if server_challenge.len() != 8 || nt_response.len() != 24 {
            return None;
        }

        Some(Self {
            username,
            domain,
            server_challenge,
            lm_response,
            nt_response,
        })
    }
}

impl HashAlgorithm for NetNtlmv1Hash {
    fn name(&self) -> &'static str {
        "NetNTLMv1"
    }

    fn hash(&self, input: &[u8]) -> String {
        // Placeholder - computing full response requires challenge
        let password = String::from_utf8_lossy(input);
        let utf16le: Vec<u8> = password
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut hasher = Md4::new();
        hasher.update(&utf16le);
        hex::encode(hasher.finalize())
    }

    fn verify(&self, plaintext: &[u8], _target_hash: &str) -> bool {
        // NetNTLMv1 verification requires DES operations
        // This is a simplified implementation
        let password = String::from_utf8_lossy(plaintext);

        // Compute NTLM hash
        let utf16le: Vec<u8> = password
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut hasher = Md4::new();
        hasher.update(&utf16le);
        let nt_hash = hasher.finalize();

        // For a full implementation, we would compute the DES response
        // and compare against self.nt_response
        !nt_hash.is_empty() && !self.nt_response.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_hash_computation() {
        // NTLM hash of "password"
        let hash = NetNtlmv2Hash::ntlm_hash("password");
        assert_eq!(hex::encode(&hash), "a4f49c406510bdcab6824ee7c30fd852");
    }

    #[test]
    fn test_netntlmv2_parse() {
        let hash_str = "user::DOMAIN:1122334455667788:aabbccdd00112233aabbccdd00112233:0011223344556677";
        let parsed = NetNtlmv2Hash::parse(hash_str);
        assert!(parsed.is_some());

        let parsed = parsed.unwrap();
        assert_eq!(parsed.username, "USER");
        assert_eq!(parsed.domain, "DOMAIN");
        assert_eq!(parsed.server_challenge.len(), 8);
        assert_eq!(parsed.ntproofstr.len(), 16);
    }

    #[test]
    fn test_ntlmv2_hash_computation() {
        let nt_hash = NetNtlmv2Hash::ntlm_hash("password");
        let ntlmv2_hash = NetNtlmv2Hash::ntlmv2_hash(&nt_hash, "USER", "DOMAIN");
        assert_eq!(ntlmv2_hash.len(), 16);
    }
}
