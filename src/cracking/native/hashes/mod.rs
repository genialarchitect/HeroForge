//! Native hash implementations
//!
//! Pure Rust implementations of various password hash algorithms.

pub mod md5_sha;
pub mod ntlm;
pub mod netntlmv2;
pub mod bcrypt;
pub mod kerberos;

pub use md5_sha::{Md5Hash, Sha1Hash, Sha256Hash, Sha512Hash};
pub use ntlm::NtlmHash;
pub use netntlmv2::NetNtlmv2Hash;
pub use bcrypt::BcryptHash;
pub use kerberos::{KerberosAsrepHash, KerberosTgsHash};

use std::sync::Arc;
use super::types::HashAlgorithm;

/// Hash algorithm registry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Ntlm,
    NetNtlmv2,
    Bcrypt,
    KerberosAsrep,
    KerberosTgs,
    Sha256Crypt,
    Sha512Crypt,
}

impl HashType {
    /// Get a hash algorithm instance for this type
    pub fn algorithm(&self) -> Arc<dyn HashAlgorithm> {
        match self {
            Self::Md5 => Arc::new(Md5Hash),
            Self::Sha1 => Arc::new(Sha1Hash),
            Self::Sha256 => Arc::new(Sha256Hash),
            Self::Sha512 => Arc::new(Sha512Hash),
            Self::Ntlm => Arc::new(NtlmHash),
            Self::NetNtlmv2 => Arc::new(NetNtlmv2Hash::default()),
            Self::Bcrypt => Arc::new(BcryptHash::default()),
            Self::KerberosAsrep => Arc::new(KerberosAsrepHash::default()),
            Self::KerberosTgs => Arc::new(KerberosTgsHash::default()),
            Self::Sha256Crypt => Arc::new(md5_sha::Sha256CryptHash::default()),
            Self::Sha512Crypt => Arc::new(md5_sha::Sha512CryptHash::default()),
        }
    }

    /// Get the hashcat mode number for this type
    pub fn hashcat_mode(&self) -> i32 {
        match self {
            Self::Md5 => 0,
            Self::Sha1 => 100,
            Self::Sha256 => 1400,
            Self::Sha512 => 1700,
            Self::Ntlm => 1000,
            Self::NetNtlmv2 => 5600,
            Self::Bcrypt => 3200,
            Self::KerberosAsrep => 18200,
            Self::KerberosTgs => 13100,
            Self::Sha256Crypt => 7400,
            Self::Sha512Crypt => 1800,
        }
    }

    /// Detect hash type from a hash string
    pub fn detect(hash: &str) -> Option<Self> {
        let hash = hash.trim();

        // Kerberos TGS (Kerberoasting)
        if hash.starts_with("$krb5tgs$") {
            return Some(Self::KerberosTgs);
        }

        // Kerberos AS-REP
        if hash.starts_with("$krb5asrep$") {
            return Some(Self::KerberosAsrep);
        }

        // bcrypt
        if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
            return Some(Self::Bcrypt);
        }

        // SHA-512 crypt
        if hash.starts_with("$6$") {
            return Some(Self::Sha512Crypt);
        }

        // SHA-256 crypt
        if hash.starts_with("$5$") {
            return Some(Self::Sha256Crypt);
        }

        // NetNTLMv2 (contains :: with multiple fields)
        if hash.contains("::") && hash.split(':').count() >= 6 {
            return Some(Self::NetNtlmv2);
        }

        // Based on length for hex hashes
        if hash.chars().all(|c| c.is_ascii_hexdigit()) {
            match hash.len() {
                32 => return Some(Self::Ntlm), // Could also be MD5
                40 => return Some(Self::Sha1),
                64 => return Some(Self::Sha256),
                128 => return Some(Self::Sha512),
                _ => {}
            }
        }

        None
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Ntlm => "NTLM",
            Self::NetNtlmv2 => "NetNTLMv2",
            Self::Bcrypt => "bcrypt",
            Self::KerberosAsrep => "Kerberos AS-REP",
            Self::KerberosTgs => "Kerberos TGS",
            Self::Sha256Crypt => "SHA-256 crypt",
            Self::Sha512Crypt => "SHA-512 crypt",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type_detection() {
        // NTLM
        assert_eq!(
            HashType::detect("31d6cfe0d16ae931b73c59d7e0c089c0"),
            Some(HashType::Ntlm)
        );

        // SHA-1
        assert_eq!(
            HashType::detect("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Some(HashType::Sha1)
        );

        // SHA-256
        assert_eq!(
            HashType::detect("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Some(HashType::Sha256)
        );

        // bcrypt
        assert_eq!(
            HashType::detect("$2a$10$N9qo8uLOickgx2ZMRZoMye"),
            Some(HashType::Bcrypt)
        );

        // Kerberos TGS
        assert_eq!(
            HashType::detect("$krb5tgs$23$*user$DOMAIN$spn*$abc123"),
            Some(HashType::KerberosTgs)
        );
    }
}
