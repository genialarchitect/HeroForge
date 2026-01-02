//! Native Password Cracking Engine
//!
//! A pure Rust implementation of password cracking that requires no external tools.
//! Supports multiple hash types, attack modes, and includes built-in wordlists.
//!
//! # Features
//!
//! - **Multiple Hash Types**: MD5, SHA-1/256/512, NTLM, NetNTLMv2, bcrypt, Kerberos
//! - **Attack Modes**: Dictionary, brute-force, mask, rule-based
//! - **Built-in Wordlists**: Common passwords, number sequences, tech passwords
//! - **Parallel Processing**: Rayon-based parallel candidate testing
//! - **Progress Tracking**: Real-time progress updates via channels
//!
//! # Example
//!
//! ```rust,ignore
//! use heroforge::cracking::native::{
//!     NativeCrackingEngine, NativeCrackConfig, HashType, AttackMode
//! };
//!
//! // Create engine
//! let engine = NativeCrackingEngine::new(NativeCrackConfig::default());
//!
//! // Quick crack with embedded wordlist
//! let hashes = vec!["5d41402abc4b2a76b9719d911017c592".to_string()]; // MD5 of "hello"
//! let results = engine.quick_crack(hashes, HashType::Md5).await;
//!
//! for result in results {
//!     if let Some(plaintext) = result.plaintext {
//!         println!("Cracked: {} -> {}", result.hash, plaintext);
//!     }
//! }
//! ```
//!
//! # Attack Modes
//!
//! ## Dictionary Attack
//! Tests words from a wordlist against the target hashes.
//!
//! ```rust,ignore
//! let attack = DictionaryAttack::from_list(vec!["password".to_string(), "admin".to_string()]);
//! ```
//!
//! ## Brute-Force Attack
//! Generates all combinations within a character space.
//!
//! ```rust,ignore
//! // Lowercase 4-6 characters
//! let attack = BruteForceAttack::lowercase(4, 6);
//!
//! // Digits only (PINs)
//! let attack = BruteForceAttack::digits(4, 8);
//! ```
//!
//! ## Mask Attack
//! Hashcat-style mask-based generation.
//!
//! ```rust,ignore
//! // ?l = lowercase, ?d = digits, ?u = uppercase
//! let attack = MaskAttack::new("?l?l?l?l?d?d"); // 4 letters + 2 digits
//! ```
//!
//! ## Rule-Based Attack
//! Applies transformation rules to dictionary words.
//!
//! ```rust,ignore
//! let dict = DictionaryAttack::from_list(words);
//! let attack = RuleBasedAttack::common_rules(dict); // append 1, !, 123, capitalize, etc.
//! ```
//!
//! # Supported Hash Types
//!
//! | Hash Type | Hashcat Mode | Notes |
//! |-----------|--------------|-------|
//! | MD5 | 0 | Fast, SIMD optimized |
//! | SHA-1 | 100 | Fast, SIMD optimized |
//! | SHA-256 | 1400 | Fast, SIMD optimized |
//! | SHA-512 | 1700 | Fast, SIMD optimized |
//! | NTLM | 1000 | Windows password hash |
//! | NetNTLMv2 | 5600 | Network authentication |
//! | bcrypt | 3200 | Slow by design |
//! | Kerberos AS-REP | 18200 | AS-REP roasting |
//! | Kerberos TGS | 13100 | Kerberoasting |
//! | SHA-256 crypt | 7400 | Unix crypt |
//! | SHA-512 crypt | 1800 | Unix crypt |

pub mod types;
pub mod hashes;
pub mod attacks;
pub mod wordlists;
pub mod engine;

// Re-export main types
pub use types::{
    CrackResult,
    CrackProgress,
    NativeCrackConfig,
    Charset,
    BuiltinCharsets,
    MaskPlaceholder,
    MutationRule,
    HashAlgorithm,
};

pub use hashes::{
    HashType,
    Md5Hash,
    Sha1Hash,
    Sha256Hash,
    Sha512Hash,
    NtlmHash,
    NetNtlmv2Hash,
    BcryptHash,
    KerberosAsrepHash,
    KerberosTgsHash,
};

pub use attacks::{
    Attack,
    AttackExecutor,
    DictionaryAttack,
    BruteForceAttack,
    RuleBasedAttack,
    MaskAttack,
};

pub use wordlists::{
    EmbeddedWordlists,
    WordlistManager,
};

pub use engine::{
    NativeCrackingEngine,
    NativeCrackJob,
    JobStatus,
    AttackMode,
};

/// Convenience function: Quick crack with default settings
pub async fn quick_crack(hashes: Vec<String>, hash_type: HashType) -> Vec<CrackResult> {
    let engine = NativeCrackingEngine::new(NativeCrackConfig::default());
    engine.quick_crack(hashes, hash_type).await
}

/// Convenience function: Verify a password against a hash
pub fn verify_password(password: &str, hash: &str, hash_type: HashType) -> bool {
    let algorithm = hash_type.algorithm();
    algorithm.verify(password.as_bytes(), hash)
}

/// Convenience function: Hash a password
pub fn hash_password(password: &str, hash_type: HashType) -> String {
    let algorithm = hash_type.algorithm();
    algorithm.hash(password.as_bytes())
}

/// Convenience function: Detect hash type from sample
pub fn detect_hash_type(hash: &str) -> Option<HashType> {
    HashType::detect(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_password() {
        // MD5
        assert!(verify_password("hello", "5d41402abc4b2a76b9719d911017c592", HashType::Md5));
        assert!(!verify_password("wrong", "5d41402abc4b2a76b9719d911017c592", HashType::Md5));

        // NTLM
        assert!(verify_password("password", "a4f49c406510bdcab6824ee7c30fd852", HashType::Ntlm));

        // SHA-1
        assert!(verify_password("", "da39a3ee5e6b4b0d3255bfef95601890afd80709", HashType::Sha1));
    }

    #[test]
    fn test_hash_password() {
        assert_eq!(
            hash_password("hello", HashType::Md5),
            "5d41402abc4b2a76b9719d911017c592"
        );

        assert_eq!(
            hash_password("", HashType::Ntlm),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn test_detect_hash_type() {
        assert_eq!(
            detect_hash_type("31d6cfe0d16ae931b73c59d7e0c089c0"),
            Some(HashType::Ntlm)
        );

        assert_eq!(
            detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Some(HashType::Sha1)
        );

        assert_eq!(
            detect_hash_type("$2a$10$abcdefghijklmnopqrstuvwxyz"),
            Some(HashType::Bcrypt)
        );
    }

    #[tokio::test]
    async fn test_quick_crack() {
        // NTLM hash of "password" - should be in top 1000
        let hashes = vec!["a4f49c406510bdcab6824ee7c30fd852".to_string()];
        let results = quick_crack(hashes, HashType::Ntlm).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plaintext, Some("password".to_string()));
    }
}
