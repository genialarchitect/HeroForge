//! Hash type identification
//!
//! Automatically identify hash types from samples.

use regex::Regex;
use std::collections::HashMap;

/// Hash identifier
pub struct HashIdentifier {
    /// Pattern matchers
    patterns: Vec<HashPattern>,
}

/// A pattern for identifying hash types
struct HashPattern {
    /// Hash type name
    name: &'static str,
    /// Hashcat mode
    mode: i32,
    /// Regex pattern
    pattern: Regex,
    /// Confidence level
    confidence: IdentifyConfidence,
    /// Description
    description: &'static str,
}

/// Identification result
#[derive(Debug, Clone)]
pub struct HashIdentification {
    /// Most likely hash type
    pub hash_type: String,
    /// Hashcat mode
    pub mode: i32,
    /// Confidence level
    pub confidence: IdentifyConfidence,
    /// Description
    pub description: String,
    /// Alternative possibilities
    pub alternatives: Vec<AlternativeMatch>,
    /// Example format
    pub example: Option<String>,
    /// Recommended attack mode
    pub recommended_attack: Option<String>,
}

/// Alternative match
#[derive(Debug, Clone)]
pub struct AlternativeMatch {
    pub hash_type: String,
    pub mode: i32,
    pub confidence: IdentifyConfidence,
}

/// Confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifyConfidence {
    /// Definite match (unique prefix/format)
    High,
    /// Likely match
    Medium,
    /// Possible match (common format)
    Low,
}

impl HashIdentifier {
    /// Create new identifier
    pub fn new() -> Self {
        let patterns = vec![
            // Kerberos hashes (unique prefixes - high confidence)
            HashPattern {
                name: "Kerberos 5 TGS-REP (Kerberoasting)",
                mode: 13100,
                pattern: Regex::new(r"^\$krb5tgs\$\d+\$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Kerberos TGS ticket hash for service accounts",
            },
            HashPattern {
                name: "Kerberos 5 AS-REP",
                mode: 18200,
                pattern: Regex::new(r"^\$krb5asrep\$\d+\$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Kerberos AS-REP hash (no preauth required)",
            },

            // bcrypt variants (unique prefix)
            HashPattern {
                name: "bcrypt",
                mode: 3200,
                pattern: Regex::new(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "bcrypt password hash (Blowfish)",
            },

            // Unix crypt variants
            HashPattern {
                name: "SHA-512 crypt",
                mode: 1800,
                pattern: Regex::new(r"^\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Unix SHA-512 crypt",
            },
            HashPattern {
                name: "SHA-256 crypt",
                mode: 7400,
                pattern: Regex::new(r"^\$5\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{43}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Unix SHA-256 crypt",
            },
            HashPattern {
                name: "MD5 crypt",
                mode: 500,
                pattern: Regex::new(r"^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Unix MD5 crypt",
            },

            // NetNTLMv2 (contains ::)
            HashPattern {
                name: "NetNTLMv2",
                mode: 5600,
                pattern: Regex::new(r"^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "NetNTLMv2 network authentication",
            },
            HashPattern {
                name: "NetNTLMv1",
                mode: 5500,
                pattern: Regex::new(r"^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "NetNTLMv1 network authentication",
            },

            // Domain cached credentials
            HashPattern {
                name: "Domain Cached Credentials 2 (DCC2)",
                mode: 2100,
                pattern: Regex::new(r"^\$DCC2\$\d+#[^#]+#[a-fA-F0-9]{32}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Windows domain cached credentials (MSCASH2)",
            },

            // LDAP SSHA
            HashPattern {
                name: "LDAP SSHA",
                mode: 111,
                pattern: Regex::new(r"^\{SSHA\}[A-Za-z0-9+/]+=*$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "LDAP SSHA password hash",
            },

            // WPA-PMKID
            HashPattern {
                name: "WPA-PMKID-PBKDF2",
                mode: 22000,
                pattern: Regex::new(r"^WPA\*\d+\*[a-fA-F0-9]{32}\*[a-fA-F0-9]{12}\*[a-fA-F0-9]{12}\*").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "WPA/WPA2 PMKID hash",
            },

            // Pure hash formats (medium confidence - could be multiple types)
            HashPattern {
                name: "NTLM",
                mode: 1000,
                pattern: Regex::new(r"^[a-fA-F0-9]{32}$").unwrap(),
                confidence: IdentifyConfidence::Medium, // Could also be MD5
                description: "NTLM or MD5 hash (32 hex chars)",
            },
            HashPattern {
                name: "SHA-1",
                mode: 100,
                pattern: Regex::new(r"^[a-fA-F0-9]{40}$").unwrap(),
                confidence: IdentifyConfidence::Medium,
                description: "SHA-1 hash (40 hex chars)",
            },
            HashPattern {
                name: "SHA-256",
                mode: 1400,
                pattern: Regex::new(r"^[a-fA-F0-9]{64}$").unwrap(),
                confidence: IdentifyConfidence::Medium,
                description: "SHA-256 hash (64 hex chars)",
            },
            HashPattern {
                name: "SHA-512",
                mode: 1700,
                pattern: Regex::new(r"^[a-fA-F0-9]{128}$").unwrap(),
                confidence: IdentifyConfidence::Medium,
                description: "SHA-512 hash (128 hex chars)",
            },

            // Database hashes
            HashPattern {
                name: "MySQL 4.1+",
                mode: 300,
                pattern: Regex::new(r"^\*[A-F0-9]{40}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "MySQL 4.1+ password hash",
            },
            HashPattern {
                name: "PostgreSQL MD5",
                mode: 12,
                pattern: Regex::new(r"^md5[a-fA-F0-9]{32}$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "PostgreSQL MD5 password",
            },

            // Office documents
            HashPattern {
                name: "MS Office 2013",
                mode: 9600,
                pattern: Regex::new(r"^\$office\$\*2013\*").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Microsoft Office 2013 document",
            },

            // Archive formats
            HashPattern {
                name: "7-Zip",
                mode: 11600,
                pattern: Regex::new(r"^\$7z\$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "7-Zip archive",
            },
            HashPattern {
                name: "RAR5",
                mode: 13000,
                pattern: Regex::new(r"^\$rar5\$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "RAR5 archive",
            },

            // Cisco
            HashPattern {
                name: "Cisco-ASA MD5",
                mode: 2410,
                pattern: Regex::new(r"^[a-fA-F0-9]{16}:[a-fA-F0-9]{4}").unwrap(),
                confidence: IdentifyConfidence::Medium,
                description: "Cisco ASA MD5 password",
            },
            HashPattern {
                name: "Cisco Type 5",
                mode: 500,
                pattern: Regex::new(r"^\$1\$[./A-Za-z0-9]{4}\$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Cisco Type 5 (MD5 crypt)",
            },
            HashPattern {
                name: "Cisco Type 9",
                mode: 9300,
                pattern: Regex::new(r"^\$9\$[./A-Za-z0-9]+\$").unwrap(),
                confidence: IdentifyConfidence::High,
                description: "Cisco Type 9 (scrypt)",
            },
        ];

        Self { patterns }
    }

    /// Identify a hash
    pub fn identify(&self, hash: &str) -> Option<HashIdentification> {
        let hash = hash.trim();

        if hash.is_empty() {
            return None;
        }

        let mut matches: Vec<(&HashPattern, bool)> = Vec::new();

        // Find all matching patterns
        for pattern in &self.patterns {
            if pattern.pattern.is_match(hash) {
                matches.push((pattern, true));
            }
        }

        if matches.is_empty() {
            return None;
        }

        // Sort by confidence (high first)
        matches.sort_by(|a, b| {
            let conf_a = match a.0.confidence {
                IdentifyConfidence::High => 0,
                IdentifyConfidence::Medium => 1,
                IdentifyConfidence::Low => 2,
            };
            let conf_b = match b.0.confidence {
                IdentifyConfidence::High => 0,
                IdentifyConfidence::Medium => 1,
                IdentifyConfidence::Low => 2,
            };
            conf_a.cmp(&conf_b)
        });

        let primary = matches[0].0;
        let alternatives: Vec<AlternativeMatch> = matches[1..]
            .iter()
            .map(|(p, _)| AlternativeMatch {
                hash_type: p.name.to_string(),
                mode: p.mode,
                confidence: p.confidence,
            })
            .collect();

        Some(HashIdentification {
            hash_type: primary.name.to_string(),
            mode: primary.mode,
            confidence: primary.confidence,
            description: primary.description.to_string(),
            alternatives,
            example: self.get_example(primary.mode),
            recommended_attack: self.get_recommended_attack(primary.mode),
        })
    }

    /// Identify multiple hashes
    pub fn identify_batch(&self, hashes: &[String]) -> HashMap<String, HashIdentification> {
        hashes.iter()
            .filter_map(|h| {
                self.identify(h).map(|id| (h.clone(), id))
            })
            .collect()
    }

    /// Check if hashes are all the same type
    pub fn are_same_type(&self, hashes: &[String]) -> Option<i32> {
        let ids: Vec<i32> = hashes.iter()
            .filter_map(|h| self.identify(h).map(|id| id.mode))
            .collect();

        if ids.is_empty() {
            return None;
        }

        let first = ids[0];
        if ids.iter().all(|&m| m == first) {
            Some(first)
        } else {
            None
        }
    }

    fn get_example(&self, mode: i32) -> Option<String> {
        match mode {
            0 => Some("5d41402abc4b2a76b9719d911017c592".to_string()),
            100 => Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string()),
            1000 => Some("31d6cfe0d16ae931b73c59d7e0c089c0".to_string()),
            1400 => Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
            3200 => Some("$2a$10$N9qo8uLOickgx2ZMRZoMye".to_string()),
            5600 => Some("user::domain:challenge:hash:blob".to_string()),
            13100 => Some("$krb5tgs$23$*user$realm$spn*$...".to_string()),
            18200 => Some("$krb5asrep$23$user@REALM:hash".to_string()),
            _ => None,
        }
    }

    fn get_recommended_attack(&self, mode: i32) -> Option<String> {
        match mode {
            0 | 100 | 1000 | 1400 | 1700 => Some("Dictionary with rules (rockyou + best64)".to_string()),
            3200 => Some("Small wordlist (bcrypt is slow)".to_string()),
            13100 | 18200 => Some("Dictionary attack - service account passwords often weak".to_string()),
            5600 => Some("Dictionary with rules or relay attack".to_string()),
            1800 | 7400 => Some("Dictionary with small rules (slow hash)".to_string()),
            22000 => Some("Dictionary attack with WPA-specific wordlist".to_string()),
            _ => None,
        }
    }
}

impl Default for HashIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick hash identification function
pub fn identify_hash(hash: &str) -> Option<HashIdentification> {
    HashIdentifier::new().identify(hash)
}

/// Get hashcat mode for a hash
pub fn get_hashcat_mode(hash: &str) -> Option<i32> {
    identify_hash(hash).map(|id| id.mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_ntlm() {
        let id = identify_hash("31d6cfe0d16ae931b73c59d7e0c089c0");
        assert!(id.is_some());
        let id = id.unwrap();
        assert!(id.mode == 1000 || id.mode == 0); // NTLM or MD5
    }

    #[test]
    fn test_identify_kerberoast() {
        let id = identify_hash("$krb5tgs$23$*user$DOMAIN$spn*$hash");
        assert!(id.is_some());
        assert_eq!(id.unwrap().mode, 13100);
    }

    #[test]
    fn test_identify_bcrypt() {
        let id = identify_hash("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy");
        assert!(id.is_some());
        assert_eq!(id.unwrap().mode, 3200);
    }

    #[test]
    fn test_identify_asrep() {
        let id = identify_hash("$krb5asrep$23$user@DOMAIN:abc123");
        assert!(id.is_some());
        assert_eq!(id.unwrap().mode, 18200);
    }

    #[test]
    fn test_identify_sha256() {
        let id = identify_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(id.is_some());
        assert_eq!(id.unwrap().mode, 1400);
    }
}
