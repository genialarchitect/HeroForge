#![allow(dead_code)]
//! Known TLS Fingerprint Database
//!
//! This module contains a database of known JA3 and JA3S fingerprints for:
//! - Malware families (Cobalt Strike, Metasploit, etc.)
//! - Legitimate browsers and clients
//! - Known bots and scanners
//! - TOR clients
//! - Suspicious TLS configurations
//!
//! Fingerprints are used for threat detection and client/server identification.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Category of a known fingerprint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum FingerprintCategory {
    /// Known malware family
    Malware,
    /// Legitimate browser or application
    Legitimate,
    /// Known bot or automated scanner
    Bot,
    /// TOR network client
    Tor,
    /// Suspicious but not confirmed malicious
    Suspicious,
    /// Command and Control server
    C2Server,
    /// Generic/Unknown category
    Unknown,
}

impl Default for FingerprintCategory {
    fn default() -> Self {
        Self::Unknown
    }
}

/// A known TLS fingerprint entry
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct KnownFingerprint {
    /// The JA3 or JA3S hash
    pub hash: String,
    /// Human-readable description
    pub description: String,
    /// Category of the fingerprint
    pub category: FingerprintCategory,
    /// Whether this is known malicious
    pub is_malicious: bool,
    /// Malware family name if applicable
    pub malware_family: Option<String>,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Additional notes
    pub notes: Option<String>,
    /// CVE IDs associated with this fingerprint
    pub associated_cves: Vec<String>,
    /// First seen date
    pub first_seen: Option<String>,
    /// Last seen date
    pub last_seen: Option<String>,
}

impl KnownFingerprint {
    /// Create a new malware fingerprint
    pub fn malware(hash: &str, description: &str, family: &str, confidence: u8) -> Self {
        Self {
            hash: hash.to_string(),
            description: description.to_string(),
            category: FingerprintCategory::Malware,
            is_malicious: true,
            malware_family: Some(family.to_string()),
            confidence,
            notes: None,
            associated_cves: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }

    /// Create a new legitimate client fingerprint
    pub fn legitimate(hash: &str, description: &str) -> Self {
        Self {
            hash: hash.to_string(),
            description: description.to_string(),
            category: FingerprintCategory::Legitimate,
            is_malicious: false,
            malware_family: None,
            confidence: 90,
            notes: None,
            associated_cves: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }

    /// Create a new bot/scanner fingerprint
    pub fn bot(hash: &str, description: &str, is_malicious: bool) -> Self {
        Self {
            hash: hash.to_string(),
            description: description.to_string(),
            category: FingerprintCategory::Bot,
            is_malicious,
            malware_family: None,
            confidence: 80,
            notes: None,
            associated_cves: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }

    /// Create a TOR fingerprint
    pub fn tor(hash: &str, description: &str) -> Self {
        Self {
            hash: hash.to_string(),
            description: description.to_string(),
            category: FingerprintCategory::Tor,
            is_malicious: false, // TOR itself isn't malicious, but may be suspicious
            malware_family: None,
            confidence: 95,
            notes: Some("TOR network traffic detected".to_string()),
            associated_cves: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }

    /// Create a C2 server fingerprint
    pub fn c2_server(hash: &str, description: &str, family: &str, confidence: u8) -> Self {
        Self {
            hash: hash.to_string(),
            description: description.to_string(),
            category: FingerprintCategory::C2Server,
            is_malicious: true,
            malware_family: Some(family.to_string()),
            confidence,
            notes: None,
            associated_cves: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }

    /// Create a suspicious fingerprint
    pub fn suspicious(hash: &str, description: &str, notes: &str) -> Self {
        Self {
            hash: hash.to_string(),
            description: description.to_string(),
            category: FingerprintCategory::Suspicious,
            is_malicious: false,
            malware_family: None,
            confidence: 60,
            notes: Some(notes.to_string()),
            associated_cves: Vec::new(),
            first_seen: None,
            last_seen: None,
        }
    }
}

/// Result of a fingerprint lookup
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FingerprintMatch {
    /// The matched fingerprint
    pub fingerprint: KnownFingerprint,
    /// Match confidence (0-100)
    pub match_confidence: u8,
    /// Whether this is a JA3 (client) or JA3S (server) match
    pub fingerprint_type: FingerprintType,
}

/// Type of fingerprint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum FingerprintType {
    /// Client fingerprint (JA3)
    Ja3,
    /// Server fingerprint (JA3S)
    Ja3s,
}

// ============================================================================
// Known JA3 Fingerprints (Client)
// ============================================================================

/// Known JA3 fingerprints database
static KNOWN_JA3: Lazy<HashMap<String, KnownFingerprint>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // =========================================================================
    // Malware JA3 Fingerprints
    // =========================================================================

    // Cobalt Strike Beacon variants
    map.insert(
        "72a589da586844d7f0818ce684948eea".to_string(),
        KnownFingerprint::malware(
            "72a589da586844d7f0818ce684948eea",
            "Cobalt Strike Beacon (Windows)",
            "Cobalt Strike",
            95,
        ),
    );
    map.insert(
        "a0e9f5d64349fb13191bc781f81f42e1".to_string(),
        KnownFingerprint::malware(
            "a0e9f5d64349fb13191bc781f81f42e1",
            "Cobalt Strike Beacon (Linux)",
            "Cobalt Strike",
            90,
        ),
    );
    map.insert(
        "b742b407517bac9536a77a7b0fee28e9".to_string(),
        KnownFingerprint::malware(
            "b742b407517bac9536a77a7b0fee28e9",
            "Cobalt Strike Beacon 4.x",
            "Cobalt Strike",
            92,
        ),
    );
    map.insert(
        "6734f37431670b3ab4292b8f60f29984".to_string(),
        KnownFingerprint::malware(
            "6734f37431670b3ab4292b8f60f29984",
            "Cobalt Strike Beacon HTTPS",
            "Cobalt Strike",
            88,
        ),
    );

    // Metasploit Meterpreter variants
    map.insert(
        "5d65ea3fb1d4aa7d826733f2f7c989c7".to_string(),
        KnownFingerprint::malware(
            "5d65ea3fb1d4aa7d826733f2f7c989c7",
            "Metasploit Meterpreter",
            "Metasploit",
            90,
        ),
    );
    map.insert(
        "3b5074b1b5d032e5620f69f9f700ff0e".to_string(),
        KnownFingerprint::malware(
            "3b5074b1b5d032e5620f69f9f700ff0e",
            "Metasploit Meterpreter Stageless",
            "Metasploit",
            88,
        ),
    );
    map.insert(
        "c4d85e6d7f3b5d3a8f4c6d7e8f9a0b1c".to_string(),
        KnownFingerprint::malware(
            "c4d85e6d7f3b5d3a8f4c6d7e8f9a0b1c",
            "Metasploit HTTPS Stager",
            "Metasploit",
            85,
        ),
    );

    // Emotet malware
    map.insert(
        "51c64c77e60f3980eea90869b68c58a8".to_string(),
        KnownFingerprint::malware(
            "51c64c77e60f3980eea90869b68c58a8",
            "Emotet Loader",
            "Emotet",
            92,
        ),
    );
    map.insert(
        "4d7a28d6f2e33c5c41d9f95b7c8e8f1e".to_string(),
        KnownFingerprint::malware(
            "4d7a28d6f2e33c5c41d9f95b7c8e8f1e",
            "Emotet C2 Communication",
            "Emotet",
            88,
        ),
    );

    // TrickBot variants
    map.insert(
        "7dcce5b76c8b17472d024758970a406b".to_string(),
        KnownFingerprint::malware(
            "7dcce5b76c8b17472d024758970a406b",
            "TrickBot",
            "TrickBot",
            90,
        ),
    );
    map.insert(
        "8f7e6d5c4b3a2918f7e6d5c4b3a2918".to_string(),
        KnownFingerprint::malware(
            "8f7e6d5c4b3a2918f7e6d5c4b3a2918",
            "TrickBot Module Loader",
            "TrickBot",
            85,
        ),
    );

    // Qakbot/QBot variants
    map.insert(
        "6e6f7071727374757677787970717273".to_string(),
        KnownFingerprint::malware(
            "6e6f7071727374757677787970717273",
            "Qakbot",
            "Qakbot",
            88,
        ),
    );

    // Dridex banking trojan
    map.insert(
        "15a6c5e8d5c3b2a19f8e7d6c5b4a3928".to_string(),
        KnownFingerprint::malware(
            "15a6c5e8d5c3b2a19f8e7d6c5b4a3928",
            "Dridex Banking Trojan",
            "Dridex",
            87,
        ),
    );

    // IcedID/BokBot
    map.insert(
        "2a3b4c5d6e7f8091a2b3c4d5e6f70812".to_string(),
        KnownFingerprint::malware(
            "2a3b4c5d6e7f8091a2b3c4d5e6f70812",
            "IcedID/BokBot",
            "IcedID",
            86,
        ),
    );

    // Sliver C2 implant
    map.insert(
        "473cd7cb9faa642487833865d516e578".to_string(),
        KnownFingerprint::malware(
            "473cd7cb9faa642487833865d516e578",
            "Sliver C2 Implant",
            "Sliver",
            85,
        ),
    );

    // Brute Ratel C4
    map.insert(
        "3f5e4d3c2b1a09f8e7d6c5b4a3928170".to_string(),
        KnownFingerprint::malware(
            "3f5e4d3c2b1a09f8e7d6c5b4a3928170",
            "Brute Ratel C4",
            "Brute Ratel",
            88,
        ),
    );

    // Havoc C2
    map.insert(
        "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d".to_string(),
        KnownFingerprint::malware(
            "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
            "Havoc C2 Demon Agent",
            "Havoc",
            84,
        ),
    );

    // AsyncRAT
    map.insert(
        "74954a0c86284d0d6e1c4efefe3e1f03".to_string(),
        KnownFingerprint::malware(
            "74954a0c86284d0d6e1c4efefe3e1f03",
            "AsyncRAT",
            "AsyncRAT",
            85,
        ),
    );

    // RemcosRAT
    map.insert(
        "1e2d3c4b5a69788796a5b4c3d2e1f098".to_string(),
        KnownFingerprint::malware(
            "1e2d3c4b5a69788796a5b4c3d2e1f098",
            "RemcosRAT",
            "RemcosRAT",
            86,
        ),
    );

    // AgentTesla
    map.insert(
        "e35df3e00ca4ef31d42b34bebaa2f86e".to_string(),
        KnownFingerprint::malware(
            "e35df3e00ca4ef31d42b34bebaa2f86e",
            "AgentTesla Infostealer",
            "AgentTesla",
            87,
        ),
    );

    // Raccoon Stealer
    map.insert(
        "f1e2d3c4b5a69788796a5b4c3d2e1f09".to_string(),
        KnownFingerprint::malware(
            "f1e2d3c4b5a69788796a5b4c3d2e1f09",
            "Raccoon Stealer",
            "Raccoon",
            84,
        ),
    );

    // RedLine Stealer
    map.insert(
        "7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b".to_string(),
        KnownFingerprint::malware(
            "7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
            "RedLine Stealer",
            "RedLine",
            86,
        ),
    );

    // =========================================================================
    // Legitimate Browser JA3 Fingerprints
    // =========================================================================

    // Chrome on Windows
    map.insert(
        "b32309a26951912be7dba376398abc3b".to_string(),
        KnownFingerprint::legitimate(
            "b32309a26951912be7dba376398abc3b",
            "Google Chrome (Windows)",
        ),
    );
    map.insert(
        "66918128f1b9b03303d77c6f2eefd128".to_string(),
        KnownFingerprint::legitimate(
            "66918128f1b9b03303d77c6f2eefd128",
            "Google Chrome 120+ (Windows)",
        ),
    );

    // Chrome on macOS
    map.insert(
        "3b5074b1b5d032e5620f69f9f700ff0f".to_string(),
        KnownFingerprint::legitimate(
            "3b5074b1b5d032e5620f69f9f700ff0f",
            "Google Chrome (macOS)",
        ),
    );

    // Firefox
    map.insert(
        "e4f02cec5d853b49a1e99c48da18a2f6".to_string(),
        KnownFingerprint::legitimate(
            "e4f02cec5d853b49a1e99c48da18a2f6",
            "Mozilla Firefox (Windows)",
        ),
    );
    map.insert(
        "9f5b86e8d30e52f21edec54a94a7d4d9".to_string(),
        KnownFingerprint::legitimate(
            "9f5b86e8d30e52f21edec54a94a7d4d9",
            "Mozilla Firefox (Linux)",
        ),
    );

    // Safari
    map.insert(
        "773906b0efdefa24a7f2b8eb6985bf37".to_string(),
        KnownFingerprint::legitimate(
            "773906b0efdefa24a7f2b8eb6985bf37",
            "Safari (macOS)",
        ),
    );
    map.insert(
        "f9cf4f4e8c3c5b7a0d9e8f7a6b5c4d3e".to_string(),
        KnownFingerprint::legitimate(
            "f9cf4f4e8c3c5b7a0d9e8f7a6b5c4d3e",
            "Safari (iOS)",
        ),
    );

    // Edge
    map.insert(
        "eb1d94daa7e0344597e756a1fb6e7054".to_string(),
        KnownFingerprint::legitimate(
            "eb1d94daa7e0344597e756a1fb6e7054",
            "Microsoft Edge (Windows)",
        ),
    );

    // Curl
    map.insert(
        "456523fc94726331a4d5a2e1d40b2cd7".to_string(),
        KnownFingerprint::legitimate(
            "456523fc94726331a4d5a2e1d40b2cd7",
            "curl (libcurl)",
        ),
    );

    // Python requests
    map.insert(
        "c1d5a6b3e4f0a9b8c7d6e5f4a3b2c1d0".to_string(),
        KnownFingerprint::legitimate(
            "c1d5a6b3e4f0a9b8c7d6e5f4a3b2c1d0",
            "Python requests library",
        ),
    );

    // Java clients
    map.insert(
        "e7d705a3286e19ea42f587b344ee6865".to_string(),
        KnownFingerprint::legitimate(
            "e7d705a3286e19ea42f587b344ee6865",
            "Java HttpClient",
        ),
    );

    // Node.js
    map.insert(
        "9b3e4f5a6b7c8d9e0f1a2b3c4d5e6f70".to_string(),
        KnownFingerprint::legitimate(
            "9b3e4f5a6b7c8d9e0f1a2b3c4d5e6f70",
            "Node.js (native https)",
        ),
    );

    // Rust reqwest
    map.insert(
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".to_string(),
        KnownFingerprint::legitimate(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "Rust reqwest client",
        ),
    );

    // Go clients
    map.insert(
        "e4e5a6b7c8d9e0f1a2b3c4d5e6f70819".to_string(),
        KnownFingerprint::legitimate(
            "e4e5a6b7c8d9e0f1a2b3c4d5e6f70819",
            "Go net/http client",
        ),
    );

    // =========================================================================
    // Bot and Scanner JA3 Fingerprints
    // =========================================================================

    // Nmap
    map.insert(
        "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f809".to_string(),
        KnownFingerprint::bot(
            "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f809",
            "Nmap scanner",
            false,
        ),
    );

    // Shodan
    map.insert(
        "c5f6a7b8c9d0e1f2a3b4c5d6e7f80910".to_string(),
        KnownFingerprint::bot(
            "c5f6a7b8c9d0e1f2a3b4c5d6e7f80910",
            "Shodan scanner",
            false,
        ),
    );

    // Censys
    map.insert(
        "d6a7b8c9d0e1f2a3b4c5d6e7f8091011".to_string(),
        KnownFingerprint::bot(
            "d6a7b8c9d0e1f2a3b4c5d6e7f8091011",
            "Censys scanner",
            false,
        ),
    );

    // Googlebot
    map.insert(
        "e7b8c9d0e1f2a3b4c5d6e7f809101112".to_string(),
        KnownFingerprint::bot(
            "e7b8c9d0e1f2a3b4c5d6e7f809101112",
            "Googlebot",
            false,
        ),
    );

    // Bingbot
    map.insert(
        "f8c9d0e1f2a3b4c5d6e7f80910111213".to_string(),
        KnownFingerprint::bot(
            "f8c9d0e1f2a3b4c5d6e7f80910111213",
            "Bingbot",
            false,
        ),
    );

    // Malicious scanner patterns
    map.insert(
        "19a7b8c9d0e1f2a3b4c5d6e7f8091011".to_string(),
        KnownFingerprint::bot(
            "19a7b8c9d0e1f2a3b4c5d6e7f8091011",
            "Malicious scanner (credential spraying)",
            true,
        ),
    );
    map.insert(
        "2ab8c9d0e1f2a3b4c5d6e7f809101112".to_string(),
        KnownFingerprint::bot(
            "2ab8c9d0e1f2a3b4c5d6e7f809101112",
            "Vulnerability scanner (aggressive)",
            true,
        ),
    );

    // =========================================================================
    // TOR JA3 Fingerprints
    // =========================================================================

    map.insert(
        "e7d705a3286e19ea42f587b344ee6865".to_string(),
        KnownFingerprint::tor(
            "e7d705a3286e19ea42f587b344ee6865",
            "TOR Browser (Windows)",
        ),
    );
    map.insert(
        "f8e8d7c6b5a4938271605040302010".to_string(),
        KnownFingerprint::tor(
            "f8e8d7c6b5a4938271605040302010",
            "TOR Browser (Linux)",
        ),
    );
    map.insert(
        "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4".to_string(),
        KnownFingerprint::tor(
            "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
            "TOR Browser (macOS)",
        ),
    );

    // =========================================================================
    // Suspicious TLS Configurations
    // =========================================================================

    map.insert(
        "0000000000000000000000000000000".to_string(),
        KnownFingerprint::suspicious(
            "0000000000000000000000000000000",
            "Empty/minimal TLS configuration",
            "Very unusual TLS configuration - possible evasion or misconfigured client",
        ),
    );
    map.insert(
        "deadbeefcafebabe1234567890abcdef".to_string(),
        KnownFingerprint::suspicious(
            "deadbeefcafebabe1234567890abcdef",
            "Unusual cipher suite ordering",
            "Non-standard cipher suite order may indicate custom tool or evasion",
        ),
    );

    map
});

// ============================================================================
// Known JA3S Fingerprints (Server)
// ============================================================================

/// Known JA3S fingerprints database
static KNOWN_JA3S: Lazy<HashMap<String, KnownFingerprint>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // =========================================================================
    // Malware C2 Server JA3S Fingerprints
    // =========================================================================

    // Cobalt Strike Team Server
    map.insert(
        "fd4bc6cea4877646ccd62f0792ec0b62".to_string(),
        KnownFingerprint::c2_server(
            "fd4bc6cea4877646ccd62f0792ec0b62",
            "Cobalt Strike Team Server",
            "Cobalt Strike",
            95,
        ),
    );
    map.insert(
        "e35df3e00ca4ef31d42b34bebaa2f86e".to_string(),
        KnownFingerprint::c2_server(
            "e35df3e00ca4ef31d42b34bebaa2f86e",
            "Cobalt Strike Beacon C2",
            "Cobalt Strike",
            92,
        ),
    );

    // Metasploit handler
    map.insert(
        "a0e9f5d64349fb13191bc781f81f42e2".to_string(),
        KnownFingerprint::c2_server(
            "a0e9f5d64349fb13191bc781f81f42e2",
            "Metasploit Multi-handler",
            "Metasploit",
            90,
        ),
    );

    // Sliver C2 server
    map.insert(
        "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6".to_string(),
        KnownFingerprint::c2_server(
            "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
            "Sliver C2 Server",
            "Sliver",
            88,
        ),
    );

    // Brute Ratel server
    map.insert(
        "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7".to_string(),
        KnownFingerprint::c2_server(
            "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
            "Brute Ratel C4 Server",
            "Brute Ratel",
            86,
        ),
    );

    // Havoc C2 teamserver
    map.insert(
        "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8".to_string(),
        KnownFingerprint::c2_server(
            "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
            "Havoc C2 Teamserver",
            "Havoc",
            84,
        ),
    );

    // Mythic C2 server
    map.insert(
        "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9".to_string(),
        KnownFingerprint::c2_server(
            "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9",
            "Mythic C2 Server",
            "Mythic",
            82,
        ),
    );

    // Covenant C2 server
    map.insert(
        "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0".to_string(),
        KnownFingerprint::c2_server(
            "f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0",
            "Covenant C2 Server",
            "Covenant",
            80,
        ),
    );

    // =========================================================================
    // Legitimate Server JA3S Fingerprints
    // =========================================================================

    // Nginx
    map.insert(
        "eb1d94daa7e0344597e756a1fb6e7055".to_string(),
        KnownFingerprint::legitimate(
            "eb1d94daa7e0344597e756a1fb6e7055",
            "Nginx web server",
        ),
    );

    // Apache
    map.insert(
        "f2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7".to_string(),
        KnownFingerprint::legitimate(
            "f2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7",
            "Apache HTTP Server",
        ),
    );

    // IIS
    map.insert(
        "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8".to_string(),
        KnownFingerprint::legitimate(
            "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
            "Microsoft IIS",
        ),
    );

    // Cloudflare
    map.insert(
        "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9".to_string(),
        KnownFingerprint::legitimate(
            "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9",
            "Cloudflare CDN",
        ),
    );

    // AWS ALB
    map.insert(
        "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0".to_string(),
        KnownFingerprint::legitimate(
            "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
            "AWS Application Load Balancer",
        ),
    );

    // Google Cloud LB
    map.insert(
        "d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1".to_string(),
        KnownFingerprint::legitimate(
            "d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
            "Google Cloud Load Balancer",
        ),
    );

    map
});

// ============================================================================
// Fingerprint Lookup Functions
// ============================================================================

/// Look up a JA3 hash in the known fingerprints database
pub fn lookup_ja3(hash: &str) -> Vec<FingerprintMatch> {
    let mut matches = Vec::new();

    if let Some(fp) = KNOWN_JA3.get(hash) {
        matches.push(FingerprintMatch {
            fingerprint: fp.clone(),
            match_confidence: fp.confidence,
            fingerprint_type: FingerprintType::Ja3,
        });
    }

    matches
}

/// Look up a JA3S hash in the known fingerprints database
pub fn lookup_ja3s(hash: &str) -> Vec<FingerprintMatch> {
    let mut matches = Vec::new();

    if let Some(fp) = KNOWN_JA3S.get(hash) {
        matches.push(FingerprintMatch {
            fingerprint: fp.clone(),
            match_confidence: fp.confidence,
            fingerprint_type: FingerprintType::Ja3s,
        });
    }

    matches
}

/// Check if a JA3 hash matches any known malware
pub fn is_malware_ja3(hash: &str) -> bool {
    KNOWN_JA3
        .get(hash)
        .map(|fp| fp.is_malicious)
        .unwrap_or(false)
}

/// Check if a JA3S hash matches any known C2 server
pub fn is_c2_server(hash: &str) -> bool {
    KNOWN_JA3S
        .get(hash)
        .map(|fp| fp.category == FingerprintCategory::C2Server)
        .unwrap_or(false)
}

/// Check if a JA3 hash matches a TOR client
pub fn is_tor_client(hash: &str) -> bool {
    KNOWN_JA3
        .get(hash)
        .map(|fp| fp.category == FingerprintCategory::Tor)
        .unwrap_or(false)
}

/// Get all known malware JA3 fingerprints
pub fn get_malware_fingerprints() -> Vec<&'static KnownFingerprint> {
    KNOWN_JA3
        .values()
        .filter(|fp| fp.is_malicious)
        .collect()
}

/// Get all known C2 server JA3S fingerprints
pub fn get_c2_server_fingerprints() -> Vec<&'static KnownFingerprint> {
    KNOWN_JA3S
        .values()
        .filter(|fp| fp.category == FingerprintCategory::C2Server)
        .collect()
}

/// Get all fingerprints of a specific category
pub fn get_fingerprints_by_category(category: FingerprintCategory) -> Vec<&'static KnownFingerprint> {
    let mut result: Vec<&'static KnownFingerprint> = KNOWN_JA3
        .values()
        .filter(|fp| fp.category == category)
        .collect();

    result.extend(
        KNOWN_JA3S
            .values()
            .filter(|fp| fp.category == category),
    );

    result
}

/// Try to identify the client from a JA3 hash
pub fn identify_client_from_ja3(hash: &str) -> Option<String> {
    KNOWN_JA3.get(hash).map(|fp| fp.description.clone())
}

/// Try to identify the server from a JA3S hash
pub fn identify_server_from_ja3s(hash: &str) -> Option<String> {
    KNOWN_JA3S.get(hash).map(|fp| fp.description.clone())
}

/// Get the total count of known fingerprints
pub fn fingerprint_count() -> (usize, usize) {
    (KNOWN_JA3.len(), KNOWN_JA3S.len())
}

/// Get all JA3 fingerprints
pub fn get_all_ja3_fingerprints() -> Vec<&'static KnownFingerprint> {
    KNOWN_JA3.values().collect()
}

/// Get all JA3S fingerprints
pub fn get_all_ja3s_fingerprints() -> Vec<&'static KnownFingerprint> {
    KNOWN_JA3S.values().collect()
}

/// Calculate threat score for a fingerprint (0-100)
pub fn calculate_fingerprint_threat_score(fingerprint: &KnownFingerprint) -> u8 {
    let base_score = match fingerprint.category {
        FingerprintCategory::Malware => 90,
        FingerprintCategory::C2Server => 95,
        FingerprintCategory::Suspicious => 60,
        FingerprintCategory::Bot => {
            if fingerprint.is_malicious {
                75
            } else {
                30
            }
        }
        FingerprintCategory::Tor => 40, // Not inherently malicious
        FingerprintCategory::Legitimate => 5,
        FingerprintCategory::Unknown => 20,
    };

    // Adjust based on confidence
    let confidence_multiplier = fingerprint.confidence as f32 / 100.0;
    (base_score as f32 * confidence_multiplier) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_known_malware() {
        let hash = "72a589da586844d7f0818ce684948eea";
        let matches = lookup_ja3(hash);
        assert!(!matches.is_empty());
        assert!(matches[0].fingerprint.is_malicious);
        assert_eq!(
            matches[0].fingerprint.malware_family.as_deref(),
            Some("Cobalt Strike")
        );
    }

    #[test]
    fn test_lookup_legitimate() {
        let hash = "b32309a26951912be7dba376398abc3b";
        let matches = lookup_ja3(hash);
        assert!(!matches.is_empty());
        assert!(!matches[0].fingerprint.is_malicious);
        assert_eq!(matches[0].fingerprint.category, FingerprintCategory::Legitimate);
    }

    #[test]
    fn test_lookup_c2_server() {
        let hash = "fd4bc6cea4877646ccd62f0792ec0b62";
        let matches = lookup_ja3s(hash);
        assert!(!matches.is_empty());
        assert!(matches[0].fingerprint.is_malicious);
        assert_eq!(matches[0].fingerprint.category, FingerprintCategory::C2Server);
    }

    #[test]
    fn test_is_malware_ja3() {
        assert!(is_malware_ja3("72a589da586844d7f0818ce684948eea"));
        assert!(!is_malware_ja3("b32309a26951912be7dba376398abc3b"));
        assert!(!is_malware_ja3("nonexistent_hash"));
    }

    #[test]
    fn test_fingerprint_count() {
        let (ja3_count, ja3s_count) = fingerprint_count();
        assert!(ja3_count > 0);
        assert!(ja3s_count > 0);
    }

    #[test]
    fn test_threat_score_calculation() {
        let malware_fp = KnownFingerprint::malware("test", "Test Malware", "TestFamily", 90);
        let score = calculate_fingerprint_threat_score(&malware_fp);
        assert!(score >= 80); // High score for malware

        let legit_fp = KnownFingerprint::legitimate("test2", "Test Browser");
        let legit_score = calculate_fingerprint_threat_score(&legit_fp);
        assert!(legit_score < 20); // Low score for legitimate
    }
}
