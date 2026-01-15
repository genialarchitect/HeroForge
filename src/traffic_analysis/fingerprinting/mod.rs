//! TLS Fingerprinting Module
//!
//! JA3/JA3S fingerprint generation and matching:
//! - Client fingerprinting (JA3)
//! - Server fingerprinting (JA3S)
//! - Known fingerprint database
//! - Threat scoring

use crate::traffic_analysis::types::*;
use chrono::Utc;
use md5::{Md5, Digest as Md5Digest};
use std::collections::HashMap;

/// JA3/JA3S fingerprinter
pub struct Ja3Fingerprinter {
    /// Known fingerprints database
    known_fingerprints: HashMap<String, KnownFingerprint>,
    /// Observed fingerprints
    observed: HashMap<String, Ja3Fingerprint>,
}

/// Known fingerprint entry
#[derive(Debug, Clone)]
pub struct KnownFingerprint {
    pub hash: String,
    pub client_name: String,
    pub category: FingerprintCategory,
    pub threat_score: u8,
    pub notes: Option<String>,
}

/// Fingerprint category
#[derive(Debug, Clone, PartialEq)]
pub enum FingerprintCategory {
    Browser,
    MobileApp,
    Desktop,
    Bot,
    Malware,
    Tool,
    Unknown,
}

impl Ja3Fingerprinter {
    /// Create a new fingerprinter
    pub fn new() -> Self {
        let mut fingerprinter = Self {
            known_fingerprints: HashMap::new(),
            observed: HashMap::new(),
        };
        fingerprinter.load_known_fingerprints();
        fingerprinter
    }

    /// Load known fingerprints database
    fn load_known_fingerprints(&mut self) {
        // Common browser fingerprints
        let known = vec![
            // Chrome
            KnownFingerprint {
                hash: "769,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0".to_string(),
                client_name: "Chrome 120".to_string(),
                category: FingerprintCategory::Browser,
                threat_score: 0,
                notes: None,
            },
            // Firefox
            KnownFingerprint {
                hash: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0".to_string(),
                client_name: "Firefox 121".to_string(),
                category: FingerprintCategory::Browser,
                threat_score: 0,
                notes: None,
            },
            // Safari
            KnownFingerprint {
                hash: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24-25,0".to_string(),
                client_name: "Safari 17".to_string(),
                category: FingerprintCategory::Browser,
                threat_score: 0,
                notes: None,
            },
            // Curl
            KnownFingerprint {
                hash: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2".to_string(),
                client_name: "curl".to_string(),
                category: FingerprintCategory::Tool,
                threat_score: 10,
                notes: Some("Command line tool - may indicate automated access".to_string()),
            },
            // Python requests
            KnownFingerprint {
                hash: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-16-22-23-13-43-45-51,29-23-30-25-24,0-1-2".to_string(),
                client_name: "Python requests".to_string(),
                category: FingerprintCategory::Tool,
                threat_score: 15,
                notes: Some("Python HTTP library - check for automated scanning".to_string()),
            },
            // Known malware fingerprints
            KnownFingerprint {
                hash: "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,0-10-11,23-24-25,0".to_string(),
                client_name: "Trickbot".to_string(),
                category: FingerprintCategory::Malware,
                threat_score: 100,
                notes: Some("Known Trickbot banking trojan fingerprint".to_string()),
            },
            KnownFingerprint {
                hash: "769,49172-49171-52393-52392-49161-49162-49195-49199-49196-49200-52243-52244-156-157-47-53,0-5-10-11,29-23-24,0".to_string(),
                client_name: "Cobalt Strike".to_string(),
                category: FingerprintCategory::Malware,
                threat_score: 100,
                notes: Some("Cobalt Strike beacon fingerprint".to_string()),
            },
            KnownFingerprint {
                hash: "771,49196-49195-49200-49199-159-158-52393-52392-52394-49327-49326-49188-49187-49192-49191-107-106-103-102-49267-49266-49312-49311-157-156-61-60-53-47-49325-49324-49315-49314-49309-49308-49320-49319-49164-49163-49154-49153-255,0-11-10-35-22-23-13-67,29-23-30-25-24,0-1-2".to_string(),
                client_name: "Emotet".to_string(),
                category: FingerprintCategory::Malware,
                threat_score: 100,
                notes: Some("Emotet malware fingerprint".to_string()),
            },
            // Scanners
            KnownFingerprint {
                hash: "771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0,29-23-30-25-24,0-1-2".to_string(),
                client_name: "Nmap NSE".to_string(),
                category: FingerprintCategory::Tool,
                threat_score: 50,
                notes: Some("Nmap scripting engine".to_string()),
            },
            KnownFingerprint {
                hash: "769,5-4-47-53-10-19-49171-49172,0-10-11,23-24-25,0".to_string(),
                client_name: "Metasploit".to_string(),
                category: FingerprintCategory::Tool,
                threat_score: 80,
                notes: Some("Metasploit framework".to_string()),
            },
        ];

        for fp in known {
            // Create JA3 hash from string
            let mut hasher = Md5::new();
            Md5Digest::update(&mut hasher, fp.hash.as_bytes());
            let hash = format!("{:x}", hasher.finalize());
            self.known_fingerprints.insert(hash, fp);
        }
    }

    /// Record a fingerprint observation
    pub fn record_fingerprint(
        &mut self,
        ja3_hash: &str,
        ja3_string: &str,
        ja3s_hash: Option<&str>,
        ja3s_string: Option<&str>,
    ) -> Ja3Fingerprint {
        let now = Utc::now();

        // Look up known fingerprint
        let known = self.known_fingerprints.get(ja3_hash);
        let threat_score = known.map(|k| k.threat_score).unwrap_or(0);
        let known_client = known.map(|k| k.client_name.clone());

        let fingerprint = if let Some(existing) = self.observed.get_mut(ja3_hash) {
            existing.seen_count += 1;
            existing.last_seen = now;
            existing.clone()
        } else {
            let fp = Ja3Fingerprint {
                id: uuid::Uuid::new_v4().to_string(),
                ja3_hash: ja3_hash.to_string(),
                ja3_string: ja3_string.to_string(),
                ja3s_hash: ja3s_hash.map(|s| s.to_string()),
                ja3s_string: ja3s_string.map(|s| s.to_string()),
                first_seen: now,
                last_seen: now,
                seen_count: 1,
                known_client,
                threat_score,
                notes: known.and_then(|k| k.notes.clone()),
            };
            self.observed.insert(ja3_hash.to_string(), fp.clone());
            fp
        };

        fingerprint
    }

    /// Look up a fingerprint
    pub fn lookup(&self, ja3_hash: &str) -> Option<&KnownFingerprint> {
        self.known_fingerprints.get(ja3_hash)
    }

    /// Check if fingerprint is known malware
    pub fn is_known_malware(&self, ja3_hash: &str) -> bool {
        self.known_fingerprints
            .get(ja3_hash)
            .map(|k| k.category == FingerprintCategory::Malware)
            .unwrap_or(false)
    }

    /// Get threat score for fingerprint
    pub fn get_threat_score(&self, ja3_hash: &str) -> u8 {
        self.known_fingerprints
            .get(ja3_hash)
            .map(|k| k.threat_score)
            .unwrap_or(0)
    }

    /// Get all observed fingerprints
    pub fn get_observed(&self) -> Vec<&Ja3Fingerprint> {
        self.observed.values().collect()
    }

    /// Get all known fingerprints from the database
    pub fn get_all_known(&self) -> Vec<(&String, &KnownFingerprint)> {
        self.known_fingerprints.iter().collect()
    }

    /// Get fingerprints by threat score threshold
    pub fn get_suspicious(&self, min_score: u8) -> Vec<&Ja3Fingerprint> {
        self.observed.values()
            .filter(|fp| fp.threat_score >= min_score)
            .collect()
    }

    /// Add custom fingerprint to database
    pub fn add_known_fingerprint(&mut self, fingerprint: KnownFingerprint) {
        let mut hasher = Md5::new();
        Md5Digest::update(&mut hasher, fingerprint.hash.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        self.known_fingerprints.insert(hash, fingerprint);
    }

    /// Calculate fingerprint statistics
    pub fn get_statistics(&self) -> FingerprintStats {
        let total = self.observed.len();
        let known = self.observed.values()
            .filter(|fp| fp.known_client.is_some())
            .count();
        let malware = self.observed.values()
            .filter(|fp| {
                self.known_fingerprints.get(&fp.ja3_hash)
                    .map(|k| k.category == FingerprintCategory::Malware)
                    .unwrap_or(false)
            })
            .count();
        let tools = self.observed.values()
            .filter(|fp| {
                self.known_fingerprints.get(&fp.ja3_hash)
                    .map(|k| k.category == FingerprintCategory::Tool)
                    .unwrap_or(false)
            })
            .count();

        FingerprintStats {
            total_observed: total,
            known_fingerprints: known,
            unknown_fingerprints: total - known,
            malware_fingerprints: malware,
            tool_fingerprints: tools,
        }
    }
}

/// Fingerprint statistics
#[derive(Debug, Clone)]
pub struct FingerprintStats {
    pub total_observed: usize,
    pub known_fingerprints: usize,
    pub unknown_fingerprints: usize,
    pub malware_fingerprints: usize,
    pub tool_fingerprints: usize,
}

impl Default for Ja3Fingerprinter {
    fn default() -> Self {
        Self::new()
    }
}
