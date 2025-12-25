#![allow(dead_code)]
//! TLS Threat Detection Module
//!
//! This module provides threat detection capabilities based on TLS handshake analysis:
//! - Known malicious fingerprint matching
//! - TLS version downgrade attack detection
//! - Weak cipher suite usage detection
//! - Certificate anomaly detection
//! - JA3 spoofing attempt detection

use serde::{Deserialize, Serialize};

use super::fingerprints::{self, FingerprintCategory};
use super::parser::{TlsClientHello, TlsServerHello};
use super::{is_grease, Ja3Fingerprint, Ja3sFingerprint};

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema)]
pub enum TlsThreatLevel {
    /// No threat detected
    None,
    /// Low severity - informational
    Low,
    /// Medium severity - suspicious activity
    Medium,
    /// High severity - likely malicious
    High,
    /// Critical severity - confirmed threat
    Critical,
}

impl Default for TlsThreatLevel {
    fn default() -> Self {
        Self::None
    }
}

impl std::fmt::Display for TlsThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsThreatLevel::None => write!(f, "None"),
            TlsThreatLevel::Low => write!(f, "Low"),
            TlsThreatLevel::Medium => write!(f, "Medium"),
            TlsThreatLevel::High => write!(f, "High"),
            TlsThreatLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Type of TLS-related threat
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum TlsThreatType {
    /// Match against known malware fingerprint
    MalwareFingerprint,
    /// Match against known C2 server fingerprint
    C2ServerFingerprint,
    /// TLS version downgrade attempt
    VersionDowngrade,
    /// Use of weak or deprecated cipher suites
    WeakCipherSuite,
    /// Use of NULL encryption cipher
    NullCipher,
    /// Use of export-grade cipher
    ExportCipher,
    /// Use of deprecated TLS version
    DeprecatedProtocol,
    /// Potential JA3 spoofing detected
    Ja3Spoofing,
    /// Suspicious extension configuration
    SuspiciousExtensions,
    /// Certificate-related anomaly
    CertificateAnomaly,
    /// TOR network usage detected
    TorNetwork,
    /// Unusual TLS configuration
    UnusualConfiguration,
    /// Bot or scanner detected
    BotScanner,
    /// Suspicious curve usage
    SuspiciousCurves,
    /// Missing expected extensions
    MissingExtensions,
}

impl std::fmt::Display for TlsThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsThreatType::MalwareFingerprint => write!(f, "Malware Fingerprint Match"),
            TlsThreatType::C2ServerFingerprint => write!(f, "C2 Server Fingerprint Match"),
            TlsThreatType::VersionDowngrade => write!(f, "TLS Version Downgrade"),
            TlsThreatType::WeakCipherSuite => write!(f, "Weak Cipher Suite"),
            TlsThreatType::NullCipher => write!(f, "NULL Cipher Suite"),
            TlsThreatType::ExportCipher => write!(f, "Export Cipher Suite"),
            TlsThreatType::DeprecatedProtocol => write!(f, "Deprecated Protocol"),
            TlsThreatType::Ja3Spoofing => write!(f, "JA3 Spoofing Attempt"),
            TlsThreatType::SuspiciousExtensions => write!(f, "Suspicious Extensions"),
            TlsThreatType::CertificateAnomaly => write!(f, "Certificate Anomaly"),
            TlsThreatType::TorNetwork => write!(f, "TOR Network Usage"),
            TlsThreatType::UnusualConfiguration => write!(f, "Unusual Configuration"),
            TlsThreatType::BotScanner => write!(f, "Bot/Scanner Detected"),
            TlsThreatType::SuspiciousCurves => write!(f, "Suspicious Curve Usage"),
            TlsThreatType::MissingExtensions => write!(f, "Missing Expected Extensions"),
        }
    }
}

/// A detected TLS threat
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TlsThreat {
    /// Type of threat
    pub threat_type: TlsThreatType,
    /// Severity level
    pub level: TlsThreatLevel,
    /// Human-readable description
    pub description: String,
    /// Additional details
    pub details: Option<String>,
    /// Related JA3/JA3S hash if applicable
    pub related_hash: Option<String>,
    /// Malware family if identified
    pub malware_family: Option<String>,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Recommended action
    pub recommendation: String,
    /// MITRE ATT&CK technique IDs if applicable
    pub mitre_techniques: Vec<String>,
}

impl TlsThreat {
    /// Create a new threat
    pub fn new(
        threat_type: TlsThreatType,
        level: TlsThreatLevel,
        description: &str,
        recommendation: &str,
    ) -> Self {
        Self {
            threat_type,
            level,
            description: description.to_string(),
            details: None,
            related_hash: None,
            malware_family: None,
            confidence: 80,
            recommendation: recommendation.to_string(),
            mitre_techniques: Vec::new(),
        }
    }

    /// Add details to the threat
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Set the related hash
    pub fn with_hash(mut self, hash: &str) -> Self {
        self.related_hash = Some(hash.to_string());
        self
    }

    /// Set the malware family
    pub fn with_malware(mut self, family: &str) -> Self {
        self.malware_family = Some(family.to_string());
        self
    }

    /// Set confidence score
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence;
        self
    }

    /// Add MITRE ATT&CK techniques
    pub fn with_mitre(mut self, techniques: Vec<&str>) -> Self {
        self.mitre_techniques = techniques.into_iter().map(String::from).collect();
        self
    }
}

/// Certificate-related anomaly types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum CertificateAnomaly {
    /// Self-signed certificate
    SelfSigned,
    /// Certificate expired
    Expired,
    /// Certificate not yet valid
    NotYetValid,
    /// Hostname mismatch
    HostnameMismatch,
    /// Weak signature algorithm
    WeakSignature,
    /// Short RSA key
    ShortKey,
    /// Unknown CA
    UnknownCA,
    /// Certificate chain issues
    ChainIssue,
}

/// Threat detection result for a TLS analysis
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ThreatDetectionResult {
    /// Detected threats
    pub threats: Vec<TlsThreat>,
    /// Overall threat level
    pub overall_level: TlsThreatLevel,
    /// Whether immediate action is recommended
    pub requires_action: bool,
    /// Summary of detection
    pub summary: String,
}

// ============================================================================
// Client-side Threat Detection
// ============================================================================

/// Detect threats from a TLS ClientHello
pub fn detect_client_threats(client_hello: &TlsClientHello, ja3: &Ja3Fingerprint) -> Vec<TlsThreat> {
    let mut threats = Vec::new();

    // Check against known malware fingerprints
    let fingerprint_threats = check_malware_fingerprint(&ja3.hash);
    threats.extend(fingerprint_threats);

    // Check for deprecated TLS versions
    if let Some(threat) = check_deprecated_client_version(client_hello.version) {
        threats.push(threat);
    }

    // Check for weak cipher suites
    let cipher_threats = check_weak_cipher_suites(&client_hello.cipher_suites);
    threats.extend(cipher_threats);

    // Check for suspicious extension patterns
    let extension_threats = check_suspicious_extensions(&client_hello.extensions);
    threats.extend(extension_threats);

    // Check for potential JA3 spoofing
    if let Some(threat) = detect_ja3_spoofing(client_hello, ja3) {
        threats.push(threat);
    }

    // Check for TOR usage
    if fingerprints::is_tor_client(&ja3.hash) {
        threats.push(
            TlsThreat::new(
                TlsThreatType::TorNetwork,
                TlsThreatLevel::Medium,
                "TOR network client detected",
                "Monitor for potential anonymization of malicious activity",
            )
            .with_hash(&ja3.hash)
            .with_details("TOR usage may indicate attempt to hide origin")
            .with_confidence(95)
            .with_mitre(vec!["T1090.003"]), // Proxy: Multi-hop Proxy
        );
    }

    // Check for unusual curve configurations
    let curve_threats = check_suspicious_curves(&client_hello.elliptic_curves);
    threats.extend(curve_threats);

    // Check for missing expected modern extensions
    let missing_ext_threats = check_missing_extensions(client_hello);
    threats.extend(missing_ext_threats);

    threats
}

// ============================================================================
// Server-side Threat Detection
// ============================================================================

/// Detect threats from a TLS ServerHello
pub fn detect_server_threats(server_hello: &TlsServerHello, ja3s: &Ja3sFingerprint) -> Vec<TlsThreat> {
    let mut threats = Vec::new();

    // Check against known C2 server fingerprints
    if fingerprints::is_c2_server(&ja3s.hash) {
        let matches = fingerprints::lookup_ja3s(&ja3s.hash);
        for m in matches {
            threats.push(
                TlsThreat::new(
                    TlsThreatType::C2ServerFingerprint,
                    TlsThreatLevel::Critical,
                    &format!("C2 server fingerprint match: {}", m.fingerprint.description),
                    "Block connection and investigate. This server is associated with known C2 infrastructure.",
                )
                .with_hash(&ja3s.hash)
                .with_malware(m.fingerprint.malware_family.as_deref().unwrap_or("Unknown"))
                .with_confidence(m.fingerprint.confidence)
                .with_mitre(vec!["T1071", "T1573"]), // Application Layer Protocol, Encrypted Channel
            );
        }
    }

    // Check for deprecated TLS version selection
    if let Some(threat) = check_deprecated_server_version(server_hello.version) {
        threats.push(threat);
    }

    // Check for weak cipher suite selection
    if is_weak_cipher(server_hello.cipher_suite) {
        let cipher_name = super::cipher_suite_to_string(server_hello.cipher_suite);
        threats.push(
            TlsThreat::new(
                TlsThreatType::WeakCipherSuite,
                TlsThreatLevel::High,
                &format!("Server selected weak cipher suite: {}", cipher_name),
                "Do not trust this connection. Server is using cryptographically weak encryption.",
            )
            .with_details(&format!("Cipher 0x{:04x} is considered weak", server_hello.cipher_suite))
            .with_confidence(95),
        );
    }

    // Check for NULL cipher selection (no encryption)
    if is_null_cipher(server_hello.cipher_suite) {
        threats.push(
            TlsThreat::new(
                TlsThreatType::NullCipher,
                TlsThreatLevel::Critical,
                "Server selected NULL cipher - NO ENCRYPTION",
                "Block connection immediately. Data will be transmitted in plaintext.",
            )
            .with_confidence(100)
            .with_mitre(vec!["T1040"]), // Network Sniffing
        );
    }

    // Check for suspicious version downgrade
    if let Some(threat) = detect_version_downgrade(server_hello) {
        threats.push(threat);
    }

    threats
}

// ============================================================================
// Helper Detection Functions
// ============================================================================

/// Check if JA3 hash matches known malware
fn check_malware_fingerprint(hash: &str) -> Vec<TlsThreat> {
    let mut threats = Vec::new();

    let matches = fingerprints::lookup_ja3(hash);
    for m in matches {
        if m.fingerprint.is_malicious {
            threats.push(
                TlsThreat::new(
                    TlsThreatType::MalwareFingerprint,
                    TlsThreatLevel::Critical,
                    &format!("Known malware fingerprint: {}", m.fingerprint.description),
                    "Block connection and investigate endpoint. Known malware detected.",
                )
                .with_hash(hash)
                .with_malware(m.fingerprint.malware_family.as_deref().unwrap_or("Unknown"))
                .with_confidence(m.fingerprint.confidence)
                .with_mitre(vec!["T1071.001", "T1573.002"]), // Web Protocols, Asymmetric Crypto
            );
        } else if m.fingerprint.category == FingerprintCategory::Bot {
            threats.push(
                TlsThreat::new(
                    TlsThreatType::BotScanner,
                    TlsThreatLevel::Low,
                    &format!("Bot/Scanner detected: {}", m.fingerprint.description),
                    "Monitor for suspicious activity. May be reconnaissance.",
                )
                .with_hash(hash)
                .with_confidence(m.fingerprint.confidence)
                .with_mitre(vec!["T1595"]), // Active Scanning
            );
        }
    }

    threats
}

/// Check for deprecated TLS versions in ClientHello
fn check_deprecated_client_version(version: u16) -> Option<TlsThreat> {
    match version {
        0x0200 => Some(
            TlsThreat::new(
                TlsThreatType::DeprecatedProtocol,
                TlsThreatLevel::Critical,
                "SSL 2.0 protocol detected",
                "Block connection. SSL 2.0 is critically insecure.",
            )
            .with_details("SSL 2.0 has fundamental design flaws and no modern client should use it")
            .with_confidence(100),
        ),
        0x0300 => Some(
            TlsThreat::new(
                TlsThreatType::DeprecatedProtocol,
                TlsThreatLevel::High,
                "SSL 3.0 protocol detected - vulnerable to POODLE",
                "Block or investigate. SSL 3.0 is deprecated and vulnerable.",
            )
            .with_details("CVE-2014-3566 (POODLE)")
            .with_confidence(100),
        ),
        0x0301 => Some(
            TlsThreat::new(
                TlsThreatType::DeprecatedProtocol,
                TlsThreatLevel::Medium,
                "TLS 1.0 protocol detected - deprecated",
                "Consider blocking. TLS 1.0 is deprecated since 2021.",
            )
            .with_confidence(95),
        ),
        0x0302 => Some(
            TlsThreat::new(
                TlsThreatType::DeprecatedProtocol,
                TlsThreatLevel::Low,
                "TLS 1.1 protocol detected - deprecated",
                "Monitor. TLS 1.1 is deprecated, prefer TLS 1.2 or 1.3.",
            )
            .with_confidence(90),
        ),
        _ => None,
    }
}

/// Check for deprecated TLS versions in ServerHello
fn check_deprecated_server_version(version: u16) -> Option<TlsThreat> {
    // Same checks as client but with server-specific messaging
    match version {
        0x0200 | 0x0300 => Some(
            TlsThreat::new(
                TlsThreatType::DeprecatedProtocol,
                TlsThreatLevel::Critical,
                &format!("Server using critically deprecated protocol: {}", super::tls_version_to_string(version)),
                "Do not establish connection. Server has severe security vulnerabilities.",
            )
            .with_confidence(100),
        ),
        0x0301 | 0x0302 => Some(
            TlsThreat::new(
                TlsThreatType::DeprecatedProtocol,
                TlsThreatLevel::Medium,
                &format!("Server using deprecated protocol: {}", super::tls_version_to_string(version)),
                "Exercise caution. Server should be updated to support TLS 1.2+.",
            )
            .with_confidence(95),
        ),
        _ => None,
    }
}

/// Check for weak cipher suites in offered list
fn check_weak_cipher_suites(cipher_suites: &[u16]) -> Vec<TlsThreat> {
    let mut threats = Vec::new();

    let mut null_ciphers = Vec::new();
    let mut export_ciphers = Vec::new();
    let mut weak_ciphers = Vec::new();

    for &cipher in cipher_suites {
        // Skip GREASE values
        if is_grease(cipher) {
            continue;
        }

        if is_null_cipher(cipher) {
            null_ciphers.push(cipher);
        } else if is_export_cipher(cipher) {
            export_ciphers.push(cipher);
        } else if is_weak_cipher(cipher) {
            weak_ciphers.push(cipher);
        }
    }

    if !null_ciphers.is_empty() {
        threats.push(
            TlsThreat::new(
                TlsThreatType::NullCipher,
                TlsThreatLevel::Critical,
                "Client offers NULL cipher suites (no encryption)",
                "Suspicious client. No legitimate client should offer NULL ciphers.",
            )
            .with_details(&format!("NULL ciphers: {:?}", null_ciphers.iter().map(|c| format!("0x{:04x}", c)).collect::<Vec<_>>()))
            .with_confidence(100)
            .with_mitre(vec!["T1557"]), // Adversary-in-the-Middle
        );
    }

    if !export_ciphers.is_empty() {
        threats.push(
            TlsThreat::new(
                TlsThreatType::ExportCipher,
                TlsThreatLevel::High,
                "Client offers export-grade cipher suites",
                "Suspicious client. Export ciphers are trivially breakable.",
            )
            .with_details(&format!("Export ciphers: {:?}", export_ciphers.iter().map(|c| format!("0x{:04x}", c)).collect::<Vec<_>>()))
            .with_confidence(95)
            .with_mitre(vec!["T1600.001"]), // Weaken Encryption
        );
    }

    if !weak_ciphers.is_empty() {
        threats.push(
            TlsThreat::new(
                TlsThreatType::WeakCipherSuite,
                TlsThreatLevel::Medium,
                &format!("Client offers {} weak cipher suites", weak_ciphers.len()),
                "Monitor. Client may be outdated or misconfigured.",
            )
            .with_details(&format!("Weak ciphers: {:?}", weak_ciphers.iter().map(|c| super::cipher_suite_to_string(*c)).collect::<Vec<_>>()))
            .with_confidence(80),
        );
    }

    threats
}

/// Check for suspicious extension patterns
fn check_suspicious_extensions(extensions: &[u16]) -> Vec<TlsThreat> {
    let mut threats = Vec::new();

    // Check for unusual extension ordering or combinations
    // Modern browsers have predictable extension orders

    // Very few extensions is suspicious
    let non_grease_ext: Vec<_> = extensions.iter().filter(|e| !is_grease(**e)).collect();

    if non_grease_ext.is_empty() {
        threats.push(
            TlsThreat::new(
                TlsThreatType::SuspiciousExtensions,
                TlsThreatLevel::Medium,
                "ClientHello contains no extensions",
                "Unusual for modern TLS. May be custom tool or very old client.",
            )
            .with_confidence(70),
        );
    } else if non_grease_ext.len() < 3 {
        threats.push(
            TlsThreat::new(
                TlsThreatType::SuspiciousExtensions,
                TlsThreatLevel::Low,
                "ClientHello contains very few extensions",
                "Unusual for modern browsers. May be simple HTTP client or malware.",
            )
            .with_confidence(60),
        );
    }

    // Heartbeat extension presence (often used in attacks)
    if extensions.contains(&0x000f) {
        threats.push(
            TlsThreat::new(
                TlsThreatType::SuspiciousExtensions,
                TlsThreatLevel::Low,
                "Heartbeat extension present",
                "Monitor. Heartbeat can be used for keep-alive but also for attacks (Heartbleed).",
            )
            .with_confidence(50),
        );
    }

    threats
}

/// Detect potential JA3 spoofing attempts
fn detect_ja3_spoofing(client_hello: &TlsClientHello, ja3: &Ja3Fingerprint) -> Option<TlsThreat> {
    // JA3 spoofing indicators:
    // 1. Fingerprint matches legitimate browser but behavior is unusual
    // 2. Very specific combination of unusual features

    // Check if it looks like Chrome but has unusual characteristics
    if ja3.client_info.potential_client.as_ref().map(|c| c.contains("Chrome")).unwrap_or(false) {
        // Chrome always has GREASE values
        if !ja3.client_info.has_grease {
            return Some(
                TlsThreat::new(
                    TlsThreatType::Ja3Spoofing,
                    TlsThreatLevel::High,
                    "Possible JA3 spoofing: Chrome fingerprint without GREASE values",
                    "Investigate. Real Chrome browsers always include GREASE values.",
                )
                .with_hash(&ja3.hash)
                .with_confidence(85)
                .with_mitre(vec!["T1036"]), // Masquerading
            );
        }
    }

    // Check for impossible combinations
    // E.g., TLS 1.3 cipher suites without TLS 1.3 version
    let has_tls13_ciphers = client_hello.cipher_suites.iter().any(|c| {
        matches!(c, 0x1301 | 0x1302 | 0x1303 | 0x1304 | 0x1305)
    });

    if has_tls13_ciphers && client_hello.version < 0x0303 {
        return Some(
            TlsThreat::new(
                TlsThreatType::Ja3Spoofing,
                TlsThreatLevel::High,
                "Inconsistent TLS configuration: TLS 1.3 ciphers with older version",
                "Suspicious. May indicate spoofed or malformed ClientHello.",
            )
            .with_confidence(75),
        );
    }

    None
}

/// Check for suspicious elliptic curve configurations
fn check_suspicious_curves(curves: &[u16]) -> Vec<TlsThreat> {
    let mut threats = Vec::new();

    let non_grease_curves: Vec<_> = curves.iter().filter(|c| !is_grease(**c)).collect();

    // No curves at all is suspicious for modern clients
    if non_grease_curves.is_empty() && !curves.is_empty() {
        // Has GREASE but no real curves - very unusual
        threats.push(
            TlsThreat::new(
                TlsThreatType::SuspiciousCurves,
                TlsThreatLevel::Medium,
                "Client offers only GREASE values for elliptic curves",
                "Unusual configuration. May be testing or evasion attempt.",
            )
            .with_confidence(70),
        );
    }

    threats
}

/// Check for missing expected extensions in modern TLS
fn check_missing_extensions(client_hello: &TlsClientHello) -> Vec<TlsThreat> {
    let mut threats = Vec::new();

    // For TLS 1.3 and 1.2, expect these extensions
    if client_hello.version >= 0x0303 {
        // SNI (server_name) - 0x0000
        if !client_hello.extensions.contains(&0x0000) {
            threats.push(
                TlsThreat::new(
                    TlsThreatType::MissingExtensions,
                    TlsThreatLevel::Low,
                    "Missing SNI extension",
                    "Unusual for modern browsers. May cause connection issues or indicate simple client.",
                )
                .with_confidence(50),
            );
        }

        // Signature algorithms - 0x000d
        if !client_hello.extensions.contains(&0x000d) {
            threats.push(
                TlsThreat::new(
                    TlsThreatType::MissingExtensions,
                    TlsThreatLevel::Low,
                    "Missing signature_algorithms extension",
                    "Required for TLS 1.2+. Unusual if missing.",
                )
                .with_confidence(60),
            );
        }
    }

    threats
}

/// Detect TLS version downgrade attempts
fn detect_version_downgrade(server_hello: &TlsServerHello) -> Option<TlsThreat> {
    // Check for SCSV downgrade sentinel
    // The random value ends with specific patterns if downgrade is detected

    // This is a simplified check - real detection would examine the random field
    if server_hello.version < 0x0303 {
        // Could be legitimate or could be downgrade attack
        // This is informational
        return Some(
            TlsThreat::new(
                TlsThreatType::VersionDowngrade,
                TlsThreatLevel::Medium,
                &format!("Server negotiated older TLS version: {}", super::tls_version_to_string(server_hello.version)),
                "Verify client offered older versions. Could be legitimate compatibility or downgrade attack.",
            )
            .with_confidence(50)
            .with_mitre(vec!["T1557"]), // Adversary-in-the-Middle
        );
    }

    None
}

// ============================================================================
// Cipher Suite Classification
// ============================================================================

/// Check if a cipher suite is a NULL cipher (no encryption)
pub fn is_null_cipher(cipher: u16) -> bool {
    matches!(
        cipher,
        0x0000 | // TLS_NULL_WITH_NULL_NULL
        0x0001 | // TLS_RSA_WITH_NULL_MD5
        0x0002 | // TLS_RSA_WITH_NULL_SHA
        0x002c | // TLS_PSK_WITH_NULL_SHA
        0x002d | // TLS_DHE_PSK_WITH_NULL_SHA
        0x002e | // TLS_RSA_PSK_WITH_NULL_SHA
        0x003b | // TLS_RSA_WITH_NULL_SHA256
        0x00b0 | // TLS_PSK_WITH_NULL_SHA256
        0x00b1 | // TLS_PSK_WITH_NULL_SHA384
        0x00b4 | // TLS_DHE_PSK_WITH_NULL_SHA256
        0x00b5 | // TLS_DHE_PSK_WITH_NULL_SHA384
        0x00b8 | // TLS_RSA_PSK_WITH_NULL_SHA256
        0x00b9 | // TLS_RSA_PSK_WITH_NULL_SHA384
        0xc001 | // TLS_ECDH_ECDSA_WITH_NULL_SHA
        0xc006 | // TLS_ECDHE_ECDSA_WITH_NULL_SHA
        0xc00b | // TLS_ECDH_RSA_WITH_NULL_SHA
        0xc010   // TLS_ECDHE_RSA_WITH_NULL_SHA
    )
}

/// Check if a cipher suite is an export cipher (40-bit or 56-bit)
pub fn is_export_cipher(cipher: u16) -> bool {
    matches!(
        cipher,
        0x0003 | // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        0x0006 | // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        0x0008 | // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x000b | // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x000e | // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0011 | // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x0014 | // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0017 | // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
        0x0019   // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    )
}

/// Check if a cipher suite is considered weak
pub fn is_weak_cipher(cipher: u16) -> bool {
    // NULL ciphers
    if is_null_cipher(cipher) {
        return true;
    }

    // Export ciphers
    if is_export_cipher(cipher) {
        return true;
    }

    // RC4 ciphers
    if matches!(
        cipher,
        0x0004 | 0x0005 | 0x0017 | 0x0018 | 0x0024 | 0x0028 | 0xc002 | 0xc007 | 0xc00c | 0xc011
    ) {
        return true;
    }

    // DES (single DES, not 3DES)
    if matches!(
        cipher,
        0x0009 | 0x000c | 0x000f | 0x0012 | 0x0015 | 0x001a
    ) {
        return true;
    }

    // 3DES (SWEET32 vulnerable)
    if matches!(
        cipher,
        0x000a | 0x000d | 0x0010 | 0x0013 | 0x0016 | 0x001b | 0xc003 | 0xc008 | 0xc00d | 0xc012
    ) {
        return true;
    }

    // Anonymous DH (no authentication)
    if matches!(
        cipher,
        0x0017 | 0x0018 | 0x0019 | 0x001a | 0x001b | 0x0034 | 0x003a | 0x006c | 0x006d | 0x0089 |
        0x009b | 0x00a6 | 0x00a7 | 0xc015 | 0xc016 | 0xc017 | 0xc018 | 0xc019 | 0xc046 | 0xc047
    ) {
        return true;
    }

    // MD5-based ciphers
    if matches!(cipher, 0x0001 | 0x0004) {
        return true;
    }

    false
}

/// Check if a cipher suite uses forward secrecy
pub fn has_forward_secrecy(cipher: u16) -> bool {
    // ECDHE ciphers
    if (0xc023..=0xc032).contains(&cipher)
        || (0xcca8..=0xccae).contains(&cipher)
        || matches!(cipher, 0xc0a0..=0xc0af)
    {
        return true;
    }

    // DHE ciphers
    if matches!(
        cipher,
        0x0033 | 0x0039 | 0x0045 | 0x0067 | 0x006b | 0x0087 | 0x009e | 0x009f | 0x00a2 | 0x00a3
    ) {
        return true;
    }

    // TLS 1.3 cipher suites (all have forward secrecy)
    if (0x1301..=0x1305).contains(&cipher) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(TlsThreatLevel::Critical > TlsThreatLevel::High);
        assert!(TlsThreatLevel::High > TlsThreatLevel::Medium);
        assert!(TlsThreatLevel::Medium > TlsThreatLevel::Low);
        assert!(TlsThreatLevel::Low > TlsThreatLevel::None);
    }

    #[test]
    fn test_null_cipher_detection() {
        assert!(is_null_cipher(0x0000));
        assert!(is_null_cipher(0x0001));
        assert!(!is_null_cipher(0x1301)); // TLS 1.3 AES-GCM
    }

    #[test]
    fn test_export_cipher_detection() {
        assert!(is_export_cipher(0x0003)); // RSA_EXPORT_WITH_RC4_40
        assert!(!is_export_cipher(0x1301));
    }

    #[test]
    fn test_weak_cipher_detection() {
        assert!(is_weak_cipher(0x0000)); // NULL
        assert!(is_weak_cipher(0x0004)); // RC4
        assert!(is_weak_cipher(0x000a)); // 3DES
        assert!(!is_weak_cipher(0x1301)); // TLS 1.3 AES-GCM
    }

    #[test]
    fn test_forward_secrecy_detection() {
        assert!(has_forward_secrecy(0x1301)); // TLS 1.3
        assert!(has_forward_secrecy(0xc02f)); // ECDHE-RSA-AES128-GCM
        assert!(!has_forward_secrecy(0x002f)); // RSA-AES128-CBC
    }

    #[test]
    fn test_deprecated_version_detection() {
        assert!(check_deprecated_client_version(0x0200).is_some()); // SSL 2.0
        assert!(check_deprecated_client_version(0x0300).is_some()); // SSL 3.0
        assert!(check_deprecated_client_version(0x0301).is_some()); // TLS 1.0
        assert!(check_deprecated_client_version(0x0303).is_none()); // TLS 1.2 is OK
        assert!(check_deprecated_client_version(0x0304).is_none()); // TLS 1.3 is OK
    }

    #[test]
    fn test_threat_creation() {
        let threat = TlsThreat::new(
            TlsThreatType::MalwareFingerprint,
            TlsThreatLevel::Critical,
            "Test threat",
            "Test recommendation",
        )
        .with_hash("abc123")
        .with_malware("TestMalware")
        .with_confidence(95)
        .with_mitre(vec!["T1071"]);

        assert_eq!(threat.threat_type, TlsThreatType::MalwareFingerprint);
        assert_eq!(threat.level, TlsThreatLevel::Critical);
        assert_eq!(threat.related_hash, Some("abc123".to_string()));
        assert_eq!(threat.malware_family, Some("TestMalware".to_string()));
        assert_eq!(threat.confidence, 95);
        assert!(!threat.mitre_techniques.is_empty());
    }
}
