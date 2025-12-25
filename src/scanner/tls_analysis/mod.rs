#![allow(dead_code)]
//! TLS Analysis Module for JA3/JA3S Fingerprinting
//!
//! This module provides TLS client and server fingerprinting capabilities
//! for blue team threat detection. It implements the JA3 and JA3S fingerprinting
//! algorithms to identify malicious clients and servers based on their TLS handshake
//! characteristics.
//!
//! # Features
//! - JA3 fingerprinting (client identification)
//! - JA3S fingerprinting (server identification)
//! - Known malware fingerprint matching
//! - TLS version downgrade detection
//! - Weak cipher suite detection
//! - Certificate anomaly detection

pub mod detection;
pub mod fingerprints;
pub mod parser;

use md5::Md5;
use md5::Digest;
use serde::{Deserialize, Serialize};
use std::fmt;

// Re-export main types
pub use detection::{TlsThreat, TlsThreatLevel};
pub use fingerprints::{FingerprintCategory, FingerprintMatch};
pub use parser::{TlsClientHello, TlsServerHello};

/// JA3 fingerprint for a TLS client
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Ja3Fingerprint {
    /// The MD5 hash of the JA3 string
    pub hash: String,
    /// The raw JA3 string before hashing
    pub raw_string: String,
    /// Client information derived from the fingerprint
    pub client_info: ClientInfo,
}

/// JA3S fingerprint for a TLS server
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Ja3sFingerprint {
    /// The MD5 hash of the JA3S string
    pub hash: String,
    /// The raw JA3S string before hashing
    pub raw_string: String,
    /// Server information derived from the fingerprint
    pub server_info: ServerInfo,
}

/// Client information extracted from JA3 fingerprint
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct ClientInfo {
    /// TLS version used
    pub tls_version: Option<String>,
    /// Number of cipher suites offered
    pub cipher_suite_count: usize,
    /// Number of extensions present
    pub extension_count: usize,
    /// Elliptic curves supported
    pub supported_curves: Vec<String>,
    /// Point formats supported
    pub point_formats: Vec<String>,
    /// Whether GREASE values were present (indicates modern browser)
    pub has_grease: bool,
    /// Potential client identification based on fingerprint patterns
    pub potential_client: Option<String>,
}

/// Server information extracted from JA3S fingerprint
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct ServerInfo {
    /// TLS version negotiated
    pub tls_version: Option<String>,
    /// Cipher suite selected
    pub selected_cipher: Option<String>,
    /// Number of extensions in response
    pub extension_count: usize,
    /// Potential server identification
    pub potential_server: Option<String>,
}

/// TLS analysis result combining JA3 and JA3S fingerprints with threat detection
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TlsAnalysisResult {
    /// JA3 fingerprint if client hello was analyzed
    pub ja3: Option<Ja3Fingerprint>,
    /// JA3S fingerprint if server hello was analyzed
    pub ja3s: Option<Ja3sFingerprint>,
    /// Threat detection results
    pub threats: Vec<TlsThreat>,
    /// Overall threat level
    pub threat_level: TlsThreatLevel,
    /// Matched known fingerprints
    pub fingerprint_matches: Vec<FingerprintMatch>,
    /// Timestamp of analysis
    pub analyzed_at: chrono::DateTime<chrono::Utc>,
    /// Source IP address if available
    pub src_ip: Option<String>,
    /// Destination IP address if available
    pub dst_ip: Option<String>,
    /// Source port if available
    pub src_port: Option<u16>,
    /// Destination port if available
    pub dst_port: Option<u16>,
}

impl TlsAnalysisResult {
    /// Create a new empty analysis result
    pub fn new() -> Self {
        Self {
            ja3: None,
            ja3s: None,
            threats: Vec::new(),
            threat_level: TlsThreatLevel::None,
            fingerprint_matches: Vec::new(),
            analyzed_at: chrono::Utc::now(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
        }
    }

    /// Set source endpoint information
    pub fn with_source(mut self, ip: String, port: u16) -> Self {
        self.src_ip = Some(ip);
        self.src_port = Some(port);
        self
    }

    /// Set destination endpoint information
    pub fn with_destination(mut self, ip: String, port: u16) -> Self {
        self.dst_ip = Some(ip);
        self.dst_port = Some(port);
        self
    }
}

impl Default for TlsAnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}

/// GREASE (Generate Random Extensions And Sustain Extensibility) values
/// These are used by modern browsers and should be filtered out for JA3 calculation
pub const GREASE_VALUES: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Check if a value is a GREASE value
pub fn is_grease(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

/// Filter out GREASE values from a list
pub fn filter_grease(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease(*v)).collect()
}

/// Calculate JA3 fingerprint from a TLS ClientHello
///
/// JA3 format: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
/// Each field is a comma-separated list of decimal values, with hyphen separating fields
///
/// # Arguments
/// * `client_hello` - Parsed TLS ClientHello message
///
/// # Returns
/// A Ja3Fingerprint containing the MD5 hash and raw string
pub fn calculate_ja3(client_hello: &TlsClientHello) -> Ja3Fingerprint {
    // Filter out GREASE values from all fields
    let version = client_hello.version;
    let ciphers = filter_grease(&client_hello.cipher_suites);
    let extensions = filter_grease(&client_hello.extensions);
    let curves = filter_grease(&client_hello.elliptic_curves);
    let point_formats = &client_hello.point_formats;

    // Build JA3 string
    let ja3_string = format!(
        "{},{},{},{},{}",
        version,
        ciphers
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        point_formats
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    );

    // Calculate MD5 hash
    let mut hasher = Md5::new();
    hasher.update(ja3_string.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    // Determine client info
    let has_grease = client_hello
        .cipher_suites
        .iter()
        .any(|c| is_grease(*c))
        || client_hello.extensions.iter().any(|e| is_grease(*e));

    let client_info = ClientInfo {
        tls_version: Some(tls_version_to_string(version)),
        cipher_suite_count: ciphers.len(),
        extension_count: extensions.len(),
        supported_curves: curves.iter().map(|c| curve_to_string(*c)).collect(),
        point_formats: point_formats
            .iter()
            .map(|p| point_format_to_string(*p))
            .collect(),
        has_grease,
        potential_client: fingerprints::identify_client_from_ja3(&hash),
    };

    Ja3Fingerprint {
        hash,
        raw_string: ja3_string,
        client_info,
    }
}

/// Calculate JA3S fingerprint from a TLS ServerHello
///
/// JA3S format: SSLVersion,CipherSuite,Extensions
/// Note: ServerHello only has ONE cipher suite (the selected one)
///
/// # Arguments
/// * `server_hello` - Parsed TLS ServerHello message
///
/// # Returns
/// A Ja3sFingerprint containing the MD5 hash and raw string
pub fn calculate_ja3s(server_hello: &TlsServerHello) -> Ja3sFingerprint {
    // Filter out GREASE values from extensions
    let version = server_hello.version;
    let cipher = server_hello.cipher_suite;
    let extensions = filter_grease(&server_hello.extensions);

    // Build JA3S string
    let ja3s_string = format!(
        "{},{},{}",
        version,
        cipher,
        extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    );

    // Calculate MD5 hash
    let mut hasher = Md5::new();
    hasher.update(ja3s_string.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    let server_info = ServerInfo {
        tls_version: Some(tls_version_to_string(version)),
        selected_cipher: Some(cipher_suite_to_string(cipher)),
        extension_count: extensions.len(),
        potential_server: fingerprints::identify_server_from_ja3s(&hash),
    };

    Ja3sFingerprint {
        hash,
        raw_string: ja3s_string,
        server_info,
    }
}

/// Perform full TLS analysis on client and/or server hello data
///
/// # Arguments
/// * `client_hello_data` - Optional raw bytes of TLS ClientHello
/// * `server_hello_data` - Optional raw bytes of TLS ServerHello
///
/// # Returns
/// Complete TLS analysis result with fingerprints and threat detection
pub fn analyze_tls_handshake(
    client_hello_data: Option<&[u8]>,
    server_hello_data: Option<&[u8]>,
) -> anyhow::Result<TlsAnalysisResult> {
    let mut result = TlsAnalysisResult::new();

    // Parse and calculate JA3 if client hello provided
    if let Some(data) = client_hello_data {
        let client_hello = parser::parse_client_hello(data)?;
        let ja3 = calculate_ja3(&client_hello);

        // Check for known fingerprints
        let matches = fingerprints::lookup_ja3(&ja3.hash);
        for m in &matches {
            if !result.fingerprint_matches.contains(m) {
                result.fingerprint_matches.push(m.clone());
            }
        }

        // Detect client-side threats
        let client_threats = detection::detect_client_threats(&client_hello, &ja3);
        result.threats.extend(client_threats);

        result.ja3 = Some(ja3);
    }

    // Parse and calculate JA3S if server hello provided
    if let Some(data) = server_hello_data {
        let server_hello = parser::parse_server_hello(data)?;
        let ja3s = calculate_ja3s(&server_hello);

        // Check for known server fingerprints
        let matches = fingerprints::lookup_ja3s(&ja3s.hash);
        for m in &matches {
            if !result.fingerprint_matches.contains(m) {
                result.fingerprint_matches.push(m.clone());
            }
        }

        // Detect server-side threats
        let server_threats = detection::detect_server_threats(&server_hello, &ja3s);
        result.threats.extend(server_threats);

        result.ja3s = Some(ja3s);
    }

    // Calculate overall threat level
    result.threat_level = calculate_overall_threat_level(&result.threats, &result.fingerprint_matches);

    Ok(result)
}

/// Calculate the overall threat level from individual threats and fingerprint matches
fn calculate_overall_threat_level(
    threats: &[TlsThreat],
    matches: &[FingerprintMatch],
) -> TlsThreatLevel {
    let mut max_level = TlsThreatLevel::None;

    // Check threat levels
    for threat in threats {
        if threat.level > max_level {
            max_level = threat.level.clone();
        }
    }

    // Check fingerprint matches for malicious indicators
    for m in matches {
        if m.fingerprint.is_malicious {
            if max_level < TlsThreatLevel::High {
                max_level = TlsThreatLevel::High;
            }
        } else if m.fingerprint.category == FingerprintCategory::Suspicious {
            if max_level < TlsThreatLevel::Medium {
                max_level = TlsThreatLevel::Medium;
            }
        }
    }

    max_level
}

/// Convert TLS version number to human-readable string
pub fn tls_version_to_string(version: u16) -> String {
    match version {
        0x0200 => "SSL 2.0".to_string(),
        0x0300 => "SSL 3.0".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0304 => "TLS 1.3".to_string(),
        v => format!("Unknown (0x{:04x})", v),
    }
}

/// Convert cipher suite number to human-readable string
pub fn cipher_suite_to_string(cipher: u16) -> String {
    match cipher {
        // TLS 1.3 cipher suites
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0x1304 => "TLS_AES_128_CCM_SHA256".to_string(),
        0x1305 => "TLS_AES_128_CCM_8_SHA256".to_string(),

        // TLS 1.2 ECDHE cipher suites
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),

        // DHE cipher suites
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),

        // RSA cipher suites (no PFS)
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".to_string(),
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256".to_string(),
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),

        // Weak/deprecated cipher suites
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5".to_string(),
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA".to_string(),
        0x000d => "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA".to_string(),
        0x0010 => "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),

        // NULL cipher suites (no encryption)
        0x0000 => "TLS_NULL_WITH_NULL_NULL".to_string(),
        0x0001 => "TLS_RSA_WITH_NULL_MD5".to_string(),
        0x0002 => "TLS_RSA_WITH_NULL_SHA".to_string(),

        // Export cipher suites (weak)
        0x0003 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5".to_string(),
        0x0006 => "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5".to_string(),

        c => format!("0x{:04x}", c),
    }
}

/// Convert elliptic curve number to human-readable string
pub fn curve_to_string(curve: u16) -> String {
    match curve {
        0x0017 => "secp256r1".to_string(),
        0x0018 => "secp384r1".to_string(),
        0x0019 => "secp521r1".to_string(),
        0x001d => "x25519".to_string(),
        0x001e => "x448".to_string(),
        0x0100 => "ffdhe2048".to_string(),
        0x0101 => "ffdhe3072".to_string(),
        0x0102 => "ffdhe4096".to_string(),
        c => format!("0x{:04x}", c),
    }
}

/// Convert point format to human-readable string
pub fn point_format_to_string(format: u8) -> String {
    match format {
        0 => "uncompressed".to_string(),
        1 => "ansiX962_compressed_prime".to_string(),
        2 => "ansiX962_compressed_char2".to_string(),
        f => format!("0x{:02x}", f),
    }
}

/// Extension type to human-readable string
pub fn extension_to_string(ext: u16) -> String {
    match ext {
        0x0000 => "server_name".to_string(),
        0x0001 => "max_fragment_length".to_string(),
        0x0005 => "status_request".to_string(),
        0x000a => "supported_groups".to_string(),
        0x000b => "ec_point_formats".to_string(),
        0x000d => "signature_algorithms".to_string(),
        0x000e => "use_srtp".to_string(),
        0x000f => "heartbeat".to_string(),
        0x0010 => "application_layer_protocol_negotiation".to_string(),
        0x0012 => "signed_certificate_timestamp".to_string(),
        0x0015 => "padding".to_string(),
        0x0016 => "encrypt_then_mac".to_string(),
        0x0017 => "extended_master_secret".to_string(),
        0x0023 => "session_ticket".to_string(),
        0x002b => "supported_versions".to_string(),
        0x002c => "cookie".to_string(),
        0x002d => "psk_key_exchange_modes".to_string(),
        0x0031 => "post_handshake_auth".to_string(),
        0x0033 => "key_share".to_string(),
        0xff01 => "renegotiation_info".to_string(),
        e => format!("0x{:04x}", e),
    }
}

impl fmt::Display for Ja3Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JA3: {} (TLS {})", self.hash, self.client_info.tls_version.as_deref().unwrap_or("unknown"))
    }
}

impl fmt::Display for Ja3sFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JA3S: {} (TLS {})", self.hash, self.server_info.tls_version.as_deref().unwrap_or("unknown"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0301));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn test_grease_filtering() {
        let values = vec![0x0a0a, 0x0301, 0x1a1a, 0x0303];
        let filtered = filter_grease(&values);
        assert_eq!(filtered, vec![0x0301, 0x0303]);
    }

    #[test]
    fn test_tls_version_to_string() {
        assert_eq!(tls_version_to_string(0x0301), "TLS 1.0");
        assert_eq!(tls_version_to_string(0x0303), "TLS 1.2");
        assert_eq!(tls_version_to_string(0x0304), "TLS 1.3");
    }

    #[test]
    fn test_cipher_suite_to_string() {
        assert_eq!(cipher_suite_to_string(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(
            cipher_suite_to_string(0xc02f),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn test_ja3_calculation() {
        let client_hello = TlsClientHello {
            version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302, 0xc02f, 0xc030],
            extensions: vec![0x0000, 0x000a, 0x000b, 0x000d],
            elliptic_curves: vec![0x001d, 0x0017, 0x0018],
            point_formats: vec![0],
        };

        let ja3 = calculate_ja3(&client_hello);
        assert!(!ja3.hash.is_empty());
        assert!(ja3.hash.len() == 32); // MD5 produces 32 hex chars
        assert!(ja3.raw_string.contains("771")); // 0x0303 = 771
    }

    #[test]
    fn test_ja3s_calculation() {
        let server_hello = TlsServerHello {
            version: 0x0303,
            cipher_suite: 0x1301,
            extensions: vec![0x002b, 0x0033],
        };

        let ja3s = calculate_ja3s(&server_hello);
        assert!(!ja3s.hash.is_empty());
        assert!(ja3s.hash.len() == 32);
        assert!(ja3s.raw_string.contains("771")); // 0x0303 = 771
    }

    #[test]
    fn test_analysis_result_creation() {
        let result = TlsAnalysisResult::new()
            .with_source("192.168.1.100".to_string(), 54321)
            .with_destination("10.0.0.1".to_string(), 443);

        assert_eq!(result.src_ip, Some("192.168.1.100".to_string()));
        assert_eq!(result.src_port, Some(54321));
        assert_eq!(result.dst_ip, Some("10.0.0.1".to_string()));
        assert_eq!(result.dst_port, Some(443));
    }
}
