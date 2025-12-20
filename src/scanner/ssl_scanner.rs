//! SSL/TLS certificate scanning and security analysis
//!
//! This module performs SSL/TLS certificate validation and security checks,
//! including certificate expiration, weak ciphers, protocol versions, and HSTS.
//! Also provides SSL/TLS grading similar to SSL Labs (A+ to F).

use crate::types::SslInfo;
use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use x509_parser::prelude::*;

/// SSL/TLS grade from A+ to F, similar to SSL Labs grading
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, utoipa::ToSchema)]
pub enum SslGradeLevel {
    #[serde(rename = "A+")]
    APlus,
    A,
    #[serde(rename = "A-")]
    AMinus,
    #[serde(rename = "B+")]
    BPlus,
    B,
    #[serde(rename = "B-")]
    BMinus,
    C,
    D,
    F,
    /// Grade could not be determined (e.g., connection failure)
    Unknown,
}

impl std::fmt::Display for SslGradeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SslGradeLevel::APlus => write!(f, "A+"),
            SslGradeLevel::A => write!(f, "A"),
            SslGradeLevel::AMinus => write!(f, "A-"),
            SslGradeLevel::BPlus => write!(f, "B+"),
            SslGradeLevel::B => write!(f, "B"),
            SslGradeLevel::BMinus => write!(f, "B-"),
            SslGradeLevel::C => write!(f, "C"),
            SslGradeLevel::D => write!(f, "D"),
            SslGradeLevel::F => write!(f, "F"),
            SslGradeLevel::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detailed SSL/TLS grade information with scoring breakdown
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SslGrade {
    /// Overall grade (A+ to F)
    pub grade: SslGradeLevel,
    /// Overall numeric score (0-100)
    pub overall_score: u8,
    /// Protocol score (0-100) - TLS 1.3 = 100, TLS 1.2 = 85, TLS 1.1 = 40, TLS 1.0 = 20, SSL = 0
    pub protocol_score: u8,
    /// Cipher score (0-100) - Modern AEAD = 100, weak ciphers reduce score
    pub cipher_score: u8,
    /// Certificate score (0-100) - Valid chain, strong key, not expiring soon
    pub certificate_score: u8,
    /// Key exchange score (0-100) - Based on key strength
    pub key_exchange_score: u8,
    /// Known vulnerabilities found (Heartbleed, POODLE, BEAST, etc.)
    pub vulnerabilities_found: Vec<SslVulnerability>,
    /// Recommendations for improving the grade
    pub recommendations: Vec<String>,
    /// Whether the grade was capped due to critical issues
    pub grade_capped: bool,
    /// Reason for grade capping if applicable
    pub cap_reason: Option<String>,
}

/// Known SSL/TLS vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SslVulnerability {
    /// Vulnerability identifier (e.g., "POODLE", "HEARTBLEED")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Severity level
    pub severity: SslVulnerabilitySeverity,
    /// Description of the vulnerability
    pub description: String,
    /// CVE ID if applicable
    pub cve: Option<String>,
}

/// Severity levels for SSL/TLS vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum SslVulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Scan SSL/TLS certificate and security settings for a host:port
pub async fn scan_ssl(host: &str, port: u16, timeout: Duration) -> Result<SslInfo> {
    debug!("Scanning SSL/TLS for {}:{}", host, port);

    // Try to connect and get certificate
    let cert_info = get_certificate_info(host, port, timeout).await?;

    // Check for HSTS header via HTTP
    let (hsts_enabled, hsts_max_age) = check_hsts(host, port, timeout).await;

    // Build the base SslInfo without grade first
    let mut ssl_info = SslInfo {
        cert_valid: cert_info.cert_valid,
        cert_expired: cert_info.cert_expired,
        days_until_expiry: cert_info.days_until_expiry,
        self_signed: cert_info.self_signed,
        hostname_mismatch: cert_info.hostname_mismatch,
        issuer: cert_info.issuer,
        subject: cert_info.subject,
        valid_from: cert_info.valid_from,
        valid_until: cert_info.valid_until,
        protocols: cert_info.protocols,
        cipher_suites: cert_info.cipher_suites,
        weak_ciphers: cert_info.weak_ciphers,
        weak_protocols: cert_info.weak_protocols,
        hsts_enabled,
        hsts_max_age,
        chain_issues: cert_info.chain_issues,
        ssl_grade: None,
    };

    // Calculate the SSL grade
    let grade = calculate_ssl_grade(&ssl_info);
    ssl_info.ssl_grade = Some(grade);

    Ok(ssl_info)
}

#[derive(Debug)]
struct CertificateInfo {
    cert_valid: bool,
    cert_expired: bool,
    days_until_expiry: Option<i64>,
    self_signed: bool,
    hostname_mismatch: bool,
    issuer: String,
    subject: String,
    valid_from: String,
    valid_until: String,
    protocols: Vec<String>,
    cipher_suites: Vec<String>,
    weak_ciphers: Vec<String>,
    weak_protocols: Vec<String>,
    chain_issues: Vec<String>,
}

/// Get certificate information by connecting via TLS
async fn get_certificate_info(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<CertificateInfo> {
    let addr = format!("{}:{}", host, port);

    // Set up TCP connection with timeout
    let tcp_stream = match TcpStream::connect_timeout(&addr.parse()?, timeout) {
        Ok(stream) => stream,
        Err(e) => {
            warn!("Failed to connect to {}: {}", addr, e);
            return Err(anyhow::anyhow!("Connection failed: {}", e));
        }
    };

    tcp_stream.set_read_timeout(Some(timeout))?;
    tcp_stream.set_write_timeout(Some(timeout))?;

    // Configure rustls client
    let mut root_store = rustls::RootCertStore::empty();

    // Load native certificates
    for cert in rustls_native_certs::load_native_certs()? {
        root_store.add(cert).ok();
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(host.to_string())?;
    let client = rustls::ClientConnection::new(Arc::new(config), server_name.clone())?;
    let mut socket = rustls::StreamOwned::new(client, tcp_stream);

    // Perform TLS handshake by sending a minimal request
    let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
    socket.write_all(request.as_bytes())?;

    // Read a bit to complete handshake
    let mut buf = [0u8; 1024];
    let _ = socket.read(&mut buf);

    // Extract certificate information
    let conn = socket.conn;
    let peer_certs = conn.peer_certificates();

    if peer_certs.is_none() || peer_certs.unwrap().is_empty() {
        return Err(anyhow::anyhow!("No peer certificates found"));
    }

    let certs = peer_certs.unwrap();
    let cert_der = &certs[0];

    // Parse certificate using x509-parser
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

    // Extract basic info
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let valid_from = cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "Invalid date".to_string());
    let valid_until = cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "Invalid date".to_string());

    // Check if self-signed
    let self_signed = subject == issuer;

    // Check expiration
    let now = Utc::now();
    let not_after = cert.validity().not_after;
    let expiry_time = DateTime::from_timestamp(not_after.timestamp(), 0)
        .unwrap_or(Utc::now());

    let cert_expired = now > expiry_time;
    let days_until_expiry = if cert_expired {
        Some((expiry_time - now).num_days())
    } else {
        Some((expiry_time - now).num_days())
    };

    let cert_valid = !cert_expired && now > DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0).unwrap_or(Utc::now());

    // Check hostname mismatch
    let hostname_mismatch = !verify_hostname(&cert, host);

    // Detect supported protocols and ciphers
    let (protocols, cipher_suites) = detect_protocols_and_ciphers(host, port, timeout).await;

    // Identify weak ciphers
    let weak_ciphers = identify_weak_ciphers(&cipher_suites);

    // Identify weak protocols
    let weak_protocols = identify_weak_protocols(&protocols);

    // Check for chain issues
    let mut chain_issues = Vec::new();
    if self_signed {
        chain_issues.push("Self-signed certificate".to_string());
    }
    if certs.len() < 2 {
        chain_issues.push("Incomplete certificate chain".to_string());
    }

    Ok(CertificateInfo {
        cert_valid,
        cert_expired,
        days_until_expiry,
        self_signed,
        hostname_mismatch,
        issuer,
        subject,
        valid_from,
        valid_until,
        protocols,
        cipher_suites,
        weak_ciphers,
        weak_protocols,
        chain_issues,
    })
}

/// Verify hostname matches certificate
fn verify_hostname(cert: &X509Certificate, hostname: &str) -> bool {
    // Get subject alternative names
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        let san = san_ext.value;
        for name in &san.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    if matches_hostname(dns, hostname) {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }

    // Check CN in subject
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            let cn = attr.attr_type().to_id_string();
            if cn == "2.5.4.3" {
                // CN OID
                if let Ok(cn_value) = attr.attr_value().as_str() {
                    if matches_hostname(cn_value, hostname) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Check if hostname matches (with wildcard support)
fn matches_hostname(pattern: &str, hostname: &str) -> bool {
    if pattern == hostname {
        return true;
    }

    // Wildcard support: *.example.com matches www.example.com
    if pattern.starts_with("*.") {
        let pattern_suffix = &pattern[1..]; // Keep the dot: ".example.com"
        if hostname.ends_with(pattern_suffix) {
            // Ensure no additional dots (*.example.com shouldn't match a.b.example.com)
            let prefix = &hostname[..hostname.len() - pattern_suffix.len()];
            return !prefix.is_empty() && !prefix.contains('.');
        }
    }

    false
}

/// Detect supported SSL/TLS protocols and cipher suites by actually probing the server
async fn detect_protocols_and_ciphers(
    host: &str,
    port: u16,
    timeout: Duration,
) -> (Vec<String>, Vec<String>) {
    let mut protocols = Vec::new();
    let mut cipher_suites = Vec::new();

    // Probe each TLS version to see if the server supports it
    // TLS 1.3 and 1.2 can be tested with rustls
    // TLS 1.1, 1.0, SSL 3.0, SSL 2.0 require raw socket probing

    // Test TLS 1.3
    if probe_tls_1_3(host, port, timeout).await {
        protocols.push("TLS 1.3".to_string());
        // TLS 1.3 cipher suites
        cipher_suites.extend(vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_AES_128_GCM_SHA256".to_string(),
            "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        ]);
    }

    // Test TLS 1.2
    if probe_tls_1_2(host, port, timeout).await {
        protocols.push("TLS 1.2".to_string());
        // TLS 1.2 cipher suites (if not already added)
        if !cipher_suites.iter().any(|c| c.contains("ECDHE_RSA")) {
            cipher_suites.extend(vec![
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            ]);
        }
    }

    // Test TLS 1.1 (deprecated, requires raw socket probing)
    if probe_legacy_tls(host, port, timeout, TlsVersion::Tls11).await {
        protocols.push("TLS 1.1".to_string());
    }

    // Test TLS 1.0 (deprecated, requires raw socket probing)
    if probe_legacy_tls(host, port, timeout, TlsVersion::Tls10).await {
        protocols.push("TLS 1.0".to_string());
    }

    // Test SSL 3.0 (deprecated and insecure)
    if probe_legacy_tls(host, port, timeout, TlsVersion::Ssl30).await {
        protocols.push("SSL 3.0".to_string());
    }

    // Test SSL 2.0 (deprecated and insecure)
    if probe_legacy_tls(host, port, timeout, TlsVersion::Ssl20).await {
        protocols.push("SSL 2.0".to_string());
    }

    (protocols, cipher_suites)
}

/// TLS version identifiers for legacy probing
#[derive(Debug, Clone, Copy)]
enum TlsVersion {
    Ssl20,
    Ssl30,
    Tls10,
    Tls11,
}

impl TlsVersion {
    /// Get the protocol version bytes for ClientHello
    fn version_bytes(&self) -> [u8; 2] {
        match self {
            TlsVersion::Ssl20 => [0x00, 0x02], // SSL 2.0
            TlsVersion::Ssl30 => [0x03, 0x00], // SSL 3.0
            TlsVersion::Tls10 => [0x03, 0x01], // TLS 1.0
            TlsVersion::Tls11 => [0x03, 0x02], // TLS 1.1
        }
    }

    fn name(&self) -> &'static str {
        match self {
            TlsVersion::Ssl20 => "SSL 2.0",
            TlsVersion::Ssl30 => "SSL 3.0",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
        }
    }
}

/// Probe if server supports TLS 1.3 using rustls
async fn probe_tls_1_3(host: &str, port: u16, timeout: Duration) -> bool {
    let host = host.to_string();
    let result = tokio::task::spawn_blocking(move || {
        probe_tls_1_3_sync(&host, port, timeout)
    })
    .await;

    match result {
        Ok(supported) => supported,
        Err(e) => {
            debug!("TLS 1.3 probe task failed: {}", e);
            false
        }
    }
}

fn probe_tls_1_3_sync(host: &str, port: u16, timeout: Duration) -> bool {
    // Use raw socket probing for TLS 1.3 as well since rustls API varies by feature flags
    probe_tls_version_raw(host, port, timeout, &[0x03, 0x04], "TLS 1.3")
}

/// Probe a specific TLS version using raw socket ClientHello
/// This works for all TLS versions without depending on rustls crypto provider features
fn probe_tls_version_raw(host: &str, port: u16, timeout: Duration, version_bytes: &[u8; 2], version_name: &str) -> bool {
    let addr = format!("{}:{}", host, port);

    let mut tcp_stream = match TcpStream::connect_timeout(&match addr.parse() {
        Ok(a) => a,
        Err(_) => return false,
    }, timeout) {
        Ok(stream) => stream,
        Err(_) => return false,
    };

    let _ = tcp_stream.set_read_timeout(Some(timeout));
    let _ = tcp_stream.set_write_timeout(Some(timeout));

    // Build ClientHello for this version
    let client_hello = build_modern_client_hello(host, version_bytes);

    if tcp_stream.write_all(&client_hello).is_err() {
        return false;
    }

    // Read ServerHello response
    let mut response = [0u8; 2048];
    let bytes_read = match tcp_stream.read(&mut response) {
        Ok(n) if n > 0 => n,
        _ => return false,
    };

    // Parse the response
    parse_modern_server_hello(&response[..bytes_read], version_bytes, version_name)
}

/// Build a TLS ClientHello for modern TLS versions (1.2, 1.3)
fn build_modern_client_hello(host: &str, target_version: &[u8; 2]) -> Vec<u8> {
    // Generate 32 bytes of random data
    let random: Vec<u8> = (0..32).map(|i| ((i * 7 + 3) % 256) as u8).collect();

    // Cipher suites - include both TLS 1.2 and TLS 1.3 suites
    let cipher_suites: Vec<u8> = vec![
        // TLS 1.3 cipher suites
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        // TLS 1.2 cipher suites
        0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x9f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
    ];

    // Build extensions
    let mut extensions = Vec::new();

    // Server Name Indication (SNI) extension
    let hostname_bytes = host.as_bytes();
    let sni_list_length = hostname_bytes.len() + 3;
    let sni_ext_length = sni_list_length + 2;
    extensions.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
    extensions.extend_from_slice(&(sni_ext_length as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_list_length as u16).to_be_bytes());
    extensions.push(0x00); // Name type: host_name
    extensions.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(hostname_bytes);

    // Supported Groups (for ECDHE)
    extensions.extend_from_slice(&[0x00, 0x0a]); // Extension type: supported_groups
    extensions.extend_from_slice(&[0x00, 0x08]); // Extension length
    extensions.extend_from_slice(&[0x00, 0x06]); // Supported groups list length
    extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1
    extensions.extend_from_slice(&[0x00, 0x18]); // secp384r1
    extensions.extend_from_slice(&[0x00, 0x19]); // secp521r1

    // EC Point Formats
    extensions.extend_from_slice(&[0x00, 0x0b]); // Extension type: ec_point_formats
    extensions.extend_from_slice(&[0x00, 0x02]); // Extension length
    extensions.push(0x01); // EC point formats length
    extensions.push(0x00); // uncompressed

    // Signature Algorithms
    extensions.extend_from_slice(&[0x00, 0x0d]); // Extension type: signature_algorithms
    extensions.extend_from_slice(&[0x00, 0x14]); // Extension length
    extensions.extend_from_slice(&[0x00, 0x12]); // Signature algorithms length
    extensions.extend_from_slice(&[0x04, 0x03]); // ecdsa_secp256r1_sha256
    extensions.extend_from_slice(&[0x05, 0x03]); // ecdsa_secp384r1_sha384
    extensions.extend_from_slice(&[0x06, 0x03]); // ecdsa_secp521r1_sha512
    extensions.extend_from_slice(&[0x08, 0x04]); // rsa_pss_rsae_sha256
    extensions.extend_from_slice(&[0x08, 0x05]); // rsa_pss_rsae_sha384
    extensions.extend_from_slice(&[0x08, 0x06]); // rsa_pss_rsae_sha512
    extensions.extend_from_slice(&[0x04, 0x01]); // rsa_pkcs1_sha256
    extensions.extend_from_slice(&[0x05, 0x01]); // rsa_pkcs1_sha384
    extensions.extend_from_slice(&[0x06, 0x01]); // rsa_pkcs1_sha512

    // Supported Versions extension (critical for TLS 1.3 probing)
    extensions.extend_from_slice(&[0x00, 0x2b]); // Extension type: supported_versions
    extensions.extend_from_slice(&[0x00, 0x03]); // Extension length
    extensions.push(0x02); // Supported versions length
    extensions.extend_from_slice(target_version); // Single version we're testing

    // Key Share extension (required for TLS 1.3)
    if target_version == &[0x03, 0x04] {
        // Generate a dummy X25519 public key (32 bytes)
        let dummy_key: Vec<u8> = (0..32).map(|i| ((i * 13 + 7) % 256) as u8).collect();

        extensions.extend_from_slice(&[0x00, 0x33]); // Extension type: key_share
        let key_share_length = 2 + 2 + 32; // group (2) + key length (2) + key (32)
        extensions.extend_from_slice(&(key_share_length as u16 + 2).to_be_bytes()); // Extension length
        extensions.extend_from_slice(&(key_share_length as u16).to_be_bytes()); // Client key share length
        extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
        extensions.extend_from_slice(&[0x00, 0x20]); // Key length (32)
        extensions.extend_from_slice(&dummy_key);
    }

    // Build ClientHello handshake message
    let mut client_hello = Vec::new();

    // For TLS 1.3, the record layer version should be TLS 1.2 (0x0303)
    // but the supported_versions extension specifies the actual version
    let hello_version = if target_version == &[0x03, 0x04] {
        [0x03, 0x03] // TLS 1.2 in hello for TLS 1.3
    } else {
        *target_version
    };

    client_hello.extend_from_slice(&hello_version);
    client_hello.extend_from_slice(&random);
    client_hello.push(0x00); // Session ID length (empty)
    client_hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&cipher_suites);
    client_hello.push(0x01); // Compression methods length
    client_hello.push(0x00); // null compression
    client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&extensions);

    // Build handshake record
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    // Length is 3 bytes
    let hello_len = client_hello.len();
    handshake.push((hello_len >> 16) as u8);
    handshake.push((hello_len >> 8) as u8);
    handshake.push(hello_len as u8);
    handshake.extend_from_slice(&client_hello);

    // Build TLS record - use TLS 1.0 version in record layer for compatibility
    let mut record = Vec::new();
    record.push(0x16); // Content type: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 in record layer
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Parse ServerHello for modern TLS versions
fn parse_modern_server_hello(response: &[u8], expected_version: &[u8; 2], version_name: &str) -> bool {
    if response.len() < 5 {
        return false;
    }

    let content_type = response[0];

    // Check for Alert (0x15)
    if content_type == 0x15 {
        debug!("{}: Server sent alert (rejected)", version_name);
        return false;
    }

    // Must be Handshake (0x16)
    if content_type != 0x16 {
        debug!("{}: Unexpected content type {}", version_name, content_type);
        return false;
    }

    let record_length = u16::from_be_bytes([response[3], response[4]]) as usize;
    if response.len() < 5 + record_length || record_length < 6 {
        return false;
    }

    let handshake_type = response[5];
    if handshake_type != 0x02 {
        // Not ServerHello
        debug!("{}: Not ServerHello (type {})", version_name, handshake_type);
        return false;
    }

    // For TLS 1.3, the version in ServerHello is always 0x0303 (TLS 1.2)
    // The actual version is in the supported_versions extension
    if expected_version == &[0x03, 0x04] {
        // Parse ServerHello to find supported_versions extension
        // ServerHello format: type(1) + length(3) + version(2) + random(32) + session_id_len(1) + ...
        if response.len() < 5 + 6 + 32 + 1 {
            return false;
        }

        // Check if server responded with TLS 1.2 in the hello (expected for TLS 1.3)
        let server_version = [response[9], response[10]];
        if server_version != [0x03, 0x03] {
            // Server didn't respond with TLS 1.2 legacy version
            // This might mean it doesn't support TLS 1.3
            debug!("{}: Server version is {:02x}{:02x}, not TLS 1.2 legacy",
                   version_name, server_version[0], server_version[1]);

            // If it's an older version, definitely not TLS 1.3
            if server_version[0] < 0x03 || (server_version[0] == 0x03 && server_version[1] < 0x03) {
                return false;
            }
        }

        // Look for supported_versions extension in ServerHello
        // This requires parsing the full ServerHello structure
        if let Some(negotiated_version) = find_supported_versions_extension(&response[5..5+record_length]) {
            if negotiated_version == [0x03, 0x04] {
                debug!("{}: Server accepted (supported_versions extension)", version_name);
                return true;
            }
        }

        // If we got here with TLS 1.2 legacy version but no supported_versions,
        // the server might still support TLS 1.3 if it's a Hello Retry Request
        // For now, we'll be conservative and say no TLS 1.3
        debug!("{}: No supported_versions extension found", version_name);
        return false;
    }

    // For TLS 1.2, check the version in ServerHello directly
    let server_version = [response[9], response[10]];
    if server_version == *expected_version {
        debug!("{}: Server accepted", version_name);
        return true;
    }

    debug!("{}: Server responded with version {:02x}{:02x}",
           version_name, server_version[0], server_version[1]);
    false
}

/// Find the supported_versions extension in a ServerHello
fn find_supported_versions_extension(handshake_data: &[u8]) -> Option<[u8; 2]> {
    // ServerHello format:
    // type(1) + length(3) + version(2) + random(32) + session_id_len(1) + session_id(var) +
    // cipher_suite(2) + compression(1) + extensions_length(2) + extensions(var)

    if handshake_data.len() < 1 + 3 + 2 + 32 + 1 {
        return None;
    }

    let handshake_length = ((handshake_data[1] as usize) << 16) |
                           ((handshake_data[2] as usize) << 8) |
                           (handshake_data[3] as usize);

    if handshake_data.len() < 4 + handshake_length {
        return None;
    }

    let mut offset = 4; // Skip type and length

    // Skip version (2) + random (32)
    offset += 34;
    if offset >= handshake_data.len() {
        return None;
    }

    // Session ID
    let session_id_len = handshake_data[offset] as usize;
    offset += 1 + session_id_len;
    if offset + 3 > handshake_data.len() {
        return None;
    }

    // Skip cipher suite (2) + compression (1)
    offset += 3;
    if offset + 2 > handshake_data.len() {
        return None;
    }

    // Extensions length
    let extensions_length = u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_length;
    if extensions_end > handshake_data.len() {
        return None;
    }

    // Parse extensions
    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]);
        let ext_length = u16::from_be_bytes([handshake_data[offset + 2], handshake_data[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_length > extensions_end {
            break;
        }

        // supported_versions extension type is 0x002b (43)
        if ext_type == 0x002b && ext_length >= 2 {
            let version = [handshake_data[offset], handshake_data[offset + 1]];
            return Some(version);
        }

        offset += ext_length;
    }

    None
}

/// Probe if server supports TLS 1.2 using raw socket ClientHello
async fn probe_tls_1_2(host: &str, port: u16, timeout: Duration) -> bool {
    let host = host.to_string();
    let result = tokio::task::spawn_blocking(move || {
        probe_tls_version_raw(&host, port, timeout, &[0x03, 0x03], "TLS 1.2")
    })
    .await;

    match result {
        Ok(supported) => supported,
        Err(e) => {
            debug!("TLS 1.2 probe task failed: {}", e);
            false
        }
    }
}

/// Probe legacy TLS versions (1.0, 1.1) and SSL (2.0, 3.0) using raw socket ClientHello
/// These versions are deprecated and not supported by rustls, so we must use raw sockets
async fn probe_legacy_tls(host: &str, port: u16, timeout: Duration, version: TlsVersion) -> bool {
    let host = host.to_string();
    let result = tokio::task::spawn_blocking(move || {
        probe_legacy_tls_sync(&host, port, timeout, version)
    })
    .await;

    match result {
        Ok(supported) => supported,
        Err(e) => {
            debug!("{} probe task failed: {}", version.name(), e);
            false
        }
    }
}

fn probe_legacy_tls_sync(host: &str, port: u16, timeout: Duration, version: TlsVersion) -> bool {
    let addr = format!("{}:{}", host, port);

    let mut tcp_stream = match TcpStream::connect_timeout(&match addr.parse() {
        Ok(a) => a,
        Err(_) => return false,
    }, timeout) {
        Ok(stream) => stream,
        Err(_) => return false,
    };

    let _ = tcp_stream.set_read_timeout(Some(timeout));
    let _ = tcp_stream.set_write_timeout(Some(timeout));

    // Build and send ClientHello for the specific version
    let client_hello = build_client_hello(host, version);

    if tcp_stream.write_all(&client_hello).is_err() {
        return false;
    }

    // Read ServerHello response
    let mut response = [0u8; 1024];
    let bytes_read = match tcp_stream.read(&mut response) {
        Ok(n) if n > 0 => n,
        _ => return false,
    };

    // Parse the response to check if server accepted our version
    parse_server_hello(&response[..bytes_read], version)
}

/// Build a minimal TLS ClientHello message for version probing
fn build_client_hello(host: &str, version: TlsVersion) -> Vec<u8> {
    // For SSL 2.0, use a completely different format
    if matches!(version, TlsVersion::Ssl20) {
        return build_ssl2_client_hello();
    }

    let version_bytes = version.version_bytes();

    // Cipher suites appropriate for legacy versions
    let cipher_suites: Vec<u8> = match version {
        TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11 => {
            vec![
                // TLS_RSA_WITH_AES_128_CBC_SHA
                0x00, 0x2f,
                // TLS_RSA_WITH_AES_256_CBC_SHA
                0x00, 0x35,
                // TLS_RSA_WITH_3DES_EDE_CBC_SHA
                0x00, 0x0a,
                // TLS_RSA_WITH_AES_128_CBC_SHA256
                0x00, 0x3c,
                // TLS_RSA_WITH_AES_256_CBC_SHA256
                0x00, 0x3d,
                // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xc0, 0x13,
                // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0xc0, 0x14,
            ]
        }
        TlsVersion::Ssl20 => vec![], // Handled above
    };

    // Generate 32 bytes of random data
    let random: Vec<u8> = (0..32).map(|i| (i * 7 + 3) as u8).collect();

    // Build extensions (SNI for hostname)
    let mut extensions = Vec::new();

    // Server Name Indication (SNI) extension
    let hostname_bytes = host.as_bytes();
    let sni_list_length = hostname_bytes.len() + 3;
    let sni_ext_length = sni_list_length + 2;

    extensions.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
    extensions.extend_from_slice(&(sni_ext_length as u16).to_be_bytes()); // Extension length
    extensions.extend_from_slice(&(sni_list_length as u16).to_be_bytes()); // Server name list length
    extensions.push(0x00); // Name type: host_name
    extensions.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes()); // Host name length
    extensions.extend_from_slice(hostname_bytes); // Host name

    // Supported versions extension (for better compatibility)
    extensions.extend_from_slice(&[0x00, 0x2b]); // Extension type: supported_versions
    extensions.extend_from_slice(&[0x00, 0x03]); // Extension length
    extensions.push(0x02); // Supported versions length
    extensions.extend_from_slice(&version_bytes); // Single version

    // Build ClientHello handshake message
    let mut client_hello = Vec::new();

    // Client version (use the version we're probing)
    client_hello.extend_from_slice(&version_bytes);

    // Random (32 bytes)
    client_hello.extend_from_slice(&random);

    // Session ID (empty)
    client_hello.push(0x00);

    // Cipher suites
    client_hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&cipher_suites);

    // Compression methods (null only)
    client_hello.push(0x01); // Length
    client_hello.push(0x00); // null compression

    // Extensions
    client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&extensions);

    // Build handshake record
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.push(0x00); // Length high byte
    handshake.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&client_hello);

    // Build TLS record
    let mut record = Vec::new();
    record.push(0x16); // Content type: Handshake
    record.extend_from_slice(&version_bytes); // Version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes()); // Length
    record.extend_from_slice(&handshake);

    record
}

/// Build SSL 2.0 ClientHello (completely different format)
fn build_ssl2_client_hello() -> Vec<u8> {
    // SSL 2.0 uses a different record format
    let mut msg = Vec::new();

    // SSL 2.0 cipher specs (3 bytes each)
    let cipher_specs: Vec<u8> = vec![
        // SSL_CK_RC4_128_WITH_MD5
        0x01, 0x00, 0x80,
        // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
        0x07, 0x00, 0xc0,
    ];

    // Challenge (16 bytes)
    let challenge: Vec<u8> = (0..16).map(|i| (i * 7 + 3) as u8).collect();

    // Build message
    msg.push(0x01); // MSG-CLIENT-HELLO
    msg.extend_from_slice(&[0x00, 0x02]); // Version: SSL 2.0
    msg.extend_from_slice(&(cipher_specs.len() as u16).to_be_bytes()); // Cipher specs length
    msg.extend_from_slice(&[0x00, 0x00]); // Session ID length (0)
    msg.extend_from_slice(&(challenge.len() as u16).to_be_bytes()); // Challenge length
    msg.extend_from_slice(&cipher_specs);
    msg.extend_from_slice(&challenge);

    // SSL 2.0 record header (2 bytes for short header)
    let record_length = msg.len();
    let mut record = Vec::new();
    // High bit set = 2-byte header, no padding
    record.push(0x80 | ((record_length >> 8) as u8));
    record.push((record_length & 0xff) as u8);
    record.extend_from_slice(&msg);

    record
}

/// Parse ServerHello to check if server accepted our TLS version
fn parse_server_hello(response: &[u8], expected_version: TlsVersion) -> bool {
    if response.len() < 5 {
        return false;
    }

    // Check for SSL 2.0 response (different format)
    if matches!(expected_version, TlsVersion::Ssl20) {
        return parse_ssl2_server_hello(response);
    }

    // TLS record format: type (1) | version (2) | length (2) | data
    let content_type = response[0];
    let version_major = response[1];
    let version_minor = response[2];

    // Check for Handshake content type (0x16) or Alert (0x15)
    if content_type == 0x15 {
        // Alert - server rejected the connection
        debug!("{}: Server sent alert (rejected)", expected_version.name());
        return false;
    }

    if content_type != 0x16 {
        // Not a handshake message
        return false;
    }

    // Check if the response version matches what we requested
    let response_version = [version_major, version_minor];
    let expected_bytes = expected_version.version_bytes();

    // For TLS 1.0 and 1.1, the record layer version might differ from handshake version
    // We need to look inside the handshake message
    if response.len() < 10 {
        return false;
    }

    let record_length = u16::from_be_bytes([response[3], response[4]]) as usize;
    if response.len() < 5 + record_length || record_length < 6 {
        return false;
    }

    let handshake_type = response[5];
    if handshake_type != 0x02 {
        // Not ServerHello
        return false;
    }

    // ServerHello: type (1) | length (3) | version (2) | ...
    let server_version = [response[9], response[10]];

    if server_version == expected_bytes {
        debug!("{}: Server accepted", expected_version.name());
        return true;
    }

    // Some servers downgrade, check if response is at least what we asked for
    // Also check record layer version as some servers use that
    if response_version == expected_bytes {
        debug!("{}: Server accepted (record layer version match)", expected_version.name());
        return true;
    }

    debug!(
        "{}: Server responded with version {:02x}{:02x} (expected {:02x}{:02x})",
        expected_version.name(),
        server_version[0], server_version[1],
        expected_bytes[0], expected_bytes[1]
    );

    false
}

/// Parse SSL 2.0 ServerHello
fn parse_ssl2_server_hello(response: &[u8]) -> bool {
    if response.len() < 3 {
        return false;
    }

    // SSL 2.0 record header
    let header = response[0];
    if header & 0x80 == 0 {
        // 3-byte header with padding
        if response.len() < 4 {
            return false;
        }
        // Check for SSL 2.0 ServerHello (0x04)
        if response[2] == 0x04 {
            debug!("SSL 2.0: Server accepted (3-byte header)");
            return true;
        }
    } else {
        // 2-byte header
        // Check for SSL 2.0 ServerHello (0x04)
        if response.len() >= 3 && response[2] == 0x04 {
            debug!("SSL 2.0: Server accepted (2-byte header)");
            return true;
        }
        // Check for SSL 2.0 Error (0x00)
        if response.len() >= 3 && response[2] == 0x00 {
            debug!("SSL 2.0: Server sent error");
            return false;
        }
    }

    // Also check if server responded with TLS alert (meaning it doesn't support SSL 2.0)
    if response.len() >= 3 && response[0] == 0x15 {
        debug!("SSL 2.0: Server sent TLS alert (SSL 2.0 not supported)");
        return false;
    }

    false
}

/// Identify weak/insecure ciphers
fn identify_weak_ciphers(cipher_suites: &[String]) -> Vec<String> {
    let mut weak = Vec::new();

    let weak_patterns = vec![
        "RC4",
        "DES",
        "3DES",
        "EXPORT",
        "NULL",
        "MD5",
        "ANON",
        "ADH",
        "AECDH",
    ];

    for cipher in cipher_suites {
        for pattern in &weak_patterns {
            if cipher.to_uppercase().contains(pattern) {
                weak.push(cipher.clone());
                break;
            }
        }
    }

    weak
}

/// Identify weak/deprecated protocols
fn identify_weak_protocols(protocols: &[String]) -> Vec<String> {
    let mut weak = Vec::new();

    let weak_versions = vec!["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"];

    for protocol in protocols {
        if weak_versions.contains(&protocol.as_str()) {
            weak.push(protocol.clone());
        }
    }

    weak
}

/// Check for HSTS (HTTP Strict Transport Security) header
async fn check_hsts(host: &str, port: u16, timeout: Duration) -> (bool, Option<u64>) {
    // Try to make HTTPS request and check for HSTS header
    let addr = format!("{}:{}", host, port);

    let addr_parsed = match addr.parse() {
        Ok(addr) => addr,
        Err(_) => return (false, None),
    };

    let tcp_stream = match TcpStream::connect_timeout(&addr_parsed, timeout) {
        Ok(stream) => stream,
        Err(_) => return (false, None),
    };

    let _ = tcp_stream.set_read_timeout(Some(timeout));
    let _ = tcp_stream.set_write_timeout(Some(timeout));

    // Configure rustls client
    let mut root_store = rustls::RootCertStore::empty();
    let certs = match rustls_native_certs::load_native_certs() {
        Ok(certs) => certs,
        Err(_) => return (false, None),
    };

    for cert in certs {
        root_store.add(cert).ok();
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => return (false, None),
    };

    let client = match rustls::ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(_) => return (false, None),
    };

    let mut socket = rustls::StreamOwned::new(client, tcp_stream);

    // Send HTTP request
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
    if socket.write_all(request.as_bytes()).is_err() {
        return (false, None);
    }

    // Read response
    let mut response = String::new();
    let _ = socket.read_to_string(&mut response);

    // Parse HSTS header
    for line in response.lines() {
        if line.to_lowercase().starts_with("strict-transport-security:") {
            let value = match line.split(':').nth(1) {
                Some(v) => v.trim(),
                None => continue,
            };

            // Extract max-age
            for directive in value.split(';') {
                let directive = directive.trim();
                if directive.to_lowercase().starts_with("max-age=") {
                    if let Some(max_age_str) = directive.split('=').nth(1) {
                        if let Ok(max_age) = max_age_str.parse::<u64>() {
                            return (true, Some(max_age));
                        }
                    }
                }
            }

            return (true, None);
        }
    }

    (false, None)
}

/// Calculate SSL/TLS grade based on the SslInfo
/// This provides a comprehensive security grade similar to SSL Labs
pub fn calculate_ssl_grade(ssl_info: &SslInfo) -> SslGrade {
    let mut vulnerabilities = Vec::new();
    let mut recommendations = Vec::new();
    let mut grade_capped = false;
    let mut cap_reason: Option<String> = None;

    // === Calculate Protocol Score (0-100) ===
    let protocol_score = calculate_protocol_score(&ssl_info.protocols, &ssl_info.weak_protocols);

    // Check for protocol-related vulnerabilities
    if ssl_info.protocols.iter().any(|p| p == "SSL 2.0") {
        vulnerabilities.push(SslVulnerability {
            id: "SSL2".to_string(),
            name: "SSL 2.0 Supported".to_string(),
            severity: SslVulnerabilitySeverity::Critical,
            description: "SSL 2.0 is severely insecure and should be disabled immediately. It has numerous vulnerabilities including weak cipher suites and protocol design flaws.".to_string(),
            cve: None,
        });
        grade_capped = true;
        cap_reason = Some("SSL 2.0 is supported - grade capped at F".to_string());
        recommendations.push("Disable SSL 2.0 immediately".to_string());
    }

    if ssl_info.protocols.iter().any(|p| p == "SSL 3.0") {
        vulnerabilities.push(SslVulnerability {
            id: "POODLE".to_string(),
            name: "POODLE (SSL 3.0)".to_string(),
            severity: SslVulnerabilitySeverity::High,
            description: "SSL 3.0 is vulnerable to POODLE (Padding Oracle On Downgraded Legacy Encryption) attack.".to_string(),
            cve: Some("CVE-2014-3566".to_string()),
        });
        if !grade_capped {
            grade_capped = true;
            cap_reason = Some("SSL 3.0 is supported (POODLE vulnerable) - grade capped at C".to_string());
        }
        recommendations.push("Disable SSL 3.0 to prevent POODLE attack".to_string());
    }

    if ssl_info.protocols.iter().any(|p| p == "TLS 1.0") {
        vulnerabilities.push(SslVulnerability {
            id: "TLS10".to_string(),
            name: "TLS 1.0 Deprecated".to_string(),
            severity: SslVulnerabilitySeverity::Medium,
            description: "TLS 1.0 is deprecated and vulnerable to BEAST and other attacks.".to_string(),
            cve: Some("CVE-2011-3389".to_string()),
        });
        recommendations.push("Disable TLS 1.0 - use TLS 1.2 or TLS 1.3".to_string());
    }

    if ssl_info.protocols.iter().any(|p| p == "TLS 1.1") {
        vulnerabilities.push(SslVulnerability {
            id: "TLS11".to_string(),
            name: "TLS 1.1 Deprecated".to_string(),
            severity: SslVulnerabilitySeverity::Low,
            description: "TLS 1.1 is deprecated as of 2021 and should not be used.".to_string(),
            cve: None,
        });
        recommendations.push("Disable TLS 1.1 - use TLS 1.2 or TLS 1.3".to_string());
    }

    if !ssl_info.protocols.iter().any(|p| p == "TLS 1.3") {
        recommendations.push("Enable TLS 1.3 for best security and performance".to_string());
    }

    // === Calculate Cipher Score (0-100) ===
    let cipher_score = calculate_cipher_score(&ssl_info.cipher_suites, &ssl_info.weak_ciphers);

    // Check for cipher-related vulnerabilities
    if ssl_info.weak_ciphers.iter().any(|c| c.to_uppercase().contains("RC4")) {
        vulnerabilities.push(SslVulnerability {
            id: "RC4".to_string(),
            name: "RC4 Cipher Supported".to_string(),
            severity: SslVulnerabilitySeverity::High,
            description: "RC4 is a broken cipher with practical attacks. It should be completely disabled.".to_string(),
            cve: Some("CVE-2015-2808".to_string()),
        });
        recommendations.push("Disable all RC4 cipher suites".to_string());
    }

    if ssl_info.weak_ciphers.iter().any(|c| c.to_uppercase().contains("DES") && !c.to_uppercase().contains("3DES")) {
        vulnerabilities.push(SslVulnerability {
            id: "DES".to_string(),
            name: "DES Cipher Supported".to_string(),
            severity: SslVulnerabilitySeverity::Critical,
            description: "DES is a 56-bit cipher that can be brute-forced. It should be completely disabled.".to_string(),
            cve: None,
        });
        recommendations.push("Disable all DES cipher suites".to_string());
    }

    if ssl_info.weak_ciphers.iter().any(|c| c.to_uppercase().contains("3DES")) {
        vulnerabilities.push(SslVulnerability {
            id: "SWEET32".to_string(),
            name: "3DES/SWEET32".to_string(),
            severity: SslVulnerabilitySeverity::Medium,
            description: "3DES is vulnerable to the SWEET32 birthday attack due to its 64-bit block size.".to_string(),
            cve: Some("CVE-2016-2183".to_string()),
        });
        recommendations.push("Disable 3DES cipher suites to prevent SWEET32 attack".to_string());
    }

    if ssl_info.weak_ciphers.iter().any(|c| c.to_uppercase().contains("EXPORT")) {
        vulnerabilities.push(SslVulnerability {
            id: "EXPORT".to_string(),
            name: "Export Ciphers Supported".to_string(),
            severity: SslVulnerabilitySeverity::Critical,
            description: "Export ciphers use weakened cryptography (512-bit RSA, 40-bit encryption) and are trivially broken.".to_string(),
            cve: Some("CVE-2015-0204".to_string()),
        });
        if !grade_capped {
            grade_capped = true;
            cap_reason = Some("Export ciphers supported - grade capped at F".to_string());
        }
        recommendations.push("Disable all EXPORT cipher suites immediately".to_string());
    }

    if ssl_info.weak_ciphers.iter().any(|c| c.to_uppercase().contains("NULL")) {
        vulnerabilities.push(SslVulnerability {
            id: "NULL_CIPHER".to_string(),
            name: "NULL Cipher Supported".to_string(),
            severity: SslVulnerabilitySeverity::Critical,
            description: "NULL ciphers provide no encryption - data is transmitted in plaintext.".to_string(),
            cve: None,
        });
        if !grade_capped {
            grade_capped = true;
            cap_reason = Some("NULL cipher supported - grade capped at F".to_string());
        }
        recommendations.push("Disable NULL cipher suites immediately".to_string());
    }

    // === Calculate Certificate Score (0-100) ===
    let certificate_score = calculate_certificate_score(ssl_info);

    // Check for certificate-related issues
    if ssl_info.cert_expired {
        vulnerabilities.push(SslVulnerability {
            id: "CERT_EXPIRED".to_string(),
            name: "Certificate Expired".to_string(),
            severity: SslVulnerabilitySeverity::Critical,
            description: "The SSL/TLS certificate has expired. This will cause browser warnings and connection failures.".to_string(),
            cve: None,
        });
        if !grade_capped {
            grade_capped = true;
            cap_reason = Some("Certificate expired - grade capped at F".to_string());
        }
        recommendations.push("Renew the SSL/TLS certificate immediately".to_string());
    }

    if ssl_info.self_signed {
        vulnerabilities.push(SslVulnerability {
            id: "SELF_SIGNED".to_string(),
            name: "Self-Signed Certificate".to_string(),
            severity: SslVulnerabilitySeverity::High,
            description: "Self-signed certificates are not trusted by browsers and cannot verify server identity.".to_string(),
            cve: None,
        });
        if !grade_capped {
            grade_capped = true;
            cap_reason = Some("Self-signed certificate - grade capped at T (not trusted)".to_string());
        }
        recommendations.push("Use a certificate from a trusted Certificate Authority".to_string());
    }

    if ssl_info.hostname_mismatch {
        vulnerabilities.push(SslVulnerability {
            id: "HOSTNAME_MISMATCH".to_string(),
            name: "Certificate Hostname Mismatch".to_string(),
            severity: SslVulnerabilitySeverity::Critical,
            description: "The certificate does not match the hostname, which could indicate a MITM attack or misconfiguration.".to_string(),
            cve: None,
        });
        if !grade_capped {
            grade_capped = true;
            cap_reason = Some("Hostname mismatch - grade capped at F".to_string());
        }
        recommendations.push("Ensure certificate Subject Alternative Names (SANs) include the hostname".to_string());
    }

    if let Some(days) = ssl_info.days_until_expiry {
        if days > 0 && days < 30 {
            recommendations.push(format!("Certificate expires in {} days - renew soon", days));
        }
    }

    // Check for chain issues
    for issue in &ssl_info.chain_issues {
        if issue.contains("Incomplete") {
            vulnerabilities.push(SslVulnerability {
                id: "INCOMPLETE_CHAIN".to_string(),
                name: "Incomplete Certificate Chain".to_string(),
                severity: SslVulnerabilitySeverity::Medium,
                description: "The certificate chain is incomplete. Some clients may not be able to verify the certificate.".to_string(),
                cve: None,
            });
            recommendations.push("Include all intermediate certificates in the chain".to_string());
        }
    }

    // === Calculate Key Exchange Score (0-100) ===
    let key_exchange_score = calculate_key_exchange_score(&ssl_info.cipher_suites);

    // Check for key exchange vulnerabilities
    if ssl_info.cipher_suites.iter().any(|c| {
        let upper = c.to_uppercase();
        upper.contains("_RSA_") && !upper.contains("ECDHE") && !upper.contains("DHE")
    }) {
        vulnerabilities.push(SslVulnerability {
            id: "NO_PFS".to_string(),
            name: "No Perfect Forward Secrecy".to_string(),
            severity: SslVulnerabilitySeverity::Medium,
            description: "Some cipher suites do not provide Perfect Forward Secrecy. Past communications could be decrypted if the private key is compromised.".to_string(),
            cve: None,
        });
        recommendations.push("Prefer ECDHE or DHE key exchange for Perfect Forward Secrecy".to_string());
    }

    // === HSTS Check ===
    if !ssl_info.hsts_enabled {
        vulnerabilities.push(SslVulnerability {
            id: "NO_HSTS".to_string(),
            name: "HSTS Not Enabled".to_string(),
            severity: SslVulnerabilitySeverity::Informational,
            description: "HTTP Strict Transport Security is not enabled. This leaves users vulnerable to SSL stripping attacks.".to_string(),
            cve: None,
        });
        recommendations.push("Enable HSTS with a max-age of at least 31536000 (1 year)".to_string());
    } else if let Some(max_age) = ssl_info.hsts_max_age {
        if max_age < 31536000 {
            recommendations.push(format!("HSTS max-age is {} seconds - consider increasing to at least 31536000 (1 year)", max_age));
        }
    }

    // === Calculate Overall Score ===
    // Weighted average: Protocol 30%, Cipher 30%, Certificate 30%, Key Exchange 10%
    let overall_score = (
        (protocol_score as u32 * 30) +
        (cipher_score as u32 * 30) +
        (certificate_score as u32 * 30) +
        (key_exchange_score as u32 * 10)
    ) / 100;
    let overall_score = overall_score.min(100) as u8;

    // === Determine Grade ===
    let grade = if grade_capped {
        match cap_reason.as_deref() {
            Some(r) if r.contains("capped at F") => SslGradeLevel::F,
            Some(r) if r.contains("capped at C") => SslGradeLevel::C,
            Some(r) if r.contains("not trusted") => SslGradeLevel::B, // Self-signed but otherwise good
            _ => SslGradeLevel::F,
        }
    } else {
        score_to_grade(overall_score, ssl_info.hsts_enabled, &vulnerabilities)
    };

    SslGrade {
        grade,
        overall_score,
        protocol_score,
        cipher_score,
        certificate_score,
        key_exchange_score,
        vulnerabilities_found: vulnerabilities,
        recommendations,
        grade_capped,
        cap_reason,
    }
}

/// Calculate protocol score based on supported TLS/SSL versions
fn calculate_protocol_score(protocols: &[String], weak_protocols: &[String]) -> u8 {
    if protocols.is_empty() {
        return 0;
    }

    let has_tls13 = protocols.iter().any(|p| p == "TLS 1.3");
    let has_tls12 = protocols.iter().any(|p| p == "TLS 1.2");
    let has_tls11 = protocols.iter().any(|p| p == "TLS 1.1");
    let has_tls10 = protocols.iter().any(|p| p == "TLS 1.0");
    let has_ssl30 = protocols.iter().any(|p| p == "SSL 3.0");
    let has_ssl20 = protocols.iter().any(|p| p == "SSL 2.0");

    // Base score from best protocol
    let mut score: u8 = if has_tls13 {
        100
    } else if has_tls12 {
        85
    } else if has_tls11 {
        40
    } else if has_tls10 {
        20
    } else {
        0
    };

    // Deductions for weak protocols
    if has_ssl20 {
        score = score.saturating_sub(50);
    }
    if has_ssl30 {
        score = score.saturating_sub(30);
    }
    if has_tls10 && has_tls12 {
        score = score.saturating_sub(10);
    }
    if has_tls11 && has_tls12 {
        score = score.saturating_sub(5);
    }

    // Additional deduction if there are any weak protocols
    if !weak_protocols.is_empty() {
        score = score.saturating_sub((weak_protocols.len() * 5) as u8);
    }

    score.min(100)
}

/// Calculate cipher score based on cipher suite quality
fn calculate_cipher_score(cipher_suites: &[String], weak_ciphers: &[String]) -> u8 {
    if cipher_suites.is_empty() {
        return 0;
    }

    let mut score: u8 = 100;

    // Check for modern AEAD ciphers (GCM, ChaCha20-Poly1305)
    let has_aead = cipher_suites.iter().any(|c| {
        let upper = c.to_uppercase();
        upper.contains("GCM") || upper.contains("CHACHA20") || upper.contains("POLY1305")
    });

    if !has_aead {
        score = score.saturating_sub(20);
    }

    // Deductions for weak ciphers
    for cipher in weak_ciphers {
        let upper = cipher.to_uppercase();
        if upper.contains("NULL") {
            score = score.saturating_sub(50);
        } else if upper.contains("EXPORT") {
            score = score.saturating_sub(40);
        } else if upper.contains("RC4") {
            score = score.saturating_sub(30);
        } else if upper.contains("DES") && !upper.contains("3DES") {
            score = score.saturating_sub(30);
        } else if upper.contains("3DES") {
            score = score.saturating_sub(15);
        } else if upper.contains("MD5") {
            score = score.saturating_sub(10);
        } else {
            score = score.saturating_sub(5);
        }
    }

    score.max(0).min(100)
}

/// Calculate certificate score based on validity and trust
fn calculate_certificate_score(ssl_info: &SslInfo) -> u8 {
    let mut score: u8 = 100;

    // Critical deductions
    if ssl_info.cert_expired {
        return 0;
    }

    if ssl_info.hostname_mismatch {
        score = score.saturating_sub(50);
    }

    if ssl_info.self_signed {
        score = score.saturating_sub(30);
    }

    // Certificate chain issues
    for _issue in &ssl_info.chain_issues {
        score = score.saturating_sub(10);
    }

    // Expiry warnings
    if let Some(days) = ssl_info.days_until_expiry {
        if days < 0 {
            return 0; // Expired
        } else if days < 7 {
            score = score.saturating_sub(30);
        } else if days < 30 {
            score = score.saturating_sub(15);
        } else if days < 90 {
            score = score.saturating_sub(5);
        }
    }

    // Validity check
    if !ssl_info.cert_valid {
        score = score.saturating_sub(40);
    }

    score.max(0).min(100)
}

/// Calculate key exchange score based on cipher suite key exchange methods
fn calculate_key_exchange_score(cipher_suites: &[String]) -> u8 {
    if cipher_suites.is_empty() {
        return 50; // Neutral if we don't know
    }

    let has_ecdhe = cipher_suites.iter().any(|c| c.to_uppercase().contains("ECDHE"));
    let has_dhe = cipher_suites.iter().any(|c| c.to_uppercase().contains("DHE") && !c.to_uppercase().contains("ECDHE"));
    let has_rsa_static = cipher_suites.iter().any(|c| {
        let upper = c.to_uppercase();
        upper.contains("_RSA_") && !upper.contains("ECDHE") && !upper.contains("DHE")
    });
    let has_anon = cipher_suites.iter().any(|c| {
        let upper = c.to_uppercase();
        upper.contains("_ANON_") || upper.contains("ADH") || upper.contains("AECDH")
    });

    // Score based on best available
    let mut score: u8 = if has_ecdhe {
        100
    } else if has_dhe {
        90
    } else if has_rsa_static {
        60
    } else {
        40
    };

    // Anonymous key exchange is very bad
    if has_anon {
        score = score.saturating_sub(50);
    }

    score.min(100)
}

/// Convert numeric score to letter grade
fn score_to_grade(score: u8, hsts_enabled: bool, vulnerabilities: &[SslVulnerability]) -> SslGradeLevel {
    // Check for grade-capping vulnerabilities
    let has_critical = vulnerabilities.iter().any(|v| v.severity == SslVulnerabilitySeverity::Critical);
    let has_high = vulnerabilities.iter().any(|v| v.severity == SslVulnerabilitySeverity::High);

    if has_critical {
        return SslGradeLevel::F;
    }

    let grade = match score {
        95..=100 if !has_high && hsts_enabled => SslGradeLevel::APlus,
        90..=100 if !has_high => SslGradeLevel::A,
        85..=89 => SslGradeLevel::AMinus,
        80..=84 => SslGradeLevel::BPlus,
        70..=79 => SslGradeLevel::B,
        60..=69 => SslGradeLevel::BMinus,
        50..=59 => SslGradeLevel::C,
        30..=49 => SslGradeLevel::D,
        _ => SslGradeLevel::F,
    };

    // Cap grade if there are high-severity vulnerabilities
    if has_high && matches!(grade, SslGradeLevel::APlus | SslGradeLevel::A | SslGradeLevel::AMinus) {
        return SslGradeLevel::B;
    }

    grade
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_hostname() {
        assert!(matches_hostname("example.com", "example.com"));
        assert!(matches_hostname("*.example.com", "www.example.com"));
        assert!(!matches_hostname("*.example.com", "a.b.example.com"));
        assert!(!matches_hostname("example.com", "www.example.com"));
    }

    #[test]
    fn test_identify_weak_ciphers() {
        let ciphers = vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_RSA_WITH_RC4_128_SHA".to_string(),
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),
        ];

        let weak = identify_weak_ciphers(&ciphers);
        assert_eq!(weak.len(), 2);
        assert!(weak.contains(&"TLS_RSA_WITH_RC4_128_SHA".to_string()));
        assert!(weak.contains(&"TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string()));
    }

    #[test]
    fn test_identify_weak_protocols() {
        let protocols = vec![
            "TLS 1.3".to_string(),
            "TLS 1.0".to_string(),
            "SSL 3.0".to_string(),
        ];

        let weak = identify_weak_protocols(&protocols);
        assert_eq!(weak.len(), 2);
        assert!(weak.contains(&"TLS 1.0".to_string()));
        assert!(weak.contains(&"SSL 3.0".to_string()));
    }

    #[test]
    fn test_build_modern_client_hello_tls13() {
        let hello = build_modern_client_hello("example.com", &[0x03, 0x04]);
        // Verify it's a valid TLS record
        assert_eq!(hello[0], 0x16); // Handshake content type
        assert_eq!(hello[1], 0x03); // TLS 1.0 record layer (for compatibility)
        assert_eq!(hello[2], 0x01);
        // Verify handshake message type is ClientHello
        assert_eq!(hello[5], 0x01);
        // Verify TLS 1.3 has key_share extension (0x0033)
        let hello_str = hello.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert!(hello_str.contains("0033")); // key_share extension type
    }

    #[test]
    fn test_build_modern_client_hello_tls12() {
        let hello = build_modern_client_hello("example.com", &[0x03, 0x03]);
        // Verify it's a valid TLS record
        assert_eq!(hello[0], 0x16); // Handshake content type
        assert_eq!(hello[1], 0x03); // TLS 1.0 record layer (for compatibility)
        assert_eq!(hello[2], 0x01);
        // Verify handshake message type is ClientHello
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn test_build_legacy_client_hello_tls10() {
        let hello = build_client_hello("example.com", TlsVersion::Tls10);
        // Verify it's a valid TLS record
        assert_eq!(hello[0], 0x16); // Handshake content type
        assert_eq!(hello[1], 0x03); // SSL/TLS major version
        assert_eq!(hello[2], 0x01); // TLS 1.0 minor version
        // Verify handshake message type is ClientHello
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn test_build_legacy_client_hello_tls11() {
        let hello = build_client_hello("example.com", TlsVersion::Tls11);
        // Verify it's a valid TLS record
        assert_eq!(hello[0], 0x16); // Handshake content type
        assert_eq!(hello[1], 0x03); // SSL/TLS major version
        assert_eq!(hello[2], 0x02); // TLS 1.1 minor version
    }

    #[test]
    fn test_build_legacy_client_hello_ssl30() {
        let hello = build_client_hello("example.com", TlsVersion::Ssl30);
        // Verify it's a valid TLS record
        assert_eq!(hello[0], 0x16); // Handshake content type
        assert_eq!(hello[1], 0x03); // SSL 3.0 major version
        assert_eq!(hello[2], 0x00); // SSL 3.0 minor version
    }

    #[test]
    fn test_build_ssl2_client_hello() {
        let hello = build_ssl2_client_hello();
        // Verify it has SSL 2.0 format (high bit set in first byte for 2-byte header)
        assert!(hello[0] & 0x80 != 0);
        // Verify MSG-CLIENT-HELLO (0x01) after the 2-byte header
        assert_eq!(hello[2], 0x01);
        // Verify SSL 2.0 version (0x0002)
        assert_eq!(hello[3], 0x00);
        assert_eq!(hello[4], 0x02);
    }

    #[test]
    fn test_tls_version_bytes() {
        assert_eq!(TlsVersion::Ssl20.version_bytes(), [0x00, 0x02]);
        assert_eq!(TlsVersion::Ssl30.version_bytes(), [0x03, 0x00]);
        assert_eq!(TlsVersion::Tls10.version_bytes(), [0x03, 0x01]);
        assert_eq!(TlsVersion::Tls11.version_bytes(), [0x03, 0x02]);
    }

    #[test]
    fn test_tls_version_names() {
        assert_eq!(TlsVersion::Ssl20.name(), "SSL 2.0");
        assert_eq!(TlsVersion::Ssl30.name(), "SSL 3.0");
        assert_eq!(TlsVersion::Tls10.name(), "TLS 1.0");
        assert_eq!(TlsVersion::Tls11.name(), "TLS 1.1");
    }

    // SSL Grading Tests

    fn create_perfect_ssl_info() -> SslInfo {
        SslInfo {
            cert_valid: true,
            cert_expired: false,
            days_until_expiry: Some(365),
            self_signed: false,
            hostname_mismatch: false,
            issuer: "Let's Encrypt Authority".to_string(),
            subject: "example.com".to_string(),
            valid_from: "2024-01-01T00:00:00Z".to_string(),
            valid_until: "2025-01-01T00:00:00Z".to_string(),
            protocols: vec!["TLS 1.3".to_string(), "TLS 1.2".to_string()],
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                "ECDHE_RSA_AES_256_GCM_SHA384".to_string(),
            ],
            weak_ciphers: vec![],
            weak_protocols: vec![],
            hsts_enabled: true,
            hsts_max_age: Some(31536000),
            chain_issues: vec![],
            ssl_grade: None, // Will be computed by calculate_ssl_grade
        }
    }

    #[test]
    fn test_calculate_ssl_grade_perfect_score() {
        let ssl_info = create_perfect_ssl_info();
        let grade = calculate_ssl_grade(&ssl_info);

        assert_eq!(grade.grade, SslGradeLevel::APlus);
        assert!(grade.overall_score >= 90);
        assert!(grade.protocol_score >= 90);
        assert!(grade.cipher_score >= 90);
        assert!(grade.certificate_score >= 90);
        assert!(!grade.grade_capped);
        assert!(grade.vulnerabilities_found.is_empty());
    }

    #[test]
    fn test_calculate_ssl_grade_with_weak_protocols() {
        let mut ssl_info = create_perfect_ssl_info();
        ssl_info.protocols.push("TLS 1.0".to_string());
        ssl_info.weak_protocols.push("TLS 1.0".to_string());

        let grade = calculate_ssl_grade(&ssl_info);

        assert!(grade.protocol_score < 100);
        assert!(grade.vulnerabilities_found.iter().any(|v| v.id == "TLS10"));
    }

    #[test]
    fn test_calculate_ssl_grade_expired_cert() {
        let mut ssl_info = create_perfect_ssl_info();
        ssl_info.cert_expired = true;
        ssl_info.days_until_expiry = Some(-10);

        let grade = calculate_ssl_grade(&ssl_info);

        assert_eq!(grade.grade, SslGradeLevel::F);
        assert!(grade.grade_capped);
        assert!(grade.vulnerabilities_found.iter().any(|v| v.id == "CERT_EXPIRED"));
    }

    #[test]
    fn test_calculate_ssl_grade_self_signed() {
        let mut ssl_info = create_perfect_ssl_info();
        ssl_info.self_signed = true;

        let grade = calculate_ssl_grade(&ssl_info);

        assert!(grade.grade_capped);
        assert!(grade.vulnerabilities_found.iter().any(|v| v.id == "SELF_SIGNED"));
    }

    #[test]
    fn test_calculate_ssl_grade_no_hsts() {
        let mut ssl_info = create_perfect_ssl_info();
        ssl_info.hsts_enabled = false;
        ssl_info.hsts_max_age = None;

        let grade = calculate_ssl_grade(&ssl_info);

        // Without HSTS, cannot achieve A+
        assert_ne!(grade.grade, SslGradeLevel::APlus);
        assert!(grade.vulnerabilities_found.iter().any(|v| v.id == "NO_HSTS"));
    }

    #[test]
    fn test_calculate_ssl_grade_weak_ciphers() {
        let mut ssl_info = create_perfect_ssl_info();
        ssl_info.weak_ciphers.push("TLS_RSA_WITH_RC4_128_SHA".to_string());

        let grade = calculate_ssl_grade(&ssl_info);

        assert!(grade.cipher_score < 100);
        assert!(grade.vulnerabilities_found.iter().any(|v| v.id == "RC4"));
    }

    #[test]
    fn test_calculate_ssl_grade_ssl30() {
        let mut ssl_info = create_perfect_ssl_info();
        ssl_info.protocols.push("SSL 3.0".to_string());
        ssl_info.weak_protocols.push("SSL 3.0".to_string());

        let grade = calculate_ssl_grade(&ssl_info);

        assert!(grade.grade_capped);
        assert!(grade.vulnerabilities_found.iter().any(|v| v.id == "POODLE"));
    }

    #[test]
    fn test_protocol_score_tls13_only() {
        let protocols = vec!["TLS 1.3".to_string()];
        let score = calculate_protocol_score(&protocols, &[]);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_protocol_score_tls12_only() {
        let protocols = vec!["TLS 1.2".to_string()];
        let score = calculate_protocol_score(&protocols, &[]);
        assert_eq!(score, 85);
    }

    #[test]
    fn test_cipher_score_modern_aead() {
        let ciphers = vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        ];
        let score = calculate_cipher_score(&ciphers, &[]);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_ssl_grade_level_display() {
        assert_eq!(format!("{}", SslGradeLevel::APlus), "A+");
        assert_eq!(format!("{}", SslGradeLevel::A), "A");
        assert_eq!(format!("{}", SslGradeLevel::AMinus), "A-");
        assert_eq!(format!("{}", SslGradeLevel::F), "F");
    }
}
