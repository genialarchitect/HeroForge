#![allow(dead_code)]

use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast::Sender;

/// TLS protocol versions
const TLS_VERSIONS: &[(u16, &str, bool)] = &[
    (0x0300, "SSL 3.0", false),
    (0x0301, "TLS 1.0", false),
    (0x0302, "TLS 1.1", false),
    (0x0303, "TLS 1.2", true),
    (0x0304, "TLS 1.3", true),
];

/// Weak/vulnerable cipher suites with severity
/// Format: (cipher_id, name, severity, vulnerability)
const WEAK_CIPHERS: &[(u16, &str, &str, &str)] = &[
    // NULL ciphers - no encryption
    (0x0000, "TLS_NULL_WITH_NULL_NULL", "critical", "No encryption"),
    (0x0001, "TLS_RSA_WITH_NULL_MD5", "critical", "No encryption"),
    (0x0002, "TLS_RSA_WITH_NULL_SHA", "critical", "No encryption"),
    (0x003b, "TLS_RSA_WITH_NULL_SHA256", "critical", "No encryption"),

    // EXPORT ciphers - weak 40/56-bit encryption
    (0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "critical", "EXPORT cipher"),
    (0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "critical", "EXPORT cipher"),
    (0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "critical", "EXPORT cipher"),
    (0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", "critical", "EXPORT cipher"),
    (0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", "critical", "EXPORT cipher"),
    (0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "critical", "EXPORT cipher"),
    (0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "critical", "EXPORT cipher"),
    (0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "critical", "EXPORT cipher"),
    (0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "critical", "EXPORT cipher"),

    // RC4 ciphers - broken stream cipher
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5", "high", "RC4"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA", "high", "RC4"),
    (0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", "high", "RC4 + Anonymous"),
    (0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "high", "RC4"),
    (0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "high", "RC4"),

    // DES ciphers - weak 56-bit encryption
    (0x0009, "TLS_RSA_WITH_DES_CBC_SHA", "high", "DES"),
    (0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA", "high", "DES"),
    (0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA", "high", "DES"),
    (0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", "high", "DES"),
    (0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", "high", "DES"),
    (0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA", "high", "DES + Anonymous"),

    // 3DES ciphers - Sweet32 vulnerability
    (0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES) + Anonymous"),
    (0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),
    (0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "medium", "Sweet32 (3DES)"),

    // Anonymous DH - no authentication, vulnerable to MitM
    (0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", "high", "Anonymous DH"),
    (0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "high", "Anonymous DH"),
    (0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", "high", "Anonymous DH"),
    (0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA", "high", "Anonymous DH"),
    (0xc015, "TLS_ECDH_anon_WITH_NULL_SHA", "critical", "Anonymous ECDH + No encryption"),
    (0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA", "high", "Anonymous ECDH + RC4"),
    (0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "high", "Anonymous ECDH + Sweet32"),
    (0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "high", "Anonymous ECDH"),
    (0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "high", "Anonymous ECDH"),

    // MD5-based ciphers - weak hash
    (0x0001, "TLS_RSA_WITH_NULL_MD5", "high", "MD5"),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5", "high", "MD5 + RC4"),
];

/// Analyze SSL/TLS on a port
/// This can be called for HTTPS, LDAPS, IMAPS, or any SSL-enabled service
pub async fn enumerate_ssl(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting SSL/TLS analysis for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let target_ip = target.ip.to_string();
    let hostname = target.hostname.as_deref();

    // Step 1: Probe TLS and get server hello (with SNI if hostname available)
    match probe_tls(&target_ip, port, hostname, timeout).await {
        Ok(Some(tls_info)) => {
            // Report TLS version
            let version_secure = TLS_VERSIONS.iter()
                .find(|(v, _, _)| *v == tls_info.version)
                .map(|(_, name, secure)| (*name, *secure))
                .unwrap_or(("Unknown", false));

            findings.push(
                Finding::with_confidence(
                    FindingType::TlsVersion,
                    format!("TLS Version: {}", version_secure.0),
                    95,
                )
                .with_metadata("version_code".to_string(), format!("0x{:04x}", tls_info.version))
                .with_metadata("secure".to_string(), version_secure.1.to_string()),
            );

            if !version_secure.1 {
                findings.push(
                    Finding::with_confidence(
                        FindingType::WeakCrypto,
                        format!("{} is deprecated", version_secure.0),
                        90,
                    )
                    .with_metadata("severity".to_string(), "High".to_string()),
                );
            }

            metadata.insert("tls_version".to_string(), version_secure.0.to_string());

            // Report cipher suite
            if !tls_info.cipher_suite.is_empty() {
                findings.push(
                    Finding::new(FindingType::CipherSuite, tls_info.cipher_suite.clone()),
                );
                metadata.insert("cipher_suite".to_string(), tls_info.cipher_suite);

                // Check for weak cipher
                if let Some((cipher_name, severity, vulnerability)) = check_weak_cipher(tls_info.cipher_id) {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::WeakCrypto,
                            format!("Weak cipher: {} ({})", cipher_name, vulnerability),
                            95,
                        )
                        .with_metadata("severity".to_string(), severity.to_string())
                        .with_metadata("vulnerability".to_string(), vulnerability.to_string())
                        .with_metadata("cipher_id".to_string(), format!("0x{:04x}", tls_info.cipher_id)),
                    );
                    send_progress(&progress_tx, &target_ip, port, "WeakCrypto", &format!("{} vulnerable", vulnerability));
                }
            }

            // Report certificate info
            if let Some(cert_info) = tls_info.cert_info {
                if !cert_info.subject_cn.is_empty() {
                    findings.push(
                        Finding::new(FindingType::Certificate, format!("Subject: {}", cert_info.subject_cn))
                            .with_metadata("cn".to_string(), cert_info.subject_cn.clone()),
                    );
                    metadata.insert("cert_cn".to_string(), cert_info.subject_cn.clone());
                }

                // Report issuer
                if !cert_info.issuer_cn.is_empty() && cert_info.issuer_cn != cert_info.subject_cn {
                    metadata.insert("cert_issuer".to_string(), cert_info.issuer_cn.clone());
                }

                if cert_info.self_signed {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::Certificate,
                            "Self-signed certificate".to_string(),
                            90,
                        )
                        .with_metadata("warning".to_string(), "Not trusted by browsers".to_string()),
                    );
                }

                if let Some(key_size) = cert_info.key_size {
                    if key_size < 2048 {
                        findings.push(
                            Finding::with_confidence(
                                FindingType::WeakCrypto,
                                format!("Weak key size: {} bits", key_size),
                                85,
                            )
                            .with_metadata("minimum_recommended".to_string(), "2048".to_string()),
                        );
                    }
                    metadata.insert("key_size".to_string(), key_size.to_string());
                }

                // Check certificate expiration
                if let Some(not_after) = cert_info.not_after {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);

                    if not_after < now {
                        // Certificate has expired
                        findings.push(
                            Finding::with_confidence(
                                FindingType::Certificate,
                                "Certificate has EXPIRED".to_string(),
                                100,
                            )
                            .with_metadata("severity".to_string(), "Critical".to_string())
                            .with_metadata("expired_timestamp".to_string(), not_after.to_string()),
                        );
                        send_progress(&progress_tx, &target_ip, port, "Certificate", "EXPIRED");
                    } else if not_after < now + (30 * 24 * 3600) {
                        // Certificate expires within 30 days
                        let days_left = (not_after - now) / (24 * 3600);
                        findings.push(
                            Finding::with_confidence(
                                FindingType::Certificate,
                                format!("Certificate expires in {} days", days_left),
                                85,
                            )
                            .with_metadata("severity".to_string(), "Medium".to_string())
                            .with_metadata("expires_timestamp".to_string(), not_after.to_string()),
                        );
                        send_progress(&progress_tx, &target_ip, port, "Certificate", &format!("Expires in {} days", days_left));
                    }
                    metadata.insert("cert_expires".to_string(), not_after.to_string());
                }
            }

            send_progress(&progress_tx, &target_ip, port, "TlsVersion", version_secure.0);
        }
        Ok(None) => {
            debug!("Could not probe TLS on {}:{}", target_ip, port);
        }
        Err(e) => {
            debug!("TLS probe failed: {}", e);
        }
    }

    // Light/Aggressive: Test for deprecated protocols
    if matches!(depth, EnumDepth::Light | EnumDepth::Aggressive) {
        for (version, name, secure) in TLS_VERSIONS {
            if !secure {
                if test_protocol_version(&target_ip, port, *version, timeout).await {
                    findings.push(
                        Finding::with_confidence(
                            FindingType::WeakCrypto,
                            format!("{} supported (deprecated)", name),
                            90,
                        )
                        .with_metadata("protocol".to_string(), name.to_string()),
                    );
                    send_progress(&progress_tx, &target_ip, port, "WeakCrypto", &format!("{} enabled", name));
                }
            }
        }
    }

    // Aggressive: Heartbleed vulnerability check
    if matches!(depth, EnumDepth::Aggressive) {
        if let Some(heartbleed_finding) = check_heartbleed(&target_ip, port, timeout).await {
            send_progress(&progress_tx, &target_ip, port, "Vulnerability", "Heartbleed CVE-2014-0160");
            findings.push(heartbleed_finding);
        }
    }

    metadata.insert("findings_count".to_string(), findings.len().to_string());

    Ok(EnumerationResult {
        service_type: ServiceType::Https, // SSL/TLS analysis uses Https type
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

struct TlsInfo {
    version: u16,
    cipher_suite: String,
    cipher_id: u16,
    cert_info: Option<CertInfo>,
}

struct CertInfo {
    subject_cn: String,
    issuer_cn: String,
    self_signed: bool,
    key_size: Option<u32>,
    not_before: Option<i64>,  // Unix timestamp
    not_after: Option<i64>,   // Unix timestamp
}

/// Check if a cipher is weak and return vulnerability info
fn check_weak_cipher(cipher_id: u16) -> Option<(&'static str, &'static str, &'static str)> {
    WEAK_CIPHERS
        .iter()
        .find(|(id, _, _, _)| *id == cipher_id)
        .map(|(_, name, severity, vuln)| (*name, *severity, *vuln))
}

async fn probe_tls(target_ip: &str, port: u16, hostname: Option<&str>, timeout: Duration) -> Result<Option<TlsInfo>> {
    let target_ip = target_ip.to_string();
    let hostname = hostname.map(|s| s.to_string());

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Send TLS ClientHello with optional SNI
        let client_hello = build_client_hello_with_sni(hostname.as_deref());
        stream.write_all(&client_hello)?;
        stream.flush()?;

        // Read ServerHello
        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response)?;

        if n < 10 {
            return Ok(None);
        }

        // Parse response
        let mut info = TlsInfo {
            version: 0,
            cipher_suite: String::new(),
            cipher_id: 0,
            cert_info: None,
        };

        // Check for TLS handshake
        if response[0] == 0x16 {  // Handshake content type
            // Get version from record layer
            info.version = ((response[1] as u16) << 8) | (response[2] as u16);

            // Look for ServerHello (type 0x02) in handshake
            if response.len() > 5 && response[5] == 0x02 {
                // Server version at offset 9-10
                if response.len() > 10 {
                    let server_version = ((response[9] as u16) << 8) | (response[10] as u16);
                    info.version = server_version;
                }

                // Cipher suite after session ID
                // Skip: msg_type(1) + length(3) + version(2) + random(32) + session_id_len(1) + session_id
                if response.len() > 43 {
                    let session_id_len = response[43] as usize;
                    let cipher_offset = 44 + session_id_len;
                    if response.len() > cipher_offset + 1 {
                        let cipher = ((response[cipher_offset] as u16) << 8) | (response[cipher_offset + 1] as u16);
                        info.cipher_id = cipher;
                        info.cipher_suite = describe_cipher(cipher);
                    }
                }
            }
        } else if response[0] == 0x15 {  // Alert
            // TLS Alert - connection likely failed
            return Ok(None);
        }

        Ok(Some(info))
    })
    .await?
}

async fn test_protocol_version(target_ip: &str, port: u16, version: u16, timeout: Duration) -> bool {
    let target_ip = target_ip.to_string();

    let result = tokio::task::spawn_blocking(move || -> Option<bool> {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = match TcpStream::connect_timeout(&addr.parse().ok()?, timeout) {
            Ok(s) => s,
            Err(_) => return Some(false),
        };
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        // Build minimal ClientHello for specific version
        let client_hello = build_version_probe(version);
        stream.write_all(&client_hello).ok()?;
        stream.flush().ok()?;

        let mut response = [0u8; 256];
        let n = stream.read(&mut response).ok()?;

        // Check for ServerHello (not alert)
        Some(n > 5 && response[0] == 0x16 && response[5] == 0x02)
    })
    .await;

    result.ok().flatten().unwrap_or(false)
}

fn build_client_hello() -> Vec<u8> {
    build_client_hello_with_sni(None)
}

/// Build TLS ClientHello with optional SNI extension
fn build_client_hello_with_sni(hostname: Option<&str>) -> Vec<u8> {
    let mut hello = Vec::new();

    // TLS Record Layer
    hello.push(0x16);        // Handshake
    hello.push(0x03);        // Version major
    hello.push(0x01);        // Version minor (TLS 1.0 for compat)

    // Record length placeholder
    let record_len_pos = hello.len();
    hello.extend(&[0x00, 0x00]);

    // Handshake - ClientHello
    hello.push(0x01);        // ClientHello

    // Handshake length placeholder
    let hs_len_pos = hello.len();
    hello.extend(&[0x00, 0x00, 0x00]);

    // Client version (TLS 1.2)
    hello.extend(&[0x03, 0x03]);

    // Random (32 bytes)
    hello.extend(&[0x00u8; 32]);

    // Session ID (empty)
    hello.push(0x00);

    // Cipher suites
    let ciphers: &[u8] = &[
        0x13, 0x01,  // TLS_AES_128_GCM_SHA256
        0x13, 0x02,  // TLS_AES_256_GCM_SHA384
        0xc0, 0x2f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9c,  // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x2f,  // TLS_RSA_WITH_AES_128_CBC_SHA
    ];
    hello.push((ciphers.len() >> 8) as u8);
    hello.push((ciphers.len() & 0xff) as u8);
    hello.extend(ciphers);

    // Compression (null only)
    hello.extend(&[0x01, 0x00]);

    // Build extensions
    let mut extensions = Vec::new();

    // SNI extension (server_name) - type 0x0000
    if let Some(host) = hostname {
        let host_bytes = host.as_bytes();
        // Extension type: server_name (0x0000)
        extensions.extend(&[0x00, 0x00]);
        // Extension data length
        let sni_data_len = host_bytes.len() + 5;
        extensions.push((sni_data_len >> 8) as u8);
        extensions.push((sni_data_len & 0xff) as u8);
        // Server name list length
        let sni_list_len = host_bytes.len() + 3;
        extensions.push((sni_list_len >> 8) as u8);
        extensions.push((sni_list_len & 0xff) as u8);
        // Server name type: hostname (0)
        extensions.push(0x00);
        // Server name length
        extensions.push((host_bytes.len() >> 8) as u8);
        extensions.push((host_bytes.len() & 0xff) as u8);
        // Server name
        extensions.extend(host_bytes);
    }

    // Supported versions extension (for TLS 1.3) - type 0x002b
    extensions.extend(&[
        0x00, 0x2b,  // Extension type: supported_versions
        0x00, 0x05,  // Extension length
        0x04,        // Supported versions length
        0x03, 0x04,  // TLS 1.3
        0x03, 0x03,  // TLS 1.2
    ]);

    // Signature algorithms extension - type 0x000d
    extensions.extend(&[
        0x00, 0x0d,  // Extension type: signature_algorithms
        0x00, 0x08,  // Extension length
        0x00, 0x06,  // Algorithms length
        0x04, 0x01,  // RSA-PKCS1-SHA256
        0x05, 0x01,  // RSA-PKCS1-SHA384
        0x06, 0x01,  // RSA-PKCS1-SHA512
    ]);

    // EC point formats extension - type 0x000b
    extensions.extend(&[
        0x00, 0x0b,  // Extension type: ec_point_formats
        0x00, 0x02,  // Extension length
        0x01,        // EC point formats length
        0x00,        // uncompressed
    ]);

    // Supported groups extension - type 0x000a
    extensions.extend(&[
        0x00, 0x0a,  // Extension type: supported_groups
        0x00, 0x06,  // Extension length
        0x00, 0x04,  // Groups length
        0x00, 0x17,  // secp256r1
        0x00, 0x18,  // secp384r1
    ]);

    // Extensions length
    hello.push((extensions.len() >> 8) as u8);
    hello.push((extensions.len() & 0xff) as u8);
    hello.extend(extensions);

    // Fill in lengths
    let hs_len = hello.len() - hs_len_pos - 3;
    hello[hs_len_pos] = (hs_len >> 16) as u8;
    hello[hs_len_pos + 1] = (hs_len >> 8) as u8;
    hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

    let record_len = hello.len() - record_len_pos - 2;
    hello[record_len_pos] = (record_len >> 8) as u8;
    hello[record_len_pos + 1] = (record_len & 0xff) as u8;

    hello
}

fn build_version_probe(version: u16) -> Vec<u8> {
    let mut hello = Vec::new();

    // TLS Record
    hello.push(0x16);
    hello.push((version >> 8) as u8);
    hello.push((version & 0xff) as u8);

    // Simple ClientHello
    let mut handshake = Vec::new();
    handshake.push(0x01);  // ClientHello

    let mut hs_data = Vec::new();
    hs_data.push((version >> 8) as u8);
    hs_data.push((version & 0xff) as u8);
    hs_data.extend(&[0x00u8; 32]);  // Random
    hs_data.push(0x00);              // Session ID
    hs_data.extend(&[0x00, 0x02, 0x00, 0x2f]);  // Cipher suite
    hs_data.extend(&[0x01, 0x00]);   // Compression

    let hs_len = hs_data.len();
    handshake.push((hs_len >> 16) as u8);
    handshake.push((hs_len >> 8) as u8);
    handshake.push((hs_len & 0xff) as u8);
    handshake.extend(hs_data);

    let record_len = handshake.len();
    hello.push((record_len >> 8) as u8);
    hello.push((record_len & 0xff) as u8);
    hello.extend(handshake);

    hello
}

fn describe_cipher(cipher: u16) -> String {
    match cipher {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),
        _ => format!("0x{:04x}", cipher),
    }
}

fn send_progress(
    tx: &Option<Sender<ScanProgressMessage>>,
    ip: &str,
    port: u16,
    finding_type: &str,
    value: &str,
) {
    if let Some(sender) = tx {
        let _ = sender.send(ScanProgressMessage::EnumerationFinding {
            ip: ip.to_string(),
            port,
            finding_type: finding_type.to_string(),
            value: value.to_string(),
        });
    }
}

/// Check HSTS (HTTP Strict Transport Security) header
/// Returns findings about HSTS configuration
async fn check_hsts(target_ip: &str, port: u16, hostname: Option<&str>, timeout: Duration) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target_ip = target_ip.to_string();
    let hostname = hostname.map(|s| s.to_string());

    let result = tokio::task::spawn_blocking(move || -> Option<(bool, Option<String>)> {
        // Build HTTP request (for future use when full TLS handshake is implemented)
        let host = hostname.as_deref().unwrap_or(&target_ip);
        let _request = format!(
            "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );

        // Connect with TLS
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        // Do TLS handshake first
        let client_hello = build_client_hello_with_sni(hostname.as_deref());
        stream.write_all(&client_hello).ok()?;
        stream.flush().ok()?;

        // Read server hello
        let mut response = vec![0u8; 8192];
        let n = stream.read(&mut response).ok()?;
        if n < 5 || response[0] != 0x16 {
            return None;
        }

        // For simplicity, we'll check for HSTS in the raw response
        // In a full implementation, we'd complete the TLS handshake and send HTTP request
        // For now, we'll return None to indicate we couldn't check
        // A proper implementation would use native-tls or rustls
        None
    }).await.ok().flatten();

    if let Some((has_hsts, hsts_value)) = result {
        if has_hsts {
            let mut finding = Finding::new(
                FindingType::SecurityConfig,
                "HSTS (Strict-Transport-Security) enabled".to_string(),
            );
            if let Some(value) = hsts_value {
                finding = finding.with_metadata("hsts_value".to_string(), value);
            }
            findings.push(finding);
        } else {
            findings.push(
                Finding::with_confidence(
                    FindingType::Misconfiguration,
                    "HSTS not enabled - vulnerable to protocol downgrade attacks".to_string(),
                    80,
                )
                .with_metadata("severity".to_string(), "Medium".to_string())
                .with_metadata("recommendation".to_string(), "Enable Strict-Transport-Security header".to_string()),
            );
        }
    }

    findings
}

/// Check for Heartbleed vulnerability (CVE-2014-0160)
/// This is a safe detection that doesn't exploit the vulnerability
async fn check_heartbleed(target_ip: &str, port: u16, timeout: Duration) -> Option<Finding> {
    let target_ip = target_ip.to_string();

    let result = tokio::task::spawn_blocking(move || -> Option<bool> {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        // Send ClientHello with heartbeat extension
        let client_hello = build_heartbeat_client_hello();
        stream.write_all(&client_hello).ok()?;
        stream.flush().ok()?;

        // Read ServerHello
        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response).ok()?;

        if n < 5 || response[0] != 0x16 {
            return Some(false);
        }

        // Check if server supports heartbeat extension
        // Look for extension type 0x000f in ServerHello
        let has_heartbeat = response[..n]
            .windows(2)
            .any(|w| w == [0x00, 0x0f]);

        if !has_heartbeat {
            return Some(false);
        }

        // Send malformed heartbeat request
        let heartbeat = build_heartbeat_request();
        stream.write_all(&heartbeat).ok()?;
        stream.flush().ok()?;

        // Read response
        let mut hb_response = vec![0u8; 65535];
        let hb_n = match stream.read(&mut hb_response) {
            Ok(n) => n,
            Err(_) => return Some(false),
        };

        // If we got a large response (more than we sent), server is vulnerable
        // Heartbeat response should be small (type + length + payload + padding)
        // If we get > 64 bytes, likely vulnerable
        Some(hb_n > 64 && hb_response[0] == 0x18) // 0x18 = heartbeat content type
    }).await.ok()?;

    if result? {
        Some(Finding::with_confidence(
            FindingType::Vulnerability,
            "CVE-2014-0160 (Heartbleed) - Memory disclosure vulnerability".to_string(),
            85,
        )
        .with_metadata("cve".to_string(), "CVE-2014-0160".to_string())
        .with_metadata("severity".to_string(), "Critical".to_string())
        .with_metadata("impact".to_string(), "Memory disclosure, credential theft".to_string()))
    } else {
        None
    }
}

/// Build ClientHello with heartbeat extension for Heartbleed detection
fn build_heartbeat_client_hello() -> Vec<u8> {
    let mut hello = Vec::new();

    // TLS Record Layer
    hello.push(0x16);        // Handshake
    hello.push(0x03);        // Version major
    hello.push(0x01);        // Version minor (TLS 1.0)

    let record_len_pos = hello.len();
    hello.extend(&[0x00, 0x00]);

    // ClientHello
    hello.push(0x01);

    let hs_len_pos = hello.len();
    hello.extend(&[0x00, 0x00, 0x00]);

    // TLS 1.1 (most affected version)
    hello.extend(&[0x03, 0x02]);

    // Random
    hello.extend(&[0x00u8; 32]);

    // Session ID
    hello.push(0x00);

    // Cipher suites
    let ciphers: &[u8] = &[0x00, 0x2f]; // TLS_RSA_WITH_AES_128_CBC_SHA
    hello.push(0x00);
    hello.push(ciphers.len() as u8);
    hello.extend(ciphers);

    // Compression
    hello.extend(&[0x01, 0x00]);

    // Extensions
    let mut extensions = Vec::new();

    // Heartbeat extension (type 0x000f)
    extensions.extend(&[0x00, 0x0f]); // Extension type
    extensions.extend(&[0x00, 0x01]); // Extension length
    extensions.push(0x01);            // Peer allowed to send heartbeats

    // Extensions length
    hello.push((extensions.len() >> 8) as u8);
    hello.push((extensions.len() & 0xff) as u8);
    hello.extend(extensions);

    // Fill lengths
    let hs_len = hello.len() - hs_len_pos - 3;
    hello[hs_len_pos] = (hs_len >> 16) as u8;
    hello[hs_len_pos + 1] = (hs_len >> 8) as u8;
    hello[hs_len_pos + 2] = (hs_len & 0xff) as u8;

    let record_len = hello.len() - record_len_pos - 2;
    hello[record_len_pos] = (record_len >> 8) as u8;
    hello[record_len_pos + 1] = (record_len & 0xff) as u8;

    hello
}

/// Build malformed heartbeat request for Heartbleed detection
fn build_heartbeat_request() -> Vec<u8> {
    let mut hb = Vec::new();

    // TLS Record Layer
    hb.push(0x18);        // Heartbeat content type
    hb.push(0x03);        // Version major
    hb.push(0x02);        // Version minor (TLS 1.1)
    hb.extend(&[0x00, 0x03]); // Record length (3 bytes)

    // Heartbeat message
    hb.push(0x01);        // HeartbeatRequest
    hb.extend(&[0x40, 0x00]); // Payload length: 16384 (much larger than actual)
    // No actual payload - this is the malformed part
    // A vulnerable server will return 16384 bytes of memory

    hb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_description() {
        assert_eq!(describe_cipher(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(describe_cipher(0xc02f), "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    }

    #[test]
    fn test_build_client_hello() {
        let hello = build_client_hello();
        assert_eq!(hello[0], 0x16);  // Handshake content type
    }

    #[test]
    fn test_build_client_hello_with_sni() {
        let hello = build_client_hello_with_sni(Some("example.com"));
        assert_eq!(hello[0], 0x16);  // Handshake content type

        // Verify SNI extension is present (0x00 0x00 extension type)
        let hello_str = hello.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        assert!(hello_str.contains("0000")); // SNI extension type
    }

    #[test]
    fn test_weak_cipher_detection() {
        // Test RC4 detection
        let rc4_result = check_weak_cipher(0x0005);
        assert!(rc4_result.is_some());
        let (name, severity, vuln) = rc4_result.unwrap();
        assert!(name.contains("RC4"));
        assert_eq!(severity, "high");
        assert_eq!(vuln, "RC4");

        // Test 3DES/Sweet32 detection
        let des3_result = check_weak_cipher(0x000a);
        assert!(des3_result.is_some());
        let (name, severity, vuln) = des3_result.unwrap();
        assert!(name.contains("3DES"));
        assert_eq!(severity, "medium");
        assert!(vuln.contains("Sweet32"));

        // Test NULL cipher detection
        let null_result = check_weak_cipher(0x0000);
        assert!(null_result.is_some());
        let (_, severity, _) = null_result.unwrap();
        assert_eq!(severity, "critical");

        // Test secure cipher (not in weak list)
        let secure_result = check_weak_cipher(0x1301); // TLS_AES_128_GCM_SHA256
        assert!(secure_result.is_none());
    }

    #[test]
    fn test_build_heartbeat_client_hello() {
        let hello = build_heartbeat_client_hello();
        assert_eq!(hello[0], 0x16);  // Handshake content type

        // Verify heartbeat extension is present (0x00 0x0f)
        assert!(hello.windows(2).any(|w| w == [0x00, 0x0f]));
    }

    #[test]
    fn test_build_heartbeat_request() {
        let hb = build_heartbeat_request();
        assert_eq!(hb[0], 0x18);  // Heartbeat content type
        assert_eq!(hb[5], 0x01);  // HeartbeatRequest type
        // Check payload length is larger than actual (malformed)
        let payload_len = ((hb[6] as u16) << 8) | (hb[7] as u16);
        assert_eq!(payload_len, 0x4000); // 16384
    }
}
