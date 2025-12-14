#![allow(dead_code)]

use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

/// TLS protocol versions
const TLS_VERSIONS: &[(u16, &str, bool)] = &[
    (0x0300, "SSL 3.0", false),
    (0x0301, "TLS 1.0", false),
    (0x0302, "TLS 1.1", false),
    (0x0303, "TLS 1.2", true),
    (0x0304, "TLS 1.3", true),
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

    // Step 1: Probe TLS and get server hello
    match probe_tls(&target_ip, port, timeout).await {
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
            }

            // Report certificate info
            if let Some(cert_info) = tls_info.cert_info {
                if !cert_info.subject_cn.is_empty() {
                    findings.push(
                        Finding::new(FindingType::Certificate, format!("Subject: {}", cert_info.subject_cn))
                            .with_metadata("cn".to_string(), cert_info.subject_cn.clone()),
                    );
                    metadata.insert("cert_cn".to_string(), cert_info.subject_cn);
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
    cert_info: Option<CertInfo>,
}

struct CertInfo {
    subject_cn: String,
    self_signed: bool,
    key_size: Option<u32>,
}

async fn probe_tls(target_ip: &str, port: u16, timeout: Duration) -> Result<Option<TlsInfo>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Send TLS ClientHello
        let client_hello = build_client_hello();
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

    // Extensions length (minimal)
    hello.extend(&[0x00, 0x00]);

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
}
