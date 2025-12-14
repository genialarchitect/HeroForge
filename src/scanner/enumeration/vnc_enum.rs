//! VNC Service Enumeration Module
//!
//! Performs protocol-level analysis of VNC (Virtual Network Computing) services including:
//! - Version detection (RFB protocol version)
//! - Authentication type detection
//! - Security type enumeration
//! - Banner analysis

use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

// VNC Security Types
const VNC_SECURITY_INVALID: u8 = 0;
const VNC_SECURITY_NONE: u8 = 1;
const VNC_SECURITY_VNC_AUTH: u8 = 2;
const VNC_SECURITY_RA2: u8 = 5;
const VNC_SECURITY_RA2NE: u8 = 6;
const VNC_SECURITY_TIGHT: u8 = 16;
const VNC_SECURITY_ULTRA: u8 = 17;
const VNC_SECURITY_TLS: u8 = 18;
const VNC_SECURITY_VENCRYPT: u8 = 19;
const VNC_SECURITY_SASL: u8 = 20;
const VNC_SECURITY_ARD: u8 = 30; // Apple Remote Desktop
const VNC_SECURITY_MS_LOGON: u8 = 0x80; // UltraVNC MS-Logon

/// VNC server information
#[derive(Debug, Clone)]
struct VncInfo {
    protocol_version: String,
    major_version: u8,
    minor_version: u8,
    security_types: Vec<u8>,
    #[allow(dead_code)]
    server_name: Option<String>,
}

impl VncInfo {
    fn security_types_str(&self) -> String {
        self.security_types
            .iter()
            .map(|&t| security_type_name(t))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn has_no_auth(&self) -> bool {
        self.security_types.contains(&VNC_SECURITY_NONE)
    }

    fn has_weak_auth(&self) -> bool {
        // VNC authentication is weak (DES-based, limited to 8 chars)
        self.security_types.contains(&VNC_SECURITY_VNC_AUTH)
    }
}

fn security_type_name(security_type: u8) -> &'static str {
    match security_type {
        VNC_SECURITY_INVALID => "Invalid",
        VNC_SECURITY_NONE => "None (No Authentication)",
        VNC_SECURITY_VNC_AUTH => "VNC Authentication",
        VNC_SECURITY_RA2 => "RA2",
        VNC_SECURITY_RA2NE => "RA2ne",
        VNC_SECURITY_TIGHT => "Tight",
        VNC_SECURITY_ULTRA => "Ultra",
        VNC_SECURITY_TLS => "TLS",
        VNC_SECURITY_VENCRYPT => "VeNCrypt",
        VNC_SECURITY_SASL => "SASL",
        VNC_SECURITY_ARD => "Apple Remote Desktop",
        VNC_SECURITY_MS_LOGON => "UltraVNC MS-Logon",
        _ => "Unknown",
    }
}

/// Main enumeration entry point for VNC services
pub async fn enumerate_vnc(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting VNC enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let target_ip = target.ip.to_string();

    // Step 1: Perform VNC handshake and get server info
    match probe_vnc(&target_ip, port, timeout).await {
        Ok(Some(vnc_info)) => {
            // Report protocol version
            findings.push(
                Finding::new(
                    FindingType::Version,
                    format!("VNC Protocol: RFB {}", vnc_info.protocol_version),
                )
                .with_metadata("protocol".to_string(), "RFB".to_string())
                .with_metadata("version".to_string(), vnc_info.protocol_version.clone()),
            );
            metadata.insert("vnc_version".to_string(), vnc_info.protocol_version.clone());

            send_progress(&progress_tx, &target_ip, port, "Version", &format!("RFB {}", vnc_info.protocol_version));

            // Report security types
            if !vnc_info.security_types.is_empty() {
                findings.push(
                    Finding::new(
                        FindingType::SecurityConfig,
                        format!("Security types: {}", vnc_info.security_types_str()),
                    )
                    .with_metadata("security_types".to_string(), vnc_info.security_types_str()),
                );
                metadata.insert("security_types".to_string(), vnc_info.security_types_str());

                send_progress(&progress_tx, &target_ip, port, "SecurityConfig", &vnc_info.security_types_str());
            }

            // Check for no authentication
            if vnc_info.has_no_auth() {
                findings.push(
                    Finding::with_confidence(
                        FindingType::Misconfiguration,
                        "VNC server allows connections without authentication".to_string(),
                        95,
                    )
                    .with_metadata("severity".to_string(), "Critical".to_string())
                    .with_metadata("recommendation".to_string(), "Enable VNC authentication or use SSH tunneling".to_string()),
                );
                metadata.insert("no_auth".to_string(), "true".to_string());

                send_progress(&progress_tx, &target_ip, port, "Misconfiguration", "No authentication required");
            }

            // Check for weak VNC authentication
            if vnc_info.has_weak_auth() && depth != EnumDepth::Passive {
                findings.push(
                    Finding::with_confidence(
                        FindingType::WeakCrypto,
                        "VNC Authentication uses weak DES encryption (8-char password limit)".to_string(),
                        85,
                    )
                    .with_metadata("severity".to_string(), "Medium".to_string())
                    .with_metadata("recommendation".to_string(), "Use VeNCrypt or SSH tunneling for stronger security".to_string()),
                );

                send_progress(&progress_tx, &target_ip, port, "WeakCrypto", "Weak VNC authentication");
            }

            // Check for secure options
            let has_secure = vnc_info.security_types.iter().any(|&t|
                t == VNC_SECURITY_TLS || t == VNC_SECURITY_VENCRYPT || t == VNC_SECURITY_SASL
            );
            if has_secure {
                findings.push(
                    Finding::new(
                        FindingType::SecurityConfig,
                        "Secure authentication options available (TLS/VeNCrypt/SASL)".to_string(),
                    )
                    .with_metadata("secure".to_string(), "true".to_string()),
                );
            }

            // For aggressive depth, try to get more info
            if depth == EnumDepth::Aggressive {
                // Check for known VNC vulnerabilities based on version
                check_vnc_vulnerabilities(&vnc_info, &mut findings, &progress_tx, &target_ip, port);
            }
        }
        Ok(None) => {
            debug!("No VNC info retrieved from {}:{}", target_ip, port);
        }
        Err(e) => {
            debug!("VNC probe failed for {}:{}: {}", target_ip, port, e);
        }
    }

    Ok(EnumerationResult {
        service_type: ServiceType::Http, // Will be changed when we add Vnc type
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// Probe VNC server for version and security information
async fn probe_vnc(
    target_ip: &str,
    port: u16,
    timeout: Duration,
) -> Result<Option<VncInfo>> {
    let addr = format!("{}:{}", target_ip, port);

    // Connect with timeout
    let mut stream = match TcpStream::connect_timeout(
        &addr.parse().map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?,
        timeout,
    ) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to connect to VNC at {}: {}", addr, e);
            return Ok(None);
        }
    };

    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Step 1: Read server version (ProtocolVersion)
    // Format: "RFB XXX.YYY\n" (12 bytes)
    let mut version_buf = [0u8; 12];
    match stream.read_exact(&mut version_buf) {
        Ok(_) => {}
        Err(e) => {
            debug!("Failed to read VNC version: {}", e);
            return Ok(None);
        }
    }

    let version_str = String::from_utf8_lossy(&version_buf);
    debug!("VNC server version: {}", version_str.trim());

    // Parse version (RFB XXX.YYY)
    let (major, minor) = parse_rfb_version(&version_str)?;

    // Step 2: Send client version (we'll match server version up to 3.8)
    let client_version = if major >= 3 && minor >= 8 {
        "RFB 003.008\n"
    } else if major >= 3 && minor >= 7 {
        "RFB 003.007\n"
    } else {
        "RFB 003.003\n"
    };
    stream.write_all(client_version.as_bytes())?;

    // Step 3: Read security types
    let security_types = if major >= 3 && minor >= 7 {
        // RFB 3.7+: Server sends list of security types
        read_security_types_37(&mut stream)?
    } else {
        // RFB 3.3: Server sends single 4-byte security type
        read_security_type_33(&mut stream)?
    };

    let version_display = format!("{}.{}", major, minor);

    Ok(Some(VncInfo {
        protocol_version: version_display,
        major_version: major,
        minor_version: minor,
        security_types,
        server_name: None,
    }))
}

fn parse_rfb_version(version_str: &str) -> Result<(u8, u8)> {
    // Format: "RFB XXX.YYY\n"
    let trimmed = version_str.trim();
    if !trimmed.starts_with("RFB ") {
        return Err(anyhow::anyhow!("Invalid RFB version string: {}", trimmed));
    }

    let version_part = &trimmed[4..];
    let parts: Vec<&str> = version_part.split('.').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid RFB version format: {}", version_part));
    }

    let major: u8 = parts[0].parse().unwrap_or(3);
    let minor: u8 = parts[1].parse().unwrap_or(3);

    Ok((major, minor))
}

fn read_security_types_37(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // RFB 3.7+: Server sends number of security types, then the types
    let mut count_buf = [0u8; 1];
    stream.read_exact(&mut count_buf)?;
    let count = count_buf[0] as usize;

    if count == 0 {
        // Server sends failure reason
        let mut reason_len_buf = [0u8; 4];
        if stream.read_exact(&mut reason_len_buf).is_ok() {
            let reason_len = u32::from_be_bytes(reason_len_buf) as usize;
            let mut reason_buf = vec![0u8; reason_len.min(1024)];
            let _ = stream.read_exact(&mut reason_buf);
            debug!("VNC connection refused: {}", String::from_utf8_lossy(&reason_buf));
        }
        return Ok(vec![VNC_SECURITY_INVALID]);
    }

    let mut types = vec![0u8; count];
    stream.read_exact(&mut types)?;

    Ok(types)
}

fn read_security_type_33(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // RFB 3.3: Server sends single 4-byte security type
    let mut type_buf = [0u8; 4];
    stream.read_exact(&mut type_buf)?;
    let security_type = u32::from_be_bytes(type_buf);

    if security_type == 0 {
        // Connection failed
        return Ok(vec![VNC_SECURITY_INVALID]);
    }

    Ok(vec![security_type as u8])
}

fn check_vnc_vulnerabilities(
    vnc_info: &VncInfo,
    findings: &mut Vec<Finding>,
    progress_tx: &Option<Sender<ScanProgressMessage>>,
    target_ip: &str,
    port: u16,
) {
    // Check for known vulnerabilities based on version

    // RealVNC < 4.1.1 - CVE-2006-2369: Authentication bypass
    if vnc_info.major_version == 3 && vnc_info.minor_version <= 3 {
        findings.push(
            Finding::with_confidence(
                FindingType::Vulnerability,
                "Potentially vulnerable to VNC authentication bypass (RFB 3.3)".to_string(),
                60,
            )
            .with_metadata("cve".to_string(), "CVE-2006-2369".to_string())
            .with_metadata("severity".to_string(), "High".to_string()),
        );

        send_progress(progress_tx, target_ip, port, "Vulnerability", "Potential auth bypass (CVE-2006-2369)");
    }

    // UltraVNC < 1.0.5.4 - Buffer overflow vulnerabilities
    if vnc_info.security_types.contains(&VNC_SECURITY_MS_LOGON) {
        findings.push(
            Finding::with_confidence(
                FindingType::InformationDisclosure,
                "UltraVNC MS-Logon detected - check for latest security patches".to_string(),
                70,
            )
            .with_metadata("vendor".to_string(), "UltraVNC".to_string()),
        );
    }

    // Apple Remote Desktop
    if vnc_info.security_types.contains(&VNC_SECURITY_ARD) {
        findings.push(
            Finding::new(
                FindingType::InformationDisclosure,
                "Apple Remote Desktop (ARD) VNC variant detected".to_string(),
            )
            .with_metadata("vendor".to_string(), "Apple".to_string()),
        );
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
    fn test_parse_rfb_version() {
        assert_eq!(parse_rfb_version("RFB 003.008\n").unwrap(), (3, 8));
        assert_eq!(parse_rfb_version("RFB 003.007\n").unwrap(), (3, 7));
        assert_eq!(parse_rfb_version("RFB 003.003\n").unwrap(), (3, 3));
        assert_eq!(parse_rfb_version("RFB 004.001\n").unwrap(), (4, 1));
    }

    #[test]
    fn test_security_type_name() {
        assert_eq!(security_type_name(VNC_SECURITY_NONE), "None (No Authentication)");
        assert_eq!(security_type_name(VNC_SECURITY_VNC_AUTH), "VNC Authentication");
        assert_eq!(security_type_name(VNC_SECURITY_TLS), "TLS");
    }

    #[test]
    fn test_vnc_info_security_checks() {
        let vnc_info = VncInfo {
            protocol_version: "3.8".to_string(),
            major_version: 3,
            minor_version: 8,
            security_types: vec![VNC_SECURITY_NONE, VNC_SECURITY_VNC_AUTH],
            server_name: None,
        };

        assert!(vnc_info.has_no_auth());
        assert!(vnc_info.has_weak_auth());
    }
}
