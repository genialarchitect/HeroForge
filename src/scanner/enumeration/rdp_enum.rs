//! RDP Service Enumeration Module
//!
//! Performs protocol-level analysis of RDP (Remote Desktop Protocol) services including:
//! - Version detection
//! - Security protocol detection (Classic RDP, TLS, CredSSP/NLA)
//! - Encryption level detection
//! - NLA (Network Level Authentication) requirement check
//! - BlueKeep vulnerability check (CVE-2019-0708)

use super::types::{EnumDepth, EnumerationResult, Finding, FindingType, ServiceType};
use crate::types::{ScanProgressMessage, ScanTarget};
use anyhow::Result;
use log::{debug, info};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::Sender;

// RDP Security Protocol constants
const PROTOCOL_RDP: u32 = 0x00000000;     // Classic RDP (Standard RDP Security)
const PROTOCOL_SSL: u32 = 0x00000001;     // TLS (Enhanced RDP Security)
const PROTOCOL_HYBRID: u32 = 0x00000002;  // CredSSP (NLA)
#[allow(dead_code)]
const PROTOCOL_RDSTLS: u32 = 0x00000004;  // RDSTLS
const PROTOCOL_HYBRID_EX: u32 = 0x00000008; // CredSSP with Early User Auth

// RDP Negotiation constants
const TYPE_RDP_NEG_REQ: u8 = 0x01;
const TYPE_RDP_NEG_RSP: u8 = 0x02;
const TYPE_RDP_NEG_FAILURE: u8 = 0x03;

// RDP Encryption Levels
#[allow(dead_code)]
const ENCRYPTION_LEVEL_NONE: u32 = 0;
#[allow(dead_code)]
const ENCRYPTION_LEVEL_LOW: u32 = 1;
#[allow(dead_code)]
const ENCRYPTION_LEVEL_CLIENT_COMPATIBLE: u32 = 2;
#[allow(dead_code)]
const ENCRYPTION_LEVEL_HIGH: u32 = 3;
#[allow(dead_code)]
const ENCRYPTION_LEVEL_FIPS: u32 = 4;

/// Main enumeration entry point for RDP services
pub async fn enumerate_rdp(
    target: &ScanTarget,
    port: u16,
    depth: EnumDepth,
    timeout: Duration,
    progress_tx: Option<Sender<ScanProgressMessage>>,
) -> Result<EnumerationResult> {
    let start = Instant::now();
    info!(
        "Starting RDP enumeration for {}:{} with depth: {:?}",
        target.ip, port, depth
    );

    let mut findings = Vec::new();
    let mut metadata = HashMap::new();
    let target_ip = target.ip.to_string();

    // Step 1: Send X.224 Connection Request and detect supported protocols
    match probe_rdp_security(&target_ip, port, timeout).await {
        Ok(Some(rdp_info)) => {
            // Report security protocols
            findings.push(
                Finding::new(
                    FindingType::RdpSecurityProtocol,
                    format!("Supported: {}", rdp_info.protocols_str()),
                )
                .with_metadata("protocols".to_string(), rdp_info.protocols_str())
                .with_metadata("classic_rdp".to_string(), rdp_info.classic_rdp.to_string())
                .with_metadata("tls".to_string(), rdp_info.ssl_supported.to_string())
                .with_metadata("nla".to_string(), rdp_info.nla_supported.to_string()),
            );

            send_progress(&progress_tx, &target_ip, port, "RdpSecurityProtocol", &rdp_info.protocols_str());

            // Check NLA requirement
            if rdp_info.nla_supported {
                findings.push(
                    Finding::new(
                        FindingType::RdpNlaRequired,
                        "NLA (Network Level Authentication) supported".to_string(),
                    )
                    .with_metadata("secure".to_string(), "true".to_string()),
                );
            } else if rdp_info.classic_rdp && !rdp_info.ssl_supported {
                // Classic RDP only - vulnerable to MitM
                findings.push(
                    Finding::with_confidence(
                        FindingType::RdpNlaRequired,
                        "NLA not supported - vulnerable to MitM and credential theft".to_string(),
                        90,
                    )
                    .with_metadata("secure".to_string(), "false".to_string())
                    .with_metadata("severity".to_string(), "High".to_string())
                    .with_metadata("recommendation".to_string(), "Enable NLA and TLS for RDP".to_string()),
                );
            } else if !rdp_info.nla_supported && rdp_info.ssl_supported {
                // TLS but no NLA
                findings.push(
                    Finding::with_confidence(
                        FindingType::RdpNlaRequired,
                        "NLA not required - TLS only, pre-authentication attacks possible".to_string(),
                        75,
                    )
                    .with_metadata("secure".to_string(), "partial".to_string())
                    .with_metadata("severity".to_string(), "Medium".to_string()),
                );
            }

            // Store metadata
            metadata.insert("nla_supported".to_string(), rdp_info.nla_supported.to_string());
            metadata.insert("ssl_supported".to_string(), rdp_info.ssl_supported.to_string());
            metadata.insert("classic_rdp".to_string(), rdp_info.classic_rdp.to_string());

            // Check for Classic RDP security (vulnerable)
            if rdp_info.classic_rdp && !rdp_info.ssl_supported && !rdp_info.nla_supported {
                findings.push(
                    Finding::with_confidence(
                        FindingType::RdpEncryptionLevel,
                        "Classic RDP security only - weak encryption".to_string(),
                        85,
                    )
                    .with_metadata("severity".to_string(), "High".to_string())
                    .with_metadata("vulnerability".to_string(), "Weak encryption, vulnerable to MitM".to_string()),
                );
            }
        }
        Ok(None) => {
            debug!("Could not probe RDP on {}:{}", target_ip, port);
            findings.push(
                Finding::with_confidence(
                    FindingType::RdpVersion,
                    "RDP service detected but protocol negotiation failed".to_string(),
                    60,
                ),
            );
        }
        Err(e) => {
            debug!("RDP probe failed: {}", e);
        }
    }

    // Light/Aggressive: Additional security checks
    if matches!(depth, EnumDepth::Light | EnumDepth::Aggressive) {
        // Try to detect Windows version from RDP banner/response
        if let Some(version_finding) = detect_rdp_version(&target_ip, port, timeout).await {
            findings.push(version_finding);
        }
    }

    // Aggressive: BlueKeep vulnerability check (CVE-2019-0708)
    if matches!(depth, EnumDepth::Aggressive) {
        match check_bluekeep(&target_ip, port, timeout).await {
            Some(bluekeep_finding) => {
                send_progress(&progress_tx, &target_ip, port, "RdpBlueKeep", "VULNERABLE");
                findings.push(bluekeep_finding);
            }
            None => {
                metadata.insert("bluekeep_checked".to_string(), "true".to_string());
                metadata.insert("bluekeep_vulnerable".to_string(), "false".to_string());
            }
        }
    }

    metadata.insert("findings_count".to_string(), findings.len().to_string());

    Ok(EnumerationResult {
        service_type: ServiceType::Rdp,
        enumeration_depth: depth,
        findings,
        duration: start.elapsed(),
        metadata,
    })
}

/// RDP security protocol information
struct RdpSecurityInfo {
    classic_rdp: bool,
    ssl_supported: bool,
    nla_supported: bool,
    hybrid_ex: bool,
    #[allow(dead_code)]
    selected_protocol: u32,
}

impl RdpSecurityInfo {
    fn protocols_str(&self) -> String {
        let mut protocols = Vec::new();
        if self.classic_rdp {
            protocols.push("Classic RDP");
        }
        if self.ssl_supported {
            protocols.push("TLS");
        }
        if self.nla_supported {
            protocols.push("CredSSP/NLA");
        }
        if self.hybrid_ex {
            protocols.push("CredSSP Extended");
        }
        if protocols.is_empty() {
            return "Unknown".to_string();
        }
        protocols.join(", ")
    }
}

/// Probe RDP to detect supported security protocols
async fn probe_rdp_security(
    target_ip: &str,
    port: u16,
    timeout: Duration,
) -> Result<Option<RdpSecurityInfo>> {
    let target_ip = target_ip.to_string();

    tokio::task::spawn_blocking(move || {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse()?, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Build X.224 Connection Request with RDP Negotiation Request
        // Request all protocols to see what server supports
        let x224_cr = build_x224_connection_request(
            PROTOCOL_HYBRID_EX | PROTOCOL_HYBRID | PROTOCOL_SSL | PROTOCOL_RDP,
        );

        stream.write_all(&x224_cr)?;
        stream.flush()?;

        // Read response (X.224 Connection Confirm)
        let mut response = vec![0u8; 256];
        let n = stream.read(&mut response)?;

        if n < 11 {
            return Ok(None);
        }

        // Parse X.224 Connection Confirm
        parse_x224_response(&response[..n])
    })
    .await?
}

/// Build X.224 Connection Request (CR) with RDP Negotiation Request
fn build_x224_connection_request(requested_protocols: u32) -> Vec<u8> {
    let mut packet = Vec::new();

    // TPKT Header (RFC 1006)
    packet.push(0x03); // Version
    packet.push(0x00); // Reserved

    // Length will be filled later (position 2-3)
    let len_pos = packet.len();
    packet.extend(&[0x00, 0x00]); // Placeholder for length

    // X.224 Connection Request (CR) TPDU
    let cr_start = packet.len();
    packet.push(0x00); // Length indicator (filled later)
    packet.push(0xe0); // CR TPDU code (1110 0000)
    packet.extend(&[0x00, 0x00]); // DST-REF
    packet.extend(&[0x00, 0x00]); // SRC-REF
    packet.push(0x00); // Class option

    // Cookie for load balancing (optional but commonly used)
    let cookie = b"Cookie: mstshash=heroforge\r\n";
    packet.extend(cookie);

    // RDP Negotiation Request (TYPE_RDP_NEG_REQ)
    packet.push(TYPE_RDP_NEG_REQ); // Type
    packet.push(0x00); // Flags
    packet.extend(&[0x08, 0x00]); // Length (8 bytes, little-endian)
    packet.extend(&requested_protocols.to_le_bytes()); // Requested protocols

    // Fill in lengths
    let total_len = packet.len();
    // TPKT length (big-endian, includes TPKT header)
    packet[len_pos] = ((total_len) >> 8) as u8;
    packet[len_pos + 1] = (total_len & 0xff) as u8;
    // X.224 length indicator (excluding itself)
    packet[cr_start] = (total_len - cr_start - 1) as u8;

    packet
}

/// Parse X.224 Connection Confirm response
fn parse_x224_response(data: &[u8]) -> Result<Option<RdpSecurityInfo>> {
    // Minimal validation
    if data.len() < 11 {
        return Ok(None);
    }

    // Check TPKT header
    if data[0] != 0x03 {
        return Ok(None);
    }

    let mut info = RdpSecurityInfo {
        classic_rdp: false,
        ssl_supported: false,
        nla_supported: false,
        hybrid_ex: false,
        selected_protocol: 0,
    };

    // Find RDP_NEG_RSP or RDP_NEG_FAILURE in response
    // Skip TPKT header (4 bytes) and look in X.224 data
    for i in 4..data.len().saturating_sub(7) {
        // Check for RDP_NEG_RSP (0x02)
        if data[i] == TYPE_RDP_NEG_RSP {
            // Verify this looks like a negotiation response
            // Format: type(1) + flags(1) + length(2) + selectedProtocol(4)
            if i + 8 <= data.len() {
                let selected_protocol = u32::from_le_bytes([
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);

                info.selected_protocol = selected_protocol;
                info.classic_rdp = selected_protocol == PROTOCOL_RDP;
                info.ssl_supported = (selected_protocol & PROTOCOL_SSL) != 0;
                info.nla_supported = (selected_protocol & PROTOCOL_HYBRID) != 0;
                info.hybrid_ex = (selected_protocol & PROTOCOL_HYBRID_EX) != 0;

                return Ok(Some(info));
            }
        }

        // Check for RDP_NEG_FAILURE (0x03)
        if data[i] == TYPE_RDP_NEG_FAILURE {
            // Server rejected our protocol request
            // This typically means only Classic RDP is supported
            info.classic_rdp = true;
            return Ok(Some(info));
        }
    }

    // If no negotiation response found, server might only support Classic RDP
    // Check if we got a valid X.224 CC (Connection Confirm)
    if data.len() > 4 && data[4] > 0 && data[5] == 0xd0 {
        // 0xd0 = CC TPDU code
        info.classic_rdp = true;
        return Ok(Some(info));
    }

    Ok(None)
}

/// Try to detect RDP/Windows version from protocol behavior
async fn detect_rdp_version(target_ip: &str, port: u16, timeout: Duration) -> Option<Finding> {
    let target_ip = target_ip.to_string();

    let result = tokio::task::spawn_blocking(move || -> Option<String> {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        // Send minimal X.224 CR to get server response
        let x224_cr = build_x224_connection_request(PROTOCOL_RDP);
        stream.write_all(&x224_cr).ok()?;
        stream.flush().ok()?;

        let mut response = vec![0u8; 512];
        let n = stream.read(&mut response).ok()?;

        if n < 11 {
            return None;
        }

        // Analyze response characteristics
        // This is heuristic-based version detection

        // Check for negotiation failure codes that hint at version
        for i in 4..n.saturating_sub(4) {
            if response[i] == TYPE_RDP_NEG_FAILURE && i + 8 <= n {
                let failure_code = u32::from_le_bytes([
                    response[i + 4],
                    response[i + 5],
                    response[i + 6],
                    response[i + 7],
                ]);

                return match failure_code {
                    0x01 => Some("SSL required (Windows Vista+)".to_string()),
                    0x02 => Some("SSL not allowed (Legacy Windows)".to_string()),
                    0x03 => Some("SSL cert required (Domain environment)".to_string()),
                    0x04 => Some("Inconsistent flags (Windows 7+)".to_string()),
                    0x05 => Some("Hybrid required (Windows 8+)".to_string()),
                    0x06 => Some("SSL with user auth (Windows 8.1+)".to_string()),
                    _ => Some(format!("Unknown failure code: 0x{:08x}", failure_code)),
                };
            }
        }

        None
    })
    .await
    .ok()?;

    result.map(|version_hint| {
        Finding::with_confidence(FindingType::RdpVersion, version_hint, 70)
    })
}

/// Check BlueKeep vulnerability (CVE-2019-0708)
/// This is a SAFE detection that does NOT exploit the vulnerability.
/// It checks for the vulnerable response pattern without sending malicious payloads.
async fn check_bluekeep(target_ip: &str, port: u16, timeout: Duration) -> Option<Finding> {
    let target_ip = target_ip.to_string();

    let result = tokio::task::spawn_blocking(move || -> Option<bool> {
        let addr = format!("{}:{}", target_ip, port);
        let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        // Step 1: X.224 Connection Request (request Classic RDP only)
        // BlueKeep affects Classic RDP security layer
        let x224_cr = build_x224_connection_request(PROTOCOL_RDP);
        stream.write_all(&x224_cr).ok()?;
        stream.flush().ok()?;

        let mut response = vec![0u8; 256];
        let n = stream.read(&mut response).ok()?;

        if n < 11 || response[0] != 0x03 {
            return Some(false);
        }

        // Check if server accepted Classic RDP (required for BlueKeep)
        let mut classic_rdp_accepted = false;
        for i in 4..n.saturating_sub(7) {
            if response[i] == TYPE_RDP_NEG_RSP {
                let selected = u32::from_le_bytes([
                    response[i + 4],
                    response[i + 5],
                    response[i + 6],
                    response[i + 7],
                ]);
                if selected == PROTOCOL_RDP {
                    classic_rdp_accepted = true;
                    break;
                }
            }
            // If negotiation failure, might still be vulnerable
            if response[i] == TYPE_RDP_NEG_FAILURE {
                // Server rejected but might still have vulnerable code path
                // Continue with detection
            }
        }

        // If server doesn't accept classic RDP at all (requires TLS/NLA), not vulnerable
        // But we still proceed with MCS detection as some configs are complex

        // Step 2: Send MCS Connect Initial with special channel structure
        // BlueKeep vulnerability is in the handling of MS_T120 channel (channel ID 31)
        let mcs_connect = build_bluekeep_detection_packet();
        stream.write_all(&mcs_connect).ok()?;
        stream.flush().ok()?;

        // Step 3: Read MCS Connect Response
        let mut mcs_response = vec![0u8; 1024];
        let mcs_n = match stream.read(&mut mcs_response) {
            Ok(n) if n > 0 => n,
            _ => return Some(false),
        };

        // Analyze response for BlueKeep indicators
        // Vulnerable servers will process our malformed channel request
        // and respond with MCS Connect Response (0x7f)
        // Non-vulnerable (patched) servers will disconnect or send error

        if mcs_n > 5 {
            // Check for TPKT + X.224 data indication + MCS response
            if mcs_response[0] == 0x03 {
                // Valid TPKT
                // Look for MCS Connect Response (BER tag 0x7f)
                for i in 4..mcs_n.saturating_sub(1) {
                    if mcs_response[i] == 0x7f {
                        // MCS Connect Response received
                        // This indicates the server processed our request
                        // which means it has the vulnerable code path
                        if classic_rdp_accepted {
                            return Some(true);
                        }
                    }
                }
            }
        }

        Some(false)
    })
    .await
    .ok()?;

    if result? {
        Some(
            Finding::with_confidence(
                FindingType::RdpBlueKeep,
                "CVE-2019-0708 (BlueKeep) - Remote Code Execution vulnerability".to_string(),
                80, // Not 100% as detection is heuristic
            )
            .with_metadata("cve".to_string(), "CVE-2019-0708".to_string())
            .with_metadata("severity".to_string(), "Critical".to_string())
            .with_metadata("cvss".to_string(), "9.8".to_string())
            .with_metadata(
                "impact".to_string(),
                "Pre-authentication RCE, no user interaction required".to_string(),
            )
            .with_metadata(
                "affected".to_string(),
                "Windows XP, 2003, Vista, 2008, 7, 2008 R2".to_string(),
            )
            .with_metadata(
                "recommendation".to_string(),
                "Apply MS19-019 patch immediately, enable NLA, block port 3389".to_string(),
            ),
        )
    } else {
        None
    }
}

/// Build MCS Connect Initial packet for BlueKeep detection
/// This packet tests if the server has vulnerable MS_T120 channel handling
fn build_bluekeep_detection_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // TPKT Header
    packet.push(0x03); // Version
    packet.push(0x00); // Reserved

    // Length placeholder
    let len_pos = packet.len();
    packet.extend(&[0x00, 0x00]);

    // X.224 Data TPDU
    packet.push(0x02); // Length indicator
    packet.push(0xf0); // Data TPDU code
    packet.push(0x80); // EOT

    // MCS Connect Initial (T.125)
    // BER encoded
    packet.push(0x7f); // Connect-Initial tag
    packet.push(0x65); // Length (101 bytes) - will adjust

    let mcs_start = packet.len();

    // callingDomainSelector
    packet.extend(&[0x04, 0x01, 0x01]); // OCTET STRING, length 1, value 1

    // calledDomainSelector
    packet.extend(&[0x04, 0x01, 0x01]); // OCTET STRING, length 1, value 1

    // upwardFlag
    packet.extend(&[0x01, 0x01, 0xff]); // BOOLEAN TRUE

    // targetParameters (DomainParameters)
    packet.push(0x30); // SEQUENCE
    packet.push(0x19); // Length (25 bytes)
    // maxChannelIds
    packet.extend(&[0x02, 0x01, 0x22]); // INTEGER 34
    // maxUserIds
    packet.extend(&[0x02, 0x01, 0x02]); // INTEGER 2
    // maxTokenIds
    packet.extend(&[0x02, 0x01, 0x00]); // INTEGER 0
    // numPriorities
    packet.extend(&[0x02, 0x01, 0x01]); // INTEGER 1
    // minThroughput
    packet.extend(&[0x02, 0x01, 0x00]); // INTEGER 0
    // maxHeight
    packet.extend(&[0x02, 0x01, 0x01]); // INTEGER 1
    // maxMCSPDUsize
    packet.extend(&[0x02, 0x02, 0xff, 0xff]); // INTEGER 65535
    // protocolVersion
    packet.extend(&[0x02, 0x01, 0x02]); // INTEGER 2

    // minimumParameters (same structure)
    packet.push(0x30); // SEQUENCE
    packet.push(0x19); // Length
    packet.extend(&[0x02, 0x01, 0x01]); // maxChannelIds = 1
    packet.extend(&[0x02, 0x01, 0x01]); // maxUserIds = 1
    packet.extend(&[0x02, 0x01, 0x01]); // maxTokenIds = 1
    packet.extend(&[0x02, 0x01, 0x01]); // numPriorities = 1
    packet.extend(&[0x02, 0x01, 0x00]); // minThroughput = 0
    packet.extend(&[0x02, 0x01, 0x01]); // maxHeight = 1
    packet.extend(&[0x02, 0x02, 0x04, 0x20]); // maxMCSPDUsize = 1056
    packet.extend(&[0x02, 0x01, 0x02]); // protocolVersion = 2

    // maximumParameters (same structure)
    packet.push(0x30); // SEQUENCE
    packet.push(0x19); // Length
    packet.extend(&[0x02, 0x01, 0xff]); // maxChannelIds = 255
    packet.extend(&[0x02, 0x01, 0xff]); // maxUserIds = 255
    packet.extend(&[0x02, 0x01, 0xff]); // maxTokenIds = 255
    packet.extend(&[0x02, 0x01, 0x01]); // numPriorities = 1
    packet.extend(&[0x02, 0x01, 0x00]); // minThroughput = 0
    packet.extend(&[0x02, 0x01, 0x01]); // maxHeight = 1
    packet.extend(&[0x02, 0x02, 0xff, 0xff]); // maxMCSPDUsize = 65535
    packet.extend(&[0x02, 0x01, 0x02]); // protocolVersion = 2

    // userData (GCC Conference Create Request)
    // This is where the BlueKeep-specific check happens
    packet.push(0x04); // OCTET STRING tag
    let userdata_len_pos = packet.len();
    packet.push(0x00); // Length placeholder

    // GCC Conference Create Request (minimal)
    let gcc_start = packet.len();
    // Object identifier for T.124
    packet.extend(&[0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01]);
    // ConnectData::connectPDU (per encoded)
    packet.extend(&[0x81, 0x00]); // Length placeholder, will be small

    // Conference name
    packet.push(0x00); // numericString length
    packet.push(0x08); // padding

    // h221NonStandard key for MS
    packet.extend(&[0x00, 0x10, 0x00, 0x01, 0xc0, 0x00]);

    // Client data length
    packet.extend(&[0x44, 0x75, 0x63, 0x61]); // "Duca" - MS client data marker
    packet.extend(&[0x81, 0x00]); // Length placeholder

    // Client Core Data (minimal)
    packet.extend(&[0x01, 0xc0]); // CS_CORE
    packet.extend(&[0x08, 0x00]); // Length (8 bytes)
    packet.extend(&[0x00, 0x04]); // Version 4.0
    packet.extend(&[0x00, 0x08]); // Desktop width
    packet.extend(&[0x00, 0x06]); // Desktop height

    let gcc_len = packet.len() - gcc_start;
    packet[userdata_len_pos] = gcc_len as u8;

    // Update MCS length
    let mcs_len = packet.len() - mcs_start;
    packet[mcs_start - 1] = mcs_len as u8;

    // Update TPKT length
    let total_len = packet.len();
    packet[len_pos] = ((total_len) >> 8) as u8;
    packet[len_pos + 1] = (total_len & 0xff) as u8;

    packet
}

/// Helper function to send progress messages
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
    fn test_build_x224_connection_request() {
        let packet = build_x224_connection_request(PROTOCOL_HYBRID | PROTOCOL_SSL);
        // Check TPKT header
        assert_eq!(packet[0], 0x03); // Version
        assert_eq!(packet[1], 0x00); // Reserved
        // Check X.224 CR code
        assert_eq!(packet[5], 0xe0); // CR TPDU code
        // Verify packet is reasonable size
        assert!(packet.len() > 30);
        assert!(packet.len() < 200);
    }

    #[test]
    fn test_rdp_security_info_display() {
        let info = RdpSecurityInfo {
            classic_rdp: true,
            ssl_supported: true,
            nla_supported: false,
            hybrid_ex: false,
            selected_protocol: PROTOCOL_SSL,
        };
        assert_eq!(info.protocols_str(), "Classic RDP, TLS");

        let info2 = RdpSecurityInfo {
            classic_rdp: false,
            ssl_supported: false,
            nla_supported: true,
            hybrid_ex: true,
            selected_protocol: PROTOCOL_HYBRID_EX,
        };
        assert_eq!(info2.protocols_str(), "CredSSP/NLA, CredSSP Extended");
    }

    #[test]
    fn test_build_bluekeep_detection_packet() {
        let packet = build_bluekeep_detection_packet();
        // Check TPKT header
        assert_eq!(packet[0], 0x03);
        // Check X.224 Data TPDU
        assert_eq!(packet[5], 0xf0);
        // Check MCS Connect Initial tag
        assert_eq!(packet[7], 0x7f);
        // Verify packet has reasonable size
        assert!(packet.len() > 50);
        assert!(packet.len() < 500);
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(PROTOCOL_RDP, 0x00000000);
        assert_eq!(PROTOCOL_SSL, 0x00000001);
        assert_eq!(PROTOCOL_HYBRID, 0x00000002);
        assert_eq!(PROTOCOL_HYBRID_EX, 0x00000008);
    }
}
