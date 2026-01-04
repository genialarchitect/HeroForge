//! CIP (Common Industrial Protocol) Scanner
//!
//! Scans for CIP devices (used by EtherNet/IP, DeviceNet, ControlNet).

use super::{ProtocolScanResult, ProtocolScanner};
use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// CIP scanner
pub struct CipScanner;

impl CipScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CipScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for CipScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Cip
    }

    fn default_port(&self) -> u16 {
        44818 // EtherNet/IP explicit messaging
    }

    async fn detect(&self, addr: SocketAddr, dur: Duration) -> Result<bool> {
        // CIP uses EtherNet/IP encapsulation
        match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send Register Session request
                let register_session = build_enip_register_session();

                if stream.write_all(&register_session).await.is_err() {
                    return Ok(false);
                }

                let mut buf = [0u8; 256];
                match timeout(dur, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n >= 24 => {
                        // Check EtherNet/IP header
                        // Command: Register Session Response = 0x0065
                        let cmd = u16::from_le_bytes([buf[0], buf[1]]);
                        if cmd == 0x0065 {
                            return Ok(true);
                        }
                        Ok(false)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    async fn scan(&self, addr: SocketAddr, dur: Duration) -> Result<ProtocolScanResult> {
        let start = Instant::now();
        let detected = self.detect(addr, dur).await.unwrap_or(false);
        let mut security_issues = Vec::new();

        let mut details = ProtocolDetails {
            device_id: Some("CIP Device".to_string()),
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        };

        if detected {
            if let Ok(info) = get_cip_identity(addr, dur).await {
                details.vendor_info = info.vendor;
                details.device_id = info.product_name.or(details.device_id);
                details.version = info.revision;

                details.metadata = serde_json::json!({
                    "vendor_id": info.vendor_id,
                    "device_type": info.device_type,
                    "serial": info.serial
                });
            }

            // CIP security issues
            security_issues.push(SecurityIssue {
                issue_type: "Authentication".to_string(),
                severity: "High".to_string(),
                description: "CIP protocol does not require authentication by default".to_string(),
                remediation: Some("Implement CIP Security per IEC 62443".to_string()),
            });

            security_issues.push(SecurityIssue {
                issue_type: "Information Disclosure".to_string(),
                severity: "Medium".to_string(),
                description: "Device identity information is publicly accessible".to_string(),
                remediation: Some("Implement network segmentation to limit CIP exposure".to_string()),
            });
        }

        Ok(ProtocolScanResult {
            protocol: OtProtocolType::Cip,
            port: addr.port(),
            detected,
            details,
            security_issues,
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Build EtherNet/IP Register Session request
fn build_enip_register_session() -> Vec<u8> {
    let mut packet = Vec::new();

    // EtherNet/IP Header
    packet.extend_from_slice(&0x0065u16.to_le_bytes()); // Command: Register Session
    packet.extend_from_slice(&0x0004u16.to_le_bytes()); // Length: 4
    packet.extend_from_slice(&0u32.to_le_bytes());       // Session Handle: 0
    packet.extend_from_slice(&0u32.to_le_bytes());       // Status: 0
    packet.extend_from_slice(&[0u8; 8]);                 // Sender Context
    packet.extend_from_slice(&0u32.to_le_bytes());       // Options: 0

    // Register Session Data
    packet.extend_from_slice(&0x0001u16.to_le_bytes()); // Protocol Version: 1
    packet.extend_from_slice(&0x0000u16.to_le_bytes()); // Options Flags: 0

    packet
}

struct CipIdentity {
    vendor_id: Option<u16>,
    vendor: Option<String>,
    device_type: Option<u16>,
    product_code: Option<u16>,
    product_name: Option<String>,
    serial: Option<String>,
    revision: Option<String>,
}

async fn get_cip_identity(addr: SocketAddr, dur: Duration) -> Result<CipIdentity> {
    let mut info = CipIdentity {
        vendor_id: None,
        vendor: None,
        device_type: None,
        product_code: None,
        product_name: None,
        serial: None,
        revision: None,
    };

    if let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await {
        // Register session first
        let register = build_enip_register_session();
        stream.write_all(&register).await?;

        let mut buf = [0u8; 256];
        if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
            if n >= 24 {
                // Extract session handle for next request
                let session = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

                // Send List Identity request
                let list_identity = build_enip_list_identity(session);
                stream.write_all(&list_identity).await?;

                if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
                    if n > 60 {
                        // Parse identity response
                        parse_cip_identity(&buf[..n], &mut info);
                    }
                }
            }
        }
    }

    Ok(info)
}

fn build_enip_list_identity(session: u32) -> Vec<u8> {
    let mut packet = Vec::new();

    // EtherNet/IP Header
    packet.extend_from_slice(&0x0063u16.to_le_bytes()); // Command: List Identity
    packet.extend_from_slice(&0x0000u16.to_le_bytes()); // Length: 0
    packet.extend_from_slice(&session.to_le_bytes());    // Session Handle
    packet.extend_from_slice(&0u32.to_le_bytes());       // Status: 0
    packet.extend_from_slice(&[0u8; 8]);                 // Sender Context
    packet.extend_from_slice(&0u32.to_le_bytes());       // Options: 0

    packet
}

fn parse_cip_identity(data: &[u8], info: &mut CipIdentity) {
    if data.len() < 60 {
        return;
    }

    // Skip to identity data (after EtherNet/IP header and CPF)
    let offset = 42;
    if offset + 16 > data.len() {
        return;
    }

    // Vendor ID
    if offset + 2 <= data.len() {
        info.vendor_id = Some(u16::from_le_bytes([data[offset], data[offset + 1]]));
    }

    // Device Type
    if offset + 4 <= data.len() {
        info.device_type = Some(u16::from_le_bytes([data[offset + 2], data[offset + 3]]));
    }

    // Product Code
    if offset + 6 <= data.len() {
        info.product_code = Some(u16::from_le_bytes([data[offset + 4], data[offset + 5]]));
    }

    // Revision
    if offset + 8 <= data.len() {
        info.revision = Some(format!("{}.{}", data[offset + 6], data[offset + 7]));
    }

    // Serial Number
    if offset + 14 <= data.len() {
        let serial = u32::from_le_bytes([
            data[offset + 10], data[offset + 11],
            data[offset + 12], data[offset + 13]
        ]);
        info.serial = Some(format!("{:08X}", serial));
    }

    // Product Name (length prefixed string)
    if offset + 15 <= data.len() {
        let name_len = data[offset + 14] as usize;
        if offset + 15 + name_len <= data.len() {
            if let Ok(s) = std::str::from_utf8(&data[offset + 15..offset + 15 + name_len]) {
                info.product_name = Some(s.to_string());
            }
        }
    }
}
