//! HART Protocol Scanner
//!
//! Scans for HART (Highway Addressable Remote Transducer) devices.

use super::{ProtocolScanResult, ProtocolScanner};
use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// HART-IP scanner
pub struct HartScanner;

impl HartScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HartScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for HartScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Hart
    }

    fn default_port(&self) -> u16 {
        5094 // HART-IP UDP port
    }

    async fn detect(&self, addr: SocketAddr, dur: Duration) -> Result<bool> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // HART-IP Session Initiate request
        let session_init = build_hart_session_init();

        socket.send_to(&session_init, addr).await?;

        let mut buf = [0u8; 512];
        match timeout(dur, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= 8 => {
                // Check for HART-IP response (version byte = 1)
                if buf[0] == 0x01 {
                    return Ok(true);
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    async fn scan(&self, addr: SocketAddr, dur: Duration) -> Result<ProtocolScanResult> {
        let start = Instant::now();
        let detected = self.detect(addr, dur).await.unwrap_or(false);
        let mut security_issues = Vec::new();

        let details = ProtocolDetails {
            device_id: Some("HART Device".to_string()),
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        };

        if detected {
            // HART-IP has limited authentication
            security_issues.push(SecurityIssue {
                issue_type: "Authentication".to_string(),
                severity: "High".to_string(),
                description: "HART-IP provides minimal authentication mechanisms".to_string(),
                remediation: Some("Implement network segmentation and use HART-IP secure mode".to_string()),
            });

            security_issues.push(SecurityIssue {
                issue_type: "Encryption".to_string(),
                severity: "Medium".to_string(),
                description: "HART-IP communications are not encrypted by default".to_string(),
                remediation: Some("Use VPN or encrypted tunnels for HART-IP traffic".to_string()),
            });
        }

        Ok(ProtocolScanResult {
            protocol: OtProtocolType::Hart,
            port: addr.port(),
            detected,
            details,
            security_issues,
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Build HART-IP Session Initiate request
fn build_hart_session_init() -> Vec<u8> {
    let mut packet = Vec::new();

    // HART-IP Header
    packet.push(0x01); // Version = 1
    packet.push(0x00); // Message Type = Session Initiate (0)
    packet.push(0x00); // Message ID high
    packet.push(0x01); // Message ID low
    packet.push(0x01); // Status = Primary Master
    packet.push(0x00); // Sequence Number high
    packet.push(0x00); // Sequence Number low
    packet.push(0x05); // Byte Count

    // HART-IP Body (Session Initiate)
    packet.push(0x01); // Master Type
    packet.push(0x01); // Inactivity Close Timer
    packet.push(0x00);
    packet.push(0x00);
    packet.push(0x00);

    packet
}
