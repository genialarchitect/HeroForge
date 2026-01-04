//! CoAP Protocol Scanner
//!
//! Scans for CoAP (Constrained Application Protocol) devices.

use super::{ProtocolScanResult, ProtocolScanner};
use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// CoAP scanner for constrained IoT devices
pub struct CoapScanner;

impl CoapScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CoapScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for CoapScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Coap
    }

    fn default_port(&self) -> u16 {
        5683 // CoAP default, 5684 for DTLS
    }

    async fn detect(&self, addr: SocketAddr, dur: Duration) -> Result<bool> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Send CoAP GET request for .well-known/core
        let get_request = build_coap_get_wellknown();

        socket.send_to(&get_request, addr).await?;

        let mut buf = [0u8; 1024];
        match timeout(dur, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= 4 => {
                // Check for valid CoAP response
                // Version should be 1 (bits 6-7), Type should be ACK (2) or NON (1)
                let ver = (buf[0] >> 6) & 0x03;
                let msg_type = (buf[0] >> 4) & 0x03;
                if ver == 1 && (msg_type == 2 || msg_type == 1) {
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

        let mut details = ProtocolDetails {
            device_id: Some("CoAP Device".to_string()),
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        };

        if detected {
            if let Ok(info) = get_coap_info(addr, dur).await {
                if let Some(ref resources) = info.resources {
                    details.metadata = serde_json::json!({"resources": resources});
                }

                if !info.uses_dtls {
                    security_issues.push(SecurityIssue {
                        issue_type: "Encryption".to_string(),
                        severity: "High".to_string(),
                        description: "CoAP traffic is unencrypted".to_string(),
                        remediation: Some("Enable DTLS on port 5684 for secure CoAP".to_string()),
                    });
                }

                if info.anonymous_allowed {
                    security_issues.push(SecurityIssue {
                        issue_type: "Authentication".to_string(),
                        severity: "High".to_string(),
                        description: "CoAP resources accessible without authentication".to_string(),
                        remediation: Some("Implement DTLS with client certificates or OSCORE".to_string()),
                    });
                }

                if info.has_actuator_resources {
                    security_issues.push(SecurityIssue {
                        issue_type: "Access Control".to_string(),
                        severity: "Critical".to_string(),
                        description: "Device exposes PUT/POST resources that may control actuators".to_string(),
                        remediation: Some("Implement strict access control on actuator endpoints".to_string()),
                    });
                }
            }
        }

        Ok(ProtocolScanResult {
            protocol: OtProtocolType::Coap,
            port: addr.port(),
            detected,
            details,
            security_issues,
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Build CoAP GET .well-known/core request
fn build_coap_get_wellknown() -> Vec<u8> {
    let mut packet = Vec::new();

    // CoAP Header
    // Version (1), Type (CON = 0), Token Length (0)
    packet.push(0x40);
    // Code: GET (0.01)
    packet.push(0x01);
    // Message ID
    packet.push(0x00);
    packet.push(0x01);

    // Options
    // Uri-Path: .well-known (option 11)
    let path1 = b".well-known";
    packet.push((11 << 4) | path1.len() as u8);
    packet.extend_from_slice(path1);

    // Uri-Path: core (delta = 0)
    let path2 = b"core";
    packet.push(path2.len() as u8);
    packet.extend_from_slice(path2);

    packet
}

struct CoapInfo {
    uses_dtls: bool,
    anonymous_allowed: bool,
    resources: Option<String>,
    has_actuator_resources: bool,
}

async fn get_coap_info(addr: SocketAddr, dur: Duration) -> Result<CoapInfo> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut info = CoapInfo {
        uses_dtls: addr.port() == 5684,
        anonymous_allowed: true, // Assume true if we can query
        resources: None,
        has_actuator_resources: false,
    };

    // Send GET .well-known/core
    let request = build_coap_get_wellknown();
    socket.send_to(&request, addr).await?;

    let mut buf = [0u8; 2048];
    if let Ok(Ok((n, _))) = timeout(dur, socket.recv_from(&mut buf)).await {
        if n > 4 {
            // Check response code (byte 1)
            let code = buf[1];
            let class = (code >> 5) & 0x07;
            let detail = code & 0x1F;

            if class == 2 && detail == 5 {
                // 2.05 Content - successful response
                // Parse payload (starts after options)
                let mut offset = 4; // Skip header

                // Skip token if present
                let token_len = buf[0] & 0x0F;
                offset += token_len as usize;

                // Skip options until payload marker (0xFF)
                while offset < n && buf[offset] != 0xFF {
                    let delta = (buf[offset] >> 4) & 0x0F;
                    let length = buf[offset] & 0x0F;

                    offset += 1;

                    // Extended delta
                    if delta == 13 {
                        offset += 1;
                    } else if delta == 14 {
                        offset += 2;
                    }

                    // Extended length
                    let actual_len = if length == 13 {
                        let l = buf[offset] as usize + 13;
                        offset += 1;
                        l
                    } else if length == 14 {
                        let l = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize + 269;
                        offset += 2;
                        l
                    } else {
                        length as usize
                    };

                    offset += actual_len;
                }

                // Skip payload marker
                if offset < n && buf[offset] == 0xFF {
                    offset += 1;

                    // Parse Core Link Format payload
                    if offset < n {
                        if let Ok(payload) = std::str::from_utf8(&buf[offset..n]) {
                            info.resources = Some(payload.to_string());

                            // Check for actuator indicators
                            if payload.contains("ct=0") || // text/plain - often actuators
                               payload.contains("PUT") ||
                               payload.contains("POST") ||
                               payload.contains("actuator") ||
                               payload.contains("switch") ||
                               payload.contains("relay")
                            {
                                info.has_actuator_resources = true;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(info)
}
