//! PROFINET Protocol Scanner
//!
//! Scans for PROFINET devices used in industrial automation.

use super::{ProtocolScanResult, ProtocolScanner};
use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// PROFINET scanner for industrial automation
pub struct ProfinetScanner;

impl ProfinetScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProfinetScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for ProfinetScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Profinet
    }

    fn default_port(&self) -> u16 {
        34964 // PROFINET-RT
    }

    async fn detect(&self, addr: SocketAddr, dur: Duration) -> Result<bool> {
        // PROFINET uses UDP for DCP (Discovery and Configuration Protocol)
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Build DCP Identify Request
        let dcp_identify = build_dcp_identify_request();

        socket.send_to(&dcp_identify, addr).await?;

        let mut buf = [0u8; 1024];
        match timeout(dur, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n > 20 => {
                // Check for valid DCP response
                // PROFINET DCP uses frame ID 0xFEFE or 0xFEFF
                if n > 2 && (buf[0] == 0xFE && (buf[1] == 0xFE || buf[1] == 0xFF)) {
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
            device_id: Some("PROFINET Device".to_string()),
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        };

        if detected {
            if let Ok(info) = get_profinet_info(addr, dur).await {
                details.vendor_info = info.vendor;
                details.device_id = info.device_name.or(details.device_id);
                if let Some(station) = info.station_name {
                    details.metadata = serde_json::json!({"station_name": station});
                }

                // PROFINET typically has no authentication
                security_issues.push(SecurityIssue {
                    issue_type: "Authentication".to_string(),
                    severity: "High".to_string(),
                    description: "PROFINET protocols typically lack authentication".to_string(),
                    remediation: Some("Segment PROFINET network and implement firewall rules".to_string()),
                });

                if !info.secured {
                    security_issues.push(SecurityIssue {
                        issue_type: "Security Configuration".to_string(),
                        severity: "Medium".to_string(),
                        description: "Device does not support or enable PROFINET Security".to_string(),
                        remediation: Some("Enable PROFINET Security Class 1 or higher".to_string()),
                    });
                }
            }
        }

        Ok(ProtocolScanResult {
            protocol: OtProtocolType::Profinet,
            port: addr.port(),
            detected,
            details,
            security_issues,
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Build DCP Identify Request
fn build_dcp_identify_request() -> Vec<u8> {
    let mut packet = Vec::new();

    // Frame ID (DCP Identify Request = 0xFEFE)
    packet.push(0xFE);
    packet.push(0xFE);

    // Service ID (Identify = 0x05)
    packet.push(0x05);

    // Service Type (Request = 0x00)
    packet.push(0x00);

    // Xid (transaction ID)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // Response Delay Factor
    packet.extend_from_slice(&[0x00, 0x01]);

    // DCPDataLength (0 for identify-all)
    packet.extend_from_slice(&[0x00, 0x00]);

    packet
}

struct ProfinetInfo {
    vendor: Option<String>,
    device_name: Option<String>,
    station_name: Option<String>,
    secured: bool,
}

async fn get_profinet_info(addr: SocketAddr, dur: Duration) -> Result<ProfinetInfo> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let dcp_request = build_dcp_identify_request();

    socket.send_to(&dcp_request, addr).await?;

    let mut buf = [0u8; 1024];
    let mut info = ProfinetInfo {
        vendor: None,
        device_name: None,
        station_name: None,
        secured: false,
    };

    if let Ok(Ok((n, _))) = timeout(dur, socket.recv_from(&mut buf)).await {
        if n > 20 {
            // Parse DCP response blocks
            let mut offset = 12; // Skip header
            while offset + 4 < n {
                let option = buf[offset];
                let suboption = buf[offset + 1];
                let block_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;

                if offset + 4 + block_len > n {
                    break;
                }

                let data = &buf[offset + 4..offset + 4 + block_len];

                match (option, suboption) {
                    (0x02, 0x01) => {
                        // Device/Manufacturer specific - Manufacturer Name
                        if let Ok(s) = std::str::from_utf8(data) {
                            info.vendor = Some(s.trim_end_matches('\0').to_string());
                        }
                    }
                    (0x02, 0x02) => {
                        // Name of Station
                        if let Ok(s) = std::str::from_utf8(data) {
                            info.station_name = Some(s.trim_end_matches('\0').to_string());
                        }
                    }
                    (0x02, 0x03) => {
                        // Device ID (contains vendor/device IDs)
                        if data.len() >= 4 {
                            let vendor_id = u16::from_be_bytes([data[0], data[1]]);
                            let device_id = u16::from_be_bytes([data[2], data[3]]);
                            info.device_name = Some(format!("VID:{:04X} DID:{:04X}", vendor_id, device_id));
                        }
                    }
                    _ => {}
                }

                offset += 4 + block_len;
                // Align to even boundary
                if block_len % 2 != 0 {
                    offset += 1;
                }
            }
        }
    }

    Ok(info)
}
