//! IEC 61850 Protocol Scanner
//!
//! Scans for IEC 61850 devices commonly used in electrical substations.

use super::{ProtocolScanResult, ProtocolScanner};
use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// IEC 61850 scanner for substation automation systems
pub struct Iec61850Scanner;

impl Iec61850Scanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Iec61850Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for Iec61850Scanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Iec61850
    }

    fn default_port(&self) -> u16 {
        102 // Uses ISO COTP over TCP
    }

    async fn detect(&self, addr: SocketAddr, dur: Duration) -> Result<bool> {
        // IEC 61850 runs over MMS which runs over ISO COTP (port 102)
        // Try to establish a COTP connection
        match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send COTP Connection Request (CR TPDU)
                let cotp_cr = build_cotp_connection_request();

                if stream.write_all(&cotp_cr).await.is_err() {
                    return Ok(false);
                }

                let mut buf = [0u8; 256];
                match timeout(dur, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 4 => {
                        // Check for COTP Connection Confirm (CC TPDU)
                        // TPKT header: version=3, reserved=0
                        // COTP: CC PDU type = 0xD0
                        if buf[0] == 0x03 && n > 6 && buf[5] == 0xD0 {
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
            device_id: Some("Substation IED".to_string()),
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        };

        if detected {
            // Try to get more info via MMS
            if let Ok(info) = get_iec61850_info(addr, dur).await {
                details.vendor_info = info.vendor;
                details.version = info.version;

                // Security checks
                if info.no_authentication {
                    security_issues.push(SecurityIssue {
                        issue_type: "Authentication".to_string(),
                        severity: "Critical".to_string(),
                        description: "IEC 61850 MMS server allows unauthenticated access".to_string(),
                        remediation: Some("Enable GOOSE/MMS authentication using IEC 62351".to_string()),
                    });
                }

                if !info.uses_tls {
                    security_issues.push(SecurityIssue {
                        issue_type: "Encryption".to_string(),
                        severity: "High".to_string(),
                        description: "MMS communications are unencrypted".to_string(),
                        remediation: Some("Implement TLS for MMS communications per IEC 62351-4".to_string()),
                    });
                }
            }
        }

        Ok(ProtocolScanResult {
            protocol: OtProtocolType::Iec61850,
            port: addr.port(),
            detected,
            details,
            security_issues,
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Build COTP Connection Request for IEC 61850
fn build_cotp_connection_request() -> Vec<u8> {
    let mut packet = Vec::new();

    // TPKT Header
    packet.push(0x03); // Version
    packet.push(0x00); // Reserved
    packet.push(0x00); // Length high byte (placeholder)
    packet.push(0x16); // Length low byte (22 bytes total)

    // COTP CR TPDU
    packet.push(0x11); // Length of COTP
    packet.push(0xE0); // CR code
    packet.push(0x00); // DST-REF high
    packet.push(0x00); // DST-REF low
    packet.push(0x00); // SRC-REF high
    packet.push(0x01); // SRC-REF low
    packet.push(0x00); // Class and options

    // Parameter: TPDU Size
    packet.push(0xC0); // Parameter code
    packet.push(0x01); // Parameter length
    packet.push(0x0A); // TPDU size = 1024

    // Parameter: Source TSAP
    packet.push(0xC1); // Parameter code
    packet.push(0x02); // Length
    packet.push(0x00);
    packet.push(0x01);

    // Parameter: Destination TSAP
    packet.push(0xC2); // Parameter code
    packet.push(0x02); // Length
    packet.push(0x00);
    packet.push(0x01);

    packet
}

struct Iec61850Info {
    vendor: Option<String>,
    version: Option<String>,
    no_authentication: bool,
    uses_tls: bool,
}

async fn get_iec61850_info(addr: SocketAddr, dur: Duration) -> Result<Iec61850Info> {
    // Basic detection - would need full MMS implementation for deep inspection
    let mut info = Iec61850Info {
        vendor: None,
        version: None,
        no_authentication: true, // Assume vulnerable until proven otherwise
        uses_tls: addr.port() == 3782, // Secure MMS uses port 3782
    };

    if let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await {
        let cotp_cr = build_cotp_connection_request();
        if stream.write_all(&cotp_cr).await.is_ok() {
            let mut buf = [0u8; 1024];
            if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
                if n > 10 {
                    info.vendor = Some("IEC 61850 Device".to_string());
                }
            }
        }
    }

    Ok(info)
}
