//! BACnet (Building Automation and Control Networks) Scanner
//!
//! Scans for BACnet/IP devices used in building automation systems (HVAC, lighting, access control).

use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use crate::ot_ics::protocols::{ProtocolScanner, ProtocolScanResult};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// BACnet Scanner
pub struct BacnetScanner {
    default_port: u16,
}

impl BacnetScanner {
    pub fn new() -> Self {
        Self { default_port: 47808 }
    }

    /// Build a BACnet Who-Is broadcast request
    fn build_who_is_request(&self) -> Vec<u8> {
        vec![
            // BVLC header
            0x81,       // BVLC Type (BACnet/IP)
            0x0B,       // Function: Original-Broadcast-NPDU
            0x00, 0x0C, // Length (12 bytes total)

            // NPDU
            0x01,       // Version
            0x20,       // Control: No DNET, no SNET, expecting reply

            // APDU - Who-Is
            0x10,       // PDU Type: Unconfirmed Request
            0x08,       // Service Choice: Who-Is
            // No device range = broadcast to all devices
        ]
    }

    /// Build a BACnet Read-Property request for device object name
    fn build_read_property_request(&self, invoke_id: u8) -> Vec<u8> {
        vec![
            // BVLC header
            0x81,       // BVLC Type
            0x0A,       // Function: Original-Unicast-NPDU
            0x00, 0x11, // Length (17 bytes total)

            // NPDU
            0x01,       // Version
            0x04,       // Control: Expecting reply

            // APDU - Read-Property
            0x00,       // PDU Type: Confirmed Request
            0x04,       // Max Segments: Unspecified, Max Response: 1476
            invoke_id,  // Invoke ID
            0x0C,       // Service Choice: Read-Property

            // Object Identifier: Device, Instance 4194303 (wildcard)
            0x0C,       // Context Tag 0, Length 4
            0x02, 0x3F, 0xFF, 0xFF,

            // Property Identifier: Object-Name (77)
            0x19, 0x4D, // Context Tag 1, Value 77
        ]
    }

    /// Parse BACnet I-Am response
    fn parse_i_am_response(&self, response: &[u8]) -> Option<ProtocolDetails> {
        if response.len() < 10 {
            return None;
        }

        // Verify BVLC header
        if response[0] != 0x81 {
            return None;
        }

        let mut details = ProtocolDetails::default();
        let mut metadata = serde_json::json!({});

        // Find I-Am service choice (0x00) in APDU
        for i in 4..response.len() - 1 {
            if response[i] == 0x10 && response[i + 1] == 0x00 {
                // Found Unconfirmed I-Am

                // Try to parse device instance (follows the service choice)
                if i + 6 < response.len() {
                    // Device object identifier usually follows
                    let device_instance = ((response[i + 3] as u32 & 0x3F) << 16)
                        | ((response[i + 4] as u32) << 8)
                        | (response[i + 5] as u32);
                    metadata["device_instance"] = serde_json::Value::Number(device_instance.into());
                    details.device_id = Some(format!("BACnet:{}", device_instance));
                }

                // Extract max APDU length
                if i + 7 < response.len() {
                    metadata["max_apdu_length"] = serde_json::Value::Number(response[i + 6].into());
                }

                break;
            }
        }

        details.metadata = metadata;
        Some(details)
    }

    /// Identify BACnet security issues
    fn identify_security_issues(&self, _response: &[u8]) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // BACnet/IP has no authentication by default
        issues.push(SecurityIssue {
            issue_type: "no_authentication".to_string(),
            severity: "high".to_string(),
            description: "BACnet/IP protocol has no built-in authentication. Any network-accessible client can read/write properties.".to_string(),
            remediation: Some("Implement network segmentation, consider BACnet Secure Connect (BACnet/SC) for encrypted communications.".to_string()),
        });

        // Broadcast discovery enabled
        issues.push(SecurityIssue {
            issue_type: "broadcast_discovery".to_string(),
            severity: "medium".to_string(),
            description: "Device responds to Who-Is broadcasts, exposing device information to network reconnaissance.".to_string(),
            remediation: Some("Restrict BACnet broadcasts using firewall rules or VLAN segmentation.".to_string()),
        });

        // UDP-based protocol
        issues.push(SecurityIssue {
            issue_type: "udp_protocol".to_string(),
            severity: "low".to_string(),
            description: "BACnet/IP uses UDP which is susceptible to spoofing attacks.".to_string(),
            remediation: Some("Monitor for anomalous BACnet traffic patterns and implement source IP validation where possible.".to_string()),
        });

        issues
    }
}

impl Default for BacnetScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for BacnetScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Bacnet
    }

    fn default_port(&self) -> u16 {
        self.default_port
    }

    async fn detect(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<bool> {
        // BACnet uses UDP
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        let request = self.build_who_is_request();
        if let Err(_) = socket.send_to(&request, addr).await {
            return Ok(false);
        }

        let mut buffer = vec![0u8; 512];
        match timeout(timeout_duration, socket.recv_from(&mut buffer)).await {
            Ok(Ok((n, _))) if n >= 4 => {
                // Check for BACnet BVLC header
                Ok(buffer[0] == 0x81)
            }
            _ => Ok(false),
        }
    }

    async fn scan(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<ProtocolScanResult> {
        let start = Instant::now();
        let mut result = ProtocolScanResult {
            protocol: OtProtocolType::Bacnet,
            port: addr.port(),
            detected: false,
            details: ProtocolDetails::default(),
            security_issues: Vec::new(),
            response_time_ms: 0,
        };

        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return Ok(result),
        };

        // Send Who-Is request
        let request = self.build_who_is_request();
        if let Ok(_) = socket.send_to(&request, addr).await {
            let mut buffer = vec![0u8; 1024];

            // BACnet devices may respond with I-Am
            if let Ok(Ok((n, _))) = timeout(timeout_duration, socket.recv_from(&mut buffer)).await {
                buffer.truncate(n);

                if n >= 4 && buffer[0] == 0x81 {
                    result.detected = true;

                    if let Some(details) = self.parse_i_am_response(&buffer) {
                        result.details = details;
                    }
                    result.security_issues = self.identify_security_issues(&buffer);
                }
            }
        }

        result.response_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }
}
