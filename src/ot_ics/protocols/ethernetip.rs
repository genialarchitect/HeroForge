//! EtherNet/IP (Industrial Protocol) Scanner
//!
//! Scans for EtherNet/IP devices commonly used in factory automation (Rockwell/Allen-Bradley).

use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use crate::ot_ics::protocols::{ProtocolScanner, ProtocolScanResult};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// EtherNet/IP Scanner
pub struct EthernetIpScanner {
    default_port: u16,
}

impl EthernetIpScanner {
    pub fn new() -> Self {
        Self { default_port: 44818 }
    }

    /// Build an EtherNet/IP List Identity request
    fn build_list_identity_request(&self) -> Vec<u8> {
        vec![
            // Encapsulation Header
            0x63, 0x00, // Command: List Identity
            0x00, 0x00, // Length: 0 (no data)
            0x00, 0x00, 0x00, 0x00, // Session Handle: 0
            0x00, 0x00, 0x00, 0x00, // Status: 0
            0x00, 0x00, 0x00, 0x00, // Sender Context (8 bytes)
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Options: 0
        ]
    }

    /// Build a Register Session request
    fn build_register_session(&self) -> Vec<u8> {
        vec![
            // Encapsulation Header
            0x65, 0x00, // Command: Register Session
            0x04, 0x00, // Length: 4
            0x00, 0x00, 0x00, 0x00, // Session Handle: 0 (requesting new)
            0x00, 0x00, 0x00, 0x00, // Status: 0
            0x00, 0x00, 0x00, 0x00, // Sender Context
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Options: 0

            // Command Specific Data
            0x01, 0x00, // Protocol Version: 1
            0x00, 0x00, // Options Flags: 0
        ]
    }

    /// Parse List Identity response
    fn parse_list_identity(&self, response: &[u8]) -> Option<ProtocolDetails> {
        if response.len() < 24 {
            return None;
        }

        // Verify command is List Identity response
        if response[0] != 0x63 || response[1] != 0x00 {
            return None;
        }

        let mut details = ProtocolDetails::default();
        let mut metadata = serde_json::json!({});

        // Get data length
        let data_len = (response[2] as u16) | ((response[3] as u16) << 8);
        if response.len() < 24 + data_len as usize {
            return Some(details);
        }

        // Parse identity data (starts at offset 24)
        if data_len >= 2 {
            let item_count = (response[24] as u16) | ((response[25] as u16) << 8);
            metadata["item_count"] = serde_json::Value::Number(item_count.into());

            // Parse CIP Identity item if present
            if data_len >= 30 {
                // Item type at 26-27, length at 28-29
                let item_type = (response[26] as u16) | ((response[27] as u16) << 8);

                if item_type == 0x0C { // CIP Identity
                    let item_len = (response[28] as u16) | ((response[29] as u16) << 8);

                    // Protocol version at 30-31
                    if data_len >= 32 {
                        let protocol_version = (response[30] as u16) | ((response[31] as u16) << 8);
                        metadata["protocol_version"] = serde_json::Value::Number(protocol_version.into());
                    }

                    // Vendor ID at 36-37
                    if data_len >= 38 {
                        let vendor_id = (response[36] as u16) | ((response[37] as u16) << 8);
                        metadata["vendor_id"] = serde_json::Value::Number(vendor_id.into());
                        details.vendor_info = Some(Self::vendor_id_to_name(vendor_id));
                    }

                    // Device type at 38-39
                    if data_len >= 40 {
                        let device_type = (response[38] as u16) | ((response[39] as u16) << 8);
                        metadata["device_type"] = serde_json::Value::Number(device_type.into());
                    }

                    // Product code at 40-41
                    if data_len >= 42 {
                        let product_code = (response[40] as u16) | ((response[41] as u16) << 8);
                        metadata["product_code"] = serde_json::Value::Number(product_code.into());
                    }

                    // Revision at 42-43
                    if data_len >= 44 {
                        let major = response[42];
                        let minor = response[43];
                        details.version = Some(format!("{}.{}", major, minor));
                    }

                    // Serial number at 46-49
                    if data_len >= 50 {
                        let serial = u32::from_le_bytes([response[46], response[47], response[48], response[49]]);
                        details.device_id = Some(format!("EIP:{:08X}", serial));
                        metadata["serial_number"] = serde_json::Value::String(format!("{:08X}", serial));
                    }

                    // Product name (variable length string after byte 50)
                    if data_len >= 52 {
                        let name_len = response[50] as usize;
                        if data_len >= 51 + name_len as u16 && response.len() >= 51 + name_len {
                            if let Ok(name) = String::from_utf8(response[51..51 + name_len].to_vec()) {
                                metadata["product_name"] = serde_json::Value::String(name);
                            }
                        }
                    }
                }
            }
        }

        details.metadata = metadata;
        Some(details)
    }

    /// Convert vendor ID to vendor name
    fn vendor_id_to_name(id: u16) -> String {
        match id {
            1 => "Rockwell Automation".to_string(),
            2 => "Mitsubishi Electric".to_string(),
            5 => "ABB".to_string(),
            6 => "Parker Hannifin".to_string(),
            11 => "Omron".to_string(),
            13 => "Siemens".to_string(),
            15 => "Schneider Electric".to_string(),
            27 => "Beckhoff".to_string(),
            50 => "Molex".to_string(),
            283 => "WAGO".to_string(),
            _ => format!("Vendor ID {}", id),
        }
    }

    /// Identify EtherNet/IP security issues
    fn identify_security_issues(&self, response: &[u8]) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // EtherNet/IP has no authentication
        issues.push(SecurityIssue {
            issue_type: "no_authentication".to_string(),
            severity: "high".to_string(),
            description: "EtherNet/IP CIP protocol has no built-in authentication. Any network client can establish sessions.".to_string(),
            remediation: Some("Implement network segmentation, use firewalls, and consider CIP Security (TLS-based) if supported.".to_string()),
        });

        // Identity disclosure
        if response.len() > 24 {
            issues.push(SecurityIssue {
                issue_type: "identity_disclosure".to_string(),
                severity: "medium".to_string(),
                description: "Device exposes detailed identity information including vendor, model, and serial number.".to_string(),
                remediation: Some("Restrict List Identity responses using network-level access controls.".to_string()),
            });
        }

        issues
    }
}

impl Default for EthernetIpScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for EthernetIpScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::EthernetIp
    }

    fn default_port(&self) -> u16 {
        self.default_port
    }

    async fn detect(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<bool> {
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let request = self.build_list_identity_request();
                if let Err(_) = stream.write_all(&request).await {
                    return Ok(false);
                }

                let mut buffer = vec![0u8; 256];
                match timeout(timeout_duration, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n >= 24 => {
                        // Check for List Identity response
                        Ok(buffer[0] == 0x63 && buffer[1] == 0x00)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    async fn scan(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<ProtocolScanResult> {
        let start = Instant::now();
        let mut result = ProtocolScanResult {
            protocol: OtProtocolType::EthernetIp,
            port: addr.port(),
            detected: false,
            details: ProtocolDetails::default(),
            security_issues: Vec::new(),
            response_time_ms: 0,
        };

        let mut stream = match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(result),
        };

        // Send List Identity request
        let request = self.build_list_identity_request();
        if let Ok(_) = stream.write_all(&request).await {
            let mut buffer = vec![0u8; 1024];
            if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
                buffer.truncate(n);

                if n >= 24 && buffer[0] == 0x63 {
                    result.detected = true;

                    if let Some(details) = self.parse_list_identity(&buffer) {
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
