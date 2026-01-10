//! Modbus Protocol Scanner
//!
//! Scans for Modbus TCP devices and extracts device information.
//! Modbus is commonly used in PLCs, RTUs, and other industrial devices.

use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use crate::ot_ics::protocols::{ProtocolScanner, ProtocolScanResult};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Modbus TCP Scanner
pub struct ModbusScanner {
    /// Default Modbus TCP port
    default_port: u16,
}

impl ModbusScanner {
    pub fn new() -> Self {
        Self { default_port: 502 }
    }

    /// Build a Modbus Read Device Identification request (function code 0x2B, MEI type 0x0E)
    fn build_device_id_request(&self, unit_id: u8) -> Vec<u8> {
        // Modbus TCP ADU structure:
        // Transaction ID (2 bytes) + Protocol ID (2 bytes) + Length (2 bytes) + Unit ID (1 byte) + PDU
        let request = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID (Modbus)
            0x00, 0x05, // Length (5 bytes follow)
            unit_id,    // Unit Identifier
            0x2B,       // Function Code: Encapsulated Interface Transport (43)
            0x0E,       // MEI Type: Read Device Identification
            0x01,       // Read Device ID Code: Basic
            0x00,       // Object ID: Start at VendorName
        ];
        request
    }

    /// Build a simple Modbus request to check if device responds
    fn build_read_holding_registers_request(&self, unit_id: u8) -> Vec<u8> {
        vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID
            0x00, 0x06, // Length
            unit_id,    // Unit ID
            0x03,       // Function Code: Read Holding Registers
            0x00, 0x00, // Starting Address
            0x00, 0x01, // Quantity of Registers
        ]
    }

    /// Parse Modbus device identification response
    fn parse_device_id_response(&self, response: &[u8]) -> Option<ProtocolDetails> {
        // Minimum response: 7 (MBAP header) + 3 (function code, MEI type, read device id code)
        if response.len() < 10 {
            return None;
        }

        // Check function code (should be 0x2B for device identification)
        if response[7] != 0x2B && response[7] != 0xAB {
            return None;
        }

        let mut details = ProtocolDetails::default();
        let mut metadata = serde_json::json!({});

        // Parse object list starting at byte 11
        if response.len() > 11 {
            let mut pos = 11;
            let mut objects: std::collections::HashMap<u8, String> = std::collections::HashMap::new();

            while pos + 2 < response.len() {
                let object_id = response[pos];
                let object_len = response[pos + 1] as usize;
                pos += 2;

                if pos + object_len <= response.len() {
                    if let Ok(value) = String::from_utf8(response[pos..pos + object_len].to_vec()) {
                        objects.insert(object_id, value.clone());
                        match object_id {
                            0x00 => {
                                details.vendor_info = Some(value);
                            }
                            0x01 => {
                                metadata["product_code"] = serde_json::Value::String(value);
                            }
                            0x02 => {
                                details.version = Some(value);
                            }
                            0x03 => {
                                metadata["vendor_url"] = serde_json::Value::String(value);
                            }
                            0x04 => {
                                metadata["product_name"] = serde_json::Value::String(value);
                            }
                            0x05 => {
                                metadata["model_name"] = serde_json::Value::String(value);
                            }
                            0x06 => {
                                metadata["user_app_name"] = serde_json::Value::String(value);
                            }
                            _ => {}
                        }
                    }
                }
                pos += object_len;
            }
        }

        details.metadata = metadata;
        Some(details)
    }

    /// Identify security issues
    fn identify_security_issues(&self, response: &[u8]) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // Issue: Modbus TCP has no built-in authentication
        issues.push(SecurityIssue {
            issue_type: "no_authentication".to_string(),
            severity: "high".to_string(),
            description: "Modbus TCP protocol has no built-in authentication mechanism. Any network-accessible client can read/write registers.".to_string(),
            remediation: Some("Implement network segmentation, firewall rules, and consider using Modbus/TCP security extensions or VPN tunnels.".to_string()),
        });

        // Issue: Modbus uses cleartext communication
        issues.push(SecurityIssue {
            issue_type: "cleartext_protocol".to_string(),
            severity: "medium".to_string(),
            description: "Modbus TCP transmits all data in cleartext, including register values and device information.".to_string(),
            remediation: Some("Use encrypted VPN tunnels for Modbus communication or implement TLS-secured Modbus gateways.".to_string()),
        });

        // Check for broadcast unit ID (0x00 or 0xFF)
        if response.len() > 6 {
            let unit_id = response[6];
            if unit_id == 0x00 || unit_id == 0xFF {
                issues.push(SecurityIssue {
                    issue_type: "broadcast_enabled".to_string(),
                    severity: "low".to_string(),
                    description: format!("Device responds to broadcast unit ID (0x{:02X}), which may allow unintended access.", unit_id),
                    remediation: Some("Configure device to only respond to specific unit IDs.".to_string()),
                });
            }
        }

        issues
    }
}

impl Default for ModbusScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for ModbusScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Modbus
    }

    fn default_port(&self) -> u16 {
        self.default_port
    }

    async fn detect(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<bool> {
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send a read holding registers request
                let request = self.build_read_holding_registers_request(1);
                if let Err(_) = stream.write_all(&request).await {
                    return Ok(false);
                }

                // Read response
                let mut buffer = vec![0u8; 256];
                match timeout(timeout_duration, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n >= 7 => {
                        // Check for Modbus protocol ID (bytes 2-3 should be 0x0000)
                        Ok(buffer[2] == 0x00 && buffer[3] == 0x00)
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
            protocol: OtProtocolType::Modbus,
            port: addr.port(),
            detected: false,
            details: ProtocolDetails::default(),
            security_issues: Vec::new(),
            response_time_ms: 0,
        };

        // Connect to target
        let mut stream = match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(result),
        };

        // Try to get device identification first
        let device_id_request = self.build_device_id_request(1);
        if let Ok(_) = stream.write_all(&device_id_request).await {
            let mut buffer = vec![0u8; 512];
            if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
                if n >= 10 && buffer[2] == 0x00 && buffer[3] == 0x00 {
                    result.detected = true;
                    buffer.truncate(n);

                    if let Some(details) = self.parse_device_id_response(&buffer) {
                        result.details = details;
                    }
                    result.security_issues = self.identify_security_issues(&buffer);
                }
            }
        }

        // If device ID didn't work, try basic read
        if !result.detected {
            // Reconnect if needed
            if let Ok(Ok(mut stream)) = timeout(timeout_duration, TcpStream::connect(addr)).await {
                let request = self.build_read_holding_registers_request(1);
                if let Ok(_) = stream.write_all(&request).await {
                    let mut buffer = vec![0u8; 256];
                    if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
                        if n >= 7 && buffer[2] == 0x00 && buffer[3] == 0x00 {
                            result.detected = true;
                            buffer.truncate(n);
                            result.security_issues = self.identify_security_issues(&buffer);
                        }
                    }
                }
            }
        }

        result.response_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_requests() {
        let scanner = ModbusScanner::new();

        let device_id = scanner.build_device_id_request(1);
        assert_eq!(device_id.len(), 11);
        assert_eq!(device_id[7], 0x2B); // Function code

        let read_regs = scanner.build_read_holding_registers_request(1);
        assert_eq!(read_regs.len(), 12);
        assert_eq!(read_regs[7], 0x03); // Function code
    }
}
