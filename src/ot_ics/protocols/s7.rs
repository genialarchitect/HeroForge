//! Siemens S7 Protocol Scanner
//!
//! Scans for Siemens S7 PLCs (S7-200, S7-300, S7-400, S7-1200, S7-1500).

use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use crate::ot_ics::protocols::{ProtocolScanner, ProtocolScanResult};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// S7 Protocol Scanner
pub struct S7Scanner {
    default_port: u16,
}

impl S7Scanner {
    pub fn new() -> Self {
        Self { default_port: 102 }
    }

    /// Build COTP Connection Request (ISO-on-TCP)
    fn build_cotp_connect_request(&self) -> Vec<u8> {
        vec![
            // TPKT Header
            0x03,       // Version
            0x00,       // Reserved
            0x00, 0x16, // Length (22 bytes)

            // COTP Header
            0x11,       // Length
            0xE0,       // PDU Type: Connection Request
            0x00, 0x00, // Destination Reference
            0x00, 0x01, // Source Reference
            0x00,       // Class + Options

            // Parameter: Source TSAP
            0xC1,       // Parameter code
            0x02,       // Parameter length
            0x01, 0x00, // Source TSAP (rack 0, slot 2)

            // Parameter: Destination TSAP
            0xC2,       // Parameter code
            0x02,       // Parameter length
            0x01, 0x02, // Destination TSAP (rack 0, slot 2)

            // Parameter: TPDU Size
            0xC0,       // Parameter code
            0x01,       // Parameter length
            0x0A,       // TPDU size (1024 bytes)
        ]
    }

    /// Build S7 Communication Setup request
    fn build_s7_setup_request(&self) -> Vec<u8> {
        vec![
            // TPKT Header
            0x03, 0x00,
            0x00, 0x19, // Length (25 bytes)

            // COTP Header
            0x02,       // Length
            0xF0,       // PDU Type: Data
            0x80,       // TPDU number + EOT

            // S7 Comm Header
            0x32,       // Protocol ID
            0x01,       // ROSCTR: Job
            0x00, 0x00, // Redundancy Identification
            0x00, 0x00, // Protocol Data Unit Reference
            0x00, 0x08, // Parameter Length
            0x00, 0x00, // Data Length

            // S7 Setup Communication parameter
            0xF0,       // Function: Setup Communication
            0x00,       // Reserved
            0x00, 0x01, // Max AmQ Calling
            0x00, 0x01, // Max AmQ Called
            0x01, 0xE0, // PDU Length (480)
        ]
    }

    /// Build S7 Read SZL (System Status List) request
    fn build_szl_request(&self, szl_id: u16, szl_index: u16) -> Vec<u8> {
        vec![
            // TPKT Header
            0x03, 0x00,
            0x00, 0x21, // Length (33 bytes)

            // COTP Header
            0x02,
            0xF0,
            0x80,

            // S7 Comm Header
            0x32,
            0x07,       // ROSCTR: Userdata
            0x00, 0x00,
            0x00, 0x01, // PDU Reference
            0x00, 0x0C, // Parameter Length
            0x00, 0x04, // Data Length

            // S7 Userdata Parameter
            0x00, 0x01, 0x12,
            0x04,       // Parameter length
            0x11,       // Type: Request
            0x44,       // Function Group: CPU functions, Subfunction: Read SZL
            0x01,       // Sequence number
            0x00,       // Data Unit Reference Number

            // S7 Data
            0xFF,       // Return code
            0x09,       // Transport size: Octet string
            0x00, 0x04, // Length
            (szl_id & 0xFF) as u8,
            ((szl_id >> 8) & 0xFF) as u8,
            (szl_index & 0xFF) as u8,
            ((szl_index >> 8) & 0xFF) as u8,
        ]
    }

    /// Parse COTP Connection Confirm
    fn parse_cotp_response(&self, response: &[u8]) -> bool {
        if response.len() < 7 {
            return false;
        }
        // Check TPKT version and COTP Connection Confirm
        response[0] == 0x03 && response[4] >= 0x02 && response[5] == 0xD0
    }

    /// Parse S7 Communication Setup response
    fn parse_s7_setup_response(&self, response: &[u8]) -> Option<ProtocolDetails> {
        if response.len() < 20 {
            return None;
        }

        // Find S7 header (0x32)
        let s7_offset = response.iter().position(|&b| b == 0x32)?;
        if response.len() < s7_offset + 12 {
            return None;
        }

        let mut details = ProtocolDetails::default();
        let mut metadata = serde_json::json!({});

        // Check for Ack_Data response
        if response[s7_offset + 1] == 0x03 {
            // Parse negotiated PDU length
            if response.len() >= s7_offset + 18 {
                let pdu_length = ((response[s7_offset + 16] as u16) << 8) | (response[s7_offset + 17] as u16);
                metadata["negotiated_pdu_length"] = serde_json::Value::Number(pdu_length.into());
            }
        }

        details.metadata = metadata;
        Some(details)
    }

    /// Parse SZL (System Status List) response
    fn parse_szl_response(&self, response: &[u8]) -> Option<ProtocolDetails> {
        if response.len() < 30 {
            return None;
        }

        let mut details = ProtocolDetails::default();
        let mut metadata = serde_json::json!({});

        // Find S7 data section
        let s7_offset = response.iter().position(|&b| b == 0x32)?;

        // SZL data starts after S7 header and parameters
        let data_offset = s7_offset + 12; // Approximate
        if response.len() <= data_offset + 10 {
            return Some(details);
        }

        // Try to extract readable strings from SZL data
        let data = &response[data_offset..];

        // Look for printable strings (module/order information)
        let mut i = 0;
        while i < data.len() {
            if data[i..].len() >= 20 {
                // Look for order number pattern (e.g., "6ES7 xxx-xxx")
                if let Ok(s) = String::from_utf8(data[i..std::cmp::min(i + 20, data.len())].to_vec()) {
                    if s.contains("6ES7") || s.contains("6ES5") || s.contains("6GK") {
                        if !metadata.get("order_number").is_some() {
                            let order = s.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                                .split_whitespace()
                                .next()
                                .unwrap_or("");
                            if order.len() > 5 {
                                metadata["order_number"] = serde_json::Value::String(order.to_string());
                                details.device_id = Some(format!("S7:{}", order));
                            }
                        }
                    }
                }
            }
            i += 1;
        }

        // Identify Siemens as vendor
        details.vendor_info = Some("Siemens".to_string());
        details.metadata = metadata;
        Some(details)
    }

    /// Identify S7 security issues
    fn identify_security_issues(&self, _response: &[u8]) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // S7 default has no authentication
        issues.push(SecurityIssue {
            issue_type: "no_authentication".to_string(),
            severity: "high".to_string(),
            description: "Siemens S7 protocol (by default) has no authentication. Access control relies on network segmentation.".to_string(),
            remediation: Some("Enable S7 communication protection (CPU Protection Level), implement network segmentation, and use firewall rules.".to_string()),
        });

        // Cleartext protocol
        issues.push(SecurityIssue {
            issue_type: "cleartext_protocol".to_string(),
            severity: "medium".to_string(),
            description: "S7 communication is unencrypted. All data including programs and process values transmitted in cleartext.".to_string(),
            remediation: Some("Use VPN tunnels for remote access. Consider S7-1500 with TLS support if available.".to_string()),
        });

        // CPU mode accessible
        issues.push(SecurityIssue {
            issue_type: "cpu_mode_readable".to_string(),
            severity: "low".to_string(),
            description: "CPU mode and diagnostic information can be read remotely without authentication.".to_string(),
            remediation: Some("Configure access protection in TIA Portal/STEP 7. Limit network access to engineering stations.".to_string()),
        });

        issues
    }
}

impl Default for S7Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for S7Scanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::S7
    }

    fn default_port(&self) -> u16 {
        self.default_port
    }

    async fn detect(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<bool> {
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send COTP Connection Request
                let request = self.build_cotp_connect_request();
                if let Err(_) = stream.write_all(&request).await {
                    return Ok(false);
                }

                let mut buffer = vec![0u8; 256];
                match timeout(timeout_duration, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n >= 7 => Ok(self.parse_cotp_response(&buffer[..n])),
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    async fn scan(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<ProtocolScanResult> {
        let start = Instant::now();
        let mut result = ProtocolScanResult {
            protocol: OtProtocolType::S7,
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

        // Step 1: COTP Connection
        let cotp_request = self.build_cotp_connect_request();
        if let Err(_) = stream.write_all(&cotp_request).await {
            return Ok(result);
        }

        let mut buffer = vec![0u8; 512];
        if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if !self.parse_cotp_response(&buffer[..n]) {
                return Ok(result);
            }
            result.detected = true;
        } else {
            return Ok(result);
        }

        // Step 2: S7 Communication Setup
        let s7_setup = self.build_s7_setup_request();
        if let Ok(_) = stream.write_all(&s7_setup).await {
            if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
                if let Some(details) = self.parse_s7_setup_response(&buffer[..n]) {
                    result.details = details;
                }
            }
        }

        // Step 3: Try to read SZL (module identification)
        let szl_request = self.build_szl_request(0x0011, 0x0000); // SZL ID for module identification
        if let Ok(_) = stream.write_all(&szl_request).await {
            if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
                if let Some(details) = self.parse_szl_response(&buffer[..n]) {
                    // Merge with existing details
                    if let Some(vendor) = details.vendor_info {
                        result.details.vendor_info = Some(vendor);
                    }
                    if let Some(device_id) = details.device_id {
                        result.details.device_id = Some(device_id);
                    }
                    // Merge metadata
                    if let Some(obj) = details.metadata.as_object() {
                        if let Some(existing) = result.details.metadata.as_object_mut() {
                            for (k, v) in obj {
                                existing.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
            }
        }

        result.security_issues = self.identify_security_issues(&buffer);
        result.response_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }
}
