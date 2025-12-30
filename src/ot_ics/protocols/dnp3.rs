//! DNP3 (Distributed Network Protocol 3) Scanner
//!
//! Scans for DNP3 devices commonly used in SCADA systems for electric and water utilities.

use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use crate::ot_ics::protocols::{ProtocolScanner, ProtocolScanResult};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// DNP3 Scanner
pub struct Dnp3Scanner {
    default_port: u16,
}

impl Dnp3Scanner {
    pub fn new() -> Self {
        Self { default_port: 20000 }
    }

    /// Build a DNP3 Read request (for device attribute discovery)
    fn build_read_request(&self, destination: u16, source: u16) -> Vec<u8> {
        // DNP3 Data Link Layer frame
        // Start bytes (0x0564) + Length + Control + Destination + Source + CRC
        let mut frame = vec![
            0x05, 0x64, // Start bytes
            0x05,       // Length (header only for now)
            0xC0,       // Control: DIR=1, PRM=1, FCV=0, FCB=0, Function=0 (Reset Link)
            (destination & 0xFF) as u8, // Destination LSB
            ((destination >> 8) & 0xFF) as u8, // Destination MSB
            (source & 0xFF) as u8, // Source LSB
            ((source >> 8) & 0xFF) as u8, // Source MSB
        ];

        // Add CRC for data link header
        let crc = self.calculate_crc(&frame[..8]);
        frame.push((crc & 0xFF) as u8);
        frame.push(((crc >> 8) & 0xFF) as u8);

        frame
    }

    /// Build a DNP3 Link Status request
    fn build_link_status_request(&self, destination: u16, source: u16) -> Vec<u8> {
        let mut frame = vec![
            0x05, 0x64, // Start bytes
            0x05,       // Length
            0xC9,       // Control: DIR=1, PRM=1, FCV=0, FCB=0, Function=9 (Request Link Status)
            (destination & 0xFF) as u8,
            ((destination >> 8) & 0xFF) as u8,
            (source & 0xFF) as u8,
            ((source >> 8) & 0xFF) as u8,
        ];

        let crc = self.calculate_crc(&frame[..8]);
        frame.push((crc & 0xFF) as u8);
        frame.push(((crc >> 8) & 0xFF) as u8);

        frame
    }

    /// Calculate DNP3 CRC-16
    fn calculate_crc(&self, data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for &byte in data {
            crc = self.update_crc(crc, byte);
        }
        !crc
    }

    fn update_crc(&self, crc: u16, byte: u8) -> u16 {
        const CRC_TABLE: [u16; 256] = [
            0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
            0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
            0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
            0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
            0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
            0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
            0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
            0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
            0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
            0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
            0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
            0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
            0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
            0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
            0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
            0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
            0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
            0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
            0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
            0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
            0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
            0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
            0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
            0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
            0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
            0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
            0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
            0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
            0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
            0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
            0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
            0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235,
        ];
        CRC_TABLE[((crc ^ (byte as u16)) & 0xFF) as usize] ^ (crc >> 8)
    }

    /// Parse DNP3 response and extract details
    fn parse_response(&self, response: &[u8]) -> Option<ProtocolDetails> {
        if response.len() < 10 {
            return None;
        }

        // Verify start bytes
        if response[0] != 0x05 || response[1] != 0x64 {
            return None;
        }

        let mut details = ProtocolDetails::default();
        let mut metadata = serde_json::json!({});

        // Extract source and destination addresses
        let destination = (response[4] as u16) | ((response[5] as u16) << 8);
        let source = (response[6] as u16) | ((response[7] as u16) << 8);

        metadata["dnp3_source_address"] = serde_json::Value::Number(source.into());
        metadata["dnp3_destination_address"] = serde_json::Value::Number(destination.into());

        // Control byte analysis
        let control = response[3];
        metadata["direction_primary"] = serde_json::Value::Bool((control & 0x80) != 0);
        metadata["function_code"] = serde_json::Value::Number((control & 0x0F).into());

        details.device_id = Some(format!("DNP3:{}", source));
        details.metadata = metadata;
        Some(details)
    }

    /// Identify DNP3-specific security issues
    fn identify_security_issues(&self, _response: &[u8]) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // DNP3 standard has no authentication (unless Secure Authentication is used)
        issues.push(SecurityIssue {
            issue_type: "no_authentication".to_string(),
            severity: "high".to_string(),
            description: "Standard DNP3 protocol lacks authentication. DNP3 Secure Authentication (SA) may not be enabled.".to_string(),
            remediation: Some("Enable DNP3 Secure Authentication (SA) per IEC 62351-5 if supported by the device.".to_string()),
        });

        // Cleartext communication
        issues.push(SecurityIssue {
            issue_type: "cleartext_protocol".to_string(),
            severity: "medium".to_string(),
            description: "DNP3 transmits data in cleartext, allowing potential eavesdropping of process data.".to_string(),
            remediation: Some("Use encrypted VPN tunnels or implement TLS bump-in-the-wire solutions.".to_string()),
        });

        issues
    }
}

impl Default for Dnp3Scanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for Dnp3Scanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Dnp3
    }

    fn default_port(&self) -> u16 {
        self.default_port
    }

    async fn detect(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<bool> {
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let request = self.build_link_status_request(1, 3);
                if let Err(_) = stream.write_all(&request).await {
                    return Ok(false);
                }

                let mut buffer = vec![0u8; 256];
                match timeout(timeout_duration, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n >= 10 => {
                        // Check for DNP3 start bytes
                        Ok(buffer[0] == 0x05 && buffer[1] == 0x64)
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
            protocol: OtProtocolType::Dnp3,
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

        // Send link status request
        let request = self.build_link_status_request(1, 3);
        if let Ok(_) = stream.write_all(&request).await {
            let mut buffer = vec![0u8; 512];
            if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
                buffer.truncate(n);
                if n >= 10 && buffer[0] == 0x05 && buffer[1] == 0x64 {
                    result.detected = true;

                    if let Some(details) = self.parse_response(&buffer) {
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
