//! OPC UA (Open Platform Communications Unified Architecture) Scanner
//!
//! Scans for OPC UA servers commonly used for industrial automation data exchange.

use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use crate::ot_ics::protocols::{ProtocolScanner, ProtocolScanResult};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// OPC UA Scanner
pub struct OpcUaScanner {
    default_port: u16,
}

impl OpcUaScanner {
    pub fn new() -> Self {
        Self { default_port: 4840 }
    }

    /// Build an OPC UA Hello message
    fn build_hello_message(&self) -> Vec<u8> {
        // OPC UA Hello message structure
        let endpoint = b"opc.tcp://localhost:4840";
        let endpoint_len = endpoint.len() as u32;

        // Calculate message size
        let message_size = 8 + 4 + 4 + 4 + 4 + 4 + 4 + endpoint_len;

        let mut message = Vec::with_capacity(message_size as usize);

        // Message header
        message.extend_from_slice(b"HEL");      // Message type: Hello
        message.push(b'F');                       // Chunk type: Final
        message.extend_from_slice(&message_size.to_le_bytes()); // Message size

        // Hello message body
        message.extend_from_slice(&0u32.to_le_bytes());        // Protocol version
        message.extend_from_slice(&65535u32.to_le_bytes());    // Receive buffer size
        message.extend_from_slice(&65535u32.to_le_bytes());    // Send buffer size
        message.extend_from_slice(&4194304u32.to_le_bytes());  // Max message size
        message.extend_from_slice(&0u32.to_le_bytes());        // Max chunk count (0 = no limit)
        message.extend_from_slice(&endpoint_len.to_le_bytes()); // Endpoint URL length
        message.extend_from_slice(endpoint);                    // Endpoint URL

        message
    }

    /// Parse OPC UA Acknowledge message
    fn parse_acknowledge(&self, response: &[u8]) -> Option<ProtocolDetails> {
        if response.len() < 28 {
            return None;
        }

        // Check message type
        if &response[0..3] != b"ACK" {
            return None;
        }

        let mut details = ProtocolDetails::default();
        let mut metadata = serde_json::json!({});

        // Parse acknowledge fields
        let protocol_version = u32::from_le_bytes([response[8], response[9], response[10], response[11]]);
        let receive_buffer = u32::from_le_bytes([response[12], response[13], response[14], response[15]]);
        let send_buffer = u32::from_le_bytes([response[16], response[17], response[18], response[19]]);
        let max_message = u32::from_le_bytes([response[20], response[21], response[22], response[23]]);
        let max_chunk = u32::from_le_bytes([response[24], response[25], response[26], response[27]]);

        metadata["protocol_version"] = serde_json::Value::Number(protocol_version.into());
        metadata["receive_buffer_size"] = serde_json::Value::Number(receive_buffer.into());
        metadata["send_buffer_size"] = serde_json::Value::Number(send_buffer.into());
        metadata["max_message_size"] = serde_json::Value::Number(max_message.into());
        metadata["max_chunk_count"] = serde_json::Value::Number(max_chunk.into());

        details.version = Some(format!("OPC UA Protocol v{}", protocol_version));
        details.metadata = metadata;

        Some(details)
    }

    /// Parse OPC UA Error message
    fn parse_error(&self, response: &[u8]) -> Option<(u32, String)> {
        if response.len() < 16 {
            return None;
        }

        if &response[0..3] != b"ERR" {
            return None;
        }

        let error_code = u32::from_le_bytes([response[8], response[9], response[10], response[11]]);
        let reason_len = u32::from_le_bytes([response[12], response[13], response[14], response[15]]) as usize;

        let reason = if response.len() >= 16 + reason_len {
            String::from_utf8_lossy(&response[16..16 + reason_len]).to_string()
        } else {
            String::new()
        };

        Some((error_code, reason))
    }

    /// Identify OPC UA security issues
    fn identify_security_issues(&self, response: &[u8]) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        // Check if server accepted connection without security
        if response.len() >= 3 && &response[0..3] == b"ACK" {
            // Server accepted Hello - need to check security policies in GetEndpoints
            issues.push(SecurityIssue {
                issue_type: "security_mode_unknown".to_string(),
                severity: "info".to_string(),
                description: "OPC UA server accepted connection. Security mode and policies should be verified via GetEndpoints.".to_string(),
                remediation: Some("Verify that SecurityMode is set to SignAndEncrypt and only strong security policies are enabled.".to_string()),
            });
        }

        // General OPC UA security recommendations
        issues.push(SecurityIssue {
            issue_type: "check_security_policy".to_string(),
            severity: "medium".to_string(),
            description: "Ensure OPC UA server uses secure policies (Basic256Sha256 or higher) and SignAndEncrypt mode.".to_string(),
            remediation: Some("Configure server to use only Basic256Sha256 or Aes128_Sha256_RsaOaep security policies. Disable None policy.".to_string()),
        });

        issues.push(SecurityIssue {
            issue_type: "anonymous_access".to_string(),
            severity: "high".to_string(),
            description: "Check if OPC UA server allows anonymous access. Anonymous access should be disabled in production.".to_string(),
            remediation: Some("Disable anonymous user token type. Require username/password or certificate-based authentication.".to_string()),
        });

        issues
    }
}

impl Default for OpcUaScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for OpcUaScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::OpcUa
    }

    fn default_port(&self) -> u16 {
        self.default_port
    }

    async fn detect(&self, addr: SocketAddr, timeout_duration: Duration) -> Result<bool> {
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                let hello = self.build_hello_message();
                if let Err(_) = stream.write_all(&hello).await {
                    return Ok(false);
                }

                let mut buffer = vec![0u8; 256];
                match timeout(timeout_duration, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n >= 8 => {
                        // Check for ACK or ERR message type
                        Ok(&buffer[0..3] == b"ACK" || &buffer[0..3] == b"ERR")
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
            protocol: OtProtocolType::OpcUa,
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

        // Send Hello message
        let hello = self.build_hello_message();
        if let Ok(_) = stream.write_all(&hello).await {
            let mut buffer = vec![0u8; 512];
            if let Ok(Ok(n)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
                buffer.truncate(n);

                if n >= 8 {
                    // Check for Acknowledge response
                    if &buffer[0..3] == b"ACK" {
                        result.detected = true;
                        if let Some(details) = self.parse_acknowledge(&buffer) {
                            result.details = details;
                        }
                    }
                    // Check for Error response (still indicates OPC UA server)
                    else if &buffer[0..3] == b"ERR" {
                        result.detected = true;
                        if let Some((code, reason)) = self.parse_error(&buffer) {
                            result.details.metadata = serde_json::json!({
                                "error_code": code,
                                "error_reason": reason
                            });
                        }
                    }

                    if result.detected {
                        result.security_issues = self.identify_security_issues(&buffer);
                    }
                }
            }
        }

        result.response_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }
}
