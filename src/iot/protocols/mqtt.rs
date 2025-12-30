//! MQTT Protocol Scanner
//!
//! Scans for MQTT brokers and identifies security issues.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// MQTT Scanner
pub struct MqttScanner {
    timeout: Duration,
}

impl MqttScanner {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Scan an MQTT broker
    pub async fn scan(&self, addr: SocketAddr) -> Result<MqttScanResult> {
        let start = Instant::now();
        let mut result = MqttScanResult {
            detected: false,
            port: addr.port(),
            protocol_version: None,
            allows_anonymous: false,
            server_info: None,
            topics_accessible: false,
            security_issues: Vec::new(),
            response_time_ms: 0,
        };

        // Try to connect
        let mut stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(result),
        };

        // Test anonymous access first
        if self.test_anonymous_access(&mut stream).await? {
            result.detected = true;
            result.allows_anonymous = true;
            result.security_issues.push(MqttSecurityIssue {
                issue_type: "anonymous_access".to_string(),
                severity: "high".to_string(),
                description: "MQTT broker allows anonymous connections without authentication".to_string(),
                remediation: Some("Configure MQTT broker to require username/password authentication".to_string()),
            });

            // Try to list topics
            if let Ok(topics_result) = self.try_list_topics(&addr).await {
                result.topics_accessible = topics_result;
                if topics_result {
                    result.security_issues.push(MqttSecurityIssue {
                        issue_type: "topics_exposed".to_string(),
                        severity: "medium".to_string(),
                        description: "MQTT topics are accessible without proper ACL restrictions".to_string(),
                        remediation: Some("Implement topic-level ACLs to restrict access to sensitive topics".to_string()),
                    });
                }
            }
        } else {
            // Try with auth - reconnect since connection may be closed
            if let Ok(Ok(mut stream)) = timeout(self.timeout, TcpStream::connect(addr)).await {
                if self.test_auth_required(&mut stream).await? {
                    result.detected = true;
                }
            }
        }

        // Check for TLS
        if addr.port() == 1883 {
            result.security_issues.push(MqttSecurityIssue {
                issue_type: "no_tls".to_string(),
                severity: "medium".to_string(),
                description: "MQTT broker is accessible on non-TLS port 1883".to_string(),
                remediation: Some("Configure MQTT broker to require TLS on port 8883".to_string()),
            });
        }

        result.response_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Test anonymous access
    async fn test_anonymous_access(&self, stream: &mut TcpStream) -> Result<bool> {
        // Send CONNECT without credentials
        let connect_packet = vec![
            0x10, // CONNECT packet type
            0x12, // Remaining length
            0x00, 0x04, // Protocol name length
            b'M', b'Q', b'T', b'T',
            0x04, // Protocol version (MQTT 3.1.1)
            0x02, // Connect flags: clean session only
            0x00, 0x3C, // Keep alive (60 seconds)
            0x00, 0x06, // Client ID length
            b't', b'e', b's', b't', b'e', b'r',
        ];

        stream.write_all(&connect_packet).await?;

        let mut buffer = vec![0u8; 32];
        if let Ok(Ok(n)) = timeout(self.timeout, stream.read(&mut buffer)).await {
            if n >= 4 && buffer[0] == 0x20 {
                // CONNACK received
                let return_code = buffer[3];
                return Ok(return_code == 0); // 0 = Connection Accepted
            }
        }

        Ok(false)
    }

    /// Test if authentication is required
    async fn test_auth_required(&self, stream: &mut TcpStream) -> Result<bool> {
        // Send CONNECT without credentials
        let connect_packet = vec![
            0x10, 0x12,
            0x00, 0x04, b'M', b'Q', b'T', b'T',
            0x04, 0x02, 0x00, 0x3C,
            0x00, 0x06, b't', b'e', b's', b't', b'e', b'r',
        ];

        stream.write_all(&connect_packet).await?;

        let mut buffer = vec![0u8; 32];
        if let Ok(Ok(n)) = timeout(self.timeout, stream.read(&mut buffer)).await {
            if n >= 4 && buffer[0] == 0x20 {
                let return_code = buffer[3];
                // 4 = Bad User Name or Password, 5 = Not Authorized
                return Ok(return_code == 4 || return_code == 5);
            }
        }

        Ok(false)
    }

    /// Try to subscribe to wildcard topic
    async fn try_list_topics(&self, addr: &SocketAddr) -> Result<bool> {
        let mut stream = match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        // Connect first
        let connect_packet = vec![
            0x10, 0x12,
            0x00, 0x04, b'M', b'Q', b'T', b'T',
            0x04, 0x02, 0x00, 0x3C,
            0x00, 0x06, b't', b'e', b's', b't', b'e', b'r',
        ];

        stream.write_all(&connect_packet).await?;

        let mut buffer = vec![0u8; 32];
        if let Ok(Ok(n)) = timeout(self.timeout, stream.read(&mut buffer)).await {
            if n >= 4 && buffer[0] == 0x20 && buffer[3] != 0 {
                return Ok(false);
            }
        }

        // Subscribe to # (all topics)
        let subscribe_packet = vec![
            0x82, // SUBSCRIBE packet type
            0x05, // Remaining length
            0x00, 0x01, // Packet identifier
            0x00, 0x01, // Topic filter length
            b'#', // Topic filter
            0x00, // QoS 0
        ];

        stream.write_all(&subscribe_packet).await?;

        let mut buffer = vec![0u8; 32];
        if let Ok(Ok(n)) = timeout(self.timeout, stream.read(&mut buffer)).await {
            if n >= 5 && buffer[0] == 0x90 {
                // SUBACK received
                let return_code = buffer[4];
                return Ok(return_code != 0x80); // 0x80 = Failure
            }
        }

        Ok(false)
    }
}

impl Default for MqttScanner {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

/// MQTT scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttScanResult {
    pub detected: bool,
    pub port: u16,
    pub protocol_version: Option<String>,
    pub allows_anonymous: bool,
    pub server_info: Option<String>,
    pub topics_accessible: bool,
    pub security_issues: Vec<MqttSecurityIssue>,
    pub response_time_ms: u64,
}

/// MQTT security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttSecurityIssue {
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub remediation: Option<String>,
}
