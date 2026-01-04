//! MQTT Protocol Scanner
//!
//! Scans for MQTT brokers commonly used in IIoT environments.

use super::{ProtocolScanResult, ProtocolScanner};
use crate::ot_ics::types::{OtProtocolType, ProtocolDetails, SecurityIssue};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// MQTT scanner for IIoT environments
pub struct MqttScanner;

impl MqttScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MqttScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProtocolScanner for MqttScanner {
    fn protocol_type(&self) -> OtProtocolType {
        OtProtocolType::Mqtt
    }

    fn default_port(&self) -> u16 {
        1883 // MQTT default, 8883 for TLS
    }

    async fn detect(&self, addr: SocketAddr, dur: Duration) -> Result<bool> {
        match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Send MQTT CONNECT packet
                let connect = build_mqtt_connect();

                if stream.write_all(&connect).await.is_err() {
                    return Ok(false);
                }

                let mut buf = [0u8; 256];
                match timeout(dur, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n >= 4 => {
                        // Check for CONNACK (packet type 0x20)
                        if buf[0] == 0x20 {
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
            device_id: Some("MQTT Broker".to_string()),
            version: None,
            vendor_info: None,
            metadata: serde_json::json!({}),
        };

        if detected {
            if let Ok(info) = get_mqtt_info(addr, dur).await {
                details.version = info.version.clone();
                details.metadata = serde_json::json!({
                    "anonymous_allowed": info.anonymous_allowed,
                    "protocol_version": info.version.unwrap_or_else(|| "unknown".to_string())
                });

                if info.anonymous_allowed {
                    security_issues.push(SecurityIssue {
                        issue_type: "Authentication".to_string(),
                        severity: "Critical".to_string(),
                        description: "MQTT broker allows connections without authentication".to_string(),
                        remediation: Some("Enable authentication and require username/password".to_string()),
                    });
                }

                if !info.uses_tls {
                    security_issues.push(SecurityIssue {
                        issue_type: "Encryption".to_string(),
                        severity: "High".to_string(),
                        description: "MQTT traffic is not encrypted".to_string(),
                        remediation: Some("Configure TLS on port 8883".to_string()),
                    });
                }

                if info.allows_wildcard_subscribe {
                    security_issues.push(SecurityIssue {
                        issue_type: "Access Control".to_string(),
                        severity: "Medium".to_string(),
                        description: "Broker allows subscribing to all topics with #".to_string(),
                        remediation: Some("Implement topic-level ACLs to restrict subscriptions".to_string()),
                    });
                }
            }
        }

        Ok(ProtocolScanResult {
            protocol: OtProtocolType::Mqtt,
            port: addr.port(),
            detected,
            details,
            security_issues,
            response_time_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Build MQTT CONNECT packet
fn build_mqtt_connect() -> Vec<u8> {
    let mut packet = Vec::new();

    // Variable header + Payload
    let mut var_header = Vec::new();

    // Protocol Name (MQTT)
    var_header.push(0x00);
    var_header.push(0x04);
    var_header.extend_from_slice(b"MQTT");

    // Protocol Level (4 = MQTT 3.1.1)
    var_header.push(0x04);

    // Connect Flags (Clean Session)
    var_header.push(0x02);

    // Keep Alive (60 seconds)
    var_header.push(0x00);
    var_header.push(0x3C);

    // Client ID (anonymous probe)
    let client_id = "heroforge-probe";
    var_header.push(0x00);
    var_header.push(client_id.len() as u8);
    var_header.extend_from_slice(client_id.as_bytes());

    // Fixed header
    packet.push(0x10); // CONNECT packet type

    // Remaining length encoding
    let remaining_len = var_header.len();
    if remaining_len < 128 {
        packet.push(remaining_len as u8);
    } else {
        packet.push((remaining_len & 0x7F | 0x80) as u8);
        packet.push((remaining_len >> 7) as u8);
    }

    packet.extend_from_slice(&var_header);
    packet
}

struct MqttInfo {
    version: Option<String>,
    anonymous_allowed: bool,
    uses_tls: bool,
    allows_wildcard_subscribe: bool,
}

async fn get_mqtt_info(addr: SocketAddr, dur: Duration) -> Result<MqttInfo> {
    let mut info = MqttInfo {
        version: None,
        anonymous_allowed: false,
        uses_tls: addr.port() == 8883,
        allows_wildcard_subscribe: false,
    };

    if let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await {
        // Try anonymous connect
        let connect = build_mqtt_connect();
        stream.write_all(&connect).await?;

        let mut buf = [0u8; 256];
        if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
            if n >= 4 && buf[0] == 0x20 {
                // CONNACK received
                let return_code = buf[3];
                if return_code == 0x00 {
                    info.anonymous_allowed = true;
                    info.version = Some("MQTT 3.1.1".to_string());

                    // Try subscribing to wildcard
                    let subscribe = build_mqtt_subscribe_wildcard();
                    stream.write_all(&subscribe).await?;

                    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
                        if n >= 4 && buf[0] == 0x90 {
                            // SUBACK
                            if buf[4] != 0x80 {
                                info.allows_wildcard_subscribe = true;
                            }
                        }
                    }

                    // Disconnect
                    let _ = stream.write_all(&[0xE0, 0x00]).await;
                }
            }
        }
    }

    Ok(info)
}

fn build_mqtt_subscribe_wildcard() -> Vec<u8> {
    let mut packet = Vec::new();

    // SUBSCRIBE packet
    packet.push(0x82); // SUBSCRIBE with QoS 1

    // Variable header + payload
    let mut var_header = Vec::new();
    // Packet Identifier
    var_header.push(0x00);
    var_header.push(0x01);
    // Topic Filter: #
    var_header.push(0x00);
    var_header.push(0x01);
    var_header.push(b'#');
    // QoS
    var_header.push(0x00);

    packet.push(var_header.len() as u8);
    packet.extend_from_slice(&var_header);
    packet
}
