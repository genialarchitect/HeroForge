//! CoAP (Constrained Application Protocol) Scanner
//!
//! Scans for CoAP devices commonly used in IoT sensors and constrained devices.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// CoAP Scanner
pub struct CoapScanner {
    timeout: Duration,
}

impl CoapScanner {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Scan a CoAP endpoint
    pub async fn scan(&self, addr: SocketAddr) -> Result<CoapScanResult> {
        let start = Instant::now();
        let mut result = CoapScanResult {
            detected: false,
            port: addr.port(),
            resources: Vec::new(),
            security_issues: Vec::new(),
            response_time_ms: 0,
        };

        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return Ok(result),
        };

        // Send CoAP GET request for .well-known/core (resource discovery)
        let discover_request = self.build_get_request("/.well-known/core");
        if let Err(_) = socket.send_to(&discover_request, addr).await {
            return Ok(result);
        }

        let mut buffer = vec![0u8; 4096];
        if let Ok(Ok((n, _))) = timeout(self.timeout, socket.recv_from(&mut buffer)).await {
            buffer.truncate(n);
            if self.is_coap_response(&buffer) {
                result.detected = true;

                // Parse resources from response
                if let Some(resources) = self.parse_link_format(&buffer) {
                    result.resources = resources;
                }

                // Identify security issues
                result.security_issues = self.identify_security_issues(&buffer);
            }
        }

        result.response_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Build a CoAP GET request
    fn build_get_request(&self, path: &str) -> Vec<u8> {
        let mut packet = vec![
            0x40, // Version 1, Type: Confirmable (0), Token Length: 0
            0x01, // Code: GET
            0x00, 0x01, // Message ID
        ];

        // Add Uri-Path options
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            // Option delta: 11 (Uri-Path)
            let len = segment.len();
            if len < 13 {
                packet.push(0xB0 | (len as u8)); // Delta 11, Length
            } else {
                packet.push(0xBD); // Delta 11, Length Extended
                packet.push((len - 13) as u8);
            }
            packet.extend_from_slice(segment.as_bytes());
        }

        packet
    }

    /// Check if response is a valid CoAP message
    fn is_coap_response(&self, response: &[u8]) -> bool {
        if response.len() < 4 {
            return false;
        }

        // Check version (should be 1)
        let version = (response[0] >> 6) & 0x03;
        if version != 1 {
            return false;
        }

        // Check if it's a response (code class 2.xx, 4.xx, or 5.xx)
        let code_class = (response[1] >> 5) & 0x07;
        code_class >= 2
    }

    /// Parse CoRE Link Format response
    fn parse_link_format(&self, response: &[u8]) -> Option<Vec<CoapResource>> {
        // Skip CoAP header
        if response.len() < 4 {
            return None;
        }

        // Find payload marker (0xFF)
        let payload_start = response.iter().position(|&b| b == 0xFF)?;
        let payload = &response[payload_start + 1..];

        let link_format = String::from_utf8_lossy(payload);
        let mut resources = Vec::new();

        for link in link_format.split(',') {
            let link = link.trim();
            if link.starts_with('<') && link.contains('>') {
                let end = link.find('>').unwrap();
                let uri = &link[1..end];

                let mut resource = CoapResource {
                    uri: uri.to_string(),
                    resource_type: None,
                    interface: None,
                    content_format: None,
                };

                // Parse attributes
                if link.len() > end + 1 {
                    let attrs = &link[end + 1..];
                    for attr in attrs.split(';') {
                        let attr = attr.trim();
                        if let Some(eq_pos) = attr.find('=') {
                            let key = &attr[..eq_pos];
                            let value = attr[eq_pos + 1..].trim_matches('"');
                            match key {
                                "rt" => resource.resource_type = Some(value.to_string()),
                                "if" => resource.interface = Some(value.to_string()),
                                "ct" => resource.content_format = Some(value.to_string()),
                                _ => {}
                            }
                        }
                    }
                }

                resources.push(resource);
            }
        }

        Some(resources)
    }

    /// Identify CoAP security issues
    fn identify_security_issues(&self, _response: &[u8]) -> Vec<CoapSecurityIssue> {
        let mut issues = Vec::new();

        // CoAP without DTLS is insecure
        issues.push(CoapSecurityIssue {
            issue_type: "no_dtls".to_string(),
            severity: "high".to_string(),
            description: "CoAP endpoint accessible without DTLS encryption".to_string(),
            remediation: Some("Enable DTLS (CoAPs) for secure communication".to_string()),
        });

        // Resource discovery enabled
        issues.push(CoapSecurityIssue {
            issue_type: "resource_discovery".to_string(),
            severity: "medium".to_string(),
            description: "CoAP resource discovery (.well-known/core) is enabled, exposing available resources".to_string(),
            remediation: Some("Consider restricting resource discovery to authenticated clients".to_string()),
        });

        issues
    }
}

impl Default for CoapScanner {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

/// CoAP scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoapScanResult {
    pub detected: bool,
    pub port: u16,
    pub resources: Vec<CoapResource>,
    pub security_issues: Vec<CoapSecurityIssue>,
    pub response_time_ms: u64,
}

/// CoAP resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoapResource {
    pub uri: String,
    pub resource_type: Option<String>,
    pub interface: Option<String>,
    pub content_format: Option<String>,
}

/// CoAP security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoapSecurityIssue {
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub remediation: Option<String>,
}
