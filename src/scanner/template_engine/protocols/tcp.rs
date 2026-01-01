//! TCP Protocol Handler
//!
//! Executes TCP-based template requests.

use crate::scanner::template_engine::matcher::{execute_matchers, ResponseData};
use crate::scanner::template_engine::types::*;
use log::debug;
use std::collections::HashMap;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TCP protocol handler
pub struct TcpHandler {
    options: ExecutionOptions,
}

impl TcpHandler {
    /// Create a new TCP handler
    pub fn new(options: ExecutionOptions) -> Self {
        Self { options }
    }

    /// Execute a TCP request from template
    pub async fn execute(
        &self,
        request: &TcpRequest,
        target: &str,
        variables: &HashMap<String, String>,
    ) -> Result<Vec<TemplateResult>, TemplateError> {
        let mut results = Vec::new();

        let hosts = if request.host.is_empty() {
            vec![target.to_string()]
        } else {
            request
                .host
                .iter()
                .map(|h| self.substitute_variables(h, target, variables))
                .collect()
        };

        for host in hosts {
            let result = self.execute_single(&host, request, variables).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Execute a single TCP request
    async fn execute_single(
        &self,
        host: &str,
        request: &TcpRequest,
        variables: &HashMap<String, String>,
    ) -> Result<TemplateResult, TemplateError> {
        let start = Instant::now();

        debug!("Connecting to TCP host: {}", host);

        let mut stream = timeout(self.options.timeout, TcpStream::connect(host))
            .await
            .map_err(|_| TemplateError::Timeout)?
            .map_err(|e| TemplateError::Network(e.to_string()))?;

        let mut all_data = Vec::new();

        for input in &request.inputs {
            // Send data if present
            if let Some(ref data) = input.data {
                let data = self.substitute_variables(data, host, variables);
                let bytes = self.parse_data(&data)?;

                debug!("Sending {} bytes to {}", bytes.len(), host);
                stream.write_all(&bytes).await?;
            }

            // Read response
            let read_size = input.read.or(request.read_size).unwrap_or(4096);
            let mut buffer = vec![0u8; read_size];

            if request.read_all {
                // Read all available data
                loop {
                    match timeout(
                        std::time::Duration::from_millis(500),
                        stream.read(&mut buffer),
                    )
                    .await
                    {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => {
                            all_data.extend_from_slice(&buffer[..n]);
                        }
                        Ok(Err(_)) => break,
                        Err(_) => break, // Timeout
                    }
                }
            } else {
                // Read once
                match timeout(self.options.timeout, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) => {
                        all_data.extend_from_slice(&buffer[..n]);
                    }
                    Ok(Err(e)) => {
                        debug!("Read error: {}", e);
                    }
                    Err(_) => {
                        debug!("Read timeout");
                    }
                }
            }
        }

        let elapsed = start.elapsed();

        // Convert response to string (lossy)
        let body = String::from_utf8_lossy(&all_data).to_string();
        let response_data = ResponseData::new(0, HashMap::new(), body);

        // Execute matchers
        let match_result = execute_matchers(
            &request.matchers,
            request.matchers_condition,
            &response_data,
        );

        Ok(TemplateResult {
            template_id: String::new(),
            template_name: String::new(),
            severity: Severity::Unknown,
            matched: match_result.matched,
            extracted: HashMap::new(),
            matched_at: host.to_string(),
            matcher_name: match_result.matcher_name,
            request_url: None,
            request_method: Some("TCP".to_string()),
            response_status: None,
            response_time: elapsed,
            curl_command: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Parse data string (handles hex encoding)
    fn parse_data(&self, data: &str) -> Result<Vec<u8>, TemplateError> {
        // Check for hex encoding
        if data.starts_with("0x") || data.contains("\\x") {
            self.parse_hex_data(data)
        } else {
            // Handle escape sequences
            let result = data
                .replace("\\r", "\r")
                .replace("\\n", "\n")
                .replace("\\t", "\t");
            Ok(result.into_bytes())
        }
    }

    /// Parse hex-encoded data
    fn parse_hex_data(&self, data: &str) -> Result<Vec<u8>, TemplateError> {
        let mut result = Vec::new();
        let mut chars = data.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'x') {
                chars.next(); // Skip 'x'
                let high = chars.next().and_then(|c| c.to_digit(16));
                let low = chars.next().and_then(|c| c.to_digit(16));

                if let (Some(h), Some(l)) = (high, low) {
                    result.push((h * 16 + l) as u8);
                }
            } else if c == '0' && chars.peek() == Some(&'x') {
                chars.next(); // Skip 'x'
                // Parse rest as hex
                let hex_str: String = chars.by_ref().take_while(|c| c.is_ascii_hexdigit()).collect();
                if let Ok(bytes) = hex::decode(&hex_str) {
                    result.extend(bytes);
                }
            } else if c == '\\' {
                match chars.next() {
                    Some('r') => result.push(b'\r'),
                    Some('n') => result.push(b'\n'),
                    Some('t') => result.push(b'\t'),
                    Some('\\') => result.push(b'\\'),
                    Some(other) => {
                        result.push(b'\\');
                        result.push(other as u8);
                    }
                    None => result.push(b'\\'),
                }
            } else {
                result.push(c as u8);
            }
        }

        Ok(result)
    }

    /// Substitute variables in string
    fn substitute_variables(
        &self,
        input: &str,
        target: &str,
        variables: &HashMap<String, String>,
    ) -> String {
        let mut result = input.to_string();

        // Substitute {{Hostname}}
        if result.contains("{{Hostname}}") {
            let hostname = target.split(':').next().unwrap_or(target);
            result = result.replace("{{Hostname}}", hostname);
        }

        // Substitute {{Host}}
        result = result.replace("{{Host}}", target);

        // Substitute template variables
        for (key, value) in variables {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_data_plain() {
        let handler = TcpHandler::new(ExecutionOptions::default());
        let data = handler.parse_data("HELLO\\r\\n").unwrap();
        assert_eq!(data, b"HELLO\r\n");
    }

    #[test]
    fn test_parse_data_hex() {
        let handler = TcpHandler::new(ExecutionOptions::default());
        let data = handler.parse_data("\\x48\\x45\\x4c\\x4c\\x4f").unwrap();
        assert_eq!(data, b"HELLO");
    }

    #[test]
    fn test_substitute_variables() {
        let handler = TcpHandler::new(ExecutionOptions::default());
        let mut vars = HashMap::new();
        vars.insert("port".to_string(), "22".to_string());

        let result = handler.substitute_variables("{{Hostname}}:{{port}}", "example.com:80", &vars);
        assert_eq!(result, "example.com:22");
    }
}
