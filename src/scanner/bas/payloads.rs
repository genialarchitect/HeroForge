#![allow(dead_code)]
//! Safe Payload Implementations
//!
//! This module provides safe payload implementations for BAS testing.
//! These payloads are designed to simulate attack techniques without
//! causing actual harm to systems.

use super::types::{PayloadType, SafePayload};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

/// Result of payload execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadResult {
    /// Whether execution succeeded
    pub success: bool,
    /// Payload type executed
    pub payload_type: PayloadType,
    /// Output from execution
    pub output: String,
    /// Duration of execution
    pub duration_ms: u64,
    /// Indicators generated (for detection validation)
    pub indicators: Vec<String>,
    /// Artifacts created (files, registry keys, etc.)
    pub artifacts: Vec<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Cleanup performed
    pub cleanup_performed: bool,
}

impl PayloadResult {
    pub fn success(payload_type: PayloadType, output: String, duration_ms: u64) -> Self {
        Self {
            success: true,
            payload_type,
            output,
            duration_ms,
            indicators: Vec::new(),
            artifacts: Vec::new(),
            error: None,
            cleanup_performed: false,
        }
    }

    pub fn failure(payload_type: PayloadType, error: String) -> Self {
        Self {
            success: false,
            payload_type,
            output: String::new(),
            duration_ms: 0,
            indicators: Vec::new(),
            artifacts: Vec::new(),
            error: Some(error),
            cleanup_performed: false,
        }
    }

    pub fn with_indicators(mut self, indicators: Vec<String>) -> Self {
        self.indicators = indicators;
        self
    }

    pub fn with_artifacts(mut self, artifacts: Vec<String>) -> Self {
        self.artifacts = artifacts;
        self
    }
}

/// Payload executor for running safe simulation payloads
pub struct PayloadExecutor {
    /// Base directory for file markers
    base_dir: PathBuf,
    /// DNS beacon domains
    beacon_domains: Vec<String>,
    /// HTTP beacon URLs
    beacon_urls: Vec<String>,
    /// Cleanup enabled
    cleanup_enabled: bool,
}

impl PayloadExecutor {
    /// Create a new payload executor
    pub fn new() -> Self {
        Self {
            base_dir: std::env::temp_dir().join("heroforge_bas"),
            beacon_domains: vec![
                "bas-test.heroforge.local".to_string(),
                "simulation.heroforge.local".to_string(),
            ],
            beacon_urls: vec![
                "http://127.0.0.1:65535/bas-beacon".to_string(),
            ],
            cleanup_enabled: true,
        }
    }

    /// Set base directory for file markers
    pub fn with_base_dir(mut self, path: PathBuf) -> Self {
        self.base_dir = path;
        self
    }

    /// Set beacon domains for DNS testing
    pub fn with_beacon_domains(mut self, domains: Vec<String>) -> Self {
        self.beacon_domains = domains;
        self
    }

    /// Enable or disable cleanup
    pub fn with_cleanup(mut self, enabled: bool) -> Self {
        self.cleanup_enabled = enabled;
        self
    }

    /// Execute a payload
    pub async fn execute(&self, payload: &SafePayload) -> Result<PayloadResult> {
        let start = std::time::Instant::now();

        let result = match payload.payload_type {
            PayloadType::FileMarker => self.execute_file_marker(payload).await,
            PayloadType::DnsBeacon => self.execute_dns_beacon(payload).await,
            PayloadType::HttpBeacon => self.execute_http_beacon(payload).await,
            PayloadType::ProcessMarker => self.execute_process_marker(payload).await,
            PayloadType::RegistryMarker => self.execute_registry_marker(payload).await,
            PayloadType::NetworkBeacon => self.execute_network_beacon(payload).await,
            PayloadType::MemoryMarker => self.execute_memory_marker(payload).await,
            PayloadType::LogInjection => self.execute_log_injection(payload).await,
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(mut r) => {
                r.duration_ms = duration_ms;
                Ok(r)
            }
            Err(e) => Ok(PayloadResult::failure(
                payload.payload_type,
                e.to_string(),
            )),
        }
    }

    /// Execute file marker payload - creates identifiable marker files
    async fn execute_file_marker(&self, payload: &SafePayload) -> Result<PayloadResult> {
        // Ensure base directory exists
        tokio::fs::create_dir_all(&self.base_dir).await?;

        // Generate unique marker file
        let marker_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        let filename = payload
            .config
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("bas_marker")
            .to_string();

        let file_path = self.base_dir.join(format!("{}_{}.txt", filename, &marker_id[..8]));

        // Create marker file with identifiable content
        let content = format!(
            r#"[HeroForge BAS Marker File]
ID: {}
Timestamp: {}
Payload: {}
Technique IDs: {:?}
Description: {}

This file was created by HeroForge Breach & Attack Simulation.
It is safe to delete this file.
"#,
            marker_id,
            timestamp,
            payload.name,
            payload.technique_ids,
            payload.description,
        );

        tokio::fs::write(&file_path, &content).await?;

        let file_path_str = file_path.to_string_lossy().to_string();

        let mut result = PayloadResult::success(
            PayloadType::FileMarker,
            format!("Created marker file: {}", file_path_str),
            0,
        );

        result.indicators = vec![
            format!("file:created:{}", file_path_str),
            format!("file:content:HeroForge BAS Marker"),
        ];
        result.artifacts = vec![file_path_str.clone()];

        // Cleanup if enabled
        if self.cleanup_enabled {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if tokio::fs::remove_file(&file_path).await.is_ok() {
                result.cleanup_performed = true;
                result.output = format!("Created and cleaned up marker file: {}", file_path_str);
            }
        }

        Ok(result)
    }

    /// Execute DNS beacon payload - performs DNS lookups for tracking
    async fn execute_dns_beacon(&self, payload: &SafePayload) -> Result<PayloadResult> {
        let marker_id = Uuid::new_v4().to_string()[..8].to_string();

        let domain = payload
            .config
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.beacon_domains[0])
            .to_string();

        // Create a beacon subdomain with unique ID
        let beacon_domain = format!("{}.{}", marker_id, domain);

        // Attempt DNS lookup (will likely fail but generates network traffic)
        let lookup_result = tokio::net::lookup_host(format!("{}:80", beacon_domain)).await;

        let output = match lookup_result {
            Ok(_addrs) => format!("DNS beacon resolved: {}", beacon_domain),
            Err(_) => format!("DNS beacon query sent (no resolution): {}", beacon_domain),
        };

        let mut result = PayloadResult::success(PayloadType::DnsBeacon, output, 0);

        result.indicators = vec![
            format!("dns:query:{}", beacon_domain),
            format!("dns:subdomain:{}", marker_id),
        ];

        Ok(result)
    }

    /// Execute HTTP beacon payload - sends HTTP requests for tracking
    async fn execute_http_beacon(&self, payload: &SafePayload) -> Result<PayloadResult> {
        let marker_id = Uuid::new_v4().to_string();

        let url = payload
            .config
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.beacon_urls[0])
            .to_string();

        // Add marker to URL
        let beacon_url = format!("{}?id={}", url, marker_id);

        // Create HTTP client with short timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;

        // Attempt HTTP request (will likely fail but generates network traffic)
        let request_result = client.get(&beacon_url).send().await;

        let output = match request_result {
            Ok(resp) => format!("HTTP beacon sent, status: {}", resp.status()),
            Err(e) => format!("HTTP beacon attempted (connection failed): {}", e),
        };

        let mut result = PayloadResult::success(PayloadType::HttpBeacon, output, 0);

        result.indicators = vec![
            format!("http:request:{}", beacon_url),
            format!("http:marker:{}", marker_id),
        ];

        Ok(result)
    }

    /// Execute process marker payload - creates identifiable process activity
    async fn execute_process_marker(&self, payload: &SafePayload) -> Result<PayloadResult> {
        let marker_id = Uuid::new_v4().to_string()[..8].to_string();

        // Get command from config or use safe default
        let command = payload
            .config
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or(if cfg!(target_os = "windows") {
                "cmd /c echo HeroForge-BAS-Marker"
            } else {
                "echo HeroForge-BAS-Marker"
            });

        // Execute safe command
        let output = if cfg!(target_os = "windows") {
            tokio::process::Command::new("cmd")
                .args(["/c", command])
                .output()
                .await?
        } else {
            tokio::process::Command::new("sh")
                .args(["-c", command])
                .output()
                .await?
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let _stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let mut result = PayloadResult::success(
            PayloadType::ProcessMarker,
            format!("Process marker executed: {}", stdout.trim()),
            0,
        );

        result.indicators = vec![
            format!("process:created:marker-{}", marker_id),
            format!("process:command:{}", command),
        ];

        Ok(result)
    }

    /// Execute registry marker payload (Windows only)
    async fn execute_registry_marker(&self, _payload: &SafePayload) -> Result<PayloadResult> {
        #[cfg(target_os = "windows")]
        {
            let marker_id = Uuid::new_v4().to_string()[..8].to_string();
            let key_name = format!("HeroForge_BAS_{}", marker_id);

            // Create registry entry in safe location
            let output = tokio::process::Command::new("reg")
                .args([
                    "add",
                    "HKCU\\Software\\HeroForge\\BAS",
                    "/v",
                    &key_name,
                    "/t",
                    "REG_SZ",
                    "/d",
                    "BAS Simulation Marker",
                    "/f",
                ])
                .output()
                .await?;

            let mut result = PayloadResult::success(
                PayloadType::RegistryMarker,
                format!("Registry marker created: {}", key_name),
                0,
            );

            result.indicators = vec![
                format!("registry:created:HKCU\\Software\\HeroForge\\BAS\\{}", key_name),
            ];
            result.artifacts = vec![format!("HKCU\\Software\\HeroForge\\BAS\\{}", key_name)];

            // Cleanup
            if self.cleanup_enabled {
                let _ = tokio::process::Command::new("reg")
                    .args([
                        "delete",
                        "HKCU\\Software\\HeroForge\\BAS",
                        "/v",
                        &key_name,
                        "/f",
                    ])
                    .output()
                    .await;
                result.cleanup_performed = true;
            }

            Ok(result)
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(PayloadResult::failure(
                PayloadType::RegistryMarker,
                "Registry markers are only supported on Windows".to_string(),
            ))
        }
    }

    /// Execute network beacon payload - creates network traffic patterns
    async fn execute_network_beacon(&self, payload: &SafePayload) -> Result<PayloadResult> {
        let marker_id = Uuid::new_v4().to_string()[..8].to_string();

        let port = payload
            .config
            .get("port")
            .and_then(|v| v.as_u64())
            .unwrap_or(65535) as u16;

        let target = payload
            .config
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1");

        // Attempt TCP connection (will fail but generates network traffic)
        let connect_result = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect((target, port)),
        )
        .await;

        let output = match connect_result {
            Ok(Ok(_)) => format!("Network beacon: connected to {}:{}", target, port),
            Ok(Err(_)) => format!("Network beacon: connection attempt to {}:{}", target, port),
            Err(_) => format!("Network beacon: timeout connecting to {}:{}", target, port),
        };

        let mut result = PayloadResult::success(PayloadType::NetworkBeacon, output, 0);

        result.indicators = vec![
            format!("network:tcp:{}:{}", target, port),
            format!("network:marker:{}", marker_id),
        ];

        Ok(result)
    }

    /// Execute memory marker payload - creates memory patterns
    async fn execute_memory_marker(&self, _payload: &SafePayload) -> Result<PayloadResult> {
        let marker_id = Uuid::new_v4().to_string();

        // Create distinctive memory pattern
        let marker_string = format!(
            "HEROFORGE_BAS_MARKER_{}_{}",
            marker_id,
            Utc::now().timestamp()
        );

        // Allocate and write pattern (will be cleaned up by Rust's drop)
        let pattern: Vec<u8> = marker_string.bytes().collect();
        let pattern_len = pattern.len();

        // Brief delay to allow memory scanners to potentially detect
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut result = PayloadResult::success(
            PayloadType::MemoryMarker,
            format!("Memory marker created: {} bytes", pattern_len),
            0,
        );

        result.indicators = vec![
            format!("memory:pattern:HEROFORGE_BAS_MARKER"),
            format!("memory:marker:{}", marker_id),
        ];
        result.cleanup_performed = true; // Memory cleaned up by Rust

        Ok(result)
    }

    /// Execute log injection payload - injects traceable log entries
    async fn execute_log_injection(&self, payload: &SafePayload) -> Result<PayloadResult> {
        let marker_id = Uuid::new_v4().to_string()[..8].to_string();
        let timestamp = Utc::now().to_rfc3339();

        let log_message = payload
            .config
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("HeroForge BAS Simulation Test");

        // Log to application logs (these can be detected by SIEM)
        log::info!(
            "[BAS-MARKER-{}] {} - Simulation: {}",
            marker_id,
            timestamp,
            log_message
        );

        // Also write to a temp file for systems that monitor file-based logs
        let log_path = self.base_dir.join(format!("bas_log_{}.log", marker_id));
        tokio::fs::create_dir_all(&self.base_dir).await?;

        let log_content = format!(
            "[{}] BAS-MARKER-{}: {}\n",
            timestamp, marker_id, log_message
        );
        tokio::fs::write(&log_path, &log_content).await?;

        let mut result = PayloadResult::success(
            PayloadType::LogInjection,
            format!("Log entry injected: BAS-MARKER-{}", marker_id),
            0,
        );

        result.indicators = vec![
            format!("log:entry:BAS-MARKER-{}", marker_id),
            format!("log:file:{}", log_path.to_string_lossy()),
        ];
        result.artifacts = vec![log_path.to_string_lossy().to_string()];

        // Cleanup
        if self.cleanup_enabled {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if tokio::fs::remove_file(&log_path).await.is_ok() {
                result.cleanup_performed = true;
            }
        }

        Ok(result)
    }

    /// Cleanup all artifacts in base directory
    pub async fn cleanup_all(&self) -> Result<usize> {
        let mut cleaned = 0;

        if self.base_dir.exists() {
            let mut entries = tokio::fs::read_dir(&self.base_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                if tokio::fs::remove_file(entry.path()).await.is_ok() {
                    cleaned += 1;
                }
            }
        }

        Ok(cleaned)
    }
}

impl Default for PayloadExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Get default payloads for a technique
pub fn get_payloads_for_technique(technique_id: &str) -> Vec<SafePayload> {
    let mut payloads = Vec::new();

    match technique_id {
        // Execution techniques
        "T1059.001" | "T1059.003" | "T1059.004" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_process", technique_id),
                    "Process Marker",
                    PayloadType::ProcessMarker,
                    "Creates process activity simulating script execution",
                )
                .with_techniques(vec![technique_id.to_string()])
                .with_indicators(vec!["process:command:echo".to_string()]),
            );
            payloads.push(
                SafePayload::new(
                    format!("{}_file", technique_id),
                    "Script File Marker",
                    PayloadType::FileMarker,
                    "Creates a marker file simulating script creation",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        // C2 techniques
        "T1071.001" | "T1105" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_http", technique_id),
                    "HTTP Beacon",
                    PayloadType::HttpBeacon,
                    "Sends HTTP beacon simulating C2 communication",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        "T1071.004" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_dns", technique_id),
                    "DNS Beacon",
                    PayloadType::DnsBeacon,
                    "Sends DNS queries simulating DNS tunneling",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        // Persistence techniques (Windows)
        "T1547.001" | "T1543.003" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_registry", technique_id),
                    "Registry Marker",
                    PayloadType::RegistryMarker,
                    "Creates registry entry simulating persistence mechanism",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        // File-based techniques
        "T1005" | "T1039" | "T1560.001" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_file", technique_id),
                    "File Access Marker",
                    PayloadType::FileMarker,
                    "Creates file markers simulating data collection",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        // Network techniques
        "T1021.001" | "T1021.002" | "T1021.004" | "T1570" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_network", technique_id),
                    "Network Beacon",
                    PayloadType::NetworkBeacon,
                    "Creates network activity simulating lateral movement",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        // Discovery techniques
        "T1082" | "T1083" | "T1087.001" | "T1087.002" | "T1016" | "T1049" | "T1057" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_process", technique_id),
                    "Discovery Command",
                    PayloadType::ProcessMarker,
                    "Executes safe discovery commands",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        // Credential access
        "T1110.001" | "T1110.003" => {
            payloads.push(
                SafePayload::new(
                    format!("{}_log", technique_id),
                    "Auth Log Marker",
                    PayloadType::LogInjection,
                    "Creates log entries simulating authentication attempts",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }

        // Default - process marker
        _ => {
            payloads.push(
                SafePayload::new(
                    format!("{}_default", technique_id),
                    "Default Process Marker",
                    PayloadType::ProcessMarker,
                    "Default process marker for technique simulation",
                )
                .with_techniques(vec![technique_id.to_string()]),
            );
        }
    }

    payloads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_marker() {
        let executor = PayloadExecutor::new();
        let payload = SafePayload::new(
            "test_file",
            "Test File Marker",
            PayloadType::FileMarker,
            "Test file marker",
        );

        let result = executor.execute(&payload).await.unwrap();
        assert!(result.success);
        assert!(!result.indicators.is_empty());
    }

    #[tokio::test]
    async fn test_process_marker() {
        let executor = PayloadExecutor::new();
        let payload = SafePayload::new(
            "test_process",
            "Test Process Marker",
            PayloadType::ProcessMarker,
            "Test process marker",
        );

        let result = executor.execute(&payload).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_dns_beacon() {
        let executor = PayloadExecutor::new();
        let payload = SafePayload::new(
            "test_dns",
            "Test DNS Beacon",
            PayloadType::DnsBeacon,
            "Test DNS beacon",
        );

        let result = executor.execute(&payload).await.unwrap();
        assert!(result.success);
        assert!(!result.indicators.is_empty());
    }

    #[test]
    fn test_get_payloads_for_technique() {
        let payloads = get_payloads_for_technique("T1059.001");
        assert!(!payloads.is_empty());
    }
}
