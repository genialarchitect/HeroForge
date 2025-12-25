//! Havoc C2 Framework Integration
//!
//! Client for interacting with Havoc C2 teamserver via WebSocket connection.
//! Havoc uses a WebSocket-based protocol for operator communication.
//!
//! References:
//! - https://github.com/HavocFramework/Havoc
//! - Teamserver WebSocket API

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

use super::types::*;

/// Havoc C2 client
pub struct HavocClient {
    config: C2Config,
    http_client: Client,
    connected: Arc<RwLock<bool>>,
    /// WebSocket message sender
    ws_tx: Arc<RwLock<Option<mpsc::Sender<HavocMessage>>>>,
    /// Received messages
    messages: Arc<RwLock<Vec<HavocMessage>>>,
}

/// Havoc protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HavocMessage {
    /// Authentication request
    Auth {
        username: String,
        password: String,
    },
    /// Authentication response
    AuthResponse {
        success: bool,
        message: Option<String>,
    },
    /// Request demon (agent) list
    GetDemons,
    /// Demon list response
    Demons {
        demons: Vec<HavocDemon>,
    },
    /// Request listener list
    GetListeners,
    /// Listener list response
    Listeners {
        listeners: Vec<HavocListener>,
    },
    /// Create listener request
    CreateListener {
        name: String,
        protocol: String,
        host: String,
        port: u16,
        config: HashMap<String, serde_json::Value>,
    },
    /// Stop listener request
    StopListener {
        name: String,
    },
    /// Task demon request
    TaskDemon {
        demon_id: String,
        command: String,
        args: Vec<String>,
    },
    /// Task response/output
    TaskOutput {
        demon_id: String,
        task_id: String,
        output: String,
        status: String,
    },
    /// Kill demon request
    KillDemon {
        demon_id: String,
    },
    /// Generate payload request
    GeneratePayload {
        listener: String,
        arch: String,
        format: String,
        config: HashMap<String, serde_json::Value>,
    },
    /// Payload generated response
    PayloadGenerated {
        payload_id: String,
        file_path: String,
    },
    /// Error response
    Error {
        message: String,
    },
    /// Heartbeat/ping
    Ping,
    /// Heartbeat/pong
    Pong,
}

/// Havoc demon (agent) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HavocDemon {
    pub demon_id: String,
    pub name: Option<String>,
    pub internal_ip: String,
    pub external_ip: Option<String>,
    pub username: String,
    pub hostname: String,
    pub domain: Option<String>,
    pub os: String,
    pub os_version: Option<String>,
    pub os_arch: String,
    pub process_name: String,
    pub process_id: u32,
    pub process_arch: String,
    #[serde(default)]
    pub elevated: bool,
    #[serde(default)]
    pub ppid: u32,
    pub first_callback: String,
    pub last_callback: String,
    #[serde(default)]
    pub sleep: u32,
    #[serde(default)]
    pub jitter: u32,
    #[serde(default)]
    pub pivots: Vec<String>,
    #[serde(default)]
    pub alive: bool,
}

/// Havoc listener information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HavocListener {
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
}

impl HavocClient {
    /// Create a new Havoc client
    pub fn new(config: C2Config) -> Result<Self> {
        let http_client = Client::builder()
            .danger_accept_invalid_certs(!config.verify_ssl)
            .build()?;

        Ok(Self {
            config,
            http_client,
            connected: Arc::new(RwLock::new(false)),
            ws_tx: Arc::new(RwLock::new(None)),
            messages: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Get WebSocket URL for teamserver
    fn ws_url(&self) -> String {
        let protocol = if self.config.verify_ssl { "wss" } else { "ws" };
        format!("{}://{}:{}/api/ws", protocol, self.config.host, self.config.port)
    }

    /// Get REST API base URL
    fn api_url(&self) -> String {
        let protocol = if self.config.verify_ssl { "https" } else { "http" };
        format!("{}://{}:{}/api", protocol, self.config.host, self.config.port)
    }

    /// Test connection and authenticate
    pub async fn test_connection(&self) -> Result<bool> {
        // Try to connect via WebSocket
        match self.connect_websocket().await {
            Ok(_) => {
                *self.connected.write().await = true;
                Ok(true)
            }
            Err(e) => {
                // Fallback to REST API check
                self.test_rest_connection().await.map_err(|_| e)
            }
        }
    }

    /// Connect to teamserver via WebSocket
    async fn connect_websocket(&self) -> Result<()> {
        let url = self.ws_url();
        let (ws_stream, _) = connect_async(&url).await
            .map_err(|e| anyhow!("WebSocket connection failed: {}", e))?;

        let (mut write, mut read) = ws_stream.split();
        let (tx, mut rx) = mpsc::channel::<HavocMessage>(100);

        // Store sender
        *self.ws_tx.write().await = Some(tx.clone());

        // Send authentication
        let auth_msg = HavocMessage::Auth {
            username: self.config.api_token.clone().unwrap_or_default(),
            password: String::new(), // Password from config if needed
        };

        let auth_json = serde_json::to_string(&auth_msg)?;
        write.send(Message::Text(auth_json.into())).await?;

        // Spawn message handler
        let messages = self.messages.clone();
        let connected = self.connected.clone();

        tokio::spawn(async move {
            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if let Ok(havoc_msg) = serde_json::from_str::<HavocMessage>(&text) {
                            match &havoc_msg {
                                HavocMessage::AuthResponse { success, .. } => {
                                    *connected.write().await = *success;
                                }
                                _ => {
                                    messages.write().await.push(havoc_msg);
                                }
                            }
                        }
                    }
                    Ok(Message::Ping(_)) => {
                        // Respond with pong is handled automatically
                    }
                    Ok(Message::Close(_)) => {
                        *connected.write().await = false;
                        break;
                    }
                    Err(_) => {
                        *connected.write().await = false;
                        break;
                    }
                    _ => {}
                }
            }
        });

        // Spawn message sender
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Ok(json) = serde_json::to_string(&msg) {
                    let _ = write.send(Message::Text(json.into())).await;
                }
            }
        });

        Ok(())
    }

    /// Test connection via REST API
    async fn test_rest_connection(&self) -> Result<bool> {
        let url = format!("{}/demons", self.api_url());

        match self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await
        {
            Ok(resp) => {
                let connected = resp.status().is_success();
                *self.connected.write().await = connected;
                Ok(connected)
            }
            Err(e) => {
                *self.connected.write().await = false;
                Err(anyhow!("Failed to connect to Havoc: {}", e))
            }
        }
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Send a WebSocket message
    async fn send_message(&self, msg: HavocMessage) -> Result<()> {
        let tx = self.ws_tx.read().await;
        if let Some(sender) = tx.as_ref() {
            sender.send(msg).await
                .map_err(|e| anyhow!("Failed to send message: {}", e))?;
            Ok(())
        } else {
            Err(anyhow!("WebSocket not connected"))
        }
    }

    /// Wait for a specific message type
    async fn wait_for_message<F>(&self, predicate: F, timeout_ms: u64) -> Result<HavocMessage>
    where
        F: Fn(&HavocMessage) -> bool,
    {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);

        while start.elapsed() < timeout {
            let mut messages = self.messages.write().await;
            if let Some(pos) = messages.iter().position(|m| predicate(m)) {
                return Ok(messages.remove(pos));
            }
            drop(messages);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        Err(anyhow!("Timeout waiting for message"))
    }

    /// List all demons (agents)
    pub async fn list_demons(&self) -> Result<Vec<Session>> {
        // Try WebSocket first
        if self.ws_tx.read().await.is_some() {
            self.send_message(HavocMessage::GetDemons).await?;

            let response = self.wait_for_message(
                |m| matches!(m, HavocMessage::Demons { .. }),
                5000,
            ).await?;

            if let HavocMessage::Demons { demons } = response {
                return Ok(demons.into_iter().map(|d| self.convert_demon(d)).collect());
            }
        }

        // Fallback to REST API
        let url = format!("{}/demons", self.api_url());
        let resp = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to list demons: {}", resp.status()));
        }

        let demons: Vec<HavocDemon> = resp.json().await.unwrap_or_default();
        Ok(demons.into_iter().map(|d| self.convert_demon(d)).collect())
    }

    /// List all listeners
    pub async fn list_listeners(&self) -> Result<Vec<Listener>> {
        // Try WebSocket
        if self.ws_tx.read().await.is_some() {
            self.send_message(HavocMessage::GetListeners).await?;

            let response = self.wait_for_message(
                |m| matches!(m, HavocMessage::Listeners { .. }),
                5000,
            ).await?;

            if let HavocMessage::Listeners { listeners } = response {
                return Ok(listeners.into_iter().map(|l| self.convert_listener(l)).collect());
            }
        }

        // Fallback to REST
        let url = format!("{}/listeners", self.api_url());
        let resp = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to list listeners: {}", resp.status()));
        }

        let listeners: Vec<HavocListener> = resp.json().await.unwrap_or_default();
        Ok(listeners.into_iter().map(|l| self.convert_listener(l)).collect())
    }

    /// Start a listener
    pub async fn start_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        let protocol = match req.protocol {
            ListenerProtocol::Http => "HTTP",
            ListenerProtocol::Https => "HTTPS",
            ListenerProtocol::Tcp => "TCP",
            ListenerProtocol::Pivot => "SMB",
            _ => "HTTPS",
        };

        if self.ws_tx.read().await.is_some() {
            self.send_message(HavocMessage::CreateListener {
                name: req.name.clone(),
                protocol: protocol.to_string(),
                host: req.host.clone(),
                port: req.port,
                config: req.config.clone().unwrap_or_default(),
            }).await?;

            // Wait for confirmation or refresh listener list
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        } else {
            // REST API
            let url = format!("{}/listeners", self.api_url());
            let body = serde_json::json!({
                "name": req.name,
                "protocol": protocol,
                "host": req.host,
                "port": req.port,
                "config": req.config,
            });

            let resp = self.http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
                .json(&body)
                .send()
                .await?;

            if !resp.status().is_success() {
                let error = resp.text().await.unwrap_or_default();
                return Err(anyhow!("Failed to create listener: {}", error));
            }
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
        if self.ws_tx.read().await.is_some() {
            self.send_message(HavocMessage::StopListener {
                name: listener_name.to_string(),
            }).await?;
        } else {
            let url = format!("{}/listeners/{}", self.api_url(), listener_name);
            let resp = self.http_client
                .delete(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
                .send()
                .await?;

            if !resp.status().is_success() {
                return Err(anyhow!("Failed to stop listener: {}", resp.status()));
            }
        }

        Ok(())
    }

    /// Execute a command on a demon
    pub async fn execute_task(&self, demon_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        let task_id = uuid::Uuid::new_v4().to_string();

        if self.ws_tx.read().await.is_some() {
            self.send_message(HavocMessage::TaskDemon {
                demon_id: demon_id.to_string(),
                command: task.command.clone(),
                args: task.args.clone().unwrap_or_default(),
            }).await?;
        } else {
            let url = format!("{}/demons/{}/task", self.api_url(), demon_id);
            let body = serde_json::json!({
                "command": task.command,
                "args": task.args,
            });

            let resp = self.http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
                .json(&body)
                .send()
                .await?;

            if !resp.status().is_success() {
                let error = resp.text().await.unwrap_or_default();
                return Err(anyhow!("Failed to execute task: {}", error));
            }
        }

        Ok(Task {
            id: task_id,
            session_id: demon_id.to_string(),
            c2_task_id: None,
            task_type: task.task_type.clone(),
            command: task.command.clone(),
            args: task.args.clone().unwrap_or_default(),
            status: TaskStatus::Sent,
            output: None,
            error: None,
            created_at: Utc::now(),
            sent_at: Some(Utc::now()),
            completed_at: None,
        })
    }

    /// Kill a demon
    pub async fn kill_demon(&self, demon_id: &str) -> Result<()> {
        if self.ws_tx.read().await.is_some() {
            self.send_message(HavocMessage::KillDemon {
                demon_id: demon_id.to_string(),
            }).await?;
        } else {
            let url = format!("{}/demons/{}/kill", self.api_url(), demon_id);
            let resp = self.http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
                .send()
                .await?;

            if !resp.status().is_success() {
                return Err(anyhow!("Failed to kill demon: {}", resp.status()));
            }
        }

        Ok(())
    }

    /// Generate a payload
    pub async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        let arch = match config.arch {
            Architecture::X64 => "x64",
            Architecture::X86 => "x86",
            _ => "x64",
        };

        let format = match config.format {
            ImplantFormat::Exe => "exe",
            ImplantFormat::Dll => "dll",
            ImplantFormat::Shellcode => "bin",
            ImplantFormat::ServiceExe => "svc",
            _ => "exe",
        };

        if self.ws_tx.read().await.is_some() {
            let mut extra = config.extra_config.clone();
            extra.insert("sleep".to_string(), serde_json::json!(config.interval));
            extra.insert("jitter".to_string(), serde_json::json!(config.jitter));

            self.send_message(HavocMessage::GeneratePayload {
                listener: config.listener_id.clone(),
                arch: arch.to_string(),
                format: format.to_string(),
                config: extra,
            }).await?;

            // Wait for payload generation
            let response = self.wait_for_message(
                |m| matches!(m, HavocMessage::PayloadGenerated { .. }),
                30000,
            ).await?;

            if let HavocMessage::PayloadGenerated { file_path, .. } = response {
                // Download the payload
                let url = format!("{}/payloads/{}", self.api_url(), file_path);
                let resp = self.http_client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
                    .send()
                    .await?;

                return Ok(resp.bytes().await?.to_vec());
            }
        }

        // REST API fallback
        let url = format!("{}/payloads/generate", self.api_url());
        let body = serde_json::json!({
            "listener": config.listener_id,
            "arch": arch,
            "format": format,
            "sleep": config.interval,
            "jitter": config.jitter,
        });

        let resp = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to generate payload: {}", error));
        }

        Ok(resp.bytes().await?.to_vec())
    }

    /// Get demon console output
    pub async fn get_demon_output(&self, demon_id: &str) -> Result<String> {
        let url = format!("{}/demons/{}/output", self.api_url(), demon_id);

        let resp = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to get demon output: {}", resp.status()));
        }

        Ok(resp.text().await?)
    }

    // Helper to convert Havoc demon to Session
    fn convert_demon(&self, d: HavocDemon) -> Session {
        let arch = match d.os_arch.to_lowercase().as_str() {
            "x64" | "amd64" => Architecture::X64,
            "x86" | "i386" => Architecture::X86,
            "arm64" | "aarch64" => Architecture::Arm64,
            "arm" => Architecture::Arm,
            _ => Architecture::X64,
        };

        let status = if d.alive {
            SessionStatus::Active
        } else {
            SessionStatus::Dead
        };

        Session {
            id: uuid::Uuid::new_v4().to_string(),
            c2_config_id: self.config.id.clone(),
            c2_session_id: d.demon_id.clone(),
            implant_id: None,
            name: d.name.unwrap_or_else(|| d.demon_id.clone()),
            hostname: d.hostname,
            username: d.username,
            domain: d.domain,
            ip_address: d.internal_ip,
            external_ip: d.external_ip,
            os: d.os,
            os_version: d.os_version,
            arch,
            pid: d.process_id,
            process_name: d.process_name,
            integrity: if d.elevated { Some("High".to_string()) } else { None },
            status,
            is_elevated: d.elevated,
            locale: None,
            first_seen: DateTime::parse_from_rfc3339(&d.first_callback)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_checkin: DateTime::parse_from_rfc3339(&d.last_callback)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            next_checkin: None,
            notes: None,
        }
    }

    // Helper to convert Havoc listener to Listener
    fn convert_listener(&self, l: HavocListener) -> Listener {
        let protocol = match l.protocol.to_uppercase().as_str() {
            "HTTP" => ListenerProtocol::Http,
            "HTTPS" => ListenerProtocol::Https,
            "TCP" => ListenerProtocol::Tcp,
            "SMB" => ListenerProtocol::Pivot,
            _ => ListenerProtocol::Https,
        };

        let status = match l.status.to_lowercase().as_str() {
            "running" | "active" => ListenerStatus::Active,
            "stopped" => ListenerStatus::Stopped,
            "error" => ListenerStatus::Error,
            _ => ListenerStatus::Active,
        };

        Listener {
            id: l.name.clone(),
            c2_config_id: self.config.id.clone(),
            name: l.name,
            protocol,
            host: l.host,
            port: l.port,
            status,
            domains: Vec::new(),
            website: None,
            config: l.config,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = HavocMessage::TaskDemon {
            demon_id: "abc123".to_string(),
            command: "shell".to_string(),
            args: vec!["whoami".to_string()],
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("TaskDemon"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_demon_parsing() {
        let json = r#"{
            "demon_id": "12345678",
            "internal_ip": "192.168.1.100",
            "username": "Administrator",
            "hostname": "WORKSTATION",
            "os": "Windows 10",
            "os_arch": "x64",
            "process_name": "explorer.exe",
            "process_id": 1234,
            "process_arch": "x64",
            "elevated": true,
            "first_callback": "2024-01-01T12:00:00Z",
            "last_callback": "2024-01-01T12:05:00Z",
            "alive": true
        }"#;

        let demon: HavocDemon = serde_json::from_str(json).unwrap();
        assert_eq!(demon.demon_id, "12345678");
        assert!(demon.elevated);
        assert!(demon.alive);
    }
}
