//! Sliver C2 Framework Integration
//!
//! Client for interacting with Sliver C2 server via its operator API.
//! Sliver uses mTLS for authentication with operator certificates.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::types::*;

/// Sliver C2 client
pub struct SliverClient {
    config: C2Config,
    client: Client,
    connected: Arc<RwLock<bool>>,
}

// Sliver API response types
#[derive(Debug, Deserialize)]
struct SliverSession {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "GID")]
    gid: String,
    #[serde(rename = "OS")]
    os: String,
    #[serde(rename = "Arch")]
    arch: String,
    #[serde(rename = "Transport")]
    transport: String,
    #[serde(rename = "RemoteAddress")]
    remote_address: String,
    #[serde(rename = "PID")]
    pid: i32,
    #[serde(rename = "Filename")]
    filename: String,
    #[serde(rename = "LastCheckin")]
    last_checkin: String,
    #[serde(rename = "IsDead")]
    is_dead: bool,
}

#[derive(Debug, Deserialize)]
struct SliverBeacon {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "GID")]
    gid: String,
    #[serde(rename = "OS")]
    os: String,
    #[serde(rename = "Arch")]
    arch: String,
    #[serde(rename = "Transport")]
    transport: String,
    #[serde(rename = "RemoteAddress")]
    remote_address: String,
    #[serde(rename = "PID")]
    pid: i32,
    #[serde(rename = "Filename")]
    filename: String,
    #[serde(rename = "LastCheckin")]
    last_checkin: String,
    #[serde(rename = "NextCheckin")]
    next_checkin: String,
    #[serde(rename = "Interval")]
    interval: i64,
    #[serde(rename = "Jitter")]
    jitter: i64,
    #[serde(rename = "IsDead")]
    is_dead: bool,
}

#[derive(Debug, Deserialize)]
struct SliverListener {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Host", default)]
    host: String,
    #[serde(rename = "Port")]
    port: u16,
    #[serde(rename = "Type", default)]
    listener_type: String,
}

#[derive(Debug, Deserialize)]
struct SliverImplant {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "OS")]
    os: String,
    #[serde(rename = "Arch")]
    arch: String,
    #[serde(rename = "Format")]
    format: String,
}

#[derive(Debug, Serialize)]
struct GenerateRequest {
    name: String,
    #[serde(rename = "MTLSc2Enabled")]
    mtls_enabled: bool,
    #[serde(rename = "HTTPc2Enabled")]
    http_enabled: bool,
    #[serde(rename = "WGc2Enabled")]
    wg_enabled: bool,
    #[serde(rename = "DNSc2Enabled")]
    dns_enabled: bool,
    #[serde(rename = "GOOS")]
    goos: String,
    #[serde(rename = "GOARCH")]
    goarch: String,
    format: String,
    #[serde(rename = "IsBeacon")]
    is_beacon: bool,
    #[serde(rename = "BeaconInterval")]
    beacon_interval: i64,
    #[serde(rename = "BeaconJitter")]
    beacon_jitter: i64,
}

#[derive(Debug, Deserialize)]
struct TaskResult {
    #[serde(rename = "TaskID")]
    task_id: String,
    #[serde(rename = "Output")]
    output: Option<String>,
    #[serde(rename = "Error")]
    error: Option<String>,
    #[serde(rename = "Completed")]
    completed: bool,
}

impl SliverClient {
    /// Create a new Sliver client
    pub fn new(config: C2Config) -> Result<Self> {
        let mut client_builder = Client::builder()
            .danger_accept_invalid_certs(!config.verify_ssl);

        // Add mTLS certificate if provided
        if let (Some(cert_pem), Some(key_pem)) = (&config.mtls_cert, &config.mtls_key) {
            let identity = reqwest::Identity::from_pem(
                format!("{}\n{}", cert_pem, key_pem).as_bytes()
            )?;
            client_builder = client_builder.identity(identity);
        }

        // Add CA cert if provided
        if let Some(ca_cert) = &config.ca_cert {
            let ca = reqwest::Certificate::from_pem(ca_cert.as_bytes())?;
            client_builder = client_builder.add_root_certificate(ca);
        }

        let client = client_builder.build()?;

        Ok(Self {
            config,
            client,
            connected: Arc::new(RwLock::new(false)),
        })
    }

    /// Get base URL for Sliver API
    fn base_url(&self) -> String {
        format!("https://{}:{}", self.config.host, self.config.port)
    }

    /// Test connection to Sliver server
    pub async fn test_connection(&self) -> Result<bool> {
        let url = format!("{}/api/version", self.base_url());

        match self.client.get(&url)
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
                Err(anyhow!("Failed to connect to Sliver: {}", e))
            }
        }
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// List all active sessions
    pub async fn list_sessions(&self) -> Result<Vec<Session>> {
        let url = format!("{}/api/sessions", self.base_url());

        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to list sessions: {}", resp.status()));
        }

        let sliver_sessions: Vec<SliverSession> = resp.json().await.unwrap_or_default();

        Ok(sliver_sessions.into_iter().map(|s| self.convert_session(s)).collect())
    }

    /// List all beacons
    pub async fn list_beacons(&self) -> Result<Vec<Session>> {
        let url = format!("{}/api/beacons", self.base_url());

        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to list beacons: {}", resp.status()));
        }

        let beacons: Vec<SliverBeacon> = resp.json().await.unwrap_or_default();

        Ok(beacons.into_iter().map(|b| self.convert_beacon(b)).collect())
    }

    /// Get all sessions (both interactive and beacons)
    pub async fn get_all_sessions(&self) -> Result<Vec<Session>> {
        let mut all_sessions = self.list_sessions().await?;
        let beacons = self.list_beacons().await?;
        all_sessions.extend(beacons);
        Ok(all_sessions)
    }

    /// List listeners (HTTP, HTTPS, mTLS, DNS, etc.)
    pub async fn list_listeners(&self) -> Result<Vec<Listener>> {
        let mut listeners = Vec::new();

        // Get HTTP listeners
        if let Ok(http_listeners) = self.list_http_listeners().await {
            listeners.extend(http_listeners);
        }

        // Get mTLS listeners
        if let Ok(mtls_listeners) = self.list_mtls_listeners().await {
            listeners.extend(mtls_listeners);
        }

        // Get DNS listeners
        if let Ok(dns_listeners) = self.list_dns_listeners().await {
            listeners.extend(dns_listeners);
        }

        Ok(listeners)
    }

    async fn list_http_listeners(&self) -> Result<Vec<Listener>> {
        let url = format!("{}/api/jobs/http", self.base_url());

        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let sliver_listeners: Vec<SliverListener> = resp.json().await.unwrap_or_default();

        Ok(sliver_listeners.into_iter().map(|l| Listener {
            id: l.id.clone(),
            c2_config_id: self.config.id.clone(),
            name: if l.name.is_empty() { format!("HTTP-{}", l.port) } else { l.name },
            protocol: ListenerProtocol::Http,
            host: l.host,
            port: l.port,
            status: ListenerStatus::Active,
            domains: Vec::new(),
            website: None,
            config: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }).collect())
    }

    async fn list_mtls_listeners(&self) -> Result<Vec<Listener>> {
        let url = format!("{}/api/jobs/mtls", self.base_url());

        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let sliver_listeners: Vec<SliverListener> = resp.json().await.unwrap_or_default();

        Ok(sliver_listeners.into_iter().map(|l| Listener {
            id: l.id.clone(),
            c2_config_id: self.config.id.clone(),
            name: if l.name.is_empty() { format!("mTLS-{}", l.port) } else { l.name },
            protocol: ListenerProtocol::Mtls,
            host: l.host,
            port: l.port,
            status: ListenerStatus::Active,
            domains: Vec::new(),
            website: None,
            config: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }).collect())
    }

    async fn list_dns_listeners(&self) -> Result<Vec<Listener>> {
        let url = format!("{}/api/jobs/dns", self.base_url());

        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let sliver_listeners: Vec<SliverListener> = resp.json().await.unwrap_or_default();

        Ok(sliver_listeners.into_iter().map(|l| Listener {
            id: l.id.clone(),
            c2_config_id: self.config.id.clone(),
            name: if l.name.is_empty() { format!("DNS-{}", l.port) } else { l.name },
            protocol: ListenerProtocol::Dns,
            host: l.host,
            port: l.port,
            status: ListenerStatus::Active,
            domains: Vec::new(),
            website: None,
            config: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }).collect())
    }

    /// Start an HTTP listener
    pub async fn start_http_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        let url = format!("{}/api/jobs/http", self.base_url());

        let body = serde_json::json!({
            "Host": req.host,
            "Port": req.port,
            "Domain": req.domains.as_ref().and_then(|d| d.first()).unwrap_or(&String::new()),
            "Website": req.website,
        });

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to start HTTP listener: {}", error_text));
        }

        let sliver_listener: SliverListener = resp.json().await?;

        Ok(Listener {
            id: sliver_listener.id,
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

    /// Start an mTLS listener
    pub async fn start_mtls_listener(&self, req: &CreateListenerRequest) -> Result<Listener> {
        let url = format!("{}/api/jobs/mtls", self.base_url());

        let body = serde_json::json!({
            "Host": req.host,
            "Port": req.port,
        });

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to start mTLS listener: {}", error_text));
        }

        let sliver_listener: SliverListener = resp.json().await?;

        Ok(Listener {
            id: sliver_listener.id,
            c2_config_id: self.config.id.clone(),
            name: req.name.clone(),
            protocol: ListenerProtocol::Mtls,
            host: req.host.clone(),
            port: req.port,
            status: ListenerStatus::Active,
            domains: Vec::new(),
            website: None,
            config: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    /// Stop a listener (job)
    pub async fn stop_listener(&self, job_id: &str) -> Result<()> {
        let url = format!("{}/api/jobs/{}", self.base_url(), job_id);

        let resp = self.client.delete(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to stop listener: {}", resp.status()));
        }

        Ok(())
    }

    /// Generate an implant
    pub async fn generate_implant(&self, config: &ImplantConfig) -> Result<Vec<u8>> {
        let url = format!("{}/api/generate", self.base_url());

        let goos = match config.platform {
            Platform::Windows => "windows",
            Platform::Linux => "linux",
            Platform::MacOS => "darwin",
            Platform::FreeBSD => "freebsd",
        };

        let goarch = match config.arch {
            Architecture::X86 => "386",
            Architecture::X64 => "amd64",
            Architecture::Arm => "arm",
            Architecture::Arm64 => "arm64",
        };

        let format = match config.format {
            ImplantFormat::Exe => "exe",
            ImplantFormat::Dll => "dll",
            ImplantFormat::Shellcode => "shellcode",
            ImplantFormat::SharedLib => "shared",
            ImplantFormat::ServiceExe => "service",
        };

        let is_beacon = matches!(config.implant_type, ImplantType::Beacon);

        let body = GenerateRequest {
            name: config.name.clone(),
            mtls_enabled: config.c2_urls.iter().any(|u| u.starts_with("mtls://")),
            http_enabled: config.c2_urls.iter().any(|u| u.starts_with("http")),
            wg_enabled: config.c2_urls.iter().any(|u| u.starts_with("wg://")),
            dns_enabled: config.c2_urls.iter().any(|u| u.starts_with("dns://")),
            goos: goos.to_string(),
            goarch: goarch.to_string(),
            format: format.to_string(),
            is_beacon,
            beacon_interval: config.interval as i64,
            beacon_jitter: config.jitter as i64,
        };

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to generate implant: {}", error_text));
        }

        Ok(resp.bytes().await?.to_vec())
    }

    /// Execute a command on a session
    pub async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        let url = format!("{}/api/sessions/{}/shell", self.base_url(), session_id);

        let body = serde_json::json!({
            "Path": task.command,
            "Args": task.args,
        });

        let resp = self.client.post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to execute task: {}", error_text));
        }

        let result: TaskResult = resp.json().await?;

        Ok(Task {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            c2_task_id: Some(result.task_id),
            task_type: task.task_type.clone(),
            command: task.command.clone(),
            args: task.args.clone().unwrap_or_default(),
            status: if result.completed { TaskStatus::Completed } else { TaskStatus::Pending },
            output: result.output,
            error: result.error,
            created_at: Utc::now(),
            sent_at: Some(Utc::now()),
            completed_at: if result.completed { Some(Utc::now()) } else { None },
        })
    }

    /// Kill a session
    pub async fn kill_session(&self, session_id: &str) -> Result<()> {
        let url = format!("{}/api/sessions/{}", self.base_url(), session_id);

        let resp = self.client.delete(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token.as_deref().unwrap_or("")))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("Failed to kill session: {}", resp.status()));
        }

        Ok(())
    }

    // Helper to convert Sliver session to our Session type
    fn convert_session(&self, s: SliverSession) -> Session {
        let ip = s.remote_address.split(':').next().unwrap_or("").to_string();
        let arch = s.arch.parse().unwrap_or(Architecture::X64);

        Session {
            id: uuid::Uuid::new_v4().to_string(),
            c2_config_id: self.config.id.clone(),
            c2_session_id: s.id,
            implant_id: None,
            name: s.name,
            hostname: s.hostname,
            username: s.username,
            domain: None,
            ip_address: ip,
            external_ip: None,
            os: s.os,
            os_version: None,
            arch,
            pid: s.pid as u32,
            process_name: s.filename,
            integrity: None,
            status: if s.is_dead { SessionStatus::Dead } else { SessionStatus::Active },
            is_elevated: false,
            locale: None,
            first_seen: Utc::now(),
            last_checkin: DateTime::parse_from_rfc3339(&s.last_checkin)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            next_checkin: None,
            notes: None,
        }
    }

    // Helper to convert Sliver beacon to our Session type
    fn convert_beacon(&self, b: SliverBeacon) -> Session {
        let ip = b.remote_address.split(':').next().unwrap_or("").to_string();
        let arch = b.arch.parse().unwrap_or(Architecture::X64);

        Session {
            id: uuid::Uuid::new_v4().to_string(),
            c2_config_id: self.config.id.clone(),
            c2_session_id: b.id,
            implant_id: None,
            name: b.name,
            hostname: b.hostname,
            username: b.username,
            domain: None,
            ip_address: ip,
            external_ip: None,
            os: b.os,
            os_version: None,
            arch,
            pid: b.pid as u32,
            process_name: b.filename,
            integrity: None,
            status: if b.is_dead { SessionStatus::Dead } else { SessionStatus::Active },
            is_elevated: false,
            locale: None,
            first_seen: Utc::now(),
            last_checkin: DateTime::parse_from_rfc3339(&b.last_checkin)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            next_checkin: DateTime::parse_from_rfc3339(&b.next_checkin)
                .map(|dt| dt.with_timezone(&Utc))
                .ok(),
            notes: None,
        }
    }
}
