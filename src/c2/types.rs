//! C2 Framework Integration Types
//!
//! Types for managing Command & Control framework integrations including
//! Cobalt Strike, Sliver, Havoc, Mythic, and Custom protocols.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported C2 frameworks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum C2Framework {
    CobaltStrike,
    Sliver,
    Havoc,
    Mythic,
    Custom,
}

impl std::fmt::Display for C2Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            C2Framework::CobaltStrike => write!(f, "cobaltstrike"),
            C2Framework::Sliver => write!(f, "sliver"),
            C2Framework::Havoc => write!(f, "havoc"),
            C2Framework::Mythic => write!(f, "mythic"),
            C2Framework::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for C2Framework {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cobaltstrike" | "cobalt_strike" | "cs" => Ok(C2Framework::CobaltStrike),
            "sliver" => Ok(C2Framework::Sliver),
            "havoc" => Ok(C2Framework::Havoc),
            "mythic" => Ok(C2Framework::Mythic),
            "custom" => Ok(C2Framework::Custom),
            _ => Err(format!("Unknown C2 framework: {}", s)),
        }
    }
}

/// C2 server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Config {
    pub id: String,
    pub name: String,
    pub framework: C2Framework,
    pub host: String,
    pub port: u16,
    pub api_token: Option<String>,
    pub mtls_cert: Option<String>,
    pub mtls_key: Option<String>,
    pub ca_cert: Option<String>,
    pub verify_ssl: bool,
    pub user_id: String,
    pub connected: bool,
    pub last_connected: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Connection status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
    Error,
}

impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionStatus::Connected => write!(f, "connected"),
            ConnectionStatus::Disconnected => write!(f, "disconnected"),
            ConnectionStatus::Connecting => write!(f, "connecting"),
            ConnectionStatus::Error => write!(f, "error"),
        }
    }
}

/// Listener protocol types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    Http,
    Https,
    Mtls,
    Dns,
    Tcp,
    Wg,        // WireGuard
    Pivot,
}

impl std::fmt::Display for ListenerProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenerProtocol::Http => write!(f, "http"),
            ListenerProtocol::Https => write!(f, "https"),
            ListenerProtocol::Mtls => write!(f, "mtls"),
            ListenerProtocol::Dns => write!(f, "dns"),
            ListenerProtocol::Tcp => write!(f, "tcp"),
            ListenerProtocol::Wg => write!(f, "wg"),
            ListenerProtocol::Pivot => write!(f, "pivot"),
        }
    }
}

impl std::str::FromStr for ListenerProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "http" => Ok(ListenerProtocol::Http),
            "https" => Ok(ListenerProtocol::Https),
            "mtls" => Ok(ListenerProtocol::Mtls),
            "dns" => Ok(ListenerProtocol::Dns),
            "tcp" => Ok(ListenerProtocol::Tcp),
            "wg" | "wireguard" => Ok(ListenerProtocol::Wg),
            "pivot" => Ok(ListenerProtocol::Pivot),
            _ => Err(format!("Unknown protocol: {}", s)),
        }
    }
}

/// Listener status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerStatus {
    Active,
    Stopped,
    Starting,
    Error,
}

impl std::fmt::Display for ListenerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenerStatus::Active => write!(f, "active"),
            ListenerStatus::Stopped => write!(f, "stopped"),
            ListenerStatus::Starting => write!(f, "starting"),
            ListenerStatus::Error => write!(f, "error"),
        }
    }
}

/// C2 Listener definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listener {
    pub id: String,
    pub c2_config_id: String,
    pub name: String,
    pub protocol: ListenerProtocol,
    pub host: String,
    pub port: u16,
    pub status: ListenerStatus,
    pub domains: Vec<String>,
    pub website: Option<String>,
    pub config: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Target platform for implants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    FreeBSD,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Windows => write!(f, "windows"),
            Platform::Linux => write!(f, "linux"),
            Platform::MacOS => write!(f, "macos"),
            Platform::FreeBSD => write!(f, "freebsd"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "windows" | "win" => Ok(Platform::Windows),
            "linux" => Ok(Platform::Linux),
            "macos" | "darwin" | "osx" => Ok(Platform::MacOS),
            "freebsd" => Ok(Platform::FreeBSD),
            _ => Err(format!("Unknown platform: {}", s)),
        }
    }
}

/// CPU architecture
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X64,
    Arm,
    Arm64,
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::X86 => write!(f, "x86"),
            Architecture::X64 => write!(f, "x64"),
            Architecture::Arm => write!(f, "arm"),
            Architecture::Arm64 => write!(f, "arm64"),
        }
    }
}

impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x86" | "386" | "i386" | "i686" => Ok(Architecture::X86),
            "x64" | "amd64" | "x86_64" => Ok(Architecture::X64),
            "arm" | "armv7" => Ok(Architecture::Arm),
            "arm64" | "aarch64" => Ok(Architecture::Arm64),
            _ => Err(format!("Unknown architecture: {}", s)),
        }
    }
}

/// Implant output format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImplantFormat {
    Exe,
    Dll,
    Shellcode,
    SharedLib,
    ServiceExe,
}

impl std::fmt::Display for ImplantFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImplantFormat::Exe => write!(f, "exe"),
            ImplantFormat::Dll => write!(f, "dll"),
            ImplantFormat::Shellcode => write!(f, "shellcode"),
            ImplantFormat::SharedLib => write!(f, "shared"),
            ImplantFormat::ServiceExe => write!(f, "service"),
        }
    }
}

/// Implant type (beacon vs session)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImplantType {
    Beacon,     // Async, periodic callbacks
    Session,    // Real-time interactive
}

/// Implant configuration for generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantConfig {
    pub name: String,
    pub c2_config_id: String,
    pub listener_id: String,
    pub platform: Platform,
    pub arch: Architecture,
    pub format: ImplantFormat,
    pub implant_type: ImplantType,

    // C2 communication settings
    pub c2_urls: Vec<String>,
    pub jitter: u32,              // Percentage (0-100)
    pub interval: u32,            // Seconds between callbacks

    // Evasion settings
    pub debug: bool,
    pub obfuscation: bool,
    pub evasion: bool,
    pub skip_symbols: bool,

    // Optional features
    pub canaries: Vec<String>,
    pub connection_retries: u32,
    pub timeout: u32,

    // Additional config
    pub extra_config: HashMap<String, serde_json::Value>,
}

/// Generated implant record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implant {
    pub id: String,
    pub c2_config_id: String,
    pub name: String,
    pub platform: Platform,
    pub arch: Architecture,
    pub format: ImplantFormat,
    pub implant_type: ImplantType,
    pub listener_id: String,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub file_size: Option<u64>,
    pub download_count: u32,
    pub created_at: DateTime<Utc>,
}

/// Session status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    Dormant,
    Dead,
    Lost,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "active"),
            SessionStatus::Dormant => write!(f, "dormant"),
            SessionStatus::Dead => write!(f, "dead"),
            SessionStatus::Lost => write!(f, "lost"),
        }
    }
}

impl std::str::FromStr for SessionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" | "alive" => Ok(SessionStatus::Active),
            "dormant" | "asleep" => Ok(SessionStatus::Dormant),
            "dead" | "killed" => Ok(SessionStatus::Dead),
            "lost" | "missing" => Ok(SessionStatus::Lost),
            _ => Err(format!("Unknown session status: {}", s)),
        }
    }
}

/// Active session/beacon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub c2_config_id: String,
    pub c2_session_id: String,      // ID from the C2 framework
    pub implant_id: Option<String>,
    pub name: String,
    pub hostname: String,
    pub username: String,
    pub domain: Option<String>,
    pub ip_address: String,
    pub external_ip: Option<String>,
    pub os: String,
    pub os_version: Option<String>,
    pub arch: Architecture,
    pub pid: u32,
    pub process_name: String,
    pub integrity: Option<String>,    // High, Medium, Low, System
    pub status: SessionStatus,
    pub is_elevated: bool,
    pub locale: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_checkin: DateTime<Utc>,
    pub next_checkin: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

/// Task status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Pending,
    Sent,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "pending"),
            TaskStatus::Sent => write!(f, "sent"),
            TaskStatus::Running => write!(f, "running"),
            TaskStatus::Completed => write!(f, "completed"),
            TaskStatus::Failed => write!(f, "failed"),
            TaskStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Task queued for a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub session_id: String,
    pub c2_task_id: Option<String>,
    pub task_type: String,
    pub command: String,
    pub args: Vec<String>,
    pub status: TaskStatus,
    pub output: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Credential extracted from session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Credential {
    pub id: String,
    pub session_id: String,
    pub credential_type: CredentialType,
    pub username: String,
    pub domain: Option<String>,
    pub secret: String,             // Password, hash, ticket, etc.
    pub source: String,             // Where it was extracted from
    pub target: Option<String>,     // Target system if applicable
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Type of credential
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    Plaintext,
    NtlmHash,
    Kerberos,
    Certificate,
    SshKey,
    Token,
    Cookie,
    ApiKey,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialType::Plaintext => write!(f, "plaintext"),
            CredentialType::NtlmHash => write!(f, "ntlm"),
            CredentialType::Kerberos => write!(f, "kerberos"),
            CredentialType::Certificate => write!(f, "certificate"),
            CredentialType::SshKey => write!(f, "ssh_key"),
            CredentialType::Token => write!(f, "token"),
            CredentialType::Cookie => write!(f, "cookie"),
            CredentialType::ApiKey => write!(f, "api_key"),
        }
    }
}

/// File downloaded from session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadedFile {
    pub id: String,
    pub session_id: String,
    pub remote_path: String,
    pub local_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_hash: String,
    pub downloaded_at: DateTime<Utc>,
}

/// Screenshot from session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Screenshot {
    pub id: String,
    pub session_id: String,
    pub file_path: String,
    pub width: u32,
    pub height: u32,
    pub captured_at: DateTime<Utc>,
}

// ============================================================================
// API Request/Response Types
// ============================================================================

/// Request to create a C2 configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CreateC2ConfigRequest {
    pub name: String,
    pub framework: C2Framework,
    pub host: String,
    pub port: u16,
    pub api_token: Option<String>,
    pub mtls_cert: Option<String>,
    pub mtls_key: Option<String>,
    pub ca_cert: Option<String>,
    pub verify_ssl: Option<bool>,
}

/// Request to create a listener
#[derive(Debug, Clone, Deserialize)]
pub struct CreateListenerRequest {
    pub name: String,
    pub protocol: ListenerProtocol,
    pub host: String,
    pub port: u16,
    pub domains: Option<Vec<String>>,
    pub website: Option<String>,
    pub config: Option<HashMap<String, serde_json::Value>>,
}

/// Request to generate an implant
#[derive(Debug, Clone, Deserialize)]
pub struct GenerateImplantRequest {
    pub name: String,
    pub listener_id: String,
    pub platform: Platform,
    pub arch: Architecture,
    pub format: ImplantFormat,
    pub implant_type: Option<ImplantType>,
    pub jitter: Option<u32>,
    pub interval: Option<u32>,
    pub debug: Option<bool>,
    pub obfuscation: Option<bool>,
    pub evasion: Option<bool>,
}

/// Request to execute a task
#[derive(Debug, Clone, Deserialize)]
pub struct ExecuteTaskRequest {
    pub task_type: String,
    pub command: String,
    pub args: Option<Vec<String>>,
}

/// Session summary for listing
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub username: String,
    pub ip_address: String,
    pub os: String,
    pub arch: String,
    pub status: SessionStatus,
    pub is_elevated: bool,
    pub last_checkin: DateTime<Utc>,
}

/// C2 server summary
#[derive(Debug, Clone, Serialize)]
pub struct C2Summary {
    pub id: String,
    pub name: String,
    pub framework: C2Framework,
    pub host: String,
    pub port: u16,
    pub connected: bool,
    pub listener_count: u32,
    pub session_count: u32,
    pub last_connected: Option<DateTime<Utc>>,
}

/// Dashboard stats
#[derive(Debug, Clone, Serialize)]
pub struct C2DashboardStats {
    pub total_servers: u32,
    pub connected_servers: u32,
    pub total_listeners: u32,
    pub active_listeners: u32,
    pub total_sessions: u32,
    pub active_sessions: u32,
    pub total_implants: u32,
    pub total_credentials: u32,
    pub sessions_by_os: HashMap<String, u32>,
    pub sessions_by_framework: HashMap<String, u32>,
}

/// Common task types
pub mod task_types {
    pub const SHELL: &str = "shell";
    pub const EXECUTE: &str = "execute";
    pub const UPLOAD: &str = "upload";
    pub const DOWNLOAD: &str = "download";
    pub const SCREENSHOT: &str = "screenshot";
    pub const KEYLOGGER: &str = "keylogger";
    pub const PROCESS_LIST: &str = "ps";
    pub const KILL_PROCESS: &str = "kill";
    pub const NETSTAT: &str = "netstat";
    pub const IFCONFIG: &str = "ifconfig";
    pub const PWD: &str = "pwd";
    pub const LS: &str = "ls";
    pub const CD: &str = "cd";
    pub const CAT: &str = "cat";
    pub const MKDIR: &str = "mkdir";
    pub const RM: &str = "rm";
    pub const WHOAMI: &str = "whoami";
    pub const GETUID: &str = "getuid";
    pub const GETPID: &str = "getpid";
    pub const GETENV: &str = "getenv";
    pub const SIDELOAD: &str = "sideload";
    pub const SPAWN: &str = "spawn";
    pub const MIGRATE: &str = "migrate";
    pub const INJECT: &str = "inject";
    pub const PIVOTS: &str = "pivots";
    pub const PORTFWD: &str = "portfwd";
    pub const SOCKS: &str = "socks";

    // Credential operations
    pub const MIMIKATZ: &str = "mimikatz";
    pub const HASHDUMP: &str = "hashdump";
    pub const KERBEROS_TICKETS: &str = "kerberos_tickets";
    pub const SAM_DUMP: &str = "sam_dump";
    pub const LSA_SECRETS: &str = "lsa_secrets";

    // Persistence
    pub const PERSISTENCE: &str = "persistence";
    pub const BACKDOOR: &str = "backdoor";

    // Recon
    pub const PORTSCAN: &str = "portscan";
    pub const PING: &str = "ping";
}
