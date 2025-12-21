#![allow(dead_code)]
//! Agent communication protocol definitions
//!
//! This module defines the protocol for communication between the server
//! and remote scan agents. Agents connect via HTTP/HTTPS and authenticate
//! using bearer tokens.
//!
//! ## Protocol Overview
//!
//! 1. **Registration**: Admin generates agent token via API
//! 2. **Connection**: Agent connects using token in Authorization header
//! 3. **Heartbeat**: Agent sends periodic heartbeats to maintain online status
//! 4. **Task Polling**: Agent polls for pending tasks
//! 5. **Execution**: Agent executes tasks and reports progress
//! 6. **Results**: Agent submits results upon task completion
//!
//! ## Security
//!
//! - Agents authenticate via Bearer tokens (256-bit random, bcrypt hashed)
//! - All communication should be over HTTPS in production
//! - Token rotation supported for security

use serde::{Deserialize, Serialize};

use super::types::{AgentTaskInfo, TaskStatus};

// ============================================================================
// Protocol Messages
// ============================================================================

/// Message types for agent-server communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// Agent registration confirmation
    Registered {
        agent_id: String,
        server_version: String,
    },

    /// Heartbeat acknowledgment
    HeartbeatAck {
        server_time: String,
        next_heartbeat_in: i64,
    },

    /// Task assignment
    TaskAssigned {
        task: AgentTaskInfo,
    },

    /// Task acknowledgment from agent
    TaskAcknowledged {
        task_id: String,
    },

    /// Task progress update from agent
    TaskProgress {
        task_id: String,
        progress_percent: f32,
        current_phase: String,
        message: Option<String>,
    },

    /// Task completion notification
    TaskCompleted {
        task_id: String,
        status: TaskStatus,
        summary: TaskCompletionSummary,
    },

    /// Error message
    Error {
        code: ErrorCode,
        message: String,
    },

    /// Agent shutdown notification
    Shutdown {
        reason: String,
    },
}

/// Summary of completed task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCompletionSummary {
    pub hosts_discovered: i32,
    pub ports_found: i32,
    pub vulnerabilities_found: i32,
    pub duration_secs: i64,
}

/// Error codes for protocol errors
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Invalid or expired authentication token
    AuthenticationFailed,
    /// Agent not found or disabled
    AgentNotFound,
    /// Task not found or not assigned to this agent
    TaskNotFound,
    /// Invalid request format
    InvalidRequest,
    /// Agent is at capacity
    AgentBusy,
    /// Server internal error
    InternalError,
    /// Rate limit exceeded
    RateLimited,
    /// Version mismatch
    VersionMismatch,
}

impl ErrorCode {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::AuthenticationFailed => 401,
            Self::AgentNotFound => 404,
            Self::TaskNotFound => 404,
            Self::InvalidRequest => 400,
            Self::AgentBusy => 503,
            Self::InternalError => 500,
            Self::RateLimited => 429,
            Self::VersionMismatch => 409,
        }
    }
}

// ============================================================================
// Task Types
// ============================================================================

/// Types of tasks that can be assigned to agents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    /// Full network triage scan
    FullScan,
    /// Host discovery only
    HostDiscovery,
    /// Port scan only
    PortScan,
    /// Service detection
    ServiceDetection,
    /// Vulnerability scan
    VulnerabilityScan,
    /// DNS reconnaissance
    DnsRecon,
    /// Web application scan
    WebAppScan,
    /// SSL/TLS analysis
    SslAnalysis,
}

impl TaskType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FullScan => "full_scan",
            Self::HostDiscovery => "host_discovery",
            Self::PortScan => "port_scan",
            Self::ServiceDetection => "service_detection",
            Self::VulnerabilityScan => "vulnerability_scan",
            Self::DnsRecon => "dns_recon",
            Self::WebAppScan => "webapp_scan",
            Self::SslAnalysis => "ssl_analysis",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "full_scan" => Some(Self::FullScan),
            "host_discovery" => Some(Self::HostDiscovery),
            "port_scan" => Some(Self::PortScan),
            "service_detection" => Some(Self::ServiceDetection),
            "vulnerability_scan" => Some(Self::VulnerabilityScan),
            "dns_recon" => Some(Self::DnsRecon),
            "webapp_scan" => Some(Self::WebAppScan),
            "ssl_analysis" => Some(Self::SslAnalysis),
            _ => None,
        }
    }
}

impl std::fmt::Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Task Configuration
// ============================================================================

/// Configuration for a scan task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskConfig {
    /// Task type
    pub task_type: TaskType,
    /// Targets (IP addresses, CIDR ranges, or domains)
    pub targets: Vec<String>,
    /// Port range for port scanning
    pub port_range: Option<(u16, u16)>,
    /// Number of concurrent threads
    pub threads: Option<usize>,
    /// Timeout per operation in milliseconds
    pub timeout_ms: Option<u64>,
    /// Scan type (tcp_connect, syn, udp, comprehensive)
    pub scan_type: Option<String>,
    /// Enable OS detection
    pub enable_os_detection: Option<bool>,
    /// Enable service detection
    pub enable_service_detection: Option<bool>,
    /// Enable vulnerability scanning
    pub enable_vuln_scan: Option<bool>,
    /// Enable service enumeration
    pub enable_enumeration: Option<bool>,
    /// Enumeration depth
    pub enum_depth: Option<String>,
    /// Specific services to enumerate
    pub enum_services: Option<Vec<String>>,
    /// UDP-specific port range
    pub udp_port_range: Option<(u16, u16)>,
    /// UDP retry count
    pub udp_retries: Option<u8>,
    /// Additional options (task-type specific)
    #[serde(default)]
    pub extra_options: serde_json::Value,
}

impl TaskConfig {
    /// Create a new task config from a scan configuration
    pub fn from_scan_config(
        task_type: TaskType,
        targets: Vec<String>,
        port_range: (u16, u16),
        config: &crate::types::ScanConfig,
    ) -> Self {
        Self {
            task_type,
            targets,
            port_range: Some(port_range),
            threads: Some(config.threads),
            timeout_ms: Some(config.timeout.as_millis() as u64),
            scan_type: Some(config.scan_type.to_string()),
            enable_os_detection: Some(config.enable_os_detection),
            enable_service_detection: Some(config.enable_service_detection),
            enable_vuln_scan: Some(config.enable_vuln_scan),
            enable_enumeration: Some(config.enable_enumeration),
            enum_depth: Some(config.enum_depth.to_string()),
            enum_services: if config.enum_services.is_empty() {
                None
            } else {
                Some(config.enum_services.iter().map(|s| s.to_string()).collect())
            },
            udp_port_range: config.udp_port_range,
            udp_retries: Some(config.udp_retries),
            extra_options: serde_json::Value::Null,
        }
    }
}

// ============================================================================
// Protocol Version
// ============================================================================

/// Current protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Minimum supported protocol version
pub const MIN_PROTOCOL_VERSION: &str = "1.0.0";

/// Check if a version is compatible
pub fn is_version_compatible(agent_version: &str) -> bool {
    // Simple version check - in production, use semver
    agent_version >= MIN_PROTOCOL_VERSION
}

// ============================================================================
// HTTP Headers
// ============================================================================

/// Header for agent token authentication
pub const HEADER_AGENT_TOKEN: &str = "X-Agent-Token";

/// Header for agent ID
pub const HEADER_AGENT_ID: &str = "X-Agent-Id";

/// Header for protocol version
pub const HEADER_PROTOCOL_VERSION: &str = "X-Protocol-Version";

/// Header for agent version
pub const HEADER_AGENT_VERSION: &str = "X-Agent-Version";

// ============================================================================
// Token Generation
// ============================================================================

use rand::Rng;

/// Generate a cryptographically secure agent token
pub fn generate_agent_token() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
    format!("hfa_{}", hex::encode(bytes))
}

/// Get the prefix of a token for display
pub fn get_token_prefix(token: &str) -> String {
    if token.len() >= super::types::TOKEN_PREFIX_LENGTH {
        token[..super::types::TOKEN_PREFIX_LENGTH].to_string()
    } else {
        token.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation() {
        let token = generate_agent_token();
        assert!(token.starts_with("hfa_"));
        assert_eq!(token.len(), 4 + 64); // "hfa_" + 32 bytes hex
    }

    #[test]
    fn test_token_prefix() {
        let token = "hfa_abcdefghijklmnop";
        let prefix = get_token_prefix(token);
        assert_eq!(prefix, "hfa_abcd");
    }

    #[test]
    fn test_task_type_round_trip() {
        for task_type in [
            TaskType::FullScan,
            TaskType::HostDiscovery,
            TaskType::PortScan,
            TaskType::ServiceDetection,
            TaskType::VulnerabilityScan,
        ] {
            let s = task_type.as_str();
            let parsed = TaskType::from_str(s).unwrap();
            assert_eq!(task_type, parsed);
        }
    }
}
