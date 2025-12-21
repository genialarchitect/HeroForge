//! Agent data structures and types for distributed scanning
//!
//! This module defines the core types used for agent-based scanning:
//! - Agent registration and status
//! - Agent groups for network segmentation
//! - Task distribution and result collection

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// ============================================================================
// Agent Status
// ============================================================================

/// Status of a scan agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    /// Agent is registered but not yet connected
    Pending,
    /// Agent is online and ready to accept tasks
    Online,
    /// Agent is currently executing a task
    Busy,
    /// Agent has not sent heartbeat within timeout period
    Offline,
    /// Agent has been disabled by admin
    Disabled,
}

impl AgentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Online => "online",
            Self::Busy => "busy",
            Self::Offline => "offline",
            Self::Disabled => "disabled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "online" => Some(Self::Online),
            "busy" => Some(Self::Busy),
            "offline" => Some(Self::Offline),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Agent Task Status
// ============================================================================

/// Status of a task assigned to an agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Task is queued and waiting for agent
    Pending,
    /// Task has been assigned to an agent
    Assigned,
    /// Task is currently being executed
    Running,
    /// Task completed successfully
    Completed,
    /// Task failed with error
    Failed,
    /// Task was cancelled
    Cancelled,
    /// Task timed out
    TimedOut,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Assigned => "assigned",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "assigned" => Some(Self::Assigned),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "timed_out" => Some(Self::TimedOut),
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut)
    }
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Core Agent Types
// ============================================================================

/// A registered scan agent
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScanAgent {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    /// Unique token for agent authentication (hashed in DB)
    #[serde(skip_serializing)]
    pub token_hash: String,
    /// Token prefix for display (first 8 chars)
    pub token_prefix: String,
    /// Current status of the agent
    pub status: String,
    /// Agent version string
    pub version: Option<String>,
    /// Hostname of the machine running the agent
    pub hostname: Option<String>,
    /// IP address the agent connects from
    pub ip_address: Option<String>,
    /// Operating system of the agent machine
    pub os_info: Option<String>,
    /// Agent capabilities (JSON array)
    pub capabilities: Option<String>,
    /// Network zones this agent can access (JSON array)
    pub network_zones: Option<String>,
    /// Max concurrent tasks
    pub max_concurrent_tasks: i32,
    /// Current number of running tasks
    pub current_tasks: i32,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub last_task_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Agent group for organizing agents by network zone
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentGroup {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    /// Network CIDR ranges this group covers (JSON array)
    pub network_ranges: Option<String>,
    /// Color for UI display
    pub color: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Junction table for agent-group membership
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentGroupMember {
    pub agent_id: String,
    pub group_id: String,
    pub added_at: DateTime<Utc>,
}

/// A task distributed to an agent
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentTask {
    pub id: String,
    pub scan_id: String,
    pub agent_id: Option<String>,
    pub group_id: Option<String>,
    pub user_id: String,
    pub status: String,
    pub task_type: String,
    /// Task configuration (JSON)
    pub config: String,
    /// Target(s) for this specific task
    pub targets: String,
    pub priority: i32,
    pub timeout_seconds: i32,
    pub retry_count: i32,
    pub max_retries: i32,
    pub error_message: Option<String>,
    pub assigned_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Result submitted by an agent for a task
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentResult {
    pub id: String,
    pub task_id: String,
    pub agent_id: String,
    /// Result data (JSON - same format as scan results)
    pub result_data: String,
    /// Summary statistics
    pub hosts_discovered: i32,
    pub ports_found: i32,
    pub vulnerabilities_found: i32,
    pub created_at: DateTime<Utc>,
}

/// Agent heartbeat record for health tracking
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentHeartbeat {
    pub id: String,
    pub agent_id: String,
    /// CPU usage percentage
    pub cpu_usage: Option<f64>,
    /// Memory usage percentage
    pub memory_usage: Option<f64>,
    /// Disk usage percentage
    pub disk_usage: Option<f64>,
    /// Current number of running tasks
    pub active_tasks: i32,
    /// Queue depth (pending tasks)
    pub queued_tasks: i32,
    /// Network latency in ms
    pub latency_ms: Option<i32>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// API Request/Response Types
// ============================================================================

/// Request to register a new agent
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterAgentRequest {
    pub name: String,
    pub description: Option<String>,
    /// Network zones this agent can access
    pub network_zones: Option<Vec<String>>,
    pub max_concurrent_tasks: Option<i32>,
}

/// Response after registering an agent
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterAgentResponse {
    pub id: String,
    pub name: String,
    /// Full token (only shown once)
    pub token: String,
    pub token_prefix: String,
    pub created_at: DateTime<Utc>,
}

/// Request to update an agent
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAgentRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub network_zones: Option<Vec<String>>,
    pub max_concurrent_tasks: Option<i32>,
    pub status: Option<String>,
}

/// Request to create an agent group
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAgentGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub network_ranges: Option<Vec<String>>,
    #[serde(default = "default_group_color")]
    pub color: String,
}

fn default_group_color() -> String {
    "#06b6d4".to_string()
}

/// Request to update an agent group
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAgentGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub network_ranges: Option<Vec<String>>,
    pub color: Option<String>,
}

/// Request to assign agents to a group
#[derive(Debug, Serialize, Deserialize)]
pub struct AssignAgentsToGroupRequest {
    pub agent_ids: Vec<String>,
}

/// Agent heartbeat request from agent
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub version: Option<String>,
    pub hostname: Option<String>,
    pub os_info: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub disk_usage: Option<f64>,
    pub active_tasks: i32,
    pub queued_tasks: i32,
}

/// Response to heartbeat with any pending tasks
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub acknowledged: bool,
    pub server_time: DateTime<Utc>,
    /// Tasks assigned to this agent
    pub pending_tasks: Vec<AgentTaskInfo>,
}

/// Task information sent to agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTaskInfo {
    pub id: String,
    pub scan_id: String,
    pub task_type: String,
    pub config: serde_json::Value,
    pub targets: Vec<String>,
    pub priority: i32,
    pub timeout_seconds: i32,
}

/// Request from agent to get tasks
#[derive(Debug, Serialize, Deserialize)]
pub struct GetTasksRequest {
    pub max_tasks: Option<i32>,
}

/// Request from agent to submit results
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitResultRequest {
    pub task_id: String,
    pub status: String,
    pub result_data: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub hosts_discovered: Option<i32>,
    pub ports_found: Option<i32>,
    pub vulnerabilities_found: Option<i32>,
}

/// Agent with group information for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentWithGroups {
    #[serde(flatten)]
    pub agent: ScanAgent,
    pub groups: Vec<AgentGroup>,
}

/// Agent group with member count for listing
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentGroupWithCount {
    #[serde(flatten)]
    pub group: AgentGroup,
    pub agent_count: i64,
}

/// Agent group with member agents
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentGroupWithAgents {
    #[serde(flatten)]
    pub group: AgentGroup,
    pub agents: Vec<ScanAgent>,
}

/// Agent statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentStats {
    pub total_agents: i64,
    pub online_agents: i64,
    pub busy_agents: i64,
    pub offline_agents: i64,
    pub total_tasks_completed: i64,
    pub total_tasks_failed: i64,
    pub average_task_duration_secs: Option<f64>,
}

/// Agent task summary for dashboard
#[derive(Debug, Serialize, Deserialize)]
pub struct TaskSummary {
    pub pending: i64,
    pub running: i64,
    pub completed: i64,
    pub failed: i64,
}

// ============================================================================
// Constants
// ============================================================================

/// Default heartbeat interval in seconds
pub const DEFAULT_HEARTBEAT_INTERVAL: i64 = 30;

/// Heartbeat timeout - agent considered offline after this many seconds
pub const HEARTBEAT_TIMEOUT_SECONDS: i64 = 90;

/// Default task timeout in seconds
pub const DEFAULT_TASK_TIMEOUT: i32 = 3600; // 1 hour

/// Maximum concurrent tasks per agent
pub const MAX_CONCURRENT_TASKS: i32 = 10;

/// Token prefix length for display
pub const TOKEN_PREFIX_LENGTH: usize = 8;
