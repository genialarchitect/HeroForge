#![allow(dead_code)]
//! Mesh message protocol for peer-to-peer agent communication
//!
//! This module defines the protocol messages used for communication between
//! agents in the mesh network. The protocol supports:
//! - Peer discovery and announcement
//! - Health monitoring (ping/pong)
//! - Task delegation and work stealing
//! - Cluster coordination
//!
//! ## Protocol Overview
//!
//! Messages are serialized as JSON and transmitted over TCP or UDP:
//! - TCP for reliable task delegation and large payloads
//! - UDP for fast heartbeats and discovery
//!
//! ## Message Flow
//!
//! 1. **Discovery**: PeerAnnounce/PeerRequest for mesh joining
//! 2. **Health**: PeerPing/PeerPong for liveness checks
//! 3. **Tasks**: TaskOffer/TaskAccept/TaskReject for work distribution
//! 4. **Cluster**: LeaderElection/ClusterState for coordination

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::{AgentTaskInfo, ClusterConfig, ClusterHealth, PeerInfo, PeerStatus};

// ============================================================================
// Protocol Version
// ============================================================================

/// Current mesh protocol version
pub const MESH_PROTOCOL_VERSION: &str = "1.0.0";

/// Minimum supported mesh protocol version
pub const MIN_MESH_PROTOCOL_VERSION: &str = "1.0.0";

/// Magic bytes for mesh protocol identification
pub const MESH_MAGIC: &[u8; 4] = b"HFMP"; // HeroForge Mesh Protocol

/// Maximum message size in bytes (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

// ============================================================================
// Mesh Messages
// ============================================================================

/// Messages exchanged between mesh peers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MeshMessage {
    // ========================================================================
    // Discovery Messages
    // ========================================================================

    /// Announce presence to other peers
    PeerAnnounce {
        /// Information about the announcing peer
        info: PeerInfo,
        /// List of known peers to share (gossip)
        known_peers: Vec<PeerInfo>,
    },

    /// Request peer information from another agent
    PeerRequest {
        /// ID of the requesting agent
        from: String,
        /// Protocol version
        protocol_version: String,
    },

    /// Response to a peer request
    PeerResponse {
        /// Information about the responding peer
        info: PeerInfo,
        /// List of known peers
        known_peers: Vec<PeerInfo>,
    },

    /// Notify peers that this agent is leaving the mesh
    PeerLeave {
        /// ID of the leaving agent
        agent_id: String,
        /// Reason for leaving
        reason: Option<String>,
    },

    // ========================================================================
    // Health Check Messages
    // ========================================================================

    /// Ping message for liveness check
    PeerPing {
        /// Timestamp when ping was sent
        timestamp: i64,
        /// Sequence number for RTT calculation
        sequence: u64,
    },

    /// Pong response to ping
    PeerPong {
        /// Original timestamp from ping
        timestamp: i64,
        /// Sequence number from ping
        sequence: u64,
        /// Current load factor (0.0 - 1.0)
        load: f32,
        /// Current status
        status: PeerStatus,
        /// Number of active tasks
        active_tasks: i32,
    },

    // ========================================================================
    // Task Delegation Messages
    // ========================================================================

    /// Offer a task to a peer
    TaskOffer {
        /// Task information
        task: AgentTaskInfo,
        /// Agent offering the task
        from_agent: String,
        /// Offer expiration time
        expires_at: DateTime<Utc>,
        /// Priority boost for urgent tasks
        priority_boost: i32,
    },

    /// Accept a task offer
    TaskAccept {
        /// ID of the accepted task
        task_id: String,
        /// Agent accepting the task
        accepting_agent: String,
        /// Estimated start time
        estimated_start: Option<DateTime<Utc>>,
    },

    /// Reject a task offer
    TaskReject {
        /// ID of the rejected task
        task_id: String,
        /// Agent rejecting the task
        rejecting_agent: String,
        /// Reason for rejection
        reason: TaskRejectReason,
    },

    /// Request to steal tasks from a peer (work stealing)
    TaskStealRequest {
        /// Agent requesting tasks
        from_agent: String,
        /// Maximum number of tasks to steal
        max_tasks: i32,
        /// Minimum task priority to steal
        min_priority: i32,
        /// Required capabilities
        capabilities: Vec<String>,
        /// Required network zones
        network_zones: Vec<String>,
    },

    /// Response to a task steal request
    TaskStealResponse {
        /// Agent responding to steal request
        from_agent: String,
        /// Tasks available for stealing
        available_tasks: Vec<AgentTaskInfo>,
    },

    /// Confirm task was stolen
    TaskStealConfirm {
        /// IDs of tasks being stolen
        task_ids: Vec<String>,
        /// Agent that stole the tasks
        stealing_agent: String,
    },

    /// Update on task progress (for delegated tasks)
    TaskProgress {
        /// Task ID
        task_id: String,
        /// Reporting agent
        agent_id: String,
        /// Progress percentage (0-100)
        progress_percent: f32,
        /// Current phase
        phase: String,
        /// Optional message
        message: Option<String>,
    },

    /// Task completion notification
    TaskComplete {
        /// Task ID
        task_id: String,
        /// Reporting agent
        agent_id: String,
        /// Whether task succeeded
        success: bool,
        /// Error message if failed
        error: Option<String>,
        /// Summary statistics
        summary: Option<TaskSummary>,
    },

    // ========================================================================
    // Cluster Coordination Messages
    // ========================================================================

    /// Request leader election
    LeaderElection {
        /// Cluster ID
        cluster_id: String,
        /// Candidate agent ID
        candidate_id: String,
        /// Election term number
        term: u64,
        /// Candidate's priority score
        priority: i32,
    },

    /// Vote in leader election
    LeaderVote {
        /// Cluster ID
        cluster_id: String,
        /// Voting agent ID
        voter_id: String,
        /// Candidate being voted for
        candidate_id: String,
        /// Election term
        term: u64,
        /// Vote granted
        granted: bool,
    },

    /// Announce new leader
    LeaderAnnounce {
        /// Cluster ID
        cluster_id: String,
        /// New leader ID
        leader_id: String,
        /// Election term
        term: u64,
    },

    /// Cluster state synchronization
    ClusterState {
        /// Cluster ID
        cluster_id: String,
        /// Current leader
        leader_id: Option<String>,
        /// Current term
        term: u64,
        /// Cluster configuration
        config: ClusterConfig,
        /// Cluster health
        health: ClusterHealth,
        /// Member list
        members: Vec<String>,
    },

    /// Join cluster request
    ClusterJoin {
        /// Cluster ID to join
        cluster_id: String,
        /// Joining agent info
        agent_info: PeerInfo,
    },

    /// Cluster join response
    ClusterJoinResponse {
        /// Cluster ID
        cluster_id: String,
        /// Whether join was accepted
        accepted: bool,
        /// Reason if rejected
        reason: Option<String>,
        /// Current cluster state if accepted
        cluster_state: Option<Box<MeshMessage>>,
    },

    // ========================================================================
    // Utility Messages
    // ========================================================================

    /// Acknowledgment for reliable delivery
    Ack {
        /// Message ID being acknowledged
        message_id: String,
    },

    /// Error response
    Error {
        /// Error code
        code: MeshErrorCode,
        /// Error message
        message: String,
        /// Related message ID if applicable
        related_message_id: Option<String>,
    },
}

impl MeshMessage {
    /// Get a unique identifier for this message type
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::PeerAnnounce { .. } => "peer_announce",
            Self::PeerRequest { .. } => "peer_request",
            Self::PeerResponse { .. } => "peer_response",
            Self::PeerLeave { .. } => "peer_leave",
            Self::PeerPing { .. } => "peer_ping",
            Self::PeerPong { .. } => "peer_pong",
            Self::TaskOffer { .. } => "task_offer",
            Self::TaskAccept { .. } => "task_accept",
            Self::TaskReject { .. } => "task_reject",
            Self::TaskStealRequest { .. } => "task_steal_request",
            Self::TaskStealResponse { .. } => "task_steal_response",
            Self::TaskStealConfirm { .. } => "task_steal_confirm",
            Self::TaskProgress { .. } => "task_progress",
            Self::TaskComplete { .. } => "task_complete",
            Self::LeaderElection { .. } => "leader_election",
            Self::LeaderVote { .. } => "leader_vote",
            Self::LeaderAnnounce { .. } => "leader_announce",
            Self::ClusterState { .. } => "cluster_state",
            Self::ClusterJoin { .. } => "cluster_join",
            Self::ClusterJoinResponse { .. } => "cluster_join_response",
            Self::Ack { .. } => "ack",
            Self::Error { .. } => "error",
        }
    }

    /// Serialize the message to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize a message from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Serialize with length prefix for TCP framing
    pub fn to_framed_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let len = json.len() as u32;
        let mut result = Vec::with_capacity(4 + json.len());
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&json);
        Ok(result)
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Reason for rejecting a task
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskRejectReason {
    /// Agent is at capacity
    AtCapacity,
    /// Missing required capabilities
    MissingCapabilities,
    /// Cannot access required network zones
    NetworkZoneUnavailable,
    /// Task priority too low
    LowPriority,
    /// Agent is shutting down
    ShuttingDown,
    /// Generic rejection
    Other(String),
}

impl std::fmt::Display for TaskRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtCapacity => write!(f, "Agent at capacity"),
            Self::MissingCapabilities => write!(f, "Missing required capabilities"),
            Self::NetworkZoneUnavailable => write!(f, "Network zone unavailable"),
            Self::LowPriority => write!(f, "Task priority too low"),
            Self::ShuttingDown => write!(f, "Agent shutting down"),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// Summary of completed task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSummary {
    /// Number of hosts discovered
    pub hosts_discovered: i32,
    /// Number of ports found
    pub ports_found: i32,
    /// Number of vulnerabilities found
    pub vulnerabilities_found: i32,
    /// Duration in seconds
    pub duration_secs: i64,
}

/// Error codes for mesh protocol errors
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshErrorCode {
    /// Unknown error
    Unknown,
    /// Protocol version mismatch
    VersionMismatch,
    /// Message too large
    MessageTooLarge,
    /// Invalid message format
    InvalidMessage,
    /// Authentication failed
    AuthenticationFailed,
    /// Peer not found
    PeerNotFound,
    /// Cluster not found
    ClusterNotFound,
    /// Not cluster leader
    NotLeader,
    /// Rate limited
    RateLimited,
    /// Internal error
    InternalError,
}

impl MeshErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::VersionMismatch => "version_mismatch",
            Self::MessageTooLarge => "message_too_large",
            Self::InvalidMessage => "invalid_message",
            Self::AuthenticationFailed => "authentication_failed",
            Self::PeerNotFound => "peer_not_found",
            Self::ClusterNotFound => "cluster_not_found",
            Self::NotLeader => "not_leader",
            Self::RateLimited => "rate_limited",
            Self::InternalError => "internal_error",
        }
    }
}

// ============================================================================
// Message Envelope
// ============================================================================

/// Envelope for mesh messages with routing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Unique message ID
    pub id: String,
    /// Sender agent ID
    pub from: String,
    /// Target agent ID (or broadcast)
    pub to: Option<String>,
    /// Timestamp when message was created
    pub timestamp: DateTime<Utc>,
    /// Protocol version
    pub version: String,
    /// The actual message
    pub message: MeshMessage,
    /// Optional signature for authentication
    pub signature: Option<String>,
}

impl MessageEnvelope {
    /// Create a new message envelope
    pub fn new(from: String, to: Option<String>, message: MeshMessage) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            from,
            to,
            timestamp: Utc::now(),
            version: MESH_PROTOCOL_VERSION.to_string(),
            message,
            signature: None,
        }
    }

    /// Create a broadcast envelope (no specific target)
    pub fn broadcast(from: String, message: MeshMessage) -> Self {
        Self::new(from, None, message)
    }

    /// Check if this is a broadcast message
    pub fn is_broadcast(&self) -> bool {
        self.to.is_none()
    }

    /// Serialize the envelope to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize an envelope from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ============================================================================
// Protocol Helpers
// ============================================================================

/// Check if a protocol version is compatible
pub fn is_version_compatible(version: &str) -> bool {
    version >= MIN_MESH_PROTOCOL_VERSION
}

/// Create a ping message
pub fn create_ping(sequence: u64) -> MeshMessage {
    MeshMessage::PeerPing {
        timestamp: Utc::now().timestamp_millis(),
        sequence,
    }
}

/// Create a pong response
pub fn create_pong(ping_timestamp: i64, sequence: u64, load: f32, status: PeerStatus, active_tasks: i32) -> MeshMessage {
    MeshMessage::PeerPong {
        timestamp: ping_timestamp,
        sequence,
        load,
        status,
        active_tasks,
    }
}

/// Create an error response
pub fn create_error(code: MeshErrorCode, message: String, related_id: Option<String>) -> MeshMessage {
    MeshMessage::Error {
        code,
        message,
        related_message_id: related_id,
    }
}

/// Calculate RTT from ping timestamp
pub fn calculate_rtt(ping_timestamp: i64) -> i64 {
    let now = Utc::now().timestamp_millis();
    now - ping_timestamp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = MeshMessage::PeerPing {
            timestamp: 1234567890,
            sequence: 1,
        };

        let bytes = msg.to_bytes().unwrap();
        let decoded = MeshMessage::from_bytes(&bytes).unwrap();

        match decoded {
            MeshMessage::PeerPing { timestamp, sequence } => {
                assert_eq!(timestamp, 1234567890);
                assert_eq!(sequence, 1);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_envelope_creation() {
        let msg = MeshMessage::PeerPing {
            timestamp: 1234567890,
            sequence: 1,
        };

        let envelope = MessageEnvelope::new(
            "agent-1".to_string(),
            Some("agent-2".to_string()),
            msg,
        );

        assert_eq!(envelope.from, "agent-1");
        assert_eq!(envelope.to, Some("agent-2".to_string()));
        assert!(!envelope.is_broadcast());
    }

    #[test]
    fn test_broadcast_envelope() {
        let msg = MeshMessage::PeerAnnounce {
            info: PeerInfo::new(
                "agent-1".to_string(),
                "Agent 1".to_string(),
                "192.168.1.1".to_string(),
                9876,
            ),
            known_peers: vec![],
        };

        let envelope = MessageEnvelope::broadcast("agent-1".to_string(), msg);

        assert!(envelope.is_broadcast());
        assert!(envelope.to.is_none());
    }

    #[test]
    fn test_version_compatibility() {
        assert!(is_version_compatible("1.0.0"));
        assert!(is_version_compatible("1.1.0"));
        assert!(is_version_compatible("2.0.0"));
        assert!(!is_version_compatible("0.9.0"));
    }
}
