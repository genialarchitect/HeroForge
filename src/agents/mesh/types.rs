#![allow(dead_code)]
//! Mesh networking types for distributed agent scanning
//!
//! This module defines the core types used for agent mesh networking:
//! - Peer information and discovery
//! - Cluster definitions and membership
//! - Mesh configuration and state

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use std::net::SocketAddr;

// ============================================================================
// Peer Information
// ============================================================================

/// Information about a peer agent in the mesh network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Unique identifier of the peer agent
    pub agent_id: String,
    /// Human-readable name of the peer
    pub name: String,
    /// Network address of the peer
    pub address: String,
    /// Port for mesh communication
    pub mesh_port: u16,
    /// Current status of the peer
    pub status: PeerStatus,
    /// Load factor (0.0 - 1.0) indicating current workload
    pub load: f32,
    /// Capabilities this peer supports
    pub capabilities: Vec<String>,
    /// Network zones this peer can access
    pub network_zones: Vec<String>,
    /// Maximum concurrent tasks this peer can handle
    pub max_tasks: i32,
    /// Current number of running tasks
    pub current_tasks: i32,
    /// Protocol version supported by this peer
    pub protocol_version: String,
    /// Timestamp when peer info was last updated
    pub last_seen: DateTime<Utc>,
    /// Round-trip latency to this peer in milliseconds
    pub latency_ms: Option<i64>,
    /// Cluster ID this peer belongs to (if any)
    pub cluster_id: Option<String>,
}

impl PeerInfo {
    /// Create a new peer info instance
    pub fn new(agent_id: String, name: String, address: String, mesh_port: u16) -> Self {
        Self {
            agent_id,
            name,
            address,
            mesh_port,
            status: PeerStatus::Unknown,
            load: 0.0,
            capabilities: Vec::new(),
            network_zones: Vec::new(),
            max_tasks: 1,
            current_tasks: 0,
            protocol_version: super::protocol::MESH_PROTOCOL_VERSION.to_string(),
            last_seen: Utc::now(),
            latency_ms: None,
            cluster_id: None,
        }
    }

    /// Get the full socket address for this peer
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        format!("{}:{}", self.address, self.mesh_port).parse().ok()
    }

    /// Check if this peer is available for work
    pub fn is_available(&self) -> bool {
        self.status == PeerStatus::Online && self.current_tasks < self.max_tasks
    }

    /// Calculate available capacity (0.0 - 1.0)
    pub fn available_capacity(&self) -> f32 {
        if self.max_tasks <= 0 {
            return 0.0;
        }
        let used = self.current_tasks as f32 / self.max_tasks as f32;
        (1.0 - used).max(0.0)
    }
}

/// Status of a peer in the mesh network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// Peer status is not known
    Unknown,
    /// Peer is online and reachable
    Online,
    /// Peer is online but at capacity
    Busy,
    /// Peer is not responding to pings
    Offline,
    /// Peer is in the process of joining the mesh
    Joining,
    /// Peer is gracefully leaving the mesh
    Leaving,
    /// Peer connection was lost unexpectedly
    Disconnected,
}

impl PeerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Online => "online",
            Self::Busy => "busy",
            Self::Offline => "offline",
            Self::Joining => "joining",
            Self::Leaving => "leaving",
            Self::Disconnected => "disconnected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "unknown" => Some(Self::Unknown),
            "online" => Some(Self::Online),
            "busy" => Some(Self::Busy),
            "offline" => Some(Self::Offline),
            "joining" => Some(Self::Joining),
            "leaving" => Some(Self::Leaving),
            "disconnected" => Some(Self::Disconnected),
            _ => None,
        }
    }
}

impl std::fmt::Display for PeerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Cluster Information
// ============================================================================

/// Information about a cluster of agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterInfo {
    /// Unique cluster identifier
    pub id: String,
    /// Human-readable cluster name
    pub name: String,
    /// Description of the cluster
    pub description: Option<String>,
    /// ID of the leader agent (if elected)
    pub leader_id: Option<String>,
    /// List of peer IDs in this cluster
    pub members: Vec<String>,
    /// Cluster configuration
    pub config: ClusterConfig,
    /// Cluster health status
    pub health: ClusterHealth,
    /// When the cluster was created
    pub created_at: DateTime<Utc>,
    /// When the cluster was last updated
    pub updated_at: DateTime<Utc>,
}

impl ClusterInfo {
    /// Create a new cluster
    pub fn new(id: String, name: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            name,
            description: None,
            leader_id: None,
            members: Vec::new(),
            config: ClusterConfig::default(),
            health: ClusterHealth::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if this cluster has a quorum
    pub fn has_quorum(&self) -> bool {
        let min_quorum = self.config.min_quorum_size;
        self.members.len() >= min_quorum as usize
    }

    /// Get the number of online members
    pub fn online_count(&self) -> usize {
        self.health.online_members as usize
    }
}

/// Cluster configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Minimum number of nodes for quorum
    pub min_quorum_size: i32,
    /// Enable automatic leader election
    pub auto_elect_leader: bool,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: i32,
    /// Peer timeout threshold in seconds
    pub peer_timeout_secs: i32,
    /// Enable work stealing between peers
    pub enable_work_stealing: bool,
    /// Maximum task steal batch size
    pub max_steal_batch: i32,
    /// Enable gossip protocol for peer discovery
    pub enable_gossip: bool,
    /// Gossip fanout (number of peers to gossip to)
    pub gossip_fanout: i32,
    /// Enable mDNS for local discovery
    pub enable_mdns: bool,
    /// Central registry URL for peer discovery
    pub registry_url: Option<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            min_quorum_size: 1,
            auto_elect_leader: true,
            heartbeat_interval_secs: 10,
            peer_timeout_secs: 30,
            enable_work_stealing: true,
            max_steal_batch: 5,
            enable_gossip: true,
            gossip_fanout: 3,
            enable_mdns: true,
            registry_url: None,
        }
    }
}

/// Cluster health metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterHealth {
    /// Number of online members
    pub online_members: i32,
    /// Number of offline members
    pub offline_members: i32,
    /// Total tasks being processed
    pub total_tasks: i32,
    /// Average load across cluster
    pub average_load: f32,
    /// Cluster is healthy
    pub is_healthy: bool,
    /// Last health check time
    pub last_check: Option<DateTime<Utc>>,
}

// ============================================================================
// Database Models
// ============================================================================

/// Agent mesh configuration stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentMeshConfig {
    pub id: String,
    pub agent_id: String,
    /// Whether mesh networking is enabled for this agent
    pub enabled: bool,
    /// Port for mesh P2P communication
    pub mesh_port: i32,
    /// External address for peer connections (if different from detected)
    pub external_address: Option<String>,
    /// Cluster this agent belongs to
    pub cluster_id: Option<String>,
    /// Role in the cluster (leader, member)
    pub cluster_role: Option<String>,
    /// Configuration JSON
    pub config_json: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Agent cluster stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentCluster {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub leader_agent_id: Option<String>,
    /// Cluster configuration JSON
    pub config_json: Option<String>,
    /// Cluster health metrics JSON
    pub health_json: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Peer connection history stored in database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentPeerConnection {
    pub id: String,
    pub agent_id: String,
    pub peer_agent_id: String,
    pub peer_address: String,
    pub peer_port: i32,
    /// Connection status
    pub status: String,
    /// Round-trip latency in milliseconds
    pub latency_ms: Option<i32>,
    /// Number of successful pings
    pub successful_pings: i32,
    /// Number of failed pings
    pub failed_pings: i32,
    /// Last successful connection time
    pub last_connected_at: Option<DateTime<Utc>>,
    /// Last connection attempt time
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================================
// Task Delegation Types
// ============================================================================

/// Information about a task that can be delegated to peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTaskInfo {
    /// Task ID
    pub id: String,
    /// Scan ID this task belongs to
    pub scan_id: String,
    /// Task type (full_scan, port_scan, etc.)
    pub task_type: String,
    /// Targets for this task
    pub targets: Vec<String>,
    /// Task priority (higher = more important)
    pub priority: i32,
    /// Timeout in seconds
    pub timeout_seconds: i32,
    /// Task configuration JSON
    pub config: serde_json::Value,
    /// Network zones required for this task
    pub required_zones: Vec<String>,
    /// Capabilities required for this task
    pub required_capabilities: Vec<String>,
}

/// Result of a task delegation attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegationResult {
    /// Task was accepted by the peer
    Accepted {
        peer_id: String,
        estimated_start: Option<DateTime<Utc>>,
    },
    /// Task was rejected by the peer
    Rejected {
        peer_id: String,
        reason: String,
    },
    /// Peer is not reachable
    Unreachable {
        peer_id: String,
    },
    /// No suitable peer found
    NoPeerAvailable,
}

/// Statistics about work stealing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkStealingStats {
    /// Number of tasks stolen from peers
    pub tasks_stolen: i64,
    /// Number of tasks offered to peers
    pub tasks_offered: i64,
    /// Number of tasks successfully delegated
    pub tasks_delegated: i64,
    /// Number of delegation failures
    pub delegation_failures: i64,
    /// Average time to find a peer (ms)
    pub avg_peer_find_time_ms: f64,
}

// ============================================================================
// Mesh State
// ============================================================================

/// Current state of the mesh network from this agent's perspective
#[derive(Debug, Clone, Default)]
pub struct MeshState {
    /// Known peers in the mesh
    pub peers: HashMap<String, PeerInfo>,
    /// Clusters this agent knows about
    pub clusters: HashMap<String, ClusterInfo>,
    /// This agent's cluster membership
    pub my_cluster_id: Option<String>,
    /// Whether this agent is the cluster leader
    pub is_leader: bool,
    /// Pending outbound task offers
    pub pending_offers: Vec<String>,
    /// Work stealing statistics
    pub stealing_stats: WorkStealingStats,
}

impl MeshState {
    /// Get all online peers
    pub fn online_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.status == PeerStatus::Online)
            .collect()
    }

    /// Get available peers (online and have capacity)
    pub fn available_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().filter(|p| p.is_available()).collect()
    }

    /// Get peer by ID
    pub fn get_peer(&self, peer_id: &str) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Get peers in a specific cluster
    pub fn cluster_peers(&self, cluster_id: &str) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.cluster_id.as_deref() == Some(cluster_id))
            .collect()
    }

    /// Find best peer for a task based on load and capabilities
    pub fn find_best_peer_for_task(&self, task: &AgentTaskInfo) -> Option<&PeerInfo> {
        let mut best_peer: Option<&PeerInfo> = None;
        let mut best_score = f32::MIN;

        for peer in self.available_peers() {
            // Check required capabilities
            let has_capabilities = task
                .required_capabilities
                .iter()
                .all(|cap| peer.capabilities.contains(cap));
            if !has_capabilities {
                continue;
            }

            // Check required network zones
            let has_zones = task.required_zones.is_empty()
                || task
                    .required_zones
                    .iter()
                    .any(|zone| peer.network_zones.contains(zone));
            if !has_zones {
                continue;
            }

            // Calculate score based on available capacity and latency
            let capacity_score = peer.available_capacity();
            let latency_score = peer.latency_ms.map(|l| 1.0 / (1.0 + l as f32 / 100.0)).unwrap_or(0.5);
            let score = capacity_score * 0.7 + latency_score * 0.3;

            if score > best_score {
                best_score = score;
                best_peer = Some(peer);
            }
        }

        best_peer
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Default mesh communication port
pub const DEFAULT_MESH_PORT: u16 = 9876;

/// Default heartbeat interval
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 10;

/// Default peer timeout
pub const DEFAULT_PEER_TIMEOUT_SECS: u64 = 30;

/// Maximum peers to discover
pub const MAX_PEERS: usize = 100;

/// mDNS service type for agent discovery
pub const MDNS_SERVICE_TYPE: &str = "_heroforge-agent._tcp.local.";

/// Gossip fanout default
pub const DEFAULT_GOSSIP_FANOUT: usize = 3;
