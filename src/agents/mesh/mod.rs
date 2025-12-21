#![allow(dead_code)]
//! Mesh Networking Module for Distributed Agent Scanning
//!
//! This module extends the agent-based scanning system with mesh networking
//! capabilities, enabling agents to communicate directly with each other for:
//!
//! - **Peer Discovery**: Find other agents in the network
//! - **Work Distribution**: Delegate tasks to available peers
//! - **Work Stealing**: Balance load across the mesh
//! - **Cluster Coordination**: Form clusters with leader election
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          HeroForge Server                                │
//! │  ┌───────────────────┐     ┌────────────────────┐                        │
//! │  │  Central Registry │────▶│   Mesh Coordinator │                        │
//! │  └───────────────────┘     └────────────────────┘                        │
//! └─────────────────────────────────┬───────────────────────────────────────┘
//!                                   │
//!            ┌──────────────────────┼──────────────────────┐
//!            │                      │                      │
//!     ┌──────▼──────┐        ┌──────▼──────┐        ┌──────▼──────┐
//!     │   Agent 1   │◀──────▶│   Agent 2   │◀──────▶│   Agent 3   │
//!     │  (Leader)   │        │   (Member)  │        │   (Member)  │
//!     └─────────────┘        └─────────────┘        └─────────────┘
//!            │                      │                      │
//!            │                      │                      │
//!     ┌──────▼──────┐        ┌──────▼──────┐        ┌──────▼──────┐
//!     │  Network A  │        │  Network B  │        │  Network C  │
//!     └─────────────┘        └─────────────┘        └─────────────┘
//! ```
//!
//! ## Components
//!
//! - **types**: Core mesh networking types (PeerInfo, ClusterInfo, etc.)
//! - **protocol**: Mesh message protocol for peer communication
//! - **discovery**: Peer discovery via registry, mDNS, and gossip
//! - **scheduler**: Distributed task scheduling with work stealing
//!
//! ## Usage
//!
//! ```rust,ignore
//! use heroforge::agents::mesh::{
//!     MeshNetwork,
//!     MeshConfig,
//!     PeerInfo,
//! };
//!
//! // Create mesh network configuration
//! let config = MeshConfig {
//!     enable_mesh: true,
//!     mesh_port: 9876,
//!     registry_url: Some("https://heroforge.example.com".to_string()),
//!     enable_mdns: true,
//!     enable_gossip: true,
//!     enable_work_stealing: true,
//!     ..Default::default()
//! };
//!
//! // Start mesh network
//! let mesh = MeshNetwork::new(agent_info, config).await?;
//! mesh.start().await?;
//!
//! // Schedule a task (may be delegated to peers)
//! let result = mesh.schedule_task(task).await?;
//! ```
//!
//! ## Security
//!
//! - All peer communication is authenticated using agent tokens
//! - Cluster membership requires server validation
//! - Task delegation respects network zone boundaries

pub mod discovery;
pub mod protocol;
pub mod scheduler;
pub mod types;

// Re-export commonly used types
#[allow(unused_imports)]
pub use discovery::{DiscoveryConfig, DiscoveryService, DiscoveryServiceBuilder, PeerEvent};
#[allow(unused_imports)]
pub use protocol::{
    create_error, create_ping, create_pong, is_version_compatible, MeshErrorCode, MeshMessage,
    MessageEnvelope, TaskRejectReason, TaskSummary, MESH_PROTOCOL_VERSION,
};
#[allow(unused_imports)]
pub use scheduler::{
    DistributedScheduler, QueuedTask, ScheduleResult, SchedulerBuilder, SchedulerConfig,
    SchedulerEvent,
};
#[allow(unused_imports)]
pub use types::{
    AgentCluster, AgentMeshConfig, AgentPeerConnection, AgentTaskInfo, ClusterConfig,
    ClusterHealth, ClusterInfo, DelegationResult, MeshState, PeerInfo, PeerStatus,
    WorkStealingStats, DEFAULT_GOSSIP_FANOUT, DEFAULT_HEARTBEAT_INTERVAL_SECS, DEFAULT_MESH_PORT,
    DEFAULT_PEER_TIMEOUT_SECS, MAX_PEERS, MDNS_SERVICE_TYPE,
};

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

// ============================================================================
// Mesh Network Manager
// ============================================================================

/// High-level mesh network manager
///
/// This struct provides a unified interface for managing mesh networking,
/// combining discovery and scheduling functionality.
pub struct MeshNetwork {
    /// Local agent information
    local_agent: PeerInfo,
    /// Mesh configuration
    config: MeshConfig,
    /// Discovery service
    discovery: Arc<DiscoveryService>,
    /// Distributed scheduler
    scheduler: Option<DistributedScheduler>,
    /// Network state
    is_running: bool,
}

/// Configuration for mesh networking
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Enable mesh networking
    pub enable_mesh: bool,
    /// Port for mesh P2P communication
    pub mesh_port: u16,
    /// External address for peer connections
    pub external_address: Option<String>,
    /// Central registry URL for peer discovery
    pub registry_url: Option<String>,
    /// Agent token for authentication
    pub agent_token: String,
    /// Enable mDNS for local discovery
    pub enable_mdns: bool,
    /// Enable gossip protocol
    pub enable_gossip: bool,
    /// Gossip fanout
    pub gossip_fanout: usize,
    /// Enable work stealing
    pub enable_work_stealing: bool,
    /// Maximum local task queue size
    pub max_local_queue: usize,
    /// Threshold for considering agent busy
    pub busy_threshold: f32,
    /// Threshold for considering agent idle
    pub idle_threshold: f32,
    /// Peer timeout in seconds
    pub peer_timeout_secs: u64,
    /// Cluster ID to join (optional)
    pub cluster_id: Option<String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enable_mesh: false,
            mesh_port: DEFAULT_MESH_PORT,
            external_address: None,
            registry_url: None,
            agent_token: String::new(),
            enable_mdns: true,
            enable_gossip: true,
            gossip_fanout: DEFAULT_GOSSIP_FANOUT,
            enable_work_stealing: true,
            max_local_queue: 100,
            busy_threshold: 0.8,
            idle_threshold: 0.3,
            peer_timeout_secs: DEFAULT_PEER_TIMEOUT_SECS,
            cluster_id: None,
        }
    }
}

impl MeshNetwork {
    /// Create a new mesh network
    pub fn new(local_agent: PeerInfo, config: MeshConfig) -> Result<Self> {
        let discovery_config = DiscoveryConfig {
            registry_url: config.registry_url.clone(),
            agent_token: config.agent_token.clone(),
            enable_mdns: config.enable_mdns,
            enable_gossip: config.enable_gossip,
            gossip_fanout: config.gossip_fanout,
            peer_timeout_secs: config.peer_timeout_secs,
            refresh_interval_secs: 30,
            max_peers: MAX_PEERS,
        };

        let discovery = Arc::new(DiscoveryService::new(local_agent.clone(), discovery_config));

        Ok(Self {
            local_agent,
            config,
            discovery,
            scheduler: None,
            is_running: false,
        })
    }

    /// Start the mesh network
    pub async fn start(&mut self) -> Result<()> {
        if !self.config.enable_mesh {
            log::info!("Mesh networking is disabled");
            return Ok(());
        }

        log::info!(
            "Starting mesh network for agent {} on port {}",
            self.local_agent.agent_id,
            self.config.mesh_port
        );

        // Start discovery service
        self.discovery.start().await?;

        // Create and start scheduler
        let scheduler_config = SchedulerConfig {
            max_local_queue: self.config.max_local_queue,
            busy_threshold: self.config.busy_threshold,
            idle_threshold: self.config.idle_threshold,
            enable_work_stealing: self.config.enable_work_stealing,
            ..Default::default()
        };

        let scheduler = DistributedScheduler::new(
            self.local_agent.agent_id.clone(),
            self.discovery.clone(),
            scheduler_config,
        );

        scheduler.start().await?;
        self.scheduler = Some(scheduler);
        self.is_running = true;

        log::info!("Mesh network started successfully");
        Ok(())
    }

    /// Stop the mesh network
    pub async fn stop(&mut self) -> Result<()> {
        if !self.is_running {
            return Ok(());
        }

        log::info!("Stopping mesh network");

        // Stop scheduler
        if let Some(scheduler) = &self.scheduler {
            scheduler.stop().await?;
        }

        // Stop discovery
        self.discovery.stop().await?;

        self.is_running = false;
        log::info!("Mesh network stopped");
        Ok(())
    }

    /// Check if mesh is running
    pub fn is_running(&self) -> bool {
        self.is_running
    }

    /// Get the discovery service
    pub fn discovery(&self) -> &Arc<DiscoveryService> {
        &self.discovery
    }

    /// Get the scheduler (if running)
    pub fn scheduler(&self) -> Option<&DistributedScheduler> {
        self.scheduler.as_ref()
    }

    /// Get current mesh state
    pub async fn get_state(&self) -> MeshState {
        self.discovery.get_state().await
    }

    /// Get all known peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        self.discovery.get_peers().await
    }

    /// Get online peers
    pub async fn get_online_peers(&self) -> Vec<PeerInfo> {
        self.get_state().await.online_peers().into_iter().cloned().collect()
    }

    /// Schedule a task (may be delegated to peers)
    pub async fn schedule_task(&self, task: AgentTaskInfo) -> Result<ScheduleResult> {
        if let Some(scheduler) = &self.scheduler {
            scheduler.schedule_task(task).await
        } else {
            Ok(ScheduleResult::Failed {
                reason: "Scheduler not running".to_string(),
            })
        }
    }

    /// Subscribe to peer discovery events
    pub fn subscribe_peer_events(&self) -> broadcast::Receiver<PeerEvent> {
        self.discovery.subscribe()
    }

    /// Subscribe to scheduler events
    pub fn subscribe_scheduler_events(&self) -> Option<broadcast::Receiver<SchedulerEvent>> {
        self.scheduler.as_ref().map(|s| s.subscribe())
    }

    /// Get work stealing statistics
    pub async fn get_work_stealing_stats(&self) -> Option<WorkStealingStats> {
        if let Some(scheduler) = &self.scheduler {
            Some(scheduler.get_stats().await)
        } else {
            None
        }
    }

    /// Update a peer's information
    pub async fn update_peer(&self, peer: PeerInfo) -> Result<()> {
        self.discovery.update_peer(peer).await
    }

    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: &str) -> Result<()> {
        self.discovery.remove_peer(peer_id).await
    }

    /// Handle an incoming mesh message
    pub async fn handle_message(&self, envelope: MessageEnvelope) -> Result<Option<MeshMessage>> {
        let from_peer = envelope.from.clone();

        // Update peer last seen
        self.discovery.update_peer_last_seen(&from_peer).await;

        match envelope.message {
            MeshMessage::PeerPing { timestamp, sequence } => {
                // Respond with pong
                let _state = self.get_state().await;
                let load = self
                    .scheduler
                    .as_ref()
                    .map(|s| futures::executor::block_on(s.calculate_local_load()))
                    .unwrap_or(0.0);

                let active_tasks = self.local_agent.current_tasks;
                let status = if active_tasks >= self.local_agent.max_tasks {
                    PeerStatus::Busy
                } else {
                    PeerStatus::Online
                };

                Ok(Some(create_pong(timestamp, sequence, load, status, active_tasks)))
            }

            MeshMessage::PeerPong {
                timestamp,
                load,
                status: _,
                active_tasks,
                ..
            } => {
                // Update peer information
                let latency = protocol::calculate_rtt(timestamp);
                self.discovery.update_peer_latency(&from_peer, latency).await;
                self.discovery.update_peer_load(&from_peer, load, active_tasks).await;
                Ok(None)
            }

            MeshMessage::PeerAnnounce { .. } | MeshMessage::PeerLeave { .. } => {
                // Handle gossip
                self.discovery
                    .handle_gossip(&from_peer, envelope.message)
                    .await?;
                Ok(None)
            }

            MeshMessage::TaskOffer {
                task,
                from_agent: _,
                expires_at: _,
                ..
            } => {
                // Check if we can accept the task
                if let Some(scheduler) = &self.scheduler {
                    let local_load = scheduler.calculate_local_load().await;

                    if local_load < self.config.busy_threshold {
                        // Accept the task
                        Ok(Some(MeshMessage::TaskAccept {
                            task_id: task.id.clone(),
                            accepting_agent: self.local_agent.agent_id.clone(),
                            estimated_start: None,
                        }))
                    } else {
                        // Reject - at capacity
                        Ok(Some(MeshMessage::TaskReject {
                            task_id: task.id,
                            rejecting_agent: self.local_agent.agent_id.clone(),
                            reason: TaskRejectReason::AtCapacity,
                        }))
                    }
                } else {
                    Ok(Some(MeshMessage::TaskReject {
                        task_id: task.id,
                        rejecting_agent: self.local_agent.agent_id.clone(),
                        reason: TaskRejectReason::Other("Scheduler not running".to_string()),
                    }))
                }
            }

            MeshMessage::TaskAccept {
                task_id,
                accepting_agent,
                ..
            } => {
                if let Some(scheduler) = &self.scheduler {
                    scheduler
                        .handle_task_accept(&task_id, &accepting_agent)
                        .await?;
                }
                Ok(None)
            }

            MeshMessage::TaskReject {
                task_id,
                rejecting_agent,
                reason,
            } => {
                if let Some(scheduler) = &self.scheduler {
                    scheduler
                        .handle_task_reject(&task_id, &rejecting_agent, reason)
                        .await?;
                }
                Ok(None)
            }

            MeshMessage::TaskStealRequest {
                from_agent,
                max_tasks,
                min_priority,
                capabilities,
                network_zones,
            } => {
                if let Some(scheduler) = &self.scheduler {
                    let tasks = scheduler
                        .handle_steal_request(
                            &from_agent,
                            max_tasks,
                            min_priority,
                            &capabilities,
                            &network_zones,
                        )
                        .await?;

                    Ok(Some(MeshMessage::TaskStealResponse {
                        from_agent: self.local_agent.agent_id.clone(),
                        available_tasks: tasks,
                    }))
                } else {
                    Ok(Some(MeshMessage::TaskStealResponse {
                        from_agent: self.local_agent.agent_id.clone(),
                        available_tasks: vec![],
                    }))
                }
            }

            MeshMessage::TaskStealConfirm {
                task_ids,
                stealing_agent,
            } => {
                if let Some(scheduler) = &self.scheduler {
                    scheduler
                        .handle_steal_confirm(&task_ids, &stealing_agent)
                        .await?;
                }
                Ok(None)
            }

            // Other messages handled as needed
            _ => {
                log::debug!(
                    "Unhandled mesh message type: {}",
                    envelope.message.message_type()
                );
                Ok(None)
            }
        }
    }
}

// ============================================================================
// Mesh Network Builder
// ============================================================================

/// Builder for creating a MeshNetwork
pub struct MeshNetworkBuilder {
    local_agent: Option<PeerInfo>,
    config: MeshConfig,
}

impl MeshNetworkBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            local_agent: None,
            config: MeshConfig::default(),
        }
    }

    /// Set the local agent
    pub fn local_agent(mut self, agent: PeerInfo) -> Self {
        self.local_agent = Some(agent);
        self
    }

    /// Enable mesh networking
    pub fn enable(mut self, enable: bool) -> Self {
        self.config.enable_mesh = enable;
        self
    }

    /// Set mesh port
    pub fn mesh_port(mut self, port: u16) -> Self {
        self.config.mesh_port = port;
        self
    }

    /// Set external address
    pub fn external_address(mut self, address: String) -> Self {
        self.config.external_address = Some(address);
        self
    }

    /// Set registry URL
    pub fn registry_url(mut self, url: String) -> Self {
        self.config.registry_url = Some(url);
        self
    }

    /// Set agent token
    pub fn agent_token(mut self, token: String) -> Self {
        self.config.agent_token = token;
        self
    }

    /// Enable mDNS
    pub fn enable_mdns(mut self, enable: bool) -> Self {
        self.config.enable_mdns = enable;
        self
    }

    /// Enable gossip
    pub fn enable_gossip(mut self, enable: bool) -> Self {
        self.config.enable_gossip = enable;
        self
    }

    /// Enable work stealing
    pub fn enable_work_stealing(mut self, enable: bool) -> Self {
        self.config.enable_work_stealing = enable;
        self
    }

    /// Set cluster ID
    pub fn cluster_id(mut self, id: String) -> Self {
        self.config.cluster_id = Some(id);
        self
    }

    /// Build the mesh network
    pub fn build(self) -> Result<MeshNetwork> {
        let local_agent = self
            .local_agent
            .ok_or_else(|| anyhow::anyhow!("Local agent is required"))?;

        MeshNetwork::new(local_agent, self.config)
    }
}

impl Default for MeshNetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_config_defaults() {
        let config = MeshConfig::default();
        assert!(!config.enable_mesh);
        assert_eq!(config.mesh_port, DEFAULT_MESH_PORT);
        assert!(config.enable_mdns);
        assert!(config.enable_gossip);
        assert!(config.enable_work_stealing);
    }

    #[test]
    fn test_builder() {
        let peer = PeerInfo::new(
            "agent-1".to_string(),
            "Agent 1".to_string(),
            "192.168.1.1".to_string(),
            9876,
        );

        let network = MeshNetworkBuilder::new()
            .local_agent(peer)
            .enable(true)
            .mesh_port(9876)
            .enable_mdns(true)
            .enable_gossip(true)
            .enable_work_stealing(true)
            .build();

        assert!(network.is_ok());
        let network = network.unwrap();
        assert!(!network.is_running());
    }
}
