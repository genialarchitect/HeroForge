#![allow(dead_code)]
//! Peer discovery for mesh networking
//!
//! This module provides multiple mechanisms for discovering peers in the mesh:
//! - **Central Registry**: Server-based peer registration and lookup
//! - **mDNS**: Local network discovery using multicast DNS
//! - **Gossip**: Peer-to-peer information sharing
//!
//! ## Discovery Flow
//!
//! 1. Agent starts and enables mesh networking
//! 2. Agent registers with central registry (if configured)
//! 3. Agent broadcasts mDNS announcement (if enabled)
//! 4. Agent receives peer info and initiates connections
//! 5. Connected peers share their known peers (gossip)
//!
//! ## Security
//!
//! - Peers authenticate using agent tokens
//! - Central registry validates agent ownership
//! - mDNS discovery requires network access control

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::time;

use super::protocol::{MeshMessage, MessageEnvelope, MESH_PROTOCOL_VERSION};
use super::types::{
    ClusterInfo, MeshState, PeerInfo, PeerStatus, DEFAULT_GOSSIP_FANOUT,
    DEFAULT_PEER_TIMEOUT_SECS, MAX_PEERS, MDNS_SERVICE_TYPE,
};

// ============================================================================
// Discovery Service
// ============================================================================

/// Peer discovery service for mesh networking
pub struct DiscoveryService {
    /// Local agent information
    local_agent: PeerInfo,
    /// Current mesh state
    state: Arc<RwLock<MeshState>>,
    /// Discovery configuration
    config: DiscoveryConfig,
    /// Channel for peer events
    peer_events: broadcast::Sender<PeerEvent>,
    /// HTTP client for registry communication
    http_client: reqwest::Client,
    /// Shutdown signal
    shutdown: broadcast::Sender<()>,
}

/// Configuration for peer discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Central registry URL
    pub registry_url: Option<String>,
    /// Agent token for registry authentication
    pub agent_token: String,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
    /// Enable gossip protocol
    pub enable_gossip: bool,
    /// Gossip fanout (number of peers to share info with)
    pub gossip_fanout: usize,
    /// Peer timeout in seconds
    pub peer_timeout_secs: u64,
    /// Discovery refresh interval in seconds
    pub refresh_interval_secs: u64,
    /// Maximum peers to discover
    pub max_peers: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            registry_url: None,
            agent_token: String::new(),
            enable_mdns: true,
            enable_gossip: true,
            gossip_fanout: DEFAULT_GOSSIP_FANOUT,
            peer_timeout_secs: DEFAULT_PEER_TIMEOUT_SECS,
            refresh_interval_secs: 30,
            max_peers: MAX_PEERS,
        }
    }
}

/// Events from the discovery service
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// New peer discovered
    PeerDiscovered(PeerInfo),
    /// Peer updated its information
    PeerUpdated(PeerInfo),
    /// Peer left the mesh
    PeerLeft(String),
    /// Peer is now unreachable
    PeerUnreachable(String),
    /// Cluster state changed
    ClusterChanged(ClusterInfo),
}

impl DiscoveryService {
    /// Create a new discovery service
    pub fn new(local_agent: PeerInfo, config: DiscoveryConfig) -> Self {
        let (peer_events, _) = broadcast::channel(100);
        let (shutdown, _) = broadcast::channel(1);

        Self {
            local_agent,
            state: Arc::new(RwLock::new(MeshState::default())),
            config,
            peer_events,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            shutdown,
        }
    }

    /// Get a subscriber for peer events
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.peer_events.subscribe()
    }

    /// Start the discovery service
    pub async fn start(&self) -> Result<()> {
        log::info!(
            "Starting mesh discovery service for agent {}",
            self.local_agent.agent_id
        );

        // Register with central registry if configured
        if self.config.registry_url.is_some() {
            if let Err(e) = self.register_with_registry().await {
                log::warn!("Failed to register with central registry: {}", e);
            }
        }

        // Start mDNS if enabled
        if self.config.enable_mdns {
            self.start_mdns_discovery().await?;
        }

        // Start periodic refresh
        self.start_refresh_loop().await;

        Ok(())
    }

    /// Stop the discovery service
    pub async fn stop(&self) -> Result<()> {
        log::info!("Stopping mesh discovery service");

        // Notify shutdown
        let _ = self.shutdown.send(());

        // Deregister from central registry
        if self.config.registry_url.is_some() {
            if let Err(e) = self.deregister_from_registry().await {
                log::warn!("Failed to deregister from registry: {}", e);
            }
        }

        // Announce departure to peers
        self.announce_departure().await;

        Ok(())
    }

    /// Get current mesh state
    pub async fn get_state(&self) -> MeshState {
        self.state.read().await.clone()
    }

    /// Get all known peers
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        self.state.read().await.peers.values().cloned().collect()
    }

    /// Get a specific peer by ID
    pub async fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        self.state.read().await.peers.get(peer_id).cloned()
    }

    /// Add or update a peer
    pub async fn update_peer(&self, peer: PeerInfo) -> Result<()> {
        let mut state = self.state.write().await;

        // Check if we've reached max peers
        if !state.peers.contains_key(&peer.agent_id) && state.peers.len() >= self.config.max_peers {
            return Err(anyhow!("Maximum peer limit reached"));
        }

        let is_new = !state.peers.contains_key(&peer.agent_id);
        state.peers.insert(peer.agent_id.clone(), peer.clone());

        // Emit event
        if is_new {
            let _ = self.peer_events.send(PeerEvent::PeerDiscovered(peer));
        } else {
            let _ = self.peer_events.send(PeerEvent::PeerUpdated(peer));
        }

        Ok(())
    }

    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: &str) -> Result<()> {
        let mut state = self.state.write().await;
        state.peers.remove(peer_id);

        let _ = self.peer_events.send(PeerEvent::PeerLeft(peer_id.to_string()));

        Ok(())
    }

    /// Mark a peer as unreachable
    pub async fn mark_peer_unreachable(&self, peer_id: &str) -> Result<()> {
        let mut state = self.state.write().await;

        if let Some(peer) = state.peers.get_mut(peer_id) {
            peer.status = PeerStatus::Disconnected;
            let _ = self
                .peer_events
                .send(PeerEvent::PeerUnreachable(peer_id.to_string()));
        }

        Ok(())
    }

    // ========================================================================
    // Central Registry
    // ========================================================================

    /// Register this agent with the central registry
    async fn register_with_registry(&self) -> Result<()> {
        let registry_url = self
            .config
            .registry_url
            .as_ref()
            .ok_or_else(|| anyhow!("No registry URL configured"))?;

        let url = format!("{}/api/mesh/register", registry_url);

        let request = RegistryRequest {
            agent_id: self.local_agent.agent_id.clone(),
            name: self.local_agent.name.clone(),
            address: self.local_agent.address.clone(),
            mesh_port: self.local_agent.mesh_port,
            capabilities: self.local_agent.capabilities.clone(),
            network_zones: self.local_agent.network_zones.clone(),
            protocol_version: MESH_PROTOCOL_VERSION.to_string(),
        };

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.agent_token))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Registry registration failed: {}", response.status()));
        }

        let registry_response: RegistryResponse = response.json().await?;
        let peer_count = registry_response.peers.len();

        // Add discovered peers
        for peer in registry_response.peers {
            self.update_peer(peer).await?;
        }

        log::info!(
            "Registered with central registry, discovered {} peers",
            peer_count
        );

        Ok(())
    }

    /// Deregister from the central registry
    async fn deregister_from_registry(&self) -> Result<()> {
        let registry_url = self
            .config
            .registry_url
            .as_ref()
            .ok_or_else(|| anyhow!("No registry URL configured"))?;

        let url = format!(
            "{}/api/mesh/deregister/{}",
            registry_url, self.local_agent.agent_id
        );

        let response = self
            .http_client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.config.agent_token))
            .send()
            .await?;

        if !response.status().is_success() {
            log::warn!("Registry deregistration failed: {}", response.status());
        }

        Ok(())
    }

    /// Fetch updated peer list from registry
    async fn refresh_from_registry(&self) -> Result<Vec<PeerInfo>> {
        let registry_url = self
            .config
            .registry_url
            .as_ref()
            .ok_or_else(|| anyhow!("No registry URL configured"))?;

        let url = format!("{}/api/mesh/peers", registry_url);

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.agent_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch peers from registry: {}", response.status()));
        }

        let peers: Vec<PeerInfo> = response.json().await?;
        Ok(peers)
    }

    // ========================================================================
    // mDNS Discovery
    // ========================================================================

    /// Start mDNS service for local network discovery
    async fn start_mdns_discovery(&self) -> Result<()> {
        log::info!("Starting mDNS discovery on service type: {}", MDNS_SERVICE_TYPE);

        // Note: In a real implementation, this would use mdns-sd or similar crate
        // For now, we'll implement a simplified version

        let local_agent = self.local_agent.clone();
        let _state = self.state.clone();
        let _peer_events = self.peer_events.clone();
        let mut shutdown = self.shutdown.subscribe();

        tokio::spawn(async move {
            // Simulate mDNS announcements (in production, use actual mDNS)
            let mut interval = time::interval(time::Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // In production, this would broadcast mDNS announcements
                        log::debug!("mDNS heartbeat for agent {}", local_agent.agent_id);
                    }
                    _ = shutdown.recv() => {
                        log::info!("mDNS discovery shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Handle discovered mDNS service
    async fn handle_mdns_discovery(&self, peer_info: PeerInfo) -> Result<()> {
        // Ignore self
        if peer_info.agent_id == self.local_agent.agent_id {
            return Ok(());
        }

        self.update_peer(peer_info).await
    }

    // ========================================================================
    // Gossip Protocol
    // ========================================================================

    /// Share peer information with other peers (gossip)
    pub async fn gossip(&self) -> Result<()> {
        if !self.config.enable_gossip {
            return Ok(());
        }

        let state = self.state.read().await;
        let online_peers: Vec<&PeerInfo> = state.online_peers();

        if online_peers.is_empty() {
            return Ok(());
        }

        // Select random subset of peers to gossip to
        let fanout = self.config.gossip_fanout.min(online_peers.len());
        let mut indices: Vec<usize> = (0..online_peers.len()).collect();

        // Simple shuffle for random selection
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        indices.shuffle(&mut rng);

        let gossip_targets: Vec<_> = indices[..fanout]
            .iter()
            .map(|&i| online_peers[i].clone())
            .collect();

        // Prepare gossip message with known peers
        let known_peers: Vec<PeerInfo> = state.peers.values().cloned().collect();

        let message = MeshMessage::PeerAnnounce {
            info: self.local_agent.clone(),
            known_peers,
        };

        drop(state); // Release lock before sending

        // Send gossip to selected peers
        for target in gossip_targets {
            if let Err(e) = self.send_to_peer(&target, message.clone()).await {
                log::warn!("Failed to gossip to peer {}: {}", target.agent_id, e);
            }
        }

        Ok(())
    }

    /// Handle received gossip message
    pub async fn handle_gossip(&self, _from_peer: &str, message: MeshMessage) -> Result<()> {
        match message {
            MeshMessage::PeerAnnounce { info, known_peers } => {
                // Update announcing peer
                if info.agent_id != self.local_agent.agent_id {
                    self.update_peer(info).await?;
                }

                // Add new peers from gossip
                for peer in known_peers {
                    if peer.agent_id != self.local_agent.agent_id {
                        // Only add if we don't already know this peer
                        let state = self.state.read().await;
                        if !state.peers.contains_key(&peer.agent_id) {
                            drop(state);
                            self.update_peer(peer).await?;
                        }
                    }
                }
            }
            MeshMessage::PeerLeave { agent_id, reason } => {
                log::info!(
                    "Peer {} leaving mesh: {}",
                    agent_id,
                    reason.unwrap_or_else(|| "no reason".to_string())
                );
                self.remove_peer(&agent_id).await?;
            }
            _ => {
                log::debug!(
                    "Ignoring non-gossip message type: {}",
                    message.message_type()
                );
            }
        }

        Ok(())
    }

    // ========================================================================
    // Peer Health Monitoring
    // ========================================================================

    /// Start periodic refresh and health check loop
    async fn start_refresh_loop(&self) {
        let state = self.state.clone();
        let config = self.config.clone();
        let local_agent = self.local_agent.clone();
        let peer_events = self.peer_events.clone();
        let http_client = self.http_client.clone();
        let mut shutdown = self.shutdown.subscribe();

        tokio::spawn(async move {
            let mut interval = time::interval(time::Duration::from_secs(config.refresh_interval_secs));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check peer health
                        Self::check_peer_health_static(&state, &config, &peer_events).await;

                        // Refresh from registry if configured
                        if let Some(registry_url) = &config.registry_url {
                            if let Err(e) = Self::refresh_from_registry_static(
                                &http_client,
                                registry_url,
                                &config.agent_token,
                                &state,
                                &local_agent.agent_id,
                            ).await {
                                log::warn!("Failed to refresh from registry: {}", e);
                            }
                        }
                    }
                    _ = shutdown.recv() => {
                        log::info!("Refresh loop shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Check health of all known peers (static version for spawn)
    async fn check_peer_health_static(
        state: &Arc<RwLock<MeshState>>,
        config: &DiscoveryConfig,
        peer_events: &broadcast::Sender<PeerEvent>,
    ) {
        let timeout = Duration::seconds(config.peer_timeout_secs as i64);
        let now = Utc::now();

        let mut state = state.write().await;
        let mut to_remove = Vec::new();

        for (peer_id, peer) in state.peers.iter_mut() {
            let elapsed = now - peer.last_seen;

            if elapsed > timeout {
                // Mark peer as disconnected
                if peer.status != PeerStatus::Disconnected {
                    peer.status = PeerStatus::Disconnected;
                    let _ = peer_events.send(PeerEvent::PeerUnreachable(peer_id.clone()));
                }

                // Remove if disconnected too long (3x timeout)
                if elapsed > timeout * 3 {
                    to_remove.push(peer_id.clone());
                }
            }
        }

        // Remove stale peers
        for peer_id in to_remove {
            state.peers.remove(&peer_id);
            let _ = peer_events.send(PeerEvent::PeerLeft(peer_id));
        }
    }

    /// Refresh from registry (static version for spawn)
    async fn refresh_from_registry_static(
        http_client: &reqwest::Client,
        registry_url: &str,
        agent_token: &str,
        state: &Arc<RwLock<MeshState>>,
        local_agent_id: &str,
    ) -> Result<()> {
        let url = format!("{}/api/mesh/peers", registry_url);

        let response = http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", agent_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch peers: {}", response.status()));
        }

        let peers: Vec<PeerInfo> = response.json().await?;
        let mut state = state.write().await;

        for peer in peers {
            if peer.agent_id != local_agent_id {
                state.peers.insert(peer.agent_id.clone(), peer);
            }
        }

        Ok(())
    }

    // ========================================================================
    // Peer Communication
    // ========================================================================

    /// Announce departure to all known peers
    async fn announce_departure(&self) {
        let message = MeshMessage::PeerLeave {
            agent_id: self.local_agent.agent_id.clone(),
            reason: Some("Graceful shutdown".to_string()),
        };

        let peers: Vec<PeerInfo> = self.get_peers().await;

        for peer in peers {
            if let Err(e) = self.send_to_peer(&peer, message.clone()).await {
                log::debug!("Failed to announce departure to {}: {}", peer.agent_id, e);
            }
        }
    }

    /// Send a message to a peer
    async fn send_to_peer(&self, peer: &PeerInfo, message: MeshMessage) -> Result<()> {
        // In production, this would use TCP or UDP to send the message
        // For now, we'll use HTTP as a simple transport

        let addr = peer.socket_addr().ok_or_else(|| anyhow!("Invalid peer address"))?;
        let url = format!("http://{}/mesh/message", addr);

        let envelope = MessageEnvelope::new(
            self.local_agent.agent_id.clone(),
            Some(peer.agent_id.clone()),
            message,
        );

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.agent_token))
            .json(&envelope)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to send message: {}", response.status()));
        }

        Ok(())
    }

    /// Update peer's last seen timestamp
    pub async fn update_peer_last_seen(&self, peer_id: &str) {
        let mut state = self.state.write().await;
        if let Some(peer) = state.peers.get_mut(peer_id) {
            peer.last_seen = Utc::now();
            if peer.status == PeerStatus::Disconnected {
                peer.status = PeerStatus::Online;
            }
        }
    }

    /// Update peer's load information
    pub async fn update_peer_load(&self, peer_id: &str, load: f32, active_tasks: i32) {
        let mut state = self.state.write().await;
        if let Some(peer) = state.peers.get_mut(peer_id) {
            peer.load = load;
            peer.current_tasks = active_tasks;
            peer.last_seen = Utc::now();

            // Update status based on load
            peer.status = if active_tasks >= peer.max_tasks {
                PeerStatus::Busy
            } else {
                PeerStatus::Online
            };
        }
    }

    /// Update peer's latency measurement
    pub async fn update_peer_latency(&self, peer_id: &str, latency_ms: i64) {
        let mut state = self.state.write().await;
        if let Some(peer) = state.peers.get_mut(peer_id) {
            peer.latency_ms = Some(latency_ms);
            peer.last_seen = Utc::now();
        }
    }
}

// ============================================================================
// Registry API Types
// ============================================================================

/// Request to register with central registry
#[derive(Debug, Serialize, Deserialize)]
struct RegistryRequest {
    agent_id: String,
    name: String,
    address: String,
    mesh_port: u16,
    capabilities: Vec<String>,
    network_zones: Vec<String>,
    protocol_version: String,
}

/// Response from central registry
#[derive(Debug, Serialize, Deserialize)]
struct RegistryResponse {
    success: bool,
    peers: Vec<PeerInfo>,
    cluster_id: Option<String>,
}

// ============================================================================
// Peer Discovery Builder
// ============================================================================

/// Builder for creating a DiscoveryService
pub struct DiscoveryServiceBuilder {
    local_agent: Option<PeerInfo>,
    config: DiscoveryConfig,
}

impl DiscoveryServiceBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            local_agent: None,
            config: DiscoveryConfig::default(),
        }
    }

    /// Set the local agent information
    pub fn local_agent(mut self, agent: PeerInfo) -> Self {
        self.local_agent = Some(agent);
        self
    }

    /// Set the registry URL
    pub fn registry_url(mut self, url: String) -> Self {
        self.config.registry_url = Some(url);
        self
    }

    /// Set the agent token
    pub fn agent_token(mut self, token: String) -> Self {
        self.config.agent_token = token;
        self
    }

    /// Enable or disable mDNS
    pub fn enable_mdns(mut self, enable: bool) -> Self {
        self.config.enable_mdns = enable;
        self
    }

    /// Enable or disable gossip
    pub fn enable_gossip(mut self, enable: bool) -> Self {
        self.config.enable_gossip = enable;
        self
    }

    /// Set gossip fanout
    pub fn gossip_fanout(mut self, fanout: usize) -> Self {
        self.config.gossip_fanout = fanout;
        self
    }

    /// Set peer timeout
    pub fn peer_timeout_secs(mut self, secs: u64) -> Self {
        self.config.peer_timeout_secs = secs;
        self
    }

    /// Set refresh interval
    pub fn refresh_interval_secs(mut self, secs: u64) -> Self {
        self.config.refresh_interval_secs = secs;
        self
    }

    /// Set max peers
    pub fn max_peers(mut self, max: usize) -> Self {
        self.config.max_peers = max;
        self
    }

    /// Build the DiscoveryService
    pub fn build(self) -> Result<DiscoveryService> {
        let local_agent = self
            .local_agent
            .ok_or_else(|| anyhow!("Local agent information is required"))?;

        Ok(DiscoveryService::new(local_agent, self.config))
    }
}

impl Default for DiscoveryServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_config_defaults() {
        let config = DiscoveryConfig::default();
        assert!(config.enable_mdns);
        assert!(config.enable_gossip);
        assert_eq!(config.gossip_fanout, DEFAULT_GOSSIP_FANOUT);
        assert_eq!(config.peer_timeout_secs, DEFAULT_PEER_TIMEOUT_SECS);
    }

    #[test]
    fn test_peer_info_available() {
        let mut peer = PeerInfo::new(
            "agent-1".to_string(),
            "Agent 1".to_string(),
            "192.168.1.1".to_string(),
            9876,
        );

        peer.status = PeerStatus::Online;
        peer.max_tasks = 5;
        peer.current_tasks = 2;

        assert!(peer.is_available());

        peer.current_tasks = 5;
        assert!(!peer.is_available());

        peer.current_tasks = 2;
        peer.status = PeerStatus::Offline;
        assert!(!peer.is_available());
    }

    #[test]
    fn test_builder() {
        let peer = PeerInfo::new(
            "agent-1".to_string(),
            "Agent 1".to_string(),
            "192.168.1.1".to_string(),
            9876,
        );

        let service = DiscoveryServiceBuilder::new()
            .local_agent(peer)
            .registry_url("http://localhost:8080".to_string())
            .agent_token("test-token".to_string())
            .enable_mdns(true)
            .enable_gossip(true)
            .build();

        assert!(service.is_ok());
    }
}
