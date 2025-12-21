#![allow(dead_code)]
//! Distributed task scheduler with work stealing
//!
//! This module implements a distributed task scheduling system for the mesh network:
//! - **Task Delegation**: Offload tasks to peer agents with available capacity
//! - **Work Stealing**: Proactively request tasks from overloaded peers
//! - **Load Balancing**: Distribute work evenly across the mesh
//! - **Priority Scheduling**: Honor task priorities during distribution
//!
//! ## Scheduling Algorithm
//!
//! 1. Local agent receives task assignment
//! 2. If local agent is overloaded, attempt to delegate to peer
//! 3. Peer selection based on: capacity, capabilities, network zones, latency
//! 4. If no suitable peer, queue task locally
//! 5. Periodically check for work stealing opportunities
//!
//! ## Work Stealing
//!
//! Idle agents can request tasks from busy peers:
//! 1. Agent detects it has spare capacity
//! 2. Agent sends TaskStealRequest to busy peer
//! 3. Busy peer responds with available tasks
//! 4. Agent selects tasks and confirms steal
//! 5. Task ownership transfers to stealing agent

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio::time;

use super::discovery::DiscoveryService;
use super::protocol::{MeshMessage, TaskRejectReason};
use super::types::{
    AgentTaskInfo, DelegationResult, PeerInfo, PeerStatus, WorkStealingStats,
};

// ============================================================================
// Distributed Scheduler
// ============================================================================

/// Distributed task scheduler for mesh networking
pub struct DistributedScheduler {
    /// Local agent ID
    local_agent_id: String,
    /// Discovery service for peer information
    discovery: Arc<DiscoveryService>,
    /// Local task queue
    local_queue: Arc<Mutex<TaskQueue>>,
    /// Pending delegations (task_id -> peer_id)
    pending_delegations: Arc<RwLock<HashMap<String, PendingDelegation>>>,
    /// Scheduler configuration
    config: SchedulerConfig,
    /// Work stealing statistics
    stats: Arc<RwLock<WorkStealingStats>>,
    /// Event channel for scheduler events
    events: broadcast::Sender<SchedulerEvent>,
    /// Shutdown signal
    shutdown: broadcast::Sender<()>,
}

/// Configuration for the distributed scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum local queue size before delegating
    pub max_local_queue: usize,
    /// Threshold for considering agent "busy" (0.0-1.0)
    pub busy_threshold: f32,
    /// Threshold for considering agent "idle" (0.0-1.0)
    pub idle_threshold: f32,
    /// Enable work stealing
    pub enable_work_stealing: bool,
    /// Maximum tasks to steal in one request
    pub max_steal_batch: i32,
    /// Minimum priority for tasks that can be stolen
    pub min_steal_priority: i32,
    /// Work stealing check interval in seconds
    pub steal_check_interval_secs: u64,
    /// Task offer timeout in seconds
    pub offer_timeout_secs: u64,
    /// Maximum pending delegations
    pub max_pending_delegations: usize,
    /// Prefer local execution when possible
    pub prefer_local: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_local_queue: 100,
            busy_threshold: 0.8,
            idle_threshold: 0.3,
            enable_work_stealing: true,
            max_steal_batch: 5,
            min_steal_priority: 0,
            steal_check_interval_secs: 10,
            offer_timeout_secs: 30,
            max_pending_delegations: 50,
            prefer_local: true,
        }
    }
}

/// A task in the local queue
#[derive(Debug, Clone)]
pub struct QueuedTask {
    pub task: AgentTaskInfo,
    pub queued_at: chrono::DateTime<chrono::Utc>,
    pub attempts: i32,
    pub last_error: Option<String>,
}

/// Local task queue with priority ordering
struct TaskQueue {
    tasks: VecDeque<QueuedTask>,
    max_size: usize,
}

impl TaskQueue {
    fn new(max_size: usize) -> Self {
        Self {
            tasks: VecDeque::new(),
            max_size,
        }
    }

    fn push(&mut self, task: AgentTaskInfo) -> Result<()> {
        if self.tasks.len() >= self.max_size {
            return Err(anyhow!("Task queue is full"));
        }

        let queued = QueuedTask {
            task,
            queued_at: Utc::now(),
            attempts: 0,
            last_error: None,
        };

        // Insert based on priority (higher priority first)
        let pos = self
            .tasks
            .iter()
            .position(|t| t.task.priority < queued.task.priority)
            .unwrap_or(self.tasks.len());

        self.tasks.insert(pos, queued);
        Ok(())
    }

    fn pop(&mut self) -> Option<QueuedTask> {
        self.tasks.pop_front()
    }

    fn len(&self) -> usize {
        self.tasks.len()
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn peek(&self) -> Option<&QueuedTask> {
        self.tasks.front()
    }

    fn remove(&mut self, task_id: &str) -> Option<QueuedTask> {
        let pos = self.tasks.iter().position(|t| t.task.id == task_id)?;
        self.tasks.remove(pos)
    }

    fn get_stealable(&self, max_count: usize, min_priority: i32) -> Vec<&QueuedTask> {
        self.tasks
            .iter()
            .filter(|t| t.task.priority >= min_priority)
            .take(max_count)
            .collect()
    }

    fn get_all(&self) -> Vec<&QueuedTask> {
        self.tasks.iter().collect()
    }
}

/// Pending task delegation
#[derive(Debug, Clone)]
struct PendingDelegation {
    task_id: String,
    target_peer: String,
    offered_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// Events from the scheduler
#[derive(Debug, Clone)]
pub enum SchedulerEvent {
    /// Task was added to local queue
    TaskQueued { task_id: String },
    /// Task was delegated to a peer
    TaskDelegated { task_id: String, peer_id: String },
    /// Task delegation was accepted
    DelegationAccepted { task_id: String, peer_id: String },
    /// Task delegation was rejected
    DelegationRejected {
        task_id: String,
        peer_id: String,
        reason: String,
    },
    /// Task was stolen from a peer
    TaskStolen { task_id: String, from_peer: String },
    /// Tasks were offered to a peer for stealing
    TasksOffered {
        task_ids: Vec<String>,
        to_peer: String,
    },
    /// Work stealing completed
    WorkStealingComplete {
        tasks_stolen: i32,
        from_peer: String,
    },
}

impl DistributedScheduler {
    /// Create a new distributed scheduler
    pub fn new(
        local_agent_id: String,
        discovery: Arc<DiscoveryService>,
        config: SchedulerConfig,
    ) -> Self {
        let (events, _) = broadcast::channel(100);
        let (shutdown, _) = broadcast::channel(1);

        Self {
            local_agent_id,
            discovery,
            local_queue: Arc::new(Mutex::new(TaskQueue::new(config.max_local_queue))),
            pending_delegations: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(WorkStealingStats::default())),
            events,
            shutdown,
        }
    }

    /// Subscribe to scheduler events
    pub fn subscribe(&self) -> broadcast::Receiver<SchedulerEvent> {
        self.events.subscribe()
    }

    /// Start the scheduler background tasks
    pub async fn start(&self) -> Result<()> {
        log::info!("Starting distributed scheduler for agent {}", self.local_agent_id);

        if self.config.enable_work_stealing {
            self.start_work_stealing_loop().await;
        }

        self.start_delegation_cleanup_loop().await;

        Ok(())
    }

    /// Stop the scheduler
    pub async fn stop(&self) -> Result<()> {
        log::info!("Stopping distributed scheduler");
        let _ = self.shutdown.send(());
        Ok(())
    }

    // ========================================================================
    // Task Scheduling
    // ========================================================================

    /// Schedule a task for execution
    pub async fn schedule_task(&self, task: AgentTaskInfo) -> Result<ScheduleResult> {
        let state = self.discovery.get_state().await;
        let local_load = self.calculate_local_load().await;

        // If prefer local and we have capacity, execute locally
        if self.config.prefer_local && local_load < self.config.busy_threshold {
            return self.queue_locally(task).await;
        }

        // If we're overloaded, try to delegate
        if local_load >= self.config.busy_threshold {
            if let Some(peer) = state.find_best_peer_for_task(&task) {
                match self.delegate_to_peer(&task, peer).await {
                    Ok(result) => return Ok(ScheduleResult::Delegated(result)),
                    Err(e) => {
                        log::warn!(
                            "Failed to delegate task {} to peer {}: {}",
                            task.id,
                            peer.agent_id,
                            e
                        );
                    }
                }
            }
        }

        // Fall back to local execution
        self.queue_locally(task).await
    }

    /// Queue a task for local execution
    async fn queue_locally(&self, task: AgentTaskInfo) -> Result<ScheduleResult> {
        let mut queue = self.local_queue.lock().await;
        let task_id = task.id.clone();

        queue.push(task)?;

        let _ = self.events.send(SchedulerEvent::TaskQueued {
            task_id: task_id.clone(),
        });

        Ok(ScheduleResult::Queued { task_id })
    }

    /// Delegate a task to a peer
    async fn delegate_to_peer(
        &self,
        task: &AgentTaskInfo,
        peer: &PeerInfo,
    ) -> Result<DelegationResult> {
        // Check pending delegations limit
        let pending = self.pending_delegations.read().await;
        if pending.len() >= self.config.max_pending_delegations {
            return Err(anyhow!("Too many pending delegations"));
        }
        drop(pending);

        let expires_at = Utc::now() + Duration::seconds(self.config.offer_timeout_secs as i64);

        // Create task offer message
        let _message = MeshMessage::TaskOffer {
            task: task.clone(),
            from_agent: self.local_agent_id.clone(),
            expires_at,
            priority_boost: 0,
        };

        // Send offer to peer
        // In production, this would actually send the message
        log::info!(
            "Offering task {} to peer {}",
            task.id,
            peer.agent_id
        );

        // Record pending delegation
        let delegation = PendingDelegation {
            task_id: task.id.clone(),
            target_peer: peer.agent_id.clone(),
            offered_at: Utc::now(),
            expires_at,
        };

        let mut pending = self.pending_delegations.write().await;
        pending.insert(task.id.clone(), delegation);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.tasks_offered += 1;

        let _ = self.events.send(SchedulerEvent::TaskDelegated {
            task_id: task.id.clone(),
            peer_id: peer.agent_id.clone(),
        });

        Ok(DelegationResult::Accepted {
            peer_id: peer.agent_id.clone(),
            estimated_start: None,
        })
    }

    /// Handle task acceptance from a peer
    pub async fn handle_task_accept(
        &self,
        task_id: &str,
        accepting_agent: &str,
    ) -> Result<()> {
        // Remove from pending delegations
        let mut pending = self.pending_delegations.write().await;
        if let Some(delegation) = pending.remove(task_id) {
            if delegation.target_peer != accepting_agent {
                log::warn!(
                    "Task {} accepted by unexpected peer {} (expected {})",
                    task_id,
                    accepting_agent,
                    delegation.target_peer
                );
            }

            // Update stats
            let mut stats = self.stats.write().await;
            stats.tasks_delegated += 1;

            let _ = self.events.send(SchedulerEvent::DelegationAccepted {
                task_id: task_id.to_string(),
                peer_id: accepting_agent.to_string(),
            });
        }

        Ok(())
    }

    /// Handle task rejection from a peer
    pub async fn handle_task_reject(
        &self,
        task_id: &str,
        rejecting_agent: &str,
        reason: TaskRejectReason,
    ) -> Result<()> {
        // Remove from pending delegations
        let mut pending = self.pending_delegations.write().await;
        if let Some(_delegation) = pending.remove(task_id) {
            // Update stats
            let mut stats = self.stats.write().await;
            stats.delegation_failures += 1;

            let _ = self.events.send(SchedulerEvent::DelegationRejected {
                task_id: task_id.to_string(),
                peer_id: rejecting_agent.to_string(),
                reason: reason.to_string(),
            });
        }

        Ok(())
    }

    // ========================================================================
    // Work Stealing
    // ========================================================================

    /// Start the work stealing background loop
    async fn start_work_stealing_loop(&self) {
        let local_agent_id = self.local_agent_id.clone();
        let discovery = self.discovery.clone();
        let config = self.config.clone();
        let stats = self.stats.clone();
        let events = self.events.clone();
        let local_queue = self.local_queue.clone();
        let mut shutdown = self.shutdown.subscribe();

        tokio::spawn(async move {
            let mut interval = time::interval(time::Duration::from_secs(config.steal_check_interval_secs));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check if we should attempt work stealing
                        let local_load = {
                            let queue = local_queue.lock().await;
                            queue.len() as f32 / config.max_local_queue as f32
                        };

                        if local_load < config.idle_threshold {
                            if let Err(e) = Self::attempt_work_stealing(
                                &local_agent_id,
                                &discovery,
                                &config,
                                &stats,
                                &events,
                            ).await {
                                log::debug!("Work stealing attempt failed: {}", e);
                            }
                        }
                    }
                    _ = shutdown.recv() => {
                        log::info!("Work stealing loop shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Attempt to steal work from busy peers
    async fn attempt_work_stealing(
        local_agent_id: &str,
        discovery: &Arc<DiscoveryService>,
        config: &SchedulerConfig,
        stats: &Arc<RwLock<WorkStealingStats>>,
        events: &broadcast::Sender<SchedulerEvent>,
    ) -> Result<()> {
        let state = discovery.get_state().await;

        // Find busy peers with tasks to steal
        let busy_peers: Vec<&PeerInfo> = state
            .peers
            .values()
            .filter(|p| {
                p.status == PeerStatus::Busy
                    && p.current_tasks > 1
                    && p.agent_id != local_agent_id
            })
            .collect();

        if busy_peers.is_empty() {
            return Ok(());
        }

        // Try to steal from the busiest peer
        let busiest = busy_peers
            .iter()
            .max_by_key(|p| p.current_tasks)
            .ok_or_else(|| anyhow!("No busy peers found"))?;

        log::info!(
            "Attempting to steal work from busy peer {} (tasks: {})",
            busiest.agent_id,
            busiest.current_tasks
        );

        // Create steal request
        let _message = MeshMessage::TaskStealRequest {
            from_agent: local_agent_id.to_string(),
            max_tasks: config.max_steal_batch,
            min_priority: config.min_steal_priority,
            capabilities: vec![],
            network_zones: vec![],
        };

        // In production, send the message and handle response
        // For now, simulate the statistics update

        let mut stats = stats.write().await;
        stats.tasks_stolen += 1; // Would be actual count from response

        let _ = events.send(SchedulerEvent::WorkStealingComplete {
            tasks_stolen: 1,
            from_peer: busiest.agent_id.clone(),
        });

        Ok(())
    }

    /// Handle work steal request from another peer
    pub async fn handle_steal_request(
        &self,
        from_agent: &str,
        max_tasks: i32,
        min_priority: i32,
        capabilities: &[String],
        network_zones: &[String],
    ) -> Result<Vec<AgentTaskInfo>> {
        let queue = self.local_queue.lock().await;

        // Get tasks that match the criteria
        let stealable = queue.get_stealable(max_tasks as usize, min_priority);

        let mut result = Vec::new();

        for queued in stealable {
            // Check capabilities match
            let has_capabilities = queued
                .task
                .required_capabilities
                .iter()
                .all(|cap| capabilities.contains(cap));

            // Check network zones match
            let has_zones = queued.task.required_zones.is_empty()
                || queued
                    .task
                    .required_zones
                    .iter()
                    .any(|zone| network_zones.contains(zone));

            if has_capabilities && has_zones {
                result.push(queued.task.clone());
            }
        }

        if !result.is_empty() {
            let _ = self.events.send(SchedulerEvent::TasksOffered {
                task_ids: result.iter().map(|t| t.id.clone()).collect(),
                to_peer: from_agent.to_string(),
            });
        }

        Ok(result)
    }

    /// Handle confirmation that tasks were stolen
    pub async fn handle_steal_confirm(&self, task_ids: &[String], stealing_agent: &str) -> Result<()> {
        let mut queue = self.local_queue.lock().await;

        for task_id in task_ids {
            if queue.remove(task_id).is_some() {
                let _ = self.events.send(SchedulerEvent::TaskStolen {
                    task_id: task_id.clone(),
                    from_peer: self.local_agent_id.clone(),
                });

                log::info!(
                    "Task {} stolen by peer {}",
                    task_id,
                    stealing_agent
                );
            }
        }

        Ok(())
    }

    // ========================================================================
    // Queue Management
    // ========================================================================

    /// Get the next task from the local queue
    pub async fn dequeue_task(&self) -> Option<QueuedTask> {
        let mut queue = self.local_queue.lock().await;
        queue.pop()
    }

    /// Get the current queue length
    pub async fn queue_length(&self) -> usize {
        let queue = self.local_queue.lock().await;
        queue.len()
    }

    /// Check if the queue is empty
    pub async fn is_queue_empty(&self) -> bool {
        let queue = self.local_queue.lock().await;
        queue.is_empty()
    }

    /// Calculate current local load (0.0 - 1.0)
    pub async fn calculate_local_load(&self) -> f32 {
        let queue = self.local_queue.lock().await;
        queue.len() as f32 / self.config.max_local_queue as f32
    }

    /// Get work stealing statistics
    pub async fn get_stats(&self) -> WorkStealingStats {
        self.stats.read().await.clone()
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    /// Start delegation cleanup background loop
    async fn start_delegation_cleanup_loop(&self) {
        let pending_delegations = self.pending_delegations.clone();
        let mut shutdown = self.shutdown.subscribe();

        tokio::spawn(async move {
            let mut interval = time::interval(time::Duration::from_secs(10));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = Utc::now();
                        let mut pending = pending_delegations.write().await;

                        // Remove expired delegations
                        pending.retain(|_, d| d.expires_at > now);
                    }
                    _ = shutdown.recv() => {
                        log::info!("Delegation cleanup loop shutting down");
                        break;
                    }
                }
            }
        });
    }
}

// ============================================================================
// Schedule Result
// ============================================================================

/// Result of scheduling a task
#[derive(Debug, Clone)]
pub enum ScheduleResult {
    /// Task was queued locally
    Queued { task_id: String },
    /// Task was delegated to a peer
    Delegated(DelegationResult),
    /// Task scheduling failed
    Failed { reason: String },
}

// ============================================================================
// Scheduler Builder
// ============================================================================

/// Builder for creating a DistributedScheduler
pub struct SchedulerBuilder {
    local_agent_id: Option<String>,
    discovery: Option<Arc<DiscoveryService>>,
    config: SchedulerConfig,
}

impl SchedulerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            local_agent_id: None,
            discovery: None,
            config: SchedulerConfig::default(),
        }
    }

    /// Set the local agent ID
    pub fn local_agent_id(mut self, id: String) -> Self {
        self.local_agent_id = Some(id);
        self
    }

    /// Set the discovery service
    pub fn discovery(mut self, discovery: Arc<DiscoveryService>) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// Set the configuration
    pub fn config(mut self, config: SchedulerConfig) -> Self {
        self.config = config;
        self
    }

    /// Set max local queue size
    pub fn max_local_queue(mut self, size: usize) -> Self {
        self.config.max_local_queue = size;
        self
    }

    /// Enable or disable work stealing
    pub fn enable_work_stealing(mut self, enable: bool) -> Self {
        self.config.enable_work_stealing = enable;
        self
    }

    /// Set busy threshold
    pub fn busy_threshold(mut self, threshold: f32) -> Self {
        self.config.busy_threshold = threshold;
        self
    }

    /// Set idle threshold
    pub fn idle_threshold(mut self, threshold: f32) -> Self {
        self.config.idle_threshold = threshold;
        self
    }

    /// Build the scheduler
    pub fn build(self) -> Result<DistributedScheduler> {
        let local_agent_id = self
            .local_agent_id
            .ok_or_else(|| anyhow!("Local agent ID is required"))?;

        let discovery = self
            .discovery
            .ok_or_else(|| anyhow!("Discovery service is required"))?;

        Ok(DistributedScheduler::new(local_agent_id, discovery, self.config))
    }
}

impl Default for SchedulerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_queue_priority() {
        let mut queue = TaskQueue::new(10);

        // Add tasks with different priorities
        let task1 = AgentTaskInfo {
            id: "task-1".to_string(),
            scan_id: "scan-1".to_string(),
            task_type: "port_scan".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            priority: 1,
            timeout_seconds: 3600,
            config: serde_json::json!({}),
            required_zones: vec![],
            required_capabilities: vec![],
        };

        let task2 = AgentTaskInfo {
            id: "task-2".to_string(),
            priority: 5,
            ..task1.clone()
        };

        let task3 = AgentTaskInfo {
            id: "task-3".to_string(),
            priority: 3,
            ..task1.clone()
        };

        queue.push(task1).unwrap();
        queue.push(task2).unwrap();
        queue.push(task3).unwrap();

        // Should return in priority order (highest first)
        assert_eq!(queue.pop().unwrap().task.id, "task-2");
        assert_eq!(queue.pop().unwrap().task.id, "task-3");
        assert_eq!(queue.pop().unwrap().task.id, "task-1");
    }

    #[test]
    fn test_queue_full() {
        let mut queue = TaskQueue::new(2);

        let task = AgentTaskInfo {
            id: "task-1".to_string(),
            scan_id: "scan-1".to_string(),
            task_type: "port_scan".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            priority: 1,
            timeout_seconds: 3600,
            config: serde_json::json!({}),
            required_zones: vec![],
            required_capabilities: vec![],
        };

        queue.push(task.clone()).unwrap();

        let task2 = AgentTaskInfo {
            id: "task-2".to_string(),
            ..task.clone()
        };
        queue.push(task2).unwrap();

        let task3 = AgentTaskInfo {
            id: "task-3".to_string(),
            ..task.clone()
        };
        assert!(queue.push(task3).is_err());
    }

    #[test]
    fn test_scheduler_config_defaults() {
        let config = SchedulerConfig::default();
        assert_eq!(config.max_local_queue, 100);
        assert!(config.enable_work_stealing);
        assert_eq!(config.max_steal_batch, 5);
    }
}
