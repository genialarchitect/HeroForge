//! Task distribution logic for agent-based scanning
//!
//! This module handles:
//! - Task creation from scan requests
//! - Agent selection based on network zones
//! - Task assignment and load balancing
//! - Task lifecycle management

use anyhow::{anyhow, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::protocol::{TaskConfig, TaskType};
use super::types::{
    AgentTask, AgentTaskInfo, TaskStatus, DEFAULT_TASK_TIMEOUT,
};
use crate::db;

// ============================================================================
// Task Distribution
// ============================================================================

/// Distributes a scan to appropriate agents
pub struct TaskDistributor {
    pool: SqlitePool,
}

impl TaskDistributor {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create tasks for a scan, distributing to agents or groups
    pub async fn create_tasks_for_scan(
        &self,
        scan_id: &str,
        user_id: &str,
        targets: Vec<String>,
        config: &crate::types::ScanConfig,
        agent_id: Option<String>,
        group_id: Option<String>,
    ) -> Result<Vec<AgentTask>> {
        // If specific agent is requested, create single task
        if let Some(agent_id) = agent_id {
            let task = self
                .create_task(
                    scan_id,
                    user_id,
                    targets,
                    config,
                    Some(agent_id),
                    None,
                    1, // Priority 1 for direct assignment
                )
                .await?;
            return Ok(vec![task]);
        }

        // If group is specified, create task for group
        if let Some(group_id) = group_id {
            let task = self
                .create_task(
                    scan_id,
                    user_id,
                    targets,
                    config,
                    None,
                    Some(group_id),
                    1,
                )
                .await?;
            return Ok(vec![task]);
        }

        // No agent/group specified - try to auto-select based on network zones
        // For now, create a single unassigned task that any agent can pick up
        let task = self
            .create_task(scan_id, user_id, targets, config, None, None, 1)
            .await?;
        Ok(vec![task])
    }

    /// Create a single task
    async fn create_task(
        &self,
        scan_id: &str,
        user_id: &str,
        targets: Vec<String>,
        config: &crate::types::ScanConfig,
        agent_id: Option<String>,
        group_id: Option<String>,
        priority: i32,
    ) -> Result<AgentTask> {
        let task_config = TaskConfig::from_scan_config(
            TaskType::FullScan,
            targets.clone(),
            config.port_range,
            config,
        );

        let task = db::agents::create_agent_task(
            &self.pool,
            scan_id,
            agent_id.as_deref(),
            group_id.as_deref(),
            user_id,
            TaskType::FullScan.as_str(),
            &serde_json::to_string(&task_config)?,
            &targets.join(","),
            priority,
            DEFAULT_TASK_TIMEOUT,
        )
        .await?;

        Ok(task)
    }

    /// Assign pending tasks to available agents
    pub async fn assign_pending_tasks(&self) -> Result<usize> {
        let pending_tasks = db::agents::get_pending_tasks(&self.pool, 100).await?;
        let mut assigned_count = 0;

        for task in pending_tasks {
            // Skip tasks already assigned to specific agent
            if task.agent_id.is_some() {
                continue;
            }

            // Find available agent for this task
            let agent = if let Some(group_id) = &task.group_id {
                // Find agent in group
                db::agents::find_available_agent_in_group(&self.pool, group_id).await?
            } else {
                // Find any available agent
                db::agents::find_available_agent(&self.pool, &task.user_id).await?
            };

            if let Some(agent) = agent {
                // Assign task to agent
                db::agents::assign_task_to_agent(&self.pool, &task.id, &agent.id).await?;
                assigned_count += 1;
            }
        }

        Ok(assigned_count)
    }

    /// Get pending tasks for a specific agent
    pub async fn get_tasks_for_agent(
        &self,
        agent_id: &str,
        max_tasks: i32,
    ) -> Result<Vec<AgentTaskInfo>> {
        let tasks = db::agents::get_tasks_for_agent(&self.pool, agent_id, max_tasks).await?;

        let task_infos: Vec<AgentTaskInfo> = tasks
            .into_iter()
            .filter_map(|task| {
                let config: serde_json::Value = serde_json::from_str(&task.config).ok()?;
                let targets: Vec<String> = task.targets.split(',').map(String::from).collect();

                Some(AgentTaskInfo {
                    id: task.id,
                    scan_id: task.scan_id,
                    task_type: task.task_type,
                    config,
                    targets,
                    priority: task.priority,
                    timeout_seconds: task.timeout_seconds,
                })
            })
            .collect();

        Ok(task_infos)
    }

    /// Mark a task as started by an agent
    pub async fn start_task(&self, task_id: &str, agent_id: &str) -> Result<()> {
        db::agents::update_task_status(
            &self.pool,
            task_id,
            TaskStatus::Running.as_str(),
            Some(agent_id),
            None,
        )
        .await?;
        Ok(())
    }

    /// Mark a task as completed
    pub async fn complete_task(
        &self,
        task_id: &str,
        status: TaskStatus,
        error_message: Option<String>,
    ) -> Result<()> {
        db::agents::update_task_status(
            &self.pool,
            task_id,
            status.as_str(),
            None,
            error_message.as_deref(),
        )
        .await?;
        Ok(())
    }

    /// Cancel a task
    pub async fn cancel_task(&self, task_id: &str) -> Result<()> {
        db::agents::update_task_status(
            &self.pool,
            task_id,
            TaskStatus::Cancelled.as_str(),
            None,
            Some("Task cancelled by user"),
        )
        .await?;
        Ok(())
    }

    /// Handle task timeout
    pub async fn timeout_stale_tasks(&self) -> Result<usize> {
        let count = db::agents::timeout_stale_tasks(&self.pool).await?;
        Ok(count as usize)
    }
}

// ============================================================================
// Agent Selection Strategy
// ============================================================================

/// Strategy for selecting agents for tasks
pub enum AgentSelectionStrategy {
    /// Round-robin selection among available agents
    RoundRobin,
    /// Select least busy agent
    LeastBusy,
    /// Select agent with lowest latency
    LowestLatency,
    /// Select agent based on network zone match
    NetworkZone,
}

impl AgentSelectionStrategy {
    /// Select an agent based on strategy
    pub async fn select_agent(
        &self,
        pool: &SqlitePool,
        user_id: &str,
        target_network: Option<&str>,
    ) -> Result<Option<String>> {
        match self {
            Self::RoundRobin => {
                // Simple round-robin: pick agent with oldest last_task_at
                let agent = db::agents::find_available_agent(pool, user_id).await?;
                Ok(agent.map(|a| a.id))
            }
            Self::LeastBusy => {
                // Select agent with fewest current tasks
                let agent = db::agents::find_least_busy_agent(pool, user_id).await?;
                Ok(agent.map(|a| a.id))
            }
            Self::LowestLatency => {
                // Would need latency data from heartbeats
                // Fall back to least busy for now
                let agent = db::agents::find_least_busy_agent(pool, user_id).await?;
                Ok(agent.map(|a| a.id))
            }
            Self::NetworkZone => {
                // Match agent network zones to target
                if let Some(network) = target_network {
                    let agent = db::agents::find_agent_for_network(pool, user_id, network).await?;
                    if agent.is_some() {
                        return Ok(agent.map(|a| a.id));
                    }
                }
                // Fall back to any available agent
                let agent = db::agents::find_available_agent(pool, user_id).await?;
                Ok(agent.map(|a| a.id))
            }
        }
    }
}

// ============================================================================
// Task Status Aggregation
// ============================================================================

/// Aggregate task statuses for a scan
pub async fn get_scan_task_status(pool: &SqlitePool, scan_id: &str) -> Result<ScanTaskStatus> {
    let tasks = db::agents::get_tasks_for_scan(pool, scan_id).await?;

    let mut status = ScanTaskStatus::default();
    for task in &tasks {
        match TaskStatus::from_str(&task.status) {
            Some(TaskStatus::Pending) => status.pending += 1,
            Some(TaskStatus::Assigned) => status.assigned += 1,
            Some(TaskStatus::Running) => status.running += 1,
            Some(TaskStatus::Completed) => status.completed += 1,
            Some(TaskStatus::Failed) => status.failed += 1,
            Some(TaskStatus::Cancelled) => status.cancelled += 1,
            Some(TaskStatus::TimedOut) => status.timed_out += 1,
            None => {}
        }
    }
    status.total = tasks.len() as i32;

    // Calculate progress
    if status.total > 0 {
        status.progress = ((status.completed + status.failed + status.cancelled + status.timed_out) as f32
            / status.total as f32)
            * 100.0;
    }

    Ok(status)
}

/// Aggregated status of all tasks for a scan
#[derive(Debug, Default)]
pub struct ScanTaskStatus {
    pub total: i32,
    pub pending: i32,
    pub assigned: i32,
    pub running: i32,
    pub completed: i32,
    pub failed: i32,
    pub cancelled: i32,
    pub timed_out: i32,
    pub progress: f32,
}

impl ScanTaskStatus {
    /// Check if all tasks are complete (success or failure)
    pub fn is_complete(&self) -> bool {
        self.pending == 0 && self.assigned == 0 && self.running == 0
    }

    /// Check if scan should be marked as failed
    pub fn has_failures(&self) -> bool {
        self.failed > 0 || self.timed_out > 0
    }
}
