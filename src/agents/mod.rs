//! Agent-Based Scanning Module
//!
//! This module provides lightweight agent support for scanning internal networks.
//! Agents are deployed on machines within target networks and communicate with
//! the main HeroForge server to receive tasks and report results.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     HeroForge Server                            │
//! │  ┌───────────┐  ┌──────────────┐  ┌────────────────────────┐    │
//! │  │ Agent API │──│ Task Queue   │──│ Result Aggregator      │    │
//! │  └───────────┘  └──────────────┘  └────────────────────────┘    │
//! └─────────────────────────┬───────────────────────────────────────┘
//!                           │ HTTPS
//!          ┌────────────────┼────────────────┐
//!          │                │                │
//!     ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
//!     │ Agent 1 │     │ Agent 2 │     │ Agent 3 │
//!     │ Zone A  │     │ Zone B  │     │ Zone C  │
//!     └─────────┘     └─────────┘     └─────────┘
//! ```
//!
//! ## Features
//!
//! - **Agent Registration**: Agents register with unique tokens
//! - **Heartbeat Monitoring**: Health tracking via periodic heartbeats
//! - **Task Distribution**: Smart task routing based on network zones
//! - **Result Aggregation**: Combines results from multiple agents
//! - **Agent Groups**: Logical groupings for network segmentation
//!
//! ## Usage
//!
//! 1. Register an agent via `/api/agents/register`
//! 2. Deploy the agent with the generated token
//! 3. Agent connects and sends heartbeats
//! 4. Create scans with agent/group selection
//! 5. Tasks are distributed to appropriate agents
//! 6. Results are aggregated and stored
//!
//! ## Security
//!
//! - Agents authenticate via bearer tokens (256-bit random)
//! - Tokens are bcrypt hashed in the database
//! - All communication should use HTTPS in production
//! - Token rotation is supported

pub mod protocol;
pub mod results;
pub mod tasks;
pub mod types;

// Re-export commonly used types
pub use protocol::{
    generate_agent_token, get_token_prefix, ErrorCode, TaskConfig, TaskType, PROTOCOL_VERSION,
};
pub use results::{AggregatedResults, AgentUpdate, ResultCollector, ResultSummary};
pub use tasks::{AgentSelectionStrategy, ScanTaskStatus, TaskDistributor};
pub use types::{
    AgentGroup, AgentGroupMember, AgentGroupWithAgents, AgentGroupWithCount, AgentHeartbeat,
    AgentResult, AgentStats, AgentStatus, AgentTask, AgentTaskInfo, AgentWithGroups,
    AssignAgentsToGroupRequest, CreateAgentGroupRequest, GetTasksRequest, HeartbeatRequest,
    HeartbeatResponse, RegisterAgentRequest, RegisterAgentResponse, ScanAgent, SubmitResultRequest,
    TaskStatus, TaskSummary, UpdateAgentGroupRequest, UpdateAgentRequest,
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_TASK_TIMEOUT, HEARTBEAT_TIMEOUT_SECONDS,
    MAX_CONCURRENT_TASKS, TOKEN_PREFIX_LENGTH,
};

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;

// ============================================================================
// Agent Manager
// ============================================================================

/// Central manager for agent operations
pub struct AgentManager {
    pool: SqlitePool,
    task_distributor: TaskDistributor,
    result_collector: ResultCollector,
}

impl AgentManager {
    /// Create a new agent manager
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool: pool.clone(),
            task_distributor: TaskDistributor::new(pool.clone()),
            result_collector: ResultCollector::new(pool),
        }
    }

    /// Get the task distributor
    pub fn task_distributor(&self) -> &TaskDistributor {
        &self.task_distributor
    }

    /// Get the result collector
    pub fn result_collector(&self) -> &ResultCollector {
        &self.result_collector
    }

    /// Register a new agent
    pub async fn register_agent(
        &self,
        user_id: &str,
        request: RegisterAgentRequest,
    ) -> Result<RegisterAgentResponse> {
        let token = generate_agent_token();
        let token_prefix = get_token_prefix(&token);

        // Hash the token
        let token_hash = bcrypt::hash(&token, crate::db::BCRYPT_COST.clone())?;

        // Create the agent in database
        let agent = crate::db::agents::create_agent(
            &self.pool,
            user_id,
            &request.name,
            request.description.as_deref(),
            &token_hash,
            &token_prefix,
            request.network_zones.as_deref(),
            request.max_concurrent_tasks.unwrap_or(1),
        )
        .await?;

        Ok(RegisterAgentResponse {
            id: agent.id,
            name: agent.name,
            token,
            token_prefix,
            created_at: agent.created_at,
        })
    }

    /// Verify an agent token and return the agent if valid
    pub async fn verify_agent_token(&self, token: &str) -> Result<Option<ScanAgent>> {
        // Get token prefix
        let prefix = get_token_prefix(token);

        // Find agents with matching prefix
        let agents = crate::db::agents::find_agents_by_token_prefix(&self.pool, &prefix).await?;

        // Verify against each potential match
        for agent in agents {
            if bcrypt::verify(token, &agent.token_hash)? {
                // Check if agent is disabled
                if agent.status == AgentStatus::Disabled.as_str() {
                    return Ok(None);
                }
                return Ok(Some(agent));
            }
        }

        Ok(None)
    }

    /// Process a heartbeat from an agent
    pub async fn process_heartbeat(
        &self,
        agent_id: &str,
        request: HeartbeatRequest,
    ) -> Result<HeartbeatResponse> {
        // Update agent info and heartbeat
        crate::db::agents::update_agent_heartbeat(
            &self.pool,
            agent_id,
            request.version.as_deref(),
            request.hostname.as_deref(),
            request.os_info.as_deref(),
            request.capabilities.as_deref(),
        )
        .await?;

        // Record heartbeat metrics
        crate::db::agents::create_heartbeat(
            &self.pool,
            agent_id,
            request.cpu_usage,
            request.memory_usage,
            request.disk_usage,
            request.active_tasks,
            request.queued_tasks,
        )
        .await?;

        // Get pending tasks for this agent
        let pending_tasks = self.task_distributor.get_tasks_for_agent(agent_id, 5).await?;

        Ok(HeartbeatResponse {
            acknowledged: true,
            server_time: Utc::now(),
            pending_tasks,
        })
    }

    /// Mark agents as offline if heartbeat timeout exceeded
    pub async fn check_agent_health(&self) -> Result<usize> {
        let count = crate::db::agents::mark_offline_agents(
            &self.pool,
            HEARTBEAT_TIMEOUT_SECONDS,
        )
        .await?;
        Ok(count as usize)
    }

    /// Get statistics about agents
    pub async fn get_stats(&self, user_id: &str) -> Result<AgentStats> {
        crate::db::agents::get_agent_stats(&self.pool, user_id).await
    }
}

// ============================================================================
// Background Tasks
// ============================================================================

/// Start background tasks for agent management
pub fn start_background_tasks(pool: SqlitePool) {
    let manager = AgentManager::new(pool);

    // Spawn health check task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            interval.tick().await;

            // Check agent health
            if let Err(e) = manager.check_agent_health().await {
                log::error!("Failed to check agent health: {}", e);
            }

            // Timeout stale tasks
            if let Err(e) = manager.task_distributor.timeout_stale_tasks().await {
                log::error!("Failed to timeout stale tasks: {}", e);
            }

            // Try to assign pending tasks
            if let Err(e) = manager.task_distributor.assign_pending_tasks().await {
                log::error!("Failed to assign pending tasks: {}", e);
            }
        }
    });
}
