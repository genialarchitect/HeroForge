//! Custom C2 Protocol Implementation
//!
//! A simple HTTP-based C2 protocol for custom implants.
//! This provides a JSON command/response format that can be easily
//! extended for custom implant communication.
//!
//! Protocol Overview:
//! - Implants register via POST /api/c2/custom/register
//! - Implants check in via POST /api/c2/custom/checkin
//! - Tasks are queued and retrieved during check-ins
//! - Results are submitted via POST /api/c2/custom/result

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::types::*;

/// Custom C2 server/handler
pub struct CustomC2Server {
    config: C2Config,
    /// Registered agents
    agents: Arc<RwLock<HashMap<String, CustomAgent>>>,
    /// Pending tasks by agent ID
    pending_tasks: Arc<RwLock<HashMap<String, Vec<CustomTask>>>>,
    /// Completed tasks
    completed_tasks: Arc<RwLock<Vec<CustomTask>>>,
}

/// Custom agent information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomAgent {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub os_version: Option<String>,
    pub arch: String,
    pub process_id: u32,
    pub process_name: String,
    pub internal_ip: String,
    pub external_ip: Option<String>,
    pub domain: Option<String>,
    pub elevated: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub sleep_interval: u32,
    pub jitter: u32,
    pub alive: bool,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Custom task definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomTask {
    pub id: String,
    pub agent_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub status: CustomTaskStatus,
    pub output: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Task status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CustomTaskStatus {
    Pending,
    Sent,
    Running,
    Completed,
    Failed,
}

// ============================================================================
// Protocol Messages
// ============================================================================

/// Agent registration request
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequest {
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub os_version: Option<String>,
    pub arch: String,
    pub process_id: u32,
    pub process_name: String,
    pub internal_ip: String,
    pub external_ip: Option<String>,
    pub domain: Option<String>,
    pub elevated: bool,
    pub sleep_interval: Option<u32>,
    pub jitter: Option<u32>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Registration response
#[derive(Debug, Clone, Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub agent_id: String,
    pub message: Option<String>,
}

/// Check-in request
#[derive(Debug, Clone, Deserialize)]
pub struct CheckinRequest {
    pub agent_id: String,
    #[serde(default)]
    pub results: Vec<TaskResult>,
}

/// Task result from agent
#[derive(Debug, Clone, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub status: CustomTaskStatus,
    pub output: Option<String>,
    pub error: Option<String>,
}

/// Check-in response
#[derive(Debug, Clone, Serialize)]
pub struct CheckinResponse {
    pub success: bool,
    pub tasks: Vec<TaskPayload>,
    pub sleep: Option<u32>,
    pub jitter: Option<u32>,
    pub kill: bool,
}

/// Task payload for agent
#[derive(Debug, Clone, Serialize)]
pub struct TaskPayload {
    pub task_id: String,
    pub command: String,
    pub args: Vec<String>,
}

/// Generic API response
#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl CustomC2Server {
    /// Create a new custom C2 server
    pub fn new(config: C2Config) -> Self {
        Self {
            config,
            agents: Arc::new(RwLock::new(HashMap::new())),
            pending_tasks: Arc::new(RwLock::new(HashMap::new())),
            completed_tasks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get config ID
    pub fn config_id(&self) -> &str {
        &self.config.id
    }

    /// Register a new agent
    pub async fn register_agent(&self, req: RegisterRequest) -> Result<RegisterResponse> {
        let agent_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let agent = CustomAgent {
            id: agent_id.clone(),
            hostname: req.hostname,
            username: req.username,
            os: req.os,
            os_version: req.os_version,
            arch: req.arch,
            process_id: req.process_id,
            process_name: req.process_name,
            internal_ip: req.internal_ip,
            external_ip: req.external_ip,
            domain: req.domain,
            elevated: req.elevated,
            first_seen: now,
            last_seen: now,
            sleep_interval: req.sleep_interval.unwrap_or(60),
            jitter: req.jitter.unwrap_or(20),
            alive: true,
            metadata: req.metadata,
        };

        self.agents.write().await.insert(agent_id.clone(), agent);
        self.pending_tasks.write().await.insert(agent_id.clone(), Vec::new());

        Ok(RegisterResponse {
            success: true,
            agent_id,
            message: Some("Agent registered successfully".to_string()),
        })
    }

    /// Handle agent check-in
    pub async fn checkin(&self, req: CheckinRequest) -> Result<CheckinResponse> {
        // Update last seen time
        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(&req.agent_id)
            .ok_or_else(|| anyhow!("Agent not found"))?;

        agent.last_seen = Utc::now();

        // Process task results
        for result in req.results {
            self.process_result(&result).await?;
        }

        // Get pending tasks
        let mut pending = self.pending_tasks.write().await;
        let tasks = pending.get_mut(&req.agent_id)
            .map(|t| std::mem::take(t))
            .unwrap_or_default();

        // Convert to payloads and mark as sent
        let task_payloads: Vec<TaskPayload> = tasks.iter().map(|t| TaskPayload {
            task_id: t.id.clone(),
            command: t.command.clone(),
            args: t.args.clone(),
        }).collect();

        // Update task status to sent
        for mut task in tasks {
            task.status = CustomTaskStatus::Sent;
            task.sent_at = Some(Utc::now());
            // Store in completed tasks for tracking
            self.completed_tasks.write().await.push(task);
        }

        Ok(CheckinResponse {
            success: true,
            tasks: task_payloads,
            sleep: Some(agent.sleep_interval),
            jitter: Some(agent.jitter),
            kill: false,
        })
    }

    /// Process a task result
    async fn process_result(&self, result: &TaskResult) -> Result<()> {
        let mut completed = self.completed_tasks.write().await;

        if let Some(task) = completed.iter_mut().find(|t| t.id == result.task_id) {
            task.status = result.status.clone();
            task.output = result.output.clone();
            task.error = result.error.clone();
            task.completed_at = Some(Utc::now());
        }

        Ok(())
    }

    /// Queue a task for an agent
    pub async fn queue_task(&self, agent_id: &str, command: &str, args: Vec<String>) -> Result<CustomTask> {
        let agents = self.agents.read().await;
        if !agents.contains_key(agent_id) {
            return Err(anyhow!("Agent not found"));
        }
        drop(agents);

        let task = CustomTask {
            id: Uuid::new_v4().to_string(),
            agent_id: agent_id.to_string(),
            command: command.to_string(),
            args,
            status: CustomTaskStatus::Pending,
            output: None,
            error: None,
            created_at: Utc::now(),
            sent_at: None,
            completed_at: None,
        };

        self.pending_tasks.write().await
            .entry(agent_id.to_string())
            .or_insert_with(Vec::new)
            .push(task.clone());

        Ok(task)
    }

    /// Get all agents
    pub async fn list_agents(&self) -> Vec<Session> {
        self.agents.read().await
            .values()
            .map(|a| self.convert_agent(a.clone()))
            .collect()
    }

    /// Get a specific agent
    pub async fn get_agent(&self, agent_id: &str) -> Option<Session> {
        self.agents.read().await
            .get(agent_id)
            .map(|a| self.convert_agent(a.clone()))
    }

    /// Kill an agent
    pub async fn kill_agent(&self, agent_id: &str) -> Result<()> {
        // Queue exit command
        self.queue_task(agent_id, "exit", Vec::new()).await?;

        // Mark as dead
        if let Some(agent) = self.agents.write().await.get_mut(agent_id) {
            agent.alive = false;
        }

        Ok(())
    }

    /// Get task by ID
    pub async fn get_task(&self, task_id: &str) -> Option<Task> {
        // Check pending tasks
        for tasks in self.pending_tasks.read().await.values() {
            if let Some(task) = tasks.iter().find(|t| t.id == task_id) {
                return Some(self.convert_task(task.clone()));
            }
        }

        // Check completed tasks
        self.completed_tasks.read().await
            .iter()
            .find(|t| t.id == task_id)
            .map(|t| self.convert_task(t.clone()))
    }

    /// Get tasks for an agent
    pub async fn list_agent_tasks(&self, agent_id: &str) -> Vec<Task> {
        let mut tasks = Vec::new();

        // Add pending tasks
        if let Some(pending) = self.pending_tasks.read().await.get(agent_id) {
            tasks.extend(pending.iter().map(|t| self.convert_task(t.clone())));
        }

        // Add completed tasks
        tasks.extend(
            self.completed_tasks.read().await
                .iter()
                .filter(|t| t.agent_id == agent_id)
                .map(|t| self.convert_task(t.clone()))
        );

        tasks
    }

    /// Update agent sleep configuration
    pub async fn update_agent_config(&self, agent_id: &str, sleep: Option<u32>, jitter: Option<u32>) -> Result<()> {
        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(agent_id)
            .ok_or_else(|| anyhow!("Agent not found"))?;

        if let Some(s) = sleep {
            agent.sleep_interval = s;
        }
        if let Some(j) = jitter {
            agent.jitter = j;
        }

        Ok(())
    }

    /// Check agent health (mark stale agents as dead)
    pub async fn check_health(&self, timeout_seconds: u32) {
        let now = Utc::now();
        let timeout = chrono::Duration::seconds(timeout_seconds as i64);

        for agent in self.agents.write().await.values_mut() {
            if now - agent.last_seen > timeout {
                agent.alive = false;
            }
        }
    }

    // Conversion helpers
    fn convert_agent(&self, a: CustomAgent) -> Session {
        let arch = match a.arch.to_lowercase().as_str() {
            "x64" | "amd64" | "x86_64" => Architecture::X64,
            "x86" | "i386" | "i686" => Architecture::X86,
            "arm64" | "aarch64" => Architecture::Arm64,
            "arm" | "armv7" => Architecture::Arm,
            _ => Architecture::X64,
        };

        let status = if a.alive {
            SessionStatus::Active
        } else {
            SessionStatus::Dead
        };

        Session {
            id: a.id.clone(),
            c2_config_id: self.config.id.clone(),
            c2_session_id: a.id,
            implant_id: None,
            name: a.hostname.clone(),
            hostname: a.hostname,
            username: a.username,
            domain: a.domain,
            ip_address: a.internal_ip,
            external_ip: a.external_ip,
            os: a.os,
            os_version: a.os_version,
            arch,
            pid: a.process_id,
            process_name: a.process_name,
            integrity: if a.elevated { Some("High".to_string()) } else { None },
            status,
            is_elevated: a.elevated,
            locale: None,
            first_seen: a.first_seen,
            last_checkin: a.last_seen,
            next_checkin: None,
            notes: None,
        }
    }

    fn convert_task(&self, t: CustomTask) -> Task {
        let status = match t.status {
            CustomTaskStatus::Pending => TaskStatus::Pending,
            CustomTaskStatus::Sent => TaskStatus::Sent,
            CustomTaskStatus::Running => TaskStatus::Running,
            CustomTaskStatus::Completed => TaskStatus::Completed,
            CustomTaskStatus::Failed => TaskStatus::Failed,
        };

        Task {
            id: t.id,
            session_id: t.agent_id,
            c2_task_id: None,
            task_type: t.command.clone(),
            command: t.command,
            args: t.args,
            status,
            output: t.output,
            error: t.error,
            created_at: t.created_at,
            sent_at: t.sent_at,
            completed_at: t.completed_at,
        }
    }
}

/// Custom C2 client wrapper (for manager compatibility)
pub struct CustomC2Client {
    server: Arc<CustomC2Server>,
}

impl CustomC2Client {
    /// Create a new client wrapping the server
    pub fn new(config: C2Config) -> Result<Self> {
        Ok(Self {
            server: Arc::new(CustomC2Server::new(config)),
        })
    }

    /// Get the server instance
    pub fn server(&self) -> Arc<CustomC2Server> {
        self.server.clone()
    }

    /// Test connection (always succeeds for custom C2)
    pub async fn test_connection(&self) -> Result<bool> {
        Ok(true)
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        true
    }

    /// List sessions (agents)
    pub async fn list_sessions(&self) -> Result<Vec<Session>> {
        Ok(self.server.list_agents().await)
    }

    /// List listeners (custom C2 doesn't have external listeners)
    pub async fn list_listeners(&self) -> Result<Vec<Listener>> {
        Ok(Vec::new())
    }

    /// Start listener (not applicable for custom C2)
    pub async fn start_listener(&self, _req: &CreateListenerRequest) -> Result<Listener> {
        Err(anyhow!("Custom C2 uses internal HTTP endpoints"))
    }

    /// Stop listener (not applicable)
    pub async fn stop_listener(&self, _listener_id: &str) -> Result<()> {
        Err(anyhow!("Custom C2 uses internal HTTP endpoints"))
    }

    /// Generate implant (custom implants are external)
    pub async fn generate_implant(&self, _config: &ImplantConfig) -> Result<Vec<u8>> {
        Err(anyhow!("Custom implants must be built separately"))
    }

    /// Execute task
    pub async fn execute_task(&self, session_id: &str, task: &ExecuteTaskRequest) -> Result<Task> {
        let custom_task = self.server.queue_task(
            session_id,
            &task.command,
            task.args.clone().unwrap_or_default(),
        ).await?;

        Ok(Task {
            id: custom_task.id,
            session_id: session_id.to_string(),
            c2_task_id: None,
            task_type: task.task_type.clone(),
            command: task.command.clone(),
            args: task.args.clone().unwrap_or_default(),
            status: TaskStatus::Pending,
            output: None,
            error: None,
            created_at: Utc::now(),
            sent_at: None,
            completed_at: None,
        })
    }

    /// Kill session
    pub async fn kill_session(&self, session_id: &str) -> Result<()> {
        self.server.kill_agent(session_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_registration() {
        let config = C2Config {
            id: "test".to_string(),
            name: "Test".to_string(),
            framework: C2Framework::Custom,
            host: "localhost".to_string(),
            port: 8080,
            api_token: None,
            mtls_cert: None,
            mtls_key: None,
            ca_cert: None,
            verify_ssl: false,
            user_id: "user1".to_string(),
            connected: false,
            last_connected: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let server = CustomC2Server::new(config);

        let req = RegisterRequest {
            hostname: "workstation".to_string(),
            username: "admin".to_string(),
            os: "Windows 10".to_string(),
            os_version: Some("10.0.19041".to_string()),
            arch: "x64".to_string(),
            process_id: 1234,
            process_name: "explorer.exe".to_string(),
            internal_ip: "192.168.1.100".to_string(),
            external_ip: None,
            domain: Some("CORP".to_string()),
            elevated: true,
            sleep_interval: Some(30),
            jitter: Some(10),
            metadata: HashMap::new(),
        };

        let resp = server.register_agent(req).await.unwrap();
        assert!(resp.success);
        assert!(!resp.agent_id.is_empty());

        let agents = server.list_agents().await;
        assert_eq!(agents.len(), 1);
    }

    #[tokio::test]
    async fn test_task_queuing() {
        let config = C2Config {
            id: "test".to_string(),
            name: "Test".to_string(),
            framework: C2Framework::Custom,
            host: "localhost".to_string(),
            port: 8080,
            api_token: None,
            mtls_cert: None,
            mtls_key: None,
            ca_cert: None,
            verify_ssl: false,
            user_id: "user1".to_string(),
            connected: false,
            last_connected: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let server = CustomC2Server::new(config);

        // Register agent first
        let reg_req = RegisterRequest {
            hostname: "test".to_string(),
            username: "user".to_string(),
            os: "Linux".to_string(),
            os_version: None,
            arch: "x64".to_string(),
            process_id: 1,
            process_name: "test".to_string(),
            internal_ip: "127.0.0.1".to_string(),
            external_ip: None,
            domain: None,
            elevated: false,
            sleep_interval: None,
            jitter: None,
            metadata: HashMap::new(),
        };

        let reg_resp = server.register_agent(reg_req).await.unwrap();
        let agent_id = reg_resp.agent_id;

        // Queue task
        let task = server.queue_task(&agent_id, "whoami", Vec::new()).await.unwrap();
        assert_eq!(task.command, "whoami");
        assert!(matches!(task.status, CustomTaskStatus::Pending));

        // Check-in should return the task
        let checkin_req = CheckinRequest {
            agent_id: agent_id.clone(),
            results: Vec::new(),
        };

        let checkin_resp = server.checkin(checkin_req).await.unwrap();
        assert!(checkin_resp.success);
        assert_eq!(checkin_resp.tasks.len(), 1);
        assert_eq!(checkin_resp.tasks[0].command, "whoami");
    }
}
