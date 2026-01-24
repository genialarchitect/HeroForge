//! Playbook management and execution engine
//!
//! Provides SOAR playbook capabilities:
//! - Playbook definition and storage (SQLite-backed)
//! - Step-by-step execution with branching
//! - Action execution (HTTP, scripts, integrations)
//! - Condition evaluation
//! - Marketplace integration

pub mod executor;
pub mod actions;
pub mod conditions;
pub mod marketplace;
pub mod triggers;
pub mod approvals;
pub mod analytics;

pub use executor::*;
pub use actions::*;
pub use conditions::*;
pub use marketplace::*;
pub use triggers::*;
pub use approvals::*;
pub use analytics::*;

use crate::green_team::types::*;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

/// Playbook execution engine with SQLite persistence
pub struct PlaybookEngine {
    pool: SqlitePool,
    action_executor: ActionExecutor,
}

impl PlaybookEngine {
    /// Create a new playbook engine with database persistence
    pub async fn new(pool: SqlitePool) -> Self {
        // Create tables if they don't exist
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS playbooks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT NOT NULL,
                trigger_json TEXT NOT NULL,
                steps_json TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                is_template INTEGER NOT NULL DEFAULT 0,
                marketplace_id TEXT,
                version TEXT NOT NULL DEFAULT '1.0',
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS playbook_runs (
                id TEXT PRIMARY KEY,
                playbook_id TEXT NOT NULL,
                trigger_type TEXT NOT NULL,
                trigger_source TEXT,
                status TEXT NOT NULL,
                current_step INTEGER NOT NULL DEFAULT 0,
                total_steps INTEGER NOT NULL,
                input_data TEXT,
                output_data TEXT,
                error_message TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds INTEGER,
                FOREIGN KEY (playbook_id) REFERENCES playbooks(id)
            )"
        ).execute(&pool).await;

        Self {
            pool,
            action_executor: ActionExecutor::new(),
        }
    }

    /// Register a playbook (persists to SQLite)
    pub async fn register_playbook(&self, playbook: Playbook) -> Result<(), String> {
        let id = playbook.id.to_string();
        let category = playbook.category.to_string();
        let trigger_json = serde_json::to_string(&playbook.trigger)
            .map_err(|e| format!("Failed to serialize trigger: {}", e))?;
        let steps_json = serde_json::to_string(&playbook.steps)
            .map_err(|e| format!("Failed to serialize steps: {}", e))?;
        let created_by = playbook.created_by.to_string();
        let created_at = playbook.created_at.to_rfc3339();
        let updated_at = playbook.updated_at.to_rfc3339();

        sqlx::query(
            "INSERT OR REPLACE INTO playbooks (id, name, description, category, trigger_json, steps_json, is_active, is_template, marketplace_id, version, created_by, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        )
        .bind(&id)
        .bind(&playbook.name)
        .bind(&playbook.description)
        .bind(&category)
        .bind(&trigger_json)
        .bind(&steps_json)
        .bind(playbook.is_active)
        .bind(playbook.is_template)
        .bind(&playbook.marketplace_id)
        .bind(&playbook.version)
        .bind(&created_by)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        Ok(())
    }

    /// Get a playbook by ID from the database
    pub async fn get_playbook(&self, id: &Uuid) -> Option<Playbook> {
        let id_str = id.to_string();
        let row = sqlx::query_as::<_, PlaybookRow>(
            "SELECT id, name, description, category, trigger_json, steps_json, is_active, is_template, marketplace_id, version, created_by, created_at, updated_at
             FROM playbooks WHERE id = ?1"
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        row.into_playbook().ok()
    }

    /// List all playbooks
    pub async fn list_playbooks(&self) -> Vec<Playbook> {
        let rows = sqlx::query_as::<_, PlaybookRow>(
            "SELECT id, name, description, category, trigger_json, steps_json, is_active, is_template, marketplace_id, version, created_by, created_at, updated_at
             FROM playbooks ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter()
            .filter_map(|r| r.into_playbook().ok())
            .collect()
    }

    /// Start a new playbook run
    pub async fn start_run(
        &self,
        playbook_id: Uuid,
        trigger_type: String,
        trigger_source: Option<String>,
        input_data: Option<serde_json::Value>,
    ) -> Result<Uuid, String> {
        let playbook = self
            .get_playbook(&playbook_id)
            .await
            .ok_or_else(|| "Playbook not found".to_string())?;

        if !playbook.is_active {
            return Err("Playbook is not active".to_string());
        }

        let run_id = Uuid::new_v4();
        let now = Utc::now();
        let input_json = input_data.as_ref().map(|d| serde_json::to_string(d).unwrap_or_default());

        sqlx::query(
            "INSERT INTO playbook_runs (id, playbook_id, trigger_type, trigger_source, status, current_step, total_steps, input_data, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        )
        .bind(run_id.to_string())
        .bind(playbook_id.to_string())
        .bind(&trigger_type)
        .bind(&trigger_source)
        .bind("running")
        .bind(0i32)
        .bind(playbook.steps.len() as i32)
        .bind(&input_json)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        Ok(run_id)
    }

    /// Execute the next step of a run
    pub async fn execute_next_step(
        &self,
        run_id: &Uuid,
        context: &mut ExecutionContext,
    ) -> Result<StepResult, String> {
        let run = self.get_run(run_id).await
            .ok_or_else(|| "Run not found".to_string())?;

        if run.status != PlaybookRunStatus::Running {
            return Err("Run is not in running state".to_string());
        }

        let playbook = self.get_playbook(&run.playbook_id).await
            .ok_or_else(|| "Playbook not found".to_string())?;

        let step_index = run.current_step as usize;
        if step_index >= playbook.steps.len() {
            let now = Utc::now();
            let duration = (now - run.started_at).num_seconds() as i32;
            sqlx::query(
                "UPDATE playbook_runs SET status = 'completed', completed_at = ?1, duration_seconds = ?2, current_step = ?3
                 WHERE id = ?4"
            )
            .bind(now.to_rfc3339())
            .bind(duration)
            .bind(run.current_step as i32)
            .bind(run_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

            return Ok(StepResult::Completed);
        }

        let step = &playbook.steps[step_index];

        // Check condition if present
        if let Some(ref condition) = step.condition {
            if !evaluate_condition(condition, context) {
                // Skip this step
                let new_step = run.current_step + 1;
                sqlx::query("UPDATE playbook_runs SET current_step = ?1 WHERE id = ?2")
                    .bind(new_step as i32)
                    .bind(run_id.to_string())
                    .execute(&self.pool)
                    .await
                    .map_err(|e| format!("Database error: {}", e))?;
                return Ok(StepResult::Skipped);
            }
        }

        // Execute the action
        match self.action_executor.execute(&step.action, context).await {
            Ok(output) => {
                context.set_step_output(&step.id, output);
                let mut new_step = run.current_step + 1;

                if let Some(ref next_step_id) = step.on_success {
                    if let Some(next_index) = playbook
                        .steps
                        .iter()
                        .position(|s| &s.id == next_step_id)
                    {
                        new_step = next_index as u32;
                    }
                }

                sqlx::query("UPDATE playbook_runs SET current_step = ?1 WHERE id = ?2")
                    .bind(new_step as i32)
                    .bind(run_id.to_string())
                    .execute(&self.pool)
                    .await
                    .map_err(|e| format!("Database error: {}", e))?;

                Ok(StepResult::Success)
            }
            Err(error) => {
                if let Some(ref next_step_id) = step.on_failure {
                    if let Some(next_index) = playbook
                        .steps
                        .iter()
                        .position(|s| &s.id == next_step_id)
                    {
                        sqlx::query("UPDATE playbook_runs SET current_step = ?1 WHERE id = ?2")
                            .bind(next_index as i32)
                            .bind(run_id.to_string())
                            .execute(&self.pool)
                            .await
                            .map_err(|e| format!("Database error: {}", e))?;
                        return Ok(StepResult::Failed(error));
                    }
                }

                // No failure handler, fail the run
                let now = Utc::now();
                let duration = (now - run.started_at).num_seconds() as i32;
                sqlx::query(
                    "UPDATE playbook_runs SET status = 'failed', error_message = ?1, completed_at = ?2, duration_seconds = ?3
                     WHERE id = ?4"
                )
                .bind(&error)
                .bind(now.to_rfc3339())
                .bind(duration)
                .bind(run_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(|e| format!("Database error: {}", e))?;

                Err(error)
            }
        }
    }

    /// Get a run by ID
    pub async fn get_run(&self, run_id: &Uuid) -> Option<PlaybookRun> {
        let row = sqlx::query_as::<_, PlaybookRunRow>(
            "SELECT id, playbook_id, trigger_type, trigger_source, status, current_step, total_steps, input_data, output_data, error_message, started_at, completed_at, duration_seconds
             FROM playbook_runs WHERE id = ?1"
        )
        .bind(run_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        row.into_run().ok()
    }

    /// Cancel a run
    pub async fn cancel_run(&self, run_id: &Uuid) -> Result<(), String> {
        let run = self.get_run(run_id).await
            .ok_or_else(|| "Run not found".to_string())?;

        if run.status != PlaybookRunStatus::Running
            && run.status != PlaybookRunStatus::WaitingApproval
        {
            return Err("Run cannot be cancelled in current state".to_string());
        }

        let now = Utc::now();
        let duration = (now - run.started_at).num_seconds() as i32;

        sqlx::query(
            "UPDATE playbook_runs SET status = 'cancelled', completed_at = ?1, duration_seconds = ?2
             WHERE id = ?3"
        )
        .bind(now.to_rfc3339())
        .bind(duration)
        .bind(run_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        Ok(())
    }
}

/// Result of executing a step
#[derive(Debug, Clone)]
pub enum StepResult {
    Success,
    Skipped,
    Failed(String),
    Completed,
    WaitingApproval,
}

/// Execution context for playbook runs
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub run_id: Uuid,
    pub variables: HashMap<String, serde_json::Value>,
    pub step_outputs: HashMap<String, serde_json::Value>,
    pub input_data: Option<serde_json::Value>,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(run_id: Uuid, input_data: Option<serde_json::Value>) -> Self {
        Self {
            run_id,
            variables: HashMap::new(),
            step_outputs: HashMap::new(),
            input_data,
        }
    }

    /// Set a variable
    pub fn set_variable(&mut self, name: &str, value: serde_json::Value) {
        self.variables.insert(name.to_string(), value);
    }

    /// Get a variable
    pub fn get_variable(&self, name: &str) -> Option<&serde_json::Value> {
        self.variables.get(name)
    }

    /// Set step output
    pub fn set_step_output(&mut self, step_id: &str, output: serde_json::Value) {
        self.step_outputs.insert(step_id.to_string(), output);
    }

    /// Get step output
    pub fn get_step_output(&self, step_id: &str) -> Option<&serde_json::Value> {
        self.step_outputs.get(step_id)
    }

    /// Resolve a template string with context values
    pub fn resolve_template(&self, template: &str) -> String {
        let mut result = template.to_string();

        for (name, value) in &self.variables {
            let placeholder = format!("{{{{ {} }}}}", name);
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                _ => value.to_string(),
            };
            result = result.replace(&placeholder, &value_str);
        }

        for (step_id, output) in &self.step_outputs {
            let placeholder = format!("{{{{ steps.{}.output }}}}", step_id);
            let output_str = match output {
                serde_json::Value::String(s) => s.clone(),
                _ => output.to_string(),
            };
            result = result.replace(&placeholder, &output_str);
        }

        if let Some(ref input) = self.input_data {
            if let Some(obj) = input.as_object() {
                for (key, value) in obj {
                    let placeholder = format!("{{{{ input.{} }}}}", key);
                    let value_str = match value {
                        serde_json::Value::String(s) => s.clone(),
                        _ => value.to_string(),
                    };
                    result = result.replace(&placeholder, &value_str);
                }
            }
        }

        result
    }
}

// --- Database row types ---

#[derive(sqlx::FromRow)]
struct PlaybookRow {
    id: String,
    name: String,
    description: Option<String>,
    category: String,
    trigger_json: String,
    steps_json: String,
    is_active: bool,
    is_template: bool,
    marketplace_id: Option<String>,
    version: String,
    created_by: String,
    created_at: String,
    updated_at: String,
}

impl PlaybookRow {
    fn into_playbook(self) -> Result<Playbook, String> {
        let id = Uuid::parse_str(&self.id).map_err(|e| format!("Invalid UUID: {}", e))?;
        let created_by = Uuid::parse_str(&self.created_by).map_err(|e| format!("Invalid UUID: {}", e))?;
        let trigger: PlaybookTrigger = serde_json::from_str(&self.trigger_json)
            .map_err(|e| format!("Invalid trigger JSON: {}", e))?;
        let steps: Vec<PlaybookStep> = serde_json::from_str(&self.steps_json)
            .map_err(|e| format!("Invalid steps JSON: {}", e))?;
        let category = parse_playbook_category(&self.category);
        let created_at = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = chrono::DateTime::parse_from_rfc3339(&self.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(Playbook {
            id,
            name: self.name,
            description: self.description,
            category,
            trigger,
            steps,
            is_active: self.is_active,
            is_template: self.is_template,
            marketplace_id: self.marketplace_id,
            version: self.version,
            created_by,
            created_at,
            updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PlaybookRunRow {
    id: String,
    playbook_id: String,
    trigger_type: String,
    trigger_source: Option<String>,
    status: String,
    current_step: i32,
    total_steps: i32,
    input_data: Option<String>,
    output_data: Option<String>,
    error_message: Option<String>,
    started_at: String,
    completed_at: Option<String>,
    duration_seconds: Option<i32>,
}

impl PlaybookRunRow {
    fn into_run(self) -> Result<PlaybookRun, String> {
        let id = Uuid::parse_str(&self.id).map_err(|e| format!("Invalid UUID: {}", e))?;
        let playbook_id = Uuid::parse_str(&self.playbook_id).map_err(|e| format!("Invalid UUID: {}", e))?;
        let status = parse_run_status(&self.status);
        let input_data = self.input_data
            .as_ref()
            .and_then(|d| serde_json::from_str(d).ok());
        let output_data = self.output_data
            .as_ref()
            .and_then(|d| serde_json::from_str(d).ok());
        let started_at = chrono::DateTime::parse_from_rfc3339(&self.started_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let completed_at = self.completed_at.as_ref().and_then(|s|
            chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
        );

        Ok(PlaybookRun {
            id,
            playbook_id,
            trigger_type: self.trigger_type,
            trigger_source: self.trigger_source,
            status,
            current_step: self.current_step as u32,
            total_steps: self.total_steps as u32,
            input_data,
            output_data,
            error_message: self.error_message,
            started_at,
            completed_at,
            duration_seconds: self.duration_seconds.map(|d| d as u32),
        })
    }
}

fn parse_playbook_category(s: &str) -> PlaybookCategory {
    match s {
        "incident_response" => PlaybookCategory::IncidentResponse,
        "threat_hunting" => PlaybookCategory::ThreatHunting,
        "compliance" => PlaybookCategory::Compliance,
        "enrichment" => PlaybookCategory::Enrichment,
        "remediation" => PlaybookCategory::Remediation,
        "notification" => PlaybookCategory::Notification,
        _ => PlaybookCategory::Custom,
    }
}

fn parse_run_status(s: &str) -> PlaybookRunStatus {
    match s {
        "pending" => PlaybookRunStatus::Pending,
        "running" => PlaybookRunStatus::Running,
        "completed" => PlaybookRunStatus::Completed,
        "failed" => PlaybookRunStatus::Failed,
        "cancelled" => PlaybookRunStatus::Cancelled,
        "waiting_approval" => PlaybookRunStatus::WaitingApproval,
        _ => PlaybookRunStatus::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_context_template() {
        let mut ctx = ExecutionContext::new(Uuid::new_v4(), None);
        ctx.set_variable("ip", serde_json::json!("192.168.1.1"));
        ctx.set_variable("port", serde_json::json!(443));

        let result = ctx.resolve_template("Block {{ ip }} on port {{ port }}");
        assert_eq!(result, "Block 192.168.1.1 on port 443");
    }

    #[tokio::test]
    async fn test_playbook_persistence() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let engine = PlaybookEngine::new(pool).await;

        let playbook = Playbook {
            id: Uuid::new_v4(),
            name: "Test Playbook".to_string(),
            description: Some("A test".to_string()),
            category: PlaybookCategory::IncidentResponse,
            trigger: PlaybookTrigger::Manual,
            steps: vec![],
            is_active: true,
            is_template: false,
            marketplace_id: None,
            version: "1.0".to_string(),
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let pb_id = playbook.id;
        engine.register_playbook(playbook).await.unwrap();

        let loaded = engine.get_playbook(&pb_id).await.unwrap();
        assert_eq!(loaded.name, "Test Playbook");
        assert!(loaded.is_active);

        let all = engine.list_playbooks().await;
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_run_lifecycle() {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let engine = PlaybookEngine::new(pool).await;

        let playbook = Playbook {
            id: Uuid::new_v4(),
            name: "Run Test".to_string(),
            description: None,
            category: PlaybookCategory::Custom,
            trigger: PlaybookTrigger::Manual,
            steps: vec![],
            is_active: true,
            is_template: false,
            marketplace_id: None,
            version: "1.0".to_string(),
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let pb_id = playbook.id;
        engine.register_playbook(playbook).await.unwrap();

        let run_id = engine.start_run(pb_id, "manual".to_string(), None, None).await.unwrap();
        let run = engine.get_run(&run_id).await.unwrap();
        assert_eq!(run.status, PlaybookRunStatus::Running);

        engine.cancel_run(&run_id).await.unwrap();
        let run = engine.get_run(&run_id).await.unwrap();
        assert_eq!(run.status, PlaybookRunStatus::Cancelled);
    }
}
