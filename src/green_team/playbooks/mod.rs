//! Playbook management and execution engine
//!
//! Provides SOAR playbook capabilities:
//! - Playbook definition and storage
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
use std::collections::HashMap;
use uuid::Uuid;

/// Playbook execution engine
pub struct PlaybookEngine {
    playbooks: HashMap<Uuid, Playbook>,
    runs: HashMap<Uuid, PlaybookRun>,
    action_executor: ActionExecutor,
}

impl PlaybookEngine {
    /// Create a new playbook engine
    pub fn new() -> Self {
        Self {
            playbooks: HashMap::new(),
            runs: HashMap::new(),
            action_executor: ActionExecutor::new(),
        }
    }

    /// Register a playbook
    pub fn register_playbook(&mut self, playbook: Playbook) {
        self.playbooks.insert(playbook.id, playbook);
    }

    /// Get a playbook by ID
    pub fn get_playbook(&self, id: &Uuid) -> Option<&Playbook> {
        self.playbooks.get(id)
    }

    /// List all playbooks
    pub fn list_playbooks(&self) -> Vec<&Playbook> {
        self.playbooks.values().collect()
    }

    /// Start a new playbook run
    pub fn start_run(
        &mut self,
        playbook_id: Uuid,
        trigger_type: String,
        trigger_source: Option<String>,
        input_data: Option<serde_json::Value>,
    ) -> Result<Uuid, String> {
        let playbook = self
            .playbooks
            .get(&playbook_id)
            .ok_or_else(|| "Playbook not found".to_string())?;

        if !playbook.is_active {
            return Err("Playbook is not active".to_string());
        }

        let run_id = Uuid::new_v4();
        let run = PlaybookRun {
            id: run_id,
            playbook_id,
            trigger_type,
            trigger_source,
            status: PlaybookRunStatus::Running,
            current_step: 0,
            total_steps: playbook.steps.len() as u32,
            input_data,
            output_data: None,
            error_message: None,
            started_at: Utc::now(),
            completed_at: None,
            duration_seconds: None,
        };

        self.runs.insert(run_id, run);
        Ok(run_id)
    }

    /// Execute the next step of a run
    pub async fn execute_next_step(
        &mut self,
        run_id: &Uuid,
        context: &mut ExecutionContext,
    ) -> Result<StepResult, String> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or_else(|| "Run not found".to_string())?;

        if run.status != PlaybookRunStatus::Running {
            return Err("Run is not in running state".to_string());
        }

        let playbook = self
            .playbooks
            .get(&run.playbook_id)
            .ok_or_else(|| "Playbook not found".to_string())?
            .clone();

        let step_index = run.current_step as usize;
        if step_index >= playbook.steps.len() {
            run.status = PlaybookRunStatus::Completed;
            run.completed_at = Some(Utc::now());
            let duration = (run.completed_at.unwrap() - run.started_at).num_seconds();
            run.duration_seconds = Some(duration as u32);
            return Ok(StepResult::Completed);
        }

        let step = &playbook.steps[step_index];

        // Check condition if present
        if let Some(ref condition) = step.condition {
            if !evaluate_condition(condition, context) {
                // Skip this step
                run.current_step += 1;
                return Ok(StepResult::Skipped);
            }
        }

        // Execute the action
        match self
            .action_executor
            .execute(&step.action, context)
            .await
        {
            Ok(output) => {
                context.set_step_output(&step.id, output);
                run.current_step += 1;

                if let Some(ref next_step_id) = step.on_success {
                    // Find and jump to the specified step
                    if let Some(next_index) = playbook
                        .steps
                        .iter()
                        .position(|s| &s.id == next_step_id)
                    {
                        run.current_step = next_index as u32;
                    }
                }

                Ok(StepResult::Success)
            }
            Err(error) => {
                if let Some(ref next_step_id) = step.on_failure {
                    // Jump to failure handler
                    if let Some(next_index) = playbook
                        .steps
                        .iter()
                        .position(|s| &s.id == next_step_id)
                    {
                        run.current_step = next_index as u32;
                        return Ok(StepResult::Failed(error));
                    }
                }

                // No failure handler, fail the run
                run.status = PlaybookRunStatus::Failed;
                run.error_message = Some(error.clone());
                run.completed_at = Some(Utc::now());
                let duration = (run.completed_at.unwrap() - run.started_at).num_seconds();
                run.duration_seconds = Some(duration as u32);
                Err(error)
            }
        }
    }

    /// Get a run by ID
    pub fn get_run(&self, run_id: &Uuid) -> Option<&PlaybookRun> {
        self.runs.get(run_id)
    }

    /// Cancel a run
    pub fn cancel_run(&mut self, run_id: &Uuid) -> Result<(), String> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or_else(|| "Run not found".to_string())?;

        if run.status != PlaybookRunStatus::Running
            && run.status != PlaybookRunStatus::WaitingApproval
        {
            return Err("Run cannot be cancelled in current state".to_string());
        }

        run.status = PlaybookRunStatus::Cancelled;
        run.completed_at = Some(Utc::now());
        let duration = (run.completed_at.unwrap() - run.started_at).num_seconds();
        run.duration_seconds = Some(duration as u32);

        Ok(())
    }
}

impl Default for PlaybookEngine {
    fn default() -> Self {
        Self::new()
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

        // Replace variable references
        for (name, value) in &self.variables {
            let placeholder = format!("{{{{ {} }}}}", name);
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                _ => value.to_string(),
            };
            result = result.replace(&placeholder, &value_str);
        }

        // Replace step output references
        for (step_id, output) in &self.step_outputs {
            let placeholder = format!("{{{{ steps.{}.output }}}}", step_id);
            let output_str = match output {
                serde_json::Value::String(s) => s.clone(),
                _ => output.to_string(),
            };
            result = result.replace(&placeholder, &output_str);
        }

        // Replace input data references
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
}
