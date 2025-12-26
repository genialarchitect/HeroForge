//! Playbook step executor

use super::ExecutionContext;
use crate::green_team::types::*;

/// Executes playbook steps with timeout and retry logic
pub struct StepExecutor {
    pub max_retries: u32,
    pub default_timeout_seconds: u32,
}

impl StepExecutor {
    /// Create a new step executor
    pub fn new() -> Self {
        Self {
            max_retries: 3,
            default_timeout_seconds: 300,
        }
    }

    /// Execute a step with retry logic
    pub async fn execute_with_retry(
        &self,
        step: &PlaybookStep,
        context: &mut ExecutionContext,
        action_executor: &super::ActionExecutor,
    ) -> Result<serde_json::Value, String> {
        let max_retries = step.retry_count.unwrap_or(0);
        let mut last_error = String::new();

        for attempt in 0..=max_retries {
            match action_executor.execute(&step.action, context).await {
                Ok(output) => return Ok(output),
                Err(e) => {
                    last_error = e;
                    if attempt < max_retries {
                        // Wait before retry (exponential backoff)
                        let delay = std::time::Duration::from_secs(2u64.pow(attempt));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(format!(
            "Step failed after {} attempts: {}",
            max_retries + 1,
            last_error
        ))
    }
}

impl Default for StepExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Parallel step executor for running multiple steps concurrently
pub struct ParallelExecutor;

impl ParallelExecutor {
    /// Execute multiple steps in parallel
    pub async fn execute_parallel(
        steps: &[PlaybookStep],
        context: &ExecutionContext,
        action_executor: &super::ActionExecutor,
    ) -> Vec<Result<serde_json::Value, String>> {
        let mut handles = Vec::new();

        for step in steps {
            let step_clone = step.clone();
            let mut ctx_clone = context.clone();
            let executor = super::ActionExecutor::new();

            let handle = tokio::spawn(async move {
                executor.execute(&step_clone.action, &mut ctx_clone).await
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(format!("Task panicked: {}", e))),
            }
        }

        results
    }
}
