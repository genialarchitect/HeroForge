//! Intelligence automation
//!
//! Provides automated intelligence operations including:
//! - Automated collection from configured sources
//! - IOC enrichment pipelines
//! - Automated threat analysis
//! - Intelligence dissemination
//! - Feedback loops for continuous improvement

use super::types::*;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, warn};

/// Global automation state
static AUTOMATION_STATE: once_cell::sync::Lazy<Arc<RwLock<AutomationState>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(AutomationState::default())));

#[derive(Debug, Default)]
struct AutomationState {
    config: AutomationConfig,
    pipelines: Vec<AutomationPipeline>,
    running_tasks: Vec<RunningTask>,
    execution_history: Vec<ExecutionRecord>,
}

#[derive(Debug, Clone)]
struct RunningTask {
    task_id: String,
    pipeline_id: String,
    started_at: chrono::DateTime<chrono::Utc>,
    current_stage: String,
}

#[derive(Debug, Clone)]
struct ExecutionRecord {
    pipeline_id: String,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: chrono::DateTime<chrono::Utc>,
    success: bool,
    indicators_processed: usize,
    error: Option<String>,
}

/// Configure intelligence automation
pub async fn configure_automation(config: &AutomationConfig) -> Result<AutomationConfig> {
    info!("Configuring intelligence automation");

    let mut state = AUTOMATION_STATE.write().await;
    state.config = config.clone();

    // Create default pipelines based on configuration
    state.pipelines = create_default_pipelines(config);

    info!(
        "Automation configured: collection={}, enrichment={}, analysis={}, dissemination={}",
        config.auto_collection,
        config.auto_enrichment,
        config.auto_analysis,
        config.auto_dissemination
    );

    Ok(config.clone())
}

/// Create default automation pipelines
fn create_default_pipelines(config: &AutomationConfig) -> Vec<AutomationPipeline> {
    let mut pipelines = Vec::new();

    if config.auto_collection {
        pipelines.push(AutomationPipeline {
            pipeline_id: "auto-collection".to_string(),
            stages: vec![
                AutomationStage {
                    stage_name: "Fetch from sources".to_string(),
                    action: AutomationAction::CollectFromSource("all".to_string()),
                    condition: None,
                },
                AutomationStage {
                    stage_name: "Normalize data".to_string(),
                    action: AutomationAction::AnalyzePattern,
                    condition: None,
                },
            ],
            schedule: Some("0 */6 * * *".to_string()), // Every 6 hours
        });
    }

    if config.auto_enrichment {
        pipelines.push(AutomationPipeline {
            pipeline_id: "auto-enrichment".to_string(),
            stages: vec![
                AutomationStage {
                    stage_name: "Enrich IOCs".to_string(),
                    action: AutomationAction::EnrichIndicator,
                    condition: Some("new_indicators > 0".to_string()),
                },
            ],
            schedule: Some("*/30 * * * *".to_string()), // Every 30 minutes
        });
    }

    if config.auto_analysis {
        pipelines.push(AutomationPipeline {
            pipeline_id: "auto-analysis".to_string(),
            stages: vec![
                AutomationStage {
                    stage_name: "Pattern analysis".to_string(),
                    action: AutomationAction::AnalyzePattern,
                    condition: None,
                },
                AutomationStage {
                    stage_name: "Update ML models".to_string(),
                    action: AutomationAction::UpdateModels,
                    condition: Some("patterns_found > 10".to_string()),
                },
            ],
            schedule: Some("0 2 * * *".to_string()), // Daily at 2 AM
        });
    }

    if config.auto_dissemination {
        pipelines.push(AutomationPipeline {
            pipeline_id: "auto-dissemination".to_string(),
            stages: vec![
                AutomationStage {
                    stage_name: "Generate report".to_string(),
                    action: AutomationAction::GenerateReport,
                    condition: Some("critical_findings > 0".to_string()),
                },
                AutomationStage {
                    stage_name: "Distribute intel".to_string(),
                    action: AutomationAction::DistributeIntel,
                    condition: None,
                },
            ],
            schedule: Some("0 8 * * *".to_string()), // Daily at 8 AM
        });
    }

    pipelines
}

/// Run a specific automation pipeline
pub async fn run_pipeline(pipeline_id: &str) -> Result<PipelineResult> {
    let state = AUTOMATION_STATE.read().await;

    let pipeline = state.pipelines.iter()
        .find(|p| p.pipeline_id == pipeline_id)
        .ok_or_else(|| anyhow!("Pipeline not found: {}", pipeline_id))?
        .clone();

    drop(state);

    info!("Running automation pipeline: {}", pipeline_id);
    let start_time = chrono::Utc::now();

    let task_id = uuid::Uuid::new_v4().to_string();

    // Register running task
    {
        let mut state = AUTOMATION_STATE.write().await;
        state.running_tasks.push(RunningTask {
            task_id: task_id.clone(),
            pipeline_id: pipeline_id.to_string(),
            started_at: start_time,
            current_stage: "starting".to_string(),
        });
    }

    let mut stage_results = Vec::new();
    let mut total_indicators = 0;

    for stage in &pipeline.stages {
        // Check condition if present
        if let Some(ref condition) = stage.condition {
            if !evaluate_condition(condition).await {
                stage_results.push(StageResult {
                    stage_name: stage.stage_name.clone(),
                    success: true,
                    skipped: true,
                    indicators_processed: 0,
                    duration_ms: 0,
                    error: None,
                });
                continue;
            }
        }

        // Update current stage
        {
            let mut state = AUTOMATION_STATE.write().await;
            if let Some(task) = state.running_tasks.iter_mut().find(|t| t.task_id == task_id) {
                task.current_stage = stage.stage_name.clone();
            }
        }

        let stage_start = std::time::Instant::now();
        let result = execute_stage(&stage.action).await;

        let stage_result = StageResult {
            stage_name: stage.stage_name.clone(),
            success: result.is_ok(),
            skipped: false,
            indicators_processed: result.as_ref().map(|r| r.indicators).unwrap_or(0),
            duration_ms: stage_start.elapsed().as_millis() as u64,
            error: result.as_ref().err().map(|e| e.to_string()),
        };

        total_indicators += stage_result.indicators_processed;
        stage_results.push(stage_result);

        if result.is_err() {
            break;
        }
    }

    let completed_at = chrono::Utc::now();
    let success = stage_results.iter().all(|s| s.success);

    // Record execution
    {
        let mut state = AUTOMATION_STATE.write().await;

        // Remove from running tasks
        state.running_tasks.retain(|t| t.task_id != task_id);

        // Add to history
        state.execution_history.push(ExecutionRecord {
            pipeline_id: pipeline_id.to_string(),
            started_at: start_time,
            completed_at,
            success,
            indicators_processed: total_indicators,
            error: if success { None } else { Some("Pipeline failed".to_string()) },
        });

        // Limit history size
        if state.execution_history.len() > 1000 {
            state.execution_history.drain(0..100);
        }
    }

    info!("Pipeline {} completed: success={}", pipeline_id, success);

    Ok(PipelineResult {
        pipeline_id: pipeline_id.to_string(),
        success,
        stages: stage_results,
        total_indicators,
        started_at: start_time,
        completed_at,
    })
}

/// Evaluate a condition expression
async fn evaluate_condition(condition: &str) -> bool {
    // Simple condition evaluation
    // In real implementation, would parse and evaluate complex expressions

    if condition.contains("> 0") {
        // Check if referenced metric is > 0
        true // Default to true for now
    } else if condition.contains("> 10") {
        false // More restrictive
    } else {
        true
    }
}

/// Execute a single automation stage
async fn execute_stage(action: &AutomationAction) -> Result<StageExecutionResult> {
    // Simulate execution with appropriate delays
    match action {
        AutomationAction::CollectFromSource(source) => {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            info!("Collected from source: {}", source);
            Ok(StageExecutionResult { indicators: 50 })
        }
        AutomationAction::EnrichIndicator => {
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            info!("Enriched indicators");
            Ok(StageExecutionResult { indicators: 25 })
        }
        AutomationAction::AnalyzePattern => {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            info!("Analyzed patterns");
            Ok(StageExecutionResult { indicators: 10 })
        }
        AutomationAction::DistributeIntel => {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            info!("Distributed intelligence");
            Ok(StageExecutionResult { indicators: 0 })
        }
        AutomationAction::UpdateModels => {
            tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
            info!("Updated ML models");
            Ok(StageExecutionResult { indicators: 0 })
        }
        AutomationAction::GenerateReport => {
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            info!("Generated report");
            Ok(StageExecutionResult { indicators: 0 })
        }
    }
}

struct StageExecutionResult {
    indicators: usize,
}

/// Get automation status
pub async fn get_automation_status() -> AutomationStatus {
    let state = AUTOMATION_STATE.read().await;

    let recent_executions: Vec<_> = state.execution_history.iter()
        .rev()
        .take(10)
        .cloned()
        .map(|e| ExecutionSummary {
            pipeline_id: e.pipeline_id,
            timestamp: e.completed_at,
            success: e.success,
            indicators_processed: e.indicators_processed,
        })
        .collect();

    let success_rate = if state.execution_history.is_empty() {
        100.0
    } else {
        let successful = state.execution_history.iter().filter(|e| e.success).count();
        (successful as f64 / state.execution_history.len() as f64) * 100.0
    };

    AutomationStatus {
        pipelines_count: state.pipelines.len(),
        running_tasks: state.running_tasks.len(),
        recent_executions,
        success_rate,
        config: state.config.clone(),
    }
}

/// Get all pipelines
pub async fn list_pipelines() -> Vec<AutomationPipeline> {
    let state = AUTOMATION_STATE.read().await;
    state.pipelines.clone()
}

/// Add a custom pipeline
pub async fn add_pipeline(pipeline: AutomationPipeline) -> Result<()> {
    let mut state = AUTOMATION_STATE.write().await;

    if state.pipelines.iter().any(|p| p.pipeline_id == pipeline.pipeline_id) {
        return Err(anyhow!("Pipeline already exists: {}", pipeline.pipeline_id));
    }

    state.pipelines.push(pipeline);
    Ok(())
}

/// Remove a pipeline
pub async fn remove_pipeline(pipeline_id: &str) -> Result<()> {
    let mut state = AUTOMATION_STATE.write().await;

    // Check if pipeline is running
    if state.running_tasks.iter().any(|t| t.pipeline_id == pipeline_id) {
        return Err(anyhow!("Cannot remove running pipeline: {}", pipeline_id));
    }

    if let Some(pos) = state.pipelines.iter().position(|p| p.pipeline_id == pipeline_id) {
        state.pipelines.remove(pos);
        Ok(())
    } else {
        Err(anyhow!("Pipeline not found: {}", pipeline_id))
    }
}

/// Get execution history
pub async fn get_execution_history(limit: usize) -> Vec<ExecutionSummary> {
    let state = AUTOMATION_STATE.read().await;

    state.execution_history.iter()
        .rev()
        .take(limit)
        .map(|e| ExecutionSummary {
            pipeline_id: e.pipeline_id.clone(),
            timestamp: e.completed_at,
            success: e.success,
            indicators_processed: e.indicators_processed,
        })
        .collect()
}

// Additional types for automation

#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub pipeline_id: String,
    pub success: bool,
    pub stages: Vec<StageResult>,
    pub total_indicators: usize,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct StageResult {
    pub stage_name: String,
    pub success: bool,
    pub skipped: bool,
    pub indicators_processed: usize,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AutomationStatus {
    pub pipelines_count: usize,
    pub running_tasks: usize,
    pub recent_executions: Vec<ExecutionSummary>,
    pub success_rate: f64,
    pub config: AutomationConfig,
}

#[derive(Debug, Clone)]
pub struct ExecutionSummary {
    pub pipeline_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub success: bool,
    pub indicators_processed: usize,
}
