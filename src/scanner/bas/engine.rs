#![allow(dead_code)]
//! Breach & Attack Simulation Engine
//!
//! This module provides the main simulation engine for BAS testing.
//! It orchestrates technique execution, detection validation, and result aggregation.

use super::detection::DetectionValidator;
use super::payloads::{get_payloads_for_technique, PayloadExecutor, PayloadResult};
use super::safety::{run_safety_check, SafetyController, SafetyViolation};
use super::techniques::TechniqueLibrary;
use super::types::*;
use anyhow::Result;
use chrono::Utc;
use log::{debug, info, warn};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, Semaphore};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

/// Breach & Attack Simulation Engine
///
/// The main engine for running BAS simulations. It handles:
/// - Safety validation before execution
/// - Technique execution using safe payloads
/// - Detection validation
/// - Gap analysis and reporting
pub struct BasEngine {
    /// Engine configuration
    config: BasConfig,
    /// Technique library
    library: TechniqueLibrary,
    /// Safety controller
    safety: SafetyController,
    /// Payload executor
    executor: PayloadExecutor,
    /// Detection validator
    detector: DetectionValidator,
}

impl BasEngine {
    /// Create a new BAS engine with the given configuration
    pub fn new(config: BasConfig) -> Self {
        Self {
            safety: SafetyController::from_config(&config),
            library: TechniqueLibrary::new(),
            executor: PayloadExecutor::new()
                .with_cleanup(config.enable_cleanup),
            detector: DetectionValidator::new()
                .with_timeout(Duration::from_secs(config.detection_timeout_secs)),
            config,
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(BasConfig::default())
    }

    /// Get the technique library
    pub fn library(&self) -> &TechniqueLibrary {
        &self.library
    }

    /// Get the safety controller
    pub fn safety(&self) -> &SafetyController {
        &self.safety
    }

    /// Get a mutable reference to the safety controller
    pub fn safety_mut(&mut self) -> &mut SafetyController {
        &mut self.safety
    }

    /// Run a simulation scenario
    pub async fn run_simulation(
        &self,
        scenario: SimulationScenario,
        progress_tx: Option<broadcast::Sender<SimulationProgress>>,
    ) -> Result<SimulationResult> {
        let simulation_id = Uuid::new_v4().to_string();
        let start_time = Instant::now();

        info!(
            "Starting BAS simulation {} ({} techniques, mode: {})",
            simulation_id,
            scenario.technique_ids.len(),
            scenario.execution_mode
        );

        // Create result container
        let mut result = SimulationResult::new(
            simulation_id.clone(),
            scenario.id.clone(),
            scenario.user_id.clone(),
            scenario.execution_mode,
        );

        // Send started progress
        if let Some(tx) = &progress_tx {
            let _ = tx.send(SimulationProgress::Started {
                simulation_id: simulation_id.clone(),
                scenario_name: scenario.name.clone(),
                total_techniques: scenario.technique_ids.len(),
            });
        }

        // Run safety checks
        let safety_result = run_safety_check(
            &self.safety,
            scenario.execution_mode,
            &scenario.technique_ids,
            &scenario.targets,
            scenario.timeout_secs,
        );

        if !safety_result.passed {
            warn!(
                "Safety check failed with {} violation(s)",
                safety_result.violations.len()
            );
            result.status = SimulationStatus::Failed;
            result.error = Some(format!(
                "Safety check failed: {}",
                safety_result
                    .violations
                    .iter()
                    .map(|v| v.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
            result.completed_at = Some(Utc::now());
            return Ok(result);
        }

        result.status = SimulationStatus::Running;

        // Create executions for each technique
        let mut executions: Vec<TechniqueExecution> = scenario
            .technique_ids
            .iter()
            .enumerate()
            .map(|(idx, tid)| {
                let mut exec = TechniqueExecution::new(
                    format!("{}-{}", simulation_id, idx),
                    simulation_id.clone(),
                    tid.clone(),
                );
                if !scenario.targets.is_empty() {
                    exec.target = Some(scenario.targets[idx % scenario.targets.len()].clone());
                }
                exec
            })
            .collect();

        // Execute techniques
        if scenario.parallel_execution && scenario.execution_mode != ExecutionMode::DryRun {
            // Parallel execution
            executions = self
                .execute_parallel(
                    executions,
                    &scenario,
                    progress_tx.clone(),
                )
                .await;
        } else {
            // Sequential execution
            executions = self
                .execute_sequential(
                    executions,
                    &scenario,
                    progress_tx.clone(),
                )
                .await;
        }

        // Calculate summary
        result.summary.calculate(&executions);

        // Identify detection gaps
        result.detection_gaps = self.detector.identify_gaps(&executions, &simulation_id);

        // Send gap notifications
        if let Some(tx) = &progress_tx {
            for gap in &result.detection_gaps {
                let _ = tx.send(SimulationProgress::DetectionGapFound {
                    technique_id: gap.technique_id.clone(),
                    technique_name: gap.technique_name.clone(),
                    severity: gap.severity,
                });
            }
        }

        // Finalize result
        result.executions = executions;
        result.status = if result.summary.failed > 0 {
            SimulationStatus::PartiallyCompleted
        } else {
            SimulationStatus::Completed
        };
        result.completed_at = Some(Utc::now());
        result.duration_ms = Some(start_time.elapsed().as_millis() as u64);

        // Collect tactics covered
        let mut tactics_covered = std::collections::HashSet::new();
        for exec in &result.executions {
            if let Some(technique) = self.library.get(&exec.technique_id) {
                for tactic in &technique.tactics {
                    tactics_covered.insert(*tactic);
                }
            }
        }
        result.summary.tactics_covered = tactics_covered.into_iter().collect();

        // Send completed progress
        if let Some(tx) = &progress_tx {
            let _ = tx.send(SimulationProgress::Completed {
                simulation_id: simulation_id.clone(),
                summary: result.summary.clone(),
                duration_ms: result.duration_ms.unwrap_or(0),
            });
        }

        info!(
            "Simulation {} completed: {} techniques, {}% detection rate, {} gaps",
            simulation_id,
            result.summary.total_techniques,
            (result.summary.detection_rate * 100.0) as u32,
            result.detection_gaps.len()
        );

        Ok(result)
    }

    /// Execute techniques sequentially
    async fn execute_sequential(
        &self,
        mut executions: Vec<TechniqueExecution>,
        scenario: &SimulationScenario,
        progress_tx: Option<broadcast::Sender<SimulationProgress>>,
    ) -> Vec<TechniqueExecution> {
        let total = executions.len();

        for (idx, execution) in executions.iter_mut().enumerate() {
            let technique_name = self
                .library
                .get(&execution.technique_id)
                .map(|t| t.name.clone())
                .unwrap_or_else(|| execution.technique_id.clone());

            // Send progress
            if let Some(tx) = &progress_tx {
                let _ = tx.send(SimulationProgress::TechniqueStarted {
                    technique_id: execution.technique_id.clone(),
                    technique_name: technique_name.clone(),
                    index: idx,
                    total,
                });
            }

            // Execute technique
            let payload_result = self
                .execute_technique(execution, scenario)
                .await;

            // Validate detection
            if scenario.execution_mode != ExecutionMode::DryRun {
                let detection = self
                    .detector
                    .validate_execution(execution, payload_result.as_ref())
                    .await;
                execution.detection_observed = detection.detected;
                if detection.detected {
                    execution.detection_details = detection.details;
                    if execution.status == TechniqueExecutionStatus::Success {
                        execution.status = TechniqueExecutionStatus::Detected;
                    }
                }
            }

            // Send completion progress
            if let Some(tx) = &progress_tx {
                let _ = tx.send(SimulationProgress::TechniqueCompleted {
                    technique_id: execution.technique_id.clone(),
                    status: execution.status,
                    detection_observed: execution.detection_observed,
                    duration_ms: execution.duration_ms.unwrap_or(0),
                });
            }

            // Check continue_on_failure
            if !scenario.continue_on_failure
                && execution.status == TechniqueExecutionStatus::Failed
            {
                warn!(
                    "Stopping simulation due to failure (continue_on_failure=false)"
                );
                break;
            }
        }

        executions
    }

    /// Execute techniques in parallel
    async fn execute_parallel(
        &self,
        executions: Vec<TechniqueExecution>,
        scenario: &SimulationScenario,
        progress_tx: Option<broadcast::Sender<SimulationProgress>>,
    ) -> Vec<TechniqueExecution> {
        let semaphore = Arc::new(Semaphore::new(self.config.max_parallel));
        let total = executions.len();

        // Note: For parallel execution, we'd normally use tokio::spawn, but since
        // we need to maintain state coherently, we'll use a join_all approach
        // In practice, parallel BAS execution should be carefully managed

        let mut results = Vec::with_capacity(executions.len());

        for (idx, mut execution) in executions.into_iter().enumerate() {
            let _permit = semaphore.clone().acquire_owned().await;

            let technique_name = self
                .library
                .get(&execution.technique_id)
                .map(|t| t.name.clone())
                .unwrap_or_else(|| execution.technique_id.clone());

            if let Some(tx) = &progress_tx {
                let _ = tx.send(SimulationProgress::TechniqueStarted {
                    technique_id: execution.technique_id.clone(),
                    technique_name,
                    index: idx,
                    total,
                });
            }

            let payload_result = self.execute_technique(&mut execution, scenario).await;

            if scenario.execution_mode != ExecutionMode::DryRun {
                let detection = self
                    .detector
                    .validate_execution(&execution, payload_result.as_ref())
                    .await;
                execution.detection_observed = detection.detected;
                if detection.detected {
                    execution.detection_details = detection.details;
                    if execution.status == TechniqueExecutionStatus::Success {
                        execution.status = TechniqueExecutionStatus::Detected;
                    }
                }
            }

            if let Some(tx) = &progress_tx {
                let _ = tx.send(SimulationProgress::TechniqueCompleted {
                    technique_id: execution.technique_id.clone(),
                    status: execution.status,
                    detection_observed: execution.detection_observed,
                    duration_ms: execution.duration_ms.unwrap_or(0),
                });
            }

            results.push(execution);
        }

        results
    }

    /// Execute a single technique
    async fn execute_technique(
        &self,
        execution: &mut TechniqueExecution,
        scenario: &SimulationScenario,
    ) -> Option<PayloadResult> {
        execution.mark_started();

        let technique = match self.library.get(&execution.technique_id) {
            Some(t) => t,
            None => {
                execution.mark_completed(TechniqueExecutionStatus::Failed);
                execution.error = Some("Technique not found in library".to_string());
                return None;
            }
        };

        debug!(
            "Executing technique {} ({})",
            technique.technique_id, technique.name
        );

        // DryRun mode - just analyze
        if scenario.execution_mode == ExecutionMode::DryRun {
            execution.mark_completed(TechniqueExecutionStatus::Success);
            execution.output = Some(format!(
                "DryRun: Would execute '{}' ({}) targeting {:?}",
                technique.name,
                technique.technique_id,
                execution.target
            ));
            return None;
        }

        // Get appropriate payloads for this technique
        let payloads = get_payloads_for_technique(&execution.technique_id);

        if payloads.is_empty() {
            execution.mark_completed(TechniqueExecutionStatus::Skipped);
            execution.output = Some("No safe payloads available for this technique".to_string());
            return None;
        }

        // Execute the first applicable payload
        let payload = &payloads[0];
        execution.payload_type = Some(payload.payload_type);

        // Apply timeout
        let timeout_duration = Duration::from_secs(scenario.timeout_secs);

        match timeout(timeout_duration, self.executor.execute(payload)).await {
            Ok(Ok(result)) => {
                if result.success {
                    execution.mark_completed(TechniqueExecutionStatus::Success);
                    execution.output = Some(result.output.clone());
                    execution.cleanup_completed = result.cleanup_performed;
                    Some(result)
                } else {
                    execution.mark_completed(TechniqueExecutionStatus::Failed);
                    execution.error = result.error.clone();
                    Some(result)
                }
            }
            Ok(Err(e)) => {
                execution.mark_completed(TechniqueExecutionStatus::Failed);
                execution.error = Some(e.to_string());
                None
            }
            Err(_) => {
                execution.mark_completed(TechniqueExecutionStatus::TimedOut);
                execution.error = Some(format!(
                    "Execution timed out after {} seconds",
                    scenario.timeout_secs
                ));
                None
            }
        }
    }

    /// Run a quick security test with common techniques
    pub async fn quick_test(&self, targets: Vec<String>) -> Result<SimulationResult> {
        let scenario = SimulationScenario::new(
            Uuid::new_v4().to_string(),
            "Quick Security Test",
            "system",
        );

        let mut scenario = scenario;
        scenario.targets = targets;
        scenario.execution_mode = ExecutionMode::Simulation;
        scenario.technique_ids = vec![
            "T1082".to_string(),     // System Information Discovery
            "T1083".to_string(),     // File and Directory Discovery
            "T1071.001".to_string(), // Web Protocols (C2)
            "T1071.004".to_string(), // DNS (C2)
            "T1059.001".to_string(), // PowerShell
        ];

        self.run_simulation(scenario, None).await
    }

    /// Get available techniques for a given mode
    pub fn get_available_techniques(&self, mode: ExecutionMode) -> Vec<&AttackTechnique> {
        self.safety.get_safe_techniques(mode)
    }

    /// Get techniques by tactic
    pub fn get_techniques_by_tactic(&self, tactic: MitreTactic) -> Vec<&AttackTechnique> {
        self.library.by_tactic(tactic)
    }

    /// Validate a scenario without executing
    pub fn validate_scenario(
        &self,
        scenario: &SimulationScenario,
    ) -> Result<Vec<SafetyViolation>, Vec<SafetyViolation>> {
        let check_result = run_safety_check(
            &self.safety,
            scenario.execution_mode,
            &scenario.technique_ids,
            &scenario.targets,
            scenario.timeout_secs,
        );

        if check_result.passed {
            Ok(check_result.violations) // Empty or just warnings
        } else {
            Err(check_result.violations)
        }
    }

    /// Get detection coverage statistics for executions
    pub fn get_detection_stats(
        &self,
        executions: &[TechniqueExecution],
    ) -> super::detection::DetectionCoverageStats {
        self.detector.get_coverage_stats(executions)
    }

    /// Cleanup all artifacts
    pub async fn cleanup(&self) -> Result<usize> {
        self.executor.cleanup_all().await
    }
}

impl Default for BasEngine {
    fn default() -> Self {
        Self::new(BasConfig::default())
    }
}

/// Builder for creating simulation scenarios
pub struct ScenarioBuilder {
    scenario: SimulationScenario,
}

impl ScenarioBuilder {
    /// Create a new scenario builder
    pub fn new(name: impl Into<String>, user_id: impl Into<String>) -> Self {
        Self {
            scenario: SimulationScenario::new(
                Uuid::new_v4().to_string(),
                name,
                user_id,
            ),
        }
    }

    /// Set execution mode
    pub fn mode(mut self, mode: ExecutionMode) -> Self {
        self.scenario.execution_mode = mode;
        self
    }

    /// Add techniques
    pub fn techniques(mut self, technique_ids: Vec<String>) -> Self {
        self.scenario.technique_ids = technique_ids;
        self
    }

    /// Add a single technique
    pub fn technique(mut self, technique_id: impl Into<String>) -> Self {
        self.scenario.technique_ids.push(technique_id.into());
        self
    }

    /// Add targets
    pub fn targets(mut self, targets: Vec<String>) -> Self {
        self.scenario.targets = targets;
        self
    }

    /// Set description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.scenario.description = desc.into();
        self
    }

    /// Set timeout
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.scenario.timeout_secs = seconds;
        self
    }

    /// Enable parallel execution
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.scenario.parallel_execution = enabled;
        self
    }

    /// Set continue on failure
    pub fn continue_on_failure(mut self, continue_on: bool) -> Self {
        self.scenario.continue_on_failure = continue_on;
        self
    }

    /// Add tags
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.scenario.tags = tags;
        self
    }

    /// Build the scenario
    pub fn build(self) -> SimulationScenario {
        self.scenario
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = BasEngine::default_config();
        assert!(engine.library().count() > 0);
    }

    #[test]
    fn test_scenario_builder() {
        let scenario = ScenarioBuilder::new("Test Scenario", "user123")
            .mode(ExecutionMode::DryRun)
            .techniques(vec!["T1059.001".to_string()])
            .targets(vec!["localhost".to_string()])
            .timeout(60)
            .build();

        assert_eq!(scenario.name, "Test Scenario");
        assert_eq!(scenario.execution_mode, ExecutionMode::DryRun);
        assert_eq!(scenario.technique_ids.len(), 1);
    }

    #[tokio::test]
    async fn test_dry_run_simulation() {
        let engine = BasEngine::default_config();

        let scenario = ScenarioBuilder::new("Dry Run Test", "test_user")
            .mode(ExecutionMode::DryRun)
            .techniques(vec!["T1082".to_string(), "T1083".to_string()])
            .targets(vec!["localhost".to_string()])
            .build();

        let result = engine.run_simulation(scenario, None).await.unwrap();

        assert_eq!(result.status, SimulationStatus::Completed);
        assert_eq!(result.executions.len(), 2);
    }

    #[test]
    fn test_validate_scenario() {
        let engine = BasEngine::default_config();

        let scenario = ScenarioBuilder::new("Valid Scenario", "user123")
            .mode(ExecutionMode::Simulation)
            .techniques(vec!["T1059.001".to_string()])
            .targets(vec!["localhost".to_string()])
            .build();

        let result = engine.validate_scenario(&scenario);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_available_techniques() {
        let engine = BasEngine::default_config();
        let techniques = engine.get_available_techniques(ExecutionMode::Simulation);
        assert!(!techniques.is_empty());
    }

    #[test]
    fn test_get_techniques_by_tactic() {
        let engine = BasEngine::default_config();
        let execution_techniques = engine.get_techniques_by_tactic(MitreTactic::Execution);
        assert!(!execution_techniques.is_empty());
    }
}
