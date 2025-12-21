//! Database operations for Breach & Attack Simulation (BAS)
//!
//! Provides CRUD operations for BAS scenarios, simulations, and detection gaps.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use utoipa::ToSchema;

use crate::scanner::bas::{
    ExecutionMode, MitreTactic, ScenarioStatus,
    SimulationResult, SimulationScenario, SimulationStatus,
};

// ============================================================================
// Database Models
// ============================================================================

/// Database model for BAS scenarios
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct BasScenarioRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub tactics: String,        // JSON array
    pub techniques: String,     // JSON array (technique IDs)
    pub execution_mode: String,
    pub timeout_secs: i64,
    pub created_by: Option<String>,
    pub is_builtin: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// Database model for BAS simulations
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct BasSimulationRecord {
    pub id: String,
    pub scenario_id: String,
    pub user_id: String,
    pub name: String,
    pub status: String,
    pub execution_mode: String,
    pub target_host: Option<String>,
    pub techniques_total: i64,
    pub techniques_executed: i64,
    pub techniques_detected: i64,
    pub techniques_failed: i64,
    pub detection_rate: Option<f64>,
    pub gap_count: i64,
    pub error_message: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
}

/// Database model for technique executions
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct BasTechniqueExecutionRecord {
    pub id: String,
    pub simulation_id: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub status: String,
    pub payload_type: Option<String>,
    pub payload_data: Option<String>,
    pub was_detected: i64,
    pub detection_source: Option<String>,
    pub detection_time_ms: Option<i64>,
    pub error_message: Option<String>,
    pub artifacts: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Database model for detection gaps
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct BasDetectionGapRecord {
    pub id: String,
    pub simulation_id: String,
    pub execution_id: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub severity: String,
    pub recommendation: Option<String>,
    pub is_acknowledged: i64,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
}

// ============================================================================
// Scenario Operations
// ============================================================================

/// Create a new BAS scenario
pub async fn create_scenario(
    pool: &SqlitePool,
    scenario: &SimulationScenario,
) -> Result<BasScenarioRecord> {
    let tactics_json = serde_json::to_string(&scenario.tags)?; // Using tags for tactics
    let techniques_json = serde_json::to_string(&scenario.technique_ids)?;
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO bas_scenarios (
            id, name, description, tactics, techniques, execution_mode,
            timeout_secs, created_by, is_builtin, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&scenario.id)
    .bind(&scenario.name)
    .bind(&scenario.description)
    .bind(&tactics_json)
    .bind(&techniques_json)
    .bind(scenario.execution_mode.as_str())
    .bind(scenario.timeout_secs as i64)
    .bind(&scenario.user_id)
    .bind(0i64) // is_builtin = false
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(BasScenarioRecord {
        id: scenario.id.clone(),
        name: scenario.name.clone(),
        description: if scenario.description.is_empty() {
            None
        } else {
            Some(scenario.description.clone())
        },
        tactics: tactics_json,
        techniques: techniques_json.clone(),
        execution_mode: scenario.execution_mode.as_str().to_string(),
        timeout_secs: scenario.timeout_secs as i64,
        created_by: Some(scenario.user_id.clone()),
        is_builtin: 0,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Get scenarios for a user (including builtin)
pub async fn get_user_scenarios(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<BasScenarioRecord>> {
    let scenarios = sqlx::query_as::<_, BasScenarioRecord>(
        r#"
        SELECT id, name, description, tactics, techniques, execution_mode,
               timeout_secs, created_by, is_builtin, created_at, updated_at
        FROM bas_scenarios
        WHERE created_by = ? OR is_builtin = 1
        ORDER BY updated_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(scenarios)
}

/// Get a scenario by ID
pub async fn get_scenario_by_id(
    pool: &SqlitePool,
    scenario_id: &str,
) -> Result<Option<BasScenarioRecord>> {
    let scenario = sqlx::query_as::<_, BasScenarioRecord>(
        r#"
        SELECT id, name, description, tactics, techniques, execution_mode,
               timeout_secs, created_by, is_builtin, created_at, updated_at
        FROM bas_scenarios
        WHERE id = ?
        "#,
    )
    .bind(scenario_id)
    .fetch_optional(pool)
    .await?;

    Ok(scenario)
}

/// Update a scenario
pub async fn update_scenario(
    pool: &SqlitePool,
    scenario: &SimulationScenario,
) -> Result<()> {
    let tactics_json = serde_json::to_string(&scenario.tags)?;
    let techniques_json = serde_json::to_string(&scenario.technique_ids)?;
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE bas_scenarios SET
            name = ?, description = ?, tactics = ?, techniques = ?,
            execution_mode = ?, timeout_secs = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&scenario.name)
    .bind(&scenario.description)
    .bind(&tactics_json)
    .bind(&techniques_json)
    .bind(scenario.execution_mode.as_str())
    .bind(scenario.timeout_secs as i64)
    .bind(&now)
    .bind(&scenario.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a scenario
pub async fn delete_scenario(pool: &SqlitePool, scenario_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM bas_scenarios WHERE id = ? AND is_builtin = 0")
        .bind(scenario_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Simulation Operations
// ============================================================================

/// Create a simulation record
pub async fn create_simulation(
    pool: &SqlitePool,
    result: &SimulationResult,
) -> Result<BasSimulationRecord> {
    let now = Utc::now().to_rfc3339();
    let started_at = result.started_at.to_rfc3339();
    let completed_at = result.completed_at.map(|t| t.to_rfc3339());

    // Calculate statistics from executions
    let total = result.executions.len() as i64;
    let executed = result.executions.iter()
        .filter(|e| e.status != crate::scanner::bas::TechniqueExecutionStatus::Pending)
        .count() as i64;
    let detected = result.summary.detected as i64;
    let failed = result.summary.failed as i64;
    let detection_rate = if total > 0 {
        Some(detected as f64 / total as f64)
    } else {
        Some(0.0)
    };
    let gap_count = result.detection_gaps.len() as i64;

    sqlx::query(
        r#"
        INSERT INTO bas_simulations (
            id, scenario_id, user_id, name, status, execution_mode,
            target_host, techniques_total, techniques_executed, techniques_detected,
            techniques_failed, detection_rate, gap_count, error_message,
            started_at, completed_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&result.id)
    .bind(&result.scenario_id)
    .bind(&result.user_id)
    .bind(format!("Simulation {}", &result.id[..8]))
    .bind(result.status.as_str())
    .bind(result.execution_mode.as_str())
    .bind::<Option<String>>(None) // target_host
    .bind(total)
    .bind(executed)
    .bind(detected)
    .bind(failed)
    .bind(detection_rate)
    .bind(gap_count)
    .bind(&result.error)
    .bind(&started_at)
    .bind(&completed_at)
    .bind(&now)
    .execute(pool)
    .await?;

    // Store technique executions
    for execution in &result.executions {
        create_technique_execution(pool, execution, &result.id).await?;
    }

    // Store detection gaps
    for gap in &result.detection_gaps {
        create_detection_gap(pool, gap).await?;
    }

    Ok(BasSimulationRecord {
        id: result.id.clone(),
        scenario_id: result.scenario_id.clone(),
        user_id: result.user_id.clone(),
        name: format!("Simulation {}", &result.id[..8]),
        status: result.status.as_str().to_string(),
        execution_mode: result.execution_mode.as_str().to_string(),
        target_host: None,
        techniques_total: total,
        techniques_executed: executed,
        techniques_detected: detected,
        techniques_failed: failed,
        detection_rate,
        gap_count,
        error_message: result.error.clone(),
        started_at: Some(started_at),
        completed_at,
        created_at: now,
    })
}

/// Get simulations for a user
pub async fn get_user_simulations(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<BasSimulationRecord>> {
    let simulations = sqlx::query_as::<_, BasSimulationRecord>(
        r#"
        SELECT id, scenario_id, user_id, name, status, execution_mode,
               target_host, techniques_total, techniques_executed, techniques_detected,
               techniques_failed, detection_rate, gap_count, error_message,
               started_at, completed_at, created_at
        FROM bas_simulations
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(simulations)
}

/// Get a simulation by ID
pub async fn get_simulation_by_id(
    pool: &SqlitePool,
    simulation_id: &str,
) -> Result<Option<BasSimulationRecord>> {
    let simulation = sqlx::query_as::<_, BasSimulationRecord>(
        r#"
        SELECT id, scenario_id, user_id, name, status, execution_mode,
               target_host, techniques_total, techniques_executed, techniques_detected,
               techniques_failed, detection_rate, gap_count, error_message,
               started_at, completed_at, created_at
        FROM bas_simulations
        WHERE id = ?
        "#,
    )
    .bind(simulation_id)
    .fetch_optional(pool)
    .await?;

    Ok(simulation)
}

/// Get simulations for a scenario
pub async fn get_simulations_by_scenario(
    pool: &SqlitePool,
    scenario_id: &str,
) -> Result<Vec<BasSimulationRecord>> {
    let simulations = sqlx::query_as::<_, BasSimulationRecord>(
        r#"
        SELECT id, scenario_id, user_id, name, status, execution_mode,
               target_host, techniques_total, techniques_executed, techniques_detected,
               techniques_failed, detection_rate, gap_count, error_message,
               started_at, completed_at, created_at
        FROM bas_simulations
        WHERE scenario_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(scenario_id)
    .fetch_all(pool)
    .await?;

    Ok(simulations)
}

/// Update simulation status
pub async fn update_simulation_status(
    pool: &SqlitePool,
    simulation_id: &str,
    status: SimulationStatus,
    error: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        UPDATE bas_simulations SET status = ?, error_message = ?, completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(status.as_str())
    .bind(error)
    .bind(&now)
    .bind(simulation_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Technique Execution Operations
// ============================================================================

/// Create a technique execution record
async fn create_technique_execution(
    pool: &SqlitePool,
    execution: &crate::scanner::bas::TechniqueExecution,
    simulation_id: &str,
) -> Result<()> {
    let started_at = execution.started_at.map(|t| t.to_rfc3339());
    let completed_at = execution.completed_at.map(|t| t.to_rfc3339());

    sqlx::query(
        r#"
        INSERT INTO bas_technique_executions (
            id, simulation_id, technique_id, technique_name, tactic, status,
            payload_type, payload_data, was_detected, detection_source,
            detection_time_ms, error_message, artifacts, started_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&execution.id)
    .bind(simulation_id)
    .bind(&execution.technique_id)
    .bind(&execution.technique_id) // technique_name - we use ID for now
    .bind("execution") // default tactic
    .bind(execution.status.as_str())
    .bind(execution.payload_type.map(|p| p.as_str().to_string()))
    .bind::<Option<String>>(None) // payload_data
    .bind(if execution.detection_observed { 1i64 } else { 0i64 })
    .bind(&execution.detection_details)
    .bind(execution.duration_ms.map(|d| d as i64))
    .bind(&execution.error)
    .bind::<Option<String>>(None) // artifacts
    .bind(&started_at)
    .bind(&completed_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get technique executions for a simulation
pub async fn get_technique_executions(
    pool: &SqlitePool,
    simulation_id: &str,
) -> Result<Vec<BasTechniqueExecutionRecord>> {
    let executions = sqlx::query_as::<_, BasTechniqueExecutionRecord>(
        r#"
        SELECT id, simulation_id, technique_id, technique_name, tactic, status,
               payload_type, payload_data, was_detected, detection_source,
               detection_time_ms, error_message, artifacts, started_at, completed_at
        FROM bas_technique_executions
        WHERE simulation_id = ?
        ORDER BY started_at ASC
        "#,
    )
    .bind(simulation_id)
    .fetch_all(pool)
    .await?;

    Ok(executions)
}

// ============================================================================
// Detection Gap Operations
// ============================================================================

/// Create a detection gap record
async fn create_detection_gap(
    pool: &SqlitePool,
    gap: &crate::scanner::bas::DetectionGap,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let tactic = gap.tactics.first()
        .map(|t| t.id().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let severity = match gap.severity {
        1 => "low",
        2 => "medium",
        3 => "medium",
        4 => "high",
        5 => "critical",
        _ => "medium",
    };

    sqlx::query(
        r#"
        INSERT INTO bas_detection_gaps (
            id, simulation_id, execution_id, technique_id, technique_name,
            tactic, severity, recommendation, is_acknowledged, acknowledged_by,
            acknowledged_at, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&gap.id)
    .bind(&gap.simulation_id)
    .bind(&gap.id) // Using gap id as execution_id since we don't have it
    .bind(&gap.technique_id)
    .bind(&gap.technique_name)
    .bind(&tactic)
    .bind(severity)
    .bind(gap.recommendations.first().cloned())
    .bind(if gap.acknowledged { 1i64 } else { 0i64 })
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind(&gap.acknowledgement_notes)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get detection gaps for a simulation
pub async fn get_detection_gaps(
    pool: &SqlitePool,
    simulation_id: &str,
) -> Result<Vec<BasDetectionGapRecord>> {
    let gaps = sqlx::query_as::<_, BasDetectionGapRecord>(
        r#"
        SELECT id, simulation_id, execution_id, technique_id, technique_name,
               tactic, severity, recommendation, is_acknowledged, acknowledged_by,
               acknowledged_at, notes, created_at
        FROM bas_detection_gaps
        WHERE simulation_id = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            created_at DESC
        "#,
    )
    .bind(simulation_id)
    .fetch_all(pool)
    .await?;

    Ok(gaps)
}

/// Acknowledge a detection gap
pub async fn acknowledge_detection_gap(
    pool: &SqlitePool,
    gap_id: &str,
    notes: Option<&str>,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        r#"
        UPDATE bas_detection_gaps SET
            is_acknowledged = 1, notes = ?, acknowledged_at = ?
        WHERE id = ?
        "#,
    )
    .bind(notes)
    .bind(&now)
    .bind(gap_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Get unacknowledged detection gaps for a user
pub async fn get_unacknowledged_gaps(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<BasDetectionGapRecord>> {
    let gaps = sqlx::query_as::<_, BasDetectionGapRecord>(
        r#"
        SELECT g.id, g.simulation_id, g.execution_id, g.technique_id, g.technique_name,
               g.tactic, g.severity, g.recommendation, g.is_acknowledged, g.acknowledged_by,
               g.acknowledged_at, g.notes, g.created_at
        FROM bas_detection_gaps g
        JOIN bas_simulations s ON g.simulation_id = s.id
        WHERE s.user_id = ? AND g.is_acknowledged = 0
        ORDER BY
            CASE g.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            g.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(gaps)
}

// ============================================================================
// Statistics
// ============================================================================

/// BAS statistics for a user
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BasStats {
    pub total_scenarios: i64,
    pub total_simulations: i64,
    pub total_techniques_tested: i64,
    pub avg_detection_rate: f64,
    pub avg_security_score: f64,
    pub total_detection_gaps: i64,
    pub unacknowledged_gaps: i64,
}

/// Get BAS statistics for a user
pub async fn get_user_stats(pool: &SqlitePool, user_id: &str) -> Result<BasStats> {
    let scenario_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM bas_scenarios WHERE created_by = ? OR is_builtin = 1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let sim_stats: (i64, Option<f64>, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*),
            AVG(detection_rate),
            COALESCE(SUM(techniques_total), 0)
        FROM bas_simulations
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let gap_counts: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*),
            COALESCE(SUM(CASE WHEN is_acknowledged = 0 THEN 1 ELSE 0 END), 0)
        FROM bas_detection_gaps g
        JOIN bas_simulations s ON g.simulation_id = s.id
        WHERE s.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Calculate average security score from detection rate (detection_rate * 100)
    let avg_security_score = sim_stats.1.unwrap_or(0.0) * 100.0;

    Ok(BasStats {
        total_scenarios: scenario_count.0,
        total_simulations: sim_stats.0,
        total_techniques_tested: sim_stats.2,
        avg_detection_rate: sim_stats.1.unwrap_or(0.0),
        avg_security_score,
        total_detection_gaps: gap_counts.0,
        unacknowledged_gaps: gap_counts.1,
    })
}

// ============================================================================
// Conversion helpers
// ============================================================================

impl BasScenarioRecord {
    /// Convert to domain model
    pub fn to_domain(&self) -> SimulationScenario {
        let technique_ids: Vec<String> = serde_json::from_str(&self.techniques)
            .unwrap_or_default();
        let tags: Vec<String> = serde_json::from_str(&self.tactics)
            .unwrap_or_default();

        SimulationScenario {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone().unwrap_or_default(),
            user_id: self.created_by.clone().unwrap_or_default(),
            status: ScenarioStatus::Ready,
            execution_mode: ExecutionMode::from_str(&self.execution_mode)
                .unwrap_or(ExecutionMode::DryRun),
            technique_ids,
            targets: Vec::new(),
            payload_configs: std::collections::HashMap::new(),
            timeout_secs: self.timeout_secs as u64,
            parallel_execution: false,
            continue_on_failure: true,
            tags,
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: chrono::DateTime::parse_from_rfc3339(&self.updated_at)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

impl BasTechniqueExecutionRecord {
    /// Convert to domain model
    pub fn to_domain(&self) -> crate::scanner::bas::TechniqueExecution {
        use crate::scanner::bas::{PayloadType, TechniqueExecutionStatus, TechniqueExecution};

        TechniqueExecution {
            id: self.id.clone(),
            simulation_id: self.simulation_id.clone(),
            technique_id: self.technique_id.clone(),
            target: None,
            payload_type: self.payload_type.as_ref().and_then(|p| PayloadType::from_str(p)),
            status: TechniqueExecutionStatus::from_str(&self.status)
                .unwrap_or(TechniqueExecutionStatus::Pending),
            started_at: self.started_at.as_ref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&Utc)),
            completed_at: self.completed_at.as_ref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&Utc)),
            duration_ms: self.detection_time_ms.map(|d| d as u64),
            output: None,
            error: self.error_message.clone(),
            detection_observed: self.was_detected != 0,
            detection_details: self.detection_source.clone(),
            cleanup_completed: false,
        }
    }
}

impl BasDetectionGapRecord {
    /// Convert to domain model
    pub fn to_domain(&self) -> crate::scanner::bas::DetectionGap {
        let tactic = MitreTactic::from_id(&self.tactic);
        let tactics = tactic.into_iter().collect();

        let severity = match self.severity.as_str() {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            _ => 3,
        };

        crate::scanner::bas::DetectionGap {
            id: self.id.clone(),
            simulation_id: self.simulation_id.clone(),
            technique_id: self.technique_id.clone(),
            technique_name: self.technique_name.clone(),
            tactics,
            expected_sources: Vec::new(),
            reason: self.recommendation.clone().unwrap_or_default(),
            recommendations: self.recommendation.clone().into_iter().collect(),
            severity,
            acknowledged: self.is_acknowledged != 0,
            acknowledgement_notes: self.notes.clone(),
            detected_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}
