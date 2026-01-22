//! Database operations for Purple Team module

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::purple_team::{
    PurpleTeamExercise, PurpleAttackConfig, PurpleAttackResult,
    DetectionCoverage, DetectionGap, DetectionRecommendation,
    ExerciseStatus, AttackStatus, DetectionStatus, GapSeverity, GapStatus,
    MitreTactic, TacticCoverage, TechniqueCoverage, DetectionDetails,
    CreateExerciseRequest, UpdateGapStatusRequest,
};

/// Initialize purple team database tables
pub async fn init_purple_team_tables(pool: &SqlitePool) -> Result<()> {
    // Purple Team Exercises table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS purple_team_exercises (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            siem_integration_id TEXT,
            attack_configs TEXT NOT NULL,
            detection_timeout_secs INTEGER DEFAULT 300,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Purple Attack Results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS purple_attack_results (
            id TEXT PRIMARY KEY,
            exercise_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            technique_name TEXT NOT NULL,
            tactic TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            target TEXT NOT NULL,
            attack_status TEXT NOT NULL,
            detection_status TEXT NOT NULL,
            detection_details TEXT,
            time_to_detect_ms INTEGER,
            executed_at TEXT NOT NULL,
            error_message TEXT,
            FOREIGN KEY (exercise_id) REFERENCES purple_team_exercises(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Purple Detection Coverage table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS purple_detection_coverage (
            id TEXT PRIMARY KEY,
            exercise_id TEXT NOT NULL UNIQUE,
            by_tactic TEXT NOT NULL,
            by_technique TEXT NOT NULL,
            overall_score REAL NOT NULL,
            calculated_at TEXT NOT NULL,
            FOREIGN KEY (exercise_id) REFERENCES purple_team_exercises(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Purple Detection Gaps table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS purple_detection_gaps (
            id TEXT PRIMARY KEY,
            exercise_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            technique_name TEXT NOT NULL,
            tactic TEXT NOT NULL,
            severity TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            created_at TEXT NOT NULL,
            remediated_at TEXT,
            notes TEXT,
            FOREIGN KEY (exercise_id) REFERENCES purple_team_exercises(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_purple_exercises_user_id ON purple_team_exercises(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_purple_exercises_status ON purple_team_exercises(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_purple_results_exercise_id ON purple_attack_results(exercise_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_purple_gaps_exercise_id ON purple_detection_gaps(exercise_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_purple_gaps_status ON purple_detection_gaps(status)")
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Exercise Operations
// ============================================================================

/// Create a new purple team exercise
pub async fn create_exercise(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateExerciseRequest,
) -> Result<PurpleTeamExercise> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let attack_configs_json = serde_json::to_string(&request.attack_configs)?;
    let timeout = request.detection_timeout_secs.unwrap_or(300);

    sqlx::query(
        r#"
        INSERT INTO purple_team_exercises (
            id, user_id, name, description, siem_integration_id,
            attack_configs, detection_timeout_secs, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.siem_integration_id)
    .bind(&attack_configs_json)
    .bind(timeout as i64)
    .bind("pending")
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(PurpleTeamExercise {
        id,
        user_id: user_id.to_string(),
        name: request.name.clone(),
        description: request.description.clone(),
        siem_integration_id: request.siem_integration_id.clone(),
        attack_configs: request.attack_configs.clone(),
        detection_timeout_secs: timeout,
        status: ExerciseStatus::Pending,
        created_at: now,
        started_at: None,
        completed_at: None,
    })
}

/// Get all exercises for a user
pub async fn get_user_exercises(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<PurpleTeamExercise>> {
    let rows = sqlx::query_as::<_, ExerciseRow>(
        r#"
        SELECT id, user_id, name, description, siem_integration_id,
               attack_configs, detection_timeout_secs, status,
               created_at, started_at, completed_at
        FROM purple_team_exercises
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Get exercise by ID
pub async fn get_exercise_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<PurpleTeamExercise>> {
    let row = sqlx::query_as::<_, ExerciseRow>(
        r#"
        SELECT id, user_id, name, description, siem_integration_id,
               attack_configs, detection_timeout_secs, status,
               created_at, started_at, completed_at
        FROM purple_team_exercises
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.try_into()?)),
        None => Ok(None),
    }
}

/// Update exercise status
pub async fn update_exercise_status(
    pool: &SqlitePool,
    id: &str,
    status: ExerciseStatus,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
) -> Result<()> {
    let status_str = format!("{}", status);

    sqlx::query(
        r#"
        UPDATE purple_team_exercises
        SET status = ?, started_at = ?, completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&status_str)
    .bind(started_at.map(|t| t.to_rfc3339()))
    .bind(completed_at.map(|t| t.to_rfc3339()))
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete an exercise
pub async fn delete_exercise(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete related data first
    sqlx::query("DELETE FROM purple_detection_gaps WHERE exercise_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM purple_detection_coverage WHERE exercise_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM purple_attack_results WHERE exercise_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM purple_team_exercises WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Attack Result Operations
// ============================================================================

/// Save attack result
pub async fn save_attack_result(
    pool: &SqlitePool,
    result: &PurpleAttackResult,
) -> Result<()> {
    let detection_details_json = result.detection_details.as_ref()
        .map(|d| serde_json::to_string(d))
        .transpose()?;

    let tactic_str = format!("{:?}", result.tactic);
    let attack_status_str = format!("{:?}", result.attack_status);
    let detection_status_str = format!("{:?}", result.detection_status);

    sqlx::query(
        r#"
        INSERT INTO purple_attack_results (
            id, exercise_id, technique_id, technique_name, tactic,
            attack_type, target, attack_status, detection_status,
            detection_details, time_to_detect_ms, executed_at, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&result.id)
    .bind(&result.exercise_id)
    .bind(&result.technique_id)
    .bind(&result.technique_name)
    .bind(&tactic_str)
    .bind(&result.attack_type)
    .bind(&result.target)
    .bind(&attack_status_str)
    .bind(&detection_status_str)
    .bind(&detection_details_json)
    .bind(result.time_to_detect_ms)
    .bind(result.executed_at.to_rfc3339())
    .bind(&result.error_message)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get attack results for an exercise
pub async fn get_exercise_results(
    pool: &SqlitePool,
    exercise_id: &str,
) -> Result<Vec<PurpleAttackResult>> {
    let rows = sqlx::query_as::<_, AttackResultRow>(
        r#"
        SELECT id, exercise_id, technique_id, technique_name, tactic,
               attack_type, target, attack_status, detection_status,
               detection_details, time_to_detect_ms, executed_at, error_message
        FROM purple_attack_results
        WHERE exercise_id = ?
        ORDER BY executed_at
        "#,
    )
    .bind(exercise_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Get a single attack result by ID
pub async fn get_attack_result(
    pool: &SqlitePool,
    result_id: &str,
) -> Result<Option<PurpleAttackResult>> {
    let row = sqlx::query_as::<_, AttackResultRow>(
        r#"
        SELECT id, exercise_id, technique_id, technique_name, tactic,
               attack_type, target, attack_status, detection_status,
               detection_details, time_to_detect_ms, executed_at, error_message
        FROM purple_attack_results
        WHERE id = ?
        "#,
    )
    .bind(result_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.try_into()?)),
        None => Ok(None),
    }
}

/// Update attack result detection status
pub async fn update_result_detection(
    pool: &SqlitePool,
    id: &str,
    detection_status: DetectionStatus,
    detection_details: Option<&DetectionDetails>,
    time_to_detect_ms: Option<i64>,
) -> Result<()> {
    let status_str = format!("{:?}", detection_status);
    let details_json = detection_details
        .map(|d| serde_json::to_string(d))
        .transpose()?;

    sqlx::query(
        r#"
        UPDATE purple_attack_results
        SET detection_status = ?, detection_details = ?, time_to_detect_ms = ?
        WHERE id = ?
        "#,
    )
    .bind(&status_str)
    .bind(&details_json)
    .bind(time_to_detect_ms)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Coverage Operations
// ============================================================================

/// Save detection coverage
pub async fn save_coverage(
    pool: &SqlitePool,
    coverage: &DetectionCoverage,
) -> Result<()> {
    let by_tactic_json = serde_json::to_string(&coverage.by_tactic)?;
    let by_technique_json = serde_json::to_string(&coverage.by_technique)?;

    // Use INSERT OR REPLACE for upsert
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO purple_detection_coverage (
            id, exercise_id, by_tactic, by_technique, overall_score, calculated_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&coverage.id)
    .bind(&coverage.exercise_id)
    .bind(&by_tactic_json)
    .bind(&by_technique_json)
    .bind(coverage.overall_score)
    .bind(coverage.calculated_at.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Get coverage for an exercise
pub async fn get_exercise_coverage(
    pool: &SqlitePool,
    exercise_id: &str,
) -> Result<Option<DetectionCoverage>> {
    let row = sqlx::query_as::<_, CoverageRow>(
        r#"
        SELECT id, exercise_id, by_tactic, by_technique, overall_score, calculated_at
        FROM purple_detection_coverage
        WHERE exercise_id = ?
        "#,
    )
    .bind(exercise_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.try_into()?)),
        None => Ok(None),
    }
}

// ============================================================================
// Gap Operations
// ============================================================================

/// Save detection gap
pub async fn save_gap(
    pool: &SqlitePool,
    gap: &DetectionGap,
) -> Result<()> {
    let tactic_str = format!("{:?}", gap.tactic);
    let severity_str = format!("{}", gap.severity);
    let status_str = format!("{}", gap.status);
    let recommendations_json = serde_json::to_string(&gap.recommendations)?;

    sqlx::query(
        r#"
        INSERT INTO purple_detection_gaps (
            id, exercise_id, technique_id, technique_name, tactic,
            severity, recommendations, status, created_at, remediated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&gap.id)
    .bind(&gap.exercise_id)
    .bind(&gap.technique_id)
    .bind(&gap.technique_name)
    .bind(&tactic_str)
    .bind(&severity_str)
    .bind(&recommendations_json)
    .bind(&status_str)
    .bind(gap.created_at.to_rfc3339())
    .bind(gap.remediated_at.map(|t| t.to_rfc3339()))
    .execute(pool)
    .await?;

    Ok(())
}

/// Get gaps for an exercise
pub async fn get_exercise_gaps(
    pool: &SqlitePool,
    exercise_id: &str,
) -> Result<Vec<DetectionGap>> {
    let rows = sqlx::query_as::<_, GapRow>(
        r#"
        SELECT id, exercise_id, technique_id, technique_name, tactic,
               severity, recommendations, status, created_at, remediated_at
        FROM purple_detection_gaps
        WHERE exercise_id = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            created_at DESC
        "#,
    )
    .bind(exercise_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Get all open gaps for a user
pub async fn get_user_open_gaps(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<DetectionGap>> {
    let rows = sqlx::query_as::<_, GapRow>(
        r#"
        SELECT g.id, g.exercise_id, g.technique_id, g.technique_name, g.tactic,
               g.severity, g.recommendations, g.status, g.created_at, g.remediated_at
        FROM purple_detection_gaps g
        JOIN purple_team_exercises e ON g.exercise_id = e.id
        WHERE e.user_id = ? AND g.status IN ('open', 'in_progress')
        ORDER BY
            CASE g.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            g.created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Update gap status
pub async fn update_gap_status(
    pool: &SqlitePool,
    id: &str,
    request: &UpdateGapStatusRequest,
) -> Result<()> {
    let status_str = format!("{}", request.status);
    let remediated_at = if request.status == GapStatus::Remediated {
        Some(Utc::now().to_rfc3339())
    } else {
        None
    };

    sqlx::query(
        r#"
        UPDATE purple_detection_gaps
        SET status = ?, notes = ?, remediated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&status_str)
    .bind(&request.notes)
    .bind(&remediated_at)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get gap by ID
pub async fn get_gap_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<DetectionGap>> {
    let row = sqlx::query_as::<_, GapRow>(
        r#"
        SELECT id, exercise_id, technique_id, technique_name, tactic,
               severity, recommendations, status, created_at, remediated_at
        FROM purple_detection_gaps
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.try_into()?)),
        None => Ok(None),
    }
}

// ============================================================================
// Dashboard & Statistics
// ============================================================================

/// Get purple team dashboard statistics
pub async fn get_dashboard_stats(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<PurpleTeamDashboardStats> {
    // Get exercise counts
    let exercise_stats = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed
        FROM purple_team_exercises
        WHERE user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get attack counts and detection rate
    let attack_stats = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN detection_status = 'Detected' THEN 1 ELSE 0 END) as detected,
            AVG(COALESCE(time_to_detect_ms, 0)) as avg_time
        FROM purple_attack_results r
        JOIN purple_team_exercises e ON r.exercise_id = e.id
        WHERE e.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get gap counts
    let gap_stats = sqlx::query_as::<_, (i64, i64)>(
        r#"
        SELECT
            SUM(CASE WHEN g.status IN ('open', 'in_progress') THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN g.status IN ('open', 'in_progress') AND g.severity = 'critical' THEN 1 ELSE 0 END) as critical
        FROM purple_detection_gaps g
        JOIN purple_team_exercises e ON g.exercise_id = e.id
        WHERE e.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let total_attacks = attack_stats.0 as usize;
    let detected = attack_stats.1 as usize;
    let detection_rate = if total_attacks > 0 {
        (detected as f32 / total_attacks as f32) * 100.0
    } else {
        0.0
    };

    // Use detection rate as overall coverage for now
    let overall_coverage = detection_rate;

    Ok(PurpleTeamDashboardStats {
        total_exercises: exercise_stats.0 as usize,
        running_exercises: exercise_stats.1 as usize,
        completed_exercises: exercise_stats.2 as usize,
        total_attacks_run: total_attacks,
        detection_rate,
        overall_coverage,
        avg_time_to_detect_ms: attack_stats.2,
        open_gaps: gap_stats.0 as usize,
        critical_gaps: gap_stats.1 as usize,
    })
}

/// Get recent exercises for dashboard
pub async fn get_recent_exercises(
    pool: &SqlitePool,
    user_id: &str,
    limit: usize,
) -> Result<Vec<ExerciseSummary>> {
    let rows = sqlx::query_as::<_, ExerciseSummaryRow>(
        r#"
        SELECT
            e.id, e.name, e.status, e.created_at, e.completed_at,
            (SELECT COUNT(*) FROM purple_attack_results WHERE exercise_id = e.id) as attacks_run,
            (SELECT COUNT(*) FROM purple_detection_gaps WHERE exercise_id = e.id) as gaps_found,
            COALESCE(c.overall_score, 0) as detection_rate
        FROM purple_team_exercises e
        LEFT JOIN purple_detection_coverage c ON e.id = c.exercise_id
        WHERE e.user_id = ?
        ORDER BY e.created_at DESC
        LIMIT ?
        "#,
    )
    .bind(user_id)
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Get coverage by tactic across all exercises
pub async fn get_cumulative_tactic_coverage(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<TacticCoverage>> {
    // Get latest coverage for each exercise and aggregate
    let rows = sqlx::query_as::<_, (String,)>(
        r#"
        SELECT c.by_tactic
        FROM purple_detection_coverage c
        JOIN purple_team_exercises e ON c.exercise_id = e.id
        WHERE e.user_id = ?
        ORDER BY c.calculated_at DESC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match rows {
        Some((json,)) => {
            let coverage: HashMap<String, TacticCoverage> = serde_json::from_str(&json)?;
            Ok(coverage.into_values().collect())
        }
        None => Ok(vec![]),
    }
}

// ============================================================================
// Row Types for sqlx
// ============================================================================

#[derive(sqlx::FromRow)]
struct ExerciseRow {
    id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    siem_integration_id: Option<String>,
    attack_configs: String,
    detection_timeout_secs: i64,
    status: String,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl TryFrom<ExerciseRow> for PurpleTeamExercise {
    type Error = anyhow::Error;

    fn try_from(row: ExerciseRow) -> Result<Self> {
        let attack_configs: Vec<PurpleAttackConfig> = serde_json::from_str(&row.attack_configs)?;
        let status = match row.status.as_str() {
            "pending" => ExerciseStatus::Pending,
            "running" => ExerciseStatus::Running,
            "completed" => ExerciseStatus::Completed,
            "failed" => ExerciseStatus::Failed,
            "cancelled" => ExerciseStatus::Cancelled,
            _ => ExerciseStatus::Pending,
        };

        Ok(PurpleTeamExercise {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            description: row.description,
            siem_integration_id: row.siem_integration_id,
            attack_configs,
            detection_timeout_secs: row.detection_timeout_secs as u64,
            status,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
            started_at: row.started_at.map(|s| DateTime::parse_from_rfc3339(&s).ok()).flatten().map(|d| d.with_timezone(&Utc)),
            completed_at: row.completed_at.map(|s| DateTime::parse_from_rfc3339(&s).ok()).flatten().map(|d| d.with_timezone(&Utc)),
        })
    }
}

#[derive(sqlx::FromRow)]
struct AttackResultRow {
    id: String,
    exercise_id: String,
    technique_id: String,
    technique_name: String,
    tactic: String,
    attack_type: String,
    target: String,
    attack_status: String,
    detection_status: String,
    detection_details: Option<String>,
    time_to_detect_ms: Option<i64>,
    executed_at: String,
    error_message: Option<String>,
}

impl TryFrom<AttackResultRow> for PurpleAttackResult {
    type Error = anyhow::Error;

    fn try_from(row: AttackResultRow) -> Result<Self> {
        let tactic = parse_tactic(&row.tactic)?;
        let attack_status = match row.attack_status.as_str() {
            "Executed" => AttackStatus::Executed,
            "Blocked" => AttackStatus::Blocked,
            "Failed" => AttackStatus::Failed,
            "Skipped" => AttackStatus::Skipped,
            _ => AttackStatus::Failed,
        };
        let detection_status = match row.detection_status.as_str() {
            "Detected" => DetectionStatus::Detected,
            "PartiallyDetected" => DetectionStatus::PartiallyDetected,
            "NotDetected" => DetectionStatus::NotDetected,
            "Pending" => DetectionStatus::Pending,
            _ => DetectionStatus::Pending,
        };
        let detection_details: Option<DetectionDetails> = row.detection_details
            .map(|s| serde_json::from_str(&s))
            .transpose()?;

        Ok(PurpleAttackResult {
            id: row.id,
            exercise_id: row.exercise_id,
            technique_id: row.technique_id,
            technique_name: row.technique_name,
            tactic,
            attack_type: row.attack_type,
            target: row.target,
            attack_status,
            detection_status,
            detection_details,
            time_to_detect_ms: row.time_to_detect_ms,
            executed_at: DateTime::parse_from_rfc3339(&row.executed_at)?.with_timezone(&Utc),
            error_message: row.error_message,
        })
    }
}

#[derive(sqlx::FromRow)]
struct CoverageRow {
    id: String,
    exercise_id: String,
    by_tactic: String,
    by_technique: String,
    overall_score: f64,
    calculated_at: String,
}

impl TryFrom<CoverageRow> for DetectionCoverage {
    type Error = anyhow::Error;

    fn try_from(row: CoverageRow) -> Result<Self> {
        let by_tactic: HashMap<String, TacticCoverage> = serde_json::from_str(&row.by_tactic)?;
        let by_technique: HashMap<String, TechniqueCoverage> = serde_json::from_str(&row.by_technique)?;

        Ok(DetectionCoverage {
            id: row.id,
            exercise_id: row.exercise_id,
            by_tactic,
            by_technique,
            overall_score: row.overall_score as f32,
            calculated_at: DateTime::parse_from_rfc3339(&row.calculated_at)?.with_timezone(&Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct GapRow {
    id: String,
    exercise_id: String,
    technique_id: String,
    technique_name: String,
    tactic: String,
    severity: String,
    recommendations: String,
    status: String,
    created_at: String,
    remediated_at: Option<String>,
}

impl TryFrom<GapRow> for DetectionGap {
    type Error = anyhow::Error;

    fn try_from(row: GapRow) -> Result<Self> {
        let tactic = parse_tactic(&row.tactic)?;
        let severity = match row.severity.as_str() {
            "critical" => GapSeverity::Critical,
            "high" => GapSeverity::High,
            "medium" => GapSeverity::Medium,
            "low" => GapSeverity::Low,
            _ => GapSeverity::Medium,
        };
        let status = match row.status.as_str() {
            "open" => GapStatus::Open,
            "in_progress" => GapStatus::InProgress,
            "remediated" => GapStatus::Remediated,
            "accepted" => GapStatus::Accepted,
            _ => GapStatus::Open,
        };
        let recommendations: Vec<DetectionRecommendation> = serde_json::from_str(&row.recommendations)?;

        Ok(DetectionGap {
            id: row.id,
            exercise_id: row.exercise_id,
            technique_id: row.technique_id,
            technique_name: row.technique_name,
            tactic,
            severity,
            recommendations,
            status,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
            remediated_at: row.remediated_at.map(|s| DateTime::parse_from_rfc3339(&s).ok()).flatten().map(|d| d.with_timezone(&Utc)),
        })
    }
}

#[derive(sqlx::FromRow)]
struct ExerciseSummaryRow {
    id: String,
    name: String,
    status: String,
    created_at: String,
    completed_at: Option<String>,
    attacks_run: i64,
    gaps_found: i64,
    detection_rate: f64,
}

impl TryFrom<ExerciseSummaryRow> for ExerciseSummary {
    type Error = anyhow::Error;

    fn try_from(row: ExerciseSummaryRow) -> Result<Self> {
        let status = match row.status.as_str() {
            "pending" => ExerciseStatus::Pending,
            "running" => ExerciseStatus::Running,
            "completed" => ExerciseStatus::Completed,
            "failed" => ExerciseStatus::Failed,
            "cancelled" => ExerciseStatus::Cancelled,
            _ => ExerciseStatus::Pending,
        };

        Ok(ExerciseSummary {
            id: row.id,
            name: row.name,
            status,
            attacks_run: row.attacks_run as usize,
            detection_rate: row.detection_rate as f32,
            gaps_found: row.gaps_found as usize,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
            completed_at: row.completed_at.map(|s| DateTime::parse_from_rfc3339(&s).ok()).flatten().map(|d| d.with_timezone(&Utc)),
        })
    }
}

fn parse_tactic(s: &str) -> Result<MitreTactic> {
    Ok(match s {
        "Reconnaissance" => MitreTactic::Reconnaissance,
        "ResourceDevelopment" => MitreTactic::ResourceDevelopment,
        "InitialAccess" => MitreTactic::InitialAccess,
        "Execution" => MitreTactic::Execution,
        "Persistence" => MitreTactic::Persistence,
        "PrivilegeEscalation" => MitreTactic::PrivilegeEscalation,
        "DefenseEvasion" => MitreTactic::DefenseEvasion,
        "CredentialAccess" => MitreTactic::CredentialAccess,
        "Discovery" => MitreTactic::Discovery,
        "LateralMovement" => MitreTactic::LateralMovement,
        "Collection" => MitreTactic::Collection,
        "CommandAndControl" => MitreTactic::CommandAndControl,
        "Exfiltration" => MitreTactic::Exfiltration,
        "Impact" => MitreTactic::Impact,
        _ => MitreTactic::Execution,
    })
}

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamDashboardStats {
    pub total_exercises: usize,
    pub running_exercises: usize,
    pub completed_exercises: usize,
    pub total_attacks_run: usize,
    pub detection_rate: f32,
    pub overall_coverage: f32,
    pub avg_time_to_detect_ms: i64,
    pub open_gaps: usize,
    pub critical_gaps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseSummary {
    pub id: String,
    pub name: String,
    pub status: ExerciseStatus,
    pub attacks_run: usize,
    pub detection_rate: f32,
    pub gaps_found: usize,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
