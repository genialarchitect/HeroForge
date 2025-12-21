//! Database operations for AI prioritization
//!
//! This module handles storage and retrieval of AI scoring data.

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;

use crate::ai::{
    AIFeedback, AIModelConfig, AIModelConfigRecord, AIPrioritizationResult,
    AIScoreRecord, AIVulnerabilityScore, PrioritizationSummary, ScoringWeights,
};

/// Store an AI score for a vulnerability
pub async fn store_ai_score(
    pool: &SqlitePool,
    scan_id: &str,
    score: &AIVulnerabilityScore,
) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let factor_scores = serde_json::to_string(&score.factor_scores)?;
    let estimated_effort = serde_json::to_string(&score.estimated_effort)?;

    sqlx::query(
        r#"
        INSERT INTO ai_scores (
            id, scan_id, vulnerability_id, effective_risk_score, risk_category,
            factor_scores, remediation_priority, estimated_effort, confidence, calculated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(scan_id, vulnerability_id) DO UPDATE SET
            effective_risk_score = ?4,
            risk_category = ?5,
            factor_scores = ?6,
            remediation_priority = ?7,
            estimated_effort = ?8,
            confidence = ?9,
            calculated_at = ?10
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(&score.vulnerability_id)
    .bind(score.effective_risk_score)
    .bind(score.risk_category.as_str())
    .bind(&factor_scores)
    .bind(score.remediation_priority as i32)
    .bind(&estimated_effort)
    .bind(score.confidence)
    .bind(&score.calculated_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get AI score for a specific vulnerability
pub async fn get_vulnerability_score(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Option<AIVulnerabilityScore>> {
    let record: Option<AIScoreRecord> = sqlx::query_as(
        r#"
        SELECT id, scan_id, vulnerability_id, effective_risk_score, risk_category,
               factor_scores, remediation_priority, estimated_effort, confidence, calculated_at
        FROM ai_scores
        WHERE vulnerability_id = ?1
        ORDER BY calculated_at DESC
        LIMIT 1
        "#,
    )
    .bind(vulnerability_id)
    .fetch_optional(pool)
    .await?;

    record.map(|r| record_to_score(r)).transpose()
}

/// Get all AI scores for a scan
pub async fn get_scores_for_scan(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<AIVulnerabilityScore>> {
    let records: Vec<AIScoreRecord> = sqlx::query_as(
        r#"
        SELECT id, scan_id, vulnerability_id, effective_risk_score, risk_category,
               factor_scores, remediation_priority, estimated_effort, confidence, calculated_at
        FROM ai_scores
        WHERE scan_id = ?1
        ORDER BY remediation_priority ASC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    records.into_iter().map(record_to_score).collect()
}

/// Store the complete prioritization result
pub async fn store_prioritization_result(
    pool: &SqlitePool,
    result: &AIPrioritizationResult,
) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let summary_json = serde_json::to_string(&result.summary)?;

    sqlx::query(
        r#"
        INSERT INTO ai_prioritization_results (
            id, scan_id, total_vulnerabilities, critical_count, high_count,
            medium_count, low_count, average_risk_score, highest_risk_score,
            summary_json, calculated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(scan_id) DO UPDATE SET
            total_vulnerabilities = ?3,
            critical_count = ?4,
            high_count = ?5,
            medium_count = ?6,
            low_count = ?7,
            average_risk_score = ?8,
            highest_risk_score = ?9,
            summary_json = ?10,
            calculated_at = ?11
        "#,
    )
    .bind(&id)
    .bind(&result.scan_id)
    .bind(result.summary.total_vulnerabilities as i64)
    .bind(result.summary.critical_count as i64)
    .bind(result.summary.high_count as i64)
    .bind(result.summary.medium_count as i64)
    .bind(result.summary.low_count as i64)
    .bind(result.summary.average_risk_score)
    .bind(result.summary.highest_risk_score)
    .bind(&summary_json)
    .bind(&result.calculated_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get the prioritization result for a scan
pub async fn get_prioritization_result(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<AIPrioritizationResult> {
    // Get summary
    let summary: Option<(i64, i64, i64, i64, i64, f64, f64, String, chrono::DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT total_vulnerabilities, critical_count, high_count, medium_count,
               low_count, average_risk_score, highest_risk_score, summary_json, calculated_at
        FROM ai_prioritization_results
        WHERE scan_id = ?1
        "#,
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    let (summary, calculated_at) = if let Some((total, crit, high, med, low, avg, highest, _, calc_at)) = summary {
        (
            PrioritizationSummary {
                total_vulnerabilities: total as usize,
                critical_count: crit as usize,
                high_count: high as usize,
                medium_count: med as usize,
                low_count: low as usize,
                average_risk_score: avg,
                highest_risk_score: highest,
            },
            calc_at,
        )
    } else {
        return Err(anyhow::anyhow!("No prioritization result found for scan: {}", scan_id));
    };

    // Get individual scores
    let scores = get_scores_for_scan(pool, scan_id).await?;

    Ok(AIPrioritizationResult {
        scan_id: scan_id.to_string(),
        scores,
        summary,
        calculated_at,
    })
}

/// Store feedback for learning
pub async fn store_feedback(pool: &SqlitePool, feedback: &AIFeedback) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO ai_feedback (
            id, vulnerability_id, user_id, priority_appropriate, priority_adjustment,
            effort_accurate, actual_effort_hours, notes, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(&feedback.vulnerability_id)
    .bind(&feedback.user_id)
    .bind(feedback.priority_appropriate)
    .bind(feedback.priority_adjustment as i32)
    .bind(feedback.effort_accurate)
    .bind(feedback.actual_effort_hours.map(|h| h as i32))
    .bind(&feedback.notes)
    .bind(&feedback.created_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get average remediation time by severity
pub async fn get_avg_remediation_time(pool: &SqlitePool, severity: &str) -> Result<Option<f64>> {
    let result: Option<(Option<f64>,)> = sqlx::query_as(
        r#"
        SELECT AVG(
            CAST((julianday(COALESCE(resolved_at, datetime('now'))) - julianday(created_at)) AS REAL)
        ) as avg_days
        FROM vulnerability_tracking
        WHERE severity = ?1 AND status = 'resolved'
        "#,
    )
    .bind(severity)
    .fetch_optional(pool)
    .await?;

    Ok(result.and_then(|(avg,)| avg))
}

/// Get model configuration from database
pub async fn get_model_config(pool: &SqlitePool) -> Result<Option<AIModelConfig>> {
    let record: Option<AIModelConfigRecord> = sqlx::query_as(
        r#"
        SELECT id, name, description, weights, is_active, created_at, updated_at
        FROM ai_model_config
        WHERE is_active = 1
        ORDER BY updated_at DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|r| r.into()))
}

/// Save model configuration to database
pub async fn save_model_config(pool: &SqlitePool, config: &AIModelConfig) -> Result<()> {
    let weights_json = serde_json::to_string(&config.weights)?;

    // Deactivate all other configs if this one is active
    if config.is_active {
        sqlx::query("UPDATE ai_model_config SET is_active = 0 WHERE id != ?1")
            .bind(&config.id)
            .execute(pool)
            .await?;
    }

    sqlx::query(
        r#"
        INSERT INTO ai_model_config (id, name, description, weights, is_active, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(id) DO UPDATE SET
            name = ?2,
            description = ?3,
            weights = ?4,
            is_active = ?5,
            updated_at = ?7
        "#,
    )
    .bind(&config.id)
    .bind(&config.name)
    .bind(&config.description)
    .bind(&weights_json)
    .bind(config.is_active)
    .bind(&config.created_at)
    .bind(&config.updated_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Convert database record to score
fn record_to_score(record: AIScoreRecord) -> Result<AIVulnerabilityScore> {
    use crate::ai::{FactorScore, RemediationEffort, RiskCategory};

    let factor_scores: Vec<FactorScore> = serde_json::from_str(&record.factor_scores)?;
    let estimated_effort: RemediationEffort = serde_json::from_str(&record.estimated_effort)?;
    let risk_category = match record.risk_category.as_str() {
        "critical" => RiskCategory::Critical,
        "high" => RiskCategory::High,
        "medium" => RiskCategory::Medium,
        _ => RiskCategory::Low,
    };

    Ok(AIVulnerabilityScore {
        vulnerability_id: record.vulnerability_id,
        effective_risk_score: record.effective_risk_score,
        risk_category,
        factor_scores,
        remediation_priority: record.remediation_priority as u32,
        estimated_effort,
        confidence: record.confidence,
        calculated_at: record.calculated_at,
    })
}

/// Check if prioritization exists for a scan
pub async fn has_prioritization_result(pool: &SqlitePool, scan_id: &str) -> Result<bool> {
    let result: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ai_prioritization_results WHERE scan_id = ?1",
    )
    .bind(scan_id)
    .fetch_one(pool)
    .await?;

    Ok(result.0 > 0)
}

/// Delete prioritization data for a scan
pub async fn delete_prioritization_for_scan(pool: &SqlitePool, scan_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM ai_scores WHERE scan_id = ?1")
        .bind(scan_id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM ai_prioritization_results WHERE scan_id = ?1")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}
