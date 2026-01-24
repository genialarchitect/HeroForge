//! Patch management analytics
//!
//! Provides real-time analytics computed from patch deployment data:
//! - Patch coverage across the fleet
//! - Mean Time To Patch (MTTP)
//! - Deployment success rates
//! - Rollback frequency tracking

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Serialize, Deserialize)]
pub struct PatchAnalytics {
    pub total_patches: i64,
    pub deployed_patches: i64,
    pub pending_patches: i64,
    pub failed_patches: i64,
    pub coverage_percentage: f64,
    pub mean_time_to_patch: f64,
    pub success_rate: f64,
    pub rollback_rate: f64,
}

/// Calculate comprehensive patch analytics from the database
pub async fn get_analytics(pool: &SqlitePool) -> Result<PatchAnalytics> {
    let total = get_total_patches(pool).await?;
    let deployed = get_deployed_patches(pool).await?;
    let pending = get_pending_patches(pool).await?;
    let failed = get_failed_patches(pool).await?;
    let coverage = get_patch_coverage(pool).await?;
    let mttp = calculate_mttp(pool).await?;
    let success_rate = get_patch_success_rate(pool).await?;
    let rollback_rate = get_rollback_frequency(pool).await?;

    Ok(PatchAnalytics {
        total_patches: total,
        deployed_patches: deployed,
        pending_patches: pending,
        failed_patches: failed,
        coverage_percentage: coverage,
        mean_time_to_patch: mttp,
        success_rate,
        rollback_rate,
    })
}

/// Calculate patch coverage percentage from deployment records
pub async fn get_patch_coverage(pool: &SqlitePool) -> Result<f64> {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status IN ('deployed', 'completed') THEN 1 ELSE 0 END) as deployed
         FROM patches"
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or((0, 0));

    if row.0 == 0 {
        return Ok(0.0);
    }

    Ok((row.1 as f64 / row.0 as f64) * 100.0)
}

/// Calculate Mean Time To Patch (in hours) from deployment timestamps
pub async fn calculate_mttp(pool: &SqlitePool) -> Result<f64> {
    // Calculate average time between patch creation and deployment completion
    let result: Option<(f64,)> = sqlx::query_as(
        "SELECT AVG(
            (julianday(d.completed_at) - julianday(p.created_at)) * 24
         ) as avg_hours
         FROM patch_deployments d
         JOIN patches p ON p.id = d.patch_id
         WHERE d.status = 'completed' AND d.completed_at IS NOT NULL"
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|r| r.0).unwrap_or(0.0))
}

/// Calculate patch deployment success rate
pub async fn get_patch_success_rate(pool: &SqlitePool) -> Result<f64> {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful
         FROM patch_deployments
         WHERE status IN ('completed', 'failed', 'rolled_back')"
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or((0, 0));

    if row.0 == 0 {
        return Ok(0.0);
    }

    Ok((row.1 as f64 / row.0 as f64) * 100.0)
}

/// Calculate rollback frequency as a percentage of deployments
pub async fn get_rollback_frequency(pool: &SqlitePool) -> Result<f64> {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT
            COUNT(*) as total,
            SUM(CASE WHEN rollback_triggered = 1 THEN 1 ELSE 0 END) as rolled_back
         FROM patch_deployments"
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or((0, 0));

    if row.0 == 0 {
        return Ok(0.0);
    }

    Ok((row.1 as f64 / row.0 as f64) * 100.0)
}

/// Get total number of tracked patches
async fn get_total_patches(pool: &SqlitePool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM patches")
        .fetch_optional(pool)
        .await?
        .unwrap_or((0,));
    Ok(row.0)
}

/// Get number of successfully deployed patches
async fn get_deployed_patches(pool: &SqlitePool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM patches WHERE status IN ('deployed', 'completed')"
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or((0,));
    Ok(row.0)
}

/// Get number of pending patches
async fn get_pending_patches(pool: &SqlitePool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM patches WHERE status = 'pending'"
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or((0,));
    Ok(row.0)
}

/// Get number of failed patch deployments
async fn get_failed_patches(pool: &SqlitePool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM patches WHERE status = 'failed'"
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or((0,));
    Ok(row.0)
}

/// Get patches by severity distribution
pub async fn get_severity_distribution(pool: &SqlitePool) -> Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT
            CASE
                WHEN cvss_score >= 9.0 THEN 'critical'
                WHEN cvss_score >= 7.0 THEN 'high'
                WHEN cvss_score >= 4.0 THEN 'medium'
                ELSE 'low'
            END as severity,
            COUNT(*) as count
         FROM patches
         WHERE cvss_score IS NOT NULL
         GROUP BY severity
         ORDER BY count DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Get patch deployment trend over time (last 30 days)
pub async fn get_deployment_trend(pool: &SqlitePool) -> Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT
            DATE(started_at) as day,
            COUNT(*) as count
         FROM patch_deployments
         WHERE started_at >= datetime('now', '-30 days')
         GROUP BY DATE(started_at)
         ORDER BY day"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}
