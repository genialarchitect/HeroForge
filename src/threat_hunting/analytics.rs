use anyhow::Result;
use sqlx::SqlitePool;

use super::types::{HuntAnalytics, HunterMetric};

/// Calculate hunt effectiveness metrics
#[allow(dead_code)]
pub async fn get_hunt_analytics(pool: &SqlitePool) -> Result<HuntAnalytics> {
    // Total hunts executed
    let total_hunts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_executions"
    )
    .fetch_one(pool)
    .await?;

    // Active hypotheses
    let active_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE status = 'active'"
    )
    .fetch_one(pool)
    .await?;

    // Validated hypotheses
    let validated_hypotheses: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hunt_hypotheses WHERE status = 'validated'"
    )
    .fetch_one(pool)
    .await?;

    // Total findings
    let total_findings: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(findings_count), 0) FROM hunt_executions"
    )
    .fetch_one(pool)
    .await?;

    // False positive rate
    let false_positives: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(false_positives), 0) FROM hunt_executions"
    )
    .fetch_one(pool)
    .await?;

    let total_results = total_findings + false_positives;
    let false_positive_rate = if total_results > 0 {
        false_positives as f64 / total_results as f64
    } else {
        0.0
    };

    // Average hunt duration (stub - would need execution time tracking)
    let average_hunt_duration_seconds = 0.0;

    // Top hunters (stub implementation)
    let top_hunters = Vec::new();

    Ok(HuntAnalytics {
        total_hunts,
        active_hypotheses,
        validated_hypotheses,
        total_findings,
        false_positive_rate,
        average_hunt_duration_seconds,
        top_hunters,
    })
}

/// Calculate ROI for a hunt campaign
#[allow(dead_code)]
pub async fn calculate_hunt_roi(
    pool: &SqlitePool,
    campaign_id: &str,
) -> Result<f64> {
    // Get findings for campaign
    let findings: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(findings_count), 0)
         FROM hunt_executions
         WHERE campaign_id = ?"
    )
    .bind(campaign_id)
    .fetch_one(pool)
    .await?;

    // Get false positives
    let false_positives: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(false_positives), 0)
         FROM hunt_executions
         WHERE campaign_id = ?"
    )
    .bind(campaign_id)
    .fetch_one(pool)
    .await?;

    // Simple ROI calculation: findings / (findings + false_positives)
    let total = findings + false_positives;
    if total > 0 {
        Ok(findings as f64 / total as f64)
    } else {
        Ok(0.0)
    }
}

/// Track hunter performance metrics
#[allow(dead_code)]
pub async fn get_hunter_metrics(pool: &SqlitePool, user_id: &str) -> Result<HunterMetric> {
    // Count hunts executed by this hunter
    let hunts_executed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM hunt_executions he
         JOIN hunt_hypotheses hh ON he.hypothesis_id = hh.id
         WHERE hh.created_by = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Count findings
    let findings_count: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(he.findings_count), 0)
         FROM hunt_executions he
         JOIN hunt_hypotheses hh ON he.hypothesis_id = hh.id
         WHERE hh.created_by = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Count validated hypotheses
    let validated_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
         FROM hunt_hypotheses
         WHERE created_by = ? AND status = 'validated'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(HunterMetric {
        user_id: user_id.to_string(),
        hunts_executed,
        findings_count,
        validated_count,
    })
}

/// Get top hunters by various metrics
#[allow(dead_code)]
pub async fn get_top_hunters(pool: &SqlitePool, limit: i64) -> Result<Vec<HunterMetric>> {
    let rows = sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT
            hh.created_by as user_id,
            COUNT(DISTINCT he.id) as hunts_executed,
            COALESCE(SUM(he.findings_count), 0) as findings_count,
            COUNT(DISTINCT CASE WHEN hh.status = 'validated' THEN hh.id END) as validated_count
         FROM hunt_hypotheses hh
         LEFT JOIN hunt_executions he ON he.hypothesis_id = hh.id
         WHERE hh.created_by IS NOT NULL
         GROUP BY hh.created_by
         ORDER BY findings_count DESC
         LIMIT ?"
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(user_id, hunts_executed, findings_count, validated_count)| HunterMetric {
            user_id,
            hunts_executed,
            findings_count,
            validated_count,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roi_calculation() {
        // Test simple ROI calculation
        let findings = 80;
        let false_positives = 20;
        let total = findings + false_positives;
        let roi = findings as f64 / total as f64;
        assert_eq!(roi, 0.8);
    }
}
