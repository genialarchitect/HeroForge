//! Playbook analytics and metrics tracking
//!
//! Provides analytics capabilities for SOAR playbooks including:
//! - Execution statistics (count, success rate, average duration)
//! - Failure analysis
//! - Trend analysis over time
//! - Top playbooks by usage

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;

/// Overall statistics for a single playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStats {
    pub playbook_id: String,
    pub playbook_name: String,
    pub total_executions: i64,
    pub successful_executions: i64,
    pub failed_executions: i64,
    pub waiting_approval_count: i64,
    pub cancelled_count: i64,
    pub success_rate: f64,
    pub average_duration_seconds: Option<f64>,
    pub min_duration_seconds: Option<i64>,
    pub max_duration_seconds: Option<i64>,
    pub last_execution_at: Option<DateTime<Utc>>,
    pub common_failure_reasons: Vec<FailureReason>,
}

/// Failure reason with count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureReason {
    pub reason: String,
    pub count: i64,
}

/// Time-series execution data for trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrend {
    pub date: String,
    pub total_executions: i64,
    pub successful_executions: i64,
    pub failed_executions: i64,
    pub average_duration_seconds: Option<f64>,
}

/// Top playbook by usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopPlaybook {
    pub playbook_id: String,
    pub playbook_name: String,
    pub execution_count: i64,
    pub success_rate: f64,
    pub average_duration_seconds: Option<f64>,
}

/// Playbook analytics service
pub struct PlaybookAnalytics {
    pool: SqlitePool,
}

impl PlaybookAnalytics {
    /// Create a new analytics service
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Get overall statistics for a specific playbook
    pub async fn get_playbook_stats(&self, playbook_id: &str) -> Result<PlaybookStats> {
        // Get basic counts and timing stats
        let stats_row = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_executions,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_executions,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_executions,
                SUM(CASE WHEN status = 'waiting_approval' THEN 1 ELSE 0 END) as waiting_approval_count,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) as cancelled_count,
                AVG(duration_seconds) as avg_duration,
                MIN(duration_seconds) as min_duration,
                MAX(duration_seconds) as max_duration,
                MAX(started_at) as last_execution_at
            FROM soar_playbook_runs
            WHERE playbook_id = ?
            "#,
        )
        .bind(playbook_id)
        .fetch_one(&self.pool)
        .await?;

        let total_executions: i64 = stats_row.get("total_executions");
        let successful_executions: i64 = stats_row.get("successful_executions");
        let failed_executions: i64 = stats_row.get("failed_executions");
        let waiting_approval_count: i64 = stats_row.get("waiting_approval_count");
        let cancelled_count: i64 = stats_row.get("cancelled_count");
        let avg_duration: Option<f64> = stats_row.get("avg_duration");
        let min_duration: Option<i64> = stats_row.get("min_duration");
        let max_duration: Option<i64> = stats_row.get("max_duration");
        let last_execution_str: Option<String> = stats_row.get("last_execution_at");

        let last_execution_at = last_execution_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)));

        // Calculate success rate
        let success_rate = if total_executions > 0 {
            (successful_executions as f64 / total_executions as f64) * 100.0
        } else {
            0.0
        };

        // Get playbook name
        let playbook_name = sqlx::query_scalar::<_, String>(
            "SELECT name FROM soar_playbooks WHERE id = ?"
        )
        .bind(playbook_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or_else(|_| "Unknown".to_string());

        // Get common failure reasons
        let failure_rows = sqlx::query(
            r#"
            SELECT error_message, COUNT(*) as count
            FROM soar_playbook_runs
            WHERE playbook_id = ? AND status = 'failed' AND error_message IS NOT NULL
            GROUP BY error_message
            ORDER BY count DESC
            LIMIT 10
            "#,
        )
        .bind(playbook_id)
        .fetch_all(&self.pool)
        .await?;

        let common_failure_reasons: Vec<FailureReason> = failure_rows
            .iter()
            .map(|row| FailureReason {
                reason: row.get::<String, _>("error_message"),
                count: row.get::<i64, _>("count"),
            })
            .collect();

        Ok(PlaybookStats {
            playbook_id: playbook_id.to_string(),
            playbook_name,
            total_executions,
            successful_executions,
            failed_executions,
            waiting_approval_count,
            cancelled_count,
            success_rate,
            average_duration_seconds: avg_duration,
            min_duration_seconds: min_duration,
            max_duration_seconds: max_duration,
            last_execution_at,
            common_failure_reasons,
        })
    }

    /// Get execution trends over time (daily aggregation)
    pub async fn get_execution_trends(
        &self,
        playbook_id: Option<&str>,
        days: i64,
    ) -> Result<Vec<ExecutionTrend>> {
        let cutoff = Utc::now() - chrono::Duration::days(days);

        let query = if let Some(id) = playbook_id {
            sqlx::query(
                r#"
                SELECT
                    DATE(started_at) as date,
                    COUNT(*) as total_executions,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_executions,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_executions,
                    AVG(duration_seconds) as avg_duration
                FROM soar_playbook_runs
                WHERE playbook_id = ? AND started_at >= ?
                GROUP BY DATE(started_at)
                ORDER BY date ASC
                "#,
            )
            .bind(id)
            .bind(cutoff.to_rfc3339())
        } else {
            sqlx::query(
                r#"
                SELECT
                    DATE(started_at) as date,
                    COUNT(*) as total_executions,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_executions,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_executions,
                    AVG(duration_seconds) as avg_duration
                FROM soar_playbook_runs
                WHERE started_at >= ?
                GROUP BY DATE(started_at)
                ORDER BY date ASC
                "#,
            )
            .bind(cutoff.to_rfc3339())
        };

        let rows = query.fetch_all(&self.pool).await?;

        let trends: Vec<ExecutionTrend> = rows
            .iter()
            .map(|row| ExecutionTrend {
                date: row.get::<String, _>("date"),
                total_executions: row.get::<i64, _>("total_executions"),
                successful_executions: row.get::<i64, _>("successful_executions"),
                failed_executions: row.get::<i64, _>("failed_executions"),
                average_duration_seconds: row.get::<Option<f64>, _>("avg_duration"),
            })
            .collect();

        Ok(trends)
    }

    /// Get top playbooks by execution count
    pub async fn get_top_playbooks(&self, limit: i64) -> Result<Vec<TopPlaybook>> {
        let rows = sqlx::query(
            r#"
            SELECT
                p.id as playbook_id,
                p.name as playbook_name,
                COUNT(r.id) as execution_count,
                CAST(SUM(CASE WHEN r.status = 'completed' THEN 1 ELSE 0 END) AS REAL) /
                    NULLIF(COUNT(r.id), 0) * 100 as success_rate,
                AVG(r.duration_seconds) as avg_duration
            FROM soar_playbooks p
            LEFT JOIN soar_playbook_runs r ON p.id = r.playbook_id
            GROUP BY p.id, p.name
            HAVING execution_count > 0
            ORDER BY execution_count DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let top_playbooks: Vec<TopPlaybook> = rows
            .iter()
            .map(|row| TopPlaybook {
                playbook_id: row.get::<String, _>("playbook_id"),
                playbook_name: row.get::<String, _>("playbook_name"),
                execution_count: row.get::<i64, _>("execution_count"),
                success_rate: row.get::<Option<f64>, _>("success_rate").unwrap_or(0.0),
                average_duration_seconds: row.get::<Option<f64>, _>("avg_duration"),
            })
            .collect();

        Ok(top_playbooks)
    }

    /// Get playbook execution count for a specific time period
    pub async fn get_execution_count(
        &self,
        playbook_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM soar_playbook_runs
            WHERE playbook_id = ?
              AND started_at >= ?
              AND started_at <= ?
            "#,
        )
        .bind(playbook_id)
        .bind(start_date.to_rfc3339())
        .bind(end_date.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Get most recent playbook runs
    pub async fn get_recent_runs(
        &self,
        playbook_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<PlaybookRunSummary>> {
        let query = if let Some(id) = playbook_id {
            sqlx::query(
                r#"
                SELECT
                    r.id,
                    r.playbook_id,
                    p.name as playbook_name,
                    r.trigger_type,
                    r.status,
                    r.started_at,
                    r.completed_at,
                    r.duration_seconds,
                    r.error_message
                FROM soar_playbook_runs r
                JOIN soar_playbooks p ON r.playbook_id = p.id
                WHERE r.playbook_id = ?
                ORDER BY r.started_at DESC
                LIMIT ?
                "#,
            )
            .bind(id)
            .bind(limit)
        } else {
            sqlx::query(
                r#"
                SELECT
                    r.id,
                    r.playbook_id,
                    p.name as playbook_name,
                    r.trigger_type,
                    r.status,
                    r.started_at,
                    r.completed_at,
                    r.duration_seconds,
                    r.error_message
                FROM soar_playbook_runs r
                JOIN soar_playbooks p ON r.playbook_id = p.id
                ORDER BY r.started_at DESC
                LIMIT ?
                "#,
            )
            .bind(limit)
        };

        let rows = query.fetch_all(&self.pool).await?;

        let runs: Vec<PlaybookRunSummary> = rows
            .iter()
            .map(|row| {
                let started_at_str: String = row.get("started_at");
                let started_at = DateTime::parse_from_rfc3339(&started_at_str)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc));

                let completed_at_str: Option<String> = row.get("completed_at");
                let completed_at = completed_at_str.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                });

                PlaybookRunSummary {
                    id: row.get("id"),
                    playbook_id: row.get("playbook_id"),
                    playbook_name: row.get("playbook_name"),
                    trigger_type: row.get("trigger_type"),
                    status: row.get("status"),
                    started_at,
                    completed_at,
                    duration_seconds: row.get("duration_seconds"),
                    error_message: row.get("error_message"),
                }
            })
            .collect();

        Ok(runs)
    }

    /// Get overall system-wide playbook statistics
    pub async fn get_system_stats(&self) -> Result<SystemStats> {
        let stats_row = sqlx::query(
            r#"
            SELECT
                COUNT(DISTINCT playbook_id) as total_playbooks,
                COUNT(*) as total_runs,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful_runs,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_runs,
                AVG(duration_seconds) as avg_duration
            FROM soar_playbook_runs
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let total_playbooks: i64 = stats_row.get("total_playbooks");
        let total_runs: i64 = stats_row.get("total_runs");
        let successful_runs: i64 = stats_row.get("successful_runs");
        let failed_runs: i64 = stats_row.get("failed_runs");
        let avg_duration: Option<f64> = stats_row.get("avg_duration");

        let success_rate = if total_runs > 0 {
            (successful_runs as f64 / total_runs as f64) * 100.0
        } else {
            0.0
        };

        Ok(SystemStats {
            total_playbooks,
            total_runs,
            successful_runs,
            failed_runs,
            success_rate,
            average_duration_seconds: avg_duration,
        })
    }
}

/// Summary of a playbook run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookRunSummary {
    pub id: String,
    pub playbook_id: String,
    pub playbook_name: String,
    pub trigger_type: String,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<i64>,
    pub error_message: Option<String>,
}

/// System-wide playbook statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub total_playbooks: i64,
    pub total_runs: i64,
    pub successful_runs: i64,
    pub failed_runs: i64,
    pub success_rate: f64,
    pub average_duration_seconds: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_success_rate_calculation() {
        // Success rate should be calculated correctly
        let total = 100;
        let successful = 85;
        let rate = (successful as f64 / total as f64) * 100.0;
        assert_eq!(rate, 85.0);
    }
}
