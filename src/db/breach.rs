//! Database operations for breach check history
//!
//! Provides CRUD operations for storing and retrieving breach check results.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::scanner::breach_detection::{BreachCheckResult, BreachSeverity};

/// Breach check history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachCheckHistoryEntry {
    pub id: String,
    pub user_id: String,
    pub check_type: String,
    pub target: String,
    pub breach_count: i64,
    pub exposure_count: i64,
    pub password_exposures: i64,
    pub has_critical: bool,
    pub has_high: bool,
    pub sources_checked: Vec<String>,
    pub errors: Vec<String>,
    pub cached: bool,
    pub created_at: DateTime<Utc>,
}

/// Save a breach check result to history
pub async fn save_breach_check_result(
    pool: &SqlitePool,
    user_id: &str,
    check_type: &str,
    target: &str,
    result: &BreachCheckResult,
    cached: bool,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let result_json = serde_json::to_string(result)?;
    let sources_checked_json = serde_json::to_string(&result.sources_checked)?;
    let errors_json = serde_json::to_string(&result.errors)?;

    let has_critical = result.breaches.iter().any(|b| b.severity == BreachSeverity::Critical);
    let has_high = result.breaches.iter().any(|b| b.severity == BreachSeverity::High);

    sqlx::query(
        r#"
        INSERT INTO breach_check_history (
            id, user_id, check_type, target, result_json,
            breach_count, exposure_count, password_exposures,
            has_critical, has_high, sources_checked, errors, cached, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(check_type)
    .bind(target)
    .bind(&result_json)
    .bind(result.stats.unique_breaches as i64)
    .bind(result.stats.total_exposures as i64)
    .bind(result.stats.password_exposures as i64)
    .bind(has_critical as i32)
    .bind(has_high as i32)
    .bind(&sources_checked_json)
    .bind(&errors_json)
    .bind(cached as i32)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get breach check history for a user
pub async fn get_breach_check_history(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<BreachCheckHistoryEntry>> {
    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let rows = sqlx::query_as::<_, (String, String, String, String, i64, i64, i64, i64, i64, String, String, i64, String)>(
        r#"
        SELECT id, user_id, check_type, target, breach_count, exposure_count,
               password_exposures, has_critical, has_high, sources_checked,
               errors, cached, created_at
        FROM breach_check_history
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2 OFFSET ?3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    let entries = rows
        .into_iter()
        .map(|row| {
            let sources: Vec<String> = serde_json::from_str(&row.9).unwrap_or_default();
            let errors: Vec<String> = serde_json::from_str(&row.10).unwrap_or_default();
            let created_at = DateTime::parse_from_rfc3339(&row.12)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            BreachCheckHistoryEntry {
                id: row.0,
                user_id: row.1,
                check_type: row.2,
                target: row.3,
                breach_count: row.4,
                exposure_count: row.5,
                password_exposures: row.6,
                has_critical: row.7 != 0,
                has_high: row.8 != 0,
                sources_checked: sources,
                errors,
                cached: row.11 != 0,
                created_at,
            }
        })
        .collect();

    Ok(entries)
}

/// Get a specific breach check result by ID
pub async fn get_breach_check_result(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<Option<BreachCheckResult>> {
    let row = sqlx::query_as::<_, (String,)>(
        "SELECT result_json FROM breach_check_history WHERE id = ?1 AND user_id = ?2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((json,)) => {
            let result: BreachCheckResult = serde_json::from_str(&json)?;
            Ok(Some(result))
        }
        None => Ok(None),
    }
}

/// Delete a breach check history entry
pub async fn delete_breach_check_entry(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM breach_check_history WHERE id = ?1 AND user_id = ?2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get breach check statistics for a user
#[derive(Debug, Serialize)]
pub struct BreachCheckStats {
    pub total_checks: i64,
    pub email_checks: i64,
    pub domain_checks: i64,
    pub password_checks: i64,
    pub total_breaches_found: i64,
    pub critical_findings: i64,
    pub high_findings: i64,
}

pub async fn get_breach_check_stats(pool: &SqlitePool, user_id: &str) -> Result<BreachCheckStats> {
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*) as total_checks,
            SUM(CASE WHEN check_type = 'email' THEN 1 ELSE 0 END) as email_checks,
            SUM(CASE WHEN check_type = 'domain' THEN 1 ELSE 0 END) as domain_checks,
            SUM(CASE WHEN check_type = 'password' THEN 1 ELSE 0 END) as password_checks,
            COALESCE(SUM(breach_count), 0) as total_breaches,
            SUM(has_critical) as critical_findings,
            SUM(has_high) as high_findings
        FROM breach_check_history
        WHERE user_id = ?1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(BreachCheckStats {
        total_checks: row.0,
        email_checks: row.1,
        domain_checks: row.2,
        password_checks: row.3,
        total_breaches_found: row.4,
        critical_findings: row.5,
        high_findings: row.6,
    })
}
