// Nuclei Scanner Database Models
// Database operations for Nuclei scans and results

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::scanner::nuclei::types::{
    NucleiConfig, NucleiResult, NucleiScan, NucleiScanStatus, NucleiSeverity,
};

/// Create a new Nuclei scan
pub async fn create_nuclei_scan(
    pool: &SqlitePool,
    user_id: &str,
    name: Option<&str>,
    targets: &[String],
    config: &NucleiConfig,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let targets_json = serde_json::to_string(targets)?;
    let config_json = serde_json::to_string(config)?;
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO nuclei_scans (id, user_id, name, targets, config, status, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(&targets_json)
    .bind(&config_json)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a Nuclei scan by ID
pub async fn get_nuclei_scan(pool: &SqlitePool, id: &str) -> Result<Option<NucleiScan>> {
    let row = sqlx::query_as::<_, NucleiScanRow>(
        r#"
        SELECT id, user_id, name, targets, config, status, results_count,
               critical_count, high_count, medium_count, low_count, info_count,
               error_message, created_at, started_at, completed_at
        FROM nuclei_scans
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_scan()?)),
        None => Ok(None),
    }
}

/// Get Nuclei scans for a user
pub async fn get_user_nuclei_scans(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<NucleiScan>> {
    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let rows = sqlx::query_as::<_, NucleiScanRow>(
        r#"
        SELECT id, user_id, name, targets, config, status, results_count,
               critical_count, high_count, medium_count, low_count, info_count,
               error_message, created_at, started_at, completed_at
        FROM nuclei_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_scan()).collect()
}

/// Update Nuclei scan status
pub async fn update_nuclei_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: NucleiScanStatus,
    error_message: Option<&str>,
) -> Result<()> {
    let status_str = status.to_string();
    let now = Utc::now().to_rfc3339();

    match status {
        NucleiScanStatus::Running => {
            sqlx::query(
                r#"
                UPDATE nuclei_scans
                SET status = ?, started_at = ?
                WHERE id = ?
                "#,
            )
            .bind(&status_str)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
        }
        NucleiScanStatus::Completed | NucleiScanStatus::Failed | NucleiScanStatus::Cancelled => {
            sqlx::query(
                r#"
                UPDATE nuclei_scans
                SET status = ?, completed_at = ?, error_message = ?
                WHERE id = ?
                "#,
            )
            .bind(&status_str)
            .bind(&now)
            .bind(error_message)
            .bind(id)
            .execute(pool)
            .await?;
        }
        _ => {
            sqlx::query(
                r#"
                UPDATE nuclei_scans
                SET status = ?, error_message = ?
                WHERE id = ?
                "#,
            )
            .bind(&status_str)
            .bind(error_message)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

/// Update Nuclei scan counts
pub async fn update_nuclei_scan_counts(
    pool: &SqlitePool,
    id: &str,
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    info: u32,
) -> Result<()> {
    let total = critical + high + medium + low + info;

    sqlx::query(
        r#"
        UPDATE nuclei_scans
        SET results_count = ?, critical_count = ?, high_count = ?,
            medium_count = ?, low_count = ?, info_count = ?
        WHERE id = ?
        "#,
    )
    .bind(total as i64)
    .bind(critical as i64)
    .bind(high as i64)
    .bind(medium as i64)
    .bind(low as i64)
    .bind(info as i64)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a Nuclei scan
pub async fn delete_nuclei_scan(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM nuclei_scans WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Save a Nuclei result
pub async fn save_nuclei_result(pool: &SqlitePool, scan_id: &str, result: &NucleiResult) -> Result<()> {
    let extracted_json = serde_json::to_string(&result.extracted_results)?;
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO nuclei_results (
            id, scan_id, template_id, template_name, severity, host, matched_at,
            check_type, extracted_results, request, response, curl_command,
            ip, matcher_name, cve_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&result.id)
    .bind(scan_id)
    .bind(&result.template_id)
    .bind(&result.template_name)
    .bind(result.severity.to_string())
    .bind(&result.host)
    .bind(&result.matched_at)
    .bind(&result.check_type)
    .bind(&extracted_json)
    .bind(&result.request)
    .bind(&result.response)
    .bind(&result.curl_command)
    .bind(&result.ip)
    .bind(&result.matcher_name)
    .bind(&result.cve_id)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Save multiple Nuclei results
pub async fn save_nuclei_results(pool: &SqlitePool, scan_id: &str, results: &[NucleiResult]) -> Result<()> {
    for result in results {
        save_nuclei_result(pool, scan_id, result).await?;
    }
    Ok(())
}

/// Get Nuclei results for a scan
pub async fn get_nuclei_results(
    pool: &SqlitePool,
    scan_id: &str,
    severity: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<NucleiResult>> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    let rows = if let Some(sev) = severity {
        sqlx::query_as::<_, NucleiResultRow>(
            r#"
            SELECT id, scan_id, template_id, template_name, severity, host, matched_at,
                   check_type, extracted_results, request, response, curl_command,
                   ip, matcher_name, cve_id, created_at
            FROM nuclei_results
            WHERE scan_id = ? AND severity = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(scan_id)
        .bind(sev)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, NucleiResultRow>(
            r#"
            SELECT id, scan_id, template_id, template_name, severity, host, matched_at,
                   check_type, extracted_results, request, response, curl_command,
                   ip, matcher_name, cve_id, created_at
            FROM nuclei_results
            WHERE scan_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(scan_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_result()).collect()
}

/// Get a single Nuclei result
pub async fn get_nuclei_result(pool: &SqlitePool, id: &str) -> Result<Option<NucleiResult>> {
    let row = sqlx::query_as::<_, NucleiResultRow>(
        r#"
        SELECT id, scan_id, template_id, template_name, severity, host, matched_at,
               check_type, extracted_results, request, response, curl_command,
               ip, matcher_name, cve_id, created_at
        FROM nuclei_results
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_result()?)),
        None => Ok(None),
    }
}

/// Count Nuclei scans for a user
pub async fn count_user_nuclei_scans(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nuclei_scans WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Get running Nuclei scans
pub async fn get_running_nuclei_scans(pool: &SqlitePool) -> Result<Vec<NucleiScan>> {
    let rows = sqlx::query_as::<_, NucleiScanRow>(
        r#"
        SELECT id, user_id, name, targets, config, status, results_count,
               critical_count, high_count, medium_count, low_count, info_count,
               error_message, created_at, started_at, completed_at
        FROM nuclei_scans
        WHERE status = 'running'
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_scan()).collect()
}

// Database row types for mapping

#[derive(sqlx::FromRow)]
struct NucleiScanRow {
    id: String,
    user_id: String,
    name: Option<String>,
    targets: String,
    config: String,
    status: String,
    results_count: i64,
    critical_count: i64,
    high_count: i64,
    medium_count: i64,
    low_count: i64,
    info_count: i64,
    error_message: Option<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl NucleiScanRow {
    fn into_scan(self) -> Result<NucleiScan> {
        let targets: Vec<String> = serde_json::from_str(&self.targets)?;
        let config: NucleiConfig = serde_json::from_str(&self.config)?;
        let status = match self.status.as_str() {
            "running" => NucleiScanStatus::Running,
            "completed" => NucleiScanStatus::Completed,
            "failed" => NucleiScanStatus::Failed,
            "cancelled" => NucleiScanStatus::Cancelled,
            _ => NucleiScanStatus::Pending,
        };

        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let started_at = self.started_at.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        let completed_at = self.completed_at.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        Ok(NucleiScan {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            targets,
            config,
            status,
            results_count: self.results_count as u32,
            critical_count: self.critical_count as u32,
            high_count: self.high_count as u32,
            medium_count: self.medium_count as u32,
            low_count: self.low_count as u32,
            info_count: self.info_count as u32,
            error_message: self.error_message,
            created_at,
            started_at,
            completed_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct NucleiResultRow {
    id: String,
    #[allow(dead_code)]
    scan_id: String,
    template_id: String,
    template_name: String,
    severity: String,
    host: String,
    matched_at: Option<String>,
    check_type: String,
    extracted_results: Option<String>,
    request: Option<String>,
    response: Option<String>,
    curl_command: Option<String>,
    ip: Option<String>,
    matcher_name: Option<String>,
    cve_id: Option<String>,
    created_at: String,
}

impl NucleiResultRow {
    fn into_result(self) -> Result<NucleiResult> {
        let severity = NucleiSeverity::from(self.severity.as_str());
        let extracted_results: Vec<String> = self
            .extracted_results
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let timestamp = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(NucleiResult {
            id: self.id,
            template_id: self.template_id,
            template_name: self.template_name,
            severity,
            host: self.host,
            matched_at: self.matched_at.unwrap_or_default(),
            check_type: self.check_type,
            extracted_results,
            request: self.request,
            response: self.response,
            curl_command: self.curl_command,
            ip: self.ip,
            matcher_name: self.matcher_name,
            cve_id: self.cve_id,
            timestamp,
        })
    }
}
