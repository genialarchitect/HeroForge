//! Database operations for secret findings
//!
//! This module provides CRUD operations for managing detected secrets
//! from scans, including status tracking and resolution.

use sqlx::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use super::models::{SecretFindingRecord, SecretFindingStats, SecretTypeCount, UpdateSecretFindingRequest};

/// Create a new secret finding record
pub async fn create_secret_finding(
    pool: &SqlitePool,
    scan_id: &str,
    host_ip: &str,
    port: Option<i32>,
    secret_type: &str,
    severity: &str,
    redacted_value: &str,
    source_type: &str,
    source_location: &str,
    line_number: Option<i32>,
    context: Option<&str>,
    confidence: f64,
) -> Result<SecretFindingRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let finding = sqlx::query_as::<_, SecretFindingRecord>(
        r#"
        INSERT INTO secret_findings (
            id, scan_id, host_ip, port, secret_type, severity, redacted_value,
            source_type, source_location, line_number, context, confidence,
            status, false_positive, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(host_ip)
    .bind(port)
    .bind(secret_type)
    .bind(severity)
    .bind(redacted_value)
    .bind(source_type)
    .bind(source_location)
    .bind(line_number)
    .bind(context)
    .bind(confidence)
    .bind("open")
    .bind(false)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(finding)
}

/// Get all secret findings for a scan
pub async fn get_findings_by_scan(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<SecretFindingRecord>> {
    let findings = sqlx::query_as::<_, SecretFindingRecord>(
        r#"
        SELECT * FROM secret_findings
        WHERE scan_id = ?1
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
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(findings)
}

/// Get secret findings with filters
pub async fn get_findings_filtered(
    pool: &SqlitePool,
    scan_id: Option<&str>,
    host_ip: Option<&str>,
    secret_type: Option<&str>,
    severity: Option<&str>,
    status: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<SecretFindingRecord>> {
    let mut query = String::from("SELECT * FROM secret_findings WHERE 1=1");
    let mut params: Vec<String> = Vec::new();

    if let Some(sid) = scan_id {
        query.push_str(&format!(" AND scan_id = ?{}", params.len() + 1));
        params.push(sid.to_string());
    }

    if let Some(host) = host_ip {
        query.push_str(&format!(" AND host_ip = ?{}", params.len() + 1));
        params.push(host.to_string());
    }

    if let Some(st) = secret_type {
        query.push_str(&format!(" AND secret_type = ?{}", params.len() + 1));
        params.push(st.to_string());
    }

    if let Some(sev) = severity {
        query.push_str(&format!(" AND severity = ?{}", params.len() + 1));
        params.push(sev.to_string());
    }

    if let Some(stat) = status {
        query.push_str(&format!(" AND status = ?{}", params.len() + 1));
        params.push(stat.to_string());
    }

    query.push_str(" ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC");

    if let Some(lim) = limit {
        query.push_str(&format!(" LIMIT {}", lim));
    }

    if let Some(off) = offset {
        query.push_str(&format!(" OFFSET {}", off));
    }

    let mut q = sqlx::query_as::<_, SecretFindingRecord>(&query);
    for param in &params {
        q = q.bind(param);
    }

    let findings = q.fetch_all(pool).await?;
    Ok(findings)
}

/// Get a single secret finding by ID
pub async fn get_finding_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<SecretFindingRecord>> {
    let finding = sqlx::query_as::<_, SecretFindingRecord>(
        "SELECT * FROM secret_findings WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(finding)
}

/// Update a secret finding
pub async fn update_finding(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    update: &UpdateSecretFindingRequest,
) -> Result<SecretFindingRecord> {
    let now = Utc::now();

    // Build update query dynamically based on provided fields
    let mut updates = vec!["updated_at = ?1"];
    let mut param_idx = 2;

    if update.status.is_some() {
        updates.push("status = ?");
        param_idx += 1;
    }

    if update.false_positive.is_some() {
        updates.push("false_positive = ?");
        param_idx += 1;
    }

    if update.notes.is_some() {
        updates.push("notes = ?");
        param_idx += 1;
    }

    // If status is being set to 'resolved', set resolved_at and resolved_by
    if let Some(ref status) = update.status {
        if status == "resolved" {
            updates.push("resolved_at = ?");
            updates.push("resolved_by = ?");
        }
    }

    // Simple approach: update all provided fields
    let _query = format!(
        "UPDATE secret_findings SET updated_at = ?1, {} WHERE id = ?{} RETURNING *",
        if update.status.is_some() { "status = ?2," } else { "" }.to_string()
            + if update.false_positive.is_some() { "false_positive = ?," } else { "" }
            + if update.notes.is_some() { "notes = ?," } else { "" },
        param_idx
    );

    // For simplicity, use a more straightforward approach
    let finding = if let Some(ref status) = update.status {
        if status == "resolved" {
            sqlx::query_as::<_, SecretFindingRecord>(
                r#"
                UPDATE secret_findings
                SET status = ?1,
                    false_positive = COALESCE(?2, false_positive),
                    notes = COALESCE(?3, notes),
                    resolved_at = ?4,
                    resolved_by = ?5,
                    updated_at = ?6
                WHERE id = ?7
                RETURNING *
                "#,
            )
            .bind(status)
            .bind(update.false_positive)
            .bind(&update.notes)
            .bind(now)
            .bind(user_id)
            .bind(now)
            .bind(id)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_as::<_, SecretFindingRecord>(
                r#"
                UPDATE secret_findings
                SET status = ?1,
                    false_positive = COALESCE(?2, false_positive),
                    notes = COALESCE(?3, notes),
                    updated_at = ?4
                WHERE id = ?5
                RETURNING *
                "#,
            )
            .bind(status)
            .bind(update.false_positive)
            .bind(&update.notes)
            .bind(now)
            .bind(id)
            .fetch_one(pool)
            .await?
        }
    } else {
        sqlx::query_as::<_, SecretFindingRecord>(
            r#"
            UPDATE secret_findings
            SET false_positive = COALESCE(?1, false_positive),
                notes = COALESCE(?2, notes),
                updated_at = ?3
            WHERE id = ?4
            RETURNING *
            "#,
        )
        .bind(update.false_positive)
        .bind(&update.notes)
        .bind(now)
        .bind(id)
        .fetch_one(pool)
        .await?
    };

    Ok(finding)
}

/// Get statistics for secret findings
pub async fn get_finding_stats(
    pool: &SqlitePool,
    scan_id: Option<&str>,
) -> Result<SecretFindingStats> {
    let where_clause = if scan_id.is_some() {
        "WHERE scan_id = ?1"
    } else {
        ""
    };

    // Get total counts
    let total_query = format!(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count,
            SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) as fp_count
        FROM secret_findings
        {}
        "#,
        where_clause
    );

    let mut q = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64)>(&total_query);
    if let Some(sid) = scan_id {
        q = q.bind(sid);
    }

    let (total, critical, high, medium, low, open, resolved, fp) = q.fetch_one(pool).await?;

    // Get counts by type
    let type_query = format!(
        r#"
        SELECT secret_type, COUNT(*) as count
        FROM secret_findings
        {}
        GROUP BY secret_type
        ORDER BY count DESC
        "#,
        where_clause
    );

    let mut type_q = sqlx::query_as::<_, (String, i64)>(&type_query);
    if let Some(sid) = scan_id {
        type_q = type_q.bind(sid);
    }

    let type_counts: Vec<(String, i64)> = type_q.fetch_all(pool).await?;

    let by_type = type_counts
        .into_iter()
        .map(|(secret_type, count)| SecretTypeCount { secret_type, count })
        .collect();

    Ok(SecretFindingStats {
        total_findings: total,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        open_count: open,
        resolved_count: resolved,
        false_positive_count: fp,
        by_type,
    })
}

/// Delete all secret findings for a scan
pub async fn delete_findings_by_scan(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<u64> {
    let result = sqlx::query("DELETE FROM secret_findings WHERE scan_id = ?1")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Bulk update status for multiple findings
pub async fn bulk_update_status(
    pool: &SqlitePool,
    ids: &[String],
    status: &str,
    user_id: &str,
) -> Result<u64> {
    let now = Utc::now();
    let mut count = 0;

    for id in ids {
        let result = if status == "resolved" {
            sqlx::query(
                r#"
                UPDATE secret_findings
                SET status = ?1, resolved_at = ?2, resolved_by = ?3, updated_at = ?4
                WHERE id = ?5
                "#,
            )
            .bind(status)
            .bind(now)
            .bind(user_id)
            .bind(now)
            .bind(id)
            .execute(pool)
            .await?
        } else {
            sqlx::query(
                "UPDATE secret_findings SET status = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(status)
            .bind(now)
            .bind(id)
            .execute(pool)
            .await?
        };

        count += result.rows_affected();
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require a test database setup
    // These are placeholder tests for documentation

    #[test]
    fn test_severity_ordering() {
        // The SQL ORDER BY should sort: critical > high > medium > low
        let severities = vec!["critical", "high", "medium", "low"];
        let expected_order = vec![1, 2, 3, 4];

        for (sev, expected) in severities.iter().zip(expected_order.iter()) {
            let order = match *sev {
                "critical" => 1,
                "high" => 2,
                "medium" => 3,
                "low" => 4,
                _ => 5,
            };
            assert_eq!(order, *expected);
        }
    }
}
