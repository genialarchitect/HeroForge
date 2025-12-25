//! Database operations for Google Dorking feature
//!
//! This module handles persistence of:
//! - Dork scan results
//! - Custom dork templates
//! - Scan history

use anyhow::Result;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::scanner::google_dorking::{DorkResult, DorkScanSummary};

// =============================================================================
// Data Types
// =============================================================================

/// Database row for dork scan
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DorkScanRow {
    pub id: String,
    pub user_id: String,
    pub domain: String,
    pub status: String,
    pub dork_count: i64,
    pub result_count: i64,
    pub summary: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Database row for individual dork result
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DorkResultRow {
    pub id: String,
    pub scan_id: String,
    pub template_id: String,
    pub query: String,
    pub results: String, // JSON array of SearchResult
    pub result_count: i64,
    pub status: String,
    pub error: Option<String>,
    pub provider: String,
    pub executed_at: String,
    pub duration_ms: i64,
}

/// Database row for custom dork template
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CustomTemplateRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub category: String,
    pub query_template: String,
    pub description: Option<String>,
    pub risk_level: Option<String>,
    pub tags: Option<String>,
    pub created_at: String,
}

// =============================================================================
// Dork Scan Operations
// =============================================================================

/// Create a new dork scan record
pub async fn create_dork_scan(
    pool: &SqlitePool,
    user_id: &str,
    domain: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO google_dork_scans (id, user_id, domain, status, dork_count, result_count, created_at)
        VALUES (?, ?, ?, 'pending', 0, 0, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(domain)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update dork scan status
pub async fn update_dork_scan_status(
    pool: &SqlitePool,
    scan_id: &str,
    status: &str,
) -> Result<()> {
    sqlx::query("UPDATE google_dork_scans SET status = ? WHERE id = ?")
        .bind(status)
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Save individual dork result
pub async fn save_dork_result(
    pool: &SqlitePool,
    scan_id: &str,
    result: &DorkResult,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let results_json = serde_json::to_string(&result.results)?;

    sqlx::query(
        r#"
        INSERT INTO google_dork_results
        (id, scan_id, template_id, query, results, result_count, status, error, provider, executed_at, duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(&result.template_id)
    .bind(&result.query)
    .bind(&results_json)
    .bind(result.result_count as i64)
    .bind(format!("{:?}", result.status).to_lowercase())
    .bind(&result.error)
    .bind(&result.provider)
    .bind(result.executed_at.to_rfc3339())
    .bind(result.duration_ms as i64)
    .execute(pool)
    .await?;

    // Update scan counters
    sqlx::query(
        r#"
        UPDATE google_dork_scans
        SET dork_count = dork_count + 1,
            result_count = result_count + ?
        WHERE id = ?
        "#,
    )
    .bind(result.result_count as i64)
    .bind(scan_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Complete dork scan with summary
pub async fn complete_dork_scan(
    pool: &SqlitePool,
    scan_id: &str,
    summary: &DorkScanSummary,
) -> Result<()> {
    let summary_json = serde_json::to_string(summary)?;
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE google_dork_scans
        SET status = 'completed',
            summary = ?,
            completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&summary_json)
    .bind(&now)
    .bind(scan_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get dork scan by ID
pub async fn get_dork_scan_by_id(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Option<DorkScanRow>> {
    let scan = sqlx::query_as::<_, DorkScanRow>(
        "SELECT id, user_id, domain, status, dork_count, result_count, summary, created_at, completed_at
         FROM google_dork_scans WHERE id = ?",
    )
    .bind(scan_id)
    .fetch_optional(pool)
    .await?;

    Ok(scan)
}

/// Get dork results for a scan
pub async fn get_dork_results(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<DorkResult>> {
    let rows = sqlx::query_as::<_, DorkResultRow>(
        "SELECT id, scan_id, template_id, query, results, result_count, status, error, provider, executed_at, duration_ms
         FROM google_dork_results WHERE scan_id = ? ORDER BY executed_at",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    let results: Vec<DorkResult> = rows
        .into_iter()
        .map(|row| {
            let search_results = serde_json::from_str(&row.results).unwrap_or_default();
            let status = match row.status.as_str() {
                "success" => crate::scanner::google_dorking::DorkStatus::Success,
                "rate_limited" => crate::scanner::google_dorking::DorkStatus::RateLimited,
                "provider_error" => crate::scanner::google_dorking::DorkStatus::ProviderError,
                "network_error" => crate::scanner::google_dorking::DorkStatus::NetworkError,
                "manual_required" => crate::scanner::google_dorking::DorkStatus::ManualRequired,
                _ => crate::scanner::google_dorking::DorkStatus::Success,
            };

            DorkResult {
                template_id: row.template_id,
                query: row.query,
                domain: String::new(), // Not stored per-result, part of scan
                results: search_results,
                result_count: row.result_count as usize,
                executed_at: chrono::DateTime::parse_from_rfc3339(&row.executed_at)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                duration_ms: row.duration_ms as u64,
                status,
                error: row.error,
                provider: row.provider,
            }
        })
        .collect();

    Ok(results)
}

/// Get user's dork scans
pub async fn get_user_dork_scans(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<DorkScanRow>> {
    let scans = sqlx::query_as::<_, DorkScanRow>(
        "SELECT id, user_id, domain, status, dork_count, result_count, summary, created_at, completed_at
         FROM google_dork_scans
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Delete dork scan and its results
pub async fn delete_dork_scan(pool: &SqlitePool, scan_id: &str) -> Result<()> {
    // Delete results first (foreign key)
    sqlx::query("DELETE FROM google_dork_results WHERE scan_id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    // Delete scan
    sqlx::query("DELETE FROM google_dork_scans WHERE id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}

// =============================================================================
// Custom Template Operations
// =============================================================================

/// Create a custom dork template
pub async fn create_custom_template(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    category: &str,
    query_template: &str,
    description: &str,
    risk_level: &str,
    tags: &[String],
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let tags_json = serde_json::to_string(tags)?;

    sqlx::query(
        r#"
        INSERT INTO custom_dork_templates
        (id, user_id, name, category, query_template, description, risk_level, tags, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(category)
    .bind(query_template)
    .bind(description)
    .bind(risk_level)
    .bind(&tags_json)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get user's custom templates
pub async fn get_user_custom_templates(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<CustomTemplateRow>> {
    let templates = sqlx::query_as::<_, CustomTemplateRow>(
        "SELECT id, user_id, name, category, query_template, description, risk_level, tags, created_at
         FROM custom_dork_templates
         WHERE user_id = ?
         ORDER BY name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get custom template by ID
pub async fn get_custom_template_by_id(
    pool: &SqlitePool,
    template_id: &str,
) -> Result<Option<CustomTemplateRow>> {
    let template = sqlx::query_as::<_, CustomTemplateRow>(
        "SELECT id, user_id, name, category, query_template, description, risk_level, tags, created_at
         FROM custom_dork_templates
         WHERE id = ?",
    )
    .bind(template_id)
    .fetch_optional(pool)
    .await?;

    Ok(template)
}

/// Delete custom template
pub async fn delete_custom_template(pool: &SqlitePool, template_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM custom_dork_templates WHERE id = ?")
        .bind(template_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Update custom template
pub async fn update_custom_template(
    pool: &SqlitePool,
    template_id: &str,
    name: &str,
    category: &str,
    query_template: &str,
    description: &str,
    risk_level: &str,
    tags: &[String],
) -> Result<()> {
    let tags_json = serde_json::to_string(tags)?;

    sqlx::query(
        r#"
        UPDATE custom_dork_templates
        SET name = ?, category = ?, query_template = ?, description = ?, risk_level = ?, tags = ?
        WHERE id = ?
        "#,
    )
    .bind(name)
    .bind(category)
    .bind(query_template)
    .bind(description)
    .bind(risk_level)
    .bind(&tags_json)
    .bind(template_id)
    .execute(pool)
    .await?;

    Ok(())
}
