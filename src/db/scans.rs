//! Scan-related database operations
//! Includes scans, reports, templates, target groups, and scheduled scans

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::models;

// ============================================================================
// Scan Operations
// ============================================================================

pub async fn create_scan(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    targets: &[String],
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<models::ScanResult> {
    create_scan_with_org(pool, user_id, name, targets, customer_id, engagement_id, None).await
}

/// Create a scan with organization context for multi-tenant isolation
pub async fn create_scan_with_org(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    targets: &[String],
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
    organization_id: Option<&str>,
) -> Result<models::ScanResult> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let targets_str = serde_json::to_string(targets)?;

    let scan = sqlx::query_as::<_, models::ScanResult>(
        r#"
        INSERT INTO scan_results (id, user_id, name, targets, status, created_at, customer_id, engagement_id, organization_id)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(&targets_str)
    .bind("pending")
    .bind(now)
    .bind(customer_id)
    .bind(engagement_id)
    .bind(organization_id)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

pub async fn get_user_scans(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::ScanResult>> {
    get_user_scans_with_org(pool, user_id, None).await
}

/// Get user scans filtered by organization for multi-tenant isolation
pub async fn get_user_scans_with_org(
    pool: &SqlitePool,
    user_id: &str,
    organization_id: Option<&str>,
) -> Result<Vec<models::ScanResult>> {
    let scans = match organization_id {
        Some(org_id) => {
            sqlx::query_as::<_, models::ScanResult>(
                "SELECT * FROM scan_results WHERE user_id = ?1 AND organization_id = ?2 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .bind(org_id)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, models::ScanResult>(
                "SELECT * FROM scan_results WHERE user_id = ?1 ORDER BY created_at DESC",
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?
        }
    };

    Ok(scans)
}

/// Get all scans for an organization (for org admins)
pub async fn get_org_scans(
    pool: &SqlitePool,
    organization_id: &str,
) -> Result<Vec<models::ScanResult>> {
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results WHERE organization_id = ?1 ORDER BY created_at DESC",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

pub async fn get_scan_by_id(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Option<models::ScanResult>> {
    let scan = sqlx::query_as::<_, models::ScanResult>("SELECT * FROM scan_results WHERE id = ?1")
        .bind(scan_id)
        .fetch_optional(pool)
        .await?;

    Ok(scan)
}

pub async fn update_scan_status(
    pool: &SqlitePool,
    scan_id: &str,
    status: &str,
    results: Option<&str>,
    error: Option<&str>,
) -> Result<()> {
    let now = chrono::Utc::now();

    if status == "running" {
        sqlx::query("UPDATE scan_results SET status = ?1, started_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(now)
            .bind(scan_id)
            .execute(pool)
            .await?;
    } else if status == "completed" {
        sqlx::query(
            "UPDATE scan_results SET status = ?1, results = ?2, completed_at = ?3 WHERE id = ?4",
        )
        .bind(status)
        .bind(results)
        .bind(now)
        .bind(scan_id)
        .execute(pool)
        .await?;
    } else if status == "failed" {
        sqlx::query(
            "UPDATE scan_results SET status = ?1, error_message = ?2, completed_at = ?3 WHERE id = ?4",
        )
        .bind(status)
        .bind(error)
        .bind(now)
        .bind(scan_id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub async fn get_all_scans(pool: &SqlitePool) -> Result<Vec<models::ScanResult>> {
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

pub async fn delete_scan_admin(pool: &SqlitePool, scan_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scan_results WHERE id = ?1")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete a scan (user-level, verifies ownership)
pub async fn delete_scan(pool: &SqlitePool, scan_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scan_results WHERE id = ?1 AND user_id = ?2")
        .bind(scan_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Report Management Functions
// ============================================================================

/// Create a new report record
pub async fn create_report(
    pool: &SqlitePool,
    user_id: &str,
    scan_id: &str,
    name: &str,
    description: Option<&str>,
    format: &str,
    template_id: &str,
    sections: &[String],
    metadata: Option<&str>,
) -> Result<models::Report> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let sections_json = serde_json::to_string(sections)?;

    let report = sqlx::query_as::<_, models::Report>(
        r#"
        INSERT INTO reports (id, user_id, scan_id, name, description, format, template_id, sections, status, metadata, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(scan_id)
    .bind(name)
    .bind(description)
    .bind(format)
    .bind(template_id)
    .bind(&sections_json)
    .bind("pending")
    .bind(metadata)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(report)
}

/// Get all reports for a user
pub async fn get_user_reports(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::Report>> {
    let reports = sqlx::query_as::<_, models::Report>(
        "SELECT * FROM reports WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

/// Get reports for a specific scan
pub async fn get_scan_reports(pool: &SqlitePool, scan_id: &str) -> Result<Vec<models::Report>> {
    let reports = sqlx::query_as::<_, models::Report>(
        "SELECT * FROM reports WHERE scan_id = ?1 ORDER BY created_at DESC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

/// Get a report by ID
pub async fn get_report_by_id(pool: &SqlitePool, report_id: &str) -> Result<Option<models::Report>> {
    let report = sqlx::query_as::<_, models::Report>("SELECT * FROM reports WHERE id = ?1")
        .bind(report_id)
        .fetch_optional(pool)
        .await?;

    Ok(report)
}

/// Update report status (generating, completed, failed)
pub async fn update_report_status(
    pool: &SqlitePool,
    report_id: &str,
    status: &str,
    file_path: Option<&str>,
    file_size: Option<i64>,
    error: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    match status {
        "generating" => {
            sqlx::query("UPDATE reports SET status = ?1 WHERE id = ?2")
                .bind(status)
                .bind(report_id)
                .execute(pool)
                .await?;
        }
        "completed" => {
            sqlx::query(
                "UPDATE reports SET status = ?1, file_path = ?2, file_size = ?3, completed_at = ?4 WHERE id = ?5",
            )
            .bind(status)
            .bind(file_path)
            .bind(file_size)
            .bind(now)
            .bind(report_id)
            .execute(pool)
            .await?;
        }
        "failed" => {
            sqlx::query(
                "UPDATE reports SET status = ?1, error_message = ?2, completed_at = ?3 WHERE id = ?4",
            )
            .bind(status)
            .bind(error)
            .bind(now)
            .bind(report_id)
            .execute(pool)
            .await?;
        }
        _ => {}
    }

    Ok(())
}

/// Delete a report
pub async fn delete_report(pool: &SqlitePool, report_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM reports WHERE id = ?1")
        .bind(report_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all reports (admin)
pub async fn get_all_reports(pool: &SqlitePool) -> Result<Vec<models::Report>> {
    let reports = sqlx::query_as::<_, models::Report>(
        "SELECT * FROM reports ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

// ============================================================================
// Scan Template Management Functions
// ============================================================================

/// Create a new scan template
pub async fn create_template(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateTemplateRequest,
) -> Result<models::ScanTemplate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let config_json = serde_json::to_string(&request.config)?;
    let category = request.category.as_ref()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "custom".to_string());

    let template = sqlx::query_as::<_, models::ScanTemplate>(
        r#"
        INSERT INTO scan_templates (id, user_id, name, description, config, is_default, is_system, category, estimated_duration_mins, use_count, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, 0, ?9, ?10)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&config_json)
    .bind(request.is_default)
    .bind(&category)
    .bind(request.estimated_duration_mins)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Get all templates for a user (including system templates)
pub async fn get_user_templates(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::ScanTemplate>> {
    let templates = sqlx::query_as::<_, models::ScanTemplate>(
        r#"
        SELECT * FROM scan_templates
        WHERE user_id = ?1 OR is_system = 1
        ORDER BY is_system DESC, is_default DESC, use_count DESC, created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get only user-created templates (excluding system templates)
pub async fn get_user_custom_templates(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::ScanTemplate>> {
    let templates = sqlx::query_as::<_, models::ScanTemplate>(
        r#"
        SELECT * FROM scan_templates
        WHERE user_id = ?1 AND is_system = 0
        ORDER BY is_default DESC, use_count DESC, created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get system templates only
pub async fn get_system_templates(pool: &SqlitePool) -> Result<Vec<models::ScanTemplate>> {
    let templates = sqlx::query_as::<_, models::ScanTemplate>(
        "SELECT * FROM scan_templates WHERE is_system = 1 ORDER BY category, name",
    )
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get templates by category
pub async fn get_templates_by_category(
    pool: &SqlitePool,
    user_id: &str,
    category: &str,
) -> Result<Vec<models::ScanTemplate>> {
    let templates = sqlx::query_as::<_, models::ScanTemplate>(
        r#"
        SELECT * FROM scan_templates
        WHERE (user_id = ?1 OR is_system = 1) AND category = ?2
        ORDER BY is_system DESC, is_default DESC, use_count DESC
        "#,
    )
    .bind(user_id)
    .bind(category)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get scan template categories with counts
pub async fn get_scan_template_categories(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::TemplateCategorySummary>> {
    let categories = sqlx::query_as::<_, (String, i32)>(
        r#"
        SELECT category, COUNT(*) as count
        FROM scan_templates
        WHERE user_id = ?1 OR is_system = 1
        GROUP BY category
        ORDER BY category
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(categories
        .into_iter()
        .map(|(category, count)| models::TemplateCategorySummary { category, count })
        .collect())
}

/// Get a template by ID
pub async fn get_template_by_id(pool: &SqlitePool, template_id: &str) -> Result<Option<models::ScanTemplate>> {
    let template = sqlx::query_as::<_, models::ScanTemplate>("SELECT * FROM scan_templates WHERE id = ?1")
        .bind(template_id)
        .fetch_optional(pool)
        .await?;

    Ok(template)
}

/// Get the default template for a user
pub async fn get_default_template(pool: &SqlitePool, user_id: &str) -> Result<Option<models::ScanTemplate>> {
    let template = sqlx::query_as::<_, models::ScanTemplate>(
        "SELECT * FROM scan_templates WHERE user_id = ?1 AND is_default = 1 LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(template)
}

/// Set a template as the default for a user (clears other defaults)
pub async fn set_default_template(pool: &SqlitePool, user_id: &str, template_id: &str) -> Result<models::ScanTemplate> {
    let now = Utc::now();

    // Clear existing default for this user
    sqlx::query("UPDATE scan_templates SET is_default = 0, updated_at = ?1 WHERE user_id = ?2 AND is_default = 1")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;

    // Set new default
    sqlx::query("UPDATE scan_templates SET is_default = 1, updated_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(template_id)
        .execute(pool)
        .await?;

    let template = sqlx::query_as::<_, models::ScanTemplate>("SELECT * FROM scan_templates WHERE id = ?1")
        .bind(template_id)
        .fetch_one(pool)
        .await?;

    Ok(template)
}

/// Increment use count and update last_used_at for a template
pub async fn increment_template_use_count(pool: &SqlitePool, template_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        "UPDATE scan_templates SET use_count = use_count + 1, last_used_at = ?1, updated_at = ?1 WHERE id = ?2"
    )
    .bind(now)
    .bind(template_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Clone a template for a user
pub async fn clone_template(
    pool: &SqlitePool,
    template_id: &str,
    user_id: &str,
    new_name: Option<String>,
) -> Result<models::ScanTemplate> {
    // Get the original template
    let original = sqlx::query_as::<_, models::ScanTemplate>("SELECT * FROM scan_templates WHERE id = ?1")
        .bind(template_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Template not found"))?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let name = new_name.unwrap_or_else(|| format!("{} (Copy)", original.name));

    let template = sqlx::query_as::<_, models::ScanTemplate>(
        r#"
        INSERT INTO scan_templates (id, user_id, name, description, config, is_default, is_system, category, estimated_duration_mins, use_count, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?7, 0, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&name)
    .bind(&original.description)
    .bind(&original.config)
    .bind(&original.category)
    .bind(original.estimated_duration_mins)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Update a template
pub async fn update_template(
    pool: &SqlitePool,
    template_id: &str,
    request: &models::UpdateTemplateRequest,
) -> Result<models::ScanTemplate> {
    let now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE scan_templates SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = &request.description {
        sqlx::query("UPDATE scan_templates SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(config) = &request.config {
        let config_json = serde_json::to_string(config)?;
        sqlx::query("UPDATE scan_templates SET config = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&config_json)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(is_default) = request.is_default {
        sqlx::query("UPDATE scan_templates SET is_default = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(is_default)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(category) = &request.category {
        sqlx::query("UPDATE scan_templates SET category = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(category.to_string())
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(estimated_duration_mins) = request.estimated_duration_mins {
        sqlx::query("UPDATE scan_templates SET estimated_duration_mins = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(estimated_duration_mins)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    let template = sqlx::query_as::<_, models::ScanTemplate>("SELECT * FROM scan_templates WHERE id = ?1")
        .bind(template_id)
        .fetch_one(pool)
        .await?;

    Ok(template)
}

/// Delete a template (only non-system templates)
pub async fn delete_template(pool: &SqlitePool, template_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scan_templates WHERE id = ?1 AND is_system = 0")
        .bind(template_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Target Group Management Functions
// ============================================================================

/// Create a new target group
pub async fn create_target_group(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateTargetGroupRequest,
) -> Result<models::TargetGroup> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let targets_json = serde_json::to_string(&request.targets)?;

    let group = sqlx::query_as::<_, models::TargetGroup>(
        r#"
        INSERT INTO target_groups (id, user_id, name, description, targets, color, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&targets_json)
    .bind(&request.color)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(group)
}

/// Get all target groups for a user
pub async fn get_user_target_groups(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::TargetGroup>> {
    let groups = sqlx::query_as::<_, models::TargetGroup>(
        "SELECT * FROM target_groups WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Get a target group by ID
pub async fn get_target_group_by_id(
    pool: &SqlitePool,
    group_id: &str,
) -> Result<Option<models::TargetGroup>> {
    let group = sqlx::query_as::<_, models::TargetGroup>(
        "SELECT * FROM target_groups WHERE id = ?1",
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// Update a target group
pub async fn update_target_group(
    pool: &SqlitePool,
    group_id: &str,
    request: &models::UpdateTargetGroupRequest,
) -> Result<models::TargetGroup> {
    let now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE target_groups SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = &request.description {
        sqlx::query("UPDATE target_groups SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(targets) = &request.targets {
        let targets_json = serde_json::to_string(targets)?;
        sqlx::query("UPDATE target_groups SET targets = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&targets_json)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(color) = &request.color {
        sqlx::query("UPDATE target_groups SET color = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(color)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    let group = sqlx::query_as::<_, models::TargetGroup>(
        "SELECT * FROM target_groups WHERE id = ?1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;

    Ok(group)
}

/// Delete a target group
pub async fn delete_target_group(pool: &SqlitePool, group_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM target_groups WHERE id = ?1")
        .bind(group_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Scheduled Scans Functions
// ============================================================================

/// Create a new scheduled scan
pub async fn create_scheduled_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateScheduledScanRequest,
) -> Result<models::ScheduledScan> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let config_json = serde_json::to_string(&request.config)?;
    let next_run_at = calculate_next_run(&request.schedule_type, &request.schedule_value)?;

    let scan = sqlx::query_as::<_, models::ScheduledScan>(
        r#"
        INSERT INTO scheduled_scans (id, user_id, name, description, config, schedule_type, schedule_value, next_run_at, is_active, run_count, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 0, ?9, ?10)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&config_json)
    .bind(&request.schedule_type)
    .bind(&request.schedule_value)
    .bind(next_run_at)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

/// Get all scheduled scans for a user
pub async fn get_user_scheduled_scans(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::ScheduledScan>> {
    let scans = sqlx::query_as::<_, models::ScheduledScan>(
        "SELECT * FROM scheduled_scans WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Get a scheduled scan by ID
pub async fn get_scheduled_scan_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<models::ScheduledScan>> {
    let scan = sqlx::query_as::<_, models::ScheduledScan>(
        "SELECT * FROM scheduled_scans WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(scan)
}

/// Update a scheduled scan
pub async fn update_scheduled_scan(
    pool: &SqlitePool,
    id: &str,
    request: &models::UpdateScheduledScanRequest,
) -> Result<models::ScheduledScan> {
    let now = Utc::now();

    // Fetch current scan to merge updates
    let current = get_scheduled_scan_by_id(pool, id).await?
        .ok_or_else(|| anyhow::anyhow!("Scheduled scan not found"))?;

    let name = request.name.as_ref().unwrap_or(&current.name);
    let description = request.description.clone().or(current.description);
    let config = request.config.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default())
        .unwrap_or(current.config);
    let schedule_type = request.schedule_type.as_ref().unwrap_or(&current.schedule_type);
    let schedule_value = request.schedule_value.as_ref().unwrap_or(&current.schedule_value);
    let is_active = request.is_active.unwrap_or(current.is_active);

    // Recalculate next_run_at if schedule changed
    let next_run_at = if request.schedule_type.is_some() || request.schedule_value.is_some() {
        calculate_next_run(schedule_type, schedule_value)?
    } else {
        current.next_run_at
    };

    let scan = sqlx::query_as::<_, models::ScheduledScan>(
        r#"
        UPDATE scheduled_scans
        SET name = ?1, description = ?2, config = ?3, schedule_type = ?4,
            schedule_value = ?5, is_active = ?6, next_run_at = ?7, updated_at = ?8
        WHERE id = ?9
        RETURNING *
        "#,
    )
    .bind(name)
    .bind(&description)
    .bind(&config)
    .bind(schedule_type)
    .bind(schedule_value)
    .bind(is_active)
    .bind(next_run_at)
    .bind(now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

/// Delete a scheduled scan
pub async fn delete_scheduled_scan(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scheduled_scans WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all scheduled scans that are due to run (next_run_at <= now and is_active = true)
pub async fn get_due_scheduled_scans(pool: &SqlitePool) -> Result<Vec<models::ScheduledScan>> {
    let now = Utc::now();
    let scans = sqlx::query_as::<_, models::ScheduledScan>(
        "SELECT * FROM scheduled_scans WHERE is_active = 1 AND next_run_at <= ?1 ORDER BY next_run_at ASC",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Update a scheduled scan after execution
pub async fn update_scheduled_scan_execution(
    pool: &SqlitePool,
    id: &str,
    scan_id: &str,
) -> Result<models::ScheduledScan> {
    // Get the current scheduled scan to calculate next run
    let current = get_scheduled_scan_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Scheduled scan not found"))?;

    let now = Utc::now();
    let next_run = calculate_next_run(&current.schedule_type, &current.schedule_value)?;
    let new_run_count = current.run_count + 1;

    let updated = sqlx::query_as::<_, models::ScheduledScan>(
        r#"
        UPDATE scheduled_scans
        SET last_run_at = ?1, last_scan_id = ?2, run_count = ?3, next_run_at = ?4, updated_at = ?5
        WHERE id = ?6
        RETURNING *
        "#,
    )
    .bind(now)
    .bind(scan_id)
    .bind(new_run_count)
    .bind(next_run)
    .bind(now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Helper function for schedule calculation
/// Supports: "daily", "weekly", "monthly", and "cron" schedule types
pub fn calculate_next_run(schedule_type: &str, schedule_value: &str) -> Result<DateTime<Utc>> {
    use chrono::{Duration, NaiveTime, Weekday, Datelike};

    let now = Utc::now();

    match schedule_type {
        "daily" => {
            // schedule_value format: "HH:MM" (e.g., "02:00")
            let time = NaiveTime::parse_from_str(schedule_value, "%H:%M")
                .map_err(|_| anyhow::anyhow!("Invalid time format, expected HH:MM"))?;
            let mut next = now.date_naive().and_time(time).and_utc();
            if next <= now {
                next = next + Duration::days(1);
            }
            Ok(next)
        }
        "weekly" => {
            // schedule_value format: "DAY HH:MM" (e.g., "monday 02:00")
            let parts: Vec<&str> = schedule_value.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid weekly format, expected 'DAY HH:MM'"));
            }
            let day_str = parts[0].to_lowercase();
            let time = NaiveTime::parse_from_str(parts[1], "%H:%M")
                .map_err(|_| anyhow::anyhow!("Invalid time format"))?;

            // Parse the target day of week
            let target_weekday = match day_str.as_str() {
                "monday" | "mon" => Weekday::Mon,
                "tuesday" | "tue" => Weekday::Tue,
                "wednesday" | "wed" => Weekday::Wed,
                "thursday" | "thu" => Weekday::Thu,
                "friday" | "fri" => Weekday::Fri,
                "saturday" | "sat" => Weekday::Sat,
                "sunday" | "sun" => Weekday::Sun,
                _ => return Err(anyhow::anyhow!("Invalid day of week: {}", day_str)),
            };

            // Calculate days until next occurrence
            let current_weekday = now.weekday();
            let days_until = (target_weekday.num_days_from_monday() as i64
                - current_weekday.num_days_from_monday() as i64 + 7) % 7;

            let mut next = now.date_naive().and_time(time).and_utc() + Duration::days(days_until);

            // If the calculated time is in the past (same day but earlier time), add 7 days
            if next <= now {
                next = next + Duration::days(7);
            }

            Ok(next)
        }
        "monthly" => {
            // schedule_value format: "DD HH:MM" (e.g., "01 02:00" for 1st of month)
            let parts: Vec<&str> = schedule_value.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid monthly format, expected 'DD HH:MM'"));
            }
            let day: u32 = parts[0].parse()
                .map_err(|_| anyhow::anyhow!("Invalid day of month: {}", parts[0]))?;
            if day < 1 || day > 31 {
                return Err(anyhow::anyhow!("Day of month must be between 1 and 31"));
            }
            let time = NaiveTime::parse_from_str(parts[1], "%H:%M")
                .map_err(|_| anyhow::anyhow!("Invalid time format"))?;

            // Try to create the date for this month
            let mut year = now.year();
            let mut month = now.month();

            // Try current month first
            if let Some(date) = chrono::NaiveDate::from_ymd_opt(year, month, day) {
                let next = date.and_time(time).and_utc();
                if next > now {
                    return Ok(next);
                }
            }

            // Move to next month
            month += 1;
            if month > 12 {
                month = 1;
                year += 1;
            }

            // Find the next valid date (handle months with fewer days)
            loop {
                if let Some(date) = chrono::NaiveDate::from_ymd_opt(year, month, day) {
                    return Ok(date.and_time(time).and_utc());
                }
                // Day doesn't exist in this month (e.g., Feb 30), try next month
                month += 1;
                if month > 12 {
                    month = 1;
                    year += 1;
                }
                // Safety check to prevent infinite loop
                if year > now.year() + 2 {
                    return Err(anyhow::anyhow!("Could not find valid date for day {}", day));
                }
            }
        }
        "cron" => {
            // schedule_value format: standard cron expression
            use cron::Schedule;
            use std::str::FromStr;

            let schedule = Schedule::from_str(schedule_value)
                .map_err(|e| anyhow::anyhow!("Invalid cron expression '{}': {}", schedule_value, e))?;

            // Get the next occurrence after now
            let next = schedule.upcoming(chrono::Utc)
                .next()
                .ok_or_else(|| anyhow::anyhow!("Could not calculate next run time from cron expression"))?;

            Ok(next)
        }
        _ => {
            // Unknown schedule type - log warning and default to 24 hours
            log::warn!(
                "Unknown schedule_type '{}', defaulting to 24 hours from now",
                schedule_type
            );
            Ok(now + Duration::days(1))
        }
    }
}

// ============================================================================
// Scheduled Scan Execution History Functions
// ============================================================================

/// Create a new execution history record
pub async fn create_execution_record(
    pool: &SqlitePool,
    scheduled_scan_id: &str,
    retry_attempt: i32,
) -> Result<models::ScheduledScanExecution> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let record = sqlx::query_as::<_, models::ScheduledScanExecution>(
        r#"
        INSERT INTO scheduled_scan_executions (id, scheduled_scan_id, started_at, status, retry_attempt)
        VALUES (?1, ?2, ?3, 'running', ?4)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(scheduled_scan_id)
    .bind(now)
    .bind(retry_attempt)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// Update an execution record when scan completes
pub async fn complete_execution_record(
    pool: &SqlitePool,
    execution_id: &str,
    scan_result_id: Option<&str>,
    status: &str,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE scheduled_scan_executions
        SET scan_result_id = ?1, completed_at = ?2, status = ?3, error_message = ?4
        WHERE id = ?5
        "#,
    )
    .bind(scan_result_id)
    .bind(now)
    .bind(status)
    .bind(error_message)
    .bind(execution_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get execution history for a scheduled scan (limited to last 50 entries)
pub async fn get_execution_history(
    pool: &SqlitePool,
    scheduled_scan_id: &str,
) -> Result<Vec<models::ScheduledScanExecution>> {
    let records = sqlx::query_as::<_, models::ScheduledScanExecution>(
        r#"
        SELECT * FROM scheduled_scan_executions
        WHERE scheduled_scan_id = ?1
        ORDER BY started_at DESC
        LIMIT 50
        "#,
    )
    .bind(scheduled_scan_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

/// Clean up old execution records (keep last 50 per scheduled scan)
pub async fn cleanup_old_executions(pool: &SqlitePool, scheduled_scan_id: &str) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM scheduled_scan_executions
        WHERE id IN (
            SELECT id FROM scheduled_scan_executions
            WHERE scheduled_scan_id = ?1
            ORDER BY started_at DESC
            LIMIT -1 OFFSET 50
        )
        "#,
    )
    .bind(scheduled_scan_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update scheduled scan retry count and error message
pub async fn update_scheduled_scan_retry(
    pool: &SqlitePool,
    id: &str,
    retry_count: i32,
    last_error: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE scheduled_scans
        SET retry_count = ?1, last_error = ?2, updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind(retry_count)
    .bind(last_error)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Reset retry count on successful execution
pub async fn reset_scheduled_scan_retry(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE scheduled_scans
        SET retry_count = 0, last_error = NULL, updated_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Scan Tags
// ============================================================================

/// Create a new scan tag
pub async fn create_scan_tag(
    pool: &SqlitePool,
    name: &str,
    color: &str,
) -> Result<models::ScanTag> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO scan_tags (id, name, color, created_at)
        VALUES (?1, ?2, ?3, ?4)
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(color)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(models::ScanTag {
        id,
        name: name.to_string(),
        color: color.to_string(),
        created_at: now,
    })
}

/// Get all scan tags
pub async fn get_all_scan_tags(pool: &SqlitePool) -> Result<Vec<models::ScanTag>> {
    let tags = sqlx::query_as::<_, models::ScanTag>(
        r#"
        SELECT id, name, color, created_at
        FROM scan_tags
        ORDER BY name ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(tags)
}

/// Get a scan tag by ID
pub async fn get_scan_tag_by_id(pool: &SqlitePool, tag_id: &str) -> Result<Option<models::ScanTag>> {
    let tag = sqlx::query_as::<_, models::ScanTag>(
        r#"
        SELECT id, name, color, created_at
        FROM scan_tags
        WHERE id = ?1
        "#,
    )
    .bind(tag_id)
    .fetch_optional(pool)
    .await?;

    Ok(tag)
}

/// Delete a scan tag (cascades to scan_tag_mappings)
pub async fn delete_scan_tag(pool: &SqlitePool, tag_id: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM scan_tags WHERE id = ?1
        "#,
    )
    .bind(tag_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Get tags for a specific scan
pub async fn get_scan_tags(pool: &SqlitePool, scan_id: &str) -> Result<Vec<models::ScanTag>> {
    let tags = sqlx::query_as::<_, models::ScanTag>(
        r#"
        SELECT t.id, t.name, t.color, t.created_at
        FROM scan_tags t
        INNER JOIN scan_tag_mappings m ON t.id = m.tag_id
        WHERE m.scan_id = ?1
        ORDER BY t.name ASC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(tags)
}

/// Add a tag to a scan
pub async fn add_tag_to_scan(pool: &SqlitePool, scan_id: &str, tag_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO scan_tag_mappings (scan_id, tag_id, created_at)
        VALUES (?1, ?2, ?3)
        "#,
    )
    .bind(scan_id)
    .bind(tag_id)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Add multiple tags to a scan
pub async fn add_tags_to_scan(pool: &SqlitePool, scan_id: &str, tag_ids: &[String]) -> Result<()> {
    let now = Utc::now();

    for tag_id in tag_ids {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO scan_tag_mappings (scan_id, tag_id, created_at)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(scan_id)
        .bind(tag_id)
        .bind(now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Remove a tag from a scan
pub async fn remove_tag_from_scan(pool: &SqlitePool, scan_id: &str, tag_id: &str) -> Result<bool> {
    let result = sqlx::query(
        r#"
        DELETE FROM scan_tag_mappings
        WHERE scan_id = ?1 AND tag_id = ?2
        "#,
    )
    .bind(scan_id)
    .bind(tag_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Get scans filtered by tag IDs
pub async fn get_scans_by_tags(
    pool: &SqlitePool,
    user_id: &str,
    tag_ids: &[String],
) -> Result<Vec<models::ScanResult>> {
    if tag_ids.is_empty() {
        return get_user_scans(pool, user_id).await;
    }

    // Build the query with placeholders for each tag ID
    let placeholders: Vec<String> = (0..tag_ids.len()).map(|i| format!("?{}", i + 2)).collect();
    let placeholders_str = placeholders.join(", ");

    let query = format!(
        r#"
        SELECT DISTINCT s.id, s.user_id, s.name, s.targets, s.status, s.results,
               s.created_at, s.started_at, s.completed_at, s.error_message,
               s.customer_id, s.engagement_id
        FROM scan_results s
        INNER JOIN scan_tag_mappings m ON s.id = m.scan_id
        WHERE s.user_id = ?1 AND m.tag_id IN ({})
        ORDER BY s.created_at DESC
        "#,
        placeholders_str
    );

    let mut query_builder = sqlx::query_as::<_, models::ScanResult>(&query).bind(user_id);

    for tag_id in tag_ids {
        query_builder = query_builder.bind(tag_id);
    }

    let scans = query_builder.fetch_all(pool).await?;
    Ok(scans)
}

/// Get all scans with their tags
pub async fn get_user_scans_with_tags(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::ScanWithTags>> {
    // First get all scans
    let scans = get_user_scans(pool, user_id).await?;

    // Then get tags for each scan
    let mut scans_with_tags = Vec::new();
    for scan in scans {
        let tags = get_scan_tags(pool, &scan.id).await?;
        scans_with_tags.push(models::ScanWithTags { scan, tags });
    }

    Ok(scans_with_tags)
}

// ============================================================================
// Duplicate Scan
// ============================================================================

/// Duplicate an existing scan configuration, creating a new pending scan
pub async fn duplicate_scan(
    pool: &SqlitePool,
    scan_id: &str,
    user_id: &str,
    new_name: Option<&str>,
) -> Result<models::ScanResult> {
    // Get the original scan
    let original = get_scan_by_id(pool, scan_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Scan not found"))?;

    // Generate new values
    let new_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let name = new_name.map(|n| n.to_string()).unwrap_or_else(|| {
        format!("{} (Copy)", original.name)
    });

    // Create the new scan with same config but pending status
    sqlx::query(
        r#"
        INSERT INTO scan_results (id, user_id, name, targets, status, results, created_at, customer_id, engagement_id)
        VALUES (?1, ?2, ?3, ?4, 'pending', NULL, ?5, ?6, ?7)
        "#,
    )
    .bind(&new_id)
    .bind(user_id)
    .bind(&name)
    .bind(&original.targets)
    .bind(now)
    .bind(&original.customer_id)
    .bind(&original.engagement_id)
    .execute(pool)
    .await?;

    // Copy tags from original scan
    let tags = get_scan_tags(pool, scan_id).await?;
    for tag in &tags {
        add_tag_to_scan(pool, &new_id, &tag.id).await?;
    }

    Ok(models::ScanResult {
        id: new_id,
        user_id: user_id.to_string(),
        name,
        targets: original.targets,
        status: "pending".to_string(),
        results: None,
        created_at: now,
        started_at: None,
        completed_at: None,
        error_message: None,
        customer_id: original.customer_id,
        engagement_id: original.engagement_id,
        organization_id: original.organization_id,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike, Weekday};

    #[test]
    fn test_calculate_next_run_daily() {
        let next = calculate_next_run("daily", "02:00").expect("Failed to calculate daily schedule");
        assert_eq!(next.hour(), 2);
        assert_eq!(next.minute(), 0);
        assert!(next > Utc::now());
    }

    #[test]
    fn test_calculate_next_run_daily_next_day() {
        let now = Utc::now();
        let test_time = format!("{:02}:{:02}", (now.hour() + 23) % 24, 0);
        let next = calculate_next_run("daily", &test_time).expect("Failed to calculate daily schedule");
        assert!(next > now);
    }

    #[test]
    fn test_calculate_next_run_weekly() {
        let next = calculate_next_run("weekly", "monday 02:00").expect("Failed to calculate weekly schedule");
        assert_eq!(next.hour(), 2);
        assert_eq!(next.minute(), 0);
        assert_eq!(next.weekday(), Weekday::Mon);
        assert!(next > Utc::now());
    }

    #[test]
    fn test_calculate_next_run_weekly_abbreviated() {
        let next = calculate_next_run("weekly", "fri 14:30").expect("Failed to calculate weekly schedule");
        assert_eq!(next.hour(), 14);
        assert_eq!(next.minute(), 30);
        assert_eq!(next.weekday(), Weekday::Fri);
        assert!(next > Utc::now());
    }

    #[test]
    fn test_calculate_next_run_monthly() {
        let next = calculate_next_run("monthly", "15 03:00").expect("Failed to calculate monthly schedule");
        assert_eq!(next.hour(), 3);
        assert_eq!(next.minute(), 0);
        assert_eq!(next.day(), 15);
        assert!(next > Utc::now());
    }

    #[test]
    fn test_calculate_next_run_cron() {
        let next = calculate_next_run("cron", "0 0 4 * * *").expect("Failed to calculate cron schedule");
        assert_eq!(next.hour(), 4);
        assert_eq!(next.minute(), 0);
        assert!(next > Utc::now());
    }

    #[test]
    fn test_calculate_next_run_cron_complex() {
        let next = calculate_next_run("cron", "0 30 2 * * Mon").expect("Failed to calculate cron schedule");
        assert_eq!(next.hour(), 2);
        assert_eq!(next.minute(), 30);
        assert_eq!(next.weekday(), Weekday::Mon);
        assert!(next > Utc::now());
    }

    #[test]
    fn test_calculate_next_run_invalid_daily() {
        let result = calculate_next_run("daily", "invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_next_run_invalid_weekly() {
        let result = calculate_next_run("weekly", "02:00");
        assert!(result.is_err());
        let result = calculate_next_run("weekly", "funday 02:00");
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_next_run_invalid_monthly() {
        let result = calculate_next_run("monthly", "32 02:00");
        assert!(result.is_err());
        let result = calculate_next_run("monthly", "15");
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_next_run_invalid_cron() {
        let result = calculate_next_run("cron", "invalid cron");
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_next_run_unknown_type() {
        let now = Utc::now();
        let next = calculate_next_run("unknown_type", "some_value").expect("Should handle unknown type");
        let diff = next - now;
        assert!(diff.num_hours() >= 23 && diff.num_hours() <= 25);
    }
}
