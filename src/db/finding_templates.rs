//! Finding templates database operations

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use super::models::{FindingTemplate, CreateFindingTemplateRequest, UpdateFindingTemplateRequest};

/// List all finding templates with optional filters
pub async fn list_finding_templates(
    pool: &SqlitePool,
    category: Option<&str>,
    severity: Option<&str>,
    search: Option<&str>,
    include_system: bool,
    user_id: Option<&str>,
) -> Result<Vec<FindingTemplate>> {
    let mut query = String::from("SELECT * FROM finding_templates WHERE 1=1");

    if let Some(cat) = category {
        query.push_str(&format!(" AND category = '{}'", cat.replace("'", "''")));
    }

    if let Some(sev) = severity {
        query.push_str(&format!(" AND severity = '{}'", sev.replace("'", "''")));
    }

    if let Some(s) = search {
        let search_escaped = s.replace("'", "''");
        query.push_str(&format!(
            " AND (title LIKE '%{}%' OR description LIKE '%{}%')",
            search_escaped, search_escaped
        ));
    }

    // Filter by system templates or user's own templates
    if !include_system {
        if let Some(uid) = user_id {
            query.push_str(&format!(" AND (is_system = 0 AND user_id = '{}')", uid.replace("'", "''")));
        } else {
            query.push_str(" AND is_system = 0");
        }
    } else if let Some(uid) = user_id {
        // Include system templates and user's own templates
        query.push_str(&format!(" AND (is_system = 1 OR user_id = '{}')", uid.replace("'", "''")));
    }

    query.push_str(" ORDER BY is_system DESC, title ASC");

    let templates = sqlx::query_as::<_, FindingTemplate>(&query)
        .fetch_all(pool)
        .await?;

    Ok(templates)
}

/// Get a single finding template by ID
pub async fn get_finding_template(
    pool: &SqlitePool,
    id: &str,
) -> Result<FindingTemplate> {
    let template = sqlx::query_as::<_, FindingTemplate>(
        "SELECT * FROM finding_templates WHERE id = ?1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Create a new finding template
pub async fn create_finding_template(
    pool: &SqlitePool,
    request: &CreateFindingTemplateRequest,
    user_id: &str,
) -> Result<FindingTemplate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Convert Vec to JSON strings
    let references_json = request.references.as_ref()
        .map(|r| serde_json::to_string(r).unwrap_or_default());
    let cwe_ids_json = request.cwe_ids.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let tags_json = request.tags.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default());

    let template = sqlx::query_as::<_, FindingTemplate>(
        r#"
        INSERT INTO finding_templates (
            id, user_id, category, title, severity, description, impact, remediation,
            "references", cwe_ids, cvss_vector, cvss_score, tags, is_system, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, ?14, ?14)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.category)
    .bind(&request.title)
    .bind(&request.severity)
    .bind(&request.description)
    .bind(&request.impact)
    .bind(&request.remediation)
    .bind(&references_json)
    .bind(&cwe_ids_json)
    .bind(&request.cvss_vector)
    .bind(&request.cvss_score)
    .bind(&tags_json)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Update a finding template (only for user's own templates, not system templates)
pub async fn update_finding_template(
    pool: &SqlitePool,
    id: &str,
    request: &UpdateFindingTemplateRequest,
    user_id: &str,
) -> Result<FindingTemplate> {
    // First check if the template exists and belongs to the user
    let existing = sqlx::query_as::<_, FindingTemplate>(
        "SELECT * FROM finding_templates WHERE id = ?1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    // Cannot modify system templates
    if existing.is_system {
        return Err(anyhow::anyhow!("Cannot modify system templates"));
    }

    // Can only modify own templates
    if existing.user_id.as_deref() != Some(user_id) {
        return Err(anyhow::anyhow!("Cannot modify templates created by other users"));
    }

    let now = Utc::now();

    // Build dynamic update
    let category = request.category.as_ref().unwrap_or(&existing.category);
    let title = request.title.as_ref().unwrap_or(&existing.title);
    let severity = request.severity.as_ref().unwrap_or(&existing.severity);
    let description = request.description.as_ref().unwrap_or(&existing.description);
    let impact = request.impact.clone().or(existing.impact);
    let remediation = request.remediation.clone().or(existing.remediation);

    let references_json = request.references.as_ref()
        .map(|r| serde_json::to_string(r).unwrap_or_default())
        .or(existing.references);
    let cwe_ids_json = request.cwe_ids.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default())
        .or(existing.cwe_ids);
    let tags_json = request.tags.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default())
        .or(existing.tags);

    let cvss_vector = request.cvss_vector.clone().or(existing.cvss_vector);
    let cvss_score = request.cvss_score.or(existing.cvss_score);

    let template = sqlx::query_as::<_, FindingTemplate>(
        r#"
        UPDATE finding_templates
        SET category = ?1, title = ?2, severity = ?3, description = ?4, impact = ?5,
            remediation = ?6, "references" = ?7, cwe_ids = ?8, cvss_vector = ?9,
            cvss_score = ?10, tags = ?11, updated_at = ?12
        WHERE id = ?13
        RETURNING *
        "#,
    )
    .bind(category)
    .bind(title)
    .bind(severity)
    .bind(description)
    .bind(&impact)
    .bind(&remediation)
    .bind(&references_json)
    .bind(&cwe_ids_json)
    .bind(&cvss_vector)
    .bind(&cvss_score)
    .bind(&tags_json)
    .bind(now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Delete a finding template (only for user's own templates, not system templates)
pub async fn delete_finding_template(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<()> {
    // First check if the template exists and belongs to the user
    let existing = sqlx::query_as::<_, FindingTemplate>(
        "SELECT * FROM finding_templates WHERE id = ?1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    // Cannot delete system templates
    if existing.is_system {
        return Err(anyhow::anyhow!("Cannot delete system templates"));
    }

    // Can only delete own templates
    if existing.user_id.as_deref() != Some(user_id) {
        return Err(anyhow::anyhow!("Cannot delete templates created by other users"));
    }

    sqlx::query("DELETE FROM finding_templates WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Clone a template (system or own) into a new user template
pub async fn clone_finding_template(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    new_title: Option<&str>,
) -> Result<FindingTemplate> {
    let existing = sqlx::query_as::<_, FindingTemplate>(
        "SELECT * FROM finding_templates WHERE id = ?1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    let new_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let title = new_title.unwrap_or(&existing.title);

    let template = sqlx::query_as::<_, FindingTemplate>(
        r#"
        INSERT INTO finding_templates (
            id, user_id, category, title, severity, description, impact, remediation,
            "references", cwe_ids, cvss_vector, cvss_score, tags, is_system, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, ?14, ?14)
        RETURNING *
        "#,
    )
    .bind(&new_id)
    .bind(user_id)
    .bind(&existing.category)
    .bind(title)
    .bind(&existing.severity)
    .bind(&existing.description)
    .bind(&existing.impact)
    .bind(&existing.remediation)
    .bind(&existing.references)
    .bind(&existing.cwe_ids)
    .bind(&existing.cvss_vector)
    .bind(&existing.cvss_score)
    .bind(&existing.tags)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Get template categories with counts
pub async fn get_template_categories(pool: &SqlitePool) -> Result<Vec<(String, i64)>> {
    let categories: Vec<(String, i64)> = sqlx::query_as(
        "SELECT category, COUNT(*) as count FROM finding_templates GROUP BY category ORDER BY category"
    )
    .fetch_all(pool)
    .await?;

    Ok(categories)
}
