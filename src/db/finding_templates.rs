//! Finding templates database operations

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use super::models::{
    FindingTemplate, CreateFindingTemplateRequest, UpdateFindingTemplateRequest,
    FindingTemplateCategory,
};

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

    // New enhanced fields
    let evidence_placeholders_json = request.evidence_placeholders.as_ref()
        .map(|e| serde_json::to_string(e).unwrap_or_default());
    let mitre_attack_ids_json = request.mitre_attack_ids.as_ref()
        .map(|m| serde_json::to_string(m).unwrap_or_default());
    let compliance_mappings_json = request.compliance_mappings.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());
    let affected_components_json = request.affected_components.as_ref()
        .map(|a| serde_json::to_string(a).unwrap_or_default());

    let template = sqlx::query_as::<_, FindingTemplate>(
        r#"
        INSERT INTO finding_templates (
            id, user_id, category, title, severity, description, impact, remediation,
            "references", cwe_ids, cvss_vector, cvss_score, tags, is_system, created_at, updated_at,
            evidence_placeholders, testing_steps, owasp_category, mitre_attack_ids,
            compliance_mappings, affected_components, use_count
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, ?14, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, 0)
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
    .bind(&evidence_placeholders_json)
    .bind(&request.testing_steps)
    .bind(&request.owasp_category)
    .bind(&mitre_attack_ids_json)
    .bind(&compliance_mappings_json)
    .bind(&affected_components_json)
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

    // New enhanced fields
    let evidence_placeholders_json = request.evidence_placeholders.as_ref()
        .map(|e| serde_json::to_string(e).unwrap_or_default())
        .or(existing.evidence_placeholders);
    let testing_steps = request.testing_steps.clone().or(existing.testing_steps);
    let owasp_category = request.owasp_category.clone().or(existing.owasp_category);
    let mitre_attack_ids_json = request.mitre_attack_ids.as_ref()
        .map(|m| serde_json::to_string(m).unwrap_or_default())
        .or(existing.mitre_attack_ids);
    let compliance_mappings_json = request.compliance_mappings.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default())
        .or(existing.compliance_mappings);
    let affected_components_json = request.affected_components.as_ref()
        .map(|a| serde_json::to_string(a).unwrap_or_default())
        .or(existing.affected_components);

    let template = sqlx::query_as::<_, FindingTemplate>(
        r#"
        UPDATE finding_templates
        SET category = ?1, title = ?2, severity = ?3, description = ?4, impact = ?5,
            remediation = ?6, "references" = ?7, cwe_ids = ?8, cvss_vector = ?9,
            cvss_score = ?10, tags = ?11, updated_at = ?12,
            evidence_placeholders = ?14, testing_steps = ?15, owasp_category = ?16,
            mitre_attack_ids = ?17, compliance_mappings = ?18, affected_components = ?19
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
    .bind(&evidence_placeholders_json)
    .bind(&testing_steps)
    .bind(&owasp_category)
    .bind(&mitre_attack_ids_json)
    .bind(&compliance_mappings_json)
    .bind(&affected_components_json)
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
            "references", cwe_ids, cvss_vector, cvss_score, tags, is_system, created_at, updated_at,
            evidence_placeholders, testing_steps, owasp_category, mitre_attack_ids,
            compliance_mappings, affected_components, use_count
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, ?14, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, 0)
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
    .bind(&existing.evidence_placeholders)
    .bind(&existing.testing_steps)
    .bind(&existing.owasp_category)
    .bind(&existing.mitre_attack_ids)
    .bind(&existing.compliance_mappings)
    .bind(&existing.affected_components)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Get template categories with counts (legacy - category column values)
pub async fn get_template_categories(pool: &SqlitePool) -> Result<Vec<(String, i64)>> {
    let categories: Vec<(String, i64)> = sqlx::query_as(
        "SELECT category, COUNT(*) as count FROM finding_templates GROUP BY category ORDER BY category"
    )
    .fetch_all(pool)
    .await?;

    Ok(categories)
}

/// List all finding template categories from the categories table
pub async fn list_finding_template_categories(pool: &SqlitePool) -> Result<Vec<FindingTemplateCategory>> {
    let categories = sqlx::query_as::<_, FindingTemplateCategory>(
        "SELECT * FROM finding_template_categories ORDER BY sort_order, name"
    )
    .fetch_all(pool)
    .await?;

    Ok(categories)
}

/// Get a single finding template category by ID
pub async fn get_finding_template_category(
    pool: &SqlitePool,
    id: &str,
) -> Result<FindingTemplateCategory> {
    let category = sqlx::query_as::<_, FindingTemplateCategory>(
        "SELECT * FROM finding_template_categories WHERE id = ?1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(category)
}

/// Create a new finding template category
pub async fn create_finding_template_category(
    pool: &SqlitePool,
    name: &str,
    parent_id: Option<&str>,
    description: Option<&str>,
    icon: Option<&str>,
    color: Option<&str>,
) -> Result<FindingTemplateCategory> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Get max sort_order
    let max_order: Option<i32> = sqlx::query_scalar(
        "SELECT MAX(sort_order) FROM finding_template_categories"
    )
    .fetch_one(pool)
    .await?;

    let category = sqlx::query_as::<_, FindingTemplateCategory>(
        r#"
        INSERT INTO finding_template_categories (id, name, parent_id, description, icon, color, sort_order, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#
    )
    .bind(&id)
    .bind(name)
    .bind(parent_id)
    .bind(description)
    .bind(icon)
    .bind(color)
    .bind(max_order.unwrap_or(0) + 1)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(category)
}

/// Delete a finding template category
pub async fn delete_finding_template_category(
    pool: &SqlitePool,
    id: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM finding_template_categories WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Increment use count when a template is applied
pub async fn increment_template_use_count(
    pool: &SqlitePool,
    id: &str,
) -> Result<()> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE finding_templates SET use_count = COALESCE(use_count, 0) + 1, last_used_at = ?1 WHERE id = ?2"
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get popular templates by use count
pub async fn get_popular_templates(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<FindingTemplate>> {
    let templates = sqlx::query_as::<_, FindingTemplate>(
        "SELECT * FROM finding_templates WHERE use_count > 0 ORDER BY use_count DESC LIMIT ?1"
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Search templates with full-text search
pub async fn search_templates(
    pool: &SqlitePool,
    query: &str,
    category: Option<&str>,
    severity: Option<&str>,
    owasp_category: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<FindingTemplate>> {
    let search_pattern = format!("%{}%", query.replace("'", "''"));

    let mut sql = String::from(
        "SELECT * FROM finding_templates WHERE (title LIKE ?1 OR description LIKE ?1 OR tags LIKE ?1)"
    );

    if category.is_some() {
        sql.push_str(" AND category = ?2");
    }
    if severity.is_some() {
        sql.push_str(" AND severity = ?3");
    }
    if owasp_category.is_some() {
        sql.push_str(" AND owasp_category = ?4");
    }

    sql.push_str(" ORDER BY COALESCE(use_count, 0) DESC, title ASC LIMIT ?5 OFFSET ?6");

    let templates = sqlx::query_as::<_, FindingTemplate>(&sql)
        .bind(&search_pattern)
        .bind(category.unwrap_or(""))
        .bind(severity.unwrap_or(""))
        .bind(owasp_category.unwrap_or(""))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

    Ok(templates)
}

/// Get templates by OWASP category
pub async fn get_templates_by_owasp(
    pool: &SqlitePool,
    owasp_category: &str,
) -> Result<Vec<FindingTemplate>> {
    let templates = sqlx::query_as::<_, FindingTemplate>(
        "SELECT * FROM finding_templates WHERE owasp_category = ?1 ORDER BY title"
    )
    .bind(owasp_category)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get templates by MITRE ATT&CK ID
pub async fn get_templates_by_mitre(
    pool: &SqlitePool,
    mitre_id: &str,
) -> Result<Vec<FindingTemplate>> {
    let pattern = format!("%\"{}%", mitre_id);
    let templates = sqlx::query_as::<_, FindingTemplate>(
        "SELECT * FROM finding_templates WHERE mitre_attack_ids LIKE ?1 ORDER BY title"
    )
    .bind(&pattern)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}
