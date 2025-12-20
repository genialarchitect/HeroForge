//! Methodology checklists database operations
//!
//! Provides CRUD operations for methodology templates and user checklists:
//! - Templates: Built-in PTES and OWASP WSTG methodology frameworks
//! - Checklists: User's checklist instances linked to scans/engagements
//! - Items: Progress tracking for individual checklist items

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use super::models::{
    MethodologyTemplate, MethodologyTemplateItem, MethodologyChecklist, ChecklistItem,
    CreateChecklistRequest, UpdateChecklistRequest, UpdateChecklistItemRequest,
    ChecklistProgress, CategoryProgress, ChecklistWithItems, MethodologyTemplateWithItems,
    ChecklistSummary,
};

// ============================================================================
// Template Operations (Read-only)
// ============================================================================

/// List all methodology templates
pub async fn list_methodology_templates(pool: &SqlitePool) -> Result<Vec<MethodologyTemplate>> {
    let templates = sqlx::query_as::<_, MethodologyTemplate>(
        "SELECT * FROM methodology_templates ORDER BY name ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get a methodology template by ID
pub async fn get_methodology_template(
    pool: &SqlitePool,
    id: &str,
) -> Result<MethodologyTemplate> {
    let template = sqlx::query_as::<_, MethodologyTemplate>(
        "SELECT * FROM methodology_templates WHERE id = ?1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Get a methodology template with all its items
pub async fn get_methodology_template_with_items(
    pool: &SqlitePool,
    id: &str,
) -> Result<MethodologyTemplateWithItems> {
    let template = get_methodology_template(pool, id).await?;

    let items = sqlx::query_as::<_, MethodologyTemplateItem>(
        "SELECT * FROM methodology_template_items WHERE template_id = ?1 ORDER BY category, sort_order"
    )
    .bind(id)
    .fetch_all(pool)
    .await?;

    Ok(MethodologyTemplateWithItems { template, items })
}

// ============================================================================
// Checklist Operations
// ============================================================================

/// Create a new checklist from a template
pub async fn create_checklist(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateChecklistRequest,
) -> Result<MethodologyChecklist> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Verify template exists
    let template = get_methodology_template(pool, &request.template_id).await?;

    let checklist = sqlx::query_as::<_, MethodologyChecklist>(
        r#"
        INSERT INTO methodology_checklists (
            id, template_id, user_id, scan_id, engagement_id, name, description,
            progress_percent, status, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0.0, 'in_progress', ?8, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.template_id)
    .bind(user_id)
    .bind(&request.scan_id)
    .bind(&request.engagement_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(now)
    .fetch_one(pool)
    .await?;

    // Create checklist items from template items
    let template_items = sqlx::query_as::<_, MethodologyTemplateItem>(
        "SELECT * FROM methodology_template_items WHERE template_id = ?1"
    )
    .bind(&request.template_id)
    .fetch_all(pool)
    .await?;

    for item in template_items {
        let item_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO checklist_items (id, checklist_id, template_item_id, status)
            VALUES (?1, ?2, ?3, 'not_started')
            "#,
        )
        .bind(&item_id)
        .bind(&id)
        .bind(&item.id)
        .execute(pool)
        .await?;
    }

    log::info!(
        "Created checklist '{}' with {} items from template '{}'",
        checklist.name,
        template.item_count,
        template.name
    );

    Ok(checklist)
}

/// Get all checklists for a user
pub async fn get_user_checklists(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ChecklistSummary>> {
    let checklists = sqlx::query_as::<_, ChecklistSummary>(
        r#"
        SELECT
            mc.id,
            mc.template_id,
            mt.name as template_name,
            mc.user_id,
            mc.scan_id,
            mc.engagement_id,
            mc.name,
            mc.description,
            mc.progress_percent,
            mc.status,
            mc.created_at,
            mc.updated_at,
            mc.completed_at,
            mt.item_count as total_items
        FROM methodology_checklists mc
        JOIN methodology_templates mt ON mc.template_id = mt.id
        WHERE mc.user_id = ?1
        ORDER BY mc.updated_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(checklists)
}

/// Get a checklist by ID
pub async fn get_checklist(
    pool: &SqlitePool,
    id: &str,
) -> Result<MethodologyChecklist> {
    let checklist = sqlx::query_as::<_, MethodologyChecklist>(
        "SELECT * FROM methodology_checklists WHERE id = ?1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(checklist)
}

/// Get a checklist with all its items and template information
pub async fn get_checklist_with_items(
    pool: &SqlitePool,
    id: &str,
) -> Result<ChecklistWithItems> {
    let checklist = get_checklist(pool, id).await?;
    let template = get_methodology_template(pool, &checklist.template_id).await?;

    // Get checklist items joined with template items
    let items = sqlx::query_as::<_, ChecklistItemWithTemplate>(
        r#"
        SELECT
            ci.id,
            ci.checklist_id,
            ci.template_item_id,
            ci.status,
            ci.notes,
            ci.evidence,
            ci.findings,
            ci.tested_at,
            ci.tester_id,
            mti.category,
            mti.item_id as template_item_code,
            mti.title,
            mti.description,
            mti.guidance,
            mti.expected_evidence,
            mti.tools,
            mti."references",
            mti.sort_order
        FROM checklist_items ci
        JOIN methodology_template_items mti ON ci.template_item_id = mti.id
        WHERE ci.checklist_id = ?1
        ORDER BY mti.category, mti.sort_order
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await?;

    Ok(ChecklistWithItems {
        checklist,
        template_name: template.name,
        template_version: template.version,
        items,
    })
}

/// Internal struct for joined query
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ChecklistItemWithTemplate {
    pub id: String,
    pub checklist_id: String,
    pub template_item_id: String,
    pub status: String,
    pub notes: Option<String>,
    pub evidence: Option<String>,
    pub findings: Option<String>,
    pub tested_at: Option<chrono::DateTime<Utc>>,
    pub tester_id: Option<String>,
    // Template item fields
    pub category: String,
    pub template_item_code: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub guidance: Option<String>,
    pub expected_evidence: Option<String>,
    pub tools: Option<String>,
    pub references: Option<String>,
    pub sort_order: i32,
}

/// Update a checklist's metadata
pub async fn update_checklist(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    request: &UpdateChecklistRequest,
) -> Result<MethodologyChecklist> {
    // Verify ownership
    let existing = get_checklist(pool, id).await?;
    if existing.user_id != user_id {
        return Err(anyhow::anyhow!("Cannot modify checklist owned by another user"));
    }

    let now = Utc::now();
    let name = request.name.as_ref().unwrap_or(&existing.name);
    let description = request.description.clone().or(existing.description);
    let status = request.status.as_ref().unwrap_or(&existing.status);

    // Handle completion
    let completed_at = if status == "completed" && existing.status != "completed" {
        Some(now)
    } else if status != "completed" {
        None
    } else {
        existing.completed_at
    };

    let checklist = sqlx::query_as::<_, MethodologyChecklist>(
        r#"
        UPDATE methodology_checklists
        SET name = ?1, description = ?2, status = ?3, updated_at = ?4, completed_at = ?5
        WHERE id = ?6
        RETURNING *
        "#,
    )
    .bind(name)
    .bind(&description)
    .bind(status)
    .bind(now)
    .bind(completed_at)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(checklist)
}

/// Delete a checklist
pub async fn delete_checklist(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<()> {
    // Verify ownership
    let existing = get_checklist(pool, id).await?;
    if existing.user_id != user_id {
        return Err(anyhow::anyhow!("Cannot delete checklist owned by another user"));
    }

    // Delete checklist (cascade will handle items)
    sqlx::query("DELETE FROM methodology_checklists WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Checklist Item Operations
// ============================================================================

/// Update a checklist item's status, notes, and evidence
pub async fn update_checklist_item(
    pool: &SqlitePool,
    checklist_id: &str,
    template_item_id: &str,
    user_id: &str,
    request: &UpdateChecklistItemRequest,
) -> Result<ChecklistItem> {
    // Verify checklist ownership
    let checklist = get_checklist(pool, checklist_id).await?;
    if checklist.user_id != user_id {
        return Err(anyhow::anyhow!("Cannot modify items in checklist owned by another user"));
    }

    // Get existing item
    let existing = sqlx::query_as::<_, ChecklistItem>(
        "SELECT * FROM checklist_items WHERE checklist_id = ?1 AND template_item_id = ?2"
    )
    .bind(checklist_id)
    .bind(template_item_id)
    .fetch_one(pool)
    .await?;

    let now = Utc::now();
    let status = request.status.as_ref().unwrap_or(&existing.status);
    let notes = request.notes.clone().or(existing.notes);
    let evidence = request.evidence.clone().or(existing.evidence);
    let findings_json = request.findings.as_ref()
        .map(|f| serde_json::to_string(f).unwrap_or_default())
        .or(existing.findings);

    // Set tested_at if status changes to completed state
    let tested_at = if ["pass", "fail", "na"].contains(&status.as_str()) && existing.tested_at.is_none() {
        Some(now)
    } else {
        existing.tested_at
    };

    // Set tester_id if being tested
    let tester_id = if ["pass", "fail", "na"].contains(&status.as_str()) && existing.tester_id.is_none() {
        Some(user_id.to_string())
    } else {
        existing.tester_id
    };

    let item = sqlx::query_as::<_, ChecklistItem>(
        r#"
        UPDATE checklist_items
        SET status = ?1, notes = ?2, evidence = ?3, findings = ?4, tested_at = ?5, tester_id = ?6
        WHERE checklist_id = ?7 AND template_item_id = ?8
        RETURNING *
        "#,
    )
    .bind(status)
    .bind(&notes)
    .bind(&evidence)
    .bind(&findings_json)
    .bind(tested_at)
    .bind(&tester_id)
    .bind(checklist_id)
    .bind(template_item_id)
    .fetch_one(pool)
    .await?;

    // Recalculate progress
    recalculate_checklist_progress(pool, checklist_id).await?;

    Ok(item)
}

/// Recalculate and update checklist progress
pub async fn recalculate_checklist_progress(
    pool: &SqlitePool,
    checklist_id: &str,
) -> Result<f64> {
    let progress = get_checklist_progress(pool, checklist_id).await?;
    let now = Utc::now();

    sqlx::query(
        "UPDATE methodology_checklists SET progress_percent = ?1, updated_at = ?2 WHERE id = ?3"
    )
    .bind(progress.progress_percent)
    .bind(now)
    .bind(checklist_id)
    .execute(pool)
    .await?;

    Ok(progress.progress_percent)
}

/// Get detailed progress for a checklist
pub async fn get_checklist_progress(
    pool: &SqlitePool,
    checklist_id: &str,
) -> Result<ChecklistProgress> {
    // Overall stats
    let stats: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN status = 'fail' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN status = 'na' THEN 1 ELSE 0 END) as not_applicable,
            SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'not_started' THEN 1 ELSE 0 END) as not_started
        FROM checklist_items
        WHERE checklist_id = ?1
        "#,
    )
    .bind(checklist_id)
    .fetch_one(pool)
    .await?;

    let (total, passed, failed, not_applicable, in_progress, not_started) = stats;
    let completed = passed + failed + not_applicable;
    let progress_percent = if total > 0 {
        (completed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    // Progress by category
    let by_category: Vec<CategoryProgress> = sqlx::query_as(
        r#"
        SELECT
            mti.category,
            COUNT(*) as total,
            SUM(CASE WHEN ci.status IN ('pass', 'fail', 'na') THEN 1 ELSE 0 END) as completed
        FROM checklist_items ci
        JOIN methodology_template_items mti ON ci.template_item_id = mti.id
        WHERE ci.checklist_id = ?1
        GROUP BY mti.category
        ORDER BY mti.category
        "#,
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;

    Ok(ChecklistProgress {
        total_items: total as i32,
        completed_items: completed as i32,
        passed: passed as i32,
        failed: failed as i32,
        not_applicable: not_applicable as i32,
        in_progress: in_progress as i32,
        not_started: not_started as i32,
        progress_percent,
        by_category,
    })
}

/// Get a single checklist item
pub async fn get_checklist_item(
    pool: &SqlitePool,
    checklist_id: &str,
    template_item_id: &str,
) -> Result<ChecklistItem> {
    let item = sqlx::query_as::<_, ChecklistItem>(
        "SELECT * FROM checklist_items WHERE checklist_id = ?1 AND template_item_id = ?2"
    )
    .bind(checklist_id)
    .bind(template_item_id)
    .fetch_one(pool)
    .await?;

    Ok(item)
}
