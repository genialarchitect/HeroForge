//! SOAR Case Management Database Operations
//!
//! Provides SQLite-backed persistence for:
//! - Case lifecycle management
//! - Task tracking
//! - Evidence collection
//! - Comments and timeline

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Database Models
// ============================================================================

/// Case stored in database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SoarCaseRow {
    pub id: String,
    pub case_number: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub priority: String,
    pub case_type: String,
    pub assignee_id: Option<String>,
    pub source: Option<String>,
    pub source_ref: Option<String>,
    pub tlp: String,
    pub tags: Option<String>, // JSON array
    pub resolution: Option<String>,
    pub resolution_time_hours: Option<f64>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
}

/// Case task stored in database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseTaskRow {
    pub id: String,
    pub case_id: String,
    pub title: String,
    pub description: Option<String>,
    pub status: String,
    pub priority: String,
    pub assignee_id: Option<String>,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Case evidence stored in database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseEvidenceRow {
    pub id: String,
    pub case_id: String,
    pub evidence_type: String,
    pub name: String,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub hash_sha256: Option<String>,
    pub metadata: Option<String>, // JSON
    pub collected_by: String,
    pub collected_at: DateTime<Utc>,
}

/// Case comment stored in database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseCommentRow {
    pub id: String,
    pub case_id: String,
    pub user_id: String,
    pub content: String,
    pub is_internal: bool,
    pub created_at: DateTime<Utc>,
}

/// Case timeline event stored in database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CaseTimelineRow {
    pub id: String,
    pub case_id: String,
    pub event_type: String,
    pub event_data: Option<String>, // JSON
    pub user_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Request Types
// ============================================================================

/// Request to create a new case
#[derive(Debug, Clone, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub priority: String,
    pub case_type: String,
    pub assignee_id: Option<String>,
    pub source: Option<String>,
    pub source_ref: Option<String>,
    pub tlp: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Request to update a case
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCaseRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub priority: Option<String>,
    pub assignee_id: Option<String>,
    pub tlp: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Request to create a task
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTaskRequest {
    pub title: String,
    pub description: Option<String>,
    pub priority: String,
    pub assignee_id: Option<String>,
    pub due_at: Option<DateTime<Utc>>,
}

/// Request to add evidence
#[derive(Debug, Clone, Deserialize)]
pub struct AddEvidenceRequest {
    pub evidence_type: String,
    pub name: String,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub hash_sha256: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Case filter for listing
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CaseFilter {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub case_type: Option<String>,
    pub assignee_id: Option<String>,
    pub created_by: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Case CRUD Operations
// ============================================================================

/// Get the next case number
async fn get_next_case_number(pool: &SqlitePool) -> Result<String> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases")
        .fetch_one(pool)
        .await?;
    Ok(format!("CASE-{:05}", count + 1))
}

/// Create a new case
pub async fn create_case(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateCaseRequest,
) -> Result<SoarCaseRow> {
    let id = Uuid::new_v4().to_string();
    let case_number = get_next_case_number(pool).await?;
    let now = Utc::now();
    let tags_json = request.tags.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());
    let tlp = request.tlp.as_deref().unwrap_or("amber");

    sqlx::query(
        r#"
        INSERT INTO soar_cases (
            id, case_number, title, description, severity, status, priority,
            case_type, assignee_id, source, source_ref, tlp, tags,
            created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&case_number)
    .bind(&request.title)
    .bind(&request.description)
    .bind(&request.severity)
    .bind(&request.priority)
    .bind(&request.case_type)
    .bind(&request.assignee_id)
    .bind(&request.source)
    .bind(&request.source_ref)
    .bind(tlp)
    .bind(&tags_json)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    // Add creation timeline event
    add_timeline_event(pool, &id, "created", Some(serde_json::json!({
        "case_number": case_number,
        "severity": &request.severity,
        "case_type": &request.case_type
    })), Some(user_id)).await?;

    get_case_by_id(pool, &id).await
}

/// Get a case by ID
pub async fn get_case_by_id(pool: &SqlitePool, case_id: &str) -> Result<SoarCaseRow> {
    sqlx::query_as::<_, SoarCaseRow>("SELECT * FROM soar_cases WHERE id = ?")
        .bind(case_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

/// Get a case by case number
pub async fn get_case_by_number(pool: &SqlitePool, case_number: &str) -> Result<SoarCaseRow> {
    sqlx::query_as::<_, SoarCaseRow>("SELECT * FROM soar_cases WHERE case_number = ?")
        .bind(case_number)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

/// List cases with optional filtering
pub async fn list_cases(pool: &SqlitePool, filter: &CaseFilter) -> Result<Vec<SoarCaseRow>> {
    let mut query = String::from("SELECT * FROM soar_cases WHERE 1=1");

    if filter.status.is_some() {
        query.push_str(" AND status = ?");
    }
    if filter.severity.is_some() {
        query.push_str(" AND severity = ?");
    }
    if filter.case_type.is_some() {
        query.push_str(" AND case_type = ?");
    }
    if filter.assignee_id.is_some() {
        query.push_str(" AND assignee_id = ?");
    }
    if filter.created_by.is_some() {
        query.push_str(" AND created_by = ?");
    }

    query.push_str(" ORDER BY created_at DESC");

    if let Some(limit) = filter.limit {
        query.push_str(&format!(" LIMIT {}", limit));
    }
    if let Some(offset) = filter.offset {
        query.push_str(&format!(" OFFSET {}", offset));
    }

    let mut q = sqlx::query_as::<_, SoarCaseRow>(&query);

    if let Some(ref status) = filter.status {
        q = q.bind(status);
    }
    if let Some(ref severity) = filter.severity {
        q = q.bind(severity);
    }
    if let Some(ref case_type) = filter.case_type {
        q = q.bind(case_type);
    }
    if let Some(ref assignee_id) = filter.assignee_id {
        q = q.bind(assignee_id);
    }
    if let Some(ref created_by) = filter.created_by {
        q = q.bind(created_by);
    }

    q.fetch_all(pool).await.map_err(Into::into)
}

/// Update a case
pub async fn update_case(
    pool: &SqlitePool,
    case_id: &str,
    request: &UpdateCaseRequest,
) -> Result<SoarCaseRow> {
    let now = Utc::now();
    let tags_json = request.tags.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?"];
    if request.title.is_some() { updates.push("title = ?"); }
    if request.description.is_some() { updates.push("description = ?"); }
    if request.severity.is_some() { updates.push("severity = ?"); }
    if request.priority.is_some() { updates.push("priority = ?"); }
    if request.assignee_id.is_some() { updates.push("assignee_id = ?"); }
    if request.tlp.is_some() { updates.push("tlp = ?"); }
    if request.tags.is_some() { updates.push("tags = ?"); }

    let query = format!("UPDATE soar_cases SET {} WHERE id = ?", updates.join(", "));

    let mut q = sqlx::query(&query).bind(now);

    if let Some(ref title) = request.title { q = q.bind(title); }
    if let Some(ref description) = request.description { q = q.bind(description); }
    if let Some(ref severity) = request.severity { q = q.bind(severity); }
    if let Some(ref priority) = request.priority { q = q.bind(priority); }
    if let Some(ref assignee_id) = request.assignee_id { q = q.bind(assignee_id); }
    if let Some(ref tlp) = request.tlp { q = q.bind(tlp); }
    if let Some(ref _tags) = request.tags { q = q.bind(&tags_json); }

    q.bind(case_id).execute(pool).await?;

    get_case_by_id(pool, case_id).await
}

/// Update case status
pub async fn update_case_status(
    pool: &SqlitePool,
    case_id: &str,
    status: &str,
    user_id: &str,
) -> Result<SoarCaseRow> {
    let now = Utc::now();
    let old_case = get_case_by_id(pool, case_id).await?;

    // Set resolved_at or closed_at based on status
    let (resolved_at, closed_at) = match status {
        "resolved" => (Some(now), None),
        "closed" => (old_case.resolved_at.or(Some(now)), Some(now)),
        _ => (None, None),
    };

    // Calculate resolution time if resolving
    let resolution_time = if status == "resolved" && old_case.status != "resolved" {
        let duration = now - old_case.created_at;
        Some(duration.num_hours() as f64 + (duration.num_minutes() % 60) as f64 / 60.0)
    } else {
        old_case.resolution_time_hours
    };

    sqlx::query(
        r#"
        UPDATE soar_cases
        SET status = ?, updated_at = ?, resolved_at = COALESCE(?, resolved_at),
            closed_at = COALESCE(?, closed_at), resolution_time_hours = COALESCE(?, resolution_time_hours)
        WHERE id = ?
        "#,
    )
    .bind(status)
    .bind(now)
    .bind(resolved_at)
    .bind(closed_at)
    .bind(resolution_time)
    .bind(case_id)
    .execute(pool)
    .await?;

    // Add status change to timeline
    add_timeline_event(pool, case_id, "status_changed", Some(serde_json::json!({
        "old_status": old_case.status,
        "new_status": status
    })), Some(user_id)).await?;

    get_case_by_id(pool, case_id).await
}

/// Assign case to user
pub async fn assign_case(
    pool: &SqlitePool,
    case_id: &str,
    assignee_id: &str,
    assigned_by: &str,
) -> Result<SoarCaseRow> {
    let now = Utc::now();
    let old_case = get_case_by_id(pool, case_id).await?;

    sqlx::query("UPDATE soar_cases SET assignee_id = ?, updated_at = ? WHERE id = ?")
        .bind(assignee_id)
        .bind(now)
        .bind(case_id)
        .execute(pool)
        .await?;

    add_timeline_event(pool, case_id, "assigned", Some(serde_json::json!({
        "old_assignee": old_case.assignee_id,
        "new_assignee": assignee_id
    })), Some(assigned_by)).await?;

    get_case_by_id(pool, case_id).await
}

/// Resolve a case with resolution notes
pub async fn resolve_case(
    pool: &SqlitePool,
    case_id: &str,
    resolution: &str,
    user_id: &str,
) -> Result<SoarCaseRow> {
    let now = Utc::now();
    let old_case = get_case_by_id(pool, case_id).await?;

    let duration = now - old_case.created_at;
    let resolution_time = duration.num_hours() as f64 + (duration.num_minutes() % 60) as f64 / 60.0;

    sqlx::query(
        r#"
        UPDATE soar_cases
        SET status = 'resolved', resolution = ?, resolved_at = ?,
            resolution_time_hours = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(resolution)
    .bind(now)
    .bind(resolution_time)
    .bind(now)
    .bind(case_id)
    .execute(pool)
    .await?;

    add_timeline_event(pool, case_id, "resolved", Some(serde_json::json!({
        "resolution": resolution,
        "resolution_time_hours": resolution_time
    })), Some(user_id)).await?;

    get_case_by_id(pool, case_id).await
}

/// Delete a case (cascade deletes tasks, evidence, comments, timeline)
pub async fn delete_case(pool: &SqlitePool, case_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM soar_cases WHERE id = ?")
        .bind(case_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Task Operations
// ============================================================================

/// Add a task to a case
pub async fn add_task(
    pool: &SqlitePool,
    case_id: &str,
    request: &CreateTaskRequest,
) -> Result<CaseTaskRow> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO soar_case_tasks (
            id, case_id, title, description, status, priority,
            assignee_id, due_at, created_at
        ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(case_id)
    .bind(&request.title)
    .bind(&request.description)
    .bind(&request.priority)
    .bind(&request.assignee_id)
    .bind(&request.due_at)
    .bind(now)
    .execute(pool)
    .await?;

    sqlx::query_as::<_, CaseTaskRow>("SELECT * FROM soar_case_tasks WHERE id = ?")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

/// Get all tasks for a case
pub async fn get_case_tasks(pool: &SqlitePool, case_id: &str) -> Result<Vec<CaseTaskRow>> {
    sqlx::query_as::<_, CaseTaskRow>(
        "SELECT * FROM soar_case_tasks WHERE case_id = ? ORDER BY created_at"
    )
    .bind(case_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

/// Update task status
pub async fn update_task_status(
    pool: &SqlitePool,
    task_id: &str,
    status: &str,
) -> Result<CaseTaskRow> {
    let completed_at = if status == "completed" { Some(Utc::now()) } else { None };

    sqlx::query("UPDATE soar_case_tasks SET status = ?, completed_at = COALESCE(?, completed_at) WHERE id = ?")
        .bind(status)
        .bind(completed_at)
        .bind(task_id)
        .execute(pool)
        .await?;

    sqlx::query_as::<_, CaseTaskRow>("SELECT * FROM soar_case_tasks WHERE id = ?")
        .bind(task_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

// ============================================================================
// Evidence Operations
// ============================================================================

/// Add evidence to a case
pub async fn add_evidence(
    pool: &SqlitePool,
    case_id: &str,
    user_id: &str,
    request: &AddEvidenceRequest,
) -> Result<CaseEvidenceRow> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let metadata_json = request.metadata.as_ref().map(|m| serde_json::to_string(m).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO soar_case_evidence (
            id, case_id, evidence_type, name, description,
            file_path, hash_sha256, metadata, collected_by, collected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(case_id)
    .bind(&request.evidence_type)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.file_path)
    .bind(&request.hash_sha256)
    .bind(&metadata_json)
    .bind(user_id)
    .bind(now)
    .execute(pool)
    .await?;

    add_timeline_event(pool, case_id, "evidence_added", Some(serde_json::json!({
        "evidence_type": &request.evidence_type,
        "name": &request.name
    })), Some(user_id)).await?;

    sqlx::query_as::<_, CaseEvidenceRow>("SELECT * FROM soar_case_evidence WHERE id = ?")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

/// Get all evidence for a case
pub async fn get_case_evidence(pool: &SqlitePool, case_id: &str) -> Result<Vec<CaseEvidenceRow>> {
    sqlx::query_as::<_, CaseEvidenceRow>(
        "SELECT * FROM soar_case_evidence WHERE case_id = ? ORDER BY collected_at"
    )
    .bind(case_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

// ============================================================================
// Comment Operations
// ============================================================================

/// Add a comment to a case
pub async fn add_comment(
    pool: &SqlitePool,
    case_id: &str,
    user_id: &str,
    content: &str,
    is_internal: bool,
) -> Result<CaseCommentRow> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO soar_case_comments (id, case_id, user_id, content, is_internal, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(case_id)
    .bind(user_id)
    .bind(content)
    .bind(is_internal)
    .bind(now)
    .execute(pool)
    .await?;

    sqlx::query_as::<_, CaseCommentRow>("SELECT * FROM soar_case_comments WHERE id = ?")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

/// Get all comments for a case
pub async fn get_case_comments(
    pool: &SqlitePool,
    case_id: &str,
    include_internal: bool,
) -> Result<Vec<CaseCommentRow>> {
    let query = if include_internal {
        "SELECT * FROM soar_case_comments WHERE case_id = ? ORDER BY created_at"
    } else {
        "SELECT * FROM soar_case_comments WHERE case_id = ? AND is_internal = 0 ORDER BY created_at"
    };

    sqlx::query_as::<_, CaseCommentRow>(query)
        .bind(case_id)
        .fetch_all(pool)
        .await
        .map_err(Into::into)
}

// ============================================================================
// Timeline Operations
// ============================================================================

/// Add a timeline event
pub async fn add_timeline_event(
    pool: &SqlitePool,
    case_id: &str,
    event_type: &str,
    event_data: Option<serde_json::Value>,
    user_id: Option<&str>,
) -> Result<CaseTimelineRow> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let data_json = event_data.map(|d| serde_json::to_string(&d).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO soar_case_timeline (id, case_id, event_type, event_data, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(case_id)
    .bind(event_type)
    .bind(&data_json)
    .bind(user_id)
    .bind(now)
    .execute(pool)
    .await?;

    sqlx::query_as::<_, CaseTimelineRow>("SELECT * FROM soar_case_timeline WHERE id = ?")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

/// Get timeline for a case
pub async fn get_case_timeline(pool: &SqlitePool, case_id: &str) -> Result<Vec<CaseTimelineRow>> {
    sqlx::query_as::<_, CaseTimelineRow>(
        "SELECT * FROM soar_case_timeline WHERE case_id = ? ORDER BY created_at"
    )
    .bind(case_id)
    .fetch_all(pool)
    .await
    .map_err(Into::into)
}

// ============================================================================
// Statistics
// ============================================================================

/// Case statistics for dashboard
#[derive(Debug, Clone, Serialize)]
pub struct CaseStats {
    pub total_cases: i64,
    pub open_cases: i64,
    pub in_progress_cases: i64,
    pub resolved_cases: i64,
    pub closed_cases: i64,
    pub avg_resolution_time_hours: Option<f64>,
    pub cases_by_severity: Vec<(String, i64)>,
    pub cases_by_type: Vec<(String, i64)>,
}

/// Get case statistics
pub async fn get_case_stats(pool: &SqlitePool) -> Result<CaseStats> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases")
        .fetch_one(pool)
        .await?;

    let open: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'open'")
        .fetch_one(pool)
        .await?;

    let in_progress: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'in_progress'")
        .fetch_one(pool)
        .await?;

    let resolved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'resolved'")
        .fetch_one(pool)
        .await?;

    let closed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'closed'")
        .fetch_one(pool)
        .await?;

    let avg_time: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(resolution_time_hours) FROM soar_cases WHERE resolution_time_hours IS NOT NULL"
    )
    .fetch_one(pool)
    .await?;

    let by_severity: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*) FROM soar_cases GROUP BY severity ORDER BY COUNT(*) DESC"
    )
    .fetch_all(pool)
    .await?;

    let by_type: Vec<(String, i64)> = sqlx::query_as(
        "SELECT case_type, COUNT(*) FROM soar_cases GROUP BY case_type ORDER BY COUNT(*) DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(CaseStats {
        total_cases: total,
        open_cases: open,
        in_progress_cases: in_progress,
        resolved_cases: resolved,
        closed_cases: closed,
        avg_resolution_time_hours: avg_time,
        cases_by_severity: by_severity,
        cases_by_type: by_type,
    })
}

/// Check if user can access case (created by or assigned to)
pub async fn user_can_access_case(pool: &SqlitePool, user_id: &str, case_id: &str) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM soar_cases WHERE id = ? AND (created_by = ? OR assignee_id = ?)"
    )
    .bind(case_id)
    .bind(user_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}
