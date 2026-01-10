//! Database operations for client compliance checklist system
//!
//! This module provides functions for managing per-client compliance checklists,
//! checklist items with checkbox state, evidence attachments, and audit history.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Checklist status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistStatus {
    NotStarted,
    InProgress,
    UnderReview,
    Completed,
    Archived,
}

impl ChecklistStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::InProgress => "in_progress",
            Self::UnderReview => "under_review",
            Self::Completed => "completed",
            Self::Archived => "archived",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "in_progress" => Self::InProgress,
            "under_review" => Self::UnderReview,
            "completed" => Self::Completed,
            "archived" => Self::Archived,
            _ => Self::NotStarted,
        }
    }
}

/// Control item status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    NotAssessed,
    InProgress,
    Compliant,
    NonCompliant,
    NotApplicable,
}

impl ControlStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotAssessed => "not_assessed",
            Self::InProgress => "in_progress",
            Self::Compliant => "compliant",
            Self::NonCompliant => "non_compliant",
            Self::NotApplicable => "not_applicable",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "in_progress" => Self::InProgress,
            "compliant" => Self::Compliant,
            "non_compliant" => Self::NonCompliant,
            "not_applicable" => Self::NotApplicable,
            _ => Self::NotAssessed,
        }
    }
}

/// Evidence type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    File,
    Image,
    Screenshot,
    Document,
    Link,
    Note,
}

impl EvidenceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Image => "image",
            Self::Screenshot => "screenshot",
            Self::Document => "document",
            Self::Link => "link",
            Self::Note => "note",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "image" => Self::Image,
            "screenshot" => Self::Screenshot,
            "document" => Self::Document,
            "link" => Self::Link,
            "note" => Self::Note,
            _ => Self::File,
        }
    }
}

/// Client compliance checklist
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientComplianceChecklist {
    pub id: String,
    pub customer_id: String,
    pub engagement_id: Option<String>,
    pub framework_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: ChecklistStatus,
    pub due_date: Option<DateTime<Utc>>,
    pub assigned_to: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub overall_score: f64,
    pub total_controls: i32,
    pub completed_controls: i32,
    pub compliant_controls: i32,
    pub non_compliant_controls: i32,
    pub not_applicable_controls: i32,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Client compliance checklist item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientComplianceItem {
    pub id: String,
    pub checklist_id: String,
    pub control_id: String,
    pub control_title: String,
    pub control_description: Option<String>,
    pub category: Option<String>,
    pub is_automated: bool,
    pub status: ControlStatus,
    pub is_checked: bool,
    pub is_applicable: bool,
    pub rating_score: Option<f64>,
    pub notes: Option<String>,
    pub findings: Option<String>,
    pub remediation_steps: Option<String>,
    pub compensating_controls: Option<String>,
    pub assigned_to: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub completed_by: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Client compliance evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientComplianceEvidence {
    pub id: String,
    pub item_id: String,
    pub checklist_id: String,
    pub customer_id: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence_type: EvidenceType,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_size: Option<i64>,
    pub mime_type: Option<String>,
    pub external_url: Option<String>,
    pub content_hash: Option<String>,
    pub uploaded_by: String,
    pub uploaded_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: String,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Client compliance history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientComplianceHistory {
    pub id: String,
    pub checklist_id: String,
    pub item_id: Option<String>,
    pub user_id: String,
    pub action: String,
    pub field_name: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChecklistRequest {
    pub customer_id: String,
    pub engagement_id: Option<String>,
    pub framework_id: String,
    pub name: String,
    pub description: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub assigned_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateChecklistRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<ChecklistStatus>,
    pub due_date: Option<DateTime<Utc>>,
    pub assigned_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateItemRequest {
    pub status: Option<ControlStatus>,
    pub is_checked: Option<bool>,
    pub is_applicable: Option<bool>,
    pub rating_score: Option<f64>,
    pub notes: Option<String>,
    pub findings: Option<String>,
    pub remediation_steps: Option<String>,
    pub compensating_controls: Option<String>,
    pub assigned_to: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddEvidenceRequest {
    pub item_id: String,
    pub title: String,
    pub description: Option<String>,
    pub evidence_type: EvidenceType,
    pub file_path: Option<String>,
    pub file_name: Option<String>,
    pub file_size: Option<i64>,
    pub mime_type: Option<String>,
    pub external_url: Option<String>,
    pub content_hash: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: Option<String>,
}

// ============================================================================
// Database Row Types
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct ChecklistRow {
    id: String,
    customer_id: String,
    engagement_id: Option<String>,
    framework_id: String,
    name: String,
    description: Option<String>,
    status: String,
    due_date: Option<String>,
    assigned_to: Option<String>,
    reviewed_by: Option<String>,
    reviewed_at: Option<String>,
    overall_score: f64,
    total_controls: i32,
    completed_controls: i32,
    compliant_controls: i32,
    non_compliant_controls: i32,
    not_applicable_controls: i32,
    created_by: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct ItemRow {
    id: String,
    checklist_id: String,
    control_id: String,
    control_title: String,
    control_description: Option<String>,
    category: Option<String>,
    is_automated: i32,
    status: String,
    is_checked: i32,
    is_applicable: i32,
    rating_score: Option<f64>,
    notes: Option<String>,
    findings: Option<String>,
    remediation_steps: Option<String>,
    compensating_controls: Option<String>,
    assigned_to: Option<String>,
    due_date: Option<String>,
    completed_at: Option<String>,
    completed_by: Option<String>,
    verified_at: Option<String>,
    verified_by: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct EvidenceRow {
    id: String,
    item_id: String,
    checklist_id: String,
    customer_id: String,
    title: String,
    description: Option<String>,
    evidence_type: String,
    file_path: Option<String>,
    file_name: Option<String>,
    file_size: Option<i64>,
    mime_type: Option<String>,
    external_url: Option<String>,
    content_hash: Option<String>,
    uploaded_by: String,
    uploaded_at: String,
    expires_at: Option<String>,
    status: Option<String>,
    metadata: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct HistoryRow {
    id: String,
    checklist_id: String,
    item_id: Option<String>,
    user_id: String,
    action: String,
    field_name: Option<String>,
    old_value: Option<String>,
    new_value: Option<String>,
    comment: Option<String>,
    created_at: String,
}

// ============================================================================
// Conversion Functions
// ============================================================================

fn parse_datetime(s: &str) -> DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_datetime_opt(s: &Option<String>) -> Option<DateTime<Utc>> {
    s.as_ref().map(|s| parse_datetime(s))
}

fn checklist_from_row(row: ChecklistRow) -> ClientComplianceChecklist {
    ClientComplianceChecklist {
        id: row.id,
        customer_id: row.customer_id,
        engagement_id: row.engagement_id,
        framework_id: row.framework_id,
        name: row.name,
        description: row.description,
        status: ChecklistStatus::from_str(&row.status),
        due_date: parse_datetime_opt(&row.due_date),
        assigned_to: row.assigned_to,
        reviewed_by: row.reviewed_by,
        reviewed_at: parse_datetime_opt(&row.reviewed_at),
        overall_score: row.overall_score,
        total_controls: row.total_controls,
        completed_controls: row.completed_controls,
        compliant_controls: row.compliant_controls,
        non_compliant_controls: row.non_compliant_controls,
        not_applicable_controls: row.not_applicable_controls,
        created_by: row.created_by,
        created_at: parse_datetime(&row.created_at),
        updated_at: parse_datetime(&row.updated_at),
    }
}

fn item_from_row(row: ItemRow) -> ClientComplianceItem {
    ClientComplianceItem {
        id: row.id,
        checklist_id: row.checklist_id,
        control_id: row.control_id,
        control_title: row.control_title,
        control_description: row.control_description,
        category: row.category,
        is_automated: row.is_automated != 0,
        status: ControlStatus::from_str(&row.status),
        is_checked: row.is_checked != 0,
        is_applicable: row.is_applicable != 0,
        rating_score: row.rating_score,
        notes: row.notes,
        findings: row.findings,
        remediation_steps: row.remediation_steps,
        compensating_controls: row.compensating_controls,
        assigned_to: row.assigned_to,
        due_date: parse_datetime_opt(&row.due_date),
        completed_at: parse_datetime_opt(&row.completed_at),
        completed_by: row.completed_by,
        verified_at: parse_datetime_opt(&row.verified_at),
        verified_by: row.verified_by,
        created_at: parse_datetime(&row.created_at),
        updated_at: parse_datetime(&row.updated_at),
    }
}

fn evidence_from_row(row: EvidenceRow) -> ClientComplianceEvidence {
    ClientComplianceEvidence {
        id: row.id,
        item_id: row.item_id,
        checklist_id: row.checklist_id,
        customer_id: row.customer_id,
        title: row.title,
        description: row.description,
        evidence_type: EvidenceType::from_str(&row.evidence_type),
        file_path: row.file_path,
        file_name: row.file_name,
        file_size: row.file_size,
        mime_type: row.mime_type,
        external_url: row.external_url,
        content_hash: row.content_hash,
        uploaded_by: row.uploaded_by,
        uploaded_at: parse_datetime(&row.uploaded_at),
        expires_at: parse_datetime_opt(&row.expires_at),
        status: row.status.unwrap_or_else(|| "active".to_string()),
        metadata: row.metadata,
        created_at: parse_datetime(&row.created_at),
        updated_at: parse_datetime(&row.updated_at),
    }
}

fn history_from_row(row: HistoryRow) -> ClientComplianceHistory {
    ClientComplianceHistory {
        id: row.id,
        checklist_id: row.checklist_id,
        item_id: row.item_id,
        user_id: row.user_id,
        action: row.action,
        field_name: row.field_name,
        old_value: row.old_value,
        new_value: row.new_value,
        comment: row.comment,
        created_at: parse_datetime(&row.created_at),
    }
}

// ============================================================================
// Checklist CRUD Functions
// ============================================================================

/// Create a new client compliance checklist
pub async fn create_checklist(
    pool: &SqlitePool,
    req: &CreateChecklistRequest,
    created_by: &str,
) -> Result<ClientComplianceChecklist> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO client_compliance_checklists (
            id, customer_id, engagement_id, framework_id, name, description,
            status, due_date, assigned_to, overall_score, total_controls,
            completed_controls, compliant_controls, non_compliant_controls,
            not_applicable_controls, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        "#,
    )
    .bind(&id)
    .bind(&req.customer_id)
    .bind(&req.engagement_id)
    .bind(&req.framework_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(ChecklistStatus::NotStarted.as_str())
    .bind(req.due_date.map(|d| d.to_rfc3339()))
    .bind(&req.assigned_to)
    .bind(0.0_f64)
    .bind(0)
    .bind(0)
    .bind(0)
    .bind(0)
    .bind(0)
    .bind(created_by)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    // Log creation
    add_history(pool, &id, None, created_by, "created", None, None, None, None).await?;

    get_checklist(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create checklist"))
}

/// Get a checklist by ID
pub async fn get_checklist(pool: &SqlitePool, id: &str) -> Result<Option<ClientComplianceChecklist>> {
    let row: Option<ChecklistRow> = sqlx::query_as(
        "SELECT * FROM client_compliance_checklists WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(checklist_from_row))
}

/// List checklists for a customer
pub async fn list_checklists_for_customer(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<Vec<ClientComplianceChecklist>> {
    let rows: Vec<ChecklistRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_checklists
        WHERE customer_id = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(checklist_from_row).collect())
}

/// List checklists for an engagement
pub async fn list_checklists_for_engagement(
    pool: &SqlitePool,
    engagement_id: &str,
) -> Result<Vec<ClientComplianceChecklist>> {
    let rows: Vec<ChecklistRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_checklists
        WHERE engagement_id = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(checklist_from_row).collect())
}

/// List all checklists (admin/reporting)
pub async fn list_all_checklists(
    pool: &SqlitePool,
    limit: i32,
    offset: i32,
) -> Result<Vec<ClientComplianceChecklist>> {
    let rows: Vec<ChecklistRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_checklists
        ORDER BY updated_at DESC
        LIMIT ?1 OFFSET ?2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(checklist_from_row).collect())
}

/// Update a checklist
pub async fn update_checklist(
    pool: &SqlitePool,
    id: &str,
    req: &UpdateChecklistRequest,
    user_id: &str,
) -> Result<ClientComplianceChecklist> {
    let now = Utc::now();

    // Get current state for history
    let current = get_checklist(pool, id).await?.ok_or_else(|| anyhow::anyhow!("Checklist not found"))?;

    // Update with COALESCE to only update provided fields
    sqlx::query(
        r#"
        UPDATE client_compliance_checklists
        SET name = COALESCE(?1, name),
            description = COALESCE(?2, description),
            status = COALESCE(?3, status),
            due_date = COALESCE(?4, due_date),
            assigned_to = COALESCE(?5, assigned_to),
            updated_at = ?6
        WHERE id = ?7
        "#,
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(req.status.as_ref().map(|s| s.as_str()))
    .bind(req.due_date.map(|d| d.to_rfc3339()))
    .bind(&req.assigned_to)
    .bind(now.to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;

    // Log changes
    if let Some(ref name) = req.name {
        add_history(pool, id, None, user_id, "updated", Some("name"), Some(&current.name), Some(name), None).await?;
    }
    if let Some(ref status) = req.status {
        add_history(pool, id, None, user_id, "updated", Some("status"), Some(current.status.as_str()), Some(status.as_str()), None).await?;
    }

    get_checklist(pool, id).await?.ok_or_else(|| anyhow::anyhow!("Checklist not found"))
}

/// Delete a checklist
pub async fn delete_checklist(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM client_compliance_checklists WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Checklist Item Functions
// ============================================================================

/// Add a control item to a checklist
pub async fn add_checklist_item(
    pool: &SqlitePool,
    checklist_id: &str,
    control_id: &str,
    control_title: &str,
    control_description: Option<&str>,
    category: Option<&str>,
    is_automated: bool,
) -> Result<ClientComplianceItem> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO client_compliance_items (
            id, checklist_id, control_id, control_title, control_description,
            category, is_automated, status, is_checked, is_applicable,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&id)
    .bind(checklist_id)
    .bind(control_id)
    .bind(control_title)
    .bind(control_description)
    .bind(category)
    .bind(if is_automated { 1 } else { 0 })
    .bind(ControlStatus::NotAssessed.as_str())
    .bind(0)
    .bind(1)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    // Update checklist total controls count
    sqlx::query(
        "UPDATE client_compliance_checklists SET total_controls = total_controls + 1, updated_at = ?1 WHERE id = ?2",
    )
    .bind(now.to_rfc3339())
    .bind(checklist_id)
    .execute(pool)
    .await?;

    get_checklist_item(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create item"))
}

/// Get a checklist item by ID
pub async fn get_checklist_item(pool: &SqlitePool, id: &str) -> Result<Option<ClientComplianceItem>> {
    let row: Option<ItemRow> = sqlx::query_as(
        "SELECT * FROM client_compliance_items WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(item_from_row))
}

/// List all items for a checklist
pub async fn list_checklist_items(pool: &SqlitePool, checklist_id: &str) -> Result<Vec<ClientComplianceItem>> {
    let rows: Vec<ItemRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_items
        WHERE checklist_id = ?1
        ORDER BY category, control_id
        "#,
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(item_from_row).collect())
}

/// Update a checklist item
pub async fn update_checklist_item(
    pool: &SqlitePool,
    id: &str,
    req: &UpdateItemRequest,
    user_id: &str,
) -> Result<ClientComplianceItem> {
    let now = Utc::now();

    // Get current state
    let current = get_checklist_item(pool, id).await?.ok_or_else(|| anyhow::anyhow!("Item not found"))?;
    let checklist_id = current.checklist_id.clone();

    // Update the item
    sqlx::query(
        r#"
        UPDATE client_compliance_items
        SET status = COALESCE(?1, status),
            is_checked = COALESCE(?2, is_checked),
            is_applicable = COALESCE(?3, is_applicable),
            rating_score = COALESCE(?4, rating_score),
            notes = COALESCE(?5, notes),
            findings = COALESCE(?6, findings),
            remediation_steps = COALESCE(?7, remediation_steps),
            compensating_controls = COALESCE(?8, compensating_controls),
            assigned_to = COALESCE(?9, assigned_to),
            due_date = COALESCE(?10, due_date),
            completed_at = CASE WHEN ?1 = 'compliant' OR ?1 = 'non_compliant' OR ?1 = 'not_applicable' THEN ?11 ELSE completed_at END,
            completed_by = CASE WHEN ?1 = 'compliant' OR ?1 = 'non_compliant' OR ?1 = 'not_applicable' THEN ?12 ELSE completed_by END,
            updated_at = ?11
        WHERE id = ?13
        "#,
    )
    .bind(req.status.as_ref().map(|s| s.as_str()))
    .bind(req.is_checked.map(|b| if b { 1 } else { 0 }))
    .bind(req.is_applicable.map(|b| if b { 1 } else { 0 }))
    .bind(&req.rating_score)
    .bind(&req.notes)
    .bind(&req.findings)
    .bind(&req.remediation_steps)
    .bind(&req.compensating_controls)
    .bind(&req.assigned_to)
    .bind(req.due_date.map(|d| d.to_rfc3339()))
    .bind(now.to_rfc3339())
    .bind(user_id)
    .bind(id)
    .execute(pool)
    .await?;

    // Log status change
    if let Some(ref status) = req.status {
        add_history(
            pool,
            &checklist_id,
            Some(id),
            user_id,
            "status_changed",
            Some("status"),
            Some(current.status.as_str()),
            Some(status.as_str()),
            None,
        ).await?;
    }

    // Log checkbox change
    if let Some(checked) = req.is_checked {
        if checked != current.is_checked {
            add_history(
                pool,
                &checklist_id,
                Some(id),
                user_id,
                if checked { "checked" } else { "unchecked" },
                Some("is_checked"),
                Some(if current.is_checked { "true" } else { "false" }),
                Some(if checked { "true" } else { "false" }),
                None,
            ).await?;
        }
    }

    // Recalculate checklist statistics
    recalculate_checklist_stats(pool, &checklist_id).await?;

    get_checklist_item(pool, id).await?.ok_or_else(|| anyhow::anyhow!("Item not found"))
}

/// Bulk update checkbox state for multiple items
pub async fn bulk_update_checkboxes(
    pool: &SqlitePool,
    item_ids: &[String],
    is_checked: bool,
    user_id: &str,
) -> Result<i32> {
    let now = Utc::now();
    let mut count = 0;

    for id in item_ids {
        let result = sqlx::query(
            r#"
            UPDATE client_compliance_items
            SET is_checked = ?1, updated_at = ?2
            WHERE id = ?3
            "#,
        )
        .bind(if is_checked { 1 } else { 0 })
        .bind(now.to_rfc3339())
        .bind(id)
        .execute(pool)
        .await?;

        if result.rows_affected() > 0 {
            count += 1;

            // Get checklist_id for history
            if let Some(item) = get_checklist_item(pool, id).await? {
                add_history(
                    pool,
                    &item.checklist_id,
                    Some(id),
                    user_id,
                    if is_checked { "checked" } else { "unchecked" },
                    None,
                    None,
                    None,
                    None,
                ).await?;
            }
        }
    }

    Ok(count)
}

// ============================================================================
// Evidence Functions
// ============================================================================

/// Add evidence to a checklist item
pub async fn add_evidence(
    pool: &SqlitePool,
    checklist_id: &str,
    customer_id: &str,
    req: &AddEvidenceRequest,
    uploaded_by: &str,
) -> Result<ClientComplianceEvidence> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO client_compliance_evidence (
            id, item_id, checklist_id, customer_id, title, description,
            evidence_type, file_path, file_name, file_size, mime_type,
            external_url, content_hash, uploaded_by, uploaded_at,
            expires_at, status, metadata, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
        "#,
    )
    .bind(&id)
    .bind(&req.item_id)
    .bind(checklist_id)
    .bind(customer_id)
    .bind(&req.title)
    .bind(&req.description)
    .bind(req.evidence_type.as_str())
    .bind(&req.file_path)
    .bind(&req.file_name)
    .bind(&req.file_size)
    .bind(&req.mime_type)
    .bind(&req.external_url)
    .bind(&req.content_hash)
    .bind(uploaded_by)
    .bind(now.to_rfc3339())
    .bind(req.expires_at.map(|d| d.to_rfc3339()))
    .bind("active")
    .bind(&req.metadata)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    // Log evidence addition
    add_history(
        pool,
        checklist_id,
        Some(&req.item_id),
        uploaded_by,
        "evidence_added",
        None,
        None,
        Some(&req.title),
        None,
    ).await?;

    get_evidence(pool, &id).await?.ok_or_else(|| anyhow::anyhow!("Failed to create evidence"))
}

/// Get evidence by ID
pub async fn get_evidence(pool: &SqlitePool, id: &str) -> Result<Option<ClientComplianceEvidence>> {
    let row: Option<EvidenceRow> = sqlx::query_as(
        "SELECT * FROM client_compliance_evidence WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(evidence_from_row))
}

/// List evidence for a checklist item
pub async fn list_evidence_for_item(pool: &SqlitePool, item_id: &str) -> Result<Vec<ClientComplianceEvidence>> {
    let rows: Vec<EvidenceRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_evidence
        WHERE item_id = ?1 AND status = 'active'
        ORDER BY uploaded_at DESC
        "#,
    )
    .bind(item_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(evidence_from_row).collect())
}

/// List all evidence for a checklist
pub async fn list_evidence_for_checklist(pool: &SqlitePool, checklist_id: &str) -> Result<Vec<ClientComplianceEvidence>> {
    let rows: Vec<EvidenceRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_evidence
        WHERE checklist_id = ?1 AND status = 'active'
        ORDER BY uploaded_at DESC
        "#,
    )
    .bind(checklist_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(evidence_from_row).collect())
}

/// List all evidence for a customer
pub async fn list_evidence_for_customer(pool: &SqlitePool, customer_id: &str) -> Result<Vec<ClientComplianceEvidence>> {
    let rows: Vec<EvidenceRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_evidence
        WHERE customer_id = ?1 AND status = 'active'
        ORDER BY uploaded_at DESC
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(evidence_from_row).collect())
}

/// Delete evidence (soft delete)
pub async fn delete_evidence(pool: &SqlitePool, id: &str, user_id: &str) -> Result<()> {
    let now = Utc::now();

    // Get evidence for history
    if let Some(evidence) = get_evidence(pool, id).await? {
        sqlx::query(
            "UPDATE client_compliance_evidence SET status = 'deleted', updated_at = ?1 WHERE id = ?2",
        )
        .bind(now.to_rfc3339())
        .bind(id)
        .execute(pool)
        .await?;

        add_history(
            pool,
            &evidence.checklist_id,
            Some(&evidence.item_id),
            user_id,
            "evidence_deleted",
            None,
            Some(&evidence.title),
            None,
            None,
        ).await?;
    }

    Ok(())
}

// ============================================================================
// History Functions
// ============================================================================

/// Add a history entry
pub async fn add_history(
    pool: &SqlitePool,
    checklist_id: &str,
    item_id: Option<&str>,
    user_id: &str,
    action: &str,
    field_name: Option<&str>,
    old_value: Option<&str>,
    new_value: Option<&str>,
    comment: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO client_compliance_history (
            id, checklist_id, item_id, user_id, action, field_name,
            old_value, new_value, comment, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
    )
    .bind(&id)
    .bind(checklist_id)
    .bind(item_id)
    .bind(user_id)
    .bind(action)
    .bind(field_name)
    .bind(old_value)
    .bind(new_value)
    .bind(comment)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get history for a checklist
pub async fn get_checklist_history(
    pool: &SqlitePool,
    checklist_id: &str,
    limit: i32,
) -> Result<Vec<ClientComplianceHistory>> {
    let rows: Vec<HistoryRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_history
        WHERE checklist_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2
        "#,
    )
    .bind(checklist_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(history_from_row).collect())
}

/// Get history for a specific item
pub async fn get_item_history(
    pool: &SqlitePool,
    item_id: &str,
    limit: i32,
) -> Result<Vec<ClientComplianceHistory>> {
    let rows: Vec<HistoryRow> = sqlx::query_as(
        r#"
        SELECT * FROM client_compliance_history
        WHERE item_id = ?1
        ORDER BY created_at DESC
        LIMIT ?2
        "#,
    )
    .bind(item_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(history_from_row).collect())
}

// ============================================================================
// Statistics Functions
// ============================================================================

/// Recalculate checklist statistics based on item states
pub async fn recalculate_checklist_stats(pool: &SqlitePool, checklist_id: &str) -> Result<()> {
    let now = Utc::now();

    // Get counts
    let (total, completed, compliant, non_compliant, not_applicable): (i32, i32, i32, i32, i32) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status IN ('compliant', 'non_compliant', 'not_applicable') THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant,
            SUM(CASE WHEN status = 'non_compliant' THEN 1 ELSE 0 END) as non_compliant,
            SUM(CASE WHEN status = 'not_applicable' THEN 1 ELSE 0 END) as not_applicable
        FROM client_compliance_items
        WHERE checklist_id = ?1
        "#,
    )
    .bind(checklist_id)
    .fetch_one(pool)
    .await?;

    // Calculate score (compliant / (total - not_applicable) * 100)
    let applicable = total - not_applicable;
    let score = if applicable > 0 {
        (compliant as f64 / applicable as f64) * 100.0
    } else {
        0.0
    };

    // Determine status
    let status = if completed == 0 {
        ChecklistStatus::NotStarted
    } else if completed == total {
        ChecklistStatus::Completed
    } else {
        ChecklistStatus::InProgress
    };

    sqlx::query(
        r#"
        UPDATE client_compliance_checklists
        SET total_controls = ?1,
            completed_controls = ?2,
            compliant_controls = ?3,
            non_compliant_controls = ?4,
            not_applicable_controls = ?5,
            overall_score = ?6,
            status = ?7,
            updated_at = ?8
        WHERE id = ?9
        "#,
    )
    .bind(total)
    .bind(completed)
    .bind(compliant)
    .bind(non_compliant)
    .bind(not_applicable)
    .bind(score)
    .bind(status.as_str())
    .bind(now.to_rfc3339())
    .bind(checklist_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get compliance summary for a customer across all checklists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerComplianceSummary {
    pub customer_id: String,
    pub total_checklists: i32,
    pub completed_checklists: i32,
    pub total_controls: i32,
    pub compliant_controls: i32,
    pub non_compliant_controls: i32,
    pub overall_score: f64,
    pub frameworks: Vec<FrameworkSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSummary {
    pub framework_id: String,
    pub checklist_count: i32,
    pub average_score: f64,
}

pub async fn get_customer_compliance_summary(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<CustomerComplianceSummary> {
    // Get aggregate stats
    let (total_checklists, completed_checklists, total_controls, compliant_controls, non_compliant_controls, avg_score): (i32, i32, i32, i32, i32, f64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total_checklists,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_checklists,
            SUM(total_controls) as total_controls,
            SUM(compliant_controls) as compliant_controls,
            SUM(non_compliant_controls) as non_compliant_controls,
            AVG(overall_score) as avg_score
        FROM client_compliance_checklists
        WHERE customer_id = ?1 AND status != 'archived'
        "#,
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    // Get per-framework stats
    let frameworks: Vec<(String, i32, f64)> = sqlx::query_as(
        r#"
        SELECT framework_id, COUNT(*) as count, AVG(overall_score) as avg_score
        FROM client_compliance_checklists
        WHERE customer_id = ?1 AND status != 'archived'
        GROUP BY framework_id
        "#,
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    Ok(CustomerComplianceSummary {
        customer_id: customer_id.to_string(),
        total_checklists,
        completed_checklists,
        total_controls,
        compliant_controls,
        non_compliant_controls,
        overall_score: avg_score,
        frameworks: frameworks.into_iter().map(|(fid, count, score)| FrameworkSummary {
            framework_id: fid,
            checklist_count: count,
            average_score: score,
        }).collect(),
    })
}

// ============================================================================
// Framework Control Population
// ============================================================================

/// Populate checklist with controls from a compliance framework
pub async fn populate_checklist_from_framework(
    pool: &SqlitePool,
    checklist_id: &str,
    framework_id: &str,
) -> Result<i32> {
    // Get controls from the compliance framework
    // This queries the existing compliance_controls table
    let controls: Vec<(String, String, Option<String>, Option<String>, i32)> = sqlx::query_as(
        r#"
        SELECT control_id, title, description, category, is_automated
        FROM compliance_controls
        WHERE framework_id = ?1
        ORDER BY category, control_id
        "#,
    )
    .bind(framework_id)
    .fetch_all(pool)
    .await?;

    let mut count = 0;
    for (control_id, title, description, category, is_automated) in controls {
        add_checklist_item(
            pool,
            checklist_id,
            &control_id,
            &title,
            description.as_deref(),
            category.as_deref(),
            is_automated != 0,
        ).await?;
        count += 1;
    }

    // Recalculate stats
    recalculate_checklist_stats(pool, checklist_id).await?;

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checklist_status_conversion() {
        assert_eq!(ChecklistStatus::NotStarted.as_str(), "not_started");
        assert_eq!(ChecklistStatus::InProgress.as_str(), "in_progress");
        assert_eq!(ChecklistStatus::Completed.as_str(), "completed");

        assert_eq!(ChecklistStatus::from_str("in_progress"), ChecklistStatus::InProgress);
        assert_eq!(ChecklistStatus::from_str("unknown"), ChecklistStatus::NotStarted);
    }

    #[test]
    fn test_control_status_conversion() {
        assert_eq!(ControlStatus::Compliant.as_str(), "compliant");
        assert_eq!(ControlStatus::NonCompliant.as_str(), "non_compliant");
        assert_eq!(ControlStatus::NotApplicable.as_str(), "not_applicable");

        assert_eq!(ControlStatus::from_str("compliant"), ControlStatus::Compliant);
        assert_eq!(ControlStatus::from_str("unknown"), ControlStatus::NotAssessed);
    }

    #[test]
    fn test_evidence_type_conversion() {
        assert_eq!(EvidenceType::Image.as_str(), "image");
        assert_eq!(EvidenceType::Document.as_str(), "document");

        assert_eq!(EvidenceType::from_str("image"), EvidenceType::Image);
        assert_eq!(EvidenceType::from_str("unknown"), EvidenceType::File);
    }
}
