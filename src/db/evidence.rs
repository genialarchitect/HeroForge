//! Database operations for compliance evidence collection
//!
//! This module provides CRUD operations for evidence records, control mappings,
//! and collection schedules.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::compliance::evidence::{
    CollectionSource, ControlEvidenceSummary, Evidence, EvidenceCollectionSchedule,
    EvidenceContent, EvidenceControlMapping, EvidenceListQuery, EvidenceMetadata, EvidenceStatus,
    EvidenceType, RetentionPolicy,
};

// ============================================================================
// Evidence CRUD Operations
// ============================================================================

/// Create a new evidence record
pub async fn create_evidence(pool: &SqlitePool, evidence: &Evidence) -> Result<String> {
    let id = if evidence.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        evidence.id.clone()
    };

    let evidence_type_json = serde_json::to_string(&evidence.evidence_type)?;
    let control_ids_json = serde_json::to_string(&evidence.control_ids)?;
    let framework_ids_json = serde_json::to_string(&evidence.framework_ids)?;
    let content_json = serde_json::to_string(&evidence.content)?;
    let collection_source_str = collection_source_to_str(&evidence.collection_source);
    let status_str = status_to_str(&evidence.status);
    let retention_policy_json = serde_json::to_string(&evidence.retention_policy)?;
    let metadata_json = serde_json::to_string(&evidence.metadata)?;

    sqlx::query(
        r#"
        INSERT INTO compliance_evidence (
            id, evidence_type, control_ids, framework_ids, title, description,
            content_hash, content, collection_source, status, version,
            previous_version_id, collected_at, collected_by, expires_at,
            retention_policy, metadata, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
        "#,
    )
    .bind(&id)
    .bind(&evidence_type_json)
    .bind(&control_ids_json)
    .bind(&framework_ids_json)
    .bind(&evidence.title)
    .bind(&evidence.description)
    .bind(&evidence.content_hash)
    .bind(&content_json)
    .bind(collection_source_str)
    .bind(status_str)
    .bind(evidence.version)
    .bind(&evidence.previous_version_id)
    .bind(evidence.collected_at)
    .bind(&evidence.collected_by)
    .bind(evidence.expires_at)
    .bind(&retention_policy_json)
    .bind(&metadata_json)
    .bind(evidence.created_at)
    .bind(evidence.updated_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get evidence by ID
pub async fn get_evidence(pool: &SqlitePool, id: &str) -> Result<Option<Evidence>> {
    let row: Option<EvidenceRow> = sqlx::query_as(
        "SELECT * FROM compliance_evidence WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(evidence_from_row(r)?)),
        None => Ok(None),
    }
}

/// List evidence with filters
pub async fn list_evidence(
    pool: &SqlitePool,
    _user_id: &str,
    query: &EvidenceListQuery,
) -> Result<(Vec<Evidence>, i64)> {
    let limit = query.limit.unwrap_or(50) as i64;
    let offset = query.offset.unwrap_or(0) as i64;

    // Build WHERE clause dynamically
    let mut where_clauses = vec!["1=1".to_string()];
    let mut params: Vec<String> = Vec::new();

    if let Some(ref control_id) = query.control_id {
        params.push(format!("%\"{}%", control_id));
        where_clauses.push(format!("control_ids LIKE ?{}", params.len()));
    }

    if let Some(ref framework_id) = query.framework_id {
        params.push(format!("%\"{}%", framework_id));
        where_clauses.push(format!("framework_ids LIKE ?{}", params.len()));
    }

    if let Some(ref evidence_type) = query.evidence_type {
        params.push(format!("%\"type\":\"{}%", evidence_type));
        where_clauses.push(format!("evidence_type LIKE ?{}", params.len()));
    }

    if let Some(ref status) = query.status {
        params.push(status.clone());
        where_clauses.push(format!("status = ?{}", params.len()));
    }

    if let Some(ref source) = query.collection_source {
        params.push(source.clone());
        where_clauses.push(format!("collection_source = ?{}", params.len()));
    }

    if !query.include_expired {
        where_clauses.push("(expires_at IS NULL OR expires_at > datetime('now'))".to_string());
    }

    if !query.include_superseded {
        where_clauses.push("status != 'superseded'".to_string());
    }

    let where_sql = where_clauses.join(" AND ");

    // Get total count - use a simpler query without dynamic binding
    let count_query = format!(
        "SELECT COUNT(*) FROM compliance_evidence WHERE {}",
        where_sql
    );
    let total: (i64,) = sqlx::query_as(&count_query)
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    // Get paginated results
    let select_query = format!(
        r#"
        SELECT * FROM compliance_evidence
        WHERE {}
        ORDER BY created_at DESC
        LIMIT {} OFFSET {}
        "#,
        where_sql, limit, offset
    );

    let rows: Vec<EvidenceRow> = sqlx::query_as(&select_query)
        .fetch_all(pool)
        .await?;

    let evidence: Result<Vec<Evidence>> = rows.into_iter().map(evidence_from_row).collect();

    Ok((evidence?, total.0))
}

/// Update evidence record
pub async fn update_evidence(pool: &SqlitePool, id: &str, evidence: &Evidence) -> Result<()> {
    let now = Utc::now();

    let evidence_type_json = serde_json::to_string(&evidence.evidence_type)?;
    let control_ids_json = serde_json::to_string(&evidence.control_ids)?;
    let framework_ids_json = serde_json::to_string(&evidence.framework_ids)?;
    let content_json = serde_json::to_string(&evidence.content)?;
    let status_str = status_to_str(&evidence.status);
    let retention_policy_json = serde_json::to_string(&evidence.retention_policy)?;
    let metadata_json = serde_json::to_string(&evidence.metadata)?;

    sqlx::query(
        r#"
        UPDATE compliance_evidence
        SET evidence_type = ?1, control_ids = ?2, framework_ids = ?3, title = ?4,
            description = ?5, content_hash = ?6, content = ?7, status = ?8,
            expires_at = ?9, retention_policy = ?10, metadata = ?11, updated_at = ?12
        WHERE id = ?13
        "#,
    )
    .bind(&evidence_type_json)
    .bind(&control_ids_json)
    .bind(&framework_ids_json)
    .bind(&evidence.title)
    .bind(&evidence.description)
    .bind(&evidence.content_hash)
    .bind(&content_json)
    .bind(status_str)
    .bind(evidence.expires_at)
    .bind(&retention_policy_json)
    .bind(&metadata_json)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update evidence status
pub async fn update_evidence_status(
    pool: &SqlitePool,
    id: &str,
    status: EvidenceStatus,
) -> Result<()> {
    let now = Utc::now();
    let status_str = status_to_str(&status);

    sqlx::query(
        "UPDATE compliance_evidence SET status = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(status_str)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete evidence by ID
pub async fn delete_evidence(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete control mappings first
    sqlx::query("DELETE FROM evidence_control_mapping WHERE evidence_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    // Delete evidence
    sqlx::query("DELETE FROM compliance_evidence WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get evidence version history
pub async fn get_evidence_history(pool: &SqlitePool, evidence_id: &str) -> Result<Vec<Evidence>> {
    // First get the evidence to find the chain
    let mut history = Vec::new();
    let mut current_id = Some(evidence_id.to_string());

    while let Some(ref id) = current_id {
        if let Some(evidence) = get_evidence(pool, id).await? {
            current_id = evidence.previous_version_id.clone();
            history.push(evidence);
        } else {
            break;
        }
    }

    // Reverse to get oldest first
    history.reverse();
    Ok(history)
}

// ============================================================================
// Evidence Control Mapping Operations
// ============================================================================

/// Create evidence-control mapping
pub async fn create_control_mapping(
    pool: &SqlitePool,
    mapping: &EvidenceControlMapping,
) -> Result<String> {
    let id = if mapping.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        mapping.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO evidence_control_mapping (
            id, evidence_id, control_id, framework_id, coverage_score,
            notes, created_at, created_by
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(&mapping.evidence_id)
    .bind(&mapping.control_id)
    .bind(&mapping.framework_id)
    .bind(mapping.coverage_score)
    .bind(&mapping.notes)
    .bind(mapping.created_at)
    .bind(&mapping.created_by)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get mappings for a control
pub async fn get_mappings_for_control(
    pool: &SqlitePool,
    framework_id: &str,
    control_id: &str,
) -> Result<Vec<EvidenceControlMapping>> {
    let rows: Vec<MappingRow> = sqlx::query_as(
        r#"
        SELECT * FROM evidence_control_mapping
        WHERE framework_id = ?1 AND control_id = ?2
        ORDER BY created_at DESC
        "#,
    )
    .bind(framework_id)
    .bind(control_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(mapping_from_row).collect())
}

/// Get evidence for a control
pub async fn get_evidence_for_control(
    pool: &SqlitePool,
    framework_id: &str,
    control_id: &str,
) -> Result<Vec<Evidence>> {
    let rows: Vec<EvidenceRow> = sqlx::query_as(
        r#"
        SELECT ce.* FROM compliance_evidence ce
        INNER JOIN evidence_control_mapping ecm ON ce.id = ecm.evidence_id
        WHERE ecm.framework_id = ?1 AND ecm.control_id = ?2
        AND ce.status IN ('active', 'approved', 'pending_review')
        ORDER BY ce.created_at DESC
        "#,
    )
    .bind(framework_id)
    .bind(control_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(evidence_from_row).collect()
}

/// Get control evidence summary
pub async fn get_control_evidence_summary(
    pool: &SqlitePool,
    framework_id: &str,
    control_id: &str,
) -> Result<ControlEvidenceSummary> {
    let counts: (i32, i32, Option<String>, Option<f64>) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN ce.status IN ('active', 'approved') THEN 1 ELSE 0 END) as active,
            MAX(ce.collected_at) as latest,
            AVG(ecm.coverage_score) as avg_coverage
        FROM evidence_control_mapping ecm
        INNER JOIN compliance_evidence ce ON ecm.evidence_id = ce.id
        WHERE ecm.framework_id = ?1 AND ecm.control_id = ?2
        "#,
    )
    .bind(framework_id)
    .bind(control_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0, 0, None, None));

    let latest_collection = counts.2.and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    });

    let days_since = latest_collection.map(|d| {
        (Utc::now() - d).num_days() as i32
    });

    // Consider evidence current if collected within last 90 days
    let is_current = days_since.map(|d| d < 90).unwrap_or(false);

    Ok(ControlEvidenceSummary {
        control_id: control_id.to_string(),
        framework_id: framework_id.to_string(),
        total_evidence: counts.0,
        active_evidence: counts.1,
        latest_collection,
        coverage_score: counts.3.unwrap_or(0.0) as f32,
        is_current,
        days_since_collection: days_since,
    })
}

/// Delete control mapping
pub async fn delete_control_mapping(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM evidence_control_mapping WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// List all control mappings with optional filters
pub async fn list_all_mappings(
    pool: &SqlitePool,
    framework_id: Option<&str>,
    control_id: Option<&str>,
    evidence_id: Option<&str>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<EvidenceControlMapping>> {
    let limit = limit.unwrap_or(100) as i64;
    let offset = offset.unwrap_or(0) as i64;

    // Build dynamic WHERE clause
    let mut conditions = vec!["1=1".to_string()];
    let mut param_idx = 1;

    if framework_id.is_some() {
        conditions.push(format!("framework_id = ?{}", param_idx));
        param_idx += 1;
    }
    if control_id.is_some() {
        conditions.push(format!("control_id = ?{}", param_idx));
        param_idx += 1;
    }
    if evidence_id.is_some() {
        conditions.push(format!("evidence_id = ?{}", param_idx));
    }

    let where_clause = conditions.join(" AND ");

    let query = format!(
        r#"
        SELECT * FROM evidence_control_mapping
        WHERE {}
        ORDER BY created_at DESC
        LIMIT {} OFFSET {}
        "#,
        where_clause, limit, offset
    );

    // Execute query with appropriate parameters
    let rows: Vec<MappingRow> = match (framework_id, control_id, evidence_id) {
        (Some(f), Some(c), Some(e)) => {
            sqlx::query_as(&query)
                .bind(f)
                .bind(c)
                .bind(e)
                .fetch_all(pool)
                .await?
        }
        (Some(f), Some(c), None) => {
            sqlx::query_as(&query)
                .bind(f)
                .bind(c)
                .fetch_all(pool)
                .await?
        }
        (Some(f), None, Some(e)) => {
            sqlx::query_as(&query)
                .bind(f)
                .bind(e)
                .fetch_all(pool)
                .await?
        }
        (None, Some(c), Some(e)) => {
            sqlx::query_as(&query)
                .bind(c)
                .bind(e)
                .fetch_all(pool)
                .await?
        }
        (Some(f), None, None) => {
            sqlx::query_as(&query)
                .bind(f)
                .fetch_all(pool)
                .await?
        }
        (None, Some(c), None) => {
            sqlx::query_as(&query)
                .bind(c)
                .fetch_all(pool)
                .await?
        }
        (None, None, Some(e)) => {
            sqlx::query_as(&query)
                .bind(e)
                .fetch_all(pool)
                .await?
        }
        (None, None, None) => {
            sqlx::query_as(&query)
                .fetch_all(pool)
                .await?
        }
    };

    Ok(rows.into_iter().map(mapping_from_row).collect())
}

// ============================================================================
// Collection Schedule Operations
// ============================================================================

/// Create collection schedule
pub async fn create_collection_schedule(
    pool: &SqlitePool,
    schedule: &EvidenceCollectionSchedule,
) -> Result<String> {
    let id = if schedule.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        schedule.id.clone()
    };

    let collection_source_str = collection_source_to_str(&schedule.collection_source);
    let control_ids_json = serde_json::to_string(&schedule.control_ids)?;
    let framework_ids_json = serde_json::to_string(&schedule.framework_ids)?;
    let config_json = serde_json::to_string(&schedule.config)?;

    sqlx::query(
        r#"
        INSERT INTO evidence_collection_schedule (
            id, user_id, name, description, collection_source, cron_expression,
            control_ids, framework_ids, enabled, last_run_at, next_run_at,
            config, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(&schedule.user_id)
    .bind(&schedule.name)
    .bind(&schedule.description)
    .bind(collection_source_str)
    .bind(&schedule.cron_expression)
    .bind(&control_ids_json)
    .bind(&framework_ids_json)
    .bind(schedule.enabled)
    .bind(schedule.last_run_at)
    .bind(schedule.next_run_at)
    .bind(&config_json)
    .bind(schedule.created_at)
    .bind(schedule.updated_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get collection schedule by ID
pub async fn get_collection_schedule(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<EvidenceCollectionSchedule>> {
    let row: Option<ScheduleRow> = sqlx::query_as(
        "SELECT * FROM evidence_collection_schedule WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(schedule_from_row(r)?)),
        None => Ok(None),
    }
}

/// List collection schedules for user
pub async fn list_collection_schedules(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<EvidenceCollectionSchedule>> {
    let rows: Vec<ScheduleRow> = sqlx::query_as(
        r#"
        SELECT * FROM evidence_collection_schedule
        WHERE user_id = ?1
        ORDER BY name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(schedule_from_row).collect()
}

/// Get due collection schedules
pub async fn get_due_schedules(pool: &SqlitePool) -> Result<Vec<EvidenceCollectionSchedule>> {
    let now = Utc::now();

    let rows: Vec<ScheduleRow> = sqlx::query_as(
        r#"
        SELECT * FROM evidence_collection_schedule
        WHERE enabled = 1
        AND (next_run_at IS NULL OR next_run_at <= ?1)
        "#,
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(schedule_from_row).collect()
}

/// Update schedule after run
pub async fn update_schedule_after_run(
    pool: &SqlitePool,
    id: &str,
    next_run_at: DateTime<Utc>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE evidence_collection_schedule
        SET last_run_at = ?1, next_run_at = ?2, updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind(now)
    .bind(next_run_at)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update collection schedule
pub async fn update_collection_schedule(
    pool: &SqlitePool,
    schedule: &EvidenceCollectionSchedule,
) -> Result<()> {
    let now = Utc::now();

    let collection_source_str = collection_source_to_str(&schedule.collection_source);
    let control_ids_json = serde_json::to_string(&schedule.control_ids)?;
    let framework_ids_json = serde_json::to_string(&schedule.framework_ids)?;
    let config_json = serde_json::to_string(&schedule.config)?;

    sqlx::query(
        r#"
        UPDATE evidence_collection_schedule
        SET name = ?1, description = ?2, collection_source = ?3, cron_expression = ?4,
            control_ids = ?5, framework_ids = ?6, enabled = ?7,
            next_run_at = ?8, config = ?9, updated_at = ?10
        WHERE id = ?11
        "#,
    )
    .bind(&schedule.name)
    .bind(&schedule.description)
    .bind(collection_source_str)
    .bind(&schedule.cron_expression)
    .bind(&control_ids_json)
    .bind(&framework_ids_json)
    .bind(schedule.enabled)
    .bind(schedule.next_run_at)
    .bind(&config_json)
    .bind(now)
    .bind(&schedule.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete collection schedule
pub async fn delete_collection_schedule(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM evidence_collection_schedule WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Helper Types and Conversions
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct EvidenceRow {
    id: String,
    evidence_type: String,
    control_ids: String,
    framework_ids: String,
    title: String,
    description: Option<String>,
    content_hash: String,
    content: String,
    collection_source: String,
    status: String,
    version: i32,
    previous_version_id: Option<String>,
    collected_at: String,
    collected_by: String,
    expires_at: Option<String>,
    retention_policy: String,
    metadata: String,
    created_at: String,
    updated_at: String,
}

fn evidence_from_row(row: EvidenceRow) -> Result<Evidence> {
    let evidence_type: EvidenceType = serde_json::from_str(&row.evidence_type)?;
    let control_ids: Vec<String> = serde_json::from_str(&row.control_ids)?;
    let framework_ids: Vec<String> = serde_json::from_str(&row.framework_ids)?;
    let content: EvidenceContent = serde_json::from_str(&row.content)?;
    let collection_source = str_to_collection_source(&row.collection_source);
    let status = str_to_status(&row.status);
    let retention_policy: RetentionPolicy = serde_json::from_str(&row.retention_policy)?;
    let metadata: EvidenceMetadata = serde_json::from_str(&row.metadata)?;

    let collected_at = chrono::DateTime::parse_from_rfc3339(&row.collected_at)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let expires_at = row.expires_at.and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    });
    let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = chrono::DateTime::parse_from_rfc3339(&row.updated_at)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(Evidence {
        id: row.id,
        evidence_type,
        control_ids,
        framework_ids,
        title: row.title,
        description: row.description,
        content_hash: row.content_hash,
        content,
        collection_source,
        status,
        version: row.version,
        previous_version_id: row.previous_version_id,
        collected_at,
        collected_by: row.collected_by,
        expires_at,
        retention_policy,
        metadata,
        created_at,
        updated_at,
    })
}

#[derive(Debug, sqlx::FromRow)]
struct MappingRow {
    id: String,
    evidence_id: String,
    control_id: String,
    framework_id: String,
    coverage_score: f64,
    notes: Option<String>,
    created_at: String,
    created_by: String,
}

fn mapping_from_row(row: MappingRow) -> EvidenceControlMapping {
    let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    EvidenceControlMapping {
        id: row.id,
        evidence_id: row.evidence_id,
        control_id: row.control_id,
        framework_id: row.framework_id,
        coverage_score: row.coverage_score as f32,
        notes: row.notes,
        created_at,
        created_by: row.created_by,
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ScheduleRow {
    id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    collection_source: String,
    cron_expression: String,
    control_ids: String,
    framework_ids: String,
    enabled: bool,
    last_run_at: Option<String>,
    next_run_at: Option<String>,
    config: String,
    created_at: String,
    updated_at: String,
}

fn schedule_from_row(row: ScheduleRow) -> Result<EvidenceCollectionSchedule> {
    let collection_source = str_to_collection_source(&row.collection_source);
    let control_ids: Vec<String> = serde_json::from_str(&row.control_ids)?;
    let framework_ids: Vec<String> = serde_json::from_str(&row.framework_ids)?;
    let config: serde_json::Value = serde_json::from_str(&row.config)?;

    let last_run_at = row.last_run_at.and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    });
    let next_run_at = row.next_run_at.and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    });
    let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = chrono::DateTime::parse_from_rfc3339(&row.updated_at)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(EvidenceCollectionSchedule {
        id: row.id,
        user_id: row.user_id,
        name: row.name,
        description: row.description,
        collection_source,
        cron_expression: row.cron_expression,
        control_ids,
        framework_ids,
        enabled: row.enabled,
        last_run_at,
        next_run_at,
        config,
        created_at,
        updated_at,
    })
}

fn collection_source_to_str(source: &CollectionSource) -> &'static str {
    match source {
        CollectionSource::AutomatedScan => "automated_scan",
        CollectionSource::ScheduledCollection => "scheduled_collection",
        CollectionSource::ManualUpload => "manual_upload",
        CollectionSource::ExternalImport => "external_import",
        CollectionSource::ApiIntegration => "api_integration",
        CollectionSource::Derived => "derived",
    }
}

fn str_to_collection_source(s: &str) -> CollectionSource {
    match s {
        "automated_scan" => CollectionSource::AutomatedScan,
        "scheduled_collection" => CollectionSource::ScheduledCollection,
        "manual_upload" => CollectionSource::ManualUpload,
        "external_import" => CollectionSource::ExternalImport,
        "api_integration" => CollectionSource::ApiIntegration,
        "derived" => CollectionSource::Derived,
        _ => CollectionSource::ManualUpload,
    }
}

fn status_to_str(status: &EvidenceStatus) -> &'static str {
    match status {
        EvidenceStatus::Active => "active",
        EvidenceStatus::Superseded => "superseded",
        EvidenceStatus::Archived => "archived",
        EvidenceStatus::PendingReview => "pending_review",
        EvidenceStatus::Approved => "approved",
        EvidenceStatus::Rejected => "rejected",
    }
}

fn str_to_status(s: &str) -> EvidenceStatus {
    match s {
        "active" => EvidenceStatus::Active,
        "superseded" => EvidenceStatus::Superseded,
        "archived" => EvidenceStatus::Archived,
        "pending_review" => EvidenceStatus::PendingReview,
        "approved" => EvidenceStatus::Approved,
        "rejected" => EvidenceStatus::Rejected,
        _ => EvidenceStatus::Active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collection_source_conversion() {
        assert_eq!(
            collection_source_to_str(&CollectionSource::AutomatedScan),
            "automated_scan"
        );
        assert_eq!(
            str_to_collection_source("automated_scan"),
            CollectionSource::AutomatedScan
        );
        assert_eq!(
            str_to_collection_source("unknown"),
            CollectionSource::ManualUpload
        );
    }

    #[test]
    fn test_status_conversion() {
        assert_eq!(status_to_str(&EvidenceStatus::Active), "active");
        assert_eq!(status_to_str(&EvidenceStatus::Superseded), "superseded");
        assert_eq!(str_to_status("active"), EvidenceStatus::Active);
        assert_eq!(str_to_status("unknown"), EvidenceStatus::Active);
    }
}
