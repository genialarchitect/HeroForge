//! Case management for security incidents and investigations
//!
//! Provides comprehensive case management with SQLite persistence:
//! - Case lifecycle management
//! - Task assignment and tracking
//! - Evidence collection and chain of custody
//! - Timeline reconstruction

use crate::green_team::types::*;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

/// Case management engine with SQLite persistence
pub struct CaseManager {
    pool: SqlitePool,
}

impl CaseManager {
    /// Create a new case manager with database persistence
    pub async fn new(pool: SqlitePool) -> Self {
        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS soar_cases (
                id TEXT PRIMARY KEY,
                case_number TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                priority TEXT NOT NULL,
                case_type TEXT NOT NULL,
                assignee_id TEXT,
                source TEXT,
                source_ref TEXT,
                tlp TEXT NOT NULL DEFAULT 'amber',
                tags TEXT NOT NULL DEFAULT '[]',
                resolution TEXT,
                resolution_time_hours REAL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                closed_at TEXT
            )"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS case_tasks (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                priority TEXT NOT NULL,
                assignee_id TEXT,
                due_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES soar_cases(id)
            )"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS case_evidence (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                hash_sha256 TEXT,
                metadata TEXT,
                collected_by TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES soar_cases(id)
            )"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS case_comments (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                content TEXT NOT NULL,
                is_internal INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES soar_cases(id)
            )"
        ).execute(&pool).await;

        let _ = sqlx::query(
            "CREATE TABLE IF NOT EXISTS case_timeline (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                user_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES soar_cases(id)
            )"
        ).execute(&pool).await;

        Self { pool }
    }

    /// Create a new case
    pub async fn create_case(&self, request: CreateCaseRequest) -> Result<SoarCase, String> {
        // Get next case number
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);
        let case_number = format!("CASE-{:05}", count + 1);
        let now = Utc::now();
        let id = Uuid::new_v4();
        let tags_json = serde_json::to_string(&request.tags.clone().unwrap_or_default()).unwrap_or_else(|_| "[]".to_string());
        let tlp = request.tlp.clone().unwrap_or(Tlp::Amber);

        let case = SoarCase {
            id,
            case_number: case_number.clone(),
            title: request.title.clone(),
            description: request.description.clone(),
            severity: request.severity.clone(),
            status: CaseStatus::Open,
            priority: request.priority.clone(),
            case_type: request.case_type.clone(),
            assignee_id: request.assignee_id,
            source: request.source.clone(),
            source_ref: request.source_ref.clone(),
            tlp: tlp.clone(),
            tags: request.tags.clone().unwrap_or_default(),
            resolution: None,
            resolution_time_hours: None,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
            resolved_at: None,
            closed_at: None,
        };

        sqlx::query(
            "INSERT INTO soar_cases (id, case_number, title, description, severity, status, priority, case_type, assignee_id, source, source_ref, tlp, tags, created_by, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"
        )
        .bind(id.to_string())
        .bind(&case_number)
        .bind(&request.title)
        .bind(&request.description)
        .bind(request.severity.to_string())
        .bind("open")
        .bind(request.priority.to_string())
        .bind(request.case_type.to_string())
        .bind(request.assignee_id.map(|u| u.to_string()))
        .bind(&request.source)
        .bind(&request.source_ref)
        .bind(tlp.to_string())
        .bind(&tags_json)
        .bind(request.created_by.to_string())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        // Add creation event to timeline
        self.add_timeline_event(id, TimelineEventType::Created, serde_json::json!({
            "case_number": case_number,
            "severity": case.severity.to_string(),
            "case_type": case.case_type.to_string()
        }), Some(request.created_by)).await;

        Ok(case)
    }

    /// Get a case by ID
    pub async fn get_case(&self, id: &Uuid) -> Option<SoarCase> {
        let row = sqlx::query_as::<_, CaseRow>(
            "SELECT id, case_number, title, description, severity, status, priority, case_type, assignee_id, source, source_ref, tlp, tags, resolution, resolution_time_hours, created_by, created_at, updated_at, resolved_at, closed_at
             FROM soar_cases WHERE id = ?1"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        row.into_case().ok()
    }

    /// Get a case by case number
    pub async fn get_case_by_number(&self, case_number: &str) -> Option<SoarCase> {
        let row = sqlx::query_as::<_, CaseRow>(
            "SELECT id, case_number, title, description, severity, status, priority, case_type, assignee_id, source, source_ref, tlp, tags, resolution, resolution_time_hours, created_by, created_at, updated_at, resolved_at, closed_at
             FROM soar_cases WHERE case_number = ?1"
        )
        .bind(case_number)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()?;

        row.into_case().ok()
    }

    /// List all cases with optional filter
    pub async fn list_cases(&self, filter: Option<CaseFilter>) -> Vec<SoarCase> {
        let mut query = "SELECT id, case_number, title, description, severity, status, priority, case_type, assignee_id, source, source_ref, tlp, tags, resolution, resolution_time_hours, created_by, created_at, updated_at, resolved_at, closed_at FROM soar_cases WHERE 1=1".to_string();

        let mut binds: Vec<String> = Vec::new();

        if let Some(ref f) = filter {
            if let Some(ref status) = f.status {
                binds.push(status.to_string());
                query.push_str(&format!(" AND status = ?{}", binds.len()));
            }
            if let Some(ref severity) = f.severity {
                binds.push(severity.to_string());
                query.push_str(&format!(" AND severity = ?{}", binds.len()));
            }
            if let Some(ref assignee_id) = f.assignee_id {
                binds.push(assignee_id.to_string());
                query.push_str(&format!(" AND assignee_id = ?{}", binds.len()));
            }
            if let Some(ref case_type) = f.case_type {
                binds.push(case_type.to_string());
                query.push_str(&format!(" AND case_type = ?{}", binds.len()));
            }
        }

        query.push_str(" ORDER BY created_at DESC");

        // Build the query dynamically
        let mut q = sqlx::query_as::<_, CaseRow>(&query);
        for b in &binds {
            q = q.bind(b);
        }

        let rows = q.fetch_all(&self.pool).await.unwrap_or_default();
        rows.into_iter().filter_map(|r| r.into_case().ok()).collect()
    }

    /// Update case status
    pub async fn update_status(&self, case_id: &Uuid, status: CaseStatus, user_id: Uuid) -> Result<(), String> {
        let case = self.get_case(case_id).await.ok_or("Case not found")?;
        let old_status = case.status.clone();
        let now = Utc::now();

        let mut resolved_at: Option<String> = None;
        let mut resolution_time: Option<f64> = None;
        let mut closed_at: Option<String> = None;

        if status == CaseStatus::Resolved {
            resolved_at = Some(now.to_rfc3339());
            let duration = now - case.created_at;
            resolution_time = Some(duration.num_minutes() as f64 / 60.0);
        } else if status == CaseStatus::Closed {
            closed_at = Some(now.to_rfc3339());
        }

        sqlx::query(
            "UPDATE soar_cases SET status = ?1, updated_at = ?2, resolved_at = COALESCE(?3, resolved_at), resolution_time_hours = COALESCE(?4, resolution_time_hours), closed_at = COALESCE(?5, closed_at)
             WHERE id = ?6"
        )
        .bind(status.to_string())
        .bind(now.to_rfc3339())
        .bind(&resolved_at)
        .bind(resolution_time)
        .bind(&closed_at)
        .bind(case_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        self.add_timeline_event(*case_id, TimelineEventType::StatusChange, serde_json::json!({
            "old_status": old_status.to_string(),
            "new_status": status.to_string()
        }), Some(user_id)).await;

        Ok(())
    }

    /// Assign case to user
    pub async fn assign_case(&self, case_id: &Uuid, assignee_id: Uuid, assigned_by: Uuid) -> Result<(), String> {
        let case = self.get_case(case_id).await.ok_or("Case not found")?;
        let old_assignee = case.assignee_id;

        sqlx::query("UPDATE soar_cases SET assignee_id = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(assignee_id.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(case_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        self.add_timeline_event(*case_id, TimelineEventType::Assignment, serde_json::json!({
            "old_assignee": old_assignee.map(|u| u.to_string()),
            "new_assignee": assignee_id.to_string()
        }), Some(assigned_by)).await;

        Ok(())
    }

    /// Resolve a case
    pub async fn resolve_case(&self, case_id: &Uuid, resolution: String, user_id: Uuid) -> Result<(), String> {
        let case = self.get_case(case_id).await.ok_or("Case not found")?;
        let now = Utc::now();
        let duration = now - case.created_at;
        let resolution_time = duration.num_minutes() as f64 / 60.0;

        sqlx::query(
            "UPDATE soar_cases SET status = 'resolved', resolution = ?1, resolved_at = ?2, resolution_time_hours = ?3, updated_at = ?4
             WHERE id = ?5"
        )
        .bind(&resolution)
        .bind(now.to_rfc3339())
        .bind(resolution_time)
        .bind(now.to_rfc3339())
        .bind(case_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        self.add_timeline_event(*case_id, TimelineEventType::Resolution, serde_json::json!({
            "resolution": resolution
        }), Some(user_id)).await;

        Ok(())
    }

    // Task Management

    /// Add a task to a case
    pub async fn add_task(&self, case_id: &Uuid, request: CreateTaskRequest) -> Result<CaseTask, String> {
        if self.get_case(case_id).await.is_none() {
            return Err("Case not found".to_string());
        }

        let task = CaseTask {
            id: Uuid::new_v4(),
            case_id: *case_id,
            title: request.title.clone(),
            description: request.description.clone(),
            status: TaskStatus::Pending,
            priority: request.priority.clone(),
            assignee_id: request.assignee_id,
            due_at: request.due_at,
            completed_at: None,
            created_at: Utc::now(),
        };

        sqlx::query(
            "INSERT INTO case_tasks (id, case_id, title, description, status, priority, assignee_id, due_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        )
        .bind(task.id.to_string())
        .bind(case_id.to_string())
        .bind(&task.title)
        .bind(&task.description)
        .bind(task.status.to_string())
        .bind(task.priority.to_string())
        .bind(task.assignee_id.map(|u| u.to_string()))
        .bind(task.due_at.map(|d| d.to_rfc3339()))
        .bind(task.created_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        self.add_timeline_event(*case_id, TimelineEventType::Task, serde_json::json!({
            "task_id": task.id.to_string(),
            "action": "created",
            "title": task.title.clone()
        }), request.assignee_id).await;

        Ok(task)
    }

    /// Get tasks for a case
    pub async fn get_tasks(&self, case_id: &Uuid) -> Vec<CaseTask> {
        let rows = sqlx::query_as::<_, TaskRow>(
            "SELECT id, case_id, title, description, status, priority, assignee_id, due_at, completed_at, created_at
             FROM case_tasks WHERE case_id = ?1 ORDER BY created_at"
        )
        .bind(case_id.to_string())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_task().ok()).collect()
    }

    /// Update task status
    pub async fn update_task_status(&self, case_id: &Uuid, task_id: &Uuid, status: TaskStatus) -> Result<(), String> {
        let completed_at = if status == TaskStatus::Completed {
            Some(Utc::now().to_rfc3339())
        } else {
            None
        };

        let result = sqlx::query(
            "UPDATE case_tasks SET status = ?1, completed_at = COALESCE(?2, completed_at)
             WHERE id = ?3 AND case_id = ?4"
        )
        .bind(status.to_string())
        .bind(&completed_at)
        .bind(task_id.to_string())
        .bind(case_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        if result.rows_affected() == 0 {
            return Err("Task not found".to_string());
        }

        Ok(())
    }

    // Evidence Management

    /// Add evidence to a case
    pub async fn add_evidence(&self, case_id: &Uuid, request: AddEvidenceRequest) -> Result<CaseEvidence, String> {
        if self.get_case(case_id).await.is_none() {
            return Err("Case not found".to_string());
        }

        let evidence = CaseEvidence {
            id: Uuid::new_v4(),
            case_id: *case_id,
            evidence_type: request.evidence_type.clone(),
            name: request.name.clone(),
            description: request.description.clone(),
            file_path: request.file_path.clone(),
            hash_sha256: request.hash_sha256.clone(),
            metadata: request.metadata.clone(),
            collected_by: request.collected_by,
            collected_at: Utc::now(),
        };

        let metadata_json = request.metadata.as_ref().map(|m| serde_json::to_string(m).unwrap_or_default());

        sqlx::query(
            "INSERT INTO case_evidence (id, case_id, evidence_type, name, description, file_path, hash_sha256, metadata, collected_by, collected_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
        .bind(evidence.id.to_string())
        .bind(case_id.to_string())
        .bind(evidence.evidence_type.to_string())
        .bind(&evidence.name)
        .bind(&evidence.description)
        .bind(&evidence.file_path)
        .bind(&evidence.hash_sha256)
        .bind(&metadata_json)
        .bind(evidence.collected_by.to_string())
        .bind(evidence.collected_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        self.add_timeline_event(*case_id, TimelineEventType::Evidence, serde_json::json!({
            "evidence_id": evidence.id.to_string(),
            "name": evidence.name.clone(),
            "evidence_type": evidence.evidence_type.to_string()
        }), Some(request.collected_by)).await;

        Ok(evidence)
    }

    /// Get evidence for a case
    pub async fn get_evidence(&self, case_id: &Uuid) -> Vec<CaseEvidence> {
        let rows = sqlx::query_as::<_, EvidenceRow>(
            "SELECT id, case_id, evidence_type, name, description, file_path, hash_sha256, metadata, collected_by, collected_at
             FROM case_evidence WHERE case_id = ?1 ORDER BY collected_at"
        )
        .bind(case_id.to_string())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_evidence().ok()).collect()
    }

    // Comments

    /// Add a comment to a case
    pub async fn add_comment(&self, case_id: &Uuid, user_id: Uuid, content: String, is_internal: bool) -> Result<CaseComment, String> {
        if self.get_case(case_id).await.is_none() {
            return Err("Case not found".to_string());
        }

        let comment = CaseComment {
            id: Uuid::new_v4(),
            case_id: *case_id,
            user_id,
            content: content.clone(),
            is_internal,
            created_at: Utc::now(),
        };

        sqlx::query(
            "INSERT INTO case_comments (id, case_id, user_id, content, is_internal, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(comment.id.to_string())
        .bind(case_id.to_string())
        .bind(user_id.to_string())
        .bind(&content)
        .bind(is_internal)
        .bind(comment.created_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        self.add_timeline_event(*case_id, TimelineEventType::Comment, serde_json::json!({
            "comment_id": comment.id.to_string(),
            "is_internal": is_internal
        }), Some(user_id)).await;

        Ok(comment)
    }

    /// Get comments for a case
    pub async fn get_comments(&self, case_id: &Uuid) -> Vec<CaseComment> {
        let rows = sqlx::query_as::<_, CommentRow>(
            "SELECT id, case_id, user_id, content, is_internal, created_at
             FROM case_comments WHERE case_id = ?1 ORDER BY created_at"
        )
        .bind(case_id.to_string())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_comment().ok()).collect()
    }

    // Timeline

    /// Add an event to the case timeline
    async fn add_timeline_event(
        &self,
        case_id: Uuid,
        event_type: TimelineEventType,
        event_data: serde_json::Value,
        user_id: Option<Uuid>,
    ) {
        let id = Uuid::new_v4();
        let event_type_str = format!("{:?}", event_type).to_lowercase();
        let data_json = serde_json::to_string(&event_data).unwrap_or_else(|_| "{}".to_string());

        let _ = sqlx::query(
            "INSERT INTO case_timeline (id, case_id, event_type, event_data, user_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(id.to_string())
        .bind(case_id.to_string())
        .bind(&event_type_str)
        .bind(&data_json)
        .bind(user_id.map(|u| u.to_string()))
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await;
    }

    /// Get timeline for a case
    pub async fn get_timeline(&self, case_id: &Uuid) -> Vec<CaseTimelineEvent> {
        let rows = sqlx::query_as::<_, TimelineRow>(
            "SELECT id, case_id, event_type, event_data, user_id, created_at
             FROM case_timeline WHERE case_id = ?1 ORDER BY created_at"
        )
        .bind(case_id.to_string())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.into_iter().filter_map(|r| r.into_event().ok()).collect()
    }

    // Statistics

    /// Get case statistics
    pub async fn get_statistics(&self) -> CaseStatistics {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases")
            .fetch_one(&self.pool).await.unwrap_or(0);
        let open: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'open'")
            .fetch_one(&self.pool).await.unwrap_or(0);
        let in_progress: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'in_progress'")
            .fetch_one(&self.pool).await.unwrap_or(0);
        let resolved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'resolved'")
            .fetch_one(&self.pool).await.unwrap_or(0);
        let closed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM soar_cases WHERE status = 'closed'")
            .fetch_one(&self.pool).await.unwrap_or(0);

        let avg_resolution_time: f64 = sqlx::query_scalar(
            "SELECT COALESCE(AVG(resolution_time_hours), 0.0) FROM soar_cases WHERE resolved_at IS NOT NULL"
        ).fetch_one(&self.pool).await.unwrap_or(0.0);

        let mut by_severity = HashMap::new();
        for sev in &["critical", "high", "medium", "low"] {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM soar_cases WHERE severity = ?1 AND status != 'closed'"
            )
            .bind(sev)
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);

            let severity = match *sev {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                _ => Severity::Low,
            };
            by_severity.insert(severity, count as usize);
        }

        CaseStatistics {
            total: total as usize,
            open: open as usize,
            in_progress: in_progress as usize,
            resolved: resolved as usize,
            closed: closed as usize,
            avg_resolution_time_hours: avg_resolution_time,
            by_severity,
        }
    }
}

/// Request to create a new case
#[derive(Debug, Clone)]
pub struct CreateCaseRequest {
    pub title: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub priority: Priority,
    pub case_type: CaseType,
    pub assignee_id: Option<Uuid>,
    pub source: Option<String>,
    pub source_ref: Option<String>,
    pub tlp: Option<Tlp>,
    pub tags: Option<Vec<String>>,
    pub created_by: Uuid,
}

/// Request to create a task
#[derive(Debug, Clone)]
pub struct CreateTaskRequest {
    pub title: String,
    pub description: Option<String>,
    pub priority: Priority,
    pub assignee_id: Option<Uuid>,
    pub due_at: Option<DateTime<Utc>>,
}

/// Request to add evidence
#[derive(Debug, Clone)]
pub struct AddEvidenceRequest {
    pub evidence_type: EvidenceType,
    pub name: String,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub hash_sha256: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub collected_by: Uuid,
}

/// Filter for listing cases
#[derive(Debug, Clone, Default)]
pub struct CaseFilter {
    pub status: Option<CaseStatus>,
    pub severity: Option<Severity>,
    pub assignee_id: Option<Uuid>,
    pub case_type: Option<CaseType>,
}

/// Case statistics
#[derive(Debug, Clone)]
pub struct CaseStatistics {
    pub total: usize,
    pub open: usize,
    pub in_progress: usize,
    pub resolved: usize,
    pub closed: usize,
    pub avg_resolution_time_hours: f64,
    pub by_severity: HashMap<Severity, usize>,
}

// --- Database row types ---

#[derive(sqlx::FromRow)]
struct CaseRow {
    id: String,
    case_number: String,
    title: String,
    description: Option<String>,
    severity: String,
    status: String,
    priority: String,
    case_type: String,
    assignee_id: Option<String>,
    source: Option<String>,
    source_ref: Option<String>,
    tlp: String,
    tags: String,
    resolution: Option<String>,
    resolution_time_hours: Option<f64>,
    created_by: String,
    created_at: String,
    updated_at: String,
    resolved_at: Option<String>,
    closed_at: Option<String>,
}

impl CaseRow {
    fn into_case(self) -> Result<SoarCase, String> {
        let id = Uuid::parse_str(&self.id).map_err(|e| e.to_string())?;
        let created_by = Uuid::parse_str(&self.created_by).map_err(|e| e.to_string())?;
        let assignee_id = self.assignee_id.as_ref().and_then(|s| Uuid::parse_str(s).ok());
        let tags: Vec<String> = serde_json::from_str(&self.tags).unwrap_or_default();
        let created_at = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());
        let updated_at = chrono::DateTime::parse_from_rfc3339(&self.updated_at)
            .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now());
        let resolved_at = self.resolved_at.as_ref().and_then(|s|
            chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc)));
        let closed_at = self.closed_at.as_ref().and_then(|s|
            chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc)));

        Ok(SoarCase {
            id,
            case_number: self.case_number,
            title: self.title,
            description: self.description,
            severity: parse_severity(&self.severity),
            status: parse_case_status(&self.status),
            priority: parse_priority(&self.priority),
            case_type: parse_case_type(&self.case_type),
            assignee_id,
            source: self.source,
            source_ref: self.source_ref,
            tlp: parse_tlp(&self.tlp),
            tags,
            resolution: self.resolution,
            resolution_time_hours: self.resolution_time_hours,
            created_by,
            created_at,
            updated_at,
            resolved_at,
            closed_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct TaskRow {
    id: String,
    case_id: String,
    title: String,
    description: Option<String>,
    status: String,
    priority: String,
    assignee_id: Option<String>,
    due_at: Option<String>,
    completed_at: Option<String>,
    created_at: String,
}

impl TaskRow {
    fn into_task(self) -> Result<CaseTask, String> {
        Ok(CaseTask {
            id: Uuid::parse_str(&self.id).map_err(|e| e.to_string())?,
            case_id: Uuid::parse_str(&self.case_id).map_err(|e| e.to_string())?,
            title: self.title,
            description: self.description,
            status: parse_task_status(&self.status),
            priority: parse_priority(&self.priority),
            assignee_id: self.assignee_id.as_ref().and_then(|s| Uuid::parse_str(s).ok()),
            due_at: self.due_at.as_ref().and_then(|s|
                chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))),
            completed_at: self.completed_at.as_ref().and_then(|s|
                chrono::DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
        })
    }
}

#[derive(sqlx::FromRow)]
struct EvidenceRow {
    id: String,
    case_id: String,
    evidence_type: String,
    name: String,
    description: Option<String>,
    file_path: Option<String>,
    hash_sha256: Option<String>,
    metadata: Option<String>,
    collected_by: String,
    collected_at: String,
}

impl EvidenceRow {
    fn into_evidence(self) -> Result<CaseEvidence, String> {
        Ok(CaseEvidence {
            id: Uuid::parse_str(&self.id).map_err(|e| e.to_string())?,
            case_id: Uuid::parse_str(&self.case_id).map_err(|e| e.to_string())?,
            evidence_type: parse_evidence_type(&self.evidence_type),
            name: self.name,
            description: self.description,
            file_path: self.file_path,
            hash_sha256: self.hash_sha256,
            metadata: self.metadata.as_ref().and_then(|s| serde_json::from_str(s).ok()),
            collected_by: Uuid::parse_str(&self.collected_by).map_err(|e| e.to_string())?,
            collected_at: chrono::DateTime::parse_from_rfc3339(&self.collected_at)
                .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
        })
    }
}

#[derive(sqlx::FromRow)]
struct CommentRow {
    id: String,
    case_id: String,
    user_id: String,
    content: String,
    is_internal: bool,
    created_at: String,
}

impl CommentRow {
    fn into_comment(self) -> Result<CaseComment, String> {
        Ok(CaseComment {
            id: Uuid::parse_str(&self.id).map_err(|e| e.to_string())?,
            case_id: Uuid::parse_str(&self.case_id).map_err(|e| e.to_string())?,
            user_id: Uuid::parse_str(&self.user_id).map_err(|e| e.to_string())?,
            content: self.content,
            is_internal: self.is_internal,
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
        })
    }
}

#[derive(sqlx::FromRow)]
struct TimelineRow {
    id: String,
    case_id: String,
    event_type: String,
    event_data: String,
    user_id: Option<String>,
    created_at: String,
}

impl TimelineRow {
    fn into_event(self) -> Result<CaseTimelineEvent, String> {
        Ok(CaseTimelineEvent {
            id: Uuid::parse_str(&self.id).map_err(|e| e.to_string())?,
            case_id: Uuid::parse_str(&self.case_id).map_err(|e| e.to_string())?,
            event_type: parse_timeline_event_type(&self.event_type),
            event_data: serde_json::from_str(&self.event_data).unwrap_or(serde_json::json!({})),
            user_id: self.user_id.as_ref().and_then(|s| Uuid::parse_str(s).ok()),
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)
                .map(|dt| dt.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
        })
    }
}

// --- Parser helpers ---

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Informational,
    }
}

fn parse_case_status(s: &str) -> CaseStatus {
    match s {
        "open" => CaseStatus::Open,
        "in_progress" => CaseStatus::InProgress,
        "pending" => CaseStatus::Pending,
        "resolved" => CaseStatus::Resolved,
        "closed" => CaseStatus::Closed,
        _ => CaseStatus::Open,
    }
}

fn parse_priority(s: &str) -> Priority {
    match s {
        "low" => Priority::Low,
        "medium" => Priority::Medium,
        "high" => Priority::High,
        "urgent" => Priority::Urgent,
        _ => Priority::Medium,
    }
}

fn parse_case_type(s: &str) -> CaseType {
    match s {
        "incident" => CaseType::Incident,
        "investigation" => CaseType::Investigation,
        "threat_hunt" => CaseType::ThreatHunt,
        "vulnerability" => CaseType::Vulnerability,
        "compliance" => CaseType::Compliance,
        _ => CaseType::Other,
    }
}

fn parse_tlp(s: &str) -> Tlp {
    match s {
        "white" => Tlp::White,
        "green" => Tlp::Green,
        "amber" => Tlp::Amber,
        "red" => Tlp::Red,
        _ => Tlp::Amber,
    }
}

fn parse_task_status(s: &str) -> TaskStatus {
    match s {
        "pending" => TaskStatus::Pending,
        "in_progress" => TaskStatus::InProgress,
        "completed" => TaskStatus::Completed,
        "blocked" => TaskStatus::Blocked,
        "cancelled" => TaskStatus::Cancelled,
        _ => TaskStatus::Pending,
    }
}

fn parse_evidence_type(s: &str) -> EvidenceType {
    match s {
        "file" => EvidenceType::File,
        "log" => EvidenceType::Log,
        "screenshot" => EvidenceType::Screenshot,
        "ioc" => EvidenceType::Ioc,
        "artifact" => EvidenceType::Artifact,
        "network_capture" => EvidenceType::NetworkCapture,
        "memory_dump" => EvidenceType::MemoryDump,
        _ => EvidenceType::Other,
    }
}

fn parse_timeline_event_type(s: &str) -> TimelineEventType {
    match s {
        "created" => TimelineEventType::Created,
        "statuschange" | "status_change" => TimelineEventType::StatusChange,
        "assignment" => TimelineEventType::Assignment,
        "comment" => TimelineEventType::Comment,
        "evidence" => TimelineEventType::Evidence,
        "task" => TimelineEventType::Task,
        "playbook" => TimelineEventType::Playbook,
        "resolution" => TimelineEventType::Resolution,
        "reopened" => TimelineEventType::Reopened,
        _ => TimelineEventType::Created,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_case() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let manager = CaseManager::new(pool).await;
        let user_id = Uuid::new_v4();

        let case = manager.create_case(CreateCaseRequest {
            title: "Test Case".to_string(),
            description: Some("Test description".to_string()),
            severity: Severity::High,
            priority: Priority::High,
            case_type: CaseType::Incident,
            assignee_id: None,
            source: Some("manual".to_string()),
            source_ref: None,
            tlp: None,
            tags: None,
            created_by: user_id,
        }).await.unwrap();

        assert_eq!(case.title, "Test Case");
        assert_eq!(case.status, CaseStatus::Open);
        assert!(case.case_number.starts_with("CASE-"));
    }

    #[tokio::test]
    async fn test_case_lifecycle() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let manager = CaseManager::new(pool).await;
        let user_id = Uuid::new_v4();

        let case = manager.create_case(CreateCaseRequest {
            title: "Test Case".to_string(),
            description: None,
            severity: Severity::Medium,
            priority: Priority::Medium,
            case_type: CaseType::Investigation,
            assignee_id: None,
            source: None,
            source_ref: None,
            tlp: None,
            tags: None,
            created_by: user_id,
        }).await.unwrap();

        let case_id = case.id;

        // Update status
        manager.update_status(&case_id, CaseStatus::InProgress, user_id).await.unwrap();
        assert_eq!(manager.get_case(&case_id).await.unwrap().status, CaseStatus::InProgress);

        // Resolve case
        manager.resolve_case(&case_id, "Issue resolved".to_string(), user_id).await.unwrap();
        let resolved = manager.get_case(&case_id).await.unwrap();
        assert_eq!(resolved.status, CaseStatus::Resolved);
        assert!(resolved.resolved_at.is_some());
    }

    #[tokio::test]
    async fn test_case_tasks() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let manager = CaseManager::new(pool).await;
        let user_id = Uuid::new_v4();

        let case = manager.create_case(CreateCaseRequest {
            title: "Task Test".to_string(),
            description: None,
            severity: Severity::Low,
            priority: Priority::Low,
            case_type: CaseType::Other,
            assignee_id: None,
            source: None,
            source_ref: None,
            tlp: None,
            tags: None,
            created_by: user_id,
        }).await.unwrap();

        let task = manager.add_task(&case.id, CreateTaskRequest {
            title: "Investigate logs".to_string(),
            description: None,
            priority: Priority::Medium,
            assignee_id: None,
            due_at: None,
        }).await.unwrap();

        let tasks = manager.get_tasks(&case.id).await;
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].title, "Investigate logs");

        manager.update_task_status(&case.id, &task.id, TaskStatus::Completed).await.unwrap();
        let tasks = manager.get_tasks(&case.id).await;
        assert_eq!(tasks[0].status, TaskStatus::Completed);
    }

    #[tokio::test]
    async fn test_statistics() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let manager = CaseManager::new(pool).await;
        let user_id = Uuid::new_v4();

        manager.create_case(CreateCaseRequest {
            title: "Case 1".to_string(),
            description: None,
            severity: Severity::High,
            priority: Priority::High,
            case_type: CaseType::Incident,
            assignee_id: None,
            source: None,
            source_ref: None,
            tlp: None,
            tags: None,
            created_by: user_id,
        }).await.unwrap();

        let stats = manager.get_statistics().await;
        assert_eq!(stats.total, 1);
        assert_eq!(stats.open, 1);
    }
}
