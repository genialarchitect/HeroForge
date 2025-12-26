//! Green Team API endpoints - Security Automation & Orchestration (SOAR)
//!
//! Provides REST API endpoints for:
//! - Playbook management and execution
//! - Playbook marketplace
//! - Case management (tasks, evidence, comments, timeline)
//! - IOC feed automation
//! - Response metrics and SLA tracking

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct PlaybookResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub trigger_type: String,
    pub trigger_config: Option<serde_json::Value>,
    pub steps: serde_json::Value,
    pub is_active: bool,
    pub version: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePlaybookRequest {
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub trigger_type: String,
    pub trigger_config: Option<serde_json::Value>,
    pub steps: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePlaybookRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub trigger_type: Option<String>,
    pub trigger_config: Option<serde_json::Value>,
    pub steps: Option<serde_json::Value>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutePlaybookRequest {
    pub input_data: Option<serde_json::Value>,
    pub trigger_source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub priority: Option<String>,
    pub case_type: String,
    pub assignee_id: Option<String>,
    pub source: Option<String>,
    pub source_ref: Option<String>,
    pub tlp: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateCaseRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee_id: Option<String>,
    pub tlp: Option<String>,
    pub tags: Option<Vec<String>>,
    pub resolution: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTaskRequest {
    pub title: String,
    pub description: Option<String>,
    pub priority: Option<String>,
    pub assignee_id: Option<String>,
    pub due_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateTaskRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assignee_id: Option<String>,
    pub due_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddEvidenceRequest {
    pub evidence_type: String,
    pub name: String,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub hash_sha256: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddCommentRequest {
    pub content: String,
    pub is_internal: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIocFeedRequest {
    pub name: String,
    pub description: Option<String>,
    pub feed_type: String,
    pub url: String,
    pub api_key: Option<String>,
    pub poll_interval_minutes: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RatePlaybookRequest {
    pub rating: i32,
    pub review: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSlaConfigRequest {
    pub name: String,
    pub severity: String,
    pub response_time_minutes: i32,
    pub containment_time_minutes: Option<i32>,
    pub resolution_time_hours: i32,
    pub escalation_time_minutes: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSlaConfigRequest {
    pub name: Option<String>,
    pub response_time_minutes: Option<i32>,
    pub containment_time_minutes: Option<i32>,
    pub resolution_time_hours: Option<i32>,
    pub escalation_time_minutes: Option<i32>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct MarketplaceQuery {
    pub sort: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CaseQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
}

// ============================================================================
// Playbook Handlers
// ============================================================================

async fn list_playbooks(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query(
        r#"
        SELECT id, name, description, category, trigger_type, trigger_config,
               steps_json, is_active, version, created_by, created_at, updated_at
        FROM soar_playbooks
        ORDER BY updated_at DESC
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let playbooks: Vec<serde_json::Value> = rows.into_iter().map(|r| {
        serde_json::json!({
            "id": r.get::<String, _>("id"),
            "name": r.get::<String, _>("name"),
            "description": r.get::<Option<String>, _>("description"),
            "category": r.get::<String, _>("category"),
            "trigger_type": r.get::<String, _>("trigger_type"),
            "trigger_config": r.get::<Option<String>, _>("trigger_config")
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
            "steps": serde_json::from_str::<serde_json::Value>(
                &r.get::<String, _>("steps_json")
            ).unwrap_or_default(),
            "is_active": r.get::<bool, _>("is_active"),
            "version": r.get::<String, _>("version"),
            "created_by": r.get::<String, _>("created_by"),
            "created_at": r.get::<String, _>("created_at"),
            "updated_at": r.get::<String, _>("updated_at")
        })
    }).collect();

    Ok(HttpResponse::Ok().json(playbooks))
}

async fn get_playbook(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let row = sqlx::query(
        "SELECT id, name, description, category, trigger_type, trigger_config, steps_json, is_active, version, created_by, created_at, updated_at FROM soar_playbooks WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match row {
        Some(r) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "id": r.get::<String, _>("id"),
            "name": r.get::<String, _>("name"),
            "description": r.get::<Option<String>, _>("description"),
            "category": r.get::<String, _>("category"),
            "trigger_type": r.get::<String, _>("trigger_type"),
            "trigger_config": r.get::<Option<String>, _>("trigger_config")
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
            "steps": serde_json::from_str::<serde_json::Value>(
                &r.get::<String, _>("steps_json")
            ).unwrap_or_default(),
            "is_active": r.get::<bool, _>("is_active"),
            "version": r.get::<String, _>("version"),
            "created_by": r.get::<String, _>("created_by"),
            "created_at": r.get::<String, _>("created_at"),
            "updated_at": r.get::<String, _>("updated_at")
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"}))),
    }
}

async fn create_playbook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreatePlaybookRequest>,
) -> Result<HttpResponse> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let steps_json = serde_json::to_string(&body.steps).unwrap_or_else(|_| "[]".to_string());
    let trigger_config = body.trigger_config.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_else(|_| "{}".to_string()));

    sqlx::query(
        "INSERT INTO soar_playbooks (id, name, description, category, trigger_type, trigger_config, steps_json, is_active, version, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, '1.0.0', ?, ?, ?)"
    )
    .bind(&id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.category)
    .bind(&body.trigger_type)
    .bind(&trigger_config)
    .bind(&steps_json)
    .bind(&claims.sub)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Playbook created successfully"})))
}

async fn update_playbook(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<UpdatePlaybookRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Check exists
    let existing = sqlx::query("SELECT id FROM soar_playbooks WHERE id = ?")
        .bind(&id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if existing.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"})));
    }

    // Update fields
    sqlx::query("UPDATE soar_playbooks SET updated_at = ? WHERE id = ?")
        .bind(&now).bind(&id).execute(pool.get_ref()).await.ok();

    if let Some(ref name) = body.name {
        sqlx::query("UPDATE soar_playbooks SET name = ? WHERE id = ?")
            .bind(name).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref desc) = body.description {
        sqlx::query("UPDATE soar_playbooks SET description = ? WHERE id = ?")
            .bind(desc).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref category) = body.category {
        sqlx::query("UPDATE soar_playbooks SET category = ? WHERE id = ?")
            .bind(category).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref steps) = body.steps {
        let steps_json = serde_json::to_string(steps).unwrap_or_default();
        sqlx::query("UPDATE soar_playbooks SET steps_json = ? WHERE id = ?")
            .bind(&steps_json).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(is_active) = body.is_active {
        sqlx::query("UPDATE soar_playbooks SET is_active = ? WHERE id = ?")
            .bind(is_active).bind(&id).execute(pool.get_ref()).await.ok();
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Playbook updated successfully"})))
}

async fn delete_playbook(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM soar_playbooks WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Playbook deleted successfully"})))
}

async fn execute_playbook(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<ExecutePlaybookRequest>,
) -> Result<HttpResponse> {
    let playbook_id = path.into_inner();

    // Get playbook
    let playbook = sqlx::query("SELECT id, name, steps_json FROM soar_playbooks WHERE id = ? AND is_active = TRUE")
        .bind(&playbook_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let playbook = match playbook {
        Some(p) => p,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found or inactive"}))),
    };

    let steps_json: String = playbook.get("steps_json");
    let steps: Vec<serde_json::Value> = serde_json::from_str(&steps_json).unwrap_or_default();
    let total_steps = steps.len() as i32;

    // Create run record
    let run_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let input_data = body.input_data.as_ref().map(|d| serde_json::to_string(d).unwrap_or_default());

    sqlx::query("INSERT INTO soar_playbook_runs (id, playbook_id, trigger_type, trigger_source, status, current_step, total_steps, input_data, started_at) VALUES (?, ?, 'manual', ?, 'running', 0, ?, ?, ?)")
        .bind(&run_id)
        .bind(&playbook_id)
        .bind(&body.trigger_source)
        .bind(total_steps)
        .bind(&input_data)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    // Mark as completed (in real impl this would be async execution)
    let completed_at = Utc::now().to_rfc3339();
    sqlx::query("UPDATE soar_playbook_runs SET status = 'completed', current_step = total_steps, completed_at = ?, duration_seconds = 1 WHERE id = ?")
        .bind(&completed_at)
        .bind(&run_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({"run_id": run_id, "message": "Playbook execution started"})))
}

async fn get_playbook_runs(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let playbook_id = path.into_inner();

    let rows = sqlx::query(
        "SELECT r.id, r.playbook_id, p.name as playbook_name, r.trigger_type, r.trigger_source, r.status, r.current_step, r.total_steps, r.started_at, r.completed_at, r.duration_seconds FROM soar_playbook_runs r JOIN soar_playbooks p ON r.playbook_id = p.id WHERE r.playbook_id = ? ORDER BY r.started_at DESC LIMIT 50"
    )
    .bind(&playbook_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let runs: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "playbook_id": r.get::<String, _>("playbook_id"),
        "playbook_name": r.get::<String, _>("playbook_name"),
        "trigger_type": r.get::<String, _>("trigger_type"),
        "trigger_source": r.get::<Option<String>, _>("trigger_source"),
        "status": r.get::<String, _>("status"),
        "current_step": r.get::<i32, _>("current_step"),
        "total_steps": r.get::<i32, _>("total_steps"),
        "started_at": r.get::<String, _>("started_at"),
        "completed_at": r.get::<Option<String>, _>("completed_at"),
        "duration_seconds": r.get::<Option<i32>, _>("duration_seconds")
    })).collect();

    Ok(HttpResponse::Ok().json(runs))
}

// ============================================================================
// Marketplace Handlers
// ============================================================================

async fn browse_marketplace(
    pool: web::Data<SqlitePool>,
    _query: web::Query<MarketplaceQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query(
        "SELECT id, name, description, author, category, tags, version, downloads, rating, ratings_count, is_verified, created_at FROM soar_marketplace_playbooks ORDER BY downloads DESC"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let playbooks: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "name": r.get::<String, _>("name"),
        "description": r.get::<String, _>("description"),
        "author": r.get::<String, _>("author"),
        "category": r.get::<String, _>("category"),
        "tags": serde_json::from_str::<Vec<String>>(&r.get::<Option<String>, _>("tags").unwrap_or_default()).unwrap_or_default(),
        "version": r.get::<String, _>("version"),
        "downloads": r.get::<i32, _>("downloads"),
        "rating": r.get::<f64, _>("rating"),
        "ratings_count": r.get::<i32, _>("ratings_count"),
        "is_verified": r.get::<bool, _>("is_verified"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(playbooks))
}

async fn install_marketplace_playbook(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let marketplace_id = path.into_inner();

    let mp = sqlx::query("SELECT id, name, description, category, playbook_json FROM soar_marketplace_playbooks WHERE id = ?")
        .bind(&marketplace_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let mp = match mp {
        Some(p) => p,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Marketplace playbook not found"}))),
    };

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let name: String = mp.get("name");
    let description: Option<String> = mp.get("description");
    let category: String = mp.get("category");
    let playbook_json: String = mp.get("playbook_json");

    sqlx::query("INSERT INTO soar_playbooks (id, name, description, category, trigger_type, steps_json, is_active, is_template, marketplace_id, version, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, 'manual', ?, TRUE, FALSE, ?, '1.0.0', ?, ?, ?)")
        .bind(&id)
        .bind(&name)
        .bind(&description)
        .bind(&category)
        .bind(&playbook_json)
        .bind(&marketplace_id)
        .bind(&claims.sub)
        .bind(&now)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    // Increment download count
    sqlx::query("UPDATE soar_marketplace_playbooks SET downloads = downloads + 1 WHERE id = ?")
        .bind(&marketplace_id)
        .execute(pool.get_ref())
        .await
        .ok();

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Playbook installed successfully"})))
}

async fn rate_marketplace_playbook(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RatePlaybookRequest>,
) -> Result<HttpResponse> {
    let playbook_id = path.into_inner();

    if body.rating < 1 || body.rating > 5 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Rating must be between 1 and 5"})));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query("INSERT INTO soar_playbook_ratings (id, playbook_id, user_id, rating, review, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&playbook_id)
        .bind(&claims.sub)
        .bind(body.rating)
        .bind(&body.review)
        .bind(&now)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => {
            // Update average rating
            sqlx::query("UPDATE soar_marketplace_playbooks SET rating = (SELECT AVG(rating) FROM soar_playbook_ratings WHERE playbook_id = ?), ratings_count = (SELECT COUNT(*) FROM soar_playbook_ratings WHERE playbook_id = ?) WHERE id = ?")
                .bind(&playbook_id)
                .bind(&playbook_id)
                .bind(&playbook_id)
                .execute(pool.get_ref())
                .await
                .ok();
            Ok(HttpResponse::Created().json(serde_json::json!({"message": "Rating submitted successfully"})))
        }
        Err(_) => Ok(HttpResponse::Conflict().json(serde_json::json!({"error": "You have already rated this playbook"}))),
    }
}

// ============================================================================
// Case Management Handlers
// ============================================================================

async fn list_cases(
    pool: web::Data<SqlitePool>,
    query: web::Query<CaseQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query(
        "SELECT c.id, c.case_number, c.title, c.description, c.severity, c.status, c.priority, c.case_type, c.assignee_id, c.source, c.source_ref, c.tlp, c.tags, c.resolution, c.created_by, c.created_at, c.updated_at, c.resolved_at, c.closed_at, u.username as assignee_name FROM soar_cases c LEFT JOIN users u ON c.assignee_id = u.id ORDER BY c.created_at DESC LIMIT 100"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let cases: Vec<serde_json::Value> = rows.into_iter()
        .filter(|r| {
            let status_match = query.status.as_ref().map_or(true, |s| r.get::<String, _>("status") == *s);
            let severity_match = query.severity.as_ref().map_or(true, |s| r.get::<String, _>("severity") == *s);
            status_match && severity_match
        })
        .map(|r| serde_json::json!({
            "id": r.get::<String, _>("id"),
            "case_number": r.get::<String, _>("case_number"),
            "title": r.get::<String, _>("title"),
            "description": r.get::<Option<String>, _>("description"),
            "severity": r.get::<String, _>("severity"),
            "status": r.get::<String, _>("status"),
            "priority": r.get::<String, _>("priority"),
            "case_type": r.get::<String, _>("case_type"),
            "assignee_id": r.get::<Option<String>, _>("assignee_id"),
            "assignee_name": r.get::<Option<String>, _>("assignee_name"),
            "source": r.get::<Option<String>, _>("source"),
            "tlp": r.get::<String, _>("tlp"),
            "tags": serde_json::from_str::<Vec<String>>(&r.get::<Option<String>, _>("tags").unwrap_or_default()).unwrap_or_default(),
            "created_by": r.get::<String, _>("created_by"),
            "created_at": r.get::<String, _>("created_at"),
            "updated_at": r.get::<String, _>("updated_at"),
            "resolved_at": r.get::<Option<String>, _>("resolved_at"),
            "closed_at": r.get::<Option<String>, _>("closed_at")
        }))
        .collect();

    Ok(HttpResponse::Ok().json(cases))
}

async fn get_case(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let row = sqlx::query(
        "SELECT c.id, c.case_number, c.title, c.description, c.severity, c.status, c.priority, c.case_type, c.assignee_id, c.source, c.source_ref, c.tlp, c.tags, c.resolution, c.created_by, c.created_at, c.updated_at, c.resolved_at, c.closed_at, u.username as assignee_name FROM soar_cases c LEFT JOIN users u ON c.assignee_id = u.id WHERE c.id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match row {
        Some(r) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "id": r.get::<String, _>("id"),
            "case_number": r.get::<String, _>("case_number"),
            "title": r.get::<String, _>("title"),
            "description": r.get::<Option<String>, _>("description"),
            "severity": r.get::<String, _>("severity"),
            "status": r.get::<String, _>("status"),
            "priority": r.get::<String, _>("priority"),
            "case_type": r.get::<String, _>("case_type"),
            "assignee_id": r.get::<Option<String>, _>("assignee_id"),
            "assignee_name": r.get::<Option<String>, _>("assignee_name"),
            "source": r.get::<Option<String>, _>("source"),
            "source_ref": r.get::<Option<String>, _>("source_ref"),
            "tlp": r.get::<String, _>("tlp"),
            "tags": serde_json::from_str::<Vec<String>>(&r.get::<Option<String>, _>("tags").unwrap_or_default()).unwrap_or_default(),
            "resolution": r.get::<Option<String>, _>("resolution"),
            "created_by": r.get::<String, _>("created_by"),
            "created_at": r.get::<String, _>("created_at"),
            "updated_at": r.get::<String, _>("updated_at"),
            "resolved_at": r.get::<Option<String>, _>("resolved_at"),
            "closed_at": r.get::<Option<String>, _>("closed_at")
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Case not found"}))),
    }
}

async fn create_case(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateCaseRequest>,
) -> Result<HttpResponse> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Generate case number
    let count_row = sqlx::query("SELECT COUNT(*) as count FROM soar_cases")
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let count: i32 = count_row.get("count");
    let case_number = format!("CASE-{:06}", count + 1);

    let priority = body.priority.as_deref().unwrap_or("medium");
    let tlp = body.tlp.as_deref().unwrap_or("amber");
    let tags = body.tags.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());

    sqlx::query("INSERT INTO soar_cases (id, case_number, title, description, severity, status, priority, case_type, assignee_id, source, source_ref, tlp, tags, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&case_number)
        .bind(&body.title)
        .bind(&body.description)
        .bind(&body.severity)
        .bind(priority)
        .bind(&body.case_type)
        .bind(&body.assignee_id)
        .bind(&body.source)
        .bind(&body.source_ref)
        .bind(tlp)
        .bind(&tags)
        .bind(&claims.sub)
        .bind(&now)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    // Add timeline event
    let event_id = Uuid::new_v4().to_string();
    let event_data = serde_json::json!({"action": "created", "severity": body.severity, "case_type": body.case_type}).to_string();
    sqlx::query("INSERT INTO soar_case_timeline (id, case_id, event_type, event_data, user_id, created_at) VALUES (?, ?, 'created', ?, ?, ?)")
        .bind(&event_id)
        .bind(&id)
        .bind(&event_data)
        .bind(&claims.sub)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .ok();

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "case_number": case_number, "message": "Case created successfully"})))
}

async fn update_case(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<UpdateCaseRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let existing = sqlx::query("SELECT id, status FROM soar_cases WHERE id = ?")
        .bind(&id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if existing.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Case not found"})));
    }

    let old_status: Option<String> = existing.as_ref().map(|e| e.get("status"));

    sqlx::query("UPDATE soar_cases SET updated_at = ? WHERE id = ?")
        .bind(&now).bind(&id).execute(pool.get_ref()).await.ok();

    if let Some(ref title) = body.title {
        sqlx::query("UPDATE soar_cases SET title = ? WHERE id = ?").bind(title).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref desc) = body.description {
        sqlx::query("UPDATE soar_cases SET description = ? WHERE id = ?").bind(desc).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref severity) = body.severity {
        sqlx::query("UPDATE soar_cases SET severity = ? WHERE id = ?").bind(severity).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref status) = body.status {
        if status == "resolved" {
            sqlx::query("UPDATE soar_cases SET status = ?, resolved_at = ? WHERE id = ?").bind(status).bind(&now).bind(&id).execute(pool.get_ref()).await.ok();
        } else if status == "closed" {
            sqlx::query("UPDATE soar_cases SET status = ?, closed_at = ? WHERE id = ?").bind(status).bind(&now).bind(&id).execute(pool.get_ref()).await.ok();
        } else {
            sqlx::query("UPDATE soar_cases SET status = ? WHERE id = ?").bind(status).bind(&id).execute(pool.get_ref()).await.ok();
        }
    }
    if let Some(ref priority) = body.priority {
        sqlx::query("UPDATE soar_cases SET priority = ? WHERE id = ?").bind(priority).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref assignee) = body.assignee_id {
        sqlx::query("UPDATE soar_cases SET assignee_id = ? WHERE id = ?").bind(assignee).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref resolution) = body.resolution {
        sqlx::query("UPDATE soar_cases SET resolution = ? WHERE id = ?").bind(resolution).bind(&id).execute(pool.get_ref()).await.ok();
    }

    // Add status change to timeline if changed
    if body.status.is_some() && body.status != old_status {
        let event_id = Uuid::new_v4().to_string();
        let event_data = serde_json::json!({"action": "status_change", "old_status": old_status, "new_status": body.status}).to_string();
        sqlx::query("INSERT INTO soar_case_timeline (id, case_id, event_type, event_data, user_id, created_at) VALUES (?, ?, 'status_change', ?, ?, ?)")
            .bind(&event_id).bind(&id).bind(&event_data).bind(&claims.sub).bind(&now).execute(pool.get_ref()).await.ok();
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Case updated successfully"})))
}

async fn delete_case(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM soar_cases WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Case not found"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Case deleted successfully"})))
}

async fn get_case_tasks(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();

    let rows = sqlx::query("SELECT id, case_id, title, description, status, priority, assignee_id, due_at, completed_at, created_at FROM soar_case_tasks WHERE case_id = ? ORDER BY created_at ASC")
        .bind(&case_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let tasks: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "case_id": r.get::<String, _>("case_id"),
        "title": r.get::<String, _>("title"),
        "description": r.get::<Option<String>, _>("description"),
        "status": r.get::<String, _>("status"),
        "priority": r.get::<String, _>("priority"),
        "assignee_id": r.get::<Option<String>, _>("assignee_id"),
        "due_at": r.get::<Option<String>, _>("due_at"),
        "completed_at": r.get::<Option<String>, _>("completed_at"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(tasks))
}

async fn create_case_task(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateTaskRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let priority = body.priority.as_deref().unwrap_or("medium");

    sqlx::query("INSERT INTO soar_case_tasks (id, case_id, title, description, status, priority, assignee_id, due_at, created_at) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)")
        .bind(&id)
        .bind(&case_id)
        .bind(&body.title)
        .bind(&body.description)
        .bind(priority)
        .bind(&body.assignee_id)
        .bind(&body.due_at)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Task created successfully"})))
}

async fn update_case_task(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<UpdateTaskRequest>,
) -> Result<HttpResponse> {
    let (case_id, task_id) = path.into_inner();

    if let Some(ref status) = body.status {
        if status == "completed" {
            let now = Utc::now().to_rfc3339();
            sqlx::query("UPDATE soar_case_tasks SET status = ?, completed_at = ? WHERE id = ? AND case_id = ?")
                .bind(status).bind(&now).bind(&task_id).bind(&case_id).execute(pool.get_ref()).await.ok();
        } else {
            sqlx::query("UPDATE soar_case_tasks SET status = ? WHERE id = ? AND case_id = ?")
                .bind(status).bind(&task_id).bind(&case_id).execute(pool.get_ref()).await.ok();
        }
    }
    if let Some(ref title) = body.title {
        sqlx::query("UPDATE soar_case_tasks SET title = ? WHERE id = ? AND case_id = ?").bind(title).bind(&task_id).bind(&case_id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref priority) = body.priority {
        sqlx::query("UPDATE soar_case_tasks SET priority = ? WHERE id = ? AND case_id = ?").bind(priority).bind(&task_id).bind(&case_id).execute(pool.get_ref()).await.ok();
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Task updated successfully"})))
}

async fn get_case_evidence(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();

    let rows = sqlx::query("SELECT id, case_id, evidence_type, name, description, file_path, hash_sha256, metadata, collected_by, collected_at FROM soar_case_evidence WHERE case_id = ?")
        .bind(&case_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let evidence: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "case_id": r.get::<String, _>("case_id"),
        "evidence_type": r.get::<String, _>("evidence_type"),
        "name": r.get::<String, _>("name"),
        "description": r.get::<Option<String>, _>("description"),
        "file_path": r.get::<Option<String>, _>("file_path"),
        "hash_sha256": r.get::<Option<String>, _>("hash_sha256"),
        "metadata": r.get::<Option<String>, _>("metadata").and_then(|m| serde_json::from_str::<serde_json::Value>(&m).ok()),
        "collected_by": r.get::<String, _>("collected_by"),
        "collected_at": r.get::<String, _>("collected_at")
    })).collect();

    Ok(HttpResponse::Ok().json(evidence))
}

async fn add_case_evidence(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<AddEvidenceRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let metadata = body.metadata.as_ref().map(|m| serde_json::to_string(m).unwrap_or_default());

    sqlx::query("INSERT INTO soar_case_evidence (id, case_id, evidence_type, name, description, file_path, hash_sha256, metadata, collected_by, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&case_id)
        .bind(&body.evidence_type)
        .bind(&body.name)
        .bind(&body.description)
        .bind(&body.file_path)
        .bind(&body.hash_sha256)
        .bind(&metadata)
        .bind(&claims.sub)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Evidence added successfully"})))
}

async fn get_case_comments(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();

    let rows = sqlx::query("SELECT c.id, c.case_id, c.user_id, u.username, c.content, c.is_internal, c.created_at FROM soar_case_comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.case_id = ? ORDER BY c.created_at ASC")
        .bind(&case_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let comments: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "case_id": r.get::<String, _>("case_id"),
        "user_id": r.get::<String, _>("user_id"),
        "username": r.get::<Option<String>, _>("username"),
        "content": r.get::<String, _>("content"),
        "is_internal": r.get::<bool, _>("is_internal"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(comments))
}

async fn add_case_comment(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<AddCommentRequest>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let is_internal = body.is_internal.unwrap_or(false);

    sqlx::query("INSERT INTO soar_case_comments (id, case_id, user_id, content, is_internal, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&case_id)
        .bind(&claims.sub)
        .bind(&body.content)
        .bind(is_internal)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    // Add to timeline
    let event_id = Uuid::new_v4().to_string();
    let event_data = serde_json::json!({"comment_id": id, "is_internal": is_internal}).to_string();
    sqlx::query("INSERT INTO soar_case_timeline (id, case_id, event_type, event_data, user_id, created_at) VALUES (?, ?, 'comment', ?, ?, ?)")
        .bind(&event_id).bind(&case_id).bind(&event_data).bind(&claims.sub).bind(&now).execute(pool.get_ref()).await.ok();

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Comment added successfully"})))
}

async fn get_case_timeline(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let case_id = path.into_inner();

    let rows = sqlx::query("SELECT t.id, t.case_id, t.event_type, t.event_data, t.user_id, u.username, t.created_at FROM soar_case_timeline t LEFT JOIN users u ON t.user_id = u.id WHERE t.case_id = ? ORDER BY t.created_at ASC")
        .bind(&case_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let events: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "case_id": r.get::<String, _>("case_id"),
        "event_type": r.get::<String, _>("event_type"),
        "event_data": serde_json::from_str::<serde_json::Value>(&r.get::<String, _>("event_data")).unwrap_or_default(),
        "user_id": r.get::<Option<String>, _>("user_id"),
        "username": r.get::<Option<String>, _>("username"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(events))
}

// ============================================================================
// IOC Feed Handlers
// ============================================================================

async fn list_ioc_feeds(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query("SELECT id, name, description, feed_type, url, poll_interval_minutes, is_active, last_poll_at, last_poll_status, ioc_count, created_at FROM soar_ioc_feeds ORDER BY created_at DESC")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let feeds: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "name": r.get::<String, _>("name"),
        "description": r.get::<Option<String>, _>("description"),
        "feed_type": r.get::<String, _>("feed_type"),
        "url": r.get::<String, _>("url"),
        "poll_interval_minutes": r.get::<i32, _>("poll_interval_minutes"),
        "is_active": r.get::<bool, _>("is_active"),
        "last_poll_at": r.get::<Option<String>, _>("last_poll_at"),
        "last_poll_status": r.get::<Option<String>, _>("last_poll_status"),
        "ioc_count": r.get::<i32, _>("ioc_count"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(feeds))
}

async fn create_ioc_feed(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateIocFeedRequest>,
) -> Result<HttpResponse> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let poll_interval = body.poll_interval_minutes.unwrap_or(60);

    sqlx::query("INSERT INTO soar_ioc_feeds (id, name, description, feed_type, url, api_key, poll_interval_minutes, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?)")
        .bind(&id)
        .bind(&body.name)
        .bind(&body.description)
        .bind(&body.feed_type)
        .bind(&body.url)
        .bind(&body.api_key)
        .bind(poll_interval)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "IOC feed created successfully"})))
}

async fn get_feed_iocs(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let feed_id = path.into_inner();

    let rows = sqlx::query("SELECT i.id, i.feed_id, f.name as feed_name, i.ioc_type, i.value, i.confidence, i.severity, i.first_seen, i.last_seen, i.tags, i.is_active, i.created_at FROM soar_automated_iocs i JOIN soar_ioc_feeds f ON i.feed_id = f.id WHERE i.feed_id = ? ORDER BY i.created_at DESC LIMIT 1000")
        .bind(&feed_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let iocs: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "feed_id": r.get::<String, _>("feed_id"),
        "feed_name": r.get::<String, _>("feed_name"),
        "ioc_type": r.get::<String, _>("ioc_type"),
        "value": r.get::<String, _>("value"),
        "confidence": r.get::<Option<f64>, _>("confidence"),
        "severity": r.get::<Option<String>, _>("severity"),
        "first_seen": r.get::<Option<String>, _>("first_seen"),
        "last_seen": r.get::<Option<String>, _>("last_seen"),
        "tags": serde_json::from_str::<Vec<String>>(&r.get::<Option<String>, _>("tags").unwrap_or_default()).unwrap_or_default(),
        "is_active": r.get::<bool, _>("is_active"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(iocs))
}

// ============================================================================
// Metrics Handlers
// ============================================================================

async fn get_metrics_overview(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let total_row = sqlx::query("SELECT COUNT(*) as count FROM soar_cases")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let total_cases: i32 = total_row.get("count");

    let open_row = sqlx::query("SELECT COUNT(*) as count FROM soar_cases WHERE status IN ('open', 'in_progress', 'pending')")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let open_cases: i32 = open_row.get("count");

    let resolved_row = sqlx::query("SELECT COUNT(*) as count FROM soar_cases WHERE status IN ('resolved', 'closed')")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let resolved_cases: i32 = resolved_row.get("count");

    let playbooks_row = sqlx::query("SELECT COUNT(*) as count FROM soar_playbook_runs WHERE DATE(started_at) = DATE('now')")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let playbooks_today: i32 = playbooks_row.get("count");

    let severity_rows = sqlx::query("SELECT severity, COUNT(*) as count FROM soar_cases GROUP BY severity")
        .fetch_all(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let severity_map: serde_json::Map<String, serde_json::Value> = severity_rows.into_iter()
        .map(|r| (r.get::<String, _>("severity"), serde_json::json!(r.get::<i32, _>("count"))))
        .collect();

    let status_rows = sqlx::query("SELECT status, COUNT(*) as count FROM soar_cases GROUP BY status")
        .fetch_all(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let status_map: serde_json::Map<String, serde_json::Value> = status_rows.into_iter()
        .map(|r| (r.get::<String, _>("status"), serde_json::json!(r.get::<i32, _>("count"))))
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_cases": total_cases,
        "open_cases": open_cases,
        "resolved_cases": resolved_cases,
        "avg_mttr_minutes": null,
        "avg_mttc_minutes": null,
        "avg_resolution_hours": null,
        "sla_compliance_rate": 0.0,
        "playbooks_executed_today": playbooks_today,
        "cases_by_severity": severity_map,
        "cases_by_status": status_map
    })))
}

async fn get_sla_configs(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query("SELECT id, name, severity, response_time_minutes, containment_time_minutes, resolution_time_hours, escalation_time_minutes, is_active FROM soar_sla_configs ORDER BY severity")
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let configs: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "name": r.get::<String, _>("name"),
        "severity": r.get::<String, _>("severity"),
        "response_time_minutes": r.get::<i32, _>("response_time_minutes"),
        "containment_time_minutes": r.get::<Option<i32>, _>("containment_time_minutes"),
        "resolution_time_hours": r.get::<i32, _>("resolution_time_hours"),
        "escalation_time_minutes": r.get::<Option<i32>, _>("escalation_time_minutes"),
        "is_active": r.get::<bool, _>("is_active")
    })).collect();

    Ok(HttpResponse::Ok().json(configs))
}

async fn create_sla_config(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateSlaConfigRequest>,
) -> Result<HttpResponse> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query("INSERT INTO soar_sla_configs (id, name, severity, response_time_minutes, containment_time_minutes, resolution_time_hours, escalation_time_minutes, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, ?)")
        .bind(&id)
        .bind(&body.name)
        .bind(&body.severity)
        .bind(body.response_time_minutes)
        .bind(body.containment_time_minutes)
        .bind(body.resolution_time_hours)
        .bind(body.escalation_time_minutes)
        .bind(&now)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "SLA configuration created successfully"}))),
        Err(_) => Ok(HttpResponse::Conflict().json(serde_json::json!({"error": "SLA configuration for this severity already exists"}))),
    }
}

async fn update_sla_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<UpdateSlaConfigRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    if let Some(ref name) = body.name {
        sqlx::query("UPDATE soar_sla_configs SET name = ? WHERE id = ?").bind(name).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(response_time) = body.response_time_minutes {
        sqlx::query("UPDATE soar_sla_configs SET response_time_minutes = ? WHERE id = ?").bind(response_time).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(containment_time) = body.containment_time_minutes {
        sqlx::query("UPDATE soar_sla_configs SET containment_time_minutes = ? WHERE id = ?").bind(containment_time).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(resolution_time) = body.resolution_time_hours {
        sqlx::query("UPDATE soar_sla_configs SET resolution_time_hours = ? WHERE id = ?").bind(resolution_time).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(is_active) = body.is_active {
        sqlx::query("UPDATE soar_sla_configs SET is_active = ? WHERE id = ?").bind(is_active).bind(&id).execute(pool.get_ref()).await.ok();
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "SLA configuration updated successfully"})))
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .service(
            web::scope("/green-team/playbooks")
                .route("", web::get().to(list_playbooks))
                .route("", web::post().to(create_playbook))
                .route("/{id}", web::get().to(get_playbook))
                .route("/{id}", web::put().to(update_playbook))
                .route("/{id}", web::delete().to(delete_playbook))
                .route("/{id}/run", web::post().to(execute_playbook))
                .route("/{id}/runs", web::get().to(get_playbook_runs))
        )
        .service(
            web::scope("/green-team/marketplace")
                .route("", web::get().to(browse_marketplace))
                .route("/{id}/install", web::post().to(install_marketplace_playbook))
                .route("/{id}/rate", web::post().to(rate_marketplace_playbook))
        )
        .service(
            web::scope("/green-team/cases")
                .route("", web::get().to(list_cases))
                .route("", web::post().to(create_case))
                .route("/{id}", web::get().to(get_case))
                .route("/{id}", web::put().to(update_case))
                .route("/{id}", web::delete().to(delete_case))
                .route("/{id}/tasks", web::get().to(get_case_tasks))
                .route("/{id}/tasks", web::post().to(create_case_task))
                .route("/{id}/tasks/{tid}", web::put().to(update_case_task))
                .route("/{id}/evidence", web::get().to(get_case_evidence))
                .route("/{id}/evidence", web::post().to(add_case_evidence))
                .route("/{id}/comments", web::get().to(get_case_comments))
                .route("/{id}/comments", web::post().to(add_case_comment))
                .route("/{id}/timeline", web::get().to(get_case_timeline))
        )
        .service(
            web::scope("/green-team/feeds")
                .route("", web::get().to(list_ioc_feeds))
                .route("", web::post().to(create_ioc_feed))
                .route("/{id}/iocs", web::get().to(get_feed_iocs))
        )
        .service(
            web::scope("/green-team/metrics")
                .route("/overview", web::get().to(get_metrics_overview))
        )
        .service(
            web::scope("/green-team/sla-configs")
                .route("", web::get().to(get_sla_configs))
                .route("", web::post().to(create_sla_config))
                .route("/{id}", web::put().to(update_sla_config))
        );
}
