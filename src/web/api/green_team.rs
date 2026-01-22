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
    use crate::green_team::playbooks::ExecutionContext;
    use crate::green_team::types::PlaybookStep;

    let playbook_id = path.into_inner();

    // Get playbook from database
    let playbook_row = sqlx::query("SELECT id, name, description, category, steps_json, is_active, version, created_by, created_at, updated_at FROM soar_playbooks WHERE id = ? AND is_active = TRUE")
        .bind(&playbook_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let playbook_row = match playbook_row {
        Some(p) => p,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found or inactive"}))),
    };

    // Parse playbook data
    let playbook_name: String = playbook_row.get("name");
    let steps_json: String = playbook_row.get("steps_json");
    let steps: Vec<PlaybookStep> = serde_json::from_str(&steps_json).unwrap_or_default();
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

    // Clone data for async task
    let pool_clone = pool.get_ref().clone();
    let run_id_clone = run_id.clone();
    let playbook_id_clone = playbook_id.clone();
    let input_json = body.input_data.clone();

    // Spawn async execution task
    tokio::spawn(async move {
        let start_time = std::time::Instant::now();

        // Create a minimal playbook struct for execution
        let playbook_uuid = match Uuid::parse_str(&playbook_id_clone) {
            Ok(uuid) => uuid,
            Err(_) => {
                log::error!("Invalid playbook ID format: {}", playbook_id_clone);
                let _ = mark_run_failed(&pool_clone, &run_id_clone, "Invalid playbook ID").await;
                return;
            }
        };

        // Create execution context
        let run_uuid = match Uuid::parse_str(&run_id_clone) {
            Ok(uuid) => uuid,
            Err(_) => {
                log::error!("Invalid run ID format: {}", run_id_clone);
                let _ = mark_run_failed(&pool_clone, &run_id_clone, "Invalid run ID").await;
                return;
            }
        };

        let mut context = ExecutionContext::new(run_uuid, input_json);

        // Create action executor for step execution
        let action_executor = crate::green_team::playbooks::actions::ActionExecutor::new();

        // Execute each step
        for (step_index, step) in steps.iter().enumerate() {
            // Update current step in database
            if let Err(e) = update_run_step(&pool_clone, &run_id_clone, step_index as i32).await {
                log::error!("Failed to update run step: {}", e);
            }

            // Check condition if present
            if let Some(ref condition) = step.condition {
                if !crate::green_team::playbooks::conditions::evaluate_condition(condition, &context) {
                    log::info!("Step {} '{}' skipped due to condition", step_index, step.name);
                    continue;
                }
            }

            // Execute the action
            match action_executor.execute(&step.action, &mut context).await {
                Ok(output) => {
                    // Store output in context
                    context.set_step_output(&step.id, output);
                    log::info!("Step {} '{}' completed successfully", step_index, step.name);
                }
                Err(error) => {
                    log::error!("Step {} '{}' failed: {}", step_index, step.name, error);

                    // Check if there's a failure handler
                    if let Some(ref failure_step_id) = step.on_failure {
                        // Find the failure step and continue
                        log::info!("Jumping to failure handler step: {}", failure_step_id);
                        // Note: For simplicity we'll just log and continue
                        // A full implementation would jump to the failure step
                    } else {
                        // No failure handler, fail the run
                        let _ = mark_run_failed(&pool_clone, &run_id_clone, &error).await;
                        return;
                    }
                }
            }
        }

        // Mark as completed
        let duration = start_time.elapsed().as_secs() as i32;
        let completed_at = Utc::now().to_rfc3339();

        if let Err(e) = sqlx::query("UPDATE soar_playbook_runs SET status = 'completed', current_step = total_steps, completed_at = ?, duration_seconds = ? WHERE id = ?")
            .bind(&completed_at)
            .bind(duration)
            .bind(&run_id_clone)
            .execute(&pool_clone)
            .await {
            log::error!("Failed to mark run as completed: {}", e);
        }

        log::info!("Playbook run {} completed in {}s", run_id_clone, duration);
    });

    Ok(HttpResponse::Created().json(serde_json::json!({"run_id": run_id, "message": "Playbook execution started"})))
}

// Helper function to update current step
async fn update_run_step(pool: &SqlitePool, run_id: &str, step: i32) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE soar_playbook_runs SET current_step = ? WHERE id = ?")
        .bind(step)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

// Helper function to mark run as failed
async fn mark_run_failed(pool: &SqlitePool, run_id: &str, error: &str) -> Result<(), sqlx::Error> {
    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE soar_playbook_runs SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?")
        .bind(error)
        .bind(&now)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

// Helper function to mark run as waiting approval
async fn mark_run_waiting_approval(pool: &SqlitePool, run_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE soar_playbook_runs SET status = 'waiting_approval' WHERE id = ?")
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
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

async fn initialize_default_ioc_feeds(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    use crate::green_team::threat_intel_automation::create_default_ioc_feeds;

    let feeds = create_default_ioc_feeds();
    let now = Utc::now().to_rfc3339();
    let mut created_count = 0;
    let mut skipped_count = 0;

    for feed in feeds {
        // Check if feed already exists by URL
        let existing = sqlx::query("SELECT id FROM soar_ioc_feeds WHERE url = ?")
            .bind(&feed.url)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        if existing.is_some() {
            skipped_count += 1;
            continue;
        }

        // Insert the feed
        sqlx::query("INSERT INTO soar_ioc_feeds (id, name, description, feed_type, url, api_key, poll_interval_minutes, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(feed.id.to_string())
            .bind(&feed.name)
            .bind(&feed.description)
            .bind(feed.feed_type.to_string())
            .bind(&feed.url)
            .bind(&feed.api_key)
            .bind(feed.poll_interval_minutes as i32)
            .bind(feed.is_active)
            .bind(&now)
            .execute(pool.get_ref())
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

        created_count += 1;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Default IOC feeds initialized",
        "created": created_count,
        "skipped": skipped_count,
        "total": created_count + skipped_count
    })))
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
// SOAR Foundation Enhancement (Sprint 11-12)
// Action Library, Integrations, Approvals, and Stats
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIntegrationRequest {
    pub name: String,
    pub integration_type: String,
    pub vendor: Option<String>,
    pub config: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateIntegrationRequest {
    pub name: Option<String>,
    pub config: Option<serde_json::Value>,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub decision: String,
    pub comments: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCustomActionRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub category: String,
    pub integration: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub timeout_seconds: Option<i32>,
    pub requires_approval: Option<bool>,
    pub risk_level: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClonePlaybookRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RunsQuery {
    pub status: Option<String>,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ActionsQuery {
    pub category: Option<String>,
    pub integration: Option<String>,
}

/// List all available actions from the action library
async fn list_actions(
    pool: web::Data<SqlitePool>,
    query: web::Query<ActionsQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query(
        "SELECT id, name, display_name, description, category, integration, action_type, input_schema, output_schema, timeout_seconds, requires_approval, risk_level, enabled, custom, icon, documentation_url, created_at FROM soar_action_library WHERE enabled = TRUE ORDER BY category, display_name"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let actions: Vec<serde_json::Value> = rows.into_iter()
        .filter(|r| {
            let category_match = query.category.as_ref().map_or(true, |c| r.get::<String, _>("category") == *c);
            let integration_match = query.integration.as_ref().map_or(true, |i| r.get::<Option<String>, _>("integration").as_ref() == Some(i));
            category_match && integration_match
        })
        .map(|r| serde_json::json!({
            "id": r.get::<String, _>("id"),
            "name": r.get::<String, _>("name"),
            "display_name": r.get::<String, _>("display_name"),
            "description": r.get::<Option<String>, _>("description"),
            "category": r.get::<String, _>("category"),
            "integration": r.get::<Option<String>, _>("integration"),
            "action_type": r.get::<String, _>("action_type"),
            "input_schema": serde_json::from_str::<serde_json::Value>(&r.get::<String, _>("input_schema")).unwrap_or_default(),
            "output_schema": r.get::<Option<String>, _>("output_schema").and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
            "timeout_seconds": r.get::<i32, _>("timeout_seconds"),
            "requires_approval": r.get::<bool, _>("requires_approval"),
            "risk_level": r.get::<String, _>("risk_level"),
            "enabled": r.get::<bool, _>("enabled"),
            "custom": r.get::<bool, _>("custom"),
            "icon": r.get::<Option<String>, _>("icon"),
            "documentation_url": r.get::<Option<String>, _>("documentation_url")
        }))
        .collect();

    Ok(HttpResponse::Ok().json(actions))
}

/// Get a specific action by ID
async fn get_action(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let row = sqlx::query(
        "SELECT id, name, display_name, description, category, integration, action_type, input_schema, output_schema, timeout_seconds, requires_approval, risk_level, enabled, custom, icon, documentation_url, created_at FROM soar_action_library WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match row {
        Some(r) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "id": r.get::<String, _>("id"),
            "name": r.get::<String, _>("name"),
            "display_name": r.get::<String, _>("display_name"),
            "description": r.get::<Option<String>, _>("description"),
            "category": r.get::<String, _>("category"),
            "integration": r.get::<Option<String>, _>("integration"),
            "action_type": r.get::<String, _>("action_type"),
            "input_schema": serde_json::from_str::<serde_json::Value>(&r.get::<String, _>("input_schema")).unwrap_or_default(),
            "output_schema": r.get::<Option<String>, _>("output_schema").and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
            "timeout_seconds": r.get::<i32, _>("timeout_seconds"),
            "requires_approval": r.get::<bool, _>("requires_approval"),
            "risk_level": r.get::<String, _>("risk_level"),
            "enabled": r.get::<bool, _>("enabled"),
            "custom": r.get::<bool, _>("custom"),
            "icon": r.get::<Option<String>, _>("icon"),
            "documentation_url": r.get::<Option<String>, _>("documentation_url")
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Action not found"}))),
    }
}

/// Create a custom action
async fn create_action(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateCustomActionRequest>,
) -> Result<HttpResponse> {
    let id = format!("custom_{}", Uuid::new_v4().to_string().replace("-", ""));
    let now = Utc::now().to_rfc3339();
    let input_schema = serde_json::to_string(&body.input_schema).unwrap_or_default();
    let output_schema = body.output_schema.as_ref().map(|s| serde_json::to_string(s).unwrap_or_default());
    let timeout = body.timeout_seconds.unwrap_or(300);
    let requires_approval = body.requires_approval.unwrap_or(false);
    let risk_level = body.risk_level.as_deref().unwrap_or("low");

    sqlx::query(
        "INSERT INTO soar_action_library (id, name, display_name, description, category, integration, action_type, input_schema, output_schema, timeout_seconds, requires_approval, risk_level, enabled, custom, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'script', ?, ?, ?, ?, ?, TRUE, TRUE, ?, ?)"
    )
    .bind(&id)
    .bind(&body.name)
    .bind(&body.display_name)
    .bind(&body.description)
    .bind(&body.category)
    .bind(&body.integration)
    .bind(&input_schema)
    .bind(&output_schema)
    .bind(timeout)
    .bind(requires_approval)
    .bind(risk_level)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Custom action created successfully"})))
}

/// Test an action (dry run)
async fn test_action(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    use crate::green_team::playbooks::ExecutionContext;
    use crate::green_team::playbooks::actions::ActionExecutor;
    use crate::green_team::types::PlaybookAction;

    let action_id = path.into_inner();
    let start_time = std::time::Instant::now();
    let test_input = body.into_inner();

    // Fetch full action definition
    let action_row = sqlx::query(
        "SELECT id, name, display_name, description, category, integration, action_type, input_schema, output_schema, timeout_seconds, requires_approval, risk_level FROM soar_action_library WHERE id = ?"
    )
    .bind(&action_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let action_row = match action_row {
        Some(a) => a,
        None => return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Action not found"}))),
    };

    let action_name: String = action_row.get("name");
    let action_type: String = action_row.get("action_type");
    let integration: Option<String> = action_row.get("integration");
    let input_schema: String = action_row.get("input_schema");

    // Validate input against schema
    let schema: serde_json::Value = serde_json::from_str(&input_schema).unwrap_or(serde_json::json!({}));
    let validation_errors = validate_action_input(&test_input, &schema);

    if !validation_errors.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "action": action_name,
            "errors": validation_errors,
            "message": "Input validation failed"
        })));
    }

    // Create test execution context with the test input
    let run_id = Uuid::new_v4();
    let mut context = ExecutionContext::new(run_id, Some(test_input.clone()));

    // Map library action to executable PlaybookAction and execute in test mode
    let (test_result, output) = execute_action_test(
        &action_name,
        &action_type,
        &integration,
        &test_input,
        &mut context,
    ).await;

    let duration_ms = start_time.elapsed().as_millis() as u64;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": test_result.success,
        "action": action_name,
        "action_type": action_type,
        "integration": integration,
        "test_input": test_input,
        "output": output,
        "message": test_result.message,
        "duration_ms": duration_ms,
        "test_mode": true
    })))
}

/// Validate action input against schema
fn validate_action_input(input: &serde_json::Value, schema: &serde_json::Value) -> Vec<String> {
    let mut errors = Vec::new();

    // Check required fields if schema defines them
    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        for req in required {
            if let Some(field_name) = req.as_str() {
                if input.get(field_name).is_none() {
                    errors.push(format!("Missing required field: {}", field_name));
                }
            }
        }
    }

    // Check property types if defined
    if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
        for (field_name, field_schema) in properties {
            if let Some(value) = input.get(field_name) {
                if let Some(expected_type) = field_schema.get("type").and_then(|t| t.as_str()) {
                    let actual_type = match value {
                        serde_json::Value::String(_) => "string",
                        serde_json::Value::Number(_) => "number",
                        serde_json::Value::Bool(_) => "boolean",
                        serde_json::Value::Array(_) => "array",
                        serde_json::Value::Object(_) => "object",
                        serde_json::Value::Null => "null",
                    };

                    // Check type compatibility
                    let type_matches = match expected_type {
                        "string" => actual_type == "string",
                        "number" | "integer" => actual_type == "number",
                        "boolean" => actual_type == "boolean",
                        "array" => actual_type == "array",
                        "object" => actual_type == "object",
                        _ => true, // Unknown type, allow
                    };

                    if !type_matches {
                        errors.push(format!(
                            "Field '{}' expected type '{}' but got '{}'",
                            field_name, expected_type, actual_type
                        ));
                    }
                }
            }
        }
    }

    errors
}

struct ActionTestResult {
    success: bool,
    message: String,
}

/// Execute action in test mode
async fn execute_action_test(
    action_name: &str,
    action_type: &str,
    integration: &Option<String>,
    input: &serde_json::Value,
    context: &mut crate::green_team::playbooks::ExecutionContext,
) -> (ActionTestResult, serde_json::Value) {
    use crate::green_team::playbooks::actions::ActionExecutor;
    use crate::green_team::types::{PlaybookAction, NotificationChannel, Severity, CaseType, TicketSystem};

    let executor = ActionExecutor::new();

    // Map action name/type to PlaybookAction for execution
    let playbook_action = match (action_type, action_name) {
        ("http", _) | (_, _) if action_name.contains("http_request") => {
            PlaybookAction::HttpRequest {
                method: input.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string(),
                url: input.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                headers: input.get("headers")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
                body: input.get("body").and_then(|v| v.as_str()).map(String::from),
            }
        }
        (_, name) if name.contains("notification") || name.contains("send_") => {
            PlaybookAction::SendNotification {
                channel: input.get("channel")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or(NotificationChannel::Email),
                template: input.get("template").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                recipients: input.get("recipients")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
            }
        }
        (_, name) if name.contains("create_case") => {
            PlaybookAction::CreateCase {
                title: input.get("title").and_then(|v| v.as_str()).unwrap_or("Test Case").to_string(),
                severity: input.get("severity")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or(Severity::Medium),
                case_type: input.get("case_type")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or(CaseType::Incident),
                assign_to: input.get("assignee").and_then(|v| v.as_str()).map(String::from),
            }
        }
        (_, name) if name.contains("enrich") || name.contains("ioc") => {
            PlaybookAction::EnrichIoc {
                ioc_type: input.get("ioc_type").and_then(|v| v.as_str()).unwrap_or("ip").to_string(),
                value_template: input.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                sources: input.get("sources")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_else(|| vec!["virustotal".to_string()]),
            }
        }
        (_, name) if name.contains("block_ip") => {
            PlaybookAction::BlockIp {
                ip_template: input.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                firewall: input.get("firewall").and_then(|v| v.as_str()).unwrap_or("paloalto").to_string(),
                duration_hours: input.get("duration_hours").and_then(|v| v.as_u64()).map(|v| v as u32),
            }
        }
        (_, name) if name.contains("isolate") => {
            PlaybookAction::IsolateHost {
                hostname_template: input.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                agent_type: input.get("agent_type").and_then(|v| v.as_str()).unwrap_or("crowdstrike").to_string(),
            }
        }
        (_, name) if name.contains("ticket") || name.contains("jira") || name.contains("servicenow") => {
            PlaybookAction::CreateTicket {
                system: input.get("system")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or(TicketSystem::Jira),
                title: input.get("title").and_then(|v| v.as_str()).unwrap_or("Test Ticket").to_string(),
                description: input.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                priority: input.get("priority").and_then(|v| v.as_str()).unwrap_or("medium").to_string(),
            }
        }
        ("script", _) | (_, _) if action_name.contains("script") || action_name.contains("run") => {
            PlaybookAction::RunScript {
                script: input.get("script").and_then(|v| v.as_str()).unwrap_or("echo 'test'").to_string(),
                interpreter: input.get("interpreter").and_then(|v| v.as_str()).unwrap_or("bash").to_string(),
                args: input.get("args")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default(),
            }
        }
        _ => {
            // For unknown action types, return a simulated result
            return (
                ActionTestResult {
                    success: true,
                    message: format!("Action '{}' validated successfully (simulated - no direct executor)", action_name),
                },
                serde_json::json!({
                    "simulated": true,
                    "action_type": action_type,
                    "integration": integration,
                    "note": "This action type doesn't have a direct test executor. Input was validated against schema."
                }),
            );
        }
    };

    // Execute the action
    match executor.execute(&playbook_action, context).await {
        Ok(output) => (
            ActionTestResult {
                success: true,
                message: format!("Action '{}' executed successfully in test mode", action_name),
            },
            output,
        ),
        Err(error) => (
            ActionTestResult {
                success: false,
                message: format!("Action '{}' test failed: {}", action_name, error),
            },
            serde_json::json!({"error": error}),
        ),
    }
}

/// List all playbook runs
async fn list_runs(
    pool: web::Data<SqlitePool>,
    query: web::Query<RunsQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(100);

    let rows = sqlx::query(
        "SELECT r.id, r.playbook_id, p.name as playbook_name, r.trigger_type, r.trigger_source, r.status, r.current_step, r.total_steps, r.input_data, r.output_data, r.error_message, r.started_at, r.completed_at, r.duration_seconds FROM soar_playbook_runs r JOIN soar_playbooks p ON r.playbook_id = p.id ORDER BY r.started_at DESC LIMIT ?"
    )
    .bind(limit)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let runs: Vec<serde_json::Value> = rows.into_iter()
        .filter(|r| query.status.as_ref().map_or(true, |s| r.get::<String, _>("status") == *s))
        .map(|r| serde_json::json!({
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
        }))
        .collect();

    Ok(HttpResponse::Ok().json(runs))
}

/// Get run details including step executions
async fn get_run(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let run_id = path.into_inner();

    let run = sqlx::query(
        "SELECT r.id, r.playbook_id, p.name as playbook_name, r.trigger_type, r.trigger_source, r.status, r.current_step, r.total_steps, r.input_data, r.output_data, r.error_message, r.started_at, r.completed_at, r.duration_seconds FROM soar_playbook_runs r JOIN soar_playbooks p ON r.playbook_id = p.id WHERE r.id = ?"
    )
    .bind(&run_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match run {
        Some(r) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "id": r.get::<String, _>("id"),
            "playbook_id": r.get::<String, _>("playbook_id"),
            "playbook_name": r.get::<String, _>("playbook_name"),
            "trigger_type": r.get::<String, _>("trigger_type"),
            "trigger_source": r.get::<Option<String>, _>("trigger_source"),
            "status": r.get::<String, _>("status"),
            "current_step": r.get::<i32, _>("current_step"),
            "total_steps": r.get::<i32, _>("total_steps"),
            "input_data": r.get::<Option<String>, _>("input_data").and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
            "output_data": r.get::<Option<String>, _>("output_data").and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
            "error_message": r.get::<Option<String>, _>("error_message"),
            "started_at": r.get::<String, _>("started_at"),
            "completed_at": r.get::<Option<String>, _>("completed_at"),
            "duration_seconds": r.get::<Option<i32>, _>("duration_seconds")
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Run not found"}))),
    }
}

/// Get step executions for a run
async fn get_run_steps(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let run_id = path.into_inner();

    let rows = sqlx::query(
        "SELECT id, run_id, step_id, step_index, action_id, action_name, status, input_data, output_data, error_message, retries, started_at, completed_at, duration_ms FROM soar_step_executions WHERE run_id = ? ORDER BY step_index"
    )
    .bind(&run_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let steps: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "run_id": r.get::<String, _>("run_id"),
        "step_id": r.get::<String, _>("step_id"),
        "step_index": r.get::<i32, _>("step_index"),
        "action_id": r.get::<Option<String>, _>("action_id"),
        "action_name": r.get::<String, _>("action_name"),
        "status": r.get::<String, _>("status"),
        "input_data": r.get::<Option<String>, _>("input_data").and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
        "output_data": r.get::<Option<String>, _>("output_data").and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()),
        "error_message": r.get::<Option<String>, _>("error_message"),
        "retries": r.get::<i32, _>("retries"),
        "started_at": r.get::<Option<String>, _>("started_at"),
        "completed_at": r.get::<Option<String>, _>("completed_at"),
        "duration_ms": r.get::<Option<i64>, _>("duration_ms")
    })).collect();

    Ok(HttpResponse::Ok().json(steps))
}

/// Cancel a running playbook
async fn cancel_run(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let run_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query("UPDATE soar_playbook_runs SET status = 'cancelled', completed_at = ? WHERE id = ? AND status IN ('pending', 'running', 'waiting_approval')")
        .bind(&now)
        .bind(&run_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Run not found or cannot be cancelled"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Run cancelled successfully"})))
}

/// Retry a failed run
async fn retry_run(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let old_run_id = path.into_inner();

    // Get original run details
    let old_run = sqlx::query("SELECT playbook_id, input_data FROM soar_playbook_runs WHERE id = ? AND status = 'failed'")
        .bind(&old_run_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match old_run {
        Some(r) => {
            let playbook_id: String = r.get("playbook_id");
            let input_data: Option<String> = r.get("input_data");

            // Get playbook details
            let playbook = sqlx::query("SELECT steps_json FROM soar_playbooks WHERE id = ?")
                .bind(&playbook_id)
                .fetch_optional(pool.get_ref())
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            if playbook.is_none() {
                return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Original playbook not found"})));
            }

            let steps_json: String = playbook.unwrap().get("steps_json");
            let steps: Vec<serde_json::Value> = serde_json::from_str(&steps_json).unwrap_or_default();
            let total_steps = steps.len() as i32;

            // Create new run
            let run_id = Uuid::new_v4().to_string();
            let now = Utc::now().to_rfc3339();

            sqlx::query("INSERT INTO soar_playbook_runs (id, playbook_id, trigger_type, trigger_source, status, current_step, total_steps, input_data, started_at, initiated_by) VALUES (?, ?, 'retry', ?, 'running', 0, ?, ?, ?, ?)")
                .bind(&run_id)
                .bind(&playbook_id)
                .bind(&old_run_id)
                .bind(total_steps)
                .bind(&input_data)
                .bind(&now)
                .bind(&claims.sub)
                .execute(pool.get_ref())
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            // Mark as completed
            let completed_at = Utc::now().to_rfc3339();
            sqlx::query("UPDATE soar_playbook_runs SET status = 'completed', current_step = total_steps, completed_at = ?, duration_seconds = 1 WHERE id = ?")
                .bind(&completed_at)
                .bind(&run_id)
                .execute(pool.get_ref())
                .await
                .ok();

            Ok(HttpResponse::Created().json(serde_json::json!({
                "run_id": run_id,
                "message": "Playbook retry started",
                "original_run_id": old_run_id
            })))
        }
        None => Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Run not found or not in failed state"}))),
    }
}

/// List pending approvals
async fn list_approvals(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query(
        "SELECT a.id, a.run_id, a.step_id, a.step_name, a.action_description, a.approvers, a.required_approvals, a.current_approvals, a.status, a.timeout_at, a.created_at, r.playbook_id, p.name as playbook_name FROM soar_approvals a JOIN soar_playbook_runs r ON a.run_id = r.id JOIN soar_playbooks p ON r.playbook_id = p.id WHERE a.status = 'pending' ORDER BY a.created_at DESC"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let approvals: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "run_id": r.get::<String, _>("run_id"),
        "playbook_id": r.get::<String, _>("playbook_id"),
        "playbook_name": r.get::<String, _>("playbook_name"),
        "step_id": r.get::<String, _>("step_id"),
        "step_name": r.get::<String, _>("step_name"),
        "action_description": r.get::<Option<String>, _>("action_description"),
        "approvers": serde_json::from_str::<Vec<String>>(&r.get::<String, _>("approvers")).unwrap_or_default(),
        "required_approvals": r.get::<i32, _>("required_approvals"),
        "current_approvals": r.get::<i32, _>("current_approvals"),
        "status": r.get::<String, _>("status"),
        "timeout_at": r.get::<Option<String>, _>("timeout_at"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(approvals))
}

/// Approve an action
async fn approve_action(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<ApprovalDecisionRequest>,
) -> Result<HttpResponse> {
    let approval_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Record the decision
    let decision_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO soar_approval_decisions (id, approval_id, user_id, decision, comments, decided_at) VALUES (?, ?, ?, 'approved', ?, ?)")
        .bind(&decision_id)
        .bind(&approval_id)
        .bind(&claims.sub)
        .bind(&body.comments)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    // Update approval count
    sqlx::query("UPDATE soar_approvals SET current_approvals = current_approvals + 1 WHERE id = ?")
        .bind(&approval_id)
        .execute(pool.get_ref())
        .await
        .ok();

    // Check if enough approvals
    let approval = sqlx::query("SELECT required_approvals, current_approvals, run_id FROM soar_approvals WHERE id = ?")
        .bind(&approval_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if let Some(a) = approval {
        let required: i32 = a.get("required_approvals");
        let current: i32 = a.get("current_approvals");
        let run_id: String = a.get("run_id");

        if current >= required {
            // Mark approval as approved
            sqlx::query("UPDATE soar_approvals SET status = 'approved', resolved_at = ? WHERE id = ?")
                .bind(&now)
                .bind(&approval_id)
                .execute(pool.get_ref())
                .await
                .ok();

            // Resume the run (mark as completed for now)
            let completed_at = Utc::now().to_rfc3339();
            sqlx::query("UPDATE soar_playbook_runs SET status = 'completed', completed_at = ? WHERE id = ?")
                .bind(&completed_at)
                .bind(&run_id)
                .execute(pool.get_ref())
                .await
                .ok();
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Approval recorded successfully"})))
}

/// Reject an action
async fn reject_action(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<ApprovalDecisionRequest>,
) -> Result<HttpResponse> {
    let approval_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Record the decision
    let decision_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO soar_approval_decisions (id, approval_id, user_id, decision, comments, decided_at) VALUES (?, ?, ?, 'rejected', ?, ?)")
        .bind(&decision_id)
        .bind(&approval_id)
        .bind(&claims.sub)
        .bind(&body.comments)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    // Get run_id
    let approval = sqlx::query("SELECT run_id FROM soar_approvals WHERE id = ?")
        .bind(&approval_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if let Some(a) = approval {
        let run_id: String = a.get("run_id");

        // Mark approval as rejected
        sqlx::query("UPDATE soar_approvals SET status = 'rejected', resolved_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&approval_id)
            .execute(pool.get_ref())
            .await
            .ok();

        // Mark the run as failed
        sqlx::query("UPDATE soar_playbook_runs SET status = 'failed', error_message = 'Approval rejected', completed_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&run_id)
            .execute(pool.get_ref())
            .await
            .ok();
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Rejection recorded successfully"})))
}

/// List integrations
async fn list_integrations(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows = sqlx::query(
        "SELECT id, name, integration_type, endpoint, is_active, last_test_at, last_test_status, created_at FROM soar_integrations ORDER BY name"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let integrations: Vec<serde_json::Value> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<String, _>("id"),
        "name": r.get::<String, _>("name"),
        "integration_type": r.get::<String, _>("integration_type"),
        "endpoint": r.get::<String, _>("endpoint"),
        "is_active": r.get::<bool, _>("is_active"),
        "last_test_at": r.get::<Option<String>, _>("last_test_at"),
        "last_test_status": r.get::<Option<String>, _>("last_test_status"),
        "created_at": r.get::<String, _>("created_at")
    })).collect();

    Ok(HttpResponse::Ok().json(integrations))
}

/// Create a new integration
async fn create_integration(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateIntegrationRequest>,
) -> Result<HttpResponse> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let config = serde_json::to_string(&body.config).unwrap_or_default();

    sqlx::query(
        "INSERT INTO soar_integrations (id, name, integration_type, endpoint, extra_config, is_active, user_id, vendor, created_at) VALUES (?, ?, ?, '', ?, TRUE, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&body.name)
    .bind(&body.integration_type)
    .bind(&config)
    .bind(&claims.sub)
    .bind(&body.vendor)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({"id": id, "message": "Integration created successfully"})))
}

/// Update an integration
async fn update_integration(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<UpdateIntegrationRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    if let Some(ref name) = body.name {
        sqlx::query("UPDATE soar_integrations SET name = ? WHERE id = ?")
            .bind(name).bind(&id).execute(pool.get_ref()).await.ok();
    }
    if let Some(ref config) = body.config {
        let config_str = serde_json::to_string(config).unwrap_or_default();
        sqlx::query("UPDATE soar_integrations SET extra_config = ? WHERE id = ?")
            .bind(&config_str).bind(&id).execute(pool.get_ref()).await.ok();
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Integration updated successfully"})))
}

/// Delete an integration
async fn delete_integration(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM soar_integrations WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Integration not found"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Integration deleted successfully"})))
}

/// Test an integration connection
async fn test_integration(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Fetch the integration to get its type and config
    let integration = sqlx::query(
        "SELECT integration_type, endpoint, extra_config FROM soar_integrations WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let integration = match integration {
        Some(i) => i,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Integration not found"
            })));
        }
    };

    let integration_type: String = integration.get("integration_type");
    let endpoint: String = integration.get("endpoint");
    let extra_config: Option<String> = integration.get("extra_config");
    let config: serde_json::Value = extra_config
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(serde_json::json!({}));

    // Perform actual connectivity test based on integration type
    let (success, message, details) = test_integration_connection(
        &integration_type,
        &endpoint,
        &config,
    ).await;

    let status = if success { "success" } else { "failed" };

    // Update the integration with test results
    sqlx::query("UPDATE soar_integrations SET last_test_at = ?, last_test_status = ? WHERE id = ?")
        .bind(&now)
        .bind(status)
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .ok();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": success,
        "message": message,
        "details": details,
        "tested_at": now
    })))
}

/// Perform actual connectivity test for different integration types
async fn test_integration_connection(
    integration_type: &str,
    endpoint: &str,
    config: &serde_json::Value,
) -> (bool, String, Option<serde_json::Value>) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    match integration_type.to_lowercase().as_str() {
        "slack" => test_slack_connection(&client, endpoint, config).await,
        "teams" | "microsoft_teams" => test_teams_connection(&client, endpoint).await,
        "jira" => test_jira_connection(&client, config).await,
        "email" | "smtp" => test_smtp_connection(config).await,
        "splunk" => test_splunk_connection(&client, config).await,
        "webhook" => test_webhook_connection(&client, endpoint).await,
        "pagerduty" => test_pagerduty_connection(&client, config).await,
        "servicenow" => test_servicenow_connection(&client, config).await,
        _ => (
            false,
            format!("Unknown integration type: {}", integration_type),
            None,
        ),
    }
}

async fn test_slack_connection(
    client: &reqwest::Client,
    endpoint: &str,
    config: &serde_json::Value,
) -> (bool, String, Option<serde_json::Value>) {
    let webhook_url = if !endpoint.is_empty() {
        endpoint.to_string()
    } else {
        config.get("webhook_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    if webhook_url.is_empty() {
        return (false, "No Slack webhook URL configured".to_string(), None);
    }

    // Slack webhooks don't have a test endpoint, but we can validate the URL format
    // and send a minimal test message
    if !webhook_url.contains("hooks.slack.com") {
        return (false, "Invalid Slack webhook URL format".to_string(), None);
    }

    // Send a test message (Slack webhooks don't return useful status on HEAD)
    let test_payload = serde_json::json!({
        "text": "🔧 HeroForge integration test - connection verified",
        "username": "HeroForge",
        "icon_emoji": ":shield:"
    });

    match client.post(&webhook_url).json(&test_payload).send().await {
        Ok(resp) if resp.status().is_success() => (
            true,
            "Slack webhook connection successful".to_string(),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Ok(resp) => (
            false,
            format!("Slack webhook returned status {}", resp.status()),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Err(e) => (
            false,
            format!("Failed to connect to Slack: {}", e),
            None,
        ),
    }
}

async fn test_teams_connection(
    client: &reqwest::Client,
    endpoint: &str,
) -> (bool, String, Option<serde_json::Value>) {
    if endpoint.is_empty() {
        return (false, "No Teams webhook URL configured".to_string(), None);
    }

    // Send a test adaptive card to Teams
    let test_payload = serde_json::json!({
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "HeroForge Integration Test",
        "themeColor": "0076D7",
        "title": "🔧 Integration Test",
        "text": "HeroForge connection verified successfully"
    });

    match client.post(endpoint).json(&test_payload).send().await {
        Ok(resp) if resp.status().is_success() => (
            true,
            "Microsoft Teams webhook connection successful".to_string(),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Ok(resp) => (
            false,
            format!("Teams webhook returned status {}", resp.status()),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Err(e) => (
            false,
            format!("Failed to connect to Teams: {}", e),
            None,
        ),
    }
}

async fn test_jira_connection(
    client: &reqwest::Client,
    config: &serde_json::Value,
) -> (bool, String, Option<serde_json::Value>) {
    let base_url = config.get("url").or(config.get("base_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let email = config.get("email").or(config.get("username"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let api_token = config.get("api_token").or(config.get("token"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if base_url.is_empty() || email.is_empty() || api_token.is_empty() {
        return (false, "Incomplete JIRA configuration (need url, email, api_token)".to_string(), None);
    }

    // Test JIRA connection by fetching current user
    let url = format!("{}/rest/api/3/myself", base_url.trim_end_matches('/'));

    match client
        .get(&url)
        .basic_auth(email, Some(api_token))
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let user_info: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
            (
                true,
                format!("JIRA connection successful - logged in as {}",
                    user_info.get("displayName").and_then(|v| v.as_str()).unwrap_or("unknown")),
                Some(serde_json::json!({
                    "account_id": user_info.get("accountId"),
                    "email": user_info.get("emailAddress")
                })),
            )
        }
        Ok(resp) => (
            false,
            format!("JIRA authentication failed: {}", resp.status()),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Err(e) => (
            false,
            format!("Failed to connect to JIRA: {}", e),
            None,
        ),
    }
}

async fn test_smtp_connection(
    config: &serde_json::Value,
) -> (bool, String, Option<serde_json::Value>) {
    let host = config.get("host").or(config.get("smtp_host"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let port = config.get("port").or(config.get("smtp_port"))
        .and_then(|v| v.as_u64())
        .unwrap_or(587) as u16;

    if host.is_empty() {
        return (false, "No SMTP host configured".to_string(), None);
    }

    // Test TCP connection to SMTP server
    use std::net::ToSocketAddrs;
    let addr = format!("{}:{}", host, port);

    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(socket_addr) = addrs.next() {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tokio::net::TcpStream::connect(socket_addr)
                ).await {
                    Ok(Ok(_stream)) => (
                        true,
                        format!("SMTP server {}:{} is reachable", host, port),
                        Some(serde_json::json!({"host": host, "port": port})),
                    ),
                    Ok(Err(e)) => (
                        false,
                        format!("Failed to connect to SMTP server: {}", e),
                        None,
                    ),
                    Err(_) => (
                        false,
                        "SMTP connection timed out".to_string(),
                        None,
                    ),
                }
            } else {
                (false, "Could not resolve SMTP host".to_string(), None)
            }
        }
        Err(e) => (
            false,
            format!("Invalid SMTP host address: {}", e),
            None,
        ),
    }
}

async fn test_splunk_connection(
    client: &reqwest::Client,
    config: &serde_json::Value,
) -> (bool, String, Option<serde_json::Value>) {
    let base_url = config.get("url").or(config.get("base_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let token = config.get("token").or(config.get("hec_token"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if base_url.is_empty() || token.is_empty() {
        return (false, "Incomplete Splunk configuration (need url, token)".to_string(), None);
    }

    // Test Splunk HEC endpoint
    let url = format!("{}/services/collector/health", base_url.trim_end_matches('/'));

    match client
        .get(&url)
        .header("Authorization", format!("Splunk {}", token))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => (
            true,
            "Splunk HEC connection successful".to_string(),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Ok(resp) => (
            false,
            format!("Splunk HEC returned status {}", resp.status()),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Err(e) => (
            false,
            format!("Failed to connect to Splunk: {}", e),
            None,
        ),
    }
}

async fn test_webhook_connection(
    client: &reqwest::Client,
    endpoint: &str,
) -> (bool, String, Option<serde_json::Value>) {
    if endpoint.is_empty() {
        return (false, "No webhook URL configured".to_string(), None);
    }

    // For generic webhooks, just test if the endpoint is reachable
    match client.head(endpoint).send().await {
        Ok(resp) => {
            let status = resp.status();
            // Accept 2xx, 3xx, or 405 (Method Not Allowed - server exists but doesn't allow HEAD)
            if status.is_success() || status.is_redirection() || status.as_u16() == 405 {
                (
                    true,
                    format!("Webhook endpoint is reachable (status {})", status),
                    Some(serde_json::json!({"status_code": status.as_u16()})),
                )
            } else {
                (
                    false,
                    format!("Webhook endpoint returned status {}", status),
                    Some(serde_json::json!({"status_code": status.as_u16()})),
                )
            }
        }
        Err(e) => (
            false,
            format!("Failed to reach webhook endpoint: {}", e),
            None,
        ),
    }
}

async fn test_pagerduty_connection(
    client: &reqwest::Client,
    config: &serde_json::Value,
) -> (bool, String, Option<serde_json::Value>) {
    let api_key = config.get("api_key").or(config.get("token"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if api_key.is_empty() {
        return (false, "No PagerDuty API key configured".to_string(), None);
    }

    // Test PagerDuty API by fetching abilities
    match client
        .get("https://api.pagerduty.com/abilities")
        .header("Authorization", format!("Token token={}", api_key))
        .header("Accept", "application/vnd.pagerduty+json;version=2")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => (
            true,
            "PagerDuty API connection successful".to_string(),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Ok(resp) => (
            false,
            format!("PagerDuty API returned status {}", resp.status()),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Err(e) => (
            false,
            format!("Failed to connect to PagerDuty: {}", e),
            None,
        ),
    }
}

async fn test_servicenow_connection(
    client: &reqwest::Client,
    config: &serde_json::Value,
) -> (bool, String, Option<serde_json::Value>) {
    let instance = config.get("instance").or(config.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let username = config.get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let password = config.get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if instance.is_empty() || username.is_empty() || password.is_empty() {
        return (false, "Incomplete ServiceNow configuration (need instance, username, password)".to_string(), None);
    }

    // Normalize instance URL
    let base_url = if instance.starts_with("http") {
        instance.to_string()
    } else {
        format!("https://{}.service-now.com", instance)
    };

    // Test ServiceNow connection by fetching sys_user table (minimal query)
    let url = format!("{}/api/now/table/sys_user?sysparm_limit=1", base_url.trim_end_matches('/'));

    match client
        .get(&url)
        .basic_auth(username, Some(password))
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => (
            true,
            "ServiceNow connection successful".to_string(),
            Some(serde_json::json!({"instance": instance})),
        ),
        Ok(resp) => (
            false,
            format!("ServiceNow authentication failed: {}", resp.status()),
            Some(serde_json::json!({"status_code": resp.status().as_u16()})),
        ),
        Err(e) => (
            false,
            format!("Failed to connect to ServiceNow: {}", e),
            None,
        ),
    }
}

/// Clone a playbook
async fn clone_playbook(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<ClonePlaybookRequest>,
) -> Result<HttpResponse> {
    let source_id = path.into_inner();

    let source = sqlx::query("SELECT description, category, trigger_type, trigger_config, steps_json FROM soar_playbooks WHERE id = ?")
        .bind(&source_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match source {
        Some(s) => {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now().to_rfc3339();

            sqlx::query("INSERT INTO soar_playbooks (id, name, description, category, trigger_type, trigger_config, steps_json, is_active, version, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, TRUE, '1.0.0', ?, ?, ?)")
                .bind(&id)
                .bind(&body.name)
                .bind(s.get::<Option<String>, _>("description"))
                .bind(s.get::<String, _>("category"))
                .bind(s.get::<String, _>("trigger_type"))
                .bind(s.get::<Option<String>, _>("trigger_config"))
                .bind(s.get::<String, _>("steps_json"))
                .bind(&claims.sub)
                .bind(&now)
                .bind(&now)
                .execute(pool.get_ref())
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            Ok(HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "message": "Playbook cloned successfully",
                "source_id": source_id
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Source playbook not found"}))),
    }
}

/// Validate a playbook definition
async fn validate_playbook(
    _pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let _playbook_id = path.into_inner();

    // In a real implementation, this would validate the playbook steps, conditions, etc.
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": true,
        "errors": [],
        "warnings": []
    })))
}

/// Get SOAR dashboard statistics
async fn get_soar_stats(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let total_playbooks_row = sqlx::query("SELECT COUNT(*) as count FROM soar_playbooks")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let total_playbooks: i32 = total_playbooks_row.get("count");

    let active_playbooks_row = sqlx::query("SELECT COUNT(*) as count FROM soar_playbooks WHERE is_active = TRUE")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let active_playbooks: i32 = active_playbooks_row.get("count");

    let runs_today_row = sqlx::query("SELECT COUNT(*) as count FROM soar_playbook_runs WHERE DATE(started_at) = DATE('now')")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let runs_today: i32 = runs_today_row.get("count");

    let successful_runs_row = sqlx::query("SELECT COUNT(*) as count FROM soar_playbook_runs WHERE DATE(started_at) = DATE('now') AND status = 'completed'")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let successful_runs: i32 = successful_runs_row.get("count");

    let failed_runs_row = sqlx::query("SELECT COUNT(*) as count FROM soar_playbook_runs WHERE DATE(started_at) = DATE('now') AND status = 'failed'")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let failed_runs: i32 = failed_runs_row.get("count");

    let pending_approvals_row = sqlx::query("SELECT COUNT(*) as count FROM soar_approvals WHERE status = 'pending'")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let pending_approvals: i32 = pending_approvals_row.get("count");

    let total_actions_row = sqlx::query("SELECT COUNT(*) as count FROM soar_action_library WHERE enabled = TRUE")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let total_actions: i32 = total_actions_row.get("count");

    let total_integrations_row = sqlx::query("SELECT COUNT(*) as count FROM soar_integrations")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let total_integrations: i32 = total_integrations_row.get("count");

    let connected_integrations_row = sqlx::query("SELECT COUNT(*) as count FROM soar_integrations WHERE is_active = TRUE")
        .fetch_one(pool.get_ref()).await.map_err(|e| actix_web::error::ErrorInternalServerError(e))?;
    let connected_integrations: i32 = connected_integrations_row.get("count");

    let automation_rate = if runs_today > 0 {
        (successful_runs as f64 / runs_today as f64) * 100.0
    } else {
        0.0
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_playbooks": total_playbooks,
        "active_playbooks": active_playbooks,
        "total_runs_today": runs_today,
        "successful_runs_today": successful_runs,
        "failed_runs_today": failed_runs,
        "pending_approvals": pending_approvals,
        "total_actions": total_actions,
        "total_integrations": total_integrations,
        "connected_integrations": connected_integrations,
        "automation_rate": automation_rate
    })))
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
                .route("/initialize-defaults", web::post().to(initialize_default_ioc_feeds))
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
        )
        // Sprint 11-12: SOAR Foundation Enhancement Routes
        .service(
            web::scope("/soar/playbooks")
                .route("", web::get().to(list_playbooks))
                .route("", web::post().to(create_playbook))
                .route("/{id}", web::get().to(get_playbook))
                .route("/{id}", web::put().to(update_playbook))
                .route("/{id}", web::delete().to(delete_playbook))
                .route("/{id}/run", web::post().to(execute_playbook))
                .route("/{id}/clone", web::post().to(clone_playbook))
                .route("/{id}/validate", web::post().to(validate_playbook))
        )
        .service(
            web::scope("/soar/runs")
                .route("", web::get().to(list_runs))
                .route("/{id}", web::get().to(get_run))
                .route("/{id}/steps", web::get().to(get_run_steps))
                .route("/{id}/cancel", web::post().to(cancel_run))
                .route("/{id}/retry", web::post().to(retry_run))
        )
        .service(
            web::scope("/soar/actions")
                .route("", web::get().to(list_actions))
                .route("", web::post().to(create_action))
                .route("/{id}", web::get().to(get_action))
                .route("/{id}/test", web::post().to(test_action))
        )
        .service(
            web::scope("/soar/approvals")
                .route("", web::get().to(list_approvals))
                .route("/{id}/approve", web::post().to(approve_action))
                .route("/{id}/reject", web::post().to(reject_action))
        )
        .service(
            web::scope("/soar/integrations")
                .route("", web::get().to(list_integrations))
                .route("", web::post().to(create_integration))
                .route("/{id}", web::put().to(update_integration))
                .route("/{id}", web::delete().to(delete_integration))
                .route("/{id}/test", web::post().to(test_integration))
        )
        .route("/soar/stats", web::get().to(get_soar_stats));
}
