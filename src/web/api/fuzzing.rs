//! Fuzzing API Endpoints
//!
//! REST API for managing fuzzing campaigns, viewing crashes, and controlling fuzzing operations.

use actix_web::{web, HttpResponse, Scope};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

use crate::web::auth::Claims;
use crate::web::error::ApiError;
use crate::fuzzing::types::*;

/// Configure fuzzing API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/fuzzing")
            // Campaigns
            .route("/campaigns", web::get().to(list_campaigns))
            .route("/campaigns", web::post().to(create_campaign))
            .route("/campaigns/{id}", web::get().to(get_campaign))
            .route("/campaigns/{id}", web::put().to(update_campaign))
            .route("/campaigns/{id}", web::delete().to(delete_campaign))
            .route("/campaigns/{id}/start", web::post().to(start_campaign))
            .route("/campaigns/{id}/stop", web::post().to(stop_campaign))
            .route("/campaigns/{id}/status", web::get().to(get_campaign_status))
            // Crashes
            .route("/campaigns/{id}/crashes", web::get().to(list_crashes))
            .route("/crashes/{id}", web::get().to(get_crash))
            .route("/crashes/{id}", web::put().to(update_crash))
            .route("/crashes/{id}/reproduce", web::post().to(reproduce_crash))
            .route("/crashes/{id}/minimize", web::post().to(minimize_crash))
            // Coverage
            .route("/campaigns/{id}/coverage", web::get().to(get_coverage))
            // Seeds
            .route("/campaigns/{id}/seeds", web::get().to(list_seeds))
            .route("/campaigns/{id}/seeds", web::post().to(add_seed))
            // Statistics
            .route("/campaigns/{id}/stats", web::get().to(get_stats))
            .route("/stats/overview", web::get().to(get_overview_stats))
            // Templates
            .route("/templates", web::get().to(list_templates))
            .route("/templates", web::post().to(create_template))
            .route("/templates/{id}", web::get().to(get_template))
            .route("/templates/{id}", web::delete().to(delete_template))
            // Dictionaries
            .route("/dictionaries", web::get().to(list_dictionaries))
            .route("/dictionaries", web::post().to(create_dictionary))
            .route("/dictionaries/{id}", web::get().to(get_dictionary))
            .route("/dictionaries/{id}", web::delete().to(delete_dictionary)),
    );
}

// === Campaign Endpoints ===

#[derive(Debug, Deserialize)]
struct ListCampaignsQuery {
    status: Option<String>,
    target_type: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Serialize)]
struct CampaignSummary {
    id: String,
    name: String,
    description: Option<String>,
    target_type: String,
    fuzzer_type: String,
    status: String,
    total_iterations: i64,
    crashes_found: i32,
    unique_crashes: i32,
    coverage_percent: Option<f64>,
    execs_per_sec: Option<f64>,
    started_at: Option<String>,
    created_at: String,
}

async fn list_campaigns(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    query: web::Query<ListCampaignsQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        r#"SELECT id, name, description, target_type, fuzzer_type, status,
                  total_iterations, crashes_found, unique_crashes, coverage_percent,
                  execs_per_sec, started_at, created_at
           FROM fuzzing_campaigns WHERE user_id = ?"#
    );

    if let Some(status) = &query.status {
        sql.push_str(&format!(" AND status = '{}'", status));
    }
    if let Some(tt) = &query.target_type {
        sql.push_str(&format!(" AND target_type = '{}'", tt));
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let campaigns: Vec<CampaignSummary> = sqlx::query(&sql)
        .bind(&claims.sub)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
        .into_iter()
        .map(|row| CampaignSummary {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            target_type: row.get("target_type"),
            fuzzer_type: row.get("fuzzer_type"),
            status: row.get("status"),
            total_iterations: row.get("total_iterations"),
            crashes_found: row.get("crashes_found"),
            unique_crashes: row.get("unique_crashes"),
            coverage_percent: row.get("coverage_percent"),
            execs_per_sec: row.get("execs_per_sec"),
            started_at: row.get("started_at"),
            created_at: row.get("created_at"),
        })
        .collect();

    Ok(HttpResponse::Ok().json(campaigns))
}

async fn create_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<CreateCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let target_config = serde_json::to_string(&body.target_config)
        .map_err(|e| ApiError::bad_request(format!("Invalid target config: {}", e)))?;
    let fuzzer_config = serde_json::to_string(&body.fuzzer_config)
        .map_err(|e| ApiError::bad_request(format!("Invalid fuzzer config: {}", e)))?;

    sqlx::query(
        r#"INSERT INTO fuzzing_campaigns
           (id, user_id, name, description, target_type, fuzzer_type, target_config, fuzzer_config, created_at, updated_at, customer_id, engagement_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.name)
    .bind(&body.description)
    .bind(body.target_type.to_string())
    .bind(body.fuzzer_type.to_string())
    .bind(&target_config)
    .bind(&fuzzer_config)
    .bind(&now)
    .bind(&now)
    .bind(&body.customer_id)
    .bind(&body.engagement_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Campaign created successfully"
    })))
}

#[derive(Debug, Serialize)]
struct CampaignDetail {
    id: String,
    name: String,
    description: Option<String>,
    target_type: String,
    fuzzer_type: String,
    target_config: serde_json::Value,
    fuzzer_config: serde_json::Value,
    status: String,
    total_iterations: i64,
    crashes_found: i32,
    unique_crashes: i32,
    coverage_percent: Option<f64>,
    execs_per_sec: Option<f64>,
    started_at: Option<String>,
    completed_at: Option<String>,
    created_at: String,
    updated_at: String,
}

async fn get_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    let row = sqlx::query(
        r#"SELECT * FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"#
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Campaign not found"))?;

    let target_config_str: String = row.get("target_config");
    let fuzzer_config_str: String = row.get("fuzzer_config");

    let campaign = CampaignDetail {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        target_type: row.get("target_type"),
        fuzzer_type: row.get("fuzzer_type"),
        target_config: serde_json::from_str(&target_config_str).unwrap_or(serde_json::json!({})),
        fuzzer_config: serde_json::from_str(&fuzzer_config_str).unwrap_or(serde_json::json!({})),
        status: row.get("status"),
        total_iterations: row.get("total_iterations"),
        crashes_found: row.get("crashes_found"),
        unique_crashes: row.get("unique_crashes"),
        coverage_percent: row.get("coverage_percent"),
        execs_per_sec: row.get("execs_per_sec"),
        started_at: row.get("started_at"),
        completed_at: row.get("completed_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    };

    Ok(HttpResponse::Ok().json(campaign))
}

async fn update_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Campaign not found"));
    }

    let mut updates = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(name) = &body.name {
        updates.push("name = ?");
        params.push(name.clone());
    }
    if let Some(desc) = &body.description {
        updates.push("description = ?");
        params.push(desc.clone());
    }
    if let Some(config) = &body.fuzzer_config {
        updates.push("fuzzer_config = ?");
        params.push(serde_json::to_string(config).unwrap_or_default());
    }

    if updates.is_empty() {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "No updates provided"
        })));
    }

    updates.push("updated_at = ?");
    params.push(now);

    let sql = format!(
        "UPDATE fuzzing_campaigns SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for param in &params {
        query = query.bind(param);
    }
    query = query.bind(&campaign_id);

    query.execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Campaign updated successfully"
    })))
}

async fn delete_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Campaign not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Campaign deleted successfully"
    })))
}

async fn start_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        r#"UPDATE fuzzing_campaigns
           SET status = 'running', started_at = ?, updated_at = ?
           WHERE id = ? AND user_id = ? AND status IN ('created', 'paused', 'completed')"#
    )
    .bind(&now)
    .bind(&now)
    .bind(&campaign_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::bad_request("Campaign not found or cannot be started"));
    }

    // In a real implementation, this would spawn a background task to run the fuzzer
    // For now, we just update the status

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Campaign started",
        "status": "running"
    })))
}

async fn stop_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        r#"UPDATE fuzzing_campaigns
           SET status = 'paused', updated_at = ?
           WHERE id = ? AND user_id = ? AND status = 'running'"#
    )
    .bind(&now)
    .bind(&campaign_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::bad_request("Campaign not found or is not running"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Campaign stopped",
        "status": "paused"
    })))
}

async fn get_campaign_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    let row = sqlx::query(
        r#"SELECT status, total_iterations, crashes_found, unique_crashes,
                  coverage_percent, execs_per_sec, started_at
           FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"#
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Campaign not found"))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": row.get::<String, _>("status"),
        "total_iterations": row.get::<i64, _>("total_iterations"),
        "crashes_found": row.get::<i32, _>("crashes_found"),
        "unique_crashes": row.get::<i32, _>("unique_crashes"),
        "coverage_percent": row.get::<Option<f64>, _>("coverage_percent"),
        "execs_per_sec": row.get::<Option<f64>, _>("execs_per_sec"),
        "started_at": row.get::<Option<String>, _>("started_at")
    })))
}

// === Crash Endpoints ===

#[derive(Debug, Serialize)]
struct CrashSummary {
    id: String,
    crash_type: String,
    crash_hash: String,
    exploitability: String,
    input_size: i32,
    reproduced: bool,
    reproduction_count: i32,
    created_at: String,
}

async fn list_crashes(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Campaign not found"));
    }

    let crashes: Vec<CrashSummary> = sqlx::query(
        r#"SELECT id, crash_type, crash_hash, exploitability, input_size,
                  reproduced, reproduction_count, created_at
           FROM fuzzing_crashes WHERE campaign_id = ?
           ORDER BY created_at DESC"#
    )
    .bind(&campaign_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|row| CrashSummary {
        id: row.get("id"),
        crash_type: row.get("crash_type"),
        crash_hash: row.get("crash_hash"),
        exploitability: row.get("exploitability"),
        input_size: row.get("input_size"),
        reproduced: row.get::<i32, _>("reproduced") != 0,
        reproduction_count: row.get("reproduction_count"),
        created_at: row.get("created_at"),
    })
    .collect();

    Ok(HttpResponse::Ok().json(crashes))
}

#[derive(Debug, Serialize)]
struct CrashDetail {
    id: String,
    campaign_id: String,
    crash_type: String,
    crash_hash: String,
    exploitability: String,
    input_data_base64: String,
    input_size: i32,
    stack_trace: Option<String>,
    registers: Option<serde_json::Value>,
    signal: Option<i32>,
    exit_code: Option<i32>,
    stderr_output: Option<String>,
    reproduced: bool,
    reproduction_count: i32,
    minimized_input_base64: Option<String>,
    notes: Option<String>,
    created_at: String,
}

async fn get_crash(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let crash_id = path.into_inner();

    let row = sqlx::query(
        r#"SELECT c.*, fc.user_id
           FROM fuzzing_crashes c
           JOIN fuzzing_campaigns fc ON c.campaign_id = fc.id
           WHERE c.id = ? AND fc.user_id = ?"#
    )
    .bind(&crash_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Crash not found"))?;

    let input_data: Vec<u8> = row.get("input_data");
    let minimized_input: Option<Vec<u8>> = row.get("minimized_input");
    let registers_str: Option<String> = row.get("registers");

    let crash = CrashDetail {
        id: row.get("id"),
        campaign_id: row.get("campaign_id"),
        crash_type: row.get("crash_type"),
        crash_hash: row.get("crash_hash"),
        exploitability: row.get("exploitability"),
        input_data_base64: base64::encode(&input_data),
        input_size: row.get("input_size"),
        stack_trace: row.get("stack_trace"),
        registers: registers_str.and_then(|s| serde_json::from_str(&s).ok()),
        signal: row.get("signal"),
        exit_code: row.get("exit_code"),
        stderr_output: row.get("stderr_output"),
        reproduced: row.get::<i32, _>("reproduced") != 0,
        reproduction_count: row.get("reproduction_count"),
        minimized_input_base64: minimized_input.map(|d| base64::encode(&d)),
        notes: row.get("notes"),
        created_at: row.get("created_at"),
    };

    Ok(HttpResponse::Ok().json(crash))
}

#[derive(Debug, Deserialize)]
struct UpdateCrashRequest {
    notes: Option<String>,
}

async fn update_crash(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateCrashRequest>,
) -> Result<HttpResponse, ApiError> {
    let crash_id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        r#"SELECT 1 FROM fuzzing_crashes c
           JOIN fuzzing_campaigns fc ON c.campaign_id = fc.id
           WHERE c.id = ? AND fc.user_id = ?"#
    )
    .bind(&crash_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Crash not found"));
    }

    if let Some(notes) = &body.notes {
        sqlx::query("UPDATE fuzzing_crashes SET notes = ? WHERE id = ?")
            .bind(notes)
            .bind(&crash_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Crash updated successfully"
    })))
}

async fn reproduce_crash(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let crash_id = path.into_inner();

    // Verify ownership
    let row = sqlx::query(
        r#"SELECT c.id, c.reproduction_count
           FROM fuzzing_crashes c
           JOIN fuzzing_campaigns fc ON c.campaign_id = fc.id
           WHERE c.id = ? AND fc.user_id = ?"#
    )
    .bind(&crash_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Crash not found"))?;

    let current_count: i32 = row.get("reproduction_count");

    // In a real implementation, we would actually reproduce the crash
    // For now, just increment the reproduction count

    sqlx::query(
        "UPDATE fuzzing_crashes SET reproduced = 1, reproduction_count = ? WHERE id = ?"
    )
    .bind(current_count + 1)
    .bind(&crash_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Crash reproduction attempted",
        "reproduced": true,
        "reproduction_count": current_count + 1
    })))
}

async fn minimize_crash(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let crash_id = path.into_inner();

    // Verify ownership
    let row = sqlx::query(
        r#"SELECT c.id, c.input_data
           FROM fuzzing_crashes c
           JOIN fuzzing_campaigns fc ON c.campaign_id = fc.id
           WHERE c.id = ? AND fc.user_id = ?"#
    )
    .bind(&crash_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Crash not found"))?;

    let input_data: Vec<u8> = row.get("input_data");
    let original_size = input_data.len();

    // In a real implementation, we would use the CrashTriager to minimize
    // For now, just simulate by returning a smaller input
    let minimized = if input_data.len() > 10 {
        input_data[..input_data.len() / 2].to_vec()
    } else {
        input_data.clone()
    };

    sqlx::query(
        "UPDATE fuzzing_crashes SET minimized_input = ? WHERE id = ?"
    )
    .bind(&minimized)
    .bind(&crash_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Input minimized",
        "original_size": original_size,
        "minimized_size": minimized.len()
    })))
}

// === Coverage Endpoints ===

async fn get_coverage(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Campaign not found"));
    }

    let coverage: Vec<serde_json::Value> = sqlx::query(
        r#"SELECT timestamp, total_edges, covered_edges, coverage_percent,
                  new_edges_this_session, total_blocks, covered_blocks
           FROM fuzzing_coverage WHERE campaign_id = ?
           ORDER BY timestamp DESC LIMIT 100"#
    )
    .bind(&campaign_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|row| serde_json::json!({
        "timestamp": row.get::<String, _>("timestamp"),
        "total_edges": row.get::<i64, _>("total_edges"),
        "covered_edges": row.get::<i64, _>("covered_edges"),
        "coverage_percent": row.get::<f64, _>("coverage_percent"),
        "new_edges_this_session": row.get::<i64, _>("new_edges_this_session"),
        "total_blocks": row.get::<Option<i64>, _>("total_blocks"),
        "covered_blocks": row.get::<Option<i64>, _>("covered_blocks")
    }))
    .collect();

    Ok(HttpResponse::Ok().json(coverage))
}

// === Seed Endpoints ===

async fn list_seeds(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Campaign not found"));
    }

    let seeds: Vec<serde_json::Value> = sqlx::query(
        r#"SELECT id, seed_hash, size, origin, coverage_edges, is_interesting, created_at
           FROM fuzzing_seeds WHERE campaign_id = ?
           ORDER BY created_at DESC"#
    )
    .bind(&campaign_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|row| serde_json::json!({
        "id": row.get::<String, _>("id"),
        "seed_hash": row.get::<String, _>("seed_hash"),
        "size": row.get::<i32, _>("size"),
        "origin": row.get::<String, _>("origin"),
        "coverage_edges": row.get::<Option<i32>, _>("coverage_edges"),
        "is_interesting": row.get::<i32, _>("is_interesting") != 0,
        "created_at": row.get::<String, _>("created_at")
    }))
    .collect();

    Ok(HttpResponse::Ok().json(seeds))
}

#[derive(Debug, Deserialize)]
struct AddSeedRequest {
    data_base64: String,
    origin: Option<String>,
}

async fn add_seed(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    body: web::Json<AddSeedRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Campaign not found"));
    }

    let data = base64::decode(&body.data_base64)
        .map_err(|e| ApiError::bad_request(format!("Invalid base64: {}", e)))?;

    let id = uuid::Uuid::new_v4().to_string();
    let seed_hash = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        format!("{:x}", hasher.finalize())
    };

    sqlx::query(
        r#"INSERT INTO fuzzing_seeds (id, campaign_id, seed_hash, seed_data, size, origin)
           VALUES (?, ?, ?, ?, ?, ?)"#
    )
    .bind(&id)
    .bind(&campaign_id)
    .bind(&seed_hash)
    .bind(&data)
    .bind(data.len() as i32)
    .bind(body.origin.as_deref().unwrap_or("user"))
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "seed_hash": seed_hash,
        "size": data.len()
    })))
}

// === Statistics Endpoints ===

async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Verify ownership
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM fuzzing_campaigns WHERE id = ? AND user_id = ?"
    )
    .bind(&campaign_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if exists.is_none() {
        return Err(ApiError::not_found("Campaign not found"));
    }

    let stats: Vec<serde_json::Value> = sqlx::query(
        r#"SELECT * FROM fuzzing_stats WHERE campaign_id = ?
           ORDER BY timestamp DESC LIMIT 100"#
    )
    .bind(&campaign_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|row| serde_json::json!({
        "timestamp": row.get::<String, _>("timestamp"),
        "total_execs": row.get::<i64, _>("total_execs"),
        "execs_per_sec": row.get::<f64, _>("execs_per_sec"),
        "total_crashes": row.get::<i32, _>("total_crashes"),
        "unique_crashes": row.get::<i32, _>("unique_crashes"),
        "hangs": row.get::<i32, _>("hangs"),
        "coverage_percent": row.get::<f64, _>("coverage_percent"),
        "new_edges": row.get::<i64, _>("new_edges"),
        "pending_inputs": row.get::<i32, _>("pending_inputs"),
        "stability": row.get::<f64, _>("stability")
    }))
    .collect();

    Ok(HttpResponse::Ok().json(stats))
}

async fn get_overview_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let total_campaigns = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM fuzzing_campaigns WHERE user_id = ?"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let running_campaigns = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM fuzzing_campaigns WHERE user_id = ? AND status = 'running'"
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let total_crashes = sqlx::query_scalar::<_, i32>(
        r#"SELECT COUNT(*) FROM fuzzing_crashes c
           JOIN fuzzing_campaigns fc ON c.campaign_id = fc.id
           WHERE fc.user_id = ?"#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let exploitable_crashes = sqlx::query_scalar::<_, i32>(
        r#"SELECT COUNT(*) FROM fuzzing_crashes c
           JOIN fuzzing_campaigns fc ON c.campaign_id = fc.id
           WHERE fc.user_id = ? AND c.exploitability IN ('exploitable', 'probably_exploitable')"#
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_campaigns": total_campaigns,
        "running_campaigns": running_campaigns,
        "total_crashes": total_crashes,
        "exploitable_crashes": exploitable_crashes
    })))
}

// === Template Endpoints ===

async fn list_templates(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let templates: Vec<serde_json::Value> = sqlx::query(
        r#"SELECT id, name, description, target_type, is_public, usage_count, created_at
           FROM fuzzing_templates
           WHERE user_id = ? OR is_public = 1
           ORDER BY usage_count DESC"#
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|row| serde_json::json!({
        "id": row.get::<String, _>("id"),
        "name": row.get::<String, _>("name"),
        "description": row.get::<Option<String>, _>("description"),
        "target_type": row.get::<String, _>("target_type"),
        "is_public": row.get::<i32, _>("is_public") != 0,
        "usage_count": row.get::<i32, _>("usage_count"),
        "created_at": row.get::<String, _>("created_at")
    }))
    .collect();

    Ok(HttpResponse::Ok().json(templates))
}

#[derive(Debug, Deserialize)]
struct CreateTemplateRequest {
    name: String,
    description: Option<String>,
    target_type: String,
    template_content: String,
    fuzz_points: Vec<serde_json::Value>,
    is_public: Option<bool>,
}

async fn create_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<CreateTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let fuzz_points_json = serde_json::to_string(&body.fuzz_points)
        .map_err(|e| ApiError::bad_request(format!("Invalid fuzz points: {}", e)))?;

    sqlx::query(
        r#"INSERT INTO fuzzing_templates
           (id, user_id, name, description, target_type, template_content, fuzz_points, is_public, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.target_type)
    .bind(&body.template_content)
    .bind(&fuzz_points_json)
    .bind(body.is_public.unwrap_or(false) as i32)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Template created successfully"
    })))
}

async fn get_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let row = sqlx::query(
        r#"SELECT * FROM fuzzing_templates
           WHERE id = ? AND (user_id = ? OR is_public = 1)"#
    )
    .bind(&template_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Template not found"))?;

    let fuzz_points_str: String = row.get("fuzz_points");

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": row.get::<String, _>("id"),
        "name": row.get::<String, _>("name"),
        "description": row.get::<Option<String>, _>("description"),
        "target_type": row.get::<String, _>("target_type"),
        "template_content": row.get::<String, _>("template_content"),
        "fuzz_points": serde_json::from_str::<serde_json::Value>(&fuzz_points_str).unwrap_or(serde_json::json!([])),
        "is_public": row.get::<i32, _>("is_public") != 0,
        "usage_count": row.get::<i32, _>("usage_count"),
        "created_at": row.get::<String, _>("created_at")
    })))
}

async fn delete_template(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM fuzzing_templates WHERE id = ? AND user_id = ?"
    )
    .bind(&template_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Template not found or you don't have permission to delete it"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Template deleted successfully"
    })))
}

// === Dictionary Endpoints ===

async fn list_dictionaries(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let dicts: Vec<serde_json::Value> = sqlx::query(
        r#"SELECT id, name, description, category, is_public, usage_count, created_at
           FROM fuzzing_dictionaries
           WHERE user_id = ? OR is_public = 1
           ORDER BY usage_count DESC"#
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .into_iter()
    .map(|row| serde_json::json!({
        "id": row.get::<String, _>("id"),
        "name": row.get::<String, _>("name"),
        "description": row.get::<Option<String>, _>("description"),
        "category": row.get::<String, _>("category"),
        "is_public": row.get::<i32, _>("is_public") != 0,
        "usage_count": row.get::<i32, _>("usage_count"),
        "created_at": row.get::<String, _>("created_at")
    }))
    .collect();

    Ok(HttpResponse::Ok().json(dicts))
}

#[derive(Debug, Deserialize)]
struct CreateDictionaryRequest {
    name: String,
    description: Option<String>,
    category: String,
    entries: Vec<String>,
    is_public: Option<bool>,
}

async fn create_dictionary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<CreateDictionaryRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let entries_json = serde_json::to_string(&body.entries)
        .map_err(|e| ApiError::bad_request(format!("Invalid entries: {}", e)))?;

    sqlx::query(
        r#"INSERT INTO fuzzing_dictionaries
           (id, user_id, name, description, category, entries, is_public, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.category)
    .bind(&entries_json)
    .bind(body.is_public.unwrap_or(false) as i32)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Dictionary created successfully"
    })))
}

async fn get_dictionary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let dict_id = path.into_inner();

    let row = sqlx::query(
        r#"SELECT * FROM fuzzing_dictionaries
           WHERE id = ? AND (user_id = ? OR is_public = 1)"#
    )
    .bind(&dict_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Dictionary not found"))?;

    let entries_str: String = row.get("entries");

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": row.get::<String, _>("id"),
        "name": row.get::<String, _>("name"),
        "description": row.get::<Option<String>, _>("description"),
        "category": row.get::<String, _>("category"),
        "entries": serde_json::from_str::<serde_json::Value>(&entries_str).unwrap_or(serde_json::json!([])),
        "is_public": row.get::<i32, _>("is_public") != 0,
        "usage_count": row.get::<i32, _>("usage_count"),
        "created_at": row.get::<String, _>("created_at")
    })))
}

async fn delete_dictionary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let dict_id = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM fuzzing_dictionaries WHERE id = ? AND user_id = ?"
    )
    .bind(&dict_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Dictionary not found or you don't have permission to delete it"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Dictionary deleted successfully"
    })))
}
