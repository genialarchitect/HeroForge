//! Sandbox Integration API Endpoints
//!
//! Provides REST API for malware sandbox integrations:
//! - Sandbox configuration management
//! - Sample submission to Cuckoo, Any.Run, Hybrid Analysis
//! - Status polling and result retrieval
//! - Cross-sandbox comparison

use actix_web::{web, HttpResponse};
use log::error;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;
use chrono::Utc;

use crate::web::auth::Claims;
use crate::web::error::ApiError;
use crate::malware_analysis::sandbox::{
    compare_sandbox_results,
    types::{
        SandboxType, SandboxResult,
        SubmissionOptions,
    },
    cuckoo::CuckooClient,
    anyrun::AnyRunClient,
    hybrid::HybridAnalysisClient,
};

// ============================================================================
// Database Row Types
// ============================================================================

#[derive(Debug, FromRow)]
struct SandboxConfigRow {
    id: String,
    name: String,
    sandbox_type: String,
    api_url: String,
    api_key_encrypted: Option<String>,
    is_default: i32,
    is_active: i32,
    timeout_seconds: i64,
    created_at: String,
}

#[derive(Debug, FromRow)]
struct SandboxSubmissionRow {
    id: String,
    sample_id: String,
    sandbox_type: String,
    sandbox_task_id: String,
    status: String,
    submitted_at: String,
}

#[derive(Debug, FromRow)]
struct SampleDataRow {
    file_data: Vec<u8>,
    filename: String,
}

#[derive(Debug, FromRow)]
struct StatsRow {
    sandbox_type: String,
    total: i64,
    pending: i64,
    running: i64,
    completed: i64,
    failed: i64,
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxConfigRequest {
    pub name: String,
    pub sandbox_type: SandboxType,
    pub api_url: String,
    pub api_key: Option<String>,
    pub is_default: Option<bool>,
    pub timeout_seconds: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxConfigResponse {
    pub id: String,
    pub name: String,
    pub sandbox_type: String,
    pub api_url: String,
    pub is_default: bool,
    pub is_active: bool,
    pub timeout_seconds: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitSampleRequest {
    pub sample_id: String,
    pub sandbox_config_id: String,
    pub options: Option<SubmissionOptionsRequest>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmissionOptionsRequest {
    pub timeout: Option<u32>,
    pub enable_network: Option<bool>,
    pub environment: Option<String>,
    pub arguments: Option<String>,
    pub password: Option<String>,
    pub internet_access: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub priority: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmissionResponse {
    pub id: String,
    pub sample_id: String,
    pub sandbox_type: String,
    pub sandbox_task_id: String,
    pub status: String,
    pub submitted_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub submission_id: String,
    pub status: String,
    pub progress: Option<u32>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxResultResponse {
    pub id: String,
    pub sample_id: String,
    pub sandbox_type: String,
    pub status: String,
    pub verdict: String,
    pub score: u8,
    pub processes_count: usize,
    pub network_iocs_count: usize,
    pub file_iocs_count: usize,
    pub dropped_files_count: usize,
    pub signatures_count: usize,
    pub mitre_techniques: Vec<String>,
    pub submitted_at: String,
    pub completed_at: Option<String>,
    pub analysis_duration_seconds: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessInfoResponse {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
    pub command_line: Option<String>,
    pub username: Option<String>,
    pub is_injected: bool,
    pub is_suspicious: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DroppedFileResponse {
    pub filename: String,
    pub path: String,
    pub file_type: Option<String>,
    pub size: u64,
    pub md5: String,
    pub sha256: String,
    pub is_executable: bool,
    pub is_suspicious: bool,
    pub detection: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub families: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScreenshotResponse {
    pub id: String,
    pub timestamp: Option<String>,
    pub url: Option<String>,
    pub thumbnail_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompareRequest {
    pub submission_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompareResponse {
    pub consensus_verdict: String,
    pub average_score: u8,
    pub sandbox_count: usize,
    pub verdicts: Vec<VerdictEntry>,
    pub scores: Vec<ScoreEntry>,
    pub common_signatures: Vec<String>,
    pub common_mitre_techniques: Vec<String>,
    pub total_network_iocs: usize,
    pub total_file_iocs: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerdictEntry {
    pub sandbox_type: String,
    pub verdict: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoreEntry {
    pub sandbox_type: String,
    pub score: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvironmentResponse {
    pub id: String,
    pub name: String,
    pub os: String,
    pub os_version: Option<String>,
    pub architecture: String,
    pub available: bool,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    pub sandbox_type: String,
    pub total_submissions: u64,
    pub pending: u64,
    pub running: u64,
    pub completed: u64,
    pub failed: u64,
    pub malicious: u64,
    pub suspicious: u64,
    pub clean: u64,
    pub average_analysis_time_seconds: f64,
}

#[derive(Debug, Deserialize)]
pub struct ListSubmissionsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sandbox_type: Option<String>,
    pub status: Option<String>,
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/sandbox")
            // Sandbox configuration
            .route("/configs", web::get().to(list_configs))
            .route("/configs", web::post().to(create_config))
            .route("/configs/{id}", web::get().to(get_config))
            .route("/configs/{id}", web::put().to(update_config))
            .route("/configs/{id}", web::delete().to(delete_config))
            .route("/configs/{id}/test", web::post().to(test_connection))

            // Sample submission
            .route("/submit", web::post().to(submit_sample))
            .route("/submissions", web::get().to(list_submissions))
            .route("/submissions/{id}", web::get().to(get_submission))
            .route("/submissions/{id}/status", web::get().to(get_status))
            .route("/submissions/{id}/results", web::get().to(get_results))
            .route("/submissions/{id}/processes", web::get().to(get_processes))
            .route("/submissions/{id}/screenshots", web::get().to(get_screenshots))
            .route("/submissions/{id}/dropped", web::get().to(get_dropped_files))
            .route("/submissions/{id}/signatures", web::get().to(get_signatures))
            .route("/submissions/{id}/iocs", web::get().to(get_iocs))

            // Comparison
            .route("/compare", web::post().to(compare_submissions))

            // Environments
            .route("/environments", web::get().to(list_environments))
            .route("/environments/{config_id}", web::get().to(get_environments_for_config))

            // Statistics
            .route("/stats", web::get().to(get_stats))
            .route("/stats/{sandbox_type}", web::get().to(get_stats_by_type))
    );
}

// ============================================================================
// Sandbox Configuration Endpoints
// ============================================================================

/// List sandbox configurations for the current user
async fn list_configs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let configs: Vec<SandboxConfigRow> = sqlx::query_as(
        r#"SELECT id, name, sandbox_type, api_url, api_key_encrypted, is_default, is_active, timeout_seconds, created_at
        FROM sandbox_configs
        WHERE user_id = ?
        ORDER BY created_at DESC"#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list sandbox configs: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    let response: Vec<SandboxConfigResponse> = configs
        .into_iter()
        .map(|c| SandboxConfigResponse {
            id: c.id,
            name: c.name,
            sandbox_type: c.sandbox_type,
            api_url: c.api_url,
            is_default: c.is_default != 0,
            is_active: c.is_active != 0,
            timeout_seconds: c.timeout_seconds,
            created_at: c.created_at,
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Create a new sandbox configuration
async fn create_config(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<SandboxConfigRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let id = Uuid::new_v4().to_string();
    let sandbox_type = body.sandbox_type.to_string();
    let is_default: i32 = if body.is_default.unwrap_or(false) { 1 } else { 0 };
    let timeout_seconds = body.timeout_seconds.unwrap_or(300);
    let created_at = Utc::now().to_rfc3339();

    // If this is set as default, unset other defaults first
    if is_default == 1 {
        let _ = sqlx::query(
            "UPDATE sandbox_configs SET is_default = 0 WHERE user_id = ? AND sandbox_type = ?"
        )
        .bind(user_id)
        .bind(&sandbox_type)
        .execute(pool.get_ref())
        .await;
    }

    // Store API key (in production, this should be encrypted)
    let api_key_encrypted = body.api_key.clone().unwrap_or_default();

    sqlx::query(
        r#"INSERT INTO sandbox_configs (id, user_id, name, sandbox_type, api_url, api_key_encrypted, is_default, is_active, timeout_seconds, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)"#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.name)
    .bind(&sandbox_type)
    .bind(&body.api_url)
    .bind(&api_key_encrypted)
    .bind(is_default)
    .bind(timeout_seconds)
    .bind(&created_at)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to create sandbox config: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "message": "Sandbox configuration created"
    })))
}

/// Get a specific sandbox configuration
async fn get_config(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let config_id = path.into_inner();

    let config: SandboxConfigRow = sqlx::query_as(
        r#"SELECT id, name, sandbox_type, api_url, api_key_encrypted, is_default, is_active, timeout_seconds, created_at
        FROM sandbox_configs
        WHERE id = ? AND user_id = ?"#
    )
    .bind(&config_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get sandbox config: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Sandbox configuration not found"))?;

    Ok(HttpResponse::Ok().json(SandboxConfigResponse {
        id: config.id,
        name: config.name,
        sandbox_type: config.sandbox_type,
        api_url: config.api_url,
        is_default: config.is_default != 0,
        is_active: config.is_active != 0,
        timeout_seconds: config.timeout_seconds,
        created_at: config.created_at,
    }))
}

/// Update a sandbox configuration
async fn update_config(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    body: web::Json<SandboxConfigRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let config_id = path.into_inner();
    let sandbox_type = body.sandbox_type.to_string();
    let is_default: i32 = if body.is_default.unwrap_or(false) { 1 } else { 0 };
    let timeout_seconds = body.timeout_seconds.unwrap_or(300);

    // If this is set as default, unset other defaults first
    if is_default == 1 {
        let _ = sqlx::query(
            "UPDATE sandbox_configs SET is_default = 0 WHERE user_id = ? AND sandbox_type = ? AND id != ?"
        )
        .bind(user_id)
        .bind(&sandbox_type)
        .bind(&config_id)
        .execute(pool.get_ref())
        .await;
    }

    let result = sqlx::query(
        r#"UPDATE sandbox_configs
        SET name = ?, sandbox_type = ?, api_url = ?, is_default = ?, timeout_seconds = ?
        WHERE id = ? AND user_id = ?"#
    )
    .bind(&body.name)
    .bind(&sandbox_type)
    .bind(&body.api_url)
    .bind(is_default)
    .bind(timeout_seconds)
    .bind(&config_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to update sandbox config: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Sandbox configuration not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Configuration updated"
    })))
}

/// Delete a sandbox configuration
async fn delete_config(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let config_id = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM sandbox_configs WHERE id = ? AND user_id = ?"
    )
    .bind(&config_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to delete sandbox config: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Sandbox configuration not found"));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Configuration deleted"
    })))
}

/// Test sandbox connection
async fn test_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let config_id = path.into_inner();

    let config: SandboxConfigRow = sqlx::query_as(
        r#"SELECT id, name, sandbox_type, api_url, api_key_encrypted, is_default, is_active, timeout_seconds, created_at
        FROM sandbox_configs
        WHERE id = ? AND user_id = ?"#
    )
    .bind(&config_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get sandbox config for test: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Sandbox configuration not found"))?;

    let sandbox_type: SandboxType = config.sandbox_type.parse()
        .map_err(|_| ApiError::bad_request("Invalid sandbox type"))?;

    // Test connection by listing environments
    let test_result = match sandbox_type {
        SandboxType::Cuckoo => {
            let client = CuckooClient::new(&config.api_url, config.api_key_encrypted.as_deref());
            client.list_machines().await
        }
        SandboxType::AnyRun => {
            let api_key = config.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required for Any.Run"))?;
            let client = AnyRunClient::new(api_key);
            client.get_environments().await
        }
        SandboxType::HybridAnalysis => {
            let api_key = config.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required for Hybrid Analysis"))?;
            let client = HybridAnalysisClient::new(api_key);
            client.get_environments().await
        }
    };

    match test_result {
        Ok(environments) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Connection successful",
                "environments_count": environments.len()
            })))
        }
        Err(e) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": false,
                "message": format!("Connection failed: {}", e)
            })))
        }
    }
}

// ============================================================================
// Sample Submission Endpoints
// ============================================================================

/// Submit a sample to a sandbox for analysis
async fn submit_sample(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<SubmitSampleRequest>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    // Get sandbox config
    let config: SandboxConfigRow = sqlx::query_as(
        r#"SELECT id, name, sandbox_type, api_url, api_key_encrypted, is_default, is_active, timeout_seconds, created_at
        FROM sandbox_configs
        WHERE id = ? AND user_id = ?"#
    )
    .bind(&body.sandbox_config_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get sandbox config: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Sandbox configuration not found"))?;

    // Get sample data
    let sample: SampleDataRow = sqlx::query_as(
        "SELECT file_data, filename FROM malware_samples WHERE id = ? AND user_id = ?"
    )
    .bind(&body.sample_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get sample: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Sample not found"))?;

    let sandbox_type: SandboxType = config.sandbox_type.parse()
        .map_err(|_| ApiError::bad_request("Invalid sandbox type"))?;

    // Build submission options
    let options = if let Some(ref opts) = body.options {
        SubmissionOptions {
            timeout: opts.timeout,
            enable_network: opts.enable_network.unwrap_or(false),
            os: None,
            environment: opts.environment.clone(),
            arguments: opts.arguments.clone(),
            password: opts.password.clone(),
            internet_access: opts.internet_access.unwrap_or(false),
            tags: opts.tags.clone().unwrap_or_default(),
            priority: opts.priority,
            interaction_script: None,
        }
    } else {
        SubmissionOptions::default()
    };

    // Submit to sandbox
    let submission_result = match sandbox_type {
        SandboxType::Cuckoo => {
            let client = CuckooClient::new(&config.api_url, config.api_key_encrypted.as_deref());
            client.submit(&sample.file_data, &sample.filename, &options).await
        }
        SandboxType::AnyRun => {
            let api_key = config.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required for Any.Run"))?;
            let client = AnyRunClient::new(api_key);
            client.submit(&sample.file_data, &sample.filename, &options).await
        }
        SandboxType::HybridAnalysis => {
            let api_key = config.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required for Hybrid Analysis"))?;
            let client = HybridAnalysisClient::new(api_key);
            client.submit(&sample.file_data, &sample.filename, &options).await
        }
    };

    let submission = submission_result.map_err(|e| {
        error!("Failed to submit sample: {}", e);
        ApiError::internal(format!("Sandbox submission failed: {}", e))
    })?;

    // Record submission in database
    let submission_id = Uuid::new_v4().to_string();
    let sandbox_type_str = sandbox_type.to_string();
    let status_str = submission.status.to_string();
    let submitted_at = submission.submitted_at.to_rfc3339();

    sqlx::query(
        r#"INSERT INTO sandbox_submissions (id, user_id, sample_id, sandbox_config_id, sandbox_type, sandbox_task_id, status, submitted_at, customer_id, engagement_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
    )
    .bind(&submission_id)
    .bind(user_id)
    .bind(&body.sample_id)
    .bind(&body.sandbox_config_id)
    .bind(&sandbox_type_str)
    .bind(&submission.task_id)
    .bind(&status_str)
    .bind(&submitted_at)
    .bind(&body.customer_id)
    .bind(&body.engagement_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to record submission: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    Ok(HttpResponse::Created().json(SubmissionResponse {
        id: submission_id,
        sample_id: body.sample_id.clone(),
        sandbox_type: sandbox_type_str,
        sandbox_task_id: submission.task_id,
        status: status_str,
        submitted_at,
    }))
}

/// List submissions for the current user
async fn list_submissions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    query: web::Query<ListSubmissionsQuery>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(50).min(100) as i64;
    let offset = query.offset.unwrap_or(0) as i64;

    let submissions: Vec<SandboxSubmissionRow> = sqlx::query_as(
        r#"SELECT id, sample_id, sandbox_type, sandbox_task_id, status, submitted_at
        FROM sandbox_submissions
        WHERE user_id = ?
        ORDER BY submitted_at DESC
        LIMIT ? OFFSET ?"#
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list submissions: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    let response: Vec<SubmissionResponse> = submissions
        .into_iter()
        .map(|s| SubmissionResponse {
            id: s.id,
            sample_id: s.sample_id,
            sandbox_type: s.sandbox_type,
            sandbox_task_id: s.sandbox_task_id,
            status: s.status,
            submitted_at: s.submitted_at,
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get a specific submission
async fn get_submission(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let submission_id = path.into_inner();

    let submission: SandboxSubmissionRow = sqlx::query_as(
        r#"SELECT id, sample_id, sandbox_type, sandbox_task_id, status, submitted_at
        FROM sandbox_submissions
        WHERE id = ? AND user_id = ?"#
    )
    .bind(&submission_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get submission: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Submission not found"))?;

    Ok(HttpResponse::Ok().json(SubmissionResponse {
        id: submission.id,
        sample_id: submission.sample_id,
        sandbox_type: submission.sandbox_type,
        sandbox_task_id: submission.sandbox_task_id,
        status: submission.status,
        submitted_at: submission.submitted_at,
    }))
}

#[derive(Debug, FromRow)]
struct SubmissionWithConfigRow {
    sandbox_type: String,
    sandbox_task_id: String,
    api_url: String,
    api_key_encrypted: Option<String>,
}

/// Get status of a submission
async fn get_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let submission_id = path.into_inner();

    let submission: SubmissionWithConfigRow = sqlx::query_as(
        r#"SELECT s.sandbox_type, s.sandbox_task_id, c.api_url, c.api_key_encrypted
        FROM sandbox_submissions s
        JOIN sandbox_configs c ON s.sandbox_config_id = c.id
        WHERE s.id = ? AND s.user_id = ?"#
    )
    .bind(&submission_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get submission: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Submission not found"))?;

    let sandbox_type: SandboxType = submission.sandbox_type.parse()
        .map_err(|_| ApiError::bad_request("Invalid sandbox type"))?;

    let status = match sandbox_type {
        SandboxType::Cuckoo => {
            let client = CuckooClient::new(&submission.api_url, submission.api_key_encrypted.as_deref());
            client.get_status(&submission.sandbox_task_id).await
        }
        SandboxType::AnyRun => {
            let api_key = submission.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = AnyRunClient::new(api_key);
            client.get_status(&submission.sandbox_task_id).await
        }
        SandboxType::HybridAnalysis => {
            let api_key = submission.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = HybridAnalysisClient::new(api_key);
            client.get_status(&submission.sandbox_task_id).await
        }
    }.map_err(|e| {
        error!("Failed to get status: {}", e);
        ApiError::internal(format!("Failed to get status: {}", e))
    })?;

    // Update status in database
    let status_str = status.to_string();
    let _ = sqlx::query(
        "UPDATE sandbox_submissions SET status = ? WHERE id = ?"
    )
    .bind(&status_str)
    .bind(&submission_id)
    .execute(pool.get_ref())
    .await;

    Ok(HttpResponse::Ok().json(StatusResponse {
        submission_id,
        status: status_str,
        progress: None,
        message: None,
    }))
}

/// Helper function to get sandbox results
async fn get_sandbox_results(
    pool: &SqlitePool,
    user_id: &str,
    submission_id: &str,
) -> Result<SandboxResult, ApiError> {
    let submission: SubmissionWithConfigRow = sqlx::query_as(
        r#"SELECT s.sandbox_type, s.sandbox_task_id, c.api_url, c.api_key_encrypted
        FROM sandbox_submissions s
        JOIN sandbox_configs c ON s.sandbox_config_id = c.id
        WHERE s.id = ? AND s.user_id = ?"#
    )
    .bind(submission_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        error!("Failed to get submission: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Submission not found"))?;

    let sandbox_type: SandboxType = submission.sandbox_type.parse()
        .map_err(|_| ApiError::bad_request("Invalid sandbox type"))?;

    match sandbox_type {
        SandboxType::Cuckoo => {
            let client = CuckooClient::new(&submission.api_url, submission.api_key_encrypted.as_deref());
            client.get_results(&submission.sandbox_task_id).await
        }
        SandboxType::AnyRun => {
            let api_key = submission.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = AnyRunClient::new(api_key);
            client.get_results(&submission.sandbox_task_id).await
        }
        SandboxType::HybridAnalysis => {
            let api_key = submission.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = HybridAnalysisClient::new(api_key);
            client.get_results(&submission.sandbox_task_id).await
        }
    }.map_err(|e| {
        error!("Failed to get results: {}", e);
        ApiError::internal(format!("Failed to get results: {}", e))
    })
}

/// Get results of a completed submission
async fn get_results(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let submission_id = path.into_inner();
    let result = get_sandbox_results(pool.get_ref(), &claims.sub, &submission_id).await?;

    Ok(HttpResponse::Ok().json(SandboxResultResponse {
        id: result.id,
        sample_id: result.sample_id,
        sandbox_type: result.sandbox_type.to_string(),
        status: result.status.to_string(),
        verdict: result.verdict.to_string(),
        score: result.score,
        processes_count: result.processes.len(),
        network_iocs_count: result.network_iocs.len(),
        file_iocs_count: result.file_iocs.len(),
        dropped_files_count: result.dropped_files.len(),
        signatures_count: result.signatures.len(),
        mitre_techniques: result.mitre_techniques,
        submitted_at: result.submitted_at.to_rfc3339(),
        completed_at: result.completed_at.map(|t| t.to_rfc3339()),
        analysis_duration_seconds: result.analysis_duration_seconds,
    }))
}

/// Get processes from submission results
async fn get_processes(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let submission_id = path.into_inner();
    let result = get_sandbox_results(pool.get_ref(), &claims.sub, &submission_id).await?;

    let processes: Vec<ProcessInfoResponse> = result.processes.iter().map(|p| ProcessInfoResponse {
        pid: p.pid,
        ppid: p.ppid,
        name: p.name.clone(),
        path: p.path.clone(),
        command_line: p.command_line.clone(),
        username: p.username.clone(),
        is_injected: p.is_injected,
        is_suspicious: p.is_suspicious,
    }).collect();

    Ok(HttpResponse::Ok().json(processes))
}

/// Get screenshots from submission
async fn get_screenshots(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let submission_id = path.into_inner();

    let submission: SubmissionWithConfigRow = sqlx::query_as(
        r#"SELECT s.sandbox_type, s.sandbox_task_id, c.api_url, c.api_key_encrypted
        FROM sandbox_submissions s
        JOIN sandbox_configs c ON s.sandbox_config_id = c.id
        WHERE s.id = ? AND s.user_id = ?"#
    )
    .bind(&submission_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get submission: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Submission not found"))?;

    let sandbox_type: SandboxType = submission.sandbox_type.parse()
        .map_err(|_| ApiError::bad_request("Invalid sandbox type"))?;

    let screenshots = match sandbox_type {
        SandboxType::Cuckoo => {
            let client = CuckooClient::new(&submission.api_url, submission.api_key_encrypted.as_deref());
            client.get_screenshots(&submission.sandbox_task_id).await
        }
        SandboxType::AnyRun => {
            let api_key = submission.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = AnyRunClient::new(api_key);
            client.get_screenshots(&submission.sandbox_task_id).await
        }
        SandboxType::HybridAnalysis => {
            let api_key = submission.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = HybridAnalysisClient::new(api_key);
            client.get_screenshots(&submission.sandbox_task_id).await
        }
    }.map_err(|e| {
        error!("Failed to get screenshots: {}", e);
        ApiError::internal(format!("Failed to get screenshots: {}", e))
    })?;

    let response: Vec<ScreenshotResponse> = screenshots.iter().map(|s| ScreenshotResponse {
        id: s.id.clone(),
        timestamp: s.timestamp.map(|t| t.to_rfc3339()),
        url: s.url.clone(),
        thumbnail_url: s.thumbnail_url.clone(),
    }).collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get dropped files from submission
async fn get_dropped_files(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let submission_id = path.into_inner();
    let result = get_sandbox_results(pool.get_ref(), &claims.sub, &submission_id).await?;

    let response: Vec<DroppedFileResponse> = result.dropped_files.iter().map(|f| DroppedFileResponse {
        filename: f.filename.clone(),
        path: f.path.clone(),
        file_type: f.file_type.clone(),
        size: f.size,
        md5: f.md5.clone(),
        sha256: f.sha256.clone(),
        is_executable: f.is_executable,
        is_suspicious: f.is_suspicious,
        detection: f.detection.clone(),
    }).collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get signatures from submission results
async fn get_signatures(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let submission_id = path.into_inner();
    let result = get_sandbox_results(pool.get_ref(), &claims.sub, &submission_id).await?;

    let signatures: Vec<SignatureResponse> = result.signatures.iter().map(|s| SignatureResponse {
        name: s.name.clone(),
        description: s.description.clone(),
        severity: format!("{:?}", s.severity).to_lowercase(),
        category: s.category.clone(),
        families: s.families.clone(),
        mitre_techniques: s.mitre_techniques.clone(),
    }).collect();

    Ok(HttpResponse::Ok().json(signatures))
}

/// Get IOCs from submission results
async fn get_iocs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let submission_id = path.into_inner();
    let result = get_sandbox_results(pool.get_ref(), &claims.sub, &submission_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "network_iocs": result.network_iocs,
        "file_iocs": result.file_iocs
    })))
}

// ============================================================================
// Comparison Endpoints
// ============================================================================

/// Compare results from multiple sandbox submissions
async fn compare_submissions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    body: web::Json<CompareRequest>,
) -> Result<HttpResponse, ApiError> {
    if body.submission_ids.len() < 2 {
        return Err(ApiError::bad_request("At least 2 submissions required for comparison"));
    }

    let mut results: Vec<SandboxResult> = Vec::new();

    for submission_id in &body.submission_ids {
        let result = get_sandbox_results(pool.get_ref(), &claims.sub, submission_id).await?;
        results.push(result);
    }

    let comparison = compare_sandbox_results(&results);

    let verdicts: Vec<VerdictEntry> = comparison.verdicts.iter().map(|(st, v)| VerdictEntry {
        sandbox_type: st.to_string(),
        verdict: v.to_string(),
    }).collect();

    let scores: Vec<ScoreEntry> = comparison.scores.iter().map(|(st, s)| ScoreEntry {
        sandbox_type: st.to_string(),
        score: *s,
    }).collect();

    Ok(HttpResponse::Ok().json(CompareResponse {
        consensus_verdict: comparison.consensus_verdict.to_string(),
        average_score: comparison.average_score,
        sandbox_count: comparison.sandbox_count,
        verdicts,
        scores,
        common_signatures: comparison.common_signatures,
        common_mitre_techniques: comparison.common_mitre_techniques,
        total_network_iocs: comparison.total_network_iocs,
        total_file_iocs: comparison.total_file_iocs,
    }))
}

// ============================================================================
// Environment Endpoints
// ============================================================================

/// List all available sandbox environments
async fn list_environments(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let configs: Vec<SandboxConfigRow> = sqlx::query_as(
        r#"SELECT id, name, sandbox_type, api_url, api_key_encrypted, is_default, is_active, timeout_seconds, created_at
        FROM sandbox_configs
        WHERE user_id = ? AND is_active = 1"#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to list configs: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    let mut all_environments: Vec<EnvironmentResponse> = Vec::new();

    for config in configs {
        let sandbox_type: SandboxType = match config.sandbox_type.parse() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let environments_result = match sandbox_type {
            SandboxType::Cuckoo => {
                let client = CuckooClient::new(&config.api_url, config.api_key_encrypted.as_deref());
                client.list_machines().await
            }
            SandboxType::AnyRun => {
                let api_key = match config.api_key_encrypted.as_deref() {
                    Some(k) => k,
                    None => continue,
                };
                let client = AnyRunClient::new(api_key);
                client.get_environments().await
            }
            SandboxType::HybridAnalysis => {
                let api_key = match config.api_key_encrypted.as_deref() {
                    Some(k) => k,
                    None => continue,
                };
                let client = HybridAnalysisClient::new(api_key);
                client.get_environments().await
            }
        };

        if let Ok(environments) = environments_result {
            for env in environments {
                all_environments.push(EnvironmentResponse {
                    id: env.id,
                    name: env.name,
                    os: env.os,
                    os_version: env.os_version,
                    architecture: env.architecture,
                    available: env.available,
                    description: env.description,
                });
            }
        }
    }

    Ok(HttpResponse::Ok().json(all_environments))
}

/// Get environments for a specific sandbox configuration
async fn get_environments_for_config(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let config_id = path.into_inner();

    let config: SandboxConfigRow = sqlx::query_as(
        r#"SELECT id, name, sandbox_type, api_url, api_key_encrypted, is_default, is_active, timeout_seconds, created_at
        FROM sandbox_configs
        WHERE id = ? AND user_id = ?"#
    )
    .bind(&config_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get config: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?
    .ok_or_else(|| ApiError::not_found("Configuration not found"))?;

    let sandbox_type: SandboxType = config.sandbox_type.parse()
        .map_err(|_| ApiError::bad_request("Invalid sandbox type"))?;

    let environments = match sandbox_type {
        SandboxType::Cuckoo => {
            let client = CuckooClient::new(&config.api_url, config.api_key_encrypted.as_deref());
            client.list_machines().await
        }
        SandboxType::AnyRun => {
            let api_key = config.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = AnyRunClient::new(api_key);
            client.get_environments().await
        }
        SandboxType::HybridAnalysis => {
            let api_key = config.api_key_encrypted.as_deref()
                .ok_or_else(|| ApiError::bad_request("API key required"))?;
            let client = HybridAnalysisClient::new(api_key);
            client.get_environments().await
        }
    }.map_err(|e| {
        error!("Failed to get environments: {}", e);
        ApiError::internal(format!("Failed to get environments: {}", e))
    })?;

    let response: Vec<EnvironmentResponse> = environments.iter().map(|env| EnvironmentResponse {
        id: env.id.clone(),
        name: env.name.clone(),
        os: env.os.clone(),
        os_version: env.os_version.clone(),
        architecture: env.architecture.clone(),
        available: env.available,
        description: env.description.clone(),
    }).collect();

    Ok(HttpResponse::Ok().json(response))
}

// ============================================================================
// Statistics Endpoints
// ============================================================================

/// Get overall sandbox statistics
async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let stats: Vec<StatsRow> = sqlx::query_as(
        r#"SELECT
            sandbox_type,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
        FROM sandbox_submissions
        WHERE user_id = ?
        GROUP BY sandbox_type"#
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get stats: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    let response: Vec<StatsResponse> = stats.iter().map(|s| StatsResponse {
        sandbox_type: s.sandbox_type.clone(),
        total_submissions: s.total as u64,
        pending: s.pending as u64,
        running: s.running as u64,
        completed: s.completed as u64,
        failed: s.failed as u64,
        malicious: 0,
        suspicious: 0,
        clean: 0,
        average_analysis_time_seconds: 0.0,
    }).collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Get statistics for a specific sandbox type
async fn get_stats_by_type(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let sandbox_type = path.into_inner();

    let stats: StatsRow = sqlx::query_as(
        r#"SELECT
            ? as sandbox_type,
            COUNT(*) as total,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
        FROM sandbox_submissions
        WHERE user_id = ? AND sandbox_type = ?"#
    )
    .bind(&sandbox_type)
    .bind(user_id)
    .bind(&sandbox_type)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        error!("Failed to get stats: {}", e);
        ApiError::internal(format!("Database error: {}", e))
    })?;

    Ok(HttpResponse::Ok().json(StatsResponse {
        sandbox_type: stats.sandbox_type,
        total_submissions: stats.total as u64,
        pending: stats.pending as u64,
        running: stats.running as u64,
        completed: stats.completed as u64,
        failed: stats.failed as u64,
        malicious: 0,
        suspicious: 0,
        clean: 0,
        average_analysis_time_seconds: 0.0,
    }))
}
