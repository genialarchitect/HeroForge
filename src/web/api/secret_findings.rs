#![allow(dead_code)]
//! Secret Findings API endpoints
//!
//! This module provides REST API endpoints for managing detected secrets
//! from scans, including git repository scanning and filesystem scanning.

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::path::PathBuf;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::{self, models};
use crate::db::models::{SecretFindingRecord, SecretFindingStats, UpdateSecretFindingRequest,
    GitSecretScanRecord, FilesystemSecretScanRecord};
use crate::scanner::secret_detection::{
    GitScanConfig, GitSecretScanner,
    FilesystemScanConfig, FilesystemScanner,
    SecretDetectionConfig,
};
use crate::web::auth;

/// Query parameters for listing secret findings
#[derive(Debug, Deserialize, ToSchema)]
pub struct SecretFindingsQuery {
    pub scan_id: Option<String>,
    pub host_ip: Option<String>,
    pub secret_type: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for bulk operations
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkUpdateResponse {
    pub updated: u64,
    pub message: String,
}

/// List secret findings with optional filters
#[utoipa::path(
    get,
    path = "/api/secrets",
    tag = "Secrets",
    params(
        ("scan_id" = Option<String>, Query, description = "Filter by scan ID"),
        ("host_ip" = Option<String>, Query, description = "Filter by host IP"),
        ("secret_type" = Option<String>, Query, description = "Filter by secret type"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination"),
    ),
    responses(
        (status = 200, description = "List of secret findings", body = Vec<SecretFindingRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_secret_findings(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    query: web::Query<SecretFindingsQuery>,
) -> Result<HttpResponse> {
    let findings = db::secret_findings::get_findings_filtered(
        pool.get_ref(),
        query.scan_id.as_deref(),
        query.host_ip.as_deref(),
        query.secret_type.as_deref(),
        query.severity.as_deref(),
        query.status.as_deref(),
        query.limit,
        query.offset,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to list secret findings: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list secret findings")
    })?;

    Ok(HttpResponse::Ok().json(findings))
}

/// Get secret findings for a specific scan
#[utoipa::path(
    get,
    path = "/api/scans/{scan_id}/secrets",
    tag = "Secrets",
    params(
        ("scan_id" = String, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "List of secret findings for scan", body = Vec<SecretFindingRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Scan not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_scan_secrets(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Verify scan exists
    let scan = db::scans::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get scan: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    if scan.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        })));
    }

    let findings = db::secret_findings::get_findings_by_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get secret findings for scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get secret findings")
        })?;

    Ok(HttpResponse::Ok().json(findings))
}

/// Get statistics for secret findings
#[utoipa::path(
    get,
    path = "/api/secrets/stats",
    tag = "Secrets",
    params(
        ("scan_id" = Option<String>, Query, description = "Filter stats by scan ID"),
    ),
    responses(
        (status = 200, description = "Secret finding statistics", body = SecretFindingStats),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_secret_stats(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    query: web::Query<SecretFindingsQuery>,
) -> Result<HttpResponse> {
    let stats = db::secret_findings::get_finding_stats(pool.get_ref(), query.scan_id.as_deref())
        .await
        .map_err(|e| {
            log::error!("Failed to get secret stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get statistics")
        })?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Get a single secret finding by ID
#[utoipa::path(
    get,
    path = "/api/secrets/{id}",
    tag = "Secrets",
    params(
        ("id" = String, Path, description = "Secret finding ID"),
    ),
    responses(
        (status = 200, description = "Secret finding details", body = SecretFindingRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Finding not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_secret_finding(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let finding = db::secret_findings::get_finding_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to get secret finding: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    match finding {
        Some(f) => Ok(HttpResponse::Ok().json(f)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Secret finding not found"
        }))),
    }
}

/// Update a secret finding (status, notes, false positive flag)
#[utoipa::path(
    patch,
    path = "/api/secrets/{id}",
    tag = "Secrets",
    params(
        ("id" = String, Path, description = "Secret finding ID"),
    ),
    request_body = UpdateSecretFindingRequest,
    responses(
        (status = 200, description = "Updated secret finding", body = SecretFindingRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Finding not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn update_secret_finding(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    path: web::Path<String>,
    body: web::Json<models::UpdateSecretFindingRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    // Verify finding exists
    let existing = db::secret_findings::get_finding_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to get secret finding: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    if existing.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Secret finding not found"
        })));
    }

    let updated = db::secret_findings::update_finding(
        pool.get_ref(),
        &id,
        &claims.sub,
        &body,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to update secret finding: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update finding")
    })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Bulk update status for multiple secret findings
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkUpdateRequest {
    pub ids: Vec<String>,
    pub status: String,
}

#[utoipa::path(
    post,
    path = "/api/secrets/bulk-status",
    tag = "Secrets",
    request_body = BulkUpdateRequest,
    responses(
        (status = 200, description = "Bulk update result", body = BulkUpdateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn bulk_update_status(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    body: web::Json<BulkUpdateRequest>,
) -> Result<HttpResponse> {
    if body.ids.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No IDs provided"
        })));
    }

    let valid_statuses = ["open", "resolved", "investigating", "false_positive"];
    if !valid_statuses.contains(&body.status.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid status. Must be one of: open, resolved, investigating, false_positive"
        })));
    }

    let updated = db::secret_findings::bulk_update_status(
        pool.get_ref(),
        &body.ids,
        &body.status,
        &claims.sub,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to bulk update secret findings: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update findings")
    })?;

    Ok(HttpResponse::Ok().json(BulkUpdateResponse {
        updated,
        message: format!("Updated {} findings to status '{}'", updated, body.status),
    }))
}

// ============================================================================
// Git Repository Scanning
// ============================================================================

/// Request to start a git repository secret scan
#[derive(Debug, Deserialize, ToSchema)]
pub struct GitSecretScanRequest {
    /// URL of the git repository to scan
    pub repository_url: Option<String>,
    /// Local path to the git repository (alternative to URL)
    pub repository_path: Option<String>,
    /// Branch to scan (default: HEAD)
    pub branch: Option<String>,
    /// Whether to scan commit history
    #[serde(default)]
    pub scan_history: bool,
    /// How many commits to scan in history (default: 100)
    pub history_depth: Option<usize>,
}

/// Response for a git secret scan
#[derive(Debug, Serialize, ToSchema)]
pub struct GitSecretScanResponse {
    pub id: String,
    pub status: String,
    pub message: String,
}

/// Start a git repository secret scan
#[utoipa::path(
    post,
    path = "/api/secrets/scan/git",
    tag = "Secrets",
    request_body = GitSecretScanRequest,
    responses(
        (status = 202, description = "Scan started", body = GitSecretScanResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn start_git_secret_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    body: web::Json<GitSecretScanRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if body.repository_url.is_none() && body.repository_path.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Either repository_url or repository_path is required"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Insert scan record
    sqlx::query(
        r#"
        INSERT INTO git_secret_scans (
            id, user_id, repository_url, repository_path, branch,
            scan_history, history_depth, status, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.repository_url)
    .bind(&body.repository_path)
    .bind(body.branch.as_deref().unwrap_or("HEAD"))
    .bind(body.scan_history)
    .bind(body.history_depth.unwrap_or(100) as i32)
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create git secret scan: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Spawn background task to perform the scan
    let pool_clone = pool.get_ref().clone();
    let scan_id = id.clone();
    let repo_url = body.repository_url.clone();
    let repo_path = body.repository_path.clone();
    let branch = body.branch.clone().unwrap_or_else(|| "HEAD".to_string());
    let scan_history = body.scan_history;
    let history_depth = body.history_depth.unwrap_or(100);

    tokio::spawn(async move {
        run_git_secret_scan(
            &pool_clone,
            &scan_id,
            repo_url,
            repo_path,
            &branch,
            scan_history,
            history_depth,
        )
        .await;
    });

    Ok(HttpResponse::Accepted().json(GitSecretScanResponse {
        id,
        status: "pending".to_string(),
        message: "Git secret scan started".to_string(),
    }))
}

/// Background task to run a git secret scan
async fn run_git_secret_scan(
    pool: &SqlitePool,
    scan_id: &str,
    repo_url: Option<String>,
    repo_path: Option<String>,
    branch: &str,
    scan_history: bool,
    history_depth: usize,
) {
    let now = Utc::now();

    // Update status to running
    let _ = sqlx::query(
        "UPDATE git_secret_scans SET status = 'running', started_at = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(now)
    .bind(now)
    .bind(scan_id)
    .execute(pool)
    .await;

    // Determine the repository path
    let path = if let Some(p) = repo_path {
        PathBuf::from(p)
    } else if let Some(_url) = &repo_url {
        // TODO: Clone the repository to a temporary directory
        // For now, we just error out if only URL is provided
        let _ = sqlx::query(
            "UPDATE git_secret_scans SET status = 'failed', error_message = ?1, completed_at = ?2, updated_at = ?3 WHERE id = ?4",
        )
        .bind("Repository URL cloning not yet implemented. Please provide a local path.")
        .bind(Utc::now())
        .bind(Utc::now())
        .bind(scan_id)
        .execute(pool)
        .await;
        return;
    } else {
        return;
    };

    // Create scanner configuration
    let mut config = GitScanConfig::default();
    config.commit_depth = if scan_history { history_depth } else { 0 };
    config.branch = Some(branch.to_string());
    config.max_file_size = 10 * 1024 * 1024; // 10MB

    let scanner = GitSecretScanner::new(config);

    match scanner.scan_repository(&path) {
        Ok(findings) => {
            let finding_count = findings.len() as i32;

            // Store findings in database
            for finding in &findings {
                let finding_id = Uuid::new_v4().to_string();
                let git_finding_id = Uuid::new_v4().to_string();

                // Insert into secret_findings table
                let _ = sqlx::query(
                    r#"
                    INSERT INTO secret_findings (
                        id, scan_id, host_ip, secret_type, severity, redacted_value,
                        source_type, source_location, line_number, context, confidence,
                        status, false_positive, entropy_score, detection_method, created_at, updated_at
                    )
                    VALUES (?1, ?2, 'localhost', ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0.9,
                            'open', 0, ?10, ?11, ?12, ?13)
                    "#,
                )
                .bind(&finding_id)
                .bind(scan_id)
                .bind(format!("{:?}", finding.finding.secret_type))
                .bind(format!("{:?}", finding.finding.severity))
                .bind(&finding.finding.redacted_value)
                .bind("git")
                .bind(&finding.file_path)
                .bind(finding.finding.line.map(|l| l as i32))
                .bind(&finding.finding.context)
                .bind(finding.finding.entropy_score)
                .bind(&finding.finding.detection_method)
                .bind(Utc::now())
                .bind(Utc::now())
                .execute(pool)
                .await;

                // Insert into git_secret_findings table
                let _ = sqlx::query(
                    r#"
                    INSERT INTO git_secret_findings (
                        id, git_scan_id, finding_id, commit_sha, commit_author,
                        commit_email, commit_date, commit_message, file_path, is_current, created_at
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                    "#,
                )
                .bind(&git_finding_id)
                .bind(scan_id)
                .bind(&finding_id)
                .bind(&finding.commit_sha)
                .bind(&finding.commit_author)
                .bind::<Option<String>>(None) // commit_email
                .bind(&finding.commit_date)
                .bind::<Option<String>>(None) // commit_message
                .bind(&finding.file_path)
                .bind(finding.is_current)
                .bind(Utc::now())
                .execute(pool)
                .await;
            }

            // Update scan status to completed
            let _ = sqlx::query(
                r#"
                UPDATE git_secret_scans
                SET status = 'completed', finding_count = ?1, completed_at = ?2, updated_at = ?3
                WHERE id = ?4
                "#,
            )
            .bind(finding_count)
            .bind(Utc::now())
            .bind(Utc::now())
            .bind(scan_id)
            .execute(pool)
            .await;

            log::info!("Git secret scan {} completed with {} findings", scan_id, finding_count);
        }
        Err(e) => {
            let _ = sqlx::query(
                r#"
                UPDATE git_secret_scans
                SET status = 'failed', error_message = ?1, completed_at = ?2, updated_at = ?3
                WHERE id = ?4
                "#,
            )
            .bind(format!("{}", e))
            .bind(Utc::now())
            .bind(Utc::now())
            .bind(scan_id)
            .execute(pool)
            .await;

            log::error!("Git secret scan {} failed: {}", scan_id, e);
        }
    }
}

/// Get git secret scan status
#[utoipa::path(
    get,
    path = "/api/secrets/scan/git/{id}",
    tag = "Secrets",
    params(
        ("id" = String, Path, description = "Git scan ID"),
    ),
    responses(
        (status = 200, description = "Git scan status", body = GitSecretScanRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Scan not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_git_secret_scan(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let scan = sqlx::query_as::<_, GitSecretScanRecord>(
        "SELECT * FROM git_secret_scans WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get git secret scan: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    match scan {
        Some(s) => Ok(HttpResponse::Ok().json(s)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Git secret scan not found"
        }))),
    }
}

/// List git secret scans
#[utoipa::path(
    get,
    path = "/api/secrets/scan/git",
    tag = "Secrets",
    responses(
        (status = 200, description = "List of git secret scans", body = Vec<GitSecretScanRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_git_secret_scans(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
) -> Result<HttpResponse> {
    let scans = sqlx::query_as::<_, GitSecretScanRecord>(
        "SELECT * FROM git_secret_scans WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to list git secret scans: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(scans))
}

// ============================================================================
// Filesystem Scanning
// ============================================================================

/// Request to start a filesystem secret scan
#[derive(Debug, Deserialize, ToSchema)]
pub struct FilesystemSecretScanRequest {
    /// Paths to scan
    pub paths: Vec<String>,
    /// Scan directories recursively
    #[serde(default = "default_true")]
    pub recursive: bool,
    /// Maximum directory depth (0 = unlimited)
    #[serde(default)]
    pub max_depth: usize,
    /// File patterns to include (glob patterns)
    pub include_patterns: Option<Vec<String>>,
    /// File patterns to exclude (glob patterns)
    pub exclude_patterns: Option<Vec<String>>,
    /// Enable entropy-based detection
    #[serde(default = "default_true")]
    pub entropy_detection: bool,
}

fn default_true() -> bool {
    true
}

/// Response for a filesystem secret scan
#[derive(Debug, Serialize, ToSchema)]
pub struct FilesystemSecretScanResponse {
    pub id: String,
    pub status: String,
    pub message: String,
}

/// Start a filesystem secret scan
#[utoipa::path(
    post,
    path = "/api/secrets/scan/filesystem",
    tag = "Secrets",
    request_body = FilesystemSecretScanRequest,
    responses(
        (status = 202, description = "Scan started", body = FilesystemSecretScanResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn start_filesystem_secret_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    body: web::Json<FilesystemSecretScanRequest>,
) -> Result<HttpResponse> {
    if body.paths.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one path is required"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Serialize paths and patterns to JSON
    let paths_json = serde_json::to_string(&body.paths).unwrap_or_default();
    let include_json = body.include_patterns.as_ref().map(|p| serde_json::to_string(p).ok()).flatten();
    let exclude_json = body.exclude_patterns.as_ref().map(|p| serde_json::to_string(p).ok()).flatten();

    // Insert scan record
    sqlx::query(
        r#"
        INSERT INTO filesystem_secret_scans (
            id, user_id, scan_paths, recursive, max_depth,
            include_patterns, exclude_patterns, entropy_detection,
            status, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&paths_json)
    .bind(body.recursive)
    .bind(body.max_depth as i32)
    .bind(&include_json)
    .bind(&exclude_json)
    .bind(body.entropy_detection)
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create filesystem secret scan: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Spawn background task
    let pool_clone = pool.get_ref().clone();
    let scan_id = id.clone();
    let paths: Vec<PathBuf> = body.paths.iter().map(PathBuf::from).collect();
    let recursive = body.recursive;
    let max_depth = body.max_depth;
    let include_patterns = body.include_patterns.clone().unwrap_or_default();
    let exclude_patterns = body.exclude_patterns.clone().unwrap_or_default();
    let entropy_detection = body.entropy_detection;

    tokio::spawn(async move {
        run_filesystem_secret_scan(
            &pool_clone,
            &scan_id,
            paths,
            recursive,
            max_depth,
            include_patterns,
            exclude_patterns,
            entropy_detection,
        )
        .await;
    });

    Ok(HttpResponse::Accepted().json(FilesystemSecretScanResponse {
        id,
        status: "pending".to_string(),
        message: "Filesystem secret scan started".to_string(),
    }))
}

/// Background task to run a filesystem secret scan
async fn run_filesystem_secret_scan(
    pool: &SqlitePool,
    scan_id: &str,
    paths: Vec<PathBuf>,
    recursive: bool,
    max_depth: usize,
    include_patterns: Vec<String>,
    exclude_patterns: Vec<String>,
    entropy_detection: bool,
) {
    let now = Utc::now();

    // Update status to running
    let _ = sqlx::query(
        "UPDATE filesystem_secret_scans SET status = 'running', started_at = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(now)
    .bind(now)
    .bind(scan_id)
    .execute(pool)
    .await;

    // Create scanner configuration
    let mut config = FilesystemScanConfig::default();
    config.paths = paths;
    config.recursive = recursive;
    config.max_depth = max_depth;
    if !include_patterns.is_empty() {
        config.include_patterns = include_patterns;
    }
    if !exclude_patterns.is_empty() {
        config.exclude_patterns.extend(exclude_patterns);
    }
    config.entropy_detection = entropy_detection;

    let scanner = FilesystemScanner::new(config);

    match scanner.scan().await {
        Ok(result) => {
            let finding_count = result.findings.len() as i32;

            // Store findings in database
            for finding in &result.findings {
                let finding_id = Uuid::new_v4().to_string();
                let fs_finding_id = Uuid::new_v4().to_string();

                // Insert into secret_findings table
                let _ = sqlx::query(
                    r#"
                    INSERT INTO secret_findings (
                        id, scan_id, host_ip, secret_type, severity, redacted_value,
                        source_type, source_location, line_number, context, confidence,
                        status, false_positive, entropy_score, detection_method, created_at, updated_at
                    )
                    VALUES (?1, ?2, 'localhost', ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0.9,
                            'open', 0, ?10, ?11, ?12, ?13)
                    "#,
                )
                .bind(&finding_id)
                .bind(scan_id)
                .bind(format!("{:?}", finding.finding.secret_type))
                .bind(format!("{:?}", finding.finding.severity))
                .bind(&finding.finding.redacted_value)
                .bind("filesystem")
                .bind(finding.relative_path.clone())
                .bind(finding.finding.line.map(|l| l as i32))
                .bind(&finding.finding.context)
                .bind(finding.finding.entropy_score)
                .bind(&finding.finding.detection_method)
                .bind(Utc::now())
                .bind(Utc::now())
                .execute(pool)
                .await;

                // Insert into filesystem_secret_findings table
                let _ = sqlx::query(
                    r#"
                    INSERT INTO filesystem_secret_findings (
                        id, fs_scan_id, finding_id, file_path, relative_path,
                        file_size, file_modified, file_owner, file_permissions, created_at
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                    "#,
                )
                .bind(&fs_finding_id)
                .bind(scan_id)
                .bind(&finding_id)
                .bind(finding.file_path.to_string_lossy().to_string())
                .bind(&finding.relative_path)
                .bind(finding.file_size as i64)
                .bind(&finding.modified_at)
                .bind(&finding.owner)
                .bind(&finding.permissions)
                .bind(Utc::now())
                .execute(pool)
                .await;
            }

            // Update scan status to completed
            let _ = sqlx::query(
                r#"
                UPDATE filesystem_secret_scans
                SET status = 'completed', finding_count = ?1, files_scanned = ?2,
                    bytes_scanned = ?3, files_skipped = ?4, directories_scanned = ?5,
                    completed_at = ?6, updated_at = ?7
                WHERE id = ?8
                "#,
            )
            .bind(finding_count)
            .bind(result.files_scanned as i32)
            .bind(result.bytes_scanned as i64)
            .bind(result.files_skipped as i32)
            .bind(result.directories_scanned as i32)
            .bind(Utc::now())
            .bind(Utc::now())
            .bind(scan_id)
            .execute(pool)
            .await;

            log::info!("Filesystem secret scan {} completed with {} findings", scan_id, finding_count);
        }
        Err(e) => {
            let _ = sqlx::query(
                r#"
                UPDATE filesystem_secret_scans
                SET status = 'failed', error_message = ?1, completed_at = ?2, updated_at = ?3
                WHERE id = ?4
                "#,
            )
            .bind(format!("{}", e))
            .bind(Utc::now())
            .bind(Utc::now())
            .bind(scan_id)
            .execute(pool)
            .await;

            log::error!("Filesystem secret scan {} failed: {}", scan_id, e);
        }
    }
}

/// Get filesystem secret scan status
#[utoipa::path(
    get,
    path = "/api/secrets/scan/filesystem/{id}",
    tag = "Secrets",
    params(
        ("id" = String, Path, description = "Filesystem scan ID"),
    ),
    responses(
        (status = 200, description = "Filesystem scan status", body = FilesystemSecretScanRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Scan not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_filesystem_secret_scan(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let scan = sqlx::query_as::<_, FilesystemSecretScanRecord>(
        "SELECT * FROM filesystem_secret_scans WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get filesystem secret scan: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    match scan {
        Some(s) => Ok(HttpResponse::Ok().json(s)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Filesystem secret scan not found"
        }))),
    }
}

/// List filesystem secret scans
#[utoipa::path(
    get,
    path = "/api/secrets/scan/filesystem",
    tag = "Secrets",
    responses(
        (status = 200, description = "List of filesystem secret scans", body = Vec<FilesystemSecretScanRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_filesystem_secret_scans(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
) -> Result<HttpResponse> {
    let scans = sqlx::query_as::<_, FilesystemSecretScanRecord>(
        "SELECT * FROM filesystem_secret_scans WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to list filesystem secret scans: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Configure routes for secret findings API
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/secrets")
            .route("", web::get().to(list_secret_findings))
            .route("/stats", web::get().to(get_secret_stats))
            .route("/bulk-status", web::post().to(bulk_update_status))
            .route("/scan/git", web::post().to(start_git_secret_scan))
            .route("/scan/git", web::get().to(list_git_secret_scans))
            .route("/scan/git/{id}", web::get().to(get_git_secret_scan))
            .route("/scan/filesystem", web::post().to(start_filesystem_secret_scan))
            .route("/scan/filesystem", web::get().to(list_filesystem_secret_scans))
            .route("/scan/filesystem/{id}", web::get().to(get_filesystem_secret_scan))
            .route("/{id}", web::get().to(get_secret_finding))
            .route("/{id}", web::patch().to(update_secret_finding)),
    );
}

/// Configure scan-specific secret routes
pub fn configure_scan_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/scans/{scan_id}/secrets", web::get().to(get_scan_secrets));
}
