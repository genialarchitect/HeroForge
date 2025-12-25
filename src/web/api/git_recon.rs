//! Git Repository Reconnaissance API endpoints
//!
//! This module provides REST API endpoints for scanning public GitHub and GitLab
//! repositories for exposed secrets using their APIs.
//!
//! # Endpoints
//!
//! - `POST /api/recon/git/scan-repo` - Scan a specific repository
//! - `POST /api/recon/git/enumerate` - Enumerate user/org repositories
//! - `GET /api/recon/git/results` - List scan results
//! - `GET /api/recon/git/results/{id}` - Get specific scan result
//! - `GET /api/recon/git/secrets` - List all secrets found
//! - `PATCH /api/recon/git/secrets/{id}` - Update secret status

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::scanner::git_recon::{
    GitHubClient, GitLabClient, GitPlatformClient, GitReconConfig, GitReconScanner,
    GitAuthMethod,
};
use crate::web::auth;

/// Request to scan a specific git repository
#[derive(Debug, Deserialize, ToSchema)]
pub struct ScanRepoRequest {
    /// Repository URL (e.g., https://github.com/owner/repo)
    pub repository_url: String,
    /// Platform (github, gitlab) - auto-detected if not provided
    pub platform: Option<String>,
    /// API token for authentication (optional, enables scanning private repos)
    pub api_token: Option<String>,
    /// Scan current files in HEAD
    #[serde(default = "default_true")]
    pub scan_current_files: bool,
    /// Scan commit history
    #[serde(default = "default_true")]
    pub scan_commit_history: bool,
    /// Number of commits to scan in history
    #[serde(default = "default_commit_depth")]
    pub commit_depth: usize,
}

fn default_true() -> bool {
    true
}

fn default_commit_depth() -> usize {
    50
}

/// Request to enumerate repositories for a user or organization
#[derive(Debug, Deserialize, ToSchema)]
pub struct EnumerateRequest {
    /// Username or organization name
    pub target: String,
    /// Target type: "user" or "org"
    pub target_type: String,
    /// Platform: "github" or "gitlab"
    pub platform: String,
    /// API token for authentication (optional)
    pub api_token: Option<String>,
    /// Include private repositories
    #[serde(default)]
    pub include_private: bool,
    /// Include forked repositories
    #[serde(default)]
    pub include_forks: bool,
    /// Include archived repositories
    #[serde(default)]
    pub include_archived: bool,
    /// Scan each discovered repository for secrets
    #[serde(default)]
    pub scan_repos: bool,
}

/// Response for scan initiation
#[derive(Debug, Serialize, ToSchema)]
pub struct ScanResponse {
    pub id: String,
    pub status: String,
    pub message: String,
}

/// Response for repository enumeration
#[derive(Debug, Serialize, ToSchema)]
pub struct EnumerateResponse {
    pub id: String,
    pub status: String,
    pub repos_found: usize,
    pub message: String,
}

/// Git recon scan record from database
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct GitReconScanRecord {
    pub id: String,
    pub user_id: String,
    pub platform: String,
    pub scan_type: String,
    pub target: String,
    pub owner: Option<String>,
    pub repo_name: Option<String>,
    pub status: String,
    pub repos_scanned: Option<i32>,
    pub files_scanned: Option<i32>,
    pub commits_scanned: Option<i32>,
    pub secrets_found: Option<i32>,
    pub error_message: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Git recon secret record from database
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct GitReconSecretRecord {
    pub id: String,
    pub scan_id: String,
    pub repo_id: Option<String>,
    pub platform: String,
    pub owner: String,
    pub repo_name: String,
    pub secret_type: String,
    pub severity: String,
    pub redacted_value: String,
    pub file_path: String,
    pub line_number: Option<i32>,
    pub context: Option<String>,
    pub commit_sha: Option<String>,
    pub commit_author: Option<String>,
    pub commit_date: Option<String>,
    pub is_current: i32,
    pub detection_method: Option<String>,
    pub remediation: Option<String>,
    pub status: String,
    pub false_positive: i32,
    pub notes: Option<String>,
    pub reviewed_by: Option<String>,
    pub reviewed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to update a secret's status
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSecretRequest {
    pub status: Option<String>,
    pub false_positive: Option<bool>,
    pub notes: Option<String>,
}

/// Query parameters for listing results
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListQuery {
    pub platform: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Scan a specific git repository
#[utoipa::path(
    post,
    path = "/api/recon/git/scan-repo",
    tag = "Git Recon",
    request_body = ScanRepoRequest,
    responses(
        (status = 202, description = "Scan started", body = ScanResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn scan_repo(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    body: web::Json<ScanRepoRequest>,
) -> Result<HttpResponse> {
    // Parse repository URL to extract platform, owner, and repo name
    let (platform, owner, repo_name) = match parse_repo_url(&body.repository_url) {
        Some(parsed) => parsed,
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid repository URL. Expected format: https://github.com/owner/repo or https://gitlab.com/owner/repo"
            })));
        }
    };

    // Override platform if specified
    let platform = body.platform.as_deref().unwrap_or(&platform);

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Insert scan record
    sqlx::query(
        r#"
        INSERT INTO git_recon_scans (
            id, user_id, platform, scan_type, target, owner, repo_name,
            scan_current_files, scan_commit_history, commit_depth,
            status, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, 'repo', ?4, ?5, ?6, ?7, ?8, ?9, 'pending', ?10, ?11)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(platform)
    .bind(&body.repository_url)
    .bind(&owner)
    .bind(&repo_name)
    .bind(body.scan_current_files)
    .bind(body.scan_commit_history)
    .bind(body.commit_depth as i32)
    .bind(&now.to_rfc3339())
    .bind(&now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create git recon scan: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Spawn background task to perform the scan
    let pool_clone = pool.get_ref().clone();
    let scan_id = id.clone();
    let platform_clone = platform.to_string();
    let owner_clone = owner.clone();
    let repo_name_clone = repo_name.clone();
    let api_token = body.api_token.clone();
    let scan_current = body.scan_current_files;
    let scan_history = body.scan_commit_history;
    let commit_depth = body.commit_depth;

    tokio::spawn(async move {
        run_repo_scan(
            &pool_clone,
            &scan_id,
            &platform_clone,
            &owner_clone,
            &repo_name_clone,
            api_token,
            scan_current,
            scan_history,
            commit_depth,
        )
        .await;
    });

    Ok(HttpResponse::Accepted().json(ScanResponse {
        id,
        status: "pending".to_string(),
        message: format!("Scan started for {}/{}", owner, repo_name),
    }))
}

/// Background task to run a repository scan
async fn run_repo_scan(
    pool: &SqlitePool,
    scan_id: &str,
    platform: &str,
    owner: &str,
    repo_name: &str,
    api_token: Option<String>,
    scan_current_files: bool,
    scan_commit_history: bool,
    commit_depth: usize,
) {
    let now = Utc::now();

    // Update status to running
    let _ = sqlx::query(
        "UPDATE git_recon_scans SET status = 'running', started_at = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(&now.to_rfc3339())
    .bind(&now.to_rfc3339())
    .bind(scan_id)
    .execute(pool)
    .await;

    // Create scanner configuration
    let mut config = GitReconConfig::default();
    config.scan_current_files = scan_current_files;
    config.scan_commit_history = scan_commit_history;
    config.commit_depth = commit_depth;

    let scanner = GitReconScanner::new(config);

    // Create appropriate client based on platform
    let auth = match api_token {
        Some(token) => GitAuthMethod::Token(token),
        None => GitAuthMethod::None,
    };

    let result = match platform {
        "github" => {
            let client = GitHubClient::with_auth(auth);
            scanner.scan_repository(&client, owner, repo_name).await
        }
        "gitlab" => {
            let client = GitLabClient::with_auth(auth);
            scanner.scan_repository(&client, owner, repo_name).await
        }
        _ => {
            let _ = update_scan_failed(pool, scan_id, "Unsupported platform").await;
            return;
        }
    };

    match result {
        Ok(scan_result) => {
            // Store secrets in database
            for secret in &scan_result.secrets {
                let secret_id = Uuid::new_v4().to_string();
                let now = Utc::now();

                let _ = sqlx::query(
                    r#"
                    INSERT INTO git_recon_secrets (
                        id, scan_id, platform, owner, repo_name, secret_type, severity,
                        redacted_value, file_path, line_number, context, commit_sha,
                        commit_author, commit_date, is_current, detection_method,
                        remediation, status, created_at, updated_at
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 'open', ?18, ?19)
                    "#,
                )
                .bind(&secret_id)
                .bind(scan_id)
                .bind(platform)
                .bind(owner)
                .bind(repo_name)
                .bind(&secret.secret_type)
                .bind(&secret.severity)
                .bind(&secret.redacted_value)
                .bind(&secret.file_path)
                .bind(secret.line_number.map(|l| l as i32))
                .bind(&secret.context)
                .bind(&secret.commit_sha)
                .bind(&secret.commit_author)
                .bind(&secret.commit_date)
                .bind(if secret.is_current { 1 } else { 0 })
                .bind(&secret.detection_method)
                .bind(&secret.remediation)
                .bind(&now.to_rfc3339())
                .bind(&now.to_rfc3339())
                .execute(pool)
                .await;
            }

            // Update scan status to completed
            let _ = sqlx::query(
                r#"
                UPDATE git_recon_scans
                SET status = 'completed', files_scanned = ?1, commits_scanned = ?2,
                    secrets_found = ?3, completed_at = ?4, updated_at = ?5
                WHERE id = ?6
                "#,
            )
            .bind(scan_result.files_scanned as i32)
            .bind(scan_result.commits_scanned as i32)
            .bind(scan_result.secrets.len() as i32)
            .bind(&Utc::now().to_rfc3339())
            .bind(&Utc::now().to_rfc3339())
            .bind(scan_id)
            .execute(pool)
            .await;

            log::info!(
                "Git recon scan {} completed: {} files, {} commits, {} secrets",
                scan_id,
                scan_result.files_scanned,
                scan_result.commits_scanned,
                scan_result.secrets.len()
            );
        }
        Err(e) => {
            let _ = update_scan_failed(pool, scan_id, &e.to_string()).await;
            log::error!("Git recon scan {} failed: {}", scan_id, e);
        }
    }
}

/// Enumerate repositories for a user or organization
#[utoipa::path(
    post,
    path = "/api/recon/git/enumerate",
    tag = "Git Recon",
    request_body = EnumerateRequest,
    responses(
        (status = 202, description = "Enumeration started", body = EnumerateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn enumerate_repos(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    body: web::Json<EnumerateRequest>,
) -> Result<HttpResponse> {
    // Validate target type
    if body.target_type != "user" && body.target_type != "org" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "target_type must be 'user' or 'org'"
        })));
    }

    // Validate platform
    if body.platform != "github" && body.platform != "gitlab" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "platform must be 'github' or 'gitlab'"
        })));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Insert scan record
    sqlx::query(
        r#"
        INSERT INTO git_recon_scans (
            id, user_id, platform, scan_type, target, owner,
            include_private, include_forks, include_archived,
            status, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', ?10, ?11)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.platform)
    .bind(&body.target_type)
    .bind(&body.target)
    .bind(&body.target)
    .bind(body.include_private)
    .bind(body.include_forks)
    .bind(body.include_archived)
    .bind(&now.to_rfc3339())
    .bind(&now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create git recon enumeration: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Spawn background task
    let pool_clone = pool.get_ref().clone();
    let scan_id = id.clone();
    let platform = body.platform.clone();
    let target_type = body.target_type.clone();
    let target = body.target.clone();
    let api_token = body.api_token.clone();
    let include_private = body.include_private;
    let include_forks = body.include_forks;
    let include_archived = body.include_archived;
    let scan_repos = body.scan_repos;

    tokio::spawn(async move {
        run_enumeration(
            &pool_clone,
            &scan_id,
            &platform,
            &target_type,
            &target,
            api_token,
            include_private,
            include_forks,
            include_archived,
            scan_repos,
        )
        .await;
    });

    Ok(HttpResponse::Accepted().json(EnumerateResponse {
        id,
        status: "pending".to_string(),
        repos_found: 0,
        message: format!("Enumeration started for {} {}", body.target_type, body.target),
    }))
}

/// Background task to run repository enumeration
async fn run_enumeration(
    pool: &SqlitePool,
    scan_id: &str,
    platform: &str,
    target_type: &str,
    target: &str,
    api_token: Option<String>,
    include_private: bool,
    include_forks: bool,
    include_archived: bool,
    scan_repos: bool,
) {
    let now = Utc::now();

    // Update status to running
    let _ = sqlx::query(
        "UPDATE git_recon_scans SET status = 'running', started_at = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(&now.to_rfc3339())
    .bind(&now.to_rfc3339())
    .bind(scan_id)
    .execute(pool)
    .await;

    let auth = match api_token {
        Some(token) => GitAuthMethod::Token(token),
        None => GitAuthMethod::None,
    };

    // Get repositories
    let repos_result = match platform {
        "github" => {
            let client = GitHubClient::with_auth(auth.clone());
            if target_type == "user" {
                client.enumerate_user_repos(target).await
            } else {
                client.enumerate_org_repos(target).await
            }
        }
        "gitlab" => {
            let client = GitLabClient::with_auth(auth.clone());
            if target_type == "user" {
                client.enumerate_user_repos(target).await
            } else {
                client.enumerate_org_repos(target).await
            }
        }
        _ => {
            let _ = update_scan_failed(pool, scan_id, "Unsupported platform").await;
            return;
        }
    };

    match repos_result {
        Ok(repos) => {
            let mut repos_stored = 0;

            // Store discovered repositories
            for repo in &repos {
                // Apply filters
                if repo.is_private && !include_private {
                    continue;
                }
                if repo.is_fork && !include_forks {
                    continue;
                }
                if repo.is_archived && !include_archived {
                    continue;
                }

                let repo_id = Uuid::new_v4().to_string();
                let now = Utc::now();

                let _ = sqlx::query(
                    r#"
                    INSERT INTO git_recon_repos (
                        id, scan_id, platform, owner, name, full_name, description,
                        url, clone_url, default_branch, is_private, is_fork, is_archived,
                        size_kb, language, stars, forks, pushed_at, created_at, discovered_at
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                    "#,
                )
                .bind(&repo_id)
                .bind(scan_id)
                .bind(platform)
                .bind(&repo.owner)
                .bind(&repo.name)
                .bind(&repo.full_name)
                .bind(&repo.description)
                .bind(&repo.url)
                .bind(&repo.clone_url)
                .bind(&repo.default_branch)
                .bind(if repo.is_private { 1 } else { 0 })
                .bind(if repo.is_fork { 1 } else { 0 })
                .bind(if repo.is_archived { 1 } else { 0 })
                .bind(repo.size_kb.map(|s| s as i64))
                .bind(&repo.language)
                .bind(repo.stars.map(|s| s as i64))
                .bind(repo.forks.map(|f| f as i64))
                .bind(&repo.pushed_at)
                .bind(&repo.created_at)
                .bind(&now.to_rfc3339())
                .execute(pool)
                .await;

                repos_stored += 1;
            }

            // Update scan with repo count
            let _ = sqlx::query(
                "UPDATE git_recon_scans SET repos_scanned = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(repos_stored as i32)
            .bind(&Utc::now().to_rfc3339())
            .bind(scan_id)
            .execute(pool)
            .await;

            // Optionally scan each repository for secrets
            if scan_repos {
                let mut config = GitReconConfig::default();
                config.include_private = include_private;
                config.include_forks = include_forks;
                config.include_archived = include_archived;

                let scanner = GitReconScanner::new(config);
                let mut total_secrets = 0;
                let mut total_files = 0;
                let mut total_commits = 0;

                for repo in &repos {
                    // Apply filters again
                    if repo.is_private && !include_private {
                        continue;
                    }
                    if repo.is_fork && !include_forks {
                        continue;
                    }
                    if repo.is_archived && !include_archived {
                        continue;
                    }

                    let scan_result = match platform {
                        "github" => {
                            let client = GitHubClient::with_auth(auth.clone());
                            scanner.scan_repository(&client, &repo.owner, &repo.name).await
                        }
                        "gitlab" => {
                            let client = GitLabClient::with_auth(auth.clone());
                            scanner.scan_repository(&client, &repo.owner, &repo.name).await
                        }
                        _ => continue,
                    };

                    if let Ok(result) = scan_result {
                        total_files += result.files_scanned;
                        total_commits += result.commits_scanned;
                        total_secrets += result.secrets.len();

                        // Store secrets
                        for secret in &result.secrets {
                            let secret_id = Uuid::new_v4().to_string();
                            let now = Utc::now();

                            let _ = sqlx::query(
                                r#"
                                INSERT INTO git_recon_secrets (
                                    id, scan_id, platform, owner, repo_name, secret_type, severity,
                                    redacted_value, file_path, line_number, context, commit_sha,
                                    commit_author, commit_date, is_current, detection_method,
                                    remediation, status, created_at, updated_at
                                )
                                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, 'open', ?18, ?19)
                                "#,
                            )
                            .bind(&secret_id)
                            .bind(scan_id)
                            .bind(platform)
                            .bind(&repo.owner)
                            .bind(&repo.name)
                            .bind(&secret.secret_type)
                            .bind(&secret.severity)
                            .bind(&secret.redacted_value)
                            .bind(&secret.file_path)
                            .bind(secret.line_number.map(|l| l as i32))
                            .bind(&secret.context)
                            .bind(&secret.commit_sha)
                            .bind(&secret.commit_author)
                            .bind(&secret.commit_date)
                            .bind(if secret.is_current { 1 } else { 0 })
                            .bind(&secret.detection_method)
                            .bind(&secret.remediation)
                            .bind(&now.to_rfc3339())
                            .bind(&now.to_rfc3339())
                            .execute(pool)
                            .await;
                        }
                    }
                }

                // Update final counts
                let _ = sqlx::query(
                    r#"
                    UPDATE git_recon_scans
                    SET files_scanned = ?1, commits_scanned = ?2, secrets_found = ?3,
                        status = 'completed', completed_at = ?4, updated_at = ?5
                    WHERE id = ?6
                    "#,
                )
                .bind(total_files as i32)
                .bind(total_commits as i32)
                .bind(total_secrets as i32)
                .bind(&Utc::now().to_rfc3339())
                .bind(&Utc::now().to_rfc3339())
                .bind(scan_id)
                .execute(pool)
                .await;
            } else {
                // Mark as completed without scanning
                let _ = sqlx::query(
                    "UPDATE git_recon_scans SET status = 'completed', completed_at = ?1, updated_at = ?2 WHERE id = ?3",
                )
                .bind(&Utc::now().to_rfc3339())
                .bind(&Utc::now().to_rfc3339())
                .bind(scan_id)
                .execute(pool)
                .await;
            }

            log::info!("Git recon enumeration {} completed: {} repos found", scan_id, repos_stored);
        }
        Err(e) => {
            let _ = update_scan_failed(pool, scan_id, &e.to_string()).await;
            log::error!("Git recon enumeration {} failed: {}", scan_id, e);
        }
    }
}

/// List git recon scan results
#[utoipa::path(
    get,
    path = "/api/recon/git/results",
    tag = "Git Recon",
    params(
        ("platform" = Option<String>, Query, description = "Filter by platform"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination"),
    ),
    responses(
        (status = 200, description = "List of scan results", body = Vec<GitReconScanRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_results(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse> {
    let mut sql = "SELECT * FROM git_recon_scans WHERE user_id = ?".to_string();
    let mut conditions = Vec::new();

    if query.platform.is_some() {
        conditions.push("platform = ?");
    }
    if query.status.is_some() {
        conditions.push("status = ?");
    }

    for condition in &conditions {
        sql.push_str(" AND ");
        sql.push_str(condition);
    }

    sql.push_str(" ORDER BY created_at DESC");

    if let Some(limit) = query.limit {
        sql.push_str(&format!(" LIMIT {}", limit));
    }
    if let Some(offset) = query.offset {
        sql.push_str(&format!(" OFFSET {}", offset));
    }

    // Build query dynamically
    let mut db_query = sqlx::query_as::<_, GitReconScanRecord>(&sql);
    db_query = db_query.bind(&claims.sub);

    if let Some(ref platform) = query.platform {
        db_query = db_query.bind(platform);
    }
    if let Some(ref status) = query.status {
        db_query = db_query.bind(status);
    }

    let results = db_query
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to list git recon results: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    Ok(HttpResponse::Ok().json(results))
}

/// Get a specific scan result
#[utoipa::path(
    get,
    path = "/api/recon/git/results/{id}",
    tag = "Git Recon",
    params(
        ("id" = String, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "Scan result", body = GitReconScanRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_result(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query_as::<_, GitReconScanRecord>(
        "SELECT * FROM git_recon_scans WHERE id = ? AND user_id = ?",
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get git recon result: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    match result {
        Some(r) => Ok(HttpResponse::Ok().json(r)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// List secrets found in git recon scans
#[utoipa::path(
    get,
    path = "/api/recon/git/secrets",
    tag = "Git Recon",
    params(
        ("scan_id" = Option<String>, Query, description = "Filter by scan ID"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination"),
    ),
    responses(
        (status = 200, description = "List of secrets", body = Vec<GitReconSecretRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_secrets(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    query: web::Query<SecretsQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);

    // Get secrets for scans owned by this user
    let results = sqlx::query_as::<_, GitReconSecretRecord>(
        r#"
        SELECT s.* FROM git_recon_secrets s
        JOIN git_recon_scans sc ON s.scan_id = sc.id
        WHERE sc.user_id = ?
        ORDER BY s.created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(&claims.sub)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to list git recon secrets: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(results))
}

/// Query parameters for secrets listing
#[derive(Debug, Deserialize, ToSchema)]
pub struct SecretsQuery {
    pub scan_id: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Update a secret's status
#[utoipa::path(
    patch,
    path = "/api/recon/git/secrets/{id}",
    tag = "Git Recon",
    params(
        ("id" = String, Path, description = "Secret ID"),
    ),
    request_body = UpdateSecretRequest,
    responses(
        (status = 200, description = "Updated secret", body = GitReconSecretRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn update_secret(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    path: web::Path<String>,
    body: web::Json<UpdateSecretRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now();

    // Verify the secret belongs to a scan owned by this user
    let existing = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT 1 FROM git_recon_secrets s
        JOIN git_recon_scans sc ON s.scan_id = sc.id
        WHERE s.id = ? AND sc.user_id = ?
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to verify secret ownership: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if existing.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Secret not found"
        })));
    }

    // Build update query
    let mut updates = Vec::new();
    if body.status.is_some() {
        updates.push("status = ?");
    }
    if body.false_positive.is_some() {
        updates.push("false_positive = ?");
    }
    if body.notes.is_some() {
        updates.push("notes = ?");
    }

    if updates.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No updates provided"
        })));
    }

    updates.push("reviewed_by = ?");
    updates.push("reviewed_at = ?");
    updates.push("updated_at = ?");

    let sql = format!(
        "UPDATE git_recon_secrets SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);

    if let Some(ref status) = body.status {
        query = query.bind(status);
    }
    if let Some(fp) = body.false_positive {
        query = query.bind(if fp { 1 } else { 0 });
    }
    if let Some(ref notes) = body.notes {
        query = query.bind(notes);
    }

    let now_str = now.to_rfc3339();
    query = query.bind(&claims.sub);
    query = query.bind(&now_str);
    query = query.bind(&now_str);
    query = query.bind(&id);

    query.execute(pool.get_ref()).await.map_err(|e| {
        log::error!("Failed to update secret: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Fetch and return updated record
    let updated = sqlx::query_as::<_, GitReconSecretRecord>(
        "SELECT * FROM git_recon_secrets WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch updated secret: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Helper function to update scan status to failed
async fn update_scan_failed(pool: &SqlitePool, scan_id: &str, error: &str) {
    let _ = sqlx::query(
        r#"
        UPDATE git_recon_scans
        SET status = 'failed', error_message = ?, completed_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(error)
    .bind(&Utc::now().to_rfc3339())
    .bind(&Utc::now().to_rfc3339())
    .bind(scan_id)
    .execute(pool)
    .await;
}

/// Parse a repository URL to extract platform, owner, and repo name
fn parse_repo_url(url: &str) -> Option<(String, String, String)> {
    let url = url.trim();

    // GitHub patterns
    if url.contains("github.com") {
        // https://github.com/owner/repo or https://github.com/owner/repo.git
        let parts: Vec<&str> = url.split('/').collect();
        if parts.len() >= 5 {
            let owner = parts[parts.len() - 2].to_string();
            let repo = parts[parts.len() - 1].trim_end_matches(".git").to_string();
            return Some(("github".to_string(), owner, repo));
        }
    }

    // GitLab patterns
    if url.contains("gitlab.com") || url.contains("gitlab") {
        let parts: Vec<&str> = url.split('/').collect();
        if parts.len() >= 5 {
            let owner = parts[parts.len() - 2].to_string();
            let repo = parts[parts.len() - 1].trim_end_matches(".git").to_string();
            return Some(("gitlab".to_string(), owner, repo));
        }
    }

    None
}

/// Configure routes for git recon API
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/recon/git")
            .route("/scan-repo", web::post().to(scan_repo))
            .route("/enumerate", web::post().to(enumerate_repos))
            .route("/results", web::get().to(list_results))
            .route("/results/{id}", web::get().to(get_result))
            .route("/secrets", web::get().to(list_secrets))
            .route("/secrets/{id}", web::patch().to(update_secret)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_url() {
        let (platform, owner, repo) =
            parse_repo_url("https://github.com/rust-lang/rust").unwrap();
        assert_eq!(platform, "github");
        assert_eq!(owner, "rust-lang");
        assert_eq!(repo, "rust");
    }

    #[test]
    fn test_parse_github_url_with_git() {
        let (platform, owner, repo) =
            parse_repo_url("https://github.com/owner/repo.git").unwrap();
        assert_eq!(platform, "github");
        assert_eq!(owner, "owner");
        assert_eq!(repo, "repo");
    }

    #[test]
    fn test_parse_gitlab_url() {
        let (platform, owner, repo) =
            parse_repo_url("https://gitlab.com/group/project").unwrap();
        assert_eq!(platform, "gitlab");
        assert_eq!(owner, "group");
        assert_eq!(repo, "project");
    }

    #[test]
    fn test_parse_invalid_url() {
        assert!(parse_repo_url("not-a-url").is_none());
        assert!(parse_repo_url("https://example.com").is_none());
    }
}
