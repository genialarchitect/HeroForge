//! IDE Integration API Endpoints
//!
//! Provides endpoints for IDE integration including real-time file scanning,
//! session management, and settings configuration.

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::devsecops::ide::{
    ApplyQuickFixRequest, DismissFindingRequest, EndSessionRequest, IdeFinding, IdeQuickFix,
    IdeScanner, IdeSession, IdeSettings, IdeStats, IdeTypeCount, ScanFileRequest,
    ScanFilesRequest, SeverityCount, StartSessionRequest, UpdateSettingsRequest,
};
use crate::web::auth::Claims;
use crate::web::error::ApiError;

/// Configure IDE integration API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ide")
            // Scanning
            .route("/scan", web::post().to(scan_file))
            .route("/scan/batch", web::post().to(scan_files))
            // Findings
            .route("/findings", web::get().to(get_findings))
            .route("/findings/{id}", web::get().to(get_finding))
            .route("/findings/{id}/dismiss", web::post().to(dismiss_finding))
            .route("/findings/{id}/quick-fix", web::post().to(apply_quick_fix))
            // Sessions
            .route("/session/start", web::post().to(start_session))
            .route("/session/end", web::post().to(end_session))
            .route("/sessions", web::get().to(list_sessions))
            .route("/sessions/{id}", web::get().to(get_session))
            // Settings
            .route("/settings", web::get().to(get_settings))
            .route("/settings", web::put().to(update_settings))
            // Stats
            .route("/stats", web::get().to(get_stats)),
    );
}

// ============================================================================
// Scanning Endpoints
// ============================================================================

/// Scan a single file for security issues
#[utoipa::path(
    post,
    path = "/api/ide/scan",
    request_body = ScanFileRequest,
    responses(
        (status = 200, description = "Scan results"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn scan_file(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<ScanFileRequest>,
) -> Result<HttpResponse, ApiError> {
    // Get user settings
    let settings: Option<IdeSettings> =
        sqlx::query_as("SELECT * FROM ide_settings WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch settings: {}", e)))?;

    // Create scanner with user settings or defaults
    let scanner = if let Some(settings) = settings {
        let severity_filter: Vec<String> = settings
            .severity_filter
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| {
                vec![
                    "critical".to_string(),
                    "high".to_string(),
                    "medium".to_string(),
                ]
            });
        IdeScanner::new(
            settings.max_file_size_kb,
            settings.scan_timeout_seconds,
            severity_filter,
        )
    } else {
        IdeScanner::default()
    };

    // Perform scan
    let response = scanner.scan_file(&body.file_path, &body.content, body.language.as_deref());

    // Store findings if session is provided
    if let Some(ref session_id) = body.session_id {
        let now = Utc::now().to_rfc3339();

        for finding in &response.findings {
            let _ = sqlx::query(
                r#"
                INSERT INTO ide_findings (
                    id, session_id, user_id, file_path, rule_id, severity, category,
                    title, description, line_start, line_end, column_start, column_end,
                    code_snippet, fix_suggestion, fix_code, cwe_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&finding.id)
            .bind(session_id)
            .bind(&claims.sub)
            .bind(&body.file_path)
            .bind(&finding.rule_id)
            .bind(&finding.severity)
            .bind(&finding.category)
            .bind(&finding.title)
            .bind(&finding.description)
            .bind(finding.line_start)
            .bind(finding.line_end)
            .bind(finding.column_start)
            .bind(finding.column_end)
            .bind(&finding.code_snippet)
            .bind(&finding.fix_suggestion)
            .bind(&finding.fix_code)
            .bind(&finding.cwe_id)
            .bind(&now)
            .execute(pool.get_ref())
            .await;
        }

        // Update session stats
        let _ = sqlx::query(
            "UPDATE ide_sessions SET files_scanned = files_scanned + 1, findings_shown = findings_shown + ?, last_activity = ? WHERE id = ?",
        )
        .bind(response.findings.len() as i32)
        .bind(&now)
        .bind(session_id)
        .execute(pool.get_ref())
        .await;
    }

    Ok(HttpResponse::Ok().json(response))
}

/// Scan multiple files in batch
#[utoipa::path(
    post,
    path = "/api/ide/scan/batch",
    request_body = ScanFilesRequest,
    responses(
        (status = 200, description = "Batch scan results"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn scan_files(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<ScanFilesRequest>,
) -> Result<HttpResponse, ApiError> {
    // Get user settings
    let settings: Option<IdeSettings> =
        sqlx::query_as("SELECT * FROM ide_settings WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch settings: {}", e)))?;

    let scanner = if let Some(settings) = settings {
        let severity_filter: Vec<String> = settings
            .severity_filter
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| {
                vec![
                    "critical".to_string(),
                    "high".to_string(),
                    "medium".to_string(),
                ]
            });
        IdeScanner::new(
            settings.max_file_size_kb,
            settings.scan_timeout_seconds,
            severity_filter,
        )
    } else {
        IdeScanner::default()
    };

    // Scan all files
    let mut results = Vec::new();
    for file in &body.files {
        let response = scanner.scan_file(&file.path, &file.content, file.language.as_deref());
        results.push(response);
    }

    Ok(HttpResponse::Ok().json(results))
}

// ============================================================================
// Finding Endpoints
// ============================================================================

/// Get findings for a file or session
#[utoipa::path(
    get,
    path = "/api/ide/findings",
    params(
        ("session_id" = Option<String>, Query, description = "Filter by session"),
        ("file_path" = Option<String>, Query, description = "Filter by file"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
    ),
    responses(
        (status = 200, description = "List of findings", body = Vec<IdeFinding>),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn get_findings(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<FindingsQuery>,
) -> Result<HttpResponse, ApiError> {
    let mut sql = String::from("SELECT * FROM ide_findings WHERE user_id = ?");
    let mut params: Vec<String> = vec![claims.sub.clone()];

    if let Some(ref session_id) = query.session_id {
        sql.push_str(" AND session_id = ?");
        params.push(session_id.clone());
    }
    if let Some(ref file_path) = query.file_path {
        sql.push_str(" AND file_path = ?");
        params.push(file_path.clone());
    }
    if let Some(ref severity) = query.severity {
        sql.push_str(" AND severity = ?");
        params.push(severity.clone());
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT 500");

    let mut query_builder = sqlx::query_as::<_, IdeFinding>(&sql);
    for param in &params {
        query_builder = query_builder.bind(param);
    }

    let findings = query_builder
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch findings: {}", e)))?;

    Ok(HttpResponse::Ok().json(findings))
}

#[derive(Debug, serde::Deserialize)]
struct FindingsQuery {
    session_id: Option<String>,
    file_path: Option<String>,
    severity: Option<String>,
}

/// Get a specific finding
async fn get_finding(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let finding_id = path.into_inner();

    let finding: IdeFinding =
        sqlx::query_as("SELECT * FROM ide_findings WHERE id = ? AND user_id = ?")
            .bind(&finding_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch finding: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Finding not found"))?;

    Ok(HttpResponse::Ok().json(finding))
}

/// Dismiss a finding
#[utoipa::path(
    post,
    path = "/api/ide/findings/{id}/dismiss",
    params(
        ("id" = String, Path, description = "Finding ID")
    ),
    request_body = DismissFindingRequest,
    responses(
        (status = 200, description = "Finding dismissed"),
        (status = 404, description = "Finding not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn dismiss_finding(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<DismissFindingRequest>,
) -> Result<HttpResponse, ApiError> {
    let finding_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE ide_findings SET is_dismissed = 1, dismissed_reason = ?, dismissed_at = ? WHERE id = ? AND user_id = ?",
    )
    .bind(&body.reason)
    .bind(&now)
    .bind(&finding_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to dismiss finding: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Finding not found"));
    }

    let finding: IdeFinding = sqlx::query_as("SELECT * FROM ide_findings WHERE id = ?")
        .bind(&finding_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch finding: {}", e)))?;

    Ok(HttpResponse::Ok().json(finding))
}

/// Apply a quick fix to a finding
#[utoipa::path(
    post,
    path = "/api/ide/findings/{id}/quick-fix",
    params(
        ("id" = String, Path, description = "Finding ID")
    ),
    request_body = ApplyQuickFixRequest,
    responses(
        (status = 200, description = "Quick fix applied"),
        (status = 404, description = "Finding not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn apply_quick_fix(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<ApplyQuickFixRequest>,
) -> Result<HttpResponse, ApiError> {
    let finding_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Verify finding exists
    let finding: IdeFinding =
        sqlx::query_as("SELECT * FROM ide_findings WHERE id = ? AND user_id = ?")
            .bind(&finding_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch finding: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Finding not found"))?;

    // Create quick fix record
    let fix_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO ide_quick_fixes (
            id, finding_id, user_id, fix_type, original_code, fixed_code, applied_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&fix_id)
    .bind(&finding_id)
    .bind(&claims.sub)
    .bind(&body.fix_type)
    .bind(&finding.code_snippet)
    .bind(&finding.fix_code)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create quick fix: {}", e)))?;

    // Update session stats
    if let Some(ref session_id) = Some(&finding.session_id) {
        let _ = sqlx::query(
            "UPDATE ide_sessions SET findings_fixed = findings_fixed + 1, last_activity = ? WHERE id = ?",
        )
        .bind(&now)
        .bind(session_id)
        .execute(pool.get_ref())
        .await;
    }

    let quick_fix: IdeQuickFix = sqlx::query_as("SELECT * FROM ide_quick_fixes WHERE id = ?")
        .bind(&fix_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch quick fix: {}", e)))?;

    Ok(HttpResponse::Ok().json(quick_fix))
}

// ============================================================================
// Session Endpoints
// ============================================================================

/// Start a new IDE session
#[utoipa::path(
    post,
    path = "/api/ide/session/start",
    request_body = StartSessionRequest,
    responses(
        (status = 201, description = "Session started", body = IdeSession),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn start_session(
    req: HttpRequest,
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<StartSessionRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Get client IP
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());

    sqlx::query(
        r#"
        INSERT INTO ide_sessions (
            id, user_id, ide_type, ide_version, project_path, project_name,
            workspace_id, session_start, last_activity, client_ip, client_info, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.ide_type)
    .bind(&body.ide_version)
    .bind(&body.project_path)
    .bind(&body.project_name)
    .bind(&body.workspace_id)
    .bind(&now)
    .bind(&now)
    .bind(&client_ip)
    .bind(&body.client_info)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create session: {}", e)))?;

    let session: IdeSession = sqlx::query_as("SELECT * FROM ide_sessions WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch session: {}", e)))?;

    Ok(HttpResponse::Created().json(session))
}

/// End an IDE session
#[utoipa::path(
    post,
    path = "/api/ide/session/end",
    request_body = EndSessionRequest,
    responses(
        (status = 200, description = "Session ended", body = IdeSession),
        (status = 404, description = "Session not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn end_session(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<EndSessionRequest>,
) -> Result<HttpResponse, ApiError> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE ide_sessions SET session_end = ?, last_activity = ? WHERE id = ? AND user_id = ?",
    )
    .bind(&now)
    .bind(&now)
    .bind(&body.session_id)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to end session: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Session not found"));
    }

    let session: IdeSession = sqlx::query_as("SELECT * FROM ide_sessions WHERE id = ?")
        .bind(&body.session_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch session: {}", e)))?;

    Ok(HttpResponse::Ok().json(session))
}

/// List sessions
async fn list_sessions(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let sessions: Vec<IdeSession> = sqlx::query_as(
        "SELECT * FROM ide_sessions WHERE user_id = ? ORDER BY session_start DESC LIMIT 100",
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch sessions: {}", e)))?;

    Ok(HttpResponse::Ok().json(sessions))
}

/// Get a specific session
async fn get_session(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let session_id = path.into_inner();

    let session: IdeSession =
        sqlx::query_as("SELECT * FROM ide_sessions WHERE id = ? AND user_id = ?")
            .bind(&session_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch session: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

    Ok(HttpResponse::Ok().json(session))
}

// ============================================================================
// Settings Endpoints
// ============================================================================

/// Get IDE settings for current user
#[utoipa::path(
    get,
    path = "/api/ide/settings",
    responses(
        (status = 200, description = "IDE settings", body = IdeSettings),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn get_settings(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let settings: Option<IdeSettings> =
        sqlx::query_as("SELECT * FROM ide_settings WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch settings: {}", e)))?;

    match settings {
        Some(s) => Ok(HttpResponse::Ok().json(s)),
        None => {
            // Return default settings
            let defaults = UpdateSettingsRequest::default();
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "scan_on_save": defaults.scan_on_save,
                "scan_on_open": defaults.scan_on_open,
                "show_inline_hints": defaults.show_inline_hints,
                "severity_filter": defaults.severity_filter,
                "excluded_paths": defaults.excluded_paths,
                "custom_rules_enabled": defaults.custom_rules_enabled,
                "scan_timeout_seconds": defaults.scan_timeout_seconds,
                "max_file_size_kb": defaults.max_file_size_kb,
                "enable_quick_fixes": defaults.enable_quick_fixes,
                "enable_code_actions": defaults.enable_code_actions,
                "theme": defaults.theme,
            })))
        }
    }
}

/// Update IDE settings
#[utoipa::path(
    put,
    path = "/api/ide/settings",
    request_body = UpdateSettingsRequest,
    responses(
        (status = 200, description = "Settings updated", body = IdeSettings),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn update_settings(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<UpdateSettingsRequest>,
) -> Result<HttpResponse, ApiError> {
    let now = Utc::now().to_rfc3339();

    // Check if settings exist
    let existing: Option<IdeSettings> =
        sqlx::query_as("SELECT * FROM ide_settings WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch settings: {}", e)))?;

    let severity_filter = body
        .severity_filter
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    let excluded_paths = body
        .excluded_paths
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    if existing.is_some() {
        // Update existing
        sqlx::query(
            r#"
            UPDATE ide_settings SET
                scan_on_save = COALESCE(?, scan_on_save),
                scan_on_open = COALESCE(?, scan_on_open),
                show_inline_hints = COALESCE(?, show_inline_hints),
                severity_filter = COALESCE(?, severity_filter),
                excluded_paths = COALESCE(?, excluded_paths),
                custom_rules_enabled = COALESCE(?, custom_rules_enabled),
                scan_timeout_seconds = COALESCE(?, scan_timeout_seconds),
                max_file_size_kb = COALESCE(?, max_file_size_kb),
                enable_quick_fixes = COALESCE(?, enable_quick_fixes),
                enable_code_actions = COALESCE(?, enable_code_actions),
                theme = COALESCE(?, theme),
                updated_at = ?
            WHERE user_id = ?
            "#,
        )
        .bind(body.scan_on_save)
        .bind(body.scan_on_open)
        .bind(body.show_inline_hints)
        .bind(&severity_filter)
        .bind(&excluded_paths)
        .bind(body.custom_rules_enabled)
        .bind(body.scan_timeout_seconds)
        .bind(body.max_file_size_kb)
        .bind(body.enable_quick_fixes)
        .bind(body.enable_code_actions)
        .bind(&body.theme)
        .bind(&now)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update settings: {}", e)))?;
    } else {
        // Create new
        let id = Uuid::new_v4().to_string();
        let defaults = UpdateSettingsRequest::default();

        sqlx::query(
            r#"
            INSERT INTO ide_settings (
                id, user_id, scan_on_save, scan_on_open, show_inline_hints,
                severity_filter, excluded_paths, custom_rules_enabled,
                scan_timeout_seconds, max_file_size_kb, enable_quick_fixes,
                enable_code_actions, theme, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&claims.sub)
        .bind(body.scan_on_save.or(defaults.scan_on_save))
        .bind(body.scan_on_open.or(defaults.scan_on_open))
        .bind(body.show_inline_hints.or(defaults.show_inline_hints))
        .bind(severity_filter.or_else(|| {
            defaults
                .severity_filter
                .map(|v| serde_json::to_string(&v).unwrap_or_default())
        }))
        .bind(excluded_paths.or_else(|| {
            defaults
                .excluded_paths
                .map(|v| serde_json::to_string(&v).unwrap_or_default())
        }))
        .bind(body.custom_rules_enabled.or(defaults.custom_rules_enabled))
        .bind(body.scan_timeout_seconds.or(defaults.scan_timeout_seconds))
        .bind(body.max_file_size_kb.or(defaults.max_file_size_kb))
        .bind(body.enable_quick_fixes.or(defaults.enable_quick_fixes))
        .bind(body.enable_code_actions.or(defaults.enable_code_actions))
        .bind(body.theme.as_ref().or(defaults.theme.as_ref()))
        .bind(&now)
        .bind(&now)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to create settings: {}", e)))?;
    }

    let settings: IdeSettings = sqlx::query_as("SELECT * FROM ide_settings WHERE user_id = ?")
        .bind(&claims.sub)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch settings: {}", e)))?;

    Ok(HttpResponse::Ok().json(settings))
}

// ============================================================================
// Stats Endpoint
// ============================================================================

/// Get IDE usage statistics
#[utoipa::path(
    get,
    path = "/api/ide/stats",
    responses(
        (status = 200, description = "IDE statistics", body = IdeStats),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "IDE Integration"
)]
async fn get_stats(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    // Total sessions
    let total_sessions: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM ide_sessions WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_one(pool.get_ref())
            .await
            .unwrap_or((0,));

    // Active sessions (no end time)
    let active_sessions: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ide_sessions WHERE user_id = ? AND session_end IS NULL",
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Total files scanned
    let total_files: (i64,) =
        sqlx::query_as("SELECT COALESCE(SUM(files_scanned), 0) FROM ide_sessions WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_one(pool.get_ref())
            .await
            .unwrap_or((0,));

    // Total findings
    let total_findings: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM ide_findings WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_one(pool.get_ref())
            .await
            .unwrap_or((0,));

    // Total fixed
    let total_fixed: (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(findings_fixed), 0) FROM ide_sessions WHERE user_id = ?",
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // By IDE type
    let by_ide_type: Vec<(String, i64)> = sqlx::query_as(
        "SELECT ide_type, COUNT(*) FROM ide_sessions WHERE user_id = ? GROUP BY ide_type",
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // By severity
    let by_severity: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*) FROM ide_findings WHERE user_id = ? GROUP BY severity",
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let stats = IdeStats {
        total_sessions: total_sessions.0,
        active_sessions: active_sessions.0,
        total_files_scanned: total_files.0,
        total_findings: total_findings.0,
        total_fixed: total_fixed.0,
        by_ide_type: by_ide_type
            .into_iter()
            .map(|(ide_type, count)| IdeTypeCount { ide_type, count })
            .collect(),
        by_severity: by_severity
            .into_iter()
            .map(|(severity, count)| SeverityCount { severity, count })
            .collect(),
    };

    Ok(HttpResponse::Ok().json(stats))
}
