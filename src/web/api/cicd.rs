// CI/CD API Endpoints
//
// Provides endpoints for CI/CD integration:
// - Token management
// - Scan triggering from pipelines
// - Report formats (SARIF, JUnit, GitLab)
// - Quality gate configuration

use actix_web::{web, HttpRequest, HttpResponse, Result};
use sqlx::SqlitePool;
use log::{info, error};

use crate::db::{self, cicd as cicd_db};
use crate::integrations::cicd::{self, types::*, gitlab};
use crate::web::auth::Claims;
use crate::scanner;
use crate::types::{ScanConfig, ScanType, HostInfo};

// ============================================================================
// Token Management Endpoints
// ============================================================================

/// Create a new CI/CD token
/// POST /api/cicd/tokens
pub async fn create_token(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    request: web::Json<CreateCiCdTokenRequest>,
) -> Result<HttpResponse> {
    let response = cicd_db::create_cicd_token(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            error!("Failed to create CI/CD token: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create CI/CD token")
        })?;

    info!("Created CI/CD token for user {}: {}", claims.sub, response.name);

    Ok(HttpResponse::Created().json(response))
}

/// Get all CI/CD tokens for the current user
/// GET /api/cicd/tokens
pub async fn get_tokens(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let tokens = cicd_db::get_user_cicd_tokens(&pool, &claims.sub)
        .await
        .map_err(|e| {
            error!("Failed to fetch CI/CD tokens: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch CI/CD tokens")
        })?;

    Ok(HttpResponse::Ok().json(tokens))
}

/// Delete (revoke) a CI/CD token
/// DELETE /api/cicd/tokens/{id}
pub async fn delete_token(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    token_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = cicd_db::delete_cicd_token(&pool, &token_id, &claims.sub)
        .await
        .map_err(|e| {
            error!("Failed to delete CI/CD token: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete CI/CD token")
        })?;

    if !deleted {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Token not found"
        })));
    }

    info!("Deleted CI/CD token {} for user {}", token_id.as_str(), claims.sub);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Token revoked successfully"
    })))
}

// ============================================================================
// Scan Endpoints (for CI/CD pipelines)
// ============================================================================

/// Trigger a scan from CI/CD pipeline
/// POST /api/cicd/scan
pub async fn trigger_scan(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    request: web::Json<CiCdScanRequest>,
) -> Result<HttpResponse> {
    // Extract and validate CI/CD token
    let (token_info, user_id) = validate_cicd_auth(&pool, &req).await?;

    // Check token permissions
    let permissions: CiCdTokenPermissions = serde_json::from_str(&token_info.permissions)
        .unwrap_or_default();
    if !permissions.can_scan {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Token does not have scan permission"
        })));
    }

    // Create the scan
    let scan_name = if request.name.is_empty() {
        format!("CI/CD Scan {}", chrono::Utc::now().format("%Y-%m-%d %H:%M"))
    } else {
        request.name.clone()
    };

    // Create scan in database
    let scan = db::scans::create_scan(
        &pool,
        &user_id,
        &scan_name,
        &request.targets,
        None, // customer_id
        None, // engagement_id
    )
    .await
    .map_err(|e| {
        error!("Failed to create scan: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create scan")
    })?;

    // Create CI/CD run record
    let cicd_run = cicd_db::create_cicd_run(
        &pool,
        &token_info.id,
        &scan.id,
        &token_info.platform,
        request.ci_ref.as_deref(),
        request.ci_branch.as_deref(),
        request.ci_url.as_deref(),
        request.repository.as_deref(),
    )
    .await
    .map_err(|e| {
        error!("Failed to create CI/CD run: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create CI/CD run")
    })?;

    // Start the scan in background
    let pool_clone = pool.get_ref().clone();
    let run_id = cicd_run.id.clone();
    let scan_id_clone = scan.id.clone();
    let user_id_clone = user_id.clone();
    let quality_gate_id = request.quality_gate_id.clone();

    tokio::spawn(async move {
        run_cicd_scan(pool_clone, run_id, scan_id_clone, user_id_clone, quality_gate_id).await;
    });

    info!("Started CI/CD scan {} for user {} (run {})", scan.id, user_id, cicd_run.id);

    Ok(HttpResponse::Created().json(serde_json::json!({
        "run_id": cicd_run.id,
        "scan_id": scan.id,
        "status": "pending"
    })))
}

/// Get scan status for CI/CD pipeline polling
/// GET /api/cicd/scan/{run_id}/status
pub async fn get_scan_status(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    run_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Validate CI/CD auth
    let (token_info, _user_id) = validate_cicd_auth(&pool, &req).await?;

    // Check permissions
    let permissions: CiCdTokenPermissions = serde_json::from_str(&token_info.permissions)
        .unwrap_or_default();
    if !permissions.can_read_results {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Token does not have read permission"
        })));
    }

    // Get the CI/CD run
    let run = cicd_db::get_cicd_run(&pool, &run_id)
        .await
        .map_err(|e| {
            error!("Failed to fetch CI/CD run: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch run status")
        })?;

    let run = match run {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Run not found"
            })));
        }
    };

    // Get scan progress if still running
    let (progress, exit_code) = if run.status == "completed" || run.status == "failed" {
        let exit_code = if run.quality_gate_passed.unwrap_or(false) { 0 } else { 1 };
        (100.0, exit_code)
    } else {
        // Get scan from database to check progress
        let scan = db::scans::get_scan_by_id(&pool, &run.scan_id).await.ok().flatten();
        let progress = match scan.as_ref().map(|s| s.status.as_str()) {
            Some("completed") => 100.0,
            Some("running") => 50.0, // Approximate
            Some("failed") => 100.0,
            _ => 0.0,
        };
        (progress, 0)
    };

    // Parse quality gate result if available
    let quality_gate_result: Option<QualityGateResult> = run.quality_gate_details
        .as_ref()
        .and_then(|d| serde_json::from_str(d).ok());

    Ok(HttpResponse::Ok().json(CiCdScanStatus {
        run_id: run.id,
        scan_id: run.scan_id,
        status: run.status,
        progress,
        quality_gate_passed: run.quality_gate_passed.map(|v| v),
        quality_gate_result,
        started_at: run.started_at,
        completed_at: run.completed_at,
        exit_code,
    }))
}

/// Get SARIF report for GitHub Security tab
/// GET /api/cicd/scan/{run_id}/sarif
pub async fn get_sarif_report(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    run_id: web::Path<String>,
) -> Result<HttpResponse> {
    let (token_info, _user_id) = validate_cicd_auth(&pool, &req).await?;

    let permissions: CiCdTokenPermissions = serde_json::from_str(&token_info.permissions)
        .unwrap_or_default();
    if !permissions.can_export {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Token does not have export permission"
        })));
    }

    // Get the run and scan results
    let run = cicd_db::get_cicd_run(&pool, &run_id)
        .await
        .map_err(|e| {
            error!("Failed to fetch CI/CD run: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch run")
        })?;

    let run = match run {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Run not found"
            })));
        }
    };

    // Get scan results
    let hosts = get_scan_hosts(&pool, &run.scan_id).await?;
    let scan = db::scans::get_scan_by_id(&pool, &run.scan_id).await.ok().flatten();
    let scan_name = scan.map(|s| s.name).unwrap_or_else(|| "CI/CD Scan".to_string());

    // Generate SARIF report
    let sarif = cicd::github_actions::generate_sarif_report(&run.scan_id, &hosts, &scan_name)
        .map_err(|e| {
            error!("Failed to generate SARIF report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to generate SARIF report")
        })?;

    Ok(HttpResponse::Ok()
        .content_type("application/sarif+json")
        .json(sarif))
}

/// Get JUnit XML report for Jenkins/CI
/// GET /api/cicd/scan/{run_id}/junit
pub async fn get_junit_report(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    run_id: web::Path<String>,
) -> Result<HttpResponse> {
    let (token_info, _user_id) = validate_cicd_auth(&pool, &req).await?;

    let permissions: CiCdTokenPermissions = serde_json::from_str(&token_info.permissions)
        .unwrap_or_default();
    if !permissions.can_export {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Token does not have export permission"
        })));
    }

    let run = cicd_db::get_cicd_run(&pool, &run_id)
        .await
        .map_err(|e| {
            error!("Failed to fetch CI/CD run: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch run")
        })?;

    let run = match run {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Run not found"
            })));
        }
    };

    let hosts = get_scan_hosts(&pool, &run.scan_id).await?;
    let scan = db::scans::get_scan_by_id(&pool, &run.scan_id).await.ok().flatten();
    let scan_name = scan.map(|s| s.name).unwrap_or_else(|| "CI/CD Scan".to_string());

    // Get quality gate result
    let qg_result: Option<QualityGateResult> = run.quality_gate_details
        .as_ref()
        .and_then(|d| serde_json::from_str(d).ok());

    let junit = cicd::jenkins::generate_junit_report(&run.scan_id, &hosts, &scan_name, qg_result.as_ref())
        .map_err(|e| {
            error!("Failed to generate JUnit report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to generate JUnit report")
        })?;

    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(junit))
}

/// Get GitLab Security report
/// GET /api/cicd/scan/{run_id}/gitlab-security
pub async fn get_gitlab_security_report(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    run_id: web::Path<String>,
) -> Result<HttpResponse> {
    let (token_info, _user_id) = validate_cicd_auth(&pool, &req).await?;

    let permissions: CiCdTokenPermissions = serde_json::from_str(&token_info.permissions)
        .unwrap_or_default();
    if !permissions.can_export {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Token does not have export permission"
        })));
    }

    let run = cicd_db::get_cicd_run(&pool, &run_id)
        .await
        .map_err(|e| {
            error!("Failed to fetch CI/CD run: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch run")
        })?;

    let run = match run {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Run not found"
            })));
        }
    };

    let hosts = get_scan_hosts(&pool, &run.scan_id).await?;
    let scan = db::scans::get_scan_by_id(&pool, &run.scan_id).await.ok().flatten();
    let scan_name = scan.map(|s| s.name).unwrap_or_else(|| "CI/CD Scan".to_string());

    let start_time = run.started_at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let end_time = run.completed_at
        .unwrap_or_else(chrono::Utc::now)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let report = gitlab::generate_security_report(&run.scan_id, &hosts, &scan_name, &start_time, &end_time)
        .map_err(|e| {
            error!("Failed to generate GitLab security report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to generate report")
        })?;

    Ok(HttpResponse::Ok().json(report))
}

/// Get GitLab Code Quality report
/// GET /api/cicd/scan/{run_id}/gitlab-quality
pub async fn get_gitlab_quality_report(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    run_id: web::Path<String>,
) -> Result<HttpResponse> {
    let (token_info, _user_id) = validate_cicd_auth(&pool, &req).await?;

    let permissions: CiCdTokenPermissions = serde_json::from_str(&token_info.permissions)
        .unwrap_or_default();
    if !permissions.can_export {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Token does not have export permission"
        })));
    }

    let run = cicd_db::get_cicd_run(&pool, &run_id)
        .await
        .map_err(|e| {
            error!("Failed to fetch CI/CD run: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch run")
        })?;

    let run = match run {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Run not found"
            })));
        }
    };

    let hosts = get_scan_hosts(&pool, &run.scan_id).await?;

    let issues = gitlab::generate_code_quality_report(&run.scan_id, &hosts)
        .map_err(|e| {
            error!("Failed to generate GitLab code quality report: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to generate report")
        })?;

    Ok(HttpResponse::Ok().json(issues))
}

// ============================================================================
// Quality Gate Endpoints
// ============================================================================

/// Create a new quality gate
/// POST /api/cicd/quality-gates
pub async fn create_quality_gate(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    request: web::Json<QualityGateRequest>,
) -> Result<HttpResponse> {
    let gate = cicd_db::create_quality_gate(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            error!("Failed to create quality gate: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create quality gate")
        })?;

    info!("Created quality gate {} for user {}", gate.id, claims.sub);

    Ok(HttpResponse::Created().json(gate))
}

/// Get all quality gates for the current user
/// GET /api/cicd/quality-gates
pub async fn get_quality_gates(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let gates = cicd_db::get_user_quality_gates(&pool, &claims.sub)
        .await
        .map_err(|e| {
            error!("Failed to fetch quality gates: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch quality gates")
        })?;

    Ok(HttpResponse::Ok().json(gates))
}

/// Update a quality gate
/// PUT /api/cicd/quality-gates/{id}
pub async fn update_quality_gate(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    gate_id: web::Path<String>,
    request: web::Json<QualityGateRequest>,
) -> Result<HttpResponse> {
    let gate = cicd_db::update_quality_gate(&pool, &gate_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            error!("Failed to update quality gate: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update quality gate")
        })?;

    match gate {
        Some(g) => Ok(HttpResponse::Ok().json(g)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Quality gate not found"
        }))),
    }
}

/// Delete a quality gate
/// DELETE /api/cicd/quality-gates/{id}
pub async fn delete_quality_gate(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    gate_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = cicd_db::delete_quality_gate(&pool, &gate_id, &claims.sub)
        .await
        .map_err(|e| {
            error!("Failed to delete quality gate: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete quality gate")
        })?;

    if !deleted {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Quality gate not found or cannot be deleted"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Quality gate deleted"
    })))
}

/// Get pipeline configuration examples
/// GET /api/cicd/examples/{platform}
pub async fn get_pipeline_example(
    req: HttpRequest,
    platform: web::Path<String>,
) -> Result<HttpResponse> {
    let platform_enum = match platform.as_str() {
        "github" | "github_actions" => CiCdPlatform::GitHubActions,
        "jenkins" => CiCdPlatform::Jenkins,
        "gitlab" | "gitlab_ci" => CiCdPlatform::GitLabCi,
        _ => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid platform. Use: github, jenkins, or gitlab"
            })));
        }
    };

    // Get the API URL from the request
    let conn_info = req.connection_info();
    let api_url = format!("{}://{}", conn_info.scheme(), conn_info.host());

    let example = cicd::generate_pipeline_example(&platform_enum, &api_url);

    // Determine content type based on platform
    let content_type = match platform_enum {
        CiCdPlatform::GitHubActions | CiCdPlatform::GitLabCi => "text/yaml",
        CiCdPlatform::Jenkins | CiCdPlatform::Generic => "text/plain",
    };

    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .body(example))
}

/// Get recent CI/CD runs for the current user
/// GET /api/cicd/runs
pub async fn get_runs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> Result<HttpResponse> {
    let limit = query.get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(20);

    let runs = cicd_db::get_user_cicd_runs(&pool, &claims.sub, limit)
        .await
        .map_err(|e| {
            error!("Failed to fetch CI/CD runs: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch runs")
        })?;

    Ok(HttpResponse::Ok().json(runs))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate CI/CD token from Authorization header
async fn validate_cicd_auth(
    pool: &SqlitePool,
    req: &HttpRequest,
) -> Result<(CiCdToken, String)> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing Authorization header"))?;

    let token = if auth_header.starts_with("Bearer ") {
        &auth_header[7..]
    } else {
        auth_header
    };

    let result = cicd_db::validate_cicd_token(pool, token)
        .await
        .map_err(|e| {
            error!("Failed to validate CI/CD token: {}", e);
            actix_web::error::ErrorInternalServerError("Token validation failed")
        })?;

    result.ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid or expired CI/CD token"))
}

/// Get scan hosts from results
async fn get_scan_hosts(pool: &SqlitePool, scan_id: &str) -> Result<Vec<HostInfo>> {
    let scan = db::scans::get_scan_by_id(pool, scan_id)
        .await
        .map_err(|e| {
            error!("Failed to fetch scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scan")
        })?;

    let scan = match scan {
        Some(s) => s,
        None => return Ok(vec![]),
    };

    // Parse results JSON
    let hosts: Vec<HostInfo> = scan.results
        .as_ref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or_default();

    Ok(hosts)
}

/// Run a CI/CD scan in the background
async fn run_cicd_scan(
    pool: SqlitePool,
    run_id: String,
    scan_id: String,
    user_id: String,
    quality_gate_id: Option<String>,
) {
    // Update run status to running
    if let Err(e) = cicd_db::update_cicd_run_status(&pool, &run_id, "running").await {
        error!("Failed to update run status: {}", e);
        return;
    }

    // Update scan status
    if let Err(e) = db::scans::update_scan_status(&pool, &scan_id, "running", None, None).await {
        error!("Failed to update scan status: {}", e);
    }

    // Get scan configuration
    let scan = match db::scans::get_scan_by_id(&pool, &scan_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            error!("Scan not found: {}", scan_id);
            let _ = cicd_db::fail_cicd_run(&pool, &run_id, Some("Scan not found")).await;
            return;
        }
        Err(e) => {
            error!("Failed to fetch scan: {}", e);
            let _ = cicd_db::fail_cicd_run(&pool, &run_id, Some(&e.to_string())).await;
            return;
        }
    };

    // Parse targets
    let targets: Vec<String> = serde_json::from_str(&scan.targets).unwrap_or_default();

    // Build scan config
    let config = ScanConfig {
        targets,
        port_range: (1, 1000), // Default for CI/CD
        threads: 100,
        timeout: std::time::Duration::from_secs(3),
        scan_type: ScanType::TCPConnect,
        enable_os_detection: true,
        enable_service_detection: true,
        enable_vuln_scan: true,
        enable_enumeration: false,
        ..Default::default()
    };

    // Run the scan
    let results = match scanner::run_scan(&config, None).await {
        Ok(r) => r,
        Err(e) => {
            error!("Scan failed: {}", e);
            let _ = db::scans::update_scan_status(&pool, &scan_id, "failed", None, Some(&e.to_string())).await;
            let _ = cicd_db::fail_cicd_run(&pool, &run_id, Some(&e.to_string())).await;
            return;
        }
    };

    // Save results and mark scan as completed
    let results_json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
    if let Err(e) = db::scans::update_scan_status(&pool, &scan_id, "completed", Some(&results_json), None).await {
        error!("Failed to save scan results: {}", e);
    }

    // Evaluate quality gate
    let quality_gate = match quality_gate_id {
        Some(id) => cicd_db::get_quality_gate(&pool, &id).await.ok().flatten(),
        None => cicd_db::get_default_quality_gate(&pool, &user_id).await.ok().flatten(),
    };

    let qg_result = if let Some(gate) = quality_gate {
        let result = cicd::evaluate_quality_gate(&results, &gate, None);
        Some(result)
    } else {
        // No quality gate configured, just check for critical vulnerabilities
        let counts = cicd::count_vulnerabilities(&results);
        let passed = counts.critical == 0;
        Some(QualityGateResult {
            passed,
            gate_name: "Default (no critical)".to_string(),
            fail_reason: if passed { None } else { Some("Critical vulnerabilities found".to_string()) },
            vulnerability_counts: counts,
            threshold_violations: vec![],
            new_vulnerabilities: None,
        })
    };

    // Complete the run
    let qg_passed = qg_result.as_ref().map(|r| r.passed).unwrap_or(true);
    let qg_details = qg_result.as_ref().and_then(|r| serde_json::to_string(r).ok());

    if let Err(e) = cicd_db::complete_cicd_run(&pool, &run_id, qg_passed, qg_details.as_deref()).await {
        error!("Failed to complete CI/CD run: {}", e);
    }

    info!("CI/CD scan completed: run={}, scan={}, passed={}", run_id, scan_id, qg_passed);
}

/// Configure CI/CD routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/cicd")
            // Token management (requires JWT auth)
            .route("/tokens", web::post().to(create_token))
            .route("/tokens", web::get().to(get_tokens))
            .route("/tokens/{id}", web::delete().to(delete_token))
            // Quality gates (requires JWT auth)
            .route("/quality-gates", web::post().to(create_quality_gate))
            .route("/quality-gates", web::get().to(get_quality_gates))
            .route("/quality-gates/{id}", web::put().to(update_quality_gate))
            .route("/quality-gates/{id}", web::delete().to(delete_quality_gate))
            // Runs (requires JWT auth)
            .route("/runs", web::get().to(get_runs))
            // Pipeline examples (public)
            .route("/examples/{platform}", web::get().to(get_pipeline_example))
    );

    // CI/CD scan endpoints (use CI/CD token auth, not JWT)
    // These need to be outside the JWT middleware scope
    cfg.service(
        web::scope("/cicd/scan")
            .route("", web::post().to(trigger_scan))
            .route("/{run_id}/status", web::get().to(get_scan_status))
            .route("/{run_id}/sarif", web::get().to(get_sarif_report))
            .route("/{run_id}/junit", web::get().to(get_junit_report))
            .route("/{run_id}/gitlab-security", web::get().to(get_gitlab_security_report))
            .route("/{run_id}/gitlab-quality", web::get().to(get_gitlab_quality_report))
    );
}
