//! CI/CD Pipeline Security API Endpoints
//!
//! Provides endpoints for scanning CI/CD pipeline configurations for security issues.

use actix_web::{web, HttpResponse};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::models::{
    AnalyzeCiCdFileRequest, CiCdAnalysisResponse, CiCdCategoryCount, CiCdFileContent,
    CiCdFindingResponse, CiCdPipelineFindingRecord, CiCdPipelineScanRecord, CiCdPlatformCount,
    CiCdScanStats, StartCiCdScanRequest, SuppressCiCdFindingRequest, UpdateCiCdFindingRequest,
};
use crate::scanner::cicd::{
    CiCdPlatform, CiCdScanResult, GitHubActionsScanner, GitLabCIScanner, JenkinsScanner,
};
use crate::web::auth::Claims;
use crate::web::error::ApiError;

/// Configure CI/CD pipeline API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/cicd-security")
            .route("/scan", web::post().to(start_scan))
            .route("/analyze", web::post().to(analyze_file))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}/findings", web::get().to(get_scan_findings))
            .route("/findings/{id}", web::get().to(get_finding))
            .route("/findings/{id}", web::put().to(update_finding))
            .route("/findings/{id}/suppress", web::post().to(suppress_finding))
            .route("/stats", web::get().to(get_stats))
            .route("/rules", web::get().to(list_rules)),
    );
}

/// Start a new CI/CD pipeline security scan
#[utoipa::path(
    post,
    path = "/api/cicd-security/scan",
    request_body = StartCiCdScanRequest,
    responses(
        (status = 201, description = "Scan started", body = CiCdPipelineScanRecord),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn start_scan(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<StartCiCdScanRequest>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Validate scan type
    let scan_type = body.scan_type.to_lowercase();
    if !["github_actions", "gitlab_ci", "jenkins", "auto"].contains(&scan_type.as_str()) {
        return Err(ApiError::bad_request(
            "Invalid scan type. Must be: github_actions, gitlab_ci, jenkins, or auto",
        ));
    }

    // Create scan record
    sqlx::query(
        r#"
        INSERT INTO cicd_pipeline_scans (
            id, user_id, scan_type, repository_url, branch, status, created_at, updated_at, customer_id, engagement_id
        ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
        "#,
    )
    .bind(&scan_id)
    .bind(&claims.sub)
    .bind(&scan_type)
    .bind(&body.repository_url)
    .bind(&body.branch)
    .bind(now)
    .bind(now)
    .bind(&body.customer_id)
    .bind(&body.engagement_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create scan: {}", e)))?;

    // If files are provided, scan them directly
    if let Some(files) = &body.files {
        let pool_clone = pool.clone();
        let scan_id_clone = scan_id.clone();
        let files_clone = files.clone();
        let scan_type_clone = scan_type.clone();

        tokio::spawn(async move {
            run_file_scan(&pool_clone, &scan_id_clone, &scan_type_clone, &files_clone).await;
        });
    }

    // Fetch the created scan
    let scan: CiCdPipelineScanRecord =
        sqlx::query_as("SELECT * FROM cicd_pipeline_scans WHERE id = ?")
            .bind(&scan_id)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch scan: {}", e)))?;

    Ok(HttpResponse::Created().json(scan))
}

/// Run the actual file scan in the background
async fn run_file_scan(
    pool: &SqlitePool,
    scan_id: &str,
    scan_type: &str,
    files: &[CiCdFileContent],
) {
    let started_at = Utc::now();

    // Update status to running
    let _ = sqlx::query(
        "UPDATE cicd_pipeline_scans SET status = 'running', started_at = ? WHERE id = ?",
    )
    .bind(started_at)
    .bind(scan_id)
    .execute(pool)
    .await;

    let mut total_result = CiCdScanResult::new(CiCdPlatform::GitHubActions);
    let mut files_scanned = 0;

    for file in files {
        files_scanned += 1;

        // Determine platform to use
        let platform = if scan_type == "auto" {
            detect_platform(&file.path)
        } else {
            scan_type.to_string()
        };

        let result = match platform.as_str() {
            "github_actions" => {
                let scanner = GitHubActionsScanner::new();
                scanner.scan_content(&file.content, &file.path)
            }
            "gitlab_ci" => {
                let scanner = GitLabCIScanner::new();
                scanner.scan_content(&file.content, &file.path)
            }
            "jenkins" => {
                let scanner = JenkinsScanner::new();
                scanner.scan_content(&file.content, &file.path)
            }
            _ => continue,
        };

        // Merge results
        for finding in result.findings {
            total_result.add_finding(finding);
        }
        total_result.files_scanned.extend(result.files_scanned);
        total_result.errors.extend(result.errors);
    }

    // Store findings
    for finding in &total_result.findings {
        let finding_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let metadata_json = if finding.metadata.is_empty() {
            None
        } else {
            serde_json::to_string(&finding.metadata).ok()
        };

        let _ = sqlx::query(
            r#"
            INSERT INTO cicd_pipeline_findings (
                id, scan_id, rule_id, platform, severity, category, title, description,
                workflow_file, job_name, step_name, line_number, column_number, code_snippet,
                remediation, cwe_id, metadata, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&finding_id)
        .bind(scan_id)
        .bind(&finding.rule_id)
        .bind(finding.platform.to_string())
        .bind(finding.severity.to_string())
        .bind(finding.category.to_string())
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.file_path)
        .bind(&finding.job_name)
        .bind(&finding.step_name)
        .bind(finding.line_number.map(|n| n as i32))
        .bind(finding.column.map(|n| n as i32))
        .bind(&finding.code_snippet)
        .bind(&finding.remediation)
        .bind(&finding.cwe_id)
        .bind(&metadata_json)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await;
    }

    let completed_at = Utc::now();
    let duration_ms = (completed_at - started_at).num_milliseconds();

    // Update scan with results
    let _ = sqlx::query(
        r#"
        UPDATE cicd_pipeline_scans SET
            status = 'completed',
            finding_count = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            info_count = ?,
            files_scanned = ?,
            duration_ms = ?,
            completed_at = ?,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(total_result.total_findings() as i32)
    .bind(total_result.critical_count as i32)
    .bind(total_result.high_count as i32)
    .bind(total_result.medium_count as i32)
    .bind(total_result.low_count as i32)
    .bind(total_result.info_count as i32)
    .bind(files_scanned as i32)
    .bind(duration_ms)
    .bind(completed_at)
    .bind(completed_at)
    .bind(scan_id)
    .execute(pool)
    .await;
}

/// Detect platform from file path
fn detect_platform(path: &str) -> String {
    if path.contains(".github/workflows") || path.ends_with(".yml") && path.contains("github") {
        "github_actions".to_string()
    } else if path.contains(".gitlab-ci") || path == ".gitlab-ci.yml" {
        "gitlab_ci".to_string()
    } else if path.to_lowercase().contains("jenkinsfile") {
        "jenkins".to_string()
    } else if path.ends_with(".yml") || path.ends_with(".yaml") {
        // Default to GitHub Actions for generic YAML
        "github_actions".to_string()
    } else {
        "jenkins".to_string()
    }
}

/// Analyze a single CI/CD file immediately (no database storage)
#[utoipa::path(
    post,
    path = "/api/cicd-security/analyze",
    request_body = AnalyzeCiCdFileRequest,
    responses(
        (status = 200, description = "Analysis complete", body = CiCdAnalysisResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn analyze_file(
    _claims: web::ReqData<Claims>,
    body: web::Json<AnalyzeCiCdFileRequest>,
) -> Result<HttpResponse, ApiError> {
    let platform = body.platform.to_lowercase();
    let file_path = body.file_path.as_deref().unwrap_or("unknown");

    let result = match platform.as_str() {
        "github_actions" => {
            let scanner = GitHubActionsScanner::new();
            scanner.scan_content(&body.content, file_path)
        }
        "gitlab_ci" => {
            let scanner = GitLabCIScanner::new();
            scanner.scan_content(&body.content, file_path)
        }
        "jenkins" => {
            let scanner = JenkinsScanner::new();
            scanner.scan_content(&body.content, file_path)
        }
        _ => {
            return Err(ApiError::bad_request(
                "Invalid platform. Must be: github_actions, gitlab_ci, or jenkins",
            ));
        }
    };

    let findings: Vec<CiCdFindingResponse> = result
        .findings
        .into_iter()
        .map(|f| CiCdFindingResponse {
            rule_id: f.rule_id,
            platform: f.platform.to_string(),
            severity: f.severity.to_string(),
            category: f.category.to_string(),
            title: f.title,
            description: f.description,
            file_path: f.file_path,
            line_number: f.line_number,
            job_name: f.job_name,
            step_name: f.step_name,
            code_snippet: f.code_snippet,
            remediation: f.remediation,
            cwe_id: f.cwe_id,
        })
        .collect();

    let response = CiCdAnalysisResponse {
        platform: platform.clone(),
        findings,
        critical_count: result.critical_count,
        high_count: result.high_count,
        medium_count: result.medium_count,
        low_count: result.low_count,
        info_count: result.info_count,
        duration_ms: result.duration_ms,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// List all CI/CD pipeline scans for the current user
#[utoipa::path(
    get,
    path = "/api/cicd-security/scans",
    responses(
        (status = 200, description = "List of scans", body = Vec<CiCdPipelineScanRecord>),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn list_scans(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let scans: Vec<CiCdPipelineScanRecord> = sqlx::query_as(
        "SELECT * FROM cicd_pipeline_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch scans: {}", e)))?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Get a specific scan by ID
#[utoipa::path(
    get,
    path = "/api/cicd-security/scans/{id}",
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan details", body = CiCdPipelineScanRecord),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn get_scan(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    let scan: CiCdPipelineScanRecord =
        sqlx::query_as("SELECT * FROM cicd_pipeline_scans WHERE id = ? AND user_id = ?")
            .bind(&scan_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch scan: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    Ok(HttpResponse::Ok().json(scan))
}

/// Get findings for a specific scan
#[utoipa::path(
    get,
    path = "/api/cicd-security/scans/{id}/findings",
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Scan findings", body = Vec<CiCdPipelineFindingRecord>),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn get_scan_findings(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify scan belongs to user
    let _: CiCdPipelineScanRecord =
        sqlx::query_as("SELECT * FROM cicd_pipeline_scans WHERE id = ? AND user_id = ?")
            .bind(&scan_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch scan: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    let findings: Vec<CiCdPipelineFindingRecord> = sqlx::query_as(
        "SELECT * FROM cicd_pipeline_findings WHERE scan_id = ? ORDER BY
         CASE severity
             WHEN 'critical' THEN 1
             WHEN 'high' THEN 2
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 4
             ELSE 5
         END, created_at DESC",
    )
    .bind(&scan_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch findings: {}", e)))?;

    Ok(HttpResponse::Ok().json(findings))
}

/// Get a specific finding by ID
#[utoipa::path(
    get,
    path = "/api/cicd-security/findings/{id}",
    params(
        ("id" = String, Path, description = "Finding ID")
    ),
    responses(
        (status = 200, description = "Finding details", body = CiCdPipelineFindingRecord),
        (status = 404, description = "Finding not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn get_finding(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let finding_id = path.into_inner();

    let finding: CiCdPipelineFindingRecord =
        sqlx::query_as("SELECT * FROM cicd_pipeline_findings WHERE id = ?")
            .bind(&finding_id)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch finding: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Finding not found"))?;

    Ok(HttpResponse::Ok().json(finding))
}

/// Update a finding (status, false positive)
#[utoipa::path(
    put,
    path = "/api/cicd-security/findings/{id}",
    params(
        ("id" = String, Path, description = "Finding ID")
    ),
    request_body = UpdateCiCdFindingRequest,
    responses(
        (status = 200, description = "Finding updated", body = CiCdPipelineFindingRecord),
        (status = 404, description = "Finding not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn update_finding(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateCiCdFindingRequest>,
) -> Result<HttpResponse, ApiError> {
    let finding_id = path.into_inner();
    let now = Utc::now();

    // Build update query dynamically
    let mut updates = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(status) = &body.status {
        updates.push("status = ?");
        params.push(status.clone());
    }

    if let Some(fp) = body.false_positive {
        updates.push("false_positive = ?");
        params.push(if fp { "1" } else { "0" }.to_string());
    }

    if updates.is_empty() {
        return Err(ApiError::bad_request("No updates provided"));
    }

    updates.push("updated_at = ?");

    let query = format!(
        "UPDATE cicd_pipeline_findings SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for param in params {
        query_builder = query_builder.bind(param);
    }
    query_builder = query_builder.bind(now).bind(&finding_id);

    query_builder
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update finding: {}", e)))?;

    // Fetch updated finding
    let finding: CiCdPipelineFindingRecord =
        sqlx::query_as("SELECT * FROM cicd_pipeline_findings WHERE id = ?")
            .bind(&finding_id)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch finding: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Finding not found"))?;

    Ok(HttpResponse::Ok().json(finding))
}

/// Suppress a finding
#[utoipa::path(
    post,
    path = "/api/cicd-security/findings/{id}/suppress",
    params(
        ("id" = String, Path, description = "Finding ID")
    ),
    request_body = SuppressCiCdFindingRequest,
    responses(
        (status = 200, description = "Finding suppressed", body = CiCdPipelineFindingRecord),
        (status = 404, description = "Finding not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn suppress_finding(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<SuppressCiCdFindingRequest>,
) -> Result<HttpResponse, ApiError> {
    let finding_id = path.into_inner();
    let now = Utc::now();

    sqlx::query(
        "UPDATE cicd_pipeline_findings SET suppressed = 1, suppressed_by = ?, suppressed_at = ?, suppression_reason = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&claims.sub)
    .bind(now)
    .bind(&body.reason)
    .bind(now)
    .bind(&finding_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to suppress finding: {}", e)))?;

    let finding: CiCdPipelineFindingRecord =
        sqlx::query_as("SELECT * FROM cicd_pipeline_findings WHERE id = ?")
            .bind(&finding_id)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch finding: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Finding not found"))?;

    Ok(HttpResponse::Ok().json(finding))
}

/// Get CI/CD scan statistics
#[utoipa::path(
    get,
    path = "/api/cicd-security/stats",
    responses(
        (status = 200, description = "Scan statistics", body = CiCdScanStats),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn get_stats(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    // Get total scans
    let total_scans: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM cicd_pipeline_scans WHERE user_id = ?")
            .bind(&claims.sub)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to get stats: {}", e)))?;

    // Get finding counts by severity
    let severity_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT f.severity, COUNT(*) as count
        FROM cicd_pipeline_findings f
        JOIN cicd_pipeline_scans s ON f.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY f.severity
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let mut critical = 0i64;
    let mut high = 0i64;
    let mut medium = 0i64;
    let mut low = 0i64;
    let mut info = 0i64;

    for (severity, count) in &severity_counts {
        match severity.as_str() {
            "critical" => critical = *count,
            "high" => high = *count,
            "medium" => medium = *count,
            "low" => low = *count,
            "info" => info = *count,
            _ => {}
        }
    }

    let total_findings = critical + high + medium + low + info;

    // Get open/resolved counts
    let status_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT f.status, COUNT(*) as count
        FROM cicd_pipeline_findings f
        JOIN cicd_pipeline_scans s ON f.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY f.status
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let mut open = 0i64;
    let mut resolved = 0i64;

    for (status, count) in &status_counts {
        match status.as_str() {
            "open" => open = *count,
            "resolved" | "fixed" => resolved += *count,
            _ => {}
        }
    }

    // Get false positive count
    let fp_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM cicd_pipeline_findings f
        JOIN cicd_pipeline_scans s ON f.scan_id = s.id
        WHERE s.user_id = ? AND f.false_positive = 1
        "#,
    )
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Get counts by platform
    let platform_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT f.platform, COUNT(*) as count
        FROM cicd_pipeline_findings f
        JOIN cicd_pipeline_scans s ON f.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY f.platform
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Get counts by category
    let category_counts: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT f.category, COUNT(*) as count
        FROM cicd_pipeline_findings f
        JOIN cicd_pipeline_scans s ON f.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY f.category
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let stats = CiCdScanStats {
        total_scans: total_scans.0,
        total_findings,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        info_count: info,
        open_findings: open,
        resolved_findings: resolved,
        false_positives: fp_count.0,
        by_platform: platform_counts
            .into_iter()
            .map(|(p, c)| CiCdPlatformCount {
                platform: p,
                count: c,
            })
            .collect(),
        by_category: category_counts
            .into_iter()
            .map(|(cat, c)| CiCdCategoryCount {
                category: cat,
                count: c,
            })
            .collect(),
    };

    Ok(HttpResponse::Ok().json(stats))
}

/// List all available CI/CD security rules
#[utoipa::path(
    get,
    path = "/api/cicd-security/rules",
    responses(
        (status = 200, description = "List of rules"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Pipeline Security"
)]
async fn list_rules(_claims: web::ReqData<Claims>) -> Result<HttpResponse, ApiError> {
    use crate::scanner::cicd::rules;

    let all_rules = rules::get_all_rules();
    let summary = rules::get_rules_summary();

    #[derive(serde::Serialize)]
    struct RulesResponse {
        total: usize,
        by_platform: std::collections::HashMap<String, usize>,
        by_category: std::collections::HashMap<String, usize>,
        by_severity: std::collections::HashMap<String, usize>,
        rules: Vec<crate::scanner::cicd::CiCdRule>,
    }

    let response = RulesResponse {
        total: summary.total,
        by_platform: summary.by_platform,
        by_category: summary.by_category,
        by_severity: summary.by_severity,
        rules: all_rules,
    };

    Ok(HttpResponse::Ok().json(response))
}
