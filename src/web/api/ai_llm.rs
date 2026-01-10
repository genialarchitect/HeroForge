//! AI LLM Orchestrator API Endpoints
//!
//! Provides REST endpoints for LLM-powered features:
//! - Automated report generation
//! - Intelligent scan planning
//! - Exploit code analysis
//! - Security policy generation

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::ai::llm_orchestrator::{LLMOrchestrator, PolicyType};
use crate::web::auth;
use crate::web::error::{ApiError, ApiErrorKind};

/// Configure AI LLM routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ai/llm")
            .route("/reports/executive/{scan_id}", web::post().to(generate_executive_report))
            .route("/reports/technical/{scan_id}", web::post().to(generate_technical_report))
            .route("/scan-plan", web::post().to(plan_scan))
            .route("/analyze-exploit", web::post().to(analyze_exploit))
            .route("/policy/generate", web::post().to(generate_policy))
            .route("/remediation-guidance", web::post().to(get_remediation_guidance)),
    );
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GenerateReportRequest {
    pub scan_id: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ScanPlanRequest {
    pub targets: Vec<String>,
    pub objectives: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AnalyzeExploitRequest {
    pub code: String,
    pub context: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GeneratePolicyRequest {
    pub policy_type: String,
    pub organization: String,
    pub compliance_frameworks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RemediationGuidanceRequest {
    pub vulnerability: String,
    pub context: String,
}

/// POST /api/ai/llm/reports/executive/{scan_id}
///
/// Generate an AI-powered executive summary report for a scan.
#[utoipa::path(
    post,
    path = "/api/ai/llm/reports/executive/{scan_id}",
    tag = "AI LLM",
    params(
        ("scan_id" = String, Path, description = "Scan ID to generate report for"),
    ),
    responses(
        (status = 200, description = "Executive report generated successfully"),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn generate_executive_report(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = crate::db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Scan not found".to_string()))?;

    let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;
    if scan.user_id != *user_id && !is_admin {
        return Err(ApiError::new(
            ApiErrorKind::Forbidden(String::new()),
            "You don't have permission to access this scan".to_string(),
        ));
    }

    // Get scan results
    let scan_results: Vec<crate::types::HostInfo> = match &scan.results {
        Some(r) => serde_json::from_str(r).map_err(|e| {
            ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Failed to parse scan results: {}", e))
        })?,
        None => {
            return Err(ApiError::new(
                ApiErrorKind::BadRequest(String::new()),
                "Scan has no results yet".to_string(),
            ))
        }
    };

    // Get API key from environment
    let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
        ApiError::new(
            ApiErrorKind::InternalError(String::new()),
            "ANTHROPIC_API_KEY not configured".to_string(),
        )
    })?;

    // Generate report
    let orchestrator = LLMOrchestrator::new(api_key);
    let report = orchestrator
        .generate_executive_report(&scan_results)
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Failed to generate report: {}", e)))?;

    // Store report in database
    let report_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO ai_reports (id, scan_id, report_type, title, summary, content, key_findings, recommendations, risk_score, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&report_id)
    .bind(&scan_id)
    .bind("executive")
    .bind("Executive Summary Report")
    .bind(&report.summary)
    .bind(&report.summary)
    .bind(serde_json::to_string(&report.key_findings).unwrap_or_default())
    .bind(serde_json::to_string(&report.recommendations).unwrap_or_default())
    .bind(report.risk_score as i32)
    .bind(user_id)
    .bind(chrono::Utc::now())
    .execute(pool.get_ref())
    .await?;

    // Log action
    crate::db::log_audit(
        &pool,
        user_id,
        "ai_report_generate",
        Some("scan"),
        Some(&scan_id),
        Some("Generated executive summary report"),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(report))
}

/// POST /api/ai/llm/reports/technical/{scan_id}
///
/// Generate an AI-powered technical report for a scan.
#[utoipa::path(
    post,
    path = "/api/ai/llm/reports/technical/{scan_id}",
    tag = "AI LLM",
    params(
        ("scan_id" = String, Path, description = "Scan ID to generate report for"),
    ),
    responses(
        (status = 200, description = "Technical report generated successfully"),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn generate_technical_report(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let scan_id = path.into_inner();

    // Similar access checks as executive report
    let scan = crate::db::get_scan_by_id(&pool, &scan_id)
        .await?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Scan not found".to_string()))?;

    let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;
    if scan.user_id != *user_id && !is_admin {
        return Err(ApiError::new(
            ApiErrorKind::Forbidden(String::new()),
            "You don't have permission to access this scan".to_string(),
        ));
    }

    let scan_results: Vec<crate::types::HostInfo> = serde_json::from_str(scan.results.as_ref().unwrap())?;

    let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
        ApiError::new(
            ApiErrorKind::InternalError(String::new()),
            "ANTHROPIC_API_KEY not configured".to_string(),
        )
    })?;
    let orchestrator = LLMOrchestrator::new(api_key);

    let report = orchestrator.generate_technical_report(&scan_results).await.map_err(|e| {
        ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Failed to generate report: {}", e))
    })?;

    // Store report
    let report_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO ai_reports (id, scan_id, report_type, title, summary, content, key_findings, recommendations, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&report_id)
    .bind(&scan_id)
    .bind("technical")
    .bind("Technical Security Report")
    .bind(&report.technical_summary)
    .bind(&report.technical_summary)
    .bind(serde_json::to_string(&report.vulnerability_breakdown).unwrap_or_default())
    .bind(serde_json::to_string(&report.remediation_roadmap).unwrap_or_default())
    .bind(user_id)
    .bind(chrono::Utc::now())
    .execute(pool.get_ref())
    .await?;

    crate::db::log_audit(&pool, user_id, "ai_report_generate", Some("scan"), Some(&scan_id), Some("Generated technical report"), None).await?;

    Ok(HttpResponse::Ok().json(report))
}

/// POST /api/ai/llm/scan-plan
///
/// Generate an intelligent scan plan based on targets and objectives.
#[utoipa::path(
    post,
    path = "/api/ai/llm/scan-plan",
    tag = "AI LLM",
    request_body = ScanPlanRequest,
    responses(
        (status = 200, description = "Scan plan generated successfully"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn plan_scan(
    pool: web::Data<SqlitePool>,
    body: web::Json<ScanPlanRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
        ApiError::new(
            ApiErrorKind::InternalError(String::new()),
            "ANTHROPIC_API_KEY not configured".to_string(),
        )
    })?;
    let orchestrator = LLMOrchestrator::new(api_key);

    let plan = orchestrator
        .plan_scan(&body.targets, &body.objectives)
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Failed to generate scan plan: {}", e)))?;

    crate::db::log_audit(&pool, user_id, "ai_scan_plan", None, None, Some("Generated intelligent scan plan"), None).await?;

    Ok(HttpResponse::Ok().json(plan))
}

/// POST /api/ai/llm/analyze-exploit
///
/// Analyze exploit code and provide security insights.
#[utoipa::path(
    post,
    path = "/api/ai/llm/analyze-exploit",
    tag = "AI LLM",
    request_body = AnalyzeExploitRequest,
    responses(
        (status = 200, description = "Exploit analyzed successfully"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn analyze_exploit(
    pool: web::Data<SqlitePool>,
    body: web::Json<AnalyzeExploitRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
        ApiError::new(
            ApiErrorKind::InternalError(String::new()),
            "ANTHROPIC_API_KEY not configured".to_string(),
        )
    })?;
    let orchestrator = LLMOrchestrator::new(api_key);

    let analysis = orchestrator
        .analyze_exploit(&body.code, body.context.as_deref())
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Failed to analyze exploit: {}", e)))?;

    crate::db::log_audit(&pool, user_id, "ai_exploit_analysis", None, None, Some("Analyzed exploit code"), None).await?;

    Ok(HttpResponse::Ok().json(analysis))
}

/// POST /api/ai/llm/policy/generate
///
/// Generate a security policy using AI.
#[utoipa::path(
    post,
    path = "/api/ai/llm/policy/generate",
    tag = "AI LLM",
    request_body = GeneratePolicyRequest,
    responses(
        (status = 200, description = "Policy generated successfully"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn generate_policy(
    pool: web::Data<SqlitePool>,
    body: web::Json<GeneratePolicyRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let policy_type = match body.policy_type.as_str() {
        "AccessControl" => PolicyType::AccessControl,
        "DataProtection" => PolicyType::DataProtection,
        "IncidentResponse" => PolicyType::IncidentResponse,
        "ChangeManagement" => PolicyType::ChangeManagement,
        "AssetManagement" => PolicyType::AssetManagement,
        "VulnerabilityManagement" => PolicyType::VulnerabilityManagement,
        "NetworkSecurity" => PolicyType::NetworkSecurity,
        "CloudSecurity" => PolicyType::CloudSecurity,
        _ => {
            return Err(ApiError::new(
                ApiErrorKind::BadRequest(String::new()),
                "Invalid policy type".to_string(),
            ))
        }
    };

    let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
        ApiError::new(
            ApiErrorKind::InternalError(String::new()),
            "ANTHROPIC_API_KEY not configured".to_string(),
        )
    })?;
    let orchestrator = LLMOrchestrator::new(api_key);

    let policy = orchestrator
        .generate_security_policy(policy_type, &body.organization, &body.compliance_frameworks)
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Failed to generate policy: {}", e)))?;

    crate::db::log_audit(&pool, user_id, "ai_policy_generate", None, None, Some(&format!("Generated {} policy", body.policy_type)), None).await?;

    Ok(HttpResponse::Ok().json(policy))
}

/// POST /api/ai/llm/remediation-guidance
///
/// Get AI-powered remediation guidance for a vulnerability.
#[utoipa::path(
    post,
    path = "/api/ai/llm/remediation-guidance",
    tag = "AI LLM",
    request_body = RemediationGuidanceRequest,
    responses(
        (status = 200, description = "Guidance generated successfully"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_remediation_guidance(
    pool: web::Data<SqlitePool>,
    body: web::Json<RemediationGuidanceRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| {
        ApiError::new(
            ApiErrorKind::InternalError(String::new()),
            "ANTHROPIC_API_KEY not configured".to_string(),
        )
    })?;
    let orchestrator = LLMOrchestrator::new(api_key);

    let guidance = orchestrator
        .generate_remediation_guidance(&body.vulnerability, &body.context)
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Failed to generate guidance: {}", e)))?;

    crate::db::log_audit(&pool, user_id, "ai_remediation_guidance", None, None, Some("Generated remediation guidance"), None).await?;

    Ok(HttpResponse::Ok().json(guidance))
}
