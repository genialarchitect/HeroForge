//! Active Directory Assessment API Endpoints
//!
//! Provides REST API endpoints for AD security assessments.
//!
//! **WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.**

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::db::ad_assessment::{self, CreateAdAssessmentRequest};
use crate::scanner::ad_assessment::{run_ad_assessment, AdAssessmentConfig, AdAuthMode};
use crate::web::auth::Claims;
use crate::web::error::{internal_error, not_found, ApiErrorKind};

/// Request to create and run an AD assessment
#[derive(Debug, Deserialize, ToSchema)]
pub struct RunAdAssessmentRequest {
    /// Assessment name
    pub name: String,
    /// Domain controller hostname or IP
    pub domain_controller: String,
    /// LDAP port (default: 389, use 636 for LDAPS)
    #[serde(default = "default_port")]
    pub port: i32,
    /// Use LDAPS (SSL/TLS)
    #[serde(default)]
    pub use_ldaps: bool,
    /// Base DN (if not provided, will be discovered)
    pub base_dn: Option<String>,
    /// Authentication username
    pub username: String,
    /// Authentication password
    pub password: String,
    /// Authentication domain (NTLM)
    pub domain: Option<String>,
    /// Customer ID (optional)
    pub customer_id: Option<String>,
    /// Engagement ID (optional)
    pub engagement_id: Option<String>,
}

fn default_port() -> i32 {
    389
}

/// Response for AD assessment list
#[derive(Debug, Serialize, ToSchema)]
pub struct AdAssessmentListResponse {
    pub assessments: Vec<ad_assessment::AdAssessmentSummary>,
}

/// Response for AD assessment detail
#[derive(Debug, Serialize, ToSchema)]
pub struct AdAssessmentResponse {
    pub assessment: ad_assessment::AdAssessmentRecord,
    pub findings: Vec<ad_assessment::AdFindingRecord>,
}

/// Create and run an AD assessment
///
/// POST /api/ad-assessment
#[utoipa::path(
    post,
    path = "/api/ad-assessment",
    tag = "AD Assessment",
    request_body = RunAdAssessmentRequest,
    responses(
        (status = 201, description = "Assessment started"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Assessment failed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_assessment(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<RunAdAssessmentRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    // Create the assessment record
    let create_req = CreateAdAssessmentRequest {
        name: body.name.clone(),
        domain_controller: body.domain_controller.clone(),
        port: Some(body.port),
        use_ldaps: Some(body.use_ldaps),
        customer_id: body.customer_id.clone(),
        engagement_id: body.engagement_id.clone(),
    };

    let assessment = ad_assessment::create_ad_assessment(&pool, &claims.sub, &create_req)
        .await
        .map_err(|e| internal_error(format!("Failed to create assessment: {}", e)))?;

    // Build the config for the scanner
    let config = AdAssessmentConfig {
        domain_controller: body.domain_controller.clone(),
        port: body.port as u16,
        use_ldaps: body.use_ldaps,
        base_dn: body.base_dn.clone(),
        auth_mode: AdAuthMode::Simple {
            username: body.username.clone(),
            password: body.password.clone(),
            domain: body.domain.clone(),
        },
        scan_options: Default::default(),
    };

    // Update status to running
    ad_assessment::update_ad_assessment_status(&pool, &assessment.id, "running")
        .await
        .map_err(|e| internal_error(format!("Failed to update status: {}", e)))?;

    // Spawn the assessment in background
    let pool_clone = pool.get_ref().clone();
    let assessment_id = assessment.id.clone();

    tokio::spawn(async move {
        match run_ad_assessment(&config).await {
            Ok(results) => {
                // Store findings
                for finding in &results.findings {
                    let _ = ad_assessment::create_ad_finding(
                        &pool_clone,
                        &assessment_id,
                        &finding.title,
                        Some(&finding.description),
                        &finding.severity.to_string(),
                        &finding.category.to_string(),
                        Some(&serde_json::to_string(&finding.mitre_attack_ids).unwrap_or_default()),
                        Some(&serde_json::to_string(&finding.affected_objects).unwrap_or_default()),
                        finding.affected_count as i32,
                        Some(&finding.remediation),
                        finding.risk_score as i32,
                        Some(&serde_json::to_string(&finding.evidence).unwrap_or_default()),
                        Some(&serde_json::to_string(&finding.references).unwrap_or_default()),
                    )
                    .await;
                }

                // Update assessment with results
                let _ = ad_assessment::update_ad_assessment_results(
                    &pool_clone,
                    &assessment_id,
                    results.domain_info.as_ref().map(|d| d.domain_name.as_str()),
                    results.domain_info.as_ref().and_then(|d| d.netbios_name.as_deref()),
                    results.domain_info.as_ref().and_then(|d| d.forest_name.as_deref()),
                    results.domain_info.as_ref().and_then(|d| d.domain_level.as_deref()),
                    results.domain_info.as_ref().and_then(|d| d.forest_level.as_deref()),
                    results.domain_info.as_ref().map(|d| d.base_dn.as_str()),
                    results.summary.total_users as i32,
                    results.summary.total_groups as i32,
                    results.summary.total_computers as i32,
                    results.summary.kerberoastable_accounts as i32,
                    results.summary.asrep_roastable_accounts as i32,
                    results.summary.unconstrained_delegation_accounts as i32,
                    results.summary.critical_findings as i32,
                    results.summary.high_findings as i32,
                    results.summary.medium_findings as i32,
                    results.summary.low_findings as i32,
                    results.summary.overall_risk_score as i32,
                    &serde_json::to_string(&results).unwrap_or_default(),
                )
                .await;
            }
            Err(e) => {
                let _ = ad_assessment::update_ad_assessment_error(&pool_clone, &assessment_id, &e.to_string()).await;
            }
        }
    });

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": assessment.id,
        "status": "running",
        "message": "AD assessment started"
    })))
}

/// List AD assessments
///
/// GET /api/ad-assessment
#[utoipa::path(
    get,
    path = "/api/ad-assessment",
    tag = "AD Assessment",
    params(
        ("status" = Option<String>, Query, description = "Filter by status")
    ),
    responses(
        (status = 200, description = "List of assessments", body = AdAssessmentListResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_assessments(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> Result<HttpResponse, ApiErrorKind> {
    let status = query.get("status").map(|s| s.as_str());

    let assessments = ad_assessment::get_user_ad_assessments(&pool, &claims.sub, status)
        .await
        .map_err(|e| internal_error(format!("Failed to list assessments: {}", e)))?;

    Ok(HttpResponse::Ok().json(AdAssessmentListResponse { assessments }))
}

/// Get AD assessment detail
///
/// GET /api/ad-assessment/{id}
#[utoipa::path(
    get,
    path = "/api/ad-assessment/{id}",
    tag = "AD Assessment",
    responses(
        (status = 200, description = "Assessment details", body = AdAssessmentResponse),
        (status = 404, description = "Assessment not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_assessment(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let id = path.into_inner();

    let assessment = ad_assessment::get_ad_assessment_by_id(&pool, &id, &claims.sub)
        .await
        .map_err(|_| not_found("Assessment not found"))?;

    let findings = ad_assessment::get_ad_findings(&pool, &id)
        .await
        .map_err(|e| internal_error(format!("Failed to get findings: {}", e)))?;

    Ok(HttpResponse::Ok().json(AdAssessmentResponse { assessment, findings }))
}

/// Delete AD assessment
///
/// DELETE /api/ad-assessment/{id}
#[utoipa::path(
    delete,
    path = "/api/ad-assessment/{id}",
    tag = "AD Assessment",
    responses(
        (status = 204, description = "Assessment deleted"),
        (status = 404, description = "Assessment not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_assessment(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let id = path.into_inner();

    let deleted = ad_assessment::delete_ad_assessment(&pool, &id, &claims.sub)
        .await
        .map_err(|e| internal_error(format!("Failed to delete assessment: {}", e)))?;

    if deleted {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(not_found("Assessment not found"))
    }
}

/// Configure routes for AD Assessment
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ad-assessment")
            .route("", web::post().to(create_assessment))
            .route("", web::get().to(list_assessments))
            .route("/{id}", web::get().to(get_assessment))
            .route("/{id}", web::delete().to(delete_assessment)),
    );
}
