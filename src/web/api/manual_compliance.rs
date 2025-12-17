//! Manual Compliance Assessment API endpoints
//!
//! Provides REST API endpoints for manual compliance assessments, including:
//! - Rubric management (create, read, update, delete)
//! - Assessment management with workflow (draft, submit, approve, reject)
//! - Evidence file upload and management
//! - Assessment campaigns for coordinating multiple assessments
//! - Combined results merging automated and manual assessments

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::compliance::manual_assessment::{
    AssessmentCampaign, AssessmentCriterion, AssessmentEvidence, CampaignProgress,
    CampaignStatus, ComplianceRubric, CriterionResponse, EvidenceRequirement,
    EvidenceType, ManualAssessment, OverallRating, RatingScale, ReviewStatus,
};
use crate::compliance::types::ComplianceFramework;
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Query parameters for listing rubrics
#[derive(Debug, Deserialize)]
pub struct RubricListQuery {
    /// Filter by framework ID
    pub framework_id: Option<String>,
}

/// Request to create a new rubric
#[derive(Debug, Deserialize)]
pub struct CreateRubricRequest {
    pub framework_id: String,
    pub control_id: String,
    pub name: String,
    pub description: Option<String>,
    pub assessment_criteria: Vec<AssessmentCriterion>,
    pub rating_scale: Option<RatingScale>,
    pub evidence_requirements: Vec<EvidenceRequirement>,
}

/// Request to update a rubric
#[derive(Debug, Deserialize)]
pub struct UpdateRubricRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub assessment_criteria: Option<Vec<AssessmentCriterion>>,
    pub rating_scale: Option<RatingScale>,
    pub evidence_requirements: Option<Vec<EvidenceRequirement>>,
}

/// Query parameters for listing assessments
#[derive(Debug, Deserialize)]
pub struct AssessmentListQuery {
    /// Filter by framework ID
    pub framework_id: Option<String>,
    /// Filter by review status
    pub status: Option<String>,
}

/// Request to create a new assessment
#[derive(Debug, Deserialize)]
pub struct CreateAssessmentRequest {
    pub rubric_id: String,
    pub framework_id: String,
    pub control_id: String,
    pub assessment_period_start: DateTime<Utc>,
    pub assessment_period_end: DateTime<Utc>,
    pub overall_rating: OverallRating,
    pub rating_score: f32,
    pub criteria_responses: Vec<CriterionResponse>,
    pub evidence_summary: Option<String>,
    pub findings: Option<String>,
    pub recommendations: Option<String>,
}

/// Request to update an assessment
#[derive(Debug, Deserialize)]
pub struct UpdateAssessmentRequest {
    pub overall_rating: Option<OverallRating>,
    pub rating_score: Option<f32>,
    pub criteria_responses: Option<Vec<CriterionResponse>>,
    pub evidence_summary: Option<String>,
    pub findings: Option<String>,
    pub recommendations: Option<String>,
}

/// Request to reject an assessment
#[derive(Debug, Deserialize)]
pub struct RejectAssessmentRequest {
    pub notes: String,
}

/// Request to add evidence to an assessment
#[derive(Debug, Deserialize)]
pub struct AddEvidenceRequest {
    pub evidence_type: EvidenceType,
    pub title: String,
    pub description: Option<String>,
    pub external_url: Option<String>,
    pub content: Option<String>,
}

/// Query parameters for listing campaigns
#[derive(Debug, Deserialize)]
pub struct CampaignListQuery {
    /// Filter by status
    pub status: Option<String>,
}

/// Request to create a new campaign
#[derive(Debug, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub frameworks: Vec<String>,
    pub due_date: Option<DateTime<Utc>>,
}

/// Request to update a campaign
#[derive(Debug, Deserialize)]
pub struct UpdateCampaignRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub frameworks: Option<Vec<String>>,
    pub due_date: Option<DateTime<Utc>>,
    pub status: Option<CampaignStatus>,
}

/// Response for rubric list
#[derive(Debug, Serialize)]
pub struct RubricListResponse {
    pub rubrics: Vec<ComplianceRubric>,
    pub total: usize,
}

/// Response for assessment list
#[derive(Debug, Serialize)]
pub struct AssessmentListResponse {
    pub assessments: Vec<ManualAssessment>,
    pub total: usize,
}

/// Response for evidence list
#[derive(Debug, Serialize)]
pub struct EvidenceListResponse {
    pub evidence: Vec<AssessmentEvidence>,
    pub total: usize,
}

/// Response for campaign list
#[derive(Debug, Serialize)]
pub struct CampaignListResponse {
    pub campaigns: Vec<AssessmentCampaign>,
    pub total: usize,
}

/// Combined compliance results response
#[derive(Debug, Serialize)]
pub struct CombinedComplianceResponse {
    pub scan_id: String,
    pub automated_summary: Option<serde_json::Value>,
    pub manual_assessments: Vec<ManualAssessment>,
    pub combined_score: f32,
    pub generated_at: DateTime<Utc>,
}

// ============================================================================
// Rubric Endpoints
// ============================================================================

/// GET /api/compliance/rubrics
/// List all rubrics with optional framework filter
#[utoipa::path(
    get,
    path = "/api/compliance/rubrics",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("framework_id" = Option<String>, Query, description = "Filter by compliance framework ID")
    ),
    responses(
        (status = 200, description = "List of rubrics"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_rubrics(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<RubricListQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Query rubrics from database (system defaults + user's custom rubrics)
    let rubrics = match &query.framework_id {
        Some(framework_id) => {
            sqlx::query_as::<_, RubricRow>(
                r#"
                SELECT id, user_id, framework_id, control_id, name, description,
                       assessment_criteria, rating_scale, evidence_requirements,
                       is_system_default, created_at, updated_at
                FROM compliance_rubrics
                WHERE framework_id = ?1 AND (user_id IS NULL OR user_id = ?2)
                ORDER BY is_system_default DESC, name ASC
                "#,
            )
            .bind(framework_id)
            .bind(user_id)
            .fetch_all(pool.get_ref())
            .await
        }
        None => {
            sqlx::query_as::<_, RubricRow>(
                r#"
                SELECT id, user_id, framework_id, control_id, name, description,
                       assessment_criteria, rating_scale, evidence_requirements,
                       is_system_default, created_at, updated_at
                FROM compliance_rubrics
                WHERE user_id IS NULL OR user_id = ?1
                ORDER BY framework_id, is_system_default DESC, name ASC
                "#,
            )
            .bind(user_id)
            .fetch_all(pool.get_ref())
            .await
        }
    }
    .map_err(|e| {
        log::error!("Failed to fetch rubrics: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rubrics")
    })?;

    let rubrics: Vec<ComplianceRubric> = rubrics.into_iter().map(|r| r.into()).collect();
    let total = rubrics.len();

    Ok(HttpResponse::Ok().json(RubricListResponse { rubrics, total }))
}

/// GET /api/compliance/rubrics/{id}
/// Get a specific rubric by ID
#[utoipa::path(
    get,
    path = "/api/compliance/rubrics/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Rubric ID")
    ),
    responses(
        (status = 200, description = "Rubric details"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Rubric not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_rubric(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    rubric_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let rubric_id = rubric_id.into_inner();

    let rubric = sqlx::query_as::<_, RubricRow>(
        r#"
        SELECT id, user_id, framework_id, control_id, name, description,
               assessment_criteria, rating_scale, evidence_requirements,
               is_system_default, created_at, updated_at
        FROM compliance_rubrics
        WHERE id = ?1 AND (user_id IS NULL OR user_id = ?2)
        "#,
    )
    .bind(&rubric_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch rubric: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rubric")
    })?;

    match rubric {
        Some(r) => Ok(HttpResponse::Ok().json(ComplianceRubric::from(r))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rubric not found"
        }))),
    }
}

/// POST /api/compliance/rubrics
/// Create a new custom rubric
#[utoipa::path(
    post,
    path = "/api/compliance/rubrics",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    request_body = CreateRubricRequest,
    responses(
        (status = 201, description = "Rubric created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn create_rubric(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateRubricRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now();
    let rubric_id = Uuid::new_v4().to_string();

    // Validate framework ID
    if ComplianceFramework::from_id(&request.framework_id).is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid framework ID",
            "valid_frameworks": ["pci_dss", "nist_800_53", "nist_csf", "cis", "hipaa", "soc2", "ferpa", "owasp_top10"]
        })));
    }

    // Serialize JSON fields
    let assessment_criteria_json = serde_json::to_string(&request.assessment_criteria)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid criteria: {}", e)))?;

    let rating_scale = request.rating_scale.clone().unwrap_or_default();
    let rating_scale_json = serde_json::to_string(&rating_scale)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid rating scale: {}", e)))?;

    let evidence_requirements_json = serde_json::to_string(&request.evidence_requirements)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid evidence requirements: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO compliance_rubrics (
            id, user_id, framework_id, control_id, name, description,
            assessment_criteria, rating_scale, evidence_requirements,
            is_system_default, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&rubric_id)
    .bind(user_id)
    .bind(&request.framework_id)
    .bind(&request.control_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&assessment_criteria_json)
    .bind(&rating_scale_json)
    .bind(&evidence_requirements_json)
    .bind(false) // is_system_default
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create rubric: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create rubric")
    })?;

    let rubric = ComplianceRubric {
        id: rubric_id,
        user_id: Some(user_id.clone()),
        framework_id: request.framework_id.clone(),
        control_id: request.control_id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        assessment_criteria: request.assessment_criteria.clone(),
        rating_scale,
        evidence_requirements: request.evidence_requirements.clone(),
        is_system_default: false,
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(rubric))
}

/// PUT /api/compliance/rubrics/{id}
/// Update a rubric (only if user owns it)
#[utoipa::path(
    put,
    path = "/api/compliance/rubrics/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Rubric ID")
    ),
    request_body = UpdateRubricRequest,
    responses(
        (status = 200, description = "Rubric updated"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - cannot modify system rubrics or others' rubrics"),
        (status = 404, description = "Rubric not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn update_rubric(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    rubric_id: web::Path<String>,
    request: web::Json<UpdateRubricRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let rubric_id = rubric_id.into_inner();

    // Fetch existing rubric
    let existing = sqlx::query_as::<_, RubricRow>(
        r#"
        SELECT id, user_id, framework_id, control_id, name, description,
               assessment_criteria, rating_scale, evidence_requirements,
               is_system_default, created_at, updated_at
        FROM compliance_rubrics
        WHERE id = ?1
        "#,
    )
    .bind(&rubric_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch rubric: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rubric")
    })?;

    let existing = match existing {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Rubric not found"
            })));
        }
    };

    // Check ownership
    if existing.is_system_default {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Cannot modify system default rubrics"
        })));
    }

    if existing.user_id.as_ref() != Some(user_id) {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Cannot modify rubrics owned by other users"
        })));
    }

    let now = Utc::now();
    let mut rubric: ComplianceRubric = existing.into();

    // Apply updates
    if let Some(name) = &request.name {
        rubric.name = name.clone();
    }
    if let Some(description) = &request.description {
        rubric.description = Some(description.clone());
    }
    if let Some(criteria) = &request.assessment_criteria {
        rubric.assessment_criteria = criteria.clone();
    }
    if let Some(scale) = &request.rating_scale {
        rubric.rating_scale = scale.clone();
    }
    if let Some(requirements) = &request.evidence_requirements {
        rubric.evidence_requirements = requirements.clone();
    }
    rubric.updated_at = now;

    // Serialize JSON fields
    let assessment_criteria_json = serde_json::to_string(&rubric.assessment_criteria)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid criteria: {}", e)))?;
    let rating_scale_json = serde_json::to_string(&rubric.rating_scale)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid rating scale: {}", e)))?;
    let evidence_requirements_json = serde_json::to_string(&rubric.evidence_requirements)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid evidence requirements: {}", e)))?;

    sqlx::query(
        r#"
        UPDATE compliance_rubrics
        SET name = ?1, description = ?2, assessment_criteria = ?3,
            rating_scale = ?4, evidence_requirements = ?5, updated_at = ?6
        WHERE id = ?7
        "#,
    )
    .bind(&rubric.name)
    .bind(&rubric.description)
    .bind(&assessment_criteria_json)
    .bind(&rating_scale_json)
    .bind(&evidence_requirements_json)
    .bind(now)
    .bind(&rubric_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to update rubric: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update rubric")
    })?;

    Ok(HttpResponse::Ok().json(rubric))
}

/// DELETE /api/compliance/rubrics/{id}
/// Delete a rubric (only if user owns it)
#[utoipa::path(
    delete,
    path = "/api/compliance/rubrics/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Rubric ID")
    ),
    responses(
        (status = 200, description = "Rubric deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - cannot delete system rubrics or others' rubrics"),
        (status = 404, description = "Rubric not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_rubric(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    rubric_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let rubric_id = rubric_id.into_inner();

    // Check ownership and existence
    let existing = sqlx::query_as::<_, (Option<String>, bool)>(
        "SELECT user_id, is_system_default FROM compliance_rubrics WHERE id = ?1",
    )
    .bind(&rubric_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch rubric: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rubric")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Rubric not found"
            })));
        }
        Some((_, true)) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Cannot delete system default rubrics"
            })));
        }
        Some((Some(owner_id), _)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Cannot delete rubrics owned by other users"
            })));
        }
        _ => {}
    }

    sqlx::query("DELETE FROM compliance_rubrics WHERE id = ?1")
        .bind(&rubric_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete rubric: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete rubric")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Rubric deleted successfully"
    })))
}

/// GET /api/compliance/frameworks/{framework_id}/rubrics
/// Get all rubrics for a specific framework
#[utoipa::path(
    get,
    path = "/api/compliance/frameworks/{framework_id}/rubrics",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("framework_id" = String, Path, description = "Compliance framework ID")
    ),
    responses(
        (status = 200, description = "List of rubrics for framework"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Framework not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_framework_rubrics(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    framework_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let framework_id = framework_id.into_inner();

    // Validate framework ID
    if ComplianceFramework::from_id(&framework_id).is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Framework not found",
            "framework_id": framework_id
        })));
    }

    let rubrics = sqlx::query_as::<_, RubricRow>(
        r#"
        SELECT id, user_id, framework_id, control_id, name, description,
               assessment_criteria, rating_scale, evidence_requirements,
               is_system_default, created_at, updated_at
        FROM compliance_rubrics
        WHERE framework_id = ?1 AND (user_id IS NULL OR user_id = ?2)
        ORDER BY control_id, is_system_default DESC, name ASC
        "#,
    )
    .bind(&framework_id)
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch rubrics: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rubrics")
    })?;

    let rubrics: Vec<ComplianceRubric> = rubrics.into_iter().map(|r| r.into()).collect();
    let total = rubrics.len();

    Ok(HttpResponse::Ok().json(RubricListResponse { rubrics, total }))
}

// ============================================================================
// Assessment Endpoints
// ============================================================================

/// GET /api/compliance/assessments
/// List all assessments with optional filters
#[utoipa::path(
    get,
    path = "/api/compliance/assessments",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("framework_id" = Option<String>, Query, description = "Filter by compliance framework ID"),
        ("status" = Option<String>, Query, description = "Filter by review status (draft, pending_review, approved, rejected)")
    ),
    responses(
        (status = 200, description = "List of assessments"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_assessments(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AssessmentListQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let mut sql = String::from(
        r#"
        SELECT id, user_id, rubric_id, framework_id, control_id,
               assessment_period_start, assessment_period_end,
               overall_rating, rating_score, criteria_responses,
               evidence_summary, findings, recommendations,
               review_status, created_at, updated_at
        FROM manual_assessments
        WHERE user_id = ?1
        "#,
    );

    let mut params: Vec<String> = vec![user_id.clone()];

    if let Some(framework_id) = &query.framework_id {
        params.push(framework_id.clone());
        sql.push_str(&format!(" AND framework_id = ?{}", params.len()));
    }

    if let Some(status) = &query.status {
        params.push(status.clone());
        sql.push_str(&format!(" AND review_status = ?{}", params.len()));
    }

    sql.push_str(" ORDER BY updated_at DESC");

    // Build and execute query dynamically
    let assessments = fetch_assessments_dynamic(&pool, &sql, &params).await.map_err(|e| {
        log::error!("Failed to fetch assessments: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessments")
    })?;

    let total = assessments.len();

    Ok(HttpResponse::Ok().json(AssessmentListResponse { assessments, total }))
}

/// GET /api/compliance/assessments/{id}
/// Get a specific assessment by ID
#[utoipa::path(
    get,
    path = "/api/compliance/assessments/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    responses(
        (status = 200, description = "Assessment details"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let is_reviewer = claims.roles.contains(&"reviewer".to_string());
    let assessment_id = assessment_id.into_inner();

    let assessment = sqlx::query_as::<_, AssessmentRow>(
        r#"
        SELECT id, user_id, rubric_id, framework_id, control_id,
               assessment_period_start, assessment_period_end,
               overall_rating, rating_score, criteria_responses,
               evidence_summary, findings, recommendations,
               review_status, created_at, updated_at
        FROM manual_assessments
        WHERE id = ?1
        "#,
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match assessment {
        Some(a) => {
            // Check access: owner, admin, or reviewer
            if a.user_id != *user_id && !is_admin && !is_reviewer {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to view this assessment"
                })));
            }
            Ok(HttpResponse::Ok().json(ManualAssessment::from(a)))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Assessment not found"
        }))),
    }
}

/// POST /api/compliance/assessments
/// Create a new assessment
#[utoipa::path(
    post,
    path = "/api/compliance/assessments",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    request_body = CreateAssessmentRequest,
    responses(
        (status = 201, description = "Assessment created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn create_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateAssessmentRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now();
    let assessment_id = Uuid::new_v4().to_string();

    // Validate framework ID
    if ComplianceFramework::from_id(&request.framework_id).is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid framework ID"
        })));
    }

    // Serialize JSON fields
    let criteria_responses_json = serde_json::to_string(&request.criteria_responses)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid criteria responses: {}", e)))?;
    let overall_rating_str = serde_json::to_string(&request.overall_rating)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid overall rating: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO manual_assessments (
            id, user_id, rubric_id, framework_id, control_id,
            assessment_period_start, assessment_period_end,
            overall_rating, rating_score, criteria_responses,
            evidence_summary, findings, recommendations,
            review_status, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        "#,
    )
    .bind(&assessment_id)
    .bind(user_id)
    .bind(&request.rubric_id)
    .bind(&request.framework_id)
    .bind(&request.control_id)
    .bind(request.assessment_period_start)
    .bind(request.assessment_period_end)
    .bind(&overall_rating_str)
    .bind(request.rating_score)
    .bind(&criteria_responses_json)
    .bind(&request.evidence_summary)
    .bind(&request.findings)
    .bind(&request.recommendations)
    .bind("draft")
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create assessment")
    })?;

    let assessment = ManualAssessment {
        id: assessment_id,
        user_id: user_id.clone(),
        rubric_id: request.rubric_id.clone(),
        framework_id: request.framework_id.clone(),
        control_id: request.control_id.clone(),
        assessment_period_start: request.assessment_period_start,
        assessment_period_end: request.assessment_period_end,
        overall_rating: request.overall_rating.clone(),
        rating_score: request.rating_score,
        criteria_responses: request.criteria_responses.clone(),
        evidence_summary: request.evidence_summary.clone(),
        findings: request.findings.clone(),
        recommendations: request.recommendations.clone(),
        review_status: ReviewStatus::Draft,
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(assessment))
}

/// PUT /api/compliance/assessments/{id}
/// Update an assessment
#[utoipa::path(
    put,
    path = "/api/compliance/assessments/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    request_body = UpdateAssessmentRequest,
    responses(
        (status = 200, description = "Assessment updated"),
        (status = 400, description = "Invalid request or assessment not in draft status"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn update_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
    request: web::Json<UpdateAssessmentRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let assessment_id = assessment_id.into_inner();

    // Fetch existing assessment
    let existing = sqlx::query_as::<_, AssessmentRow>(
        r#"
        SELECT id, user_id, rubric_id, framework_id, control_id,
               assessment_period_start, assessment_period_end,
               overall_rating, rating_score, criteria_responses,
               evidence_summary, findings, recommendations,
               review_status, created_at, updated_at
        FROM manual_assessments
        WHERE id = ?1
        "#,
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    let existing = match existing {
        Some(a) => a,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
    };

    // Check ownership
    if existing.user_id != *user_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to modify this assessment"
        })));
    }

    // Check status - can only update draft or rejected assessments
    if existing.review_status != "draft" && existing.review_status != "rejected" {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Can only update assessments in draft or rejected status",
            "current_status": existing.review_status
        })));
    }

    let now = Utc::now();
    let mut assessment: ManualAssessment = existing.into();

    // Apply updates
    if let Some(overall_rating) = &request.overall_rating {
        assessment.overall_rating = overall_rating.clone();
    }
    if let Some(rating_score) = request.rating_score {
        assessment.rating_score = rating_score;
    }
    if let Some(criteria_responses) = &request.criteria_responses {
        assessment.criteria_responses = criteria_responses.clone();
    }
    if let Some(evidence_summary) = &request.evidence_summary {
        assessment.evidence_summary = Some(evidence_summary.clone());
    }
    if let Some(findings) = &request.findings {
        assessment.findings = Some(findings.clone());
    }
    if let Some(recommendations) = &request.recommendations {
        assessment.recommendations = Some(recommendations.clone());
    }
    assessment.updated_at = now;
    // Reset to draft if was rejected
    assessment.review_status = ReviewStatus::Draft;

    // Serialize JSON fields
    let overall_rating_str = serde_json::to_string(&assessment.overall_rating)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid overall rating: {}", e)))?;
    let criteria_responses_json = serde_json::to_string(&assessment.criteria_responses)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid criteria responses: {}", e)))?;

    sqlx::query(
        r#"
        UPDATE manual_assessments
        SET overall_rating = ?1, rating_score = ?2, criteria_responses = ?3,
            evidence_summary = ?4, findings = ?5, recommendations = ?6,
            review_status = ?7, updated_at = ?8
        WHERE id = ?9
        "#,
    )
    .bind(&overall_rating_str)
    .bind(assessment.rating_score)
    .bind(&criteria_responses_json)
    .bind(&assessment.evidence_summary)
    .bind(&assessment.findings)
    .bind(&assessment.recommendations)
    .bind("draft")
    .bind(now)
    .bind(&assessment_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to update assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update assessment")
    })?;

    Ok(HttpResponse::Ok().json(assessment))
}

/// DELETE /api/compliance/assessments/{id}
/// Delete an assessment
#[utoipa::path(
    delete,
    path = "/api/compliance/assessments/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    responses(
        (status = 200, description = "Assessment deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let assessment_id = assessment_id.into_inner();

    // Check ownership
    let existing = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM manual_assessments WHERE id = ?1",
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id && !is_admin => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to delete this assessment"
            })));
        }
        _ => {}
    }

    // Delete associated evidence first
    sqlx::query("DELETE FROM assessment_evidence WHERE assessment_id = ?1")
        .bind(&assessment_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete evidence: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete assessment")
        })?;

    // Delete assessment
    sqlx::query("DELETE FROM manual_assessments WHERE id = ?1")
        .bind(&assessment_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete assessment: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete assessment")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Assessment deleted successfully"
    })))
}

/// POST /api/compliance/assessments/{id}/submit
/// Submit an assessment for review
#[utoipa::path(
    post,
    path = "/api/compliance/assessments/{id}/submit",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    responses(
        (status = 200, description = "Assessment submitted for review"),
        (status = 400, description = "Assessment not in draft status"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn submit_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let assessment_id = assessment_id.into_inner();

    // Fetch existing assessment
    let existing = sqlx::query_as::<_, (String, String)>(
        "SELECT user_id, review_status FROM manual_assessments WHERE id = ?1",
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id, _)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to submit this assessment"
            })));
        }
        Some((_, status)) if status != "draft" && status != "rejected" => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Can only submit assessments in draft or rejected status",
                "current_status": status
            })));
        }
        _ => {}
    }

    let now = Utc::now();

    sqlx::query(
        "UPDATE manual_assessments SET review_status = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind("pending_review")
    .bind(now)
    .bind(&assessment_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to submit assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to submit assessment")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Assessment submitted for review",
        "status": "pending_review"
    })))
}

/// POST /api/compliance/assessments/{id}/approve
/// Approve an assessment (requires reviewer role or admin)
#[utoipa::path(
    post,
    path = "/api/compliance/assessments/{id}/approve",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    responses(
        (status = 200, description = "Assessment approved"),
        (status = 400, description = "Assessment not pending review"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires reviewer or admin role"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn approve_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
) -> Result<HttpResponse> {
    let is_admin = claims.roles.contains(&"admin".to_string());
    let is_reviewer = claims.roles.contains(&"reviewer".to_string());
    let assessment_id = assessment_id.into_inner();

    // Check permissions
    if !is_admin && !is_reviewer {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Requires reviewer or admin role to approve assessments"
        })));
    }

    // Fetch existing assessment
    let existing = sqlx::query_as::<_, (String,)>(
        "SELECT review_status FROM manual_assessments WHERE id = ?1",
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((status,)) if status != "pending_review" => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Can only approve assessments pending review",
                "current_status": status
            })));
        }
        _ => {}
    }

    let now = Utc::now();

    sqlx::query(
        "UPDATE manual_assessments SET review_status = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind("approved")
    .bind(now)
    .bind(&assessment_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to approve assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to approve assessment")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Assessment approved",
        "status": "approved"
    })))
}

/// POST /api/compliance/assessments/{id}/reject
/// Reject an assessment with notes
#[utoipa::path(
    post,
    path = "/api/compliance/assessments/{id}/reject",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    request_body = RejectAssessmentRequest,
    responses(
        (status = 200, description = "Assessment rejected"),
        (status = 400, description = "Assessment not pending review"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires reviewer or admin role"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn reject_assessment(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
    request: web::Json<RejectAssessmentRequest>,
) -> Result<HttpResponse> {
    let is_admin = claims.roles.contains(&"admin".to_string());
    let is_reviewer = claims.roles.contains(&"reviewer".to_string());
    let assessment_id = assessment_id.into_inner();

    // Check permissions
    if !is_admin && !is_reviewer {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Requires reviewer or admin role to reject assessments"
        })));
    }

    // Fetch existing assessment
    let existing = sqlx::query_as::<_, (String,)>(
        "SELECT review_status FROM manual_assessments WHERE id = ?1",
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((status,)) if status != "pending_review" => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Can only reject assessments pending review",
                "current_status": status
            })));
        }
        _ => {}
    }

    let now = Utc::now();

    // Update assessment status and add rejection notes to findings
    sqlx::query(
        r#"
        UPDATE manual_assessments
        SET review_status = ?1,
            findings = COALESCE(findings, '') || ?2,
            updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind("rejected")
    .bind(format!("\n\n[REJECTION NOTES - {}]: {}", now.format("%Y-%m-%d %H:%M:%S UTC"), request.notes))
    .bind(now)
    .bind(&assessment_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to reject assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to reject assessment")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Assessment rejected",
        "status": "rejected",
        "rejection_notes": request.notes
    })))
}

// ============================================================================
// Evidence Endpoints
// ============================================================================

/// POST /api/compliance/assessments/{id}/evidence
/// Upload evidence file or add link to an assessment
#[utoipa::path(
    post,
    path = "/api/compliance/assessments/{id}/evidence",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    request_body = AddEvidenceRequest,
    responses(
        (status = 201, description = "Evidence added"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn add_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
    request: web::Json<AddEvidenceRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let assessment_id = assessment_id.into_inner();

    // Verify ownership
    let existing = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM manual_assessments WHERE id = ?1",
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to add evidence to this assessment"
            })));
        }
        _ => {}
    }

    let now = Utc::now();
    let evidence_id = Uuid::new_v4().to_string();

    let evidence_type_str = serde_json::to_string(&request.evidence_type)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid evidence type: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO assessment_evidence (
            id, assessment_id, user_id, evidence_type, title, description,
            file_path, external_url, content, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&evidence_id)
    .bind(&assessment_id)
    .bind(user_id)
    .bind(&evidence_type_str)
    .bind(&request.title)
    .bind(&request.description)
    .bind::<Option<String>>(None) // file_path - set later for file uploads
    .bind(&request.external_url)
    .bind(&request.content)
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to add evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add evidence")
    })?;

    let evidence = AssessmentEvidence {
        id: evidence_id,
        assessment_id,
        evidence_type: request.evidence_type.clone(),
        title: request.title.clone(),
        description: request.description.clone(),
        file_path: None,
        external_url: request.external_url.clone(),
        content: request.content.clone(),
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(evidence))
}

/// Request to upload an evidence file (base64 encoded)
#[derive(Debug, Deserialize)]
pub struct UploadEvidenceFileRequest {
    pub title: String,
    pub description: Option<String>,
    pub filename: String,
    /// Base64-encoded file content
    pub file_data: String,
}

/// POST /api/compliance/assessments/{id}/evidence/upload
/// Upload an evidence file (base64 encoded in JSON)
#[utoipa::path(
    post,
    path = "/api/compliance/assessments/{id}/evidence/upload",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    request_body = UploadEvidenceFileRequest,
    responses(
        (status = 201, description = "Evidence file uploaded"),
        (status = 400, description = "Invalid file"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn upload_evidence_file(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
    request: web::Json<UploadEvidenceFileRequest>,
) -> Result<HttpResponse> {
    use base64::Engine;

    let user_id = &claims.sub;
    let assessment_id = assessment_id.into_inner();

    // Verify ownership
    let existing = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM manual_assessments WHERE id = ?1",
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to upload evidence to this assessment"
            })));
        }
        _ => {}
    }

    // Decode base64 file data
    let file_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.file_data)
        .map_err(|e| {
            log::error!("Failed to decode base64: {}", e);
            actix_web::error::ErrorBadRequest("Invalid base64-encoded file data")
        })?;

    // Create evidence directory if it doesn't exist
    let evidence_dir = std::env::var("EVIDENCE_DIR").unwrap_or_else(|_| "./evidence".to_string());
    tokio::fs::create_dir_all(&evidence_dir).await.map_err(|e| {
        log::error!("Failed to create evidence directory: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to process upload")
    })?;

    let now = Utc::now();
    let evidence_id = Uuid::new_v4().to_string();

    // Sanitize filename - keep only alphanumeric, dots, dashes, and underscores
    let sanitized_filename: String = request
        .filename
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = if sanitized_filename.is_empty() {
        format!("{}.bin", evidence_id)
    } else {
        sanitized_filename
    };

    let filepath = format!("{}/{}_{}", evidence_dir, evidence_id, filename);

    // Write file
    tokio::fs::write(&filepath, &file_bytes).await.map_err(|e| {
        log::error!("Failed to write file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to save file")
    })?;

    let evidence_type_str = serde_json::to_string(&EvidenceType::File)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid evidence type: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO assessment_evidence (
            id, assessment_id, user_id, evidence_type, title, description,
            file_path, external_url, content, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
    )
    .bind(&evidence_id)
    .bind(&assessment_id)
    .bind(user_id)
    .bind(&evidence_type_str)
    .bind(&request.title)
    .bind(&request.description)
    .bind(&filepath)
    .bind::<Option<String>>(None)
    .bind::<Option<String>>(None)
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to add evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add evidence")
    })?;

    let evidence = AssessmentEvidence {
        id: evidence_id,
        assessment_id,
        evidence_type: EvidenceType::File,
        title: request.title.clone(),
        description: request.description.clone(),
        file_path: Some(filepath),
        external_url: None,
        content: None,
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(evidence))
}

/// GET /api/compliance/assessments/{id}/evidence
/// List all evidence for an assessment
#[utoipa::path(
    get,
    path = "/api/compliance/assessments/{id}/evidence",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Assessment ID")
    ),
    responses(
        (status = 200, description = "List of evidence"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Assessment not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    assessment_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let is_reviewer = claims.roles.contains(&"reviewer".to_string());
    let assessment_id = assessment_id.into_inner();

    // Verify access
    let existing = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM manual_assessments WHERE id = ?1",
    )
    .bind(&assessment_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessment")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Assessment not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id && !is_admin && !is_reviewer => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to view evidence for this assessment"
            })));
        }
        _ => {}
    }

    let evidence = sqlx::query_as::<_, EvidenceRow>(
        r#"
        SELECT id, assessment_id, evidence_type, title, description,
               file_path, external_url, content, created_at, updated_at
        FROM assessment_evidence
        WHERE assessment_id = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&assessment_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch evidence")
    })?;

    let evidence: Vec<AssessmentEvidence> = evidence.into_iter().map(|e| e.into()).collect();
    let total = evidence.len();

    Ok(HttpResponse::Ok().json(EvidenceListResponse { evidence, total }))
}

/// DELETE /api/compliance/evidence/{id}
/// Delete an evidence item
#[utoipa::path(
    delete,
    path = "/api/compliance/evidence/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Evidence ID")
    ),
    responses(
        (status = 200, description = "Evidence deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Evidence not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    evidence_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let evidence_id = evidence_id.into_inner();

    // Get evidence with assessment info
    let existing = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT ma.user_id, ae.file_path
        FROM assessment_evidence ae
        JOIN manual_assessments ma ON ae.assessment_id = ma.id
        WHERE ae.id = ?1
        "#,
    )
    .bind(&evidence_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch evidence")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Evidence not found"
            })));
        }
        Some((owner_id, _)) if owner_id != *user_id && !is_admin => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to delete this evidence"
            })));
        }
        Some((_, Some(file_path))) => {
            // Delete file from disk
            if let Err(e) = tokio::fs::remove_file(&file_path).await {
                log::warn!("Failed to delete evidence file {}: {}", file_path, e);
            }
        }
        _ => {}
    }

    sqlx::query("DELETE FROM assessment_evidence WHERE id = ?1")
        .bind(&evidence_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete evidence: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete evidence")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Evidence deleted successfully"
    })))
}

/// GET /api/compliance/evidence/{id}/download
/// Download an evidence file
#[utoipa::path(
    get,
    path = "/api/compliance/evidence/{id}/download",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Evidence ID")
    ),
    responses(
        (status = 200, description = "Evidence file downloaded"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Evidence not found or not a file"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn download_evidence(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    evidence_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let is_admin = claims.roles.contains(&"admin".to_string());
    let is_reviewer = claims.roles.contains(&"reviewer".to_string());
    let evidence_id = evidence_id.into_inner();

    // Get evidence with assessment info
    let existing = sqlx::query_as::<_, (String, Option<String>, String)>(
        r#"
        SELECT ma.user_id, ae.file_path, ae.title
        FROM assessment_evidence ae
        JOIN manual_assessments ma ON ae.assessment_id = ma.id
        WHERE ae.id = ?1
        "#,
    )
    .bind(&evidence_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch evidence: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch evidence")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Evidence not found"
            })));
        }
        Some((owner_id, _, _)) if owner_id != *user_id && !is_admin && !is_reviewer => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to download this evidence"
            })));
        }
        Some((_, None, _)) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Evidence is not a file"
            })));
        }
        Some((_, Some(file_path), title)) => {
            let content = tokio::fs::read(&file_path).await.map_err(|e| {
                log::error!("Failed to read evidence file: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to read file")
            })?;

            // Determine content type from file extension
            let content_type = get_content_type_from_extension(&file_path);

            // Extract filename from path
            let filename = std::path::Path::new(&file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&title);

            return Ok(HttpResponse::Ok()
                .content_type(content_type)
                .insert_header((
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                ))
                .body(content));
        }
    }
}

/// Determine content type from file extension
fn get_content_type_from_extension(path: &str) -> &'static str {
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    match extension.as_str() {
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "rar" => "application/vnd.rar",
        "7z" => "application/x-7z-compressed",
        _ => "application/octet-stream",
    }
}

// ============================================================================
// Campaign Endpoints
// ============================================================================

/// GET /api/compliance/campaigns
/// List all campaigns
#[utoipa::path(
    get,
    path = "/api/compliance/campaigns",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("status" = Option<String>, Query, description = "Filter by status (draft, active, completed, archived)")
    ),
    responses(
        (status = 200, description = "List of campaigns"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_campaigns(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<CampaignListQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let campaigns = match &query.status {
        Some(status) => {
            sqlx::query_as::<_, CampaignRow>(
                r#"
                SELECT id, user_id, name, description, frameworks, due_date,
                       status, created_at, updated_at
                FROM assessment_campaigns
                WHERE user_id = ?1 AND status = ?2
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .bind(status)
            .fetch_all(pool.get_ref())
            .await
        }
        None => {
            sqlx::query_as::<_, CampaignRow>(
                r#"
                SELECT id, user_id, name, description, frameworks, due_date,
                       status, created_at, updated_at
                FROM assessment_campaigns
                WHERE user_id = ?1
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .fetch_all(pool.get_ref())
            .await
        }
    }
    .map_err(|e| {
        log::error!("Failed to fetch campaigns: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaigns")
    })?;

    let campaigns: Vec<AssessmentCampaign> = campaigns.into_iter().map(|c| c.into()).collect();
    let total = campaigns.len();

    Ok(HttpResponse::Ok().json(CampaignListResponse { campaigns, total }))
}

/// GET /api/compliance/campaigns/{id}
/// Get a specific campaign by ID
#[utoipa::path(
    get,
    path = "/api/compliance/campaigns/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign details"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    let campaign = sqlx::query_as::<_, CampaignRow>(
        r#"
        SELECT id, user_id, name, description, frameworks, due_date,
               status, created_at, updated_at
        FROM assessment_campaigns
        WHERE id = ?1
        "#,
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
    })?;

    match campaign {
        Some(c) if c.user_id == *user_id => {
            Ok(HttpResponse::Ok().json(AssessmentCampaign::from(c)))
        }
        Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to view this campaign"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Campaign not found"
        }))),
    }
}

/// POST /api/compliance/campaigns
/// Create a new campaign
#[utoipa::path(
    post,
    path = "/api/compliance/campaigns",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    request_body = CreateCampaignRequest,
    responses(
        (status = 201, description = "Campaign created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn create_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateCampaignRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now();
    let campaign_id = Uuid::new_v4().to_string();

    // Validate frameworks
    for framework_id in &request.frameworks {
        if ComplianceFramework::from_id(framework_id).is_none() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid framework ID: {}", framework_id)
            })));
        }
    }

    let frameworks_json = serde_json::to_string(&request.frameworks)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid frameworks: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO assessment_campaigns (
            id, user_id, name, description, frameworks, due_date,
            status, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&campaign_id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&frameworks_json)
    .bind(request.due_date)
    .bind("draft")
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create campaign")
    })?;

    let campaign = AssessmentCampaign {
        id: campaign_id,
        user_id: user_id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        frameworks: request.frameworks.clone(),
        due_date: request.due_date,
        status: CampaignStatus::Draft,
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(campaign))
}

/// PUT /api/compliance/campaigns/{id}
/// Update a campaign
#[utoipa::path(
    put,
    path = "/api/compliance/campaigns/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    request_body = UpdateCampaignRequest,
    responses(
        (status = 200, description = "Campaign updated"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn update_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
    request: web::Json<UpdateCampaignRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    // Fetch existing campaign
    let existing = sqlx::query_as::<_, CampaignRow>(
        r#"
        SELECT id, user_id, name, description, frameworks, due_date,
               status, created_at, updated_at
        FROM assessment_campaigns
        WHERE id = ?1
        "#,
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
    })?;

    let existing = match existing {
        Some(c) => c,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Campaign not found"
            })));
        }
    };

    if existing.user_id != *user_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to modify this campaign"
        })));
    }

    let now = Utc::now();
    let mut campaign: AssessmentCampaign = existing.into();

    // Apply updates
    if let Some(name) = &request.name {
        campaign.name = name.clone();
    }
    if let Some(description) = &request.description {
        campaign.description = Some(description.clone());
    }
    if let Some(frameworks) = &request.frameworks {
        // Validate frameworks
        for framework_id in frameworks {
            if ComplianceFramework::from_id(framework_id).is_none() {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid framework ID: {}", framework_id)
                })));
            }
        }
        campaign.frameworks = frameworks.clone();
    }
    if let Some(due_date) = request.due_date {
        campaign.due_date = Some(due_date);
    }
    if let Some(status) = &request.status {
        campaign.status = status.clone();
    }
    campaign.updated_at = now;

    let frameworks_json = serde_json::to_string(&campaign.frameworks)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid frameworks: {}", e)))?;
    let status_str = serde_json::to_string(&campaign.status)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid status: {}", e)))?;

    sqlx::query(
        r#"
        UPDATE assessment_campaigns
        SET name = ?1, description = ?2, frameworks = ?3, due_date = ?4,
            status = ?5, updated_at = ?6
        WHERE id = ?7
        "#,
    )
    .bind(&campaign.name)
    .bind(&campaign.description)
    .bind(&frameworks_json)
    .bind(campaign.due_date)
    .bind(&status_str)
    .bind(now)
    .bind(&campaign_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to update campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update campaign")
    })?;

    Ok(HttpResponse::Ok().json(campaign))
}

/// DELETE /api/compliance/campaigns/{id}
/// Delete a campaign
#[utoipa::path(
    delete,
    path = "/api/compliance/campaigns/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    // Check ownership
    let existing = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM assessment_campaigns WHERE id = ?1",
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
    })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Campaign not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to delete this campaign"
            })));
        }
        _ => {}
    }

    sqlx::query("DELETE FROM assessment_campaigns WHERE id = ?1")
        .bind(&campaign_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete campaign: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete campaign")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Campaign deleted successfully"
    })))
}

/// GET /api/compliance/campaigns/{id}/progress
/// Get progress for a campaign
#[utoipa::path(
    get,
    path = "/api/compliance/campaigns/{id}/progress",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign progress"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_campaign_progress(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    // Verify ownership and get frameworks
    let campaign = sqlx::query_as::<_, (String, String)>(
        "SELECT user_id, frameworks FROM assessment_campaigns WHERE id = ?1",
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
    })?;

    let (owner_id, frameworks_json) = match campaign {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Campaign not found"
            })));
        }
        Some((owner_id, _)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to view this campaign"
            })));
        }
        Some(c) => c,
    };

    let _ = owner_id; // Suppress unused variable warning

    // Parse frameworks
    let frameworks: Vec<String> = serde_json::from_str(&frameworks_json).unwrap_or_default();

    // Calculate total controls across all frameworks
    let mut total_controls = 0usize;
    for framework_id in &frameworks {
        if let Some(framework) = ComplianceFramework::from_id(framework_id) {
            total_controls += crate::compliance::frameworks::get_controls(framework).len();
        }
    }

    // Count assessments by status for this user and campaign frameworks
    let stats = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT review_status, COUNT(*) as count
        FROM manual_assessments
        WHERE user_id = ?1 AND framework_id IN (SELECT value FROM json_each(?2))
        GROUP BY review_status
        "#,
    )
    .bind(user_id)
    .bind(&frameworks_json)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment stats: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to calculate progress")
    })?;

    let mut assessed = 0usize;
    let mut pending_review = 0usize;
    let mut approved = 0usize;

    for (status, count) in stats {
        let count = count as usize;
        assessed += count;
        match status.as_str() {
            "pending_review" => pending_review = count,
            "approved" => approved = count,
            _ => {}
        }
    }

    let progress = CampaignProgress::new(total_controls, assessed, pending_review, approved);

    Ok(HttpResponse::Ok().json(progress))
}

// ============================================================================
// Combined Results Endpoint
// ============================================================================

/// GET /api/scans/{id}/compliance/combined
/// Get combined automated and manual compliance results for a scan
#[utoipa::path(
    get,
    path = "/api/scans/{id}/compliance/combined",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Scan ID")
    ),
    responses(
        (status = 200, description = "Combined compliance results"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Scan not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_combined_compliance(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let scan_id = scan_id.into_inner();

    // Verify scan ownership
    let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id).await.map_err(|e| {
        log::error!("Failed to fetch scan: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch scan")
    })?;

    let scan = match scan {
        Some(s) if s.user_id == *user_id => s,
        Some(_) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to view this scan"
            })));
        }
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    // Get automated compliance summary if scan is completed
    let automated_summary = if scan.status == "completed" {
        let hosts: Vec<crate::types::HostInfo> = match &scan.results {
            Some(results_json) => serde_json::from_str(results_json).unwrap_or_default(),
            None => Vec::new(),
        };

        let frameworks = vec![
            ComplianceFramework::PciDss4,
            ComplianceFramework::Nist80053,
            ComplianceFramework::CisBenchmarks,
            ComplianceFramework::OwaspTop10,
        ];

        let analyzer = crate::compliance::analyzer::ComplianceAnalyzer::new(frameworks);
        match analyzer.analyze(&hosts, &scan_id).await {
            Ok(summary) => Some(serde_json::to_value(summary).unwrap_or_default()),
            Err(e) => {
                log::warn!("Failed to generate automated compliance: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Get manual assessments for this user
    let manual_assessments = sqlx::query_as::<_, AssessmentRow>(
        r#"
        SELECT id, user_id, rubric_id, framework_id, control_id,
               assessment_period_start, assessment_period_end,
               overall_rating, rating_score, criteria_responses,
               evidence_summary, findings, recommendations,
               review_status, created_at, updated_at
        FROM manual_assessments
        WHERE user_id = ?1 AND review_status = 'approved'
        ORDER BY framework_id, control_id
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch manual assessments: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch assessments")
    })?;

    let manual_assessments: Vec<ManualAssessment> =
        manual_assessments.into_iter().map(|a| a.into()).collect();

    // Calculate combined score
    let automated_score = automated_summary
        .as_ref()
        .and_then(|s| s.get("overall_score"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as f32;

    let manual_score = if !manual_assessments.is_empty() {
        manual_assessments.iter().map(|a| a.rating_score).sum::<f32>()
            / manual_assessments.len() as f32
    } else {
        0.0
    };

    // Weight: 60% automated, 40% manual (if both available)
    let combined_score = if automated_summary.is_some() && !manual_assessments.is_empty() {
        automated_score * 0.6 + manual_score * 0.4
    } else if automated_summary.is_some() {
        automated_score
    } else {
        manual_score
    };

    Ok(HttpResponse::Ok().json(CombinedComplianceResponse {
        scan_id,
        automated_summary,
        manual_assessments,
        combined_score,
        generated_at: Utc::now(),
    }))
}

// ============================================================================
// Database Row Types
// ============================================================================

#[derive(Debug, sqlx::FromRow)]
struct RubricRow {
    id: String,
    user_id: Option<String>,
    framework_id: String,
    control_id: String,
    name: String,
    description: Option<String>,
    assessment_criteria: String,
    rating_scale: String,
    evidence_requirements: String,
    is_system_default: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<RubricRow> for ComplianceRubric {
    fn from(row: RubricRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            framework_id: row.framework_id,
            control_id: row.control_id,
            name: row.name,
            description: row.description,
            assessment_criteria: serde_json::from_str(&row.assessment_criteria).unwrap_or_default(),
            rating_scale: serde_json::from_str(&row.rating_scale).unwrap_or_default(),
            evidence_requirements: serde_json::from_str(&row.evidence_requirements)
                .unwrap_or_default(),
            is_system_default: row.is_system_default,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AssessmentRow {
    id: String,
    user_id: String,
    rubric_id: String,
    framework_id: String,
    control_id: String,
    assessment_period_start: DateTime<Utc>,
    assessment_period_end: DateTime<Utc>,
    overall_rating: String,
    rating_score: f32,
    criteria_responses: String,
    evidence_summary: Option<String>,
    findings: Option<String>,
    recommendations: Option<String>,
    review_status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AssessmentRow> for ManualAssessment {
    fn from(row: AssessmentRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            rubric_id: row.rubric_id,
            framework_id: row.framework_id,
            control_id: row.control_id,
            assessment_period_start: row.assessment_period_start,
            assessment_period_end: row.assessment_period_end,
            overall_rating: serde_json::from_str(&row.overall_rating).unwrap_or(OverallRating::NonCompliant),
            rating_score: row.rating_score,
            criteria_responses: serde_json::from_str(&row.criteria_responses).unwrap_or_default(),
            evidence_summary: row.evidence_summary,
            findings: row.findings,
            recommendations: row.recommendations,
            review_status: match row.review_status.as_str() {
                "draft" => ReviewStatus::Draft,
                "pending_review" => ReviewStatus::PendingReview,
                "approved" => ReviewStatus::Approved,
                "rejected" => ReviewStatus::Rejected,
                _ => ReviewStatus::Draft,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct EvidenceRow {
    id: String,
    assessment_id: String,
    evidence_type: String,
    title: String,
    description: Option<String>,
    file_path: Option<String>,
    external_url: Option<String>,
    content: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<EvidenceRow> for AssessmentEvidence {
    fn from(row: EvidenceRow) -> Self {
        Self {
            id: row.id,
            assessment_id: row.assessment_id,
            evidence_type: serde_json::from_str(&row.evidence_type).unwrap_or(EvidenceType::Note),
            title: row.title,
            description: row.description,
            file_path: row.file_path,
            external_url: row.external_url,
            content: row.content,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct CampaignRow {
    id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    frameworks: String,
    due_date: Option<DateTime<Utc>>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<CampaignRow> for AssessmentCampaign {
    fn from(row: CampaignRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            name: row.name,
            description: row.description,
            frameworks: serde_json::from_str(&row.frameworks).unwrap_or_default(),
            due_date: row.due_date,
            status: match row.status.as_str() {
                "draft" => CampaignStatus::Draft,
                "active" => CampaignStatus::Active,
                "completed" => CampaignStatus::Completed,
                "archived" => CampaignStatus::Archived,
                _ => CampaignStatus::Draft,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to fetch assessments with dynamic parameters
async fn fetch_assessments_dynamic(
    pool: &SqlitePool,
    sql: &str,
    params: &[String],
) -> Result<Vec<ManualAssessment>, sqlx::Error> {
    // Build query dynamically based on number of parameters
    // This is a workaround since sqlx doesn't support dynamic parameter binding
    match params.len() {
        1 => {
            sqlx::query_as::<_, AssessmentRow>(sql)
                .bind(&params[0])
                .fetch_all(pool)
                .await
                .map(|rows| rows.into_iter().map(|r| r.into()).collect())
        }
        2 => {
            sqlx::query_as::<_, AssessmentRow>(sql)
                .bind(&params[0])
                .bind(&params[1])
                .fetch_all(pool)
                .await
                .map(|rows| rows.into_iter().map(|r| r.into()).collect())
        }
        3 => {
            sqlx::query_as::<_, AssessmentRow>(sql)
                .bind(&params[0])
                .bind(&params[1])
                .bind(&params[2])
                .fetch_all(pool)
                .await
                .map(|rows| rows.into_iter().map(|r| r.into()).collect())
        }
        _ => Ok(Vec::new()),
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure manual compliance routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Rubric endpoints
        .route("/compliance/rubrics", web::get().to(list_rubrics))
        .route("/compliance/rubrics", web::post().to(create_rubric))
        .route("/compliance/rubrics/{id}", web::get().to(get_rubric))
        .route("/compliance/rubrics/{id}", web::put().to(update_rubric))
        .route("/compliance/rubrics/{id}", web::delete().to(delete_rubric))
        .route(
            "/compliance/frameworks/{framework_id}/rubrics",
            web::get().to(get_framework_rubrics),
        )
        // Assessment endpoints
        .route("/compliance/assessments", web::get().to(list_assessments))
        .route("/compliance/assessments", web::post().to(create_assessment))
        .route("/compliance/assessments/{id}", web::get().to(get_assessment))
        .route("/compliance/assessments/{id}", web::put().to(update_assessment))
        .route("/compliance/assessments/{id}", web::delete().to(delete_assessment))
        .route(
            "/compliance/assessments/{id}/submit",
            web::post().to(submit_assessment),
        )
        .route(
            "/compliance/assessments/{id}/approve",
            web::post().to(approve_assessment),
        )
        .route(
            "/compliance/assessments/{id}/reject",
            web::post().to(reject_assessment),
        )
        // Evidence endpoints
        .route(
            "/compliance/assessments/{id}/evidence",
            web::post().to(add_evidence),
        )
        .route(
            "/compliance/assessments/{id}/evidence/upload",
            web::post().to(upload_evidence_file),
        )
        .route(
            "/compliance/assessments/{id}/evidence",
            web::get().to(list_evidence),
        )
        .route("/compliance/evidence/{id}", web::delete().to(delete_evidence))
        .route(
            "/compliance/evidence/{id}/download",
            web::get().to(download_evidence),
        )
        // Campaign endpoints
        .route("/compliance/campaigns", web::get().to(list_campaigns))
        .route("/compliance/campaigns", web::post().to(create_campaign))
        .route("/compliance/campaigns/{id}", web::get().to(get_campaign))
        .route("/compliance/campaigns/{id}", web::put().to(update_campaign))
        .route("/compliance/campaigns/{id}", web::delete().to(delete_campaign))
        .route(
            "/compliance/campaigns/{id}/progress",
            web::get().to(get_campaign_progress),
        )
        // Combined results endpoint
        .route(
            "/scans/{id}/compliance/combined",
            web::get().to(get_combined_compliance),
        );
}
