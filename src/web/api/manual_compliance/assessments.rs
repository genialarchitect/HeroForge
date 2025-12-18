//! Assessment API handlers
//!
//! Provides REST API endpoints for manual compliance assessment management including:
//! - List, get, create, update, delete assessments
//! - Workflow operations: submit, approve, reject

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::compliance::manual_assessment::{ManualAssessment, ReviewStatus};
use crate::compliance::types::ComplianceFramework;
use crate::web::auth;

use super::types::{
    AssessmentListQuery, AssessmentListResponse, AssessmentRow, CreateAssessmentRequest,
    RejectAssessmentRequest, UpdateAssessmentRequest, fetch_assessments_dynamic,
};

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
    let assessments = fetch_assessments_dynamic(&pool, &sql, &params)
        .await
        .map_err(|e| {
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
    let criteria_responses_json = serde_json::to_string(&request.criteria_responses).map_err(
        |e| actix_web::error::ErrorBadRequest(format!("Invalid criteria responses: {}", e)),
    )?;
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
    let criteria_responses_json = serde_json::to_string(&assessment.criteria_responses).map_err(
        |e| actix_web::error::ErrorBadRequest(format!("Invalid criteria responses: {}", e)),
    )?;

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
    let existing =
        sqlx::query_as::<_, (String,)>("SELECT user_id FROM manual_assessments WHERE id = ?1")
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

    sqlx::query("UPDATE manual_assessments SET review_status = ?1, updated_at = ?2 WHERE id = ?3")
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

    sqlx::query("UPDATE manual_assessments SET review_status = ?1, updated_at = ?2 WHERE id = ?3")
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
    .bind(format!(
        "\n\n[REJECTION NOTES - {}]: {}",
        now.format("%Y-%m-%d %H:%M:%S UTC"),
        request.notes
    ))
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
