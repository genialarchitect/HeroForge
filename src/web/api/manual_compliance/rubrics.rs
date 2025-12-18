//! Rubric API handlers
//!
//! Provides REST API endpoints for compliance rubric management including:
//! - List, get, create, update, delete rubrics
//! - Get rubrics by framework

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::compliance::manual_assessment::ComplianceRubric;
use crate::compliance::types::ComplianceFramework;
use crate::web::auth;

use super::types::{
    CreateRubricRequest, RubricListQuery, RubricListResponse, RubricRow, UpdateRubricRequest,
};

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
        .map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid evidence requirements: {}", e))
        })?;

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
        .map_err(|e| {
            actix_web::error::ErrorBadRequest(format!("Invalid evidence requirements: {}", e))
        })?;

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
