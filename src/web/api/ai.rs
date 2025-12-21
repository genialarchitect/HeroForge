//! AI Prioritization API Endpoints
//!
//! Provides REST endpoints for AI-based vulnerability prioritization.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::ai::{
    AIFeedback, AIModelConfig, AIPrioritizationManager, AIPrioritizationResult, AIVulnerabilityScore,
    PrioritizeRequest, SubmitFeedbackRequest, UpdateConfigRequest,
};
use crate::web::auth;
use crate::web::error::{ApiError, ApiErrorKind};

/// Configure AI prioritization routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ai")
            .route("/prioritize/{scan_id}", web::post().to(prioritize_scan))
            .route("/scores/{scan_id}", web::get().to(get_scan_scores))
            .route("/scores/vulnerability/{vuln_id}", web::get().to(get_vulnerability_score))
            .route("/config", web::get().to(get_config))
            .route("/config", web::put().to(update_config))
            .route("/feedback", web::post().to(submit_feedback)),
    );
}

/// POST /api/ai/prioritize/{scan_id}
///
/// Calculate AI prioritization scores for all vulnerabilities in a scan.
#[utoipa::path(
    post,
    path = "/api/ai/prioritize/{scan_id}",
    tag = "AI Prioritization",
    params(
        ("scan_id" = String, Path, description = "Scan ID to prioritize"),
    ),
    request_body = PrioritizeRequest,
    responses(
        (status = 200, description = "Prioritization calculated successfully", body = AIPrioritizationResult),
        (status = 404, description = "Scan not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn prioritize_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<PrioritizeRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;
    let scan_id = path.into_inner();

    // Verify scan exists and user has access
    let scan = crate::db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| ApiError::new(ApiErrorKind::InternalError(String::new()), format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::new(ApiErrorKind::NotFound(String::new()), "Scan not found".to_string()))?;

    // Check if user owns the scan or is admin
    let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;
    if scan.user_id != *user_id && !is_admin {
        return Err(ApiError::new(
            ApiErrorKind::Forbidden(String::new()),
            "You don't have permission to access this scan".to_string(),
        ));
    }

    // Check if we should recalculate or return existing
    if !body.force_recalculate {
        if crate::db::ai::has_prioritization_result(&pool, &scan_id).await? {
            let result = crate::db::ai::get_prioritization_result(&pool, &scan_id).await?;
            return Ok(HttpResponse::Ok().json(result));
        }
    }

    // Create manager and run prioritization
    let manager = AIPrioritizationManager::from_database(Arc::new(pool.get_ref().clone())).await?;
    let result = manager.prioritize_scan(&scan_id).await?;

    // Log the action
    crate::db::log_audit(
        &pool,
        user_id,
        "ai_prioritize",
        Some("scan"),
        Some(&scan_id),
        Some(&format!(
            "AI prioritization calculated: {} vulnerabilities scored",
            result.summary.total_vulnerabilities
        )),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(result))
}

/// GET /api/ai/scores/{scan_id}
///
/// Get prioritized vulnerability scores for a scan.
#[utoipa::path(
    get,
    path = "/api/ai/scores/{scan_id}",
    tag = "AI Prioritization",
    params(
        ("scan_id" = String, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "Prioritization scores", body = AIPrioritizationResult),
        (status = 404, description = "No scores found for scan"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_scan_scores(
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

    // Check if user owns the scan or is admin
    let is_admin = crate::db::has_permission(&pool, user_id, "can_view_all_scans").await?;
    if scan.user_id != *user_id && !is_admin {
        return Err(ApiError::new(
            ApiErrorKind::Forbidden(String::new()),
            "You don't have permission to access this scan".to_string(),
        ));
    }

    // Get prioritization result
    match crate::db::ai::get_prioritization_result(&pool, &scan_id).await {
        Ok(result) => Ok(HttpResponse::Ok().json(result)),
        Err(_) => Err(ApiError::new(
            ApiErrorKind::NotFound(String::new()),
            "No AI prioritization scores found for this scan. Run prioritization first.".to_string(),
        )),
    }
}

/// GET /api/ai/scores/vulnerability/{vuln_id}
///
/// Get score breakdown for a specific vulnerability.
#[utoipa::path(
    get,
    path = "/api/ai/scores/vulnerability/{vuln_id}",
    tag = "AI Prioritization",
    params(
        ("vuln_id" = String, Path, description = "Vulnerability ID"),
    ),
    responses(
        (status = 200, description = "Vulnerability score breakdown", body = AIVulnerabilityScore),
        (status = 404, description = "Score not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_vulnerability_score(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let vuln_id = path.into_inner();

    // Get score for vulnerability
    match crate::db::ai::get_vulnerability_score(&pool, &vuln_id).await? {
        Some(score) => Ok(HttpResponse::Ok().json(score)),
        None => Err(ApiError::new(
            ApiErrorKind::NotFound(String::new()),
            "No AI score found for this vulnerability".to_string(),
        )),
    }
}

/// GET /api/ai/config
///
/// Get current AI model configuration.
#[utoipa::path(
    get,
    path = "/api/ai/config",
    tag = "AI Prioritization",
    responses(
        (status = 200, description = "Current AI configuration", body = AIModelConfig),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_config(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    // Get current config or default
    let config = crate::db::ai::get_model_config(&pool)
        .await?
        .unwrap_or_else(AIModelConfig::default);

    Ok(HttpResponse::Ok().json(config))
}

/// PUT /api/ai/config
///
/// Update AI model configuration (admin only).
#[utoipa::path(
    put,
    path = "/api/ai/config",
    tag = "AI Prioritization",
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Configuration updated", body = AIModelConfig),
        (status = 403, description = "Admin access required"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn update_config(
    pool: web::Data<SqlitePool>,
    body: web::Json<UpdateConfigRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    // Check admin permission
    let is_admin = crate::db::has_permission(&pool, user_id, "can_manage_settings").await?;
    if !is_admin {
        return Err(ApiError::new(
            ApiErrorKind::Forbidden(String::new()),
            "Admin access required to update AI configuration".to_string(),
        ));
    }

    // Get current config or default
    let mut config = crate::db::ai::get_model_config(&pool)
        .await?
        .unwrap_or_else(AIModelConfig::default);

    // Apply updates
    if let Some(name) = &body.name {
        config.name = name.clone();
    }
    if let Some(description) = &body.description {
        config.description = Some(description.clone());
    }
    if let Some(weights) = &body.weights {
        config.weights = weights.clone();
    }
    config.updated_at = chrono::Utc::now();

    // Save config
    crate::db::ai::save_model_config(&pool, &config).await?;

    // Log the action
    crate::db::log_audit(
        &pool,
        user_id,
        "ai_config_update",
        Some("ai_config"),
        Some(&config.id),
        Some("Updated AI prioritization configuration"),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(config))
}

/// POST /api/ai/feedback
///
/// Submit feedback for AI score learning.
#[utoipa::path(
    post,
    path = "/api/ai/feedback",
    tag = "AI Prioritization",
    request_body = SubmitFeedbackRequest,
    responses(
        (status = 200, description = "Feedback submitted successfully"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn submit_feedback(
    pool: web::Data<SqlitePool>,
    body: web::Json<SubmitFeedbackRequest>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse, ApiError> {
    let user_id = &claims.sub;

    let feedback = AIFeedback {
        vulnerability_id: body.vulnerability_id.clone(),
        user_id: user_id.clone(),
        priority_appropriate: body.priority_appropriate,
        priority_adjustment: body.priority_adjustment,
        effort_accurate: body.effort_accurate,
        actual_effort_hours: body.actual_effort_hours,
        notes: body.notes.clone(),
        created_at: chrono::Utc::now(),
    };

    crate::db::ai::store_feedback(&pool, &feedback).await?;

    // Log the action
    crate::db::log_audit(
        &pool,
        user_id,
        "ai_feedback",
        Some("vulnerability"),
        Some(&body.vulnerability_id),
        Some("Submitted AI prioritization feedback"),
        None,
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Feedback submitted successfully"
    })))
}
