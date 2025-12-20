//! Secret Findings API endpoints
//!
//! This module provides REST API endpoints for managing detected secrets
//! from scans.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::db::{self, models};
use crate::db::models::{SecretFindingRecord, SecretFindingStats, UpdateSecretFindingRequest};
use crate::web::auth;

/// Query parameters for listing secret findings
#[derive(Debug, Deserialize, ToSchema)]
pub struct SecretFindingsQuery {
    pub scan_id: Option<String>,
    pub host_ip: Option<String>,
    pub secret_type: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for bulk operations
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkUpdateResponse {
    pub updated: u64,
    pub message: String,
}

/// List secret findings with optional filters
#[utoipa::path(
    get,
    path = "/api/secrets",
    tag = "Secrets",
    params(
        ("scan_id" = Option<String>, Query, description = "Filter by scan ID"),
        ("host_ip" = Option<String>, Query, description = "Filter by host IP"),
        ("secret_type" = Option<String>, Query, description = "Filter by secret type"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination"),
    ),
    responses(
        (status = 200, description = "List of secret findings", body = Vec<SecretFindingRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn list_secret_findings(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    query: web::Query<SecretFindingsQuery>,
) -> Result<HttpResponse> {
    let findings = db::secret_findings::get_findings_filtered(
        pool.get_ref(),
        query.scan_id.as_deref(),
        query.host_ip.as_deref(),
        query.secret_type.as_deref(),
        query.severity.as_deref(),
        query.status.as_deref(),
        query.limit,
        query.offset,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to list secret findings: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list secret findings")
    })?;

    Ok(HttpResponse::Ok().json(findings))
}

/// Get secret findings for a specific scan
#[utoipa::path(
    get,
    path = "/api/scans/{scan_id}/secrets",
    tag = "Secrets",
    params(
        ("scan_id" = String, Path, description = "Scan ID"),
    ),
    responses(
        (status = 200, description = "List of secret findings for scan", body = Vec<SecretFindingRecord>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Scan not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_scan_secrets(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Verify scan exists
    let scan = db::scans::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get scan: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    if scan.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        })));
    }

    let findings = db::secret_findings::get_findings_by_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get secret findings for scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get secret findings")
        })?;

    Ok(HttpResponse::Ok().json(findings))
}

/// Get statistics for secret findings
#[utoipa::path(
    get,
    path = "/api/secrets/stats",
    tag = "Secrets",
    params(
        ("scan_id" = Option<String>, Query, description = "Filter stats by scan ID"),
    ),
    responses(
        (status = 200, description = "Secret finding statistics", body = SecretFindingStats),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_secret_stats(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    query: web::Query<SecretFindingsQuery>,
) -> Result<HttpResponse> {
    let stats = db::secret_findings::get_finding_stats(pool.get_ref(), query.scan_id.as_deref())
        .await
        .map_err(|e| {
            log::error!("Failed to get secret stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get statistics")
        })?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Get a single secret finding by ID
#[utoipa::path(
    get,
    path = "/api/secrets/{id}",
    tag = "Secrets",
    params(
        ("id" = String, Path, description = "Secret finding ID"),
    ),
    responses(
        (status = 200, description = "Secret finding details", body = SecretFindingRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Finding not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_secret_finding(
    pool: web::Data<SqlitePool>,
    _claims: auth::jwt::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let finding = db::secret_findings::get_finding_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to get secret finding: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    match finding {
        Some(f) => Ok(HttpResponse::Ok().json(f)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Secret finding not found"
        }))),
    }
}

/// Update a secret finding (status, notes, false positive flag)
#[utoipa::path(
    patch,
    path = "/api/secrets/{id}",
    tag = "Secrets",
    params(
        ("id" = String, Path, description = "Secret finding ID"),
    ),
    request_body = UpdateSecretFindingRequest,
    responses(
        (status = 200, description = "Updated secret finding", body = SecretFindingRecord),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Finding not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn update_secret_finding(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    path: web::Path<String>,
    body: web::Json<models::UpdateSecretFindingRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    // Verify finding exists
    let existing = db::secret_findings::get_finding_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to get secret finding: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    if existing.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Secret finding not found"
        })));
    }

    let updated = db::secret_findings::update_finding(
        pool.get_ref(),
        &id,
        &claims.sub,
        &body,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to update secret finding: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update finding")
    })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Bulk update status for multiple secret findings
#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkUpdateRequest {
    pub ids: Vec<String>,
    pub status: String,
}

#[utoipa::path(
    post,
    path = "/api/secrets/bulk-status",
    tag = "Secrets",
    request_body = BulkUpdateRequest,
    responses(
        (status = 200, description = "Bulk update result", body = BulkUpdateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error"),
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn bulk_update_status(
    pool: web::Data<SqlitePool>,
    claims: auth::jwt::Claims,
    body: web::Json<BulkUpdateRequest>,
) -> Result<HttpResponse> {
    if body.ids.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No IDs provided"
        })));
    }

    let valid_statuses = ["open", "resolved", "investigating", "false_positive"];
    if !valid_statuses.contains(&body.status.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid status. Must be one of: open, resolved, investigating, false_positive"
        })));
    }

    let updated = db::secret_findings::bulk_update_status(
        pool.get_ref(),
        &body.ids,
        &body.status,
        &claims.sub,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to bulk update secret findings: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update findings")
    })?;

    Ok(HttpResponse::Ok().json(BulkUpdateResponse {
        updated,
        message: format!("Updated {} findings to status '{}'", updated, body.status),
    }))
}

/// Configure routes for secret findings API
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/secrets")
            .route("", web::get().to(list_secret_findings))
            .route("/stats", web::get().to(get_secret_stats))
            .route("/bulk-status", web::post().to(bulk_update_status))
            .route("/{id}", web::get().to(get_secret_finding))
            .route("/{id}", web::patch().to(update_secret_finding)),
    );
}

/// Configure scan-specific secret routes
pub fn configure_scan_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/scans/{scan_id}/secrets", web::get().to(get_scan_secrets));
}
