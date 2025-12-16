use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::models::{
    AddVulnerabilityCommentRequest, BulkUpdateVulnerabilitiesRequest, UpdateVulnerabilityRequest,
};
use crate::web::auth;

/// Query parameters for listing vulnerabilities
#[derive(Debug, Deserialize)]
pub struct VulnerabilityListQuery {
    pub scan_id: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
}

/// Get vulnerabilities with optional filters
pub async fn list_vulnerabilities(
    pool: web::Data<SqlitePool>,
    query: web::Query<VulnerabilityListQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // If scan_id is provided, use that for filtering
    if let Some(scan_id) = &query.scan_id {
        match crate::db::get_vulnerability_tracking_by_scan(
            pool.get_ref(),
            scan_id,
            query.status.as_deref(),
            query.severity.as_deref(),
        )
        .await
        {
            Ok(vulnerabilities) => HttpResponse::Ok().json(vulnerabilities),
            Err(e) => {
                log::error!("Failed to get vulnerabilities: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to retrieve vulnerabilities"
                }))
            }
        }
    } else {
        // If no scan_id, return empty list or error
        HttpResponse::BadRequest().json(serde_json::json!({
            "error": "scan_id parameter is required"
        }))
    }
}

/// Get single vulnerability with details
pub async fn get_vulnerability(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_vulnerability_detail(pool.get_ref(), &vuln_id).await {
        Ok(detail) => HttpResponse::Ok().json(detail),
        Err(e) => {
            log::error!("Failed to get vulnerability detail: {}", e);
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "Vulnerability not found"
            }))
        }
    }
}

/// Update vulnerability status and metadata
pub async fn update_vulnerability(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<UpdateVulnerabilityRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::update_vulnerability_status(
        pool.get_ref(),
        &vuln_id,
        &request.into_inner(),
        &claims.sub,
    )
    .await
    {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => {
            log::error!("Failed to update vulnerability: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update vulnerability"
            }))
        }
    }
}

/// Add comment to vulnerability
pub async fn add_comment(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<AddVulnerabilityCommentRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::add_vulnerability_comment(
        pool.get_ref(),
        &vuln_id,
        &claims.sub,
        &request.comment,
    )
    .await
    {
        Ok(comment) => HttpResponse::Created().json(comment),
        Err(e) => {
            log::error!("Failed to add comment: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add comment"
            }))
        }
    }
}

/// Bulk update vulnerabilities
pub async fn bulk_update_vulnerabilities(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkUpdateVulnerabilitiesRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    match crate::db::bulk_update_vulnerability_status(
        pool.get_ref(),
        &req.vulnerability_ids,
        req.status.as_deref(),
        req.assignee_id.as_deref(),
        &claims.sub,
    )
    .await
    {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "updated": count
        })),
        Err(e) => {
            log::error!("Failed to bulk update vulnerabilities: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update vulnerabilities"
            }))
        }
    }
}

/// Get vulnerability statistics
pub async fn get_vulnerability_stats(
    pool: web::Data<SqlitePool>,
    query: web::Query<VulnerabilityStatsQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_vulnerability_statistics(pool.get_ref(), query.scan_id.as_deref()).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Failed to get vulnerability statistics: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve statistics"
            }))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct VulnerabilityStatsQuery {
    pub scan_id: Option<String>,
}

/// Configure vulnerability routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/vulnerabilities")
            .route("", web::get().to(list_vulnerabilities))
            .route("/{id}", web::get().to(get_vulnerability))
            .route("/{id}", web::put().to(update_vulnerability))
            .route("/{id}/comments", web::post().to(add_comment))
            .route("/bulk-update", web::post().to(bulk_update_vulnerabilities))
            .route("/stats", web::get().to(get_vulnerability_stats)),
    );
}
