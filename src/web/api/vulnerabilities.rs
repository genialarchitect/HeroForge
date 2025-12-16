use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::models::{
    AddVulnerabilityCommentRequest, BulkAssignVulnerabilitiesRequest, BulkUpdateVulnerabilitiesRequest,
    UpdateVulnerabilityRequest, VerifyVulnerabilityRequest,
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

/// Request to bulk export vulnerabilities
#[derive(Debug, Deserialize)]
pub struct BulkExportVulnerabilitiesRequest {
    pub vulnerability_ids: Vec<String>,
    pub format: String, // "csv" or "json"
}

/// Bulk export vulnerabilities to CSV or JSON
pub async fn bulk_export_vulnerabilities(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkExportVulnerabilitiesRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Validate request
    if request.vulnerability_ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one vulnerability ID must be specified"
        }));
    }

    if request.vulnerability_ids.len() > 1000 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Maximum 1000 vulnerabilities per export request"
        }));
    }

    let format = request.format.to_lowercase();
    if !["json", "csv"].contains(&format.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid format. Must be 'json' or 'csv'"
        }));
    }

    // Fetch all vulnerabilities
    let mut vulnerabilities = Vec::new();
    for vuln_id in &request.vulnerability_ids {
        match crate::db::get_vulnerability_detail(pool.get_ref(), vuln_id).await {
            Ok(detail) => vulnerabilities.push(detail.vulnerability),
            Err(e) => {
                log::error!("Failed to fetch vulnerability {}: {}", vuln_id, e);
                // Continue with other vulnerabilities
            }
        }
    }

    if vulnerabilities.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "No vulnerabilities found"
        }));
    }

    match format.as_str() {
        "json" => {
            // Export as JSON
            match serde_json::to_string_pretty(&vulnerabilities) {
                Ok(json_data) => {
                    HttpResponse::Ok()
                        .content_type("application/json")
                        .insert_header((
                            "Content-Disposition",
                            "attachment; filename=\"vulnerabilities_export.json\"",
                        ))
                        .body(json_data)
                }
                Err(e) => {
                    log::error!("Failed to serialize vulnerabilities: {}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to generate export"
                    }))
                }
            }
        }
        "csv" => {
            // Export as CSV
            let mut csv_data = String::new();
            csv_data.push_str("ID,Scan ID,Host IP,Port,Vulnerability ID,Severity,Status,Assignee,Notes,Due Date,Created At,Updated At,Resolved At,Resolved By\n");

            for vuln in vulnerabilities {
                csv_data.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    vuln.id,
                    vuln.scan_id,
                    vuln.host_ip,
                    vuln.port.map(|p| p.to_string()).unwrap_or_default(),
                    vuln.vulnerability_id,
                    vuln.severity,
                    vuln.status,
                    vuln.assignee_id.as_deref().unwrap_or(""),
                    vuln.notes.as_deref().unwrap_or("").replace(",", ";"),
                    vuln.due_date
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    vuln.created_at.to_rfc3339(),
                    vuln.updated_at.to_rfc3339(),
                    vuln.resolved_at
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default(),
                    vuln.resolved_by.as_deref().unwrap_or("")
                ));
            }

            HttpResponse::Ok()
                .content_type("text/csv")
                .insert_header((
                    "Content-Disposition",
                    "attachment; filename=\"vulnerabilities_export.csv\"",
                ))
                .body(csv_data)
        }
        _ => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Unsupported format"
        })),
    }
}

/// Get timeline for vulnerability
pub async fn get_vulnerability_timeline(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_remediation_timeline(pool.get_ref(), &vuln_id).await {
        Ok(timeline) => HttpResponse::Ok().json(timeline),
        Err(e) => {
            log::error!("Failed to get vulnerability timeline: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve timeline"
            }))
        }
    }
}

/// Mark vulnerability for verification
pub async fn mark_for_verification(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<VerifyVulnerabilityRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::mark_vulnerability_for_verification(
        pool.get_ref(),
        &vuln_id,
        request.scan_id.as_deref(),
        &claims.sub,
    )
    .await
    {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => {
            log::error!("Failed to mark vulnerability for verification: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to mark for verification"
            }))
        }
    }
}

/// Bulk assign vulnerabilities
pub async fn bulk_assign(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkAssignVulnerabilitiesRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::bulk_assign_vulnerabilities(
        pool.get_ref(),
        &request.vulnerability_ids,
        &request.assignee_id,
        &claims.sub,
    )
    .await
    {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "updated": count
        })),
        Err(e) => {
            log::error!("Failed to bulk assign vulnerabilities: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to bulk assign"
            }))
        }
    }
}

/// Configure vulnerability routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/vulnerabilities")
            .route("", web::get().to(list_vulnerabilities))
            .route("/{id}", web::get().to(get_vulnerability))
            .route("/{id}", web::put().to(update_vulnerability))
            .route("/{id}/comments", web::post().to(add_comment))
            .route("/{id}/timeline", web::get().to(get_vulnerability_timeline))
            .route("/{id}/verify", web::post().to(mark_for_verification))
            .route("/bulk-update", web::post().to(bulk_update_vulnerabilities))
            .route("/bulk-assign", web::post().to(bulk_assign))
            .route("/bulk-export", web::post().to(bulk_export_vulnerabilities))
            .route("/stats", web::get().to(get_vulnerability_stats)),
    );
}
