use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::models::{
    AddVulnerabilityCommentRequest, BulkAssignVulnerabilitiesRequest, BulkRetestRequest,
    BulkUpdateVulnerabilitiesRequest, CompleteRetestRequest, RequestRetestRequest,
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

/// List vulnerabilities with optional filters
#[utoipa::path(
    get,
    path = "/api/vulnerabilities",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("scan_id" = Option<String>, Query, description = "Filter by scan ID (required)"),
        ("status" = Option<String>, Query, description = "Filter by status (open, in_progress, resolved, false_positive, accepted_risk)"),
        ("severity" = Option<String>, Query, description = "Filter by severity (critical, high, medium, low, info)")
    ),
    responses(
        (status = 200, description = "List of vulnerabilities", body = Vec<crate::web::openapi::VulnerabilityTrackingSchema>),
        (status = 400, description = "Missing scan_id parameter", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/{id}",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    responses(
        (status = 200, description = "Vulnerability details"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Vulnerability not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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
#[utoipa::path(
    put,
    path = "/api/vulnerabilities/{id}",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body(
        content = crate::web::openapi::UpdateVulnerabilityRequestSchema,
        description = "Vulnerability update data"
    ),
    responses(
        (status = 200, description = "Vulnerability updated", body = crate::web::openapi::VulnerabilityTrackingSchema),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/{id}/comments",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body(
        content = crate::web::openapi::AddCommentRequestSchema,
        description = "Comment to add"
    ),
    responses(
        (status = 201, description = "Comment added"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/bulk-update",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = crate::web::openapi::BulkUpdateVulnerabilitiesRequestSchema,
        description = "Vulnerability IDs and update data"
    ),
    responses(
        (status = 200, description = "Vulnerabilities updated"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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
        req.due_date,
        req.priority.as_deref(),
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
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/stats",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("scan_id" = Option<String>, Query, description = "Optional scan ID filter")
    ),
    responses(
        (status = 200, description = "Vulnerability statistics", body = crate::web::openapi::VulnerabilityStatsSchema),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/{id}/timeline",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    responses(
        (status = 200, description = "Vulnerability timeline"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/{id}/verify",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body(
        content = inline(crate::db::models::VerifyVulnerabilityRequest),
        description = "Optional scan ID for verification"
    ),
    responses(
        (status = 200, description = "Vulnerability marked for verification", body = crate::web::openapi::VulnerabilityTrackingSchema),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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

/// Bulk assign vulnerabilities to a user
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/bulk-assign",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::BulkAssignVulnerabilitiesRequest),
        description = "Vulnerability IDs and assignee"
    ),
    responses(
        (status = 200, description = "Vulnerabilities assigned"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
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

// ============================================================================
// Retest Workflow Endpoints
// ============================================================================

/// Request a retest for a vulnerability
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/{id}/request-retest",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body(
        content = inline(crate::db::models::RequestRetestRequest),
        description = "Optional notes for the retest request"
    ),
    responses(
        (status = 200, description = "Retest requested", body = crate::web::openapi::VulnerabilityTrackingSchema),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn request_retest(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<RequestRetestRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::request_vulnerability_retest(
        pool.get_ref(),
        &vuln_id,
        &claims.sub,
        request.notes.as_deref(),
    )
    .await
    {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => {
            log::error!("Failed to request retest: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to request retest"
            }))
        }
    }
}

/// Bulk request retests for multiple vulnerabilities
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/bulk-retest",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::BulkRetestRequest),
        description = "Vulnerability IDs to request retests for"
    ),
    responses(
        (status = 200, description = "Retests requested"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn bulk_request_retest(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkRetestRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::bulk_request_retests(
        pool.get_ref(),
        &request.vulnerability_ids,
        &claims.sub,
        request.notes.as_deref(),
    )
    .await
    {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "requested": count
        })),
        Err(e) => {
            log::error!("Failed to bulk request retests: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to request retests"
            }))
        }
    }
}

/// Complete a retest with results
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/{id}/complete-retest",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body(
        content = inline(crate::db::models::CompleteRetestRequest),
        description = "Retest completion data"
    ),
    responses(
        (status = 200, description = "Retest completed", body = crate::web::openapi::VulnerabilityTrackingSchema),
        (status = 400, description = "Invalid retest result", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn complete_retest(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<CompleteRetestRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::complete_vulnerability_retest(
        pool.get_ref(),
        &vuln_id,
        &request.result,
        request.scan_id.as_deref(),
        &claims.sub,
        request.notes.as_deref(),
    )
    .await
    {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Invalid retest result") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_msg
                }))
            } else {
                log::error!("Failed to complete retest: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to complete retest"
                }))
            }
        }
    }
}

/// Get vulnerabilities pending retest
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/pending-retest",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("scan_id" = Option<String>, Query, description = "Optional scan ID filter")
    ),
    responses(
        (status = 200, description = "Vulnerabilities pending retest", body = Vec<crate::web::openapi::VulnerabilityTrackingSchema>),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_pending_retests(
    pool: web::Data<SqlitePool>,
    query: web::Query<VulnerabilityStatsQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_vulnerabilities_pending_retest(pool.get_ref(), query.scan_id.as_deref()).await {
        Ok(vulnerabilities) => HttpResponse::Ok().json(vulnerabilities),
        Err(e) => {
            log::error!("Failed to get pending retests: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve pending retests"
            }))
        }
    }
}

/// Get retest history for a vulnerability
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/{id}/retest-history",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    responses(
        (status = 200, description = "Retest history"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_retest_history(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_retest_history(pool.get_ref(), &vuln_id).await {
        Ok(history) => HttpResponse::Ok().json(history),
        Err(e) => {
            log::error!("Failed to get retest history: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve retest history"
            }))
        }
    }
}
