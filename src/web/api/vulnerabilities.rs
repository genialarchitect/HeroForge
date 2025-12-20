use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::models::{
    AddVulnerabilityCommentRequest, AssignVulnerabilityRequest, BulkAssignVulnerabilitiesRequest,
    BulkRetestRequest, BulkUpdateVulnerabilitiesRequest, BulkUpdateSeverityRequest,
    BulkDeleteVulnerabilitiesRequest, BulkAddTagsRequest, CompleteRetestRequest,
    RequestRetestRequest, UpdateAssignmentRequest, UpdateVulnerabilityRequest,
    VerifyVulnerabilityRequest,
};
use crate::db::vulnerabilities::MAX_BULK_SIZE;
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

/// Get comments for a vulnerability
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/{id}/comments",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    responses(
        (status = 200, description = "List of comments with user info"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_comments(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_vulnerability_comments_with_user(pool.get_ref(), &vuln_id).await {
        Ok(comments) => HttpResponse::Ok().json(comments),
        Err(e) => {
            log::error!("Failed to get comments: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve comments"
            }))
        }
    }
}

/// Delete a comment from a vulnerability (author only)
#[utoipa::path(
    delete,
    path = "/api/vulnerabilities/{id}/comments/{comment_id}",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID"),
        ("comment_id" = String, Path, description = "Comment ID")
    ),
    responses(
        (status = 200, description = "Comment deleted"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Forbidden - can only delete own comments", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Comment not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn delete_comment(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let (vuln_id, comment_id) = path.into_inner();

    match crate::db::delete_vulnerability_comment(
        pool.get_ref(),
        &vuln_id,
        &comment_id,
        &claims.sub,
    )
    .await
    {
        Ok(deleted) => {
            if deleted {
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "Comment deleted successfully"
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Comment not found"
                }))
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("only delete your own comments") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": error_msg
                }))
            } else if error_msg.contains("not found") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Comment not found"
                }))
            } else {
                log::error!("Failed to delete comment: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to delete comment"
                }))
            }
        }
    }
}

/// Update a comment on a vulnerability (author only)
#[utoipa::path(
    put,
    path = "/api/vulnerabilities/{id}/comments/{comment_id}",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID"),
        ("comment_id" = String, Path, description = "Comment ID")
    ),
    request_body(
        content = crate::web::openapi::UpdateCommentRequestSchema,
        description = "Updated comment content"
    ),
    responses(
        (status = 200, description = "Comment updated"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Forbidden - can only edit own comments", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Comment not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn update_comment(
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    request: web::Json<crate::db::models::UpdateVulnerabilityCommentRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let (vuln_id, comment_id) = path.into_inner();

    if request.comment.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Comment cannot be empty"
        }));
    }

    match crate::db::update_vulnerability_comment(
        pool.get_ref(),
        &vuln_id,
        &comment_id,
        &claims.sub,
        &request.comment,
    )
    .await
    {
        Ok(comment) => HttpResponse::Ok().json(comment),
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("only edit your own comments") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": error_msg
                }))
            } else if error_msg.contains("not found") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Comment not found"
                }))
            } else {
                log::error!("Failed to update comment: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update comment"
                }))
            }
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

// ============================================================================
// Additional Bulk Operations
// ============================================================================

/// Bulk update vulnerability status
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/bulk/status",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = crate::web::openapi::BulkUpdateVulnerabilitiesRequestSchema,
        description = "Vulnerability IDs and status to set"
    ),
    responses(
        (status = 200, description = "Vulnerabilities updated", body = crate::web::openapi::BulkOperationResponseSchema),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn bulk_update_status(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkUpdateVulnerabilitiesRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Validate batch size
    if req.vulnerability_ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one vulnerability ID is required"
        }));
    }

    if req.vulnerability_ids.len() > MAX_BULK_SIZE {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Maximum {} vulnerabilities per request", MAX_BULK_SIZE)
        }));
    }

    // Validate status if provided
    if let Some(ref status) = req.status {
        let valid_statuses = ["open", "in_progress", "resolved", "false_positive", "accepted_risk"];
        if !valid_statuses.contains(&status.as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid status '{}'. Must be one of: {}", status, valid_statuses.join(", "))
            }));
        }
    }

    // Verify all IDs exist
    match crate::db::verify_vulnerability_ids(pool.get_ref(), &req.vulnerability_ids).await {
        Ok(found_ids) => {
            let missing = req.vulnerability_ids.len() - found_ids.len();
            if missing > 0 {
                log::warn!("{} vulnerability IDs not found during bulk status update", missing);
            }
        }
        Err(e) => {
            log::error!("Failed to verify vulnerability IDs: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify vulnerability IDs"
            }));
        }
    }

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
            "updated": count,
            "failed": req.vulnerability_ids.len() - count,
            "message": format!("Successfully updated {} vulnerabilities", count)
        })),
        Err(e) => {
            log::error!("Failed to bulk update status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update vulnerabilities"
            }))
        }
    }
}

/// Bulk update vulnerability severity
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/bulk/severity",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::BulkUpdateSeverityRequest),
        description = "Vulnerability IDs and severity to set"
    ),
    responses(
        (status = 200, description = "Severities updated", body = crate::web::openapi::BulkOperationResponseSchema),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn bulk_update_severity(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkUpdateSeverityRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Validate batch size
    if req.vulnerability_ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one vulnerability ID is required"
        }));
    }

    if req.vulnerability_ids.len() > MAX_BULK_SIZE {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Maximum {} vulnerabilities per request", MAX_BULK_SIZE)
        }));
    }

    // Validate severity
    let valid_severities = ["critical", "high", "medium", "low", "info"];
    if !valid_severities.contains(&req.severity.to_lowercase().as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid severity '{}'. Must be one of: {}", req.severity, valid_severities.join(", "))
        }));
    }

    match crate::db::bulk_update_severity(
        pool.get_ref(),
        &req.vulnerability_ids,
        &req.severity,
        &claims.sub,
    )
    .await
    {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "updated": count,
            "failed": req.vulnerability_ids.len() - count,
            "message": format!("Successfully updated severity for {} vulnerabilities", count)
        })),
        Err(e) => {
            log::error!("Failed to bulk update severity: {}", e);
            let error_msg = e.to_string();
            if error_msg.contains("Invalid severity") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_msg
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update severities"
                }))
            }
        }
    }
}

/// Bulk delete vulnerabilities (soft delete)
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/bulk/delete",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::BulkDeleteVulnerabilitiesRequest),
        description = "Vulnerability IDs to delete"
    ),
    responses(
        (status = 200, description = "Vulnerabilities deleted", body = crate::web::openapi::BulkOperationResponseSchema),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn bulk_delete(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkDeleteVulnerabilitiesRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Validate batch size
    if req.vulnerability_ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one vulnerability ID is required"
        }));
    }

    if req.vulnerability_ids.len() > MAX_BULK_SIZE {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Maximum {} vulnerabilities per request", MAX_BULK_SIZE)
        }));
    }

    match crate::db::bulk_delete_vulnerabilities(
        pool.get_ref(),
        &req.vulnerability_ids,
        &claims.sub,
    )
    .await
    {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "deleted": count,
            "failed": req.vulnerability_ids.len() - count,
            "message": format!("Successfully deleted {} vulnerabilities", count)
        })),
        Err(e) => {
            log::error!("Failed to bulk delete: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete vulnerabilities"
            }))
        }
    }
}

/// Bulk add tags to vulnerabilities
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/bulk/tags",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    request_body(
        content = inline(crate::db::models::BulkAddTagsRequest),
        description = "Vulnerability IDs and tags to add"
    ),
    responses(
        (status = 200, description = "Tags added", body = crate::web::openapi::BulkOperationResponseSchema),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn bulk_add_tags(
    pool: web::Data<SqlitePool>,
    request: web::Json<BulkAddTagsRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Validate batch size
    if req.vulnerability_ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one vulnerability ID is required"
        }));
    }

    if req.vulnerability_ids.len() > MAX_BULK_SIZE {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Maximum {} vulnerabilities per request", MAX_BULK_SIZE)
        }));
    }

    if req.tags.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one tag is required"
        }));
    }

    // Validate tag length
    for tag in &req.tags {
        if tag.len() > 50 {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Tag '{}' exceeds maximum length of 50 characters", tag)
            }));
        }
    }

    match crate::db::bulk_add_tags(
        pool.get_ref(),
        &req.vulnerability_ids,
        &req.tags,
        &claims.sub,
    )
    .await
    {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "updated": count,
            "failed": req.vulnerability_ids.len() - count,
            "message": format!("Successfully added tags to {} vulnerabilities", count)
        })),
        Err(e) => {
            log::error!("Failed to bulk add tags: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add tags"
            }))
        }
    }
}

// ============================================================================
// Vulnerability Assignment Endpoints
// ============================================================================

/// Query parameters for getting user assignments
#[derive(Debug, Deserialize)]
pub struct MyAssignmentsQuery {
    pub status: Option<String>,
    pub overdue: Option<bool>,
    pub user_id: Option<String>, // Admin can query other users
}

/// Query parameters for listing vulnerabilities with assignment info
#[derive(Debug, Deserialize)]
pub struct VulnerabilityAssignmentListQuery {
    pub scan_id: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub assigned_to: Option<String>,
    pub overdue: Option<bool>,
}

/// Get current user's assigned vulnerabilities
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/assigned",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("overdue" = Option<bool>, Query, description = "Only show overdue vulnerabilities"),
        ("user_id" = Option<String>, Query, description = "Admin: get assignments for another user")
    ),
    responses(
        (status = 200, description = "User's assigned vulnerabilities with stats", body = crate::db::models::MyAssignmentsResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 403, description = "Forbidden - cannot view other user's assignments", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_my_assignments(
    pool: web::Data<SqlitePool>,
    query: web::Query<MyAssignmentsQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Determine whose assignments to fetch
    let target_user_id = match &query.user_id {
        Some(user_id) if user_id != &claims.sub => {
            // Check if user is admin by checking roles table
            let is_admin = match crate::db::get_user_roles(pool.get_ref(), &claims.sub).await {
                Ok(roles) => roles.iter().any(|r| r.name == "admin"),
                Err(_) => false,
            };

            if !is_admin {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "You don't have permission to view other users' assignments"
                }));
            }
            user_id.clone()
        }
        _ => claims.sub.clone(),
    };

    // Get assignments
    let assignments = match crate::db::get_user_assignments(
        pool.get_ref(),
        &target_user_id,
        query.status.as_deref(),
        query.overdue.unwrap_or(false),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            log::error!("Failed to get user assignments: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve assignments"
            }));
        }
    };

    // Get stats
    let stats = match crate::db::get_user_assignment_stats(pool.get_ref(), &target_user_id).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to get assignment stats: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve assignment statistics"
            }));
        }
    };

    HttpResponse::Ok().json(crate::db::models::MyAssignmentsResponse { stats, assignments })
}

/// List vulnerabilities with assignment information
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/with-assignments",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("scan_id" = Option<String>, Query, description = "Filter by scan ID"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("assigned_to" = Option<String>, Query, description = "Filter by assignee user ID (use 'unassigned' for unassigned vulns, 'me' for current user)"),
        ("overdue" = Option<bool>, Query, description = "Only show overdue vulnerabilities")
    ),
    responses(
        (status = 200, description = "List of vulnerabilities with assignment info", body = Vec<crate::db::models::VulnerabilityAssignmentWithUser>),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn list_vulnerabilities_with_assignments(
    pool: web::Data<SqlitePool>,
    query: web::Query<VulnerabilityAssignmentListQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Handle 'me' as special value for assigned_to
    let assigned_to = match query.assigned_to.as_deref() {
        Some("me") => Some(claims.sub.as_str()),
        other => other,
    };

    match crate::db::get_vulnerabilities_with_assignments(
        pool.get_ref(),
        query.scan_id.as_deref(),
        query.status.as_deref(),
        query.severity.as_deref(),
        assigned_to,
        query.overdue.unwrap_or(false),
    )
    .await
    {
        Ok(vulnerabilities) => HttpResponse::Ok().json(vulnerabilities),
        Err(e) => {
            log::error!("Failed to get vulnerabilities with assignments: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve vulnerabilities"
            }))
        }
    }
}

/// Assign a vulnerability to a user
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/{id}/assign",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body = AssignVulnerabilityRequest,
    responses(
        (status = 200, description = "Vulnerability assigned successfully", body = crate::web::openapi::VulnerabilityTrackingSchema),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Vulnerability not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn assign_vulnerability(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    req: web::Json<AssignVulnerabilityRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Validate priority if provided
    if let Some(ref priority) = req.priority {
        let valid_priorities = ["critical", "high", "medium", "low", "p1", "p2", "p3", "p4"];
        if !valid_priorities.contains(&priority.to_lowercase().as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid priority. Must be one of: {}", valid_priorities.join(", "))
            }));
        }
    }

    // Verify the assignee exists
    match crate::db::get_user_by_id(pool.get_ref(), &req.assignee_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Assignee user not found"
            }));
        }
        Err(e) => {
            log::error!("Failed to verify assignee: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify assignee"
            }));
        }
    }

    match crate::db::assign_vulnerability(
        pool.get_ref(),
        &vuln_id,
        &req.assignee_id,
        req.due_date,
        req.priority.as_deref(),
        &claims.sub,
    )
    .await
    {
        Ok(vuln) => HttpResponse::Ok().json(vuln),
        Err(e) => {
            log::error!("Failed to assign vulnerability: {}", e);
            if e.to_string().contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Vulnerability not found"
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to assign vulnerability"
                }))
            }
        }
    }
}

/// Unassign a vulnerability
#[utoipa::path(
    delete,
    path = "/api/vulnerabilities/{id}/assign",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    responses(
        (status = 200, description = "Vulnerability unassigned successfully", body = crate::web::openapi::VulnerabilityTrackingSchema),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Vulnerability not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn unassign_vulnerability(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::unassign_vulnerability(pool.get_ref(), &vuln_id, &claims.sub).await {
        Ok(vuln) => HttpResponse::Ok().json(vuln),
        Err(e) => {
            log::error!("Failed to unassign vulnerability: {}", e);
            if e.to_string().contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Vulnerability not found"
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to unassign vulnerability"
                }))
            }
        }
    }
}

/// Update a vulnerability assignment (due date, priority, status)
#[utoipa::path(
    put,
    path = "/api/vulnerabilities/{id}/assignment",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body = UpdateAssignmentRequest,
    responses(
        (status = 200, description = "Assignment updated successfully", body = crate::web::openapi::VulnerabilityTrackingSchema),
        (status = 400, description = "Invalid request", body = crate::web::openapi::ErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 404, description = "Vulnerability not found", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn update_assignment(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    req: web::Json<UpdateAssignmentRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Validate priority if provided
    if let Some(ref priority) = req.priority {
        let valid_priorities = ["critical", "high", "medium", "low", "p1", "p2", "p3", "p4"];
        if !valid_priorities.contains(&priority.to_lowercase().as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid priority. Must be one of: {}", valid_priorities.join(", "))
            }));
        }
    }

    // Validate status if provided
    if let Some(ref status) = req.status {
        let valid_statuses = ["open", "in_progress", "pending_verification", "resolved", "false_positive", "accepted_risk"];
        if !valid_statuses.contains(&status.as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid status. Must be one of: {}", valid_statuses.join(", "))
            }));
        }
    }

    // Build update request using existing update_vulnerability function
    let update_req = UpdateVulnerabilityRequest {
        status: req.status.clone(),
        assignee_id: None,
        notes: None,
        due_date: req.due_date,
        priority: req.priority.clone(),
        remediation_steps: None,
        estimated_effort: None,
        actual_effort: None,
    };

    match crate::db::update_vulnerability_status(
        pool.get_ref(),
        &vuln_id,
        &update_req,
        &claims.sub,
    )
    .await
    {
        Ok(vuln) => HttpResponse::Ok().json(vuln),
        Err(e) => {
            log::error!("Failed to update assignment: {}", e);
            if e.to_string().contains("not found") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Vulnerability not found"
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update assignment"
                }))
            }
        }
    }
}

/// Get assignment statistics for current user
#[utoipa::path(
    get,
    path = "/api/vulnerabilities/assignment-stats",
    tag = "Vulnerabilities",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Assignment statistics", body = crate::db::models::UserAssignmentStats),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn get_assignment_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match crate::db::get_user_assignment_stats(pool.get_ref(), &claims.sub).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Failed to get assignment stats: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve assignment statistics"
            }))
        }
    }
}

/// Get list of users for assignment picker (any authenticated user can access)
#[utoipa::path(
    get,
    path = "/api/users",
    tag = "Users",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of users for assignment picker"),
        (status = 401, description = "Unauthorized", body = crate::web::openapi::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::web::openapi::ErrorResponse)
    )
)]
pub async fn list_users_for_picker(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get basic user info for assignment picker (id, username, email)
    match crate::db::get_all_users(pool.get_ref()).await {
        Ok(users) => {
            // Return minimal user info for the picker
            let picker_users: Vec<serde_json::Value> = users
                .into_iter()
                .filter(|u| u.is_active)  // Only include active users
                .map(|u| {
                    serde_json::json!({
                        "id": u.id,
                        "username": u.username,
                        "email": u.email
                    })
                })
                .collect();
            HttpResponse::Ok().json(picker_users)
        }
        Err(e) => {
            log::error!("Failed to get users for picker: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve users"
            }))
        }
    }
}
