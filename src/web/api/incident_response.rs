//! Incident Response API Endpoints
//!
//! Provides REST API for incident response capabilities:
//! - Incident CRUD and lifecycle management
//! - Timeline event management and export
//! - Evidence collection and chain of custody
//! - Response playbooks and automated actions

use actix_web::{web, HttpResponse, HttpRequest};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db;
use crate::incident_response::{
    self,
    types::*,
};
use crate::web::auth::jwt::Claims;

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing incidents
#[derive(Debug, Deserialize)]
pub struct ListIncidentsQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub classification: Option<String>,
    pub assignee_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Query parameters for timeline export
#[derive(Debug, Deserialize)]
pub struct TimelineExportQuery {
    pub format: Option<String>,
}

// ============================================================================
// Incident Endpoints
// ============================================================================

/// Create a new incident
#[utoipa::path(
    post,
    path = "/api/incidents",
    tag = "Incident Response",
    request_body = CreateIncidentRequest,
    responses(
        (status = 201, description = "Incident created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_incident(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    request: web::Json<CreateIncidentRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let request = request.into_inner();

    // Validate severity
    if request.severity.parse::<IncidentSeverity>().is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid severity. Must be P1, P2, P3, or P4"
        }));
    }

    // Validate classification
    if request.classification.parse::<IncidentClassification>().is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid classification"
        }));
    }

    match incident_response::incidents::create_incident(
        pool.get_ref(),
        &claims.sub,
        request,
        claims.org_id.as_deref(),
    ).await {
        Ok(incident) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "incident_created",
                Some("incident"),
                Some(&incident.id),
                Some(&format!("Created incident: {}", incident.title)),
                ip.as_deref(),
                req.headers().get("user-agent").and_then(|h| h.to_str().ok()),
            ).await;

            HttpResponse::Created().json(incident)
        }
        Err(e) => {
            log::error!("Failed to create incident: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create incident"
            }))
        }
    }
}

/// List incidents with optional filters
#[utoipa::path(
    get,
    path = "/api/incidents",
    tag = "Incident Response",
    params(
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("severity" = Option<String>, Query, description = "Filter by severity"),
        ("classification" = Option<String>, Query, description = "Filter by classification"),
        ("assignee_id" = Option<String>, Query, description = "Filter by assignee"),
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "List of incidents"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_incidents(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<ListIncidentsQuery>,
) -> HttpResponse {
    match incident_response::incidents::list_incidents(
        pool.get_ref(),
        query.status.as_deref(),
        query.severity.as_deref(),
        query.classification.as_deref(),
        query.assignee_id.as_deref(),
        claims.org_id.as_deref(),
        query.limit,
        query.offset,
    ).await {
        Ok(incidents) => HttpResponse::Ok().json(incidents),
        Err(e) => {
            log::error!("Failed to list incidents: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list incidents"
            }))
        }
    }
}

/// Get a single incident with details
#[utoipa::path(
    get,
    path = "/api/incidents/{id}",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Incident details"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_incident(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let incident_id = path.into_inner();

    match incident_response::incidents::get_incident_with_details(pool.get_ref(), &incident_id).await {
        Ok(incident) => HttpResponse::Ok().json(incident),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Incident not found"
                }))
            } else {
                log::error!("Failed to get incident: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get incident"
                }))
            }
        }
    }
}

/// Update an incident
#[utoipa::path(
    put,
    path = "/api/incidents/{id}",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    request_body = UpdateIncidentRequest,
    responses(
        (status = 200, description = "Incident updated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_incident(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<UpdateIncidentRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let incident_id = path.into_inner();
    let request = request.into_inner();

    // Validate severity if provided
    if let Some(ref severity) = request.severity {
        if severity.parse::<IncidentSeverity>().is_err() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid severity"
            }));
        }
    }

    match incident_response::incidents::update_incident(pool.get_ref(), &incident_id, request).await {
        Ok(incident) => {
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "incident_updated",
                Some("incident"),
                Some(&incident.id),
                Some(&format!("Updated incident: {}", incident.title)),
                ip.as_deref(),
                req.headers().get("user-agent").and_then(|h| h.to_str().ok()),
            ).await;

            HttpResponse::Ok().json(incident)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Incident not found"
                }))
            } else {
                log::error!("Failed to update incident: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update incident"
                }))
            }
        }
    }
}

/// Update incident status
#[utoipa::path(
    put,
    path = "/api/incidents/{id}/status",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    request_body = UpdateIncidentStatusRequest,
    responses(
        (status = 200, description = "Status updated"),
        (status = 400, description = "Invalid status"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_incident_status(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<UpdateIncidentStatusRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let incident_id = path.into_inner();
    let request = request.into_inner();

    // Validate status
    if request.status.parse::<IncidentStatus>().is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid status. Must be: detected, triaged, contained, eradicated, recovered, or closed"
        }));
    }

    // Get old status for timeline
    let old_status = match incident_response::incidents::get_incident(pool.get_ref(), &incident_id).await {
        Ok(i) => i.status,
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Incident not found"
            }));
        }
    };

    match incident_response::incidents::update_incident_status(pool.get_ref(), &incident_id, &request.status).await {
        Ok(incident) => {
            // Create timeline event
            let _ = incident_response::timeline::create_status_change_event(
                pool.get_ref(),
                &incident_id,
                &old_status,
                &request.status,
                &claims.sub,
            ).await;

            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "incident_status_updated",
                Some("incident"),
                Some(&incident.id),
                Some(&format!("Changed status from {} to {}", old_status, request.status)),
                ip.as_deref(),
                req.headers().get("user-agent").and_then(|h| h.to_str().ok()),
            ).await;

            HttpResponse::Ok().json(incident)
        }
        Err(e) => {
            log::error!("Failed to update incident status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update incident status"
            }))
        }
    }
}

/// Assign incident to a user
#[utoipa::path(
    put,
    path = "/api/incidents/{id}/assign",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    request_body = AssignIncidentRequest,
    responses(
        (status = 200, description = "Incident assigned"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Incident not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn assign_incident(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<AssignIncidentRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let incident_id = path.into_inner();
    let request = request.into_inner();

    match incident_response::incidents::assign_incident(
        pool.get_ref(),
        &incident_id,
        request.assignee_id.as_deref(),
    ).await {
        Ok(incident) => {
            // Create timeline event
            let _ = incident_response::timeline::create_assignment_event(
                pool.get_ref(),
                &incident_id,
                request.assignee_id.as_deref(),
                &claims.sub,
            ).await;

            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let assignment_msg = match request.assignee_id {
                Some(id) => format!("Assigned to {}", id),
                None => "Unassigned".to_string(),
            };
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "incident_assigned",
                Some("incident"),
                Some(&incident.id),
                Some(&assignment_msg),
                ip.as_deref(),
                req.headers().get("user-agent").and_then(|h| h.to_str().ok()),
            ).await;

            HttpResponse::Ok().json(incident)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Incident not found"
                }))
            } else {
                log::error!("Failed to assign incident: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to assign incident"
                }))
            }
        }
    }
}

/// Delete an incident
#[utoipa::path(
    delete,
    path = "/api/incidents/{id}",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 204, description = "Incident deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_incident(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let incident_id = path.into_inner();

    match incident_response::incidents::delete_incident(pool.get_ref(), &incident_id).await {
        Ok(_) => {
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "incident_deleted",
                Some("incident"),
                Some(&incident_id),
                Some("Deleted incident"),
                ip.as_deref(),
                req.headers().get("user-agent").and_then(|h| h.to_str().ok()),
            ).await;

            HttpResponse::NoContent().finish()
        }
        Err(e) => {
            log::error!("Failed to delete incident: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete incident"
            }))
        }
    }
}

/// Get incident dashboard statistics
#[utoipa::path(
    get,
    path = "/api/incidents/dashboard",
    tag = "Incident Response",
    responses(
        (status = 200, description = "Dashboard statistics"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_incident_dashboard(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> HttpResponse {
    match incident_response::incidents::get_dashboard_stats(
        pool.get_ref(),
        claims.org_id.as_deref(),
    ).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Failed to get dashboard stats: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get dashboard statistics"
            }))
        }
    }
}

// ============================================================================
// Timeline Endpoints
// ============================================================================

/// Add a timeline event to an incident
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/timeline",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    request_body = CreateTimelineEventRequest,
    responses(
        (status = 201, description = "Timeline event created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_timeline_event(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<CreateTimelineEventRequest>,
) -> HttpResponse {
    let incident_id = path.into_inner();
    let request = request.into_inner();

    // Validate event type
    if request.event_type.parse::<TimelineEventType>().is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid event type"
        }));
    }

    match incident_response::timeline::create_timeline_event(
        pool.get_ref(),
        &incident_id,
        &claims.sub,
        request,
    ).await {
        Ok(event) => HttpResponse::Created().json(event),
        Err(e) => {
            log::error!("Failed to create timeline event: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create timeline event"
            }))
        }
    }
}

/// Get timeline events for an incident
#[utoipa::path(
    get,
    path = "/api/incidents/{id}/timeline",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Timeline events"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_timeline(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let incident_id = path.into_inner();

    match incident_response::timeline::get_incident_timeline_with_creators(pool.get_ref(), &incident_id).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(e) => {
            log::error!("Failed to get timeline: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get timeline"
            }))
        }
    }
}

/// Export timeline in specified format
#[utoipa::path(
    get,
    path = "/api/incidents/{id}/timeline/export",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID"),
        ("format" = Option<String>, Query, description = "Export format: json, csv, pdf")
    ),
    responses(
        (status = 200, description = "Exported timeline"),
        (status = 400, description = "Invalid format"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn export_timeline(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
    query: web::Query<TimelineExportQuery>,
) -> HttpResponse {
    let incident_id = path.into_inner();
    let format = query.format.as_deref().unwrap_or("json");

    let events = match incident_response::timeline::get_incident_timeline(pool.get_ref(), &incident_id).await {
        Ok(e) => e,
        Err(e) => {
            log::error!("Failed to get timeline for export: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get timeline"
            }));
        }
    };

    match format.to_lowercase().as_str() {
        "json" => {
            match incident_response::timeline::export_timeline_json(&events) {
                Ok(json) => HttpResponse::Ok()
                    .content_type("application/json")
                    .insert_header(("Content-Disposition", format!("attachment; filename=timeline_{}.json", incident_id)))
                    .body(json),
                Err(e) => {
                    log::error!("Failed to export timeline as JSON: {}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to export timeline"
                    }))
                }
            }
        }
        "csv" => {
            match incident_response::timeline::export_timeline_csv(&events) {
                Ok(csv) => HttpResponse::Ok()
                    .content_type("text/csv")
                    .insert_header(("Content-Disposition", format!("attachment; filename=timeline_{}.csv", incident_id)))
                    .body(csv),
                Err(e) => {
                    log::error!("Failed to export timeline as CSV: {}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to export timeline"
                    }))
                }
            }
        }
        "pdf" => {
            let pdf_data = incident_response::timeline::export_timeline_pdf_data(&incident_id, &events);
            HttpResponse::Ok()
                .content_type("application/json")
                .json(pdf_data)
        }
        _ => {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid format. Must be: json, csv, or pdf"
            }))
        }
    }
}

// ============================================================================
// Evidence Endpoints
// ============================================================================

/// Add evidence to an incident
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/evidence",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    request_body = CreateEvidenceRequest,
    responses(
        (status = 201, description = "Evidence created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_evidence(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<CreateEvidenceRequest>,
) -> HttpResponse {
    let incident_id = path.into_inner();
    let request = request.into_inner();

    // Validate evidence type
    if request.evidence_type.parse::<EvidenceType>().is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid evidence type"
        }));
    }

    match incident_response::evidence::create_evidence(
        pool.get_ref(),
        &incident_id,
        &claims.sub,
        request,
    ).await {
        Ok(evidence) => HttpResponse::Created().json(evidence),
        Err(e) => {
            log::error!("Failed to create evidence: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create evidence"
            }))
        }
    }
}

/// Get all evidence for an incident
#[utoipa::path(
    get,
    path = "/api/incidents/{id}/evidence",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "Evidence list"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_evidence(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let incident_id = path.into_inner();

    match incident_response::evidence::get_incident_evidence_with_details(pool.get_ref(), &incident_id).await {
        Ok(evidence) => HttpResponse::Ok().json(evidence),
        Err(e) => {
            log::error!("Failed to get evidence: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get evidence"
            }))
        }
    }
}

/// Add chain of custody entry for evidence
#[utoipa::path(
    post,
    path = "/api/incidents/{incident_id}/evidence/{evidence_id}/custody",
    tag = "Incident Response",
    params(
        ("incident_id" = String, Path, description = "Incident ID"),
        ("evidence_id" = String, Path, description = "Evidence ID")
    ),
    request_body = AddCustodyEntryRequest,
    responses(
        (status = 201, description = "Custody entry added"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_custody_entry(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    request: web::Json<AddCustodyEntryRequest>,
) -> HttpResponse {
    let (_incident_id, evidence_id) = path.into_inner();
    let request = request.into_inner();

    match incident_response::evidence::add_custody_entry(
        pool.get_ref(),
        &evidence_id,
        &claims.sub,
        &request.action,
        request.notes.as_deref(),
    ).await {
        Ok(entry) => HttpResponse::Created().json(entry),
        Err(e) => {
            log::error!("Failed to add custody entry: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add custody entry"
            }))
        }
    }
}

/// Get chain of custody for evidence
#[utoipa::path(
    get,
    path = "/api/incidents/{incident_id}/evidence/{evidence_id}/custody",
    tag = "Incident Response",
    params(
        ("incident_id" = String, Path, description = "Incident ID"),
        ("evidence_id" = String, Path, description = "Evidence ID")
    ),
    responses(
        (status = 200, description = "Chain of custody"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_custody_chain(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_incident_id, evidence_id) = path.into_inner();

    match incident_response::evidence::get_custody_chain_with_actors(pool.get_ref(), &evidence_id).await {
        Ok(chain) => HttpResponse::Ok().json(chain),
        Err(e) => {
            log::error!("Failed to get custody chain: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get custody chain"
            }))
        }
    }
}

// ============================================================================
// Playbook Endpoints
// ============================================================================

/// Create a response playbook
#[utoipa::path(
    post,
    path = "/api/incidents/playbooks",
    tag = "Incident Response",
    request_body = CreatePlaybookRequest,
    responses(
        (status = 201, description = "Playbook created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_playbook(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    request: web::Json<CreatePlaybookRequest>,
) -> HttpResponse {
    let request = request.into_inner();

    if request.name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Playbook name is required"
        }));
    }

    if request.steps.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one step is required"
        }));
    }

    match incident_response::automation::create_playbook(pool.get_ref(), &claims.sub, request).await {
        Ok(playbook) => HttpResponse::Created().json(playbook),
        Err(e) => {
            log::error!("Failed to create playbook: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create playbook"
            }))
        }
    }
}

/// List all playbooks
#[utoipa::path(
    get,
    path = "/api/incidents/playbooks",
    tag = "Incident Response",
    responses(
        (status = 200, description = "List of playbooks"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_playbooks(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    match incident_response::automation::list_playbooks(pool.get_ref()).await {
        Ok(playbooks) => HttpResponse::Ok().json(playbooks),
        Err(e) => {
            log::error!("Failed to list playbooks: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list playbooks"
            }))
        }
    }
}

/// Get a playbook by ID
#[utoipa::path(
    get,
    path = "/api/incidents/playbooks/{id}",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Playbook ID")
    ),
    responses(
        (status = 200, description = "Playbook details"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Playbook not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_playbook(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let playbook_id = path.into_inner();

    match incident_response::automation::get_playbook(pool.get_ref(), &playbook_id).await {
        Ok(playbook) => {
            // Parse steps for response
            let steps = incident_response::automation::get_playbook_steps(&playbook).unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "playbook": playbook,
                "steps": steps
            }))
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Playbook not found"
                }))
            } else {
                log::error!("Failed to get playbook: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get playbook"
                }))
            }
        }
    }
}

/// Update a playbook
#[utoipa::path(
    put,
    path = "/api/incidents/playbooks/{id}",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Playbook ID")
    ),
    request_body = UpdatePlaybookRequest,
    responses(
        (status = 200, description = "Playbook updated"),
        (status = 400, description = "Cannot update built-in playbook"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Playbook not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_playbook(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
    request: web::Json<UpdatePlaybookRequest>,
) -> HttpResponse {
    let playbook_id = path.into_inner();
    let request = request.into_inner();

    match incident_response::automation::update_playbook(pool.get_ref(), &playbook_id, request).await {
        Ok(playbook) => HttpResponse::Ok().json(playbook),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("built-in") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Cannot update built-in playbooks"
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Playbook not found"
                }))
            } else {
                log::error!("Failed to update playbook: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update playbook"
                }))
            }
        }
    }
}

/// Delete a playbook
#[utoipa::path(
    delete,
    path = "/api/incidents/playbooks/{id}",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Playbook ID")
    ),
    responses(
        (status = 204, description = "Playbook deleted"),
        (status = 400, description = "Cannot delete built-in playbook"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_playbook(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let playbook_id = path.into_inner();

    match incident_response::automation::delete_playbook(pool.get_ref(), &playbook_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("built-in") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Cannot delete built-in playbooks"
                }))
            } else {
                log::error!("Failed to delete playbook: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to delete playbook"
                }))
            }
        }
    }
}

// ============================================================================
// Response Action Endpoints
// ============================================================================

/// Execute a response action
#[utoipa::path(
    post,
    path = "/api/incidents/{id}/actions",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    request_body = ExecuteActionRequest,
    responses(
        (status = 201, description = "Action created (pending approval)"),
        (status = 400, description = "Invalid action type"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_action(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<ExecuteActionRequest>,
) -> HttpResponse {
    let incident_id = path.into_inner();
    let request = request.into_inner();

    // Validate action type
    if request.action_type.parse::<ResponseActionType>().is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid action type"
        }));
    }

    match incident_response::automation::create_action(
        pool.get_ref(),
        &incident_id,
        &claims.sub,
        request,
    ).await {
        Ok(action) => HttpResponse::Created().json(action),
        Err(e) => {
            log::error!("Failed to create action: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create action"
            }))
        }
    }
}

/// Get actions for an incident
#[utoipa::path(
    get,
    path = "/api/incidents/{id}/actions",
    tag = "Incident Response",
    params(
        ("id" = String, Path, description = "Incident ID")
    ),
    responses(
        (status = 200, description = "List of actions"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_actions(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let incident_id = path.into_inner();

    match incident_response::automation::list_incident_actions(pool.get_ref(), &incident_id).await {
        Ok(actions) => HttpResponse::Ok().json(actions),
        Err(e) => {
            log::error!("Failed to list actions: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list actions"
            }))
        }
    }
}

/// List all pending actions
#[utoipa::path(
    get,
    path = "/api/incidents/actions/pending",
    tag = "Incident Response",
    responses(
        (status = 200, description = "List of pending actions"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_pending_actions(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    match incident_response::automation::list_pending_actions(pool.get_ref()).await {
        Ok(actions) => HttpResponse::Ok().json(actions),
        Err(e) => {
            log::error!("Failed to list pending actions: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list pending actions"
            }))
        }
    }
}

/// Approve or reject an action
#[utoipa::path(
    post,
    path = "/api/incidents/{incident_id}/actions/{action_id}/approve",
    tag = "Incident Response",
    params(
        ("incident_id" = String, Path, description = "Incident ID"),
        ("action_id" = String, Path, description = "Action ID")
    ),
    request_body = ApproveActionRequest,
    responses(
        (status = 200, description = "Action approved/rejected"),
        (status = 400, description = "Action not in pending status"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_action(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
    request: web::Json<ApproveActionRequest>,
) -> HttpResponse {
    let (_incident_id, action_id) = path.into_inner();
    let request = request.into_inner();

    let result = if request.approved {
        incident_response::automation::approve_action(pool.get_ref(), &action_id, &claims.sub).await
    } else {
        incident_response::automation::reject_action(
            pool.get_ref(),
            &action_id,
            &claims.sub,
            request.notes.as_deref(),
        ).await
    };

    match result {
        Ok(action) => HttpResponse::Ok().json(action),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("pending") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Action is not in pending status"
                }))
            } else {
                log::error!("Failed to approve/reject action: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to approve/reject action"
                }))
            }
        }
    }
}

/// Execute an approved action
#[utoipa::path(
    post,
    path = "/api/incidents/{incident_id}/actions/{action_id}/execute",
    tag = "Incident Response",
    params(
        ("incident_id" = String, Path, description = "Incident ID"),
        ("action_id" = String, Path, description = "Action ID")
    ),
    responses(
        (status = 200, description = "Action executed"),
        (status = 400, description = "Action not approved"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn execute_action(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_incident_id, action_id) = path.into_inner();

    match incident_response::automation::execute_action(pool.get_ref(), &action_id).await {
        Ok(action) => HttpResponse::Ok().json(action),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("approved") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Action must be approved before execution"
                }))
            } else {
                log::error!("Failed to execute action: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to execute action"
                }))
            }
        }
    }
}

/// Get audit log for an action
#[utoipa::path(
    get,
    path = "/api/incidents/{incident_id}/actions/{action_id}/audit",
    tag = "Incident Response",
    params(
        ("incident_id" = String, Path, description = "Incident ID"),
        ("action_id" = String, Path, description = "Action ID")
    ),
    responses(
        (status = 200, description = "Action audit log"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_action_audit(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_incident_id, action_id) = path.into_inner();

    match incident_response::automation::get_action_audit_log(pool.get_ref(), &action_id).await {
        Ok(logs) => HttpResponse::Ok().json(logs),
        Err(e) => {
            log::error!("Failed to get action audit log: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get action audit log"
            }))
        }
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure incident response routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Dashboard endpoint (must be before /{id} to avoid conflict)
        .route("/incidents/dashboard", web::get().to(get_incident_dashboard))
        // Playbook endpoints (must be before /{id} to avoid conflict)
        .route("/incidents/playbooks", web::post().to(create_playbook))
        .route("/incidents/playbooks", web::get().to(list_playbooks))
        .route("/incidents/playbooks/{id}", web::get().to(get_playbook))
        .route("/incidents/playbooks/{id}", web::put().to(update_playbook))
        .route("/incidents/playbooks/{id}", web::delete().to(delete_playbook))
        // Pending actions (must be before /{id})
        .route("/incidents/actions/pending", web::get().to(list_pending_actions))
        // Incident CRUD
        .route("/incidents", web::post().to(create_incident))
        .route("/incidents", web::get().to(list_incidents))
        .route("/incidents/{id}", web::get().to(get_incident))
        .route("/incidents/{id}", web::put().to(update_incident))
        .route("/incidents/{id}", web::delete().to(delete_incident))
        // Incident status and assignment
        .route("/incidents/{id}/status", web::put().to(update_incident_status))
        .route("/incidents/{id}/assign", web::put().to(assign_incident))
        // Timeline endpoints
        .route("/incidents/{id}/timeline", web::post().to(create_timeline_event))
        .route("/incidents/{id}/timeline", web::get().to(get_timeline))
        .route("/incidents/{id}/timeline/export", web::get().to(export_timeline))
        // Evidence endpoints
        .route("/incidents/{id}/evidence", web::post().to(create_evidence))
        .route("/incidents/{id}/evidence", web::get().to(get_evidence))
        .route("/incidents/{incident_id}/evidence/{evidence_id}/custody", web::post().to(add_custody_entry))
        .route("/incidents/{incident_id}/evidence/{evidence_id}/custody", web::get().to(get_custody_chain))
        // Action endpoints
        .route("/incidents/{id}/actions", web::post().to(create_action))
        .route("/incidents/{id}/actions", web::get().to(list_actions))
        .route("/incidents/{incident_id}/actions/{action_id}/approve", web::post().to(approve_action))
        .route("/incidents/{incident_id}/actions/{action_id}/execute", web::post().to(execute_action))
        .route("/incidents/{incident_id}/actions/{action_id}/audit", web::get().to(get_action_audit));
}
