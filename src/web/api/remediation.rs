//! Remediation workflow API endpoints
//!
//! Provides endpoints for:
//! - Verification requests management
//! - Ticket synchronization (JIRA/ServiceNow)
//! - SLA configuration
//! - Overdue vulnerabilities
//! - Remediation dashboard

#![allow(dead_code)]

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};

use crate::db::remediation::{
    CreateVerificationRequest, UpdateVerificationRequest, CreateTicketSyncRequest,
    create_verification_request, get_verification_request_by_id,
    get_verification_requests_for_vulnerability, get_pending_verification_requests,
    update_verification_request, complete_verification_request,
    create_ticket_sync, get_ticket_syncs_for_vulnerability,
    update_ticket_sync_status, log_ticket_sync_operation,
    get_ticket_sync_history, get_sla_configs, get_sla_config_for_severity,
    create_sla_config, get_overdue_vulnerabilities, get_sla_breach_summary,
    create_remediation_assignment, get_assignment_history,
    create_escalation, acknowledge_escalation, get_escalations_for_vulnerability,
    get_unacknowledged_escalations, get_remediation_dashboard_stats,
};
use crate::web::auth;

// ============================================================================
// Query Parameters
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct VerificationListQuery {
    pub vulnerability_id: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct OverdueQuery {
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct SlaConfigQuery {
    pub severity: Option<String>,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateSlaConfigRequest {
    pub name: String,
    pub severity: String,
    pub target_days: i32,
    pub warning_threshold_days: Option<i32>,
    pub escalation_emails: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CompleteVerificationBody {
    pub passed: bool,
    pub result_details: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignmentRequest {
    pub assigned_to: String,
    pub reason: Option<String>,
    pub due_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EscalationRequest {
    pub escalation_level: Option<i32>,
    pub escalation_reason: String,
    pub escalated_to: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TicketSyncStatusUpdate {
    pub external_status: Option<String>,
    pub external_priority: Option<String>,
    pub external_assignee: Option<String>,
}

// ============================================================================
// Verification Request Endpoints
// ============================================================================

/// Create a verification request
pub async fn create_verification(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateVerificationRequest>,
) -> HttpResponse {
    match create_verification_request(pool.get_ref(), &claims.sub, body.into_inner()).await {
        Ok(request) => HttpResponse::Created().json(request),
        Err(e) => {
            log::error!("Failed to create verification request: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create verification request"
            }))
        }
    }
}

/// Get verification request by ID
pub async fn get_verification(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_verification_request_by_id(pool.get_ref(), &id).await {
        Ok(Some(request)) => HttpResponse::Ok().json(request),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Verification request not found"
        })),
        Err(e) => {
            log::error!("Failed to get verification request: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get verification request"
            }))
        }
    }
}

/// List verification requests
pub async fn list_verifications(
    pool: web::Data<SqlitePool>,
    query: web::Query<VerificationListQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // If vulnerability_id provided, get verifications for that vulnerability
    if let Some(vuln_id) = &query.vulnerability_id {
        match get_verification_requests_for_vulnerability(pool.get_ref(), vuln_id).await {
            Ok(requests) => return HttpResponse::Ok().json(requests),
            Err(e) => {
                log::error!("Failed to get verification requests: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get verification requests"
                }));
            }
        }
    }

    // Otherwise, get pending requests assigned to user
    match get_pending_verification_requests(pool.get_ref(), &claims.sub).await {
        Ok(requests) => HttpResponse::Ok().json(requests),
        Err(e) => {
            log::error!("Failed to get pending verification requests: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get verification requests"
            }))
        }
    }
}

/// Update verification request
pub async fn update_verification(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<UpdateVerificationRequest>,
) -> HttpResponse {
    match update_verification_request(pool.get_ref(), &id, body.into_inner()).await {
        Ok(request) => HttpResponse::Ok().json(request),
        Err(e) => {
            log::error!("Failed to update verification request: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update verification request"
            }))
        }
    }
}

/// Complete verification request
pub async fn complete_verification(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CompleteVerificationBody>,
) -> HttpResponse {
    match complete_verification_request(
        pool.get_ref(),
        &id,
        body.passed,
        body.result_details.as_deref(),
        body.evidence.as_deref(),
    )
    .await
    {
        Ok(request) => HttpResponse::Ok().json(request),
        Err(e) => {
            log::error!("Failed to complete verification request: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to complete verification request"
            }))
        }
    }
}

// ============================================================================
// Ticket Sync Endpoints
// ============================================================================

/// Create ticket sync
pub async fn create_sync(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateTicketSyncRequest>,
) -> HttpResponse {
    match create_ticket_sync(pool.get_ref(), body.into_inner()).await {
        Ok(sync) => HttpResponse::Created().json(sync),
        Err(e) => {
            log::error!("Failed to create ticket sync: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create ticket sync"
            }))
        }
    }
}

/// Get ticket syncs for vulnerability
pub async fn get_ticket_syncs(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_ticket_syncs_for_vulnerability(pool.get_ref(), &vuln_id).await {
        Ok(syncs) => HttpResponse::Ok().json(syncs),
        Err(e) => {
            log::error!("Failed to get ticket syncs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get ticket syncs"
            }))
        }
    }
}

/// Update ticket sync status
pub async fn update_sync_status(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<TicketSyncStatusUpdate>,
) -> HttpResponse {
    match update_ticket_sync_status(
        pool.get_ref(),
        &id,
        body.external_status.as_deref(),
        body.external_priority.as_deref(),
        body.external_assignee.as_deref(),
    )
    .await
    {
        Ok(sync) => {
            // Log the sync operation
            let _ = log_ticket_sync_operation(
                pool.get_ref(),
                &id,
                "inbound",
                "status_update",
                Some(&serde_json::to_string(&body.into_inner()).unwrap_or_default()),
                "success",
                None,
            )
            .await;
            HttpResponse::Ok().json(sync)
        }
        Err(e) => {
            log::error!("Failed to update ticket sync: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update ticket sync"
            }))
        }
    }
}

/// Get ticket sync history
pub async fn get_sync_history(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_ticket_sync_history(pool.get_ref(), &id, Some(50)).await {
        Ok(history) => HttpResponse::Ok().json(history),
        Err(e) => {
            log::error!("Failed to get ticket sync history: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get sync history"
            }))
        }
    }
}

// ============================================================================
// SLA Configuration Endpoints
// ============================================================================

/// Get SLA configurations
pub async fn get_sla_configurations(
    pool: web::Data<SqlitePool>,
    query: web::Query<SlaConfigQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    if let Some(severity) = &query.severity {
        match get_sla_config_for_severity(pool.get_ref(), org_id, severity).await {
            Ok(Some(config)) => return HttpResponse::Ok().json(config),
            Ok(None) => {
                return HttpResponse::NotFound().json(serde_json::json!({
                    "error": "No SLA config found for severity"
                }))
            }
            Err(e) => {
                log::error!("Failed to get SLA config: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get SLA config"
                }));
            }
        }
    }

    match get_sla_configs(pool.get_ref(), org_id).await {
        Ok(configs) => HttpResponse::Ok().json(configs),
        Err(e) => {
            log::error!("Failed to get SLA configs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get SLA configs"
            }))
        }
    }
}

/// Create custom SLA configuration
pub async fn create_sla_configuration(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateSlaConfigRequest>,
) -> HttpResponse {
    let org_id = match &claims.org_id {
        Some(id) => id,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Organization context required"
            }))
        }
    };

    match create_sla_config(
        pool.get_ref(),
        org_id,
        &body.name,
        &body.severity,
        body.target_days,
        body.warning_threshold_days,
        body.escalation_emails.as_deref(),
    )
    .await
    {
        Ok(config) => HttpResponse::Created().json(config),
        Err(e) => {
            log::error!("Failed to create SLA config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create SLA config"
            }))
        }
    }
}

// ============================================================================
// Overdue & SLA Breach Endpoints
// ============================================================================

/// Get overdue vulnerabilities
pub async fn get_overdue(
    pool: web::Data<SqlitePool>,
    query: web::Query<OverdueQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_overdue_vulnerabilities(pool.get_ref(), org_id, query.limit).await {
        Ok(vulns) => HttpResponse::Ok().json(vulns),
        Err(e) => {
            log::error!("Failed to get overdue vulnerabilities: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get overdue vulnerabilities"
            }))
        }
    }
}

/// Get SLA breach summary
pub async fn get_breach_summary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_sla_breach_summary(pool.get_ref(), org_id).await {
        Ok(summary) => HttpResponse::Ok().json(summary),
        Err(e) => {
            log::error!("Failed to get SLA breach summary: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get breach summary"
            }))
        }
    }
}

// ============================================================================
// Assignment Endpoints
// ============================================================================

/// Create remediation assignment
pub async fn create_assignment(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<AssignmentRequest>,
) -> HttpResponse {
    // First get current assignee to track in history
    let previous_assignee = match crate::db::get_vulnerability_detail(pool.get_ref(), &vuln_id).await {
        Ok(detail) => detail.vulnerability.assignee_id,
        Err(_) => None,
    };

    match create_remediation_assignment(
        pool.get_ref(),
        &vuln_id,
        &claims.sub,
        &body.assigned_to,
        previous_assignee.as_deref(),
        body.reason.as_deref(),
        body.due_date.as_deref(),
    )
    .await
    {
        Ok(assignment) => {
            // Also update the vulnerability's assignee_id
            // Parse due_date if provided
            let due_date_parsed = body.due_date.as_ref().and_then(|d| {
                chrono::DateTime::parse_from_rfc3339(d).ok().map(|dt| dt.with_timezone(&chrono::Utc))
            });
            let _ = crate::db::assign_vulnerability(
                pool.get_ref(),
                &vuln_id,
                &body.assigned_to,
                due_date_parsed,
                None, // priority
                &claims.sub,
            )
            .await;
            HttpResponse::Created().json(assignment)
        }
        Err(e) => {
            log::error!("Failed to create assignment: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create assignment"
            }))
        }
    }
}

/// Get assignment history for vulnerability
pub async fn get_assignments(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_assignment_history(pool.get_ref(), &vuln_id).await {
        Ok(history) => HttpResponse::Ok().json(history),
        Err(e) => {
            log::error!("Failed to get assignment history: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get assignment history"
            }))
        }
    }
}

// ============================================================================
// Escalation Endpoints
// ============================================================================

/// Create escalation
pub async fn create_vuln_escalation(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<EscalationRequest>,
) -> HttpResponse {
    let level = body.escalation_level.unwrap_or(1);

    match create_escalation(
        pool.get_ref(),
        &vuln_id,
        level,
        &body.escalation_reason,
        body.escalated_to.as_deref(),
        Some(&claims.sub),
        body.notes.as_deref(),
    )
    .await
    {
        Ok(escalation) => HttpResponse::Created().json(escalation),
        Err(e) => {
            log::error!("Failed to create escalation: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create escalation"
            }))
        }
    }
}

/// Get escalations for vulnerability
pub async fn get_vuln_escalations(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_escalations_for_vulnerability(pool.get_ref(), &vuln_id).await {
        Ok(escalations) => HttpResponse::Ok().json(escalations),
        Err(e) => {
            log::error!("Failed to get escalations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get escalations"
            }))
        }
    }
}

/// Acknowledge escalation
pub async fn acknowledge(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match acknowledge_escalation(pool.get_ref(), &id, &claims.sub).await {
        Ok(escalation) => HttpResponse::Ok().json(escalation),
        Err(e) => {
            log::error!("Failed to acknowledge escalation: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to acknowledge escalation"
            }))
        }
    }
}

/// Get unacknowledged escalations for current user
pub async fn get_my_escalations(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_unacknowledged_escalations(pool.get_ref(), &claims.sub, Some(50)).await {
        Ok(escalations) => HttpResponse::Ok().json(escalations),
        Err(e) => {
            log::error!("Failed to get escalations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get escalations"
            }))
        }
    }
}

// ============================================================================
// Dashboard Endpoints
// ============================================================================

/// Get remediation dashboard statistics
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_remediation_dashboard_stats(pool.get_ref(), org_id).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Failed to get remediation dashboard: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get dashboard stats"
            }))
        }
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/remediation")
            // Verification requests
            .route("/verifications", web::post().to(create_verification))
            .route("/verifications", web::get().to(list_verifications))
            .route("/verifications/{id}", web::get().to(get_verification))
            .route("/verifications/{id}", web::put().to(update_verification))
            .route("/verifications/{id}/complete", web::post().to(complete_verification))
            // Ticket sync
            .route("/ticket-sync", web::post().to(create_sync))
            .route("/ticket-sync/vulnerability/{vuln_id}", web::get().to(get_ticket_syncs))
            .route("/ticket-sync/{id}", web::put().to(update_sync_status))
            .route("/ticket-sync/{id}/history", web::get().to(get_sync_history))
            // SLA configuration
            .route("/sla-configs", web::get().to(get_sla_configurations))
            .route("/sla-configs", web::post().to(create_sla_configuration))
            // Overdue & breaches
            .route("/overdue", web::get().to(get_overdue))
            .route("/sla-breaches", web::get().to(get_breach_summary))
            // Assignments
            .route("/vulnerabilities/{vuln_id}/assignments", web::post().to(create_assignment))
            .route("/vulnerabilities/{vuln_id}/assignments", web::get().to(get_assignments))
            // Escalations
            .route("/vulnerabilities/{vuln_id}/escalations", web::post().to(create_vuln_escalation))
            .route("/vulnerabilities/{vuln_id}/escalations", web::get().to(get_vuln_escalations))
            .route("/escalations/{id}/acknowledge", web::post().to(acknowledge))
            .route("/escalations/pending", web::get().to(get_my_escalations))
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard)),
    );
}
