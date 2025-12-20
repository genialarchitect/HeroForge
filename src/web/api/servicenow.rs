//! ServiceNow integration API endpoints
//!
//! Provides REST API endpoints for managing ServiceNow integration settings
//! and creating incidents/change requests from vulnerabilities.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;

use crate::db::servicenow::{
    self, CreateServiceNowTicketRequest, UpsertServiceNowSettingsRequest,
};
use crate::integrations::servicenow::{
    format_vulnerability_description, severity_to_impact, severity_to_urgency, ChangeData,
    IncidentData, ServiceNowClient,
};
use crate::web::auth;

/// Get ServiceNow settings for the current user
pub async fn get_servicenow_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match servicenow::get_servicenow_settings(pool.get_ref(), &claims.sub).await {
        Ok(Some(settings)) => {
            // Return settings with password hidden
            let response = ServiceNowSettingsResponse {
                user_id: settings.user_id,
                instance_url: settings.instance_url,
                username: settings.username,
                default_assignment_group: settings.default_assignment_group,
                default_category: settings.default_category,
                default_impact: settings.default_impact,
                default_urgency: settings.default_urgency,
                enabled: settings.enabled,
                created_at: settings.created_at.to_rfc3339(),
                updated_at: settings.updated_at.to_rfc3339(),
            };
            HttpResponse::Ok().json(response)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "ServiceNow settings not configured"
        })),
        Err(e) => {
            log::error!("Failed to get ServiceNow settings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow settings"
            }))
        }
    }
}

/// Settings response (password hidden)
#[derive(serde::Serialize)]
struct ServiceNowSettingsResponse {
    user_id: String,
    instance_url: String,
    username: String,
    default_assignment_group: Option<String>,
    default_category: Option<String>,
    default_impact: i32,
    default_urgency: i32,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

/// Create or update ServiceNow settings for the current user
pub async fn upsert_servicenow_settings(
    pool: web::Data<SqlitePool>,
    request: web::Json<UpsertServiceNowSettingsRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Validate instance URL format
    if !req.instance_url.starts_with("https://") {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Instance URL must start with https://"
        }));
    }

    match servicenow::upsert_servicenow_settings(pool.get_ref(), &claims.sub, &req).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "ServiceNow settings saved successfully"
        })),
        Err(e) => {
            log::error!("Failed to save ServiceNow settings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to save ServiceNow settings"
            }))
        }
    }
}

/// Test ServiceNow connection with current settings
pub async fn test_servicenow_connection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get ServiceNow settings
    let settings = match servicenow::get_servicenow_settings(pool.get_ref(), &claims.sub).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "ServiceNow settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get ServiceNow settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow settings"
            }));
        }
    };

    // Create ServiceNow client and test connection
    match ServiceNowClient::new(
        settings.instance_url,
        settings.username,
        settings.password_encrypted,
    ) {
        Ok(client) => match client.test_connection().await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "message": "ServiceNow connection successful"
            })),
            Err(e) => {
                log::error!("ServiceNow connection test failed: {}", e);
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("ServiceNow connection failed: {}", e)
                }))
            }
        },
        Err(e) => {
            log::error!("Failed to create ServiceNow client: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow client: {}", e)
            }))
        }
    }
}

/// Get available assignment groups from ServiceNow
pub async fn get_assignment_groups(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get ServiceNow settings
    let settings = match servicenow::get_servicenow_settings(pool.get_ref(), &claims.sub).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "ServiceNow settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get ServiceNow settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow settings"
            }));
        }
    };

    // Create ServiceNow client
    let client = match ServiceNowClient::new(
        settings.instance_url,
        settings.username,
        settings.password_encrypted,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create ServiceNow client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow client: {}", e)
            }));
        }
    };

    // Get assignment groups
    match client.get_assignment_groups().await {
        Ok(groups) => HttpResponse::Ok().json(groups),
        Err(e) => {
            log::error!("Failed to get ServiceNow assignment groups: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get assignment groups: {}", e)
            }))
        }
    }
}

/// Get available categories from ServiceNow
pub async fn get_categories(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get ServiceNow settings
    let settings = match servicenow::get_servicenow_settings(pool.get_ref(), &claims.sub).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "ServiceNow settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get ServiceNow settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow settings"
            }));
        }
    };

    // Create ServiceNow client
    let client = match ServiceNowClient::new(
        settings.instance_url,
        settings.username,
        settings.password_encrypted,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create ServiceNow client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow client: {}", e)
            }));
        }
    };

    // Get categories
    match client.get_categories().await {
        Ok(categories) => HttpResponse::Ok().json(categories),
        Err(e) => {
            log::error!("Failed to get ServiceNow categories: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get categories: {}", e)
            }))
        }
    }
}

/// Create a ServiceNow incident from a vulnerability
pub async fn create_incident(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<CreateServiceNowTicketRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Get vulnerability details
    let vuln = match sqlx::query_as::<_, crate::db::models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?",
    )
    .bind(vuln_id.as_str())
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Vulnerability not found"
            }))
        }
        Err(e) => {
            log::error!("Failed to get vulnerability: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve vulnerability"
            }));
        }
    };

    // Get ServiceNow settings
    let settings = match servicenow::get_servicenow_settings(pool.get_ref(), &claims.sub).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "ServiceNow settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get ServiceNow settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow settings"
            }));
        }
    };

    if !settings.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "ServiceNow integration is disabled"
        }));
    }

    // Create ServiceNow client
    let client = match ServiceNowClient::new(
        settings.instance_url.clone(),
        settings.username,
        settings.password_encrypted,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create ServiceNow client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow client: {}", e)
            }));
        }
    };

    // Format vulnerability description
    let description = format_vulnerability_description(
        &vuln.vulnerability_id,
        &vuln.host_ip,
        vuln.port,
        &vuln.severity,
        vuln.notes.as_deref(),
        None, // CVE IDs would come from vulnerability data
        None, // CVSS score
        None, // Remediation
    );

    // Create short description
    let short_description = format!(
        "[{}] {} on {}",
        vuln.severity.to_uppercase(),
        vuln.vulnerability_id,
        vuln.host_ip
    );

    // Determine impact/urgency
    let impact = severity_to_impact(&vuln.severity);
    let urgency = severity_to_urgency(&vuln.severity);

    // Build incident data
    let incident_data = IncidentData {
        short_description,
        description,
        category: req.category.or(settings.default_category),
        impact,
        urgency,
        assignment_group: req.assignment_group.or(settings.default_assignment_group),
        u_affected_ci: Some(vuln.host_ip.clone()),
        caller_id: None,
    };

    // Create incident
    let ticket_response = match client.create_incident(incident_data).await {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("Failed to create ServiceNow incident: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow incident: {}", e)
            }));
        }
    };

    // Save ticket record to database
    match servicenow::create_servicenow_ticket(
        pool.get_ref(),
        vuln_id.as_str(),
        &ticket_response.number,
        "incident",
        &ticket_response.sys_id,
        &settings.instance_url,
        &claims.sub,
    )
    .await
    {
        Ok(ticket) => {
            log::info!(
                "Created ServiceNow incident {} for vulnerability {}",
                ticket.ticket_number,
                vuln_id
            );
            HttpResponse::Created().json(serde_json::json!({
                "id": ticket.id,
                "ticket_number": ticket.ticket_number,
                "ticket_type": ticket.ticket_type,
                "ticket_url": ticket.ticket_url
            }))
        }
        Err(e) => {
            log::error!("Failed to save ServiceNow ticket record: {}", e);
            // Ticket was created but we failed to save it locally
            HttpResponse::Created().json(serde_json::json!({
                "ticket_number": ticket_response.number,
                "ticket_type": "incident",
                "warning": "Ticket created but failed to save tracking record locally"
            }))
        }
    }
}

/// Create a ServiceNow change request from a vulnerability
pub async fn create_change(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    request: web::Json<CreateServiceNowTicketRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    // Get vulnerability details
    let vuln = match sqlx::query_as::<_, crate::db::models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?",
    )
    .bind(vuln_id.as_str())
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Vulnerability not found"
            }))
        }
        Err(e) => {
            log::error!("Failed to get vulnerability: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve vulnerability"
            }));
        }
    };

    // Get ServiceNow settings
    let settings = match servicenow::get_servicenow_settings(pool.get_ref(), &claims.sub).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "ServiceNow settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get ServiceNow settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow settings"
            }));
        }
    };

    if !settings.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "ServiceNow integration is disabled"
        }));
    }

    // Create ServiceNow client
    let client = match ServiceNowClient::new(
        settings.instance_url.clone(),
        settings.username,
        settings.password_encrypted,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create ServiceNow client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow client: {}", e)
            }));
        }
    };

    // Format vulnerability description
    let description = format_vulnerability_description(
        &vuln.vulnerability_id,
        &vuln.host_ip,
        vuln.port,
        &vuln.severity,
        vuln.notes.as_deref(),
        None,
        None,
        None,
    );

    // Create short description for change request
    let short_description = format!(
        "Remediation: {} on {}",
        vuln.vulnerability_id,
        vuln.host_ip
    );

    // Determine impact/risk from severity
    let impact = severity_to_impact(&vuln.severity);
    let risk = severity_to_impact(&vuln.severity); // Use same mapping for risk

    // Build change data
    let change_data = ChangeData {
        short_description,
        description,
        category: req.category.or(settings.default_category),
        impact,
        risk,
        assignment_group: req.assignment_group.or(settings.default_assignment_group),
        u_affected_ci: Some(vuln.host_ip.clone()),
        requested_by: None,
    };

    // Create change request
    let ticket_response = match client.create_change(change_data).await {
        Ok(resp) => resp,
        Err(e) => {
            log::error!("Failed to create ServiceNow change request: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow change request: {}", e)
            }));
        }
    };

    // Save ticket record to database
    match servicenow::create_servicenow_ticket(
        pool.get_ref(),
        vuln_id.as_str(),
        &ticket_response.number,
        "change",
        &ticket_response.sys_id,
        &settings.instance_url,
        &claims.sub,
    )
    .await
    {
        Ok(ticket) => {
            log::info!(
                "Created ServiceNow change {} for vulnerability {}",
                ticket.ticket_number,
                vuln_id
            );
            HttpResponse::Created().json(serde_json::json!({
                "id": ticket.id,
                "ticket_number": ticket.ticket_number,
                "ticket_type": ticket.ticket_type,
                "ticket_url": ticket.ticket_url
            }))
        }
        Err(e) => {
            log::error!("Failed to save ServiceNow ticket record: {}", e);
            HttpResponse::Created().json(serde_json::json!({
                "ticket_number": ticket_response.number,
                "ticket_type": "change",
                "warning": "Ticket created but failed to save tracking record locally"
            }))
        }
    }
}

/// Get ServiceNow tickets for a vulnerability
pub async fn get_tickets_for_vulnerability(
    pool: web::Data<SqlitePool>,
    vuln_id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match servicenow::get_tickets_for_vulnerability(pool.get_ref(), vuln_id.as_str()).await {
        Ok(tickets) => HttpResponse::Ok().json(tickets),
        Err(e) => {
            log::error!("Failed to get ServiceNow tickets: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow tickets"
            }))
        }
    }
}

/// Get ticket status from ServiceNow
pub async fn get_ticket_status(
    pool: web::Data<SqlitePool>,
    ticket_number: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Get ServiceNow settings
    let settings = match servicenow::get_servicenow_settings(pool.get_ref(), &claims.sub).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "ServiceNow settings not configured"
            }))
        }
        Err(e) => {
            log::error!("Failed to get ServiceNow settings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve ServiceNow settings"
            }));
        }
    };

    // Create ServiceNow client
    let client = match ServiceNowClient::new(
        settings.instance_url,
        settings.username,
        settings.password_encrypted,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to create ServiceNow client: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create ServiceNow client: {}", e)
            }));
        }
    };

    // Get ticket status
    match client.get_ticket_status(ticket_number.as_str()).await {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(e) => {
            log::error!("Failed to get ServiceNow ticket status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get ticket status: {}", e)
            }))
        }
    }
}
