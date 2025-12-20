//! Credential Audit API Endpoints
//!
//! Provides REST API endpoints for credential security audits.
//!
//! **WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.**

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::db::credential_audit::{self, CreateCredentialAuditRequest};
use crate::scanner::credential_audit::{
    CredentialAuditConfig, CredentialAuditEngine, CredentialAuditTarget, CredentialServiceType,
};
use crate::web::auth::Claims;
use crate::web::error::{bad_request, internal_error, not_found, ApiErrorKind};

/// Request to create and run a credential audit
#[derive(Debug, Deserialize, ToSchema)]
pub struct RunCredentialAuditRequest {
    /// Audit name
    pub name: String,
    /// Targets to audit
    pub targets: Vec<TargetSpec>,
    /// Use default credentials only (faster)
    #[serde(default)]
    pub default_creds_only: bool,
    /// Custom credentials to try (username, password pairs)
    #[serde(default)]
    pub custom_credentials: Vec<(String, String)>,
    /// Maximum concurrent connections
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Delay between attempts in milliseconds
    #[serde(default = "default_delay")]
    pub delay_between_attempts_ms: u64,
    /// Maximum attempts per account (to avoid lockouts)
    #[serde(default = "default_max_attempts")]
    pub max_attempts_per_account: usize,
    /// Stop on first successful credential
    #[serde(default = "default_true")]
    pub stop_on_success: bool,
    /// Customer ID (optional)
    pub customer_id: Option<String>,
    /// Engagement ID (optional)
    pub engagement_id: Option<String>,
}

/// Target specification for credential audit
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct TargetSpec {
    /// Host IP or hostname
    pub host: String,
    /// Port number
    pub port: u16,
    /// Service type (ssh, ftp, telnet, mysql, postgresql, redis, rdp, vnc, etc.)
    pub service: String,
    /// Use SSL/TLS
    #[serde(default)]
    pub use_ssl: bool,
    /// Path for web-based services
    pub path: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_max_concurrent() -> usize {
    5
}

fn default_timeout() -> u64 {
    10
}

fn default_delay() -> u64 {
    1000
}

fn default_max_attempts() -> usize {
    3
}

/// Response for credential audit list
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialAuditListResponse {
    pub audits: Vec<credential_audit::CredentialAuditSummary>,
}

/// Response for credential audit detail
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialAuditResponse {
    pub audit: credential_audit::CredentialAuditRecord,
    pub targets: Vec<credential_audit::CredentialAuditTargetRecord>,
}

/// Create and run a credential audit
///
/// POST /api/credential-audit
#[utoipa::path(
    post,
    path = "/api/credential-audit",
    tag = "Credential Audit",
    request_body = RunCredentialAuditRequest,
    responses(
        (status = 201, description = "Audit started"),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Audit failed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_audit(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<RunCredentialAuditRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    // Convert target specs to CredentialAuditTargets
    let mut targets = Vec::new();
    for spec in &body.targets {
        let service_type = CredentialServiceType::from_str(&spec.service)
            .ok_or_else(|| bad_request(format!("Unknown service type: {}", spec.service)))?;

        let mut target = CredentialAuditTarget::new(spec.host.clone(), spec.port, service_type);
        if spec.use_ssl {
            target = target.with_ssl(true);
        }
        if let Some(ref path) = spec.path {
            target = target.with_path(path.clone());
        }
        targets.push(target);
    }

    // Build configuration
    let config = CredentialAuditConfig {
        targets,
        service_types: Vec::new(), // Will test all detected services
        custom_credentials: body.custom_credentials.clone(),
        wordlist_id: None,
        max_concurrent: body.max_concurrent,
        delay_between_attempts_ms: body.delay_between_attempts_ms,
        timeout: std::time::Duration::from_secs(body.timeout_secs),
        max_attempts_per_account: body.max_attempts_per_account,
        stop_on_success: body.stop_on_success,
        default_creds_only: body.default_creds_only,
    };

    // Create the audit record
    let create_req = CreateCredentialAuditRequest {
        name: body.name.clone(),
        config: serde_json::to_value(&config).unwrap_or_default(),
        customer_id: body.customer_id.clone(),
        engagement_id: body.engagement_id.clone(),
    };

    let audit = credential_audit::create_credential_audit(&pool, &claims.sub, &create_req)
        .await
        .map_err(|e| internal_error(format!("Failed to create audit: {}", e)))?;

    // Update status to running
    credential_audit::update_credential_audit_status(&pool, &audit.id, "running")
        .await
        .map_err(|e| internal_error(format!("Failed to update status: {}", e)))?;

    // Spawn the audit in background
    let pool_clone = pool.get_ref().clone();
    let audit_id = audit.id.clone();

    tokio::spawn(async move {
        let engine = CredentialAuditEngine::new(config);

        match engine.run().await {
            Ok(result) => {
                // Store target results
                for target_result in &result.results {
                    let successful_creds = if target_result.successful_credentials.is_empty() {
                        None
                    } else {
                        Some(serde_json::to_string(&target_result.successful_credentials).unwrap_or_default())
                    };

                    let _ = credential_audit::create_credential_audit_target(
                        &pool_clone,
                        &audit_id,
                        &target_result.target.host,
                        target_result.target.port as i32,
                        &target_result.target.service_type.display_name(),
                        target_result.target.use_ssl,
                        target_result.target.path.as_deref(),
                        successful_creds.as_deref(),
                        target_result.failed_attempts as i32,
                        target_result.connection_errors as i32,
                        target_result.error_message.as_deref(),
                    )
                    .await;
                }

                // Build services tested string
                let services: std::collections::HashSet<String> = result
                    .results
                    .iter()
                    .map(|t| t.target.service_type.display_name().to_string())
                    .collect();
                let services_str = services.into_iter().collect::<Vec<_>>().join(",");

                // Update audit with results
                let _ = credential_audit::update_credential_audit_results(
                    &pool_clone,
                    &audit_id,
                    result.summary.total_targets as i32,
                    result.summary.total_attempts as i32,
                    result.summary.successful_logins as i32,
                    result.summary.failed_attempts as i32,
                    result.summary.connection_errors as i32,
                    &services_str,
                    result.duration_secs.unwrap_or(0.0),
                )
                .await;
            }
            Err(e) => {
                let _ = credential_audit::update_credential_audit_error(
                    &pool_clone,
                    &audit_id,
                    &e.to_string(),
                )
                .await;
            }
        }
    });

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": audit.id,
        "status": "running",
        "message": "Credential audit started"
    })))
}

/// List credential audits
///
/// GET /api/credential-audit
#[utoipa::path(
    get,
    path = "/api/credential-audit",
    tag = "Credential Audit",
    params(
        ("status" = Option<String>, Query, description = "Filter by status")
    ),
    responses(
        (status = 200, description = "List of audits", body = CredentialAuditListResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_audits(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> Result<HttpResponse, ApiErrorKind> {
    let status = query.get("status").map(|s| s.as_str());

    let audits = credential_audit::get_user_credential_audits(&pool, &claims.sub, status)
        .await
        .map_err(|e| internal_error(format!("Failed to list audits: {}", e)))?;

    Ok(HttpResponse::Ok().json(CredentialAuditListResponse { audits }))
}

/// Get credential audit detail
///
/// GET /api/credential-audit/{id}
#[utoipa::path(
    get,
    path = "/api/credential-audit/{id}",
    tag = "Credential Audit",
    responses(
        (status = 200, description = "Audit details", body = CredentialAuditResponse),
        (status = 404, description = "Audit not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_audit(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let id = path.into_inner();

    let audit = credential_audit::get_credential_audit_by_id(&pool, &id, &claims.sub)
        .await
        .map_err(|_| not_found("Audit not found"))?;

    let targets = credential_audit::get_credential_audit_targets(&pool, &id)
        .await
        .map_err(|e| internal_error(format!("Failed to get targets: {}", e)))?;

    Ok(HttpResponse::Ok().json(CredentialAuditResponse { audit, targets }))
}

/// Get successful credentials from an audit
///
/// GET /api/credential-audit/{id}/successful
#[utoipa::path(
    get,
    path = "/api/credential-audit/{id}/successful",
    tag = "Credential Audit",
    responses(
        (status = 200, description = "Targets with successful credentials"),
        (status = 404, description = "Audit not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_successful_credentials(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let id = path.into_inner();

    // Verify audit exists and user has access
    let _ = credential_audit::get_credential_audit_by_id(&pool, &id, &claims.sub)
        .await
        .map_err(|_| not_found("Audit not found"))?;

    let targets = credential_audit::get_successful_credential_targets(&pool, &id)
        .await
        .map_err(|e| internal_error(format!("Failed to get targets: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "successful_targets": targets
    })))
}

/// Delete credential audit
///
/// DELETE /api/credential-audit/{id}
#[utoipa::path(
    delete,
    path = "/api/credential-audit/{id}",
    tag = "Credential Audit",
    responses(
        (status = 204, description = "Audit deleted"),
        (status = 404, description = "Audit not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_audit(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let id = path.into_inner();

    let deleted = credential_audit::delete_credential_audit(&pool, &id, &claims.sub)
        .await
        .map_err(|e| internal_error(format!("Failed to delete audit: {}", e)))?;

    if deleted {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(not_found("Audit not found"))
    }
}

/// Configure routes for Credential Audit
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/credential-audit")
            .route("", web::post().to(create_audit))
            .route("", web::get().to(list_audits))
            .route("/{id}", web::get().to(get_audit))
            .route("/{id}/successful", web::get().to(get_successful_credentials))
            .route("/{id}", web::delete().to(delete_audit)),
    );
}
