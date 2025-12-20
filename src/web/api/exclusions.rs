//! Scan Exclusions API endpoints
//!
//! Provides CRUD operations for host/port exclusion rules.
//! Exclusions can be global (automatically applied to all scans) or per-scan.

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::{self, exclusions::{self, ExclusionType}, models::AuditLog};
use crate::web::auth;
use serde::{Deserialize, Serialize};

/// List all exclusions for the current user
#[utoipa::path(
    get,
    path = "/api/exclusions",
    tag = "Exclusions",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of exclusion rules", body = Vec<exclusions::ScanExclusion>),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_exclusions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let exclusions = db::get_user_exclusions(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get exclusions: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to load exclusions")
        })?;

    Ok(HttpResponse::Ok().json(exclusions))
}

/// Get global exclusions for the current user
#[utoipa::path(
    get,
    path = "/api/exclusions/global",
    tag = "Exclusions",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of global exclusion rules", body = Vec<exclusions::ScanExclusion>),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn list_global_exclusions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let exclusions = db::get_global_exclusions(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get global exclusions: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to load global exclusions")
        })?;

    Ok(HttpResponse::Ok().json(exclusions))
}

/// Get a specific exclusion by ID
#[utoipa::path(
    get,
    path = "/api/exclusions/{id}",
    tag = "Exclusions",
    params(
        ("id" = String, Path, description = "Exclusion ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Exclusion rule details", body = exclusions::ScanExclusion),
        (status = 404, description = "Exclusion not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_exclusion(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let exclusion_id = path.into_inner();

    let exclusion = db::get_exclusion_by_id(&pool, &exclusion_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get exclusion: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to load exclusion")
        })?;

    match exclusion {
        Some(exc) if exc.user_id == claims.sub => Ok(HttpResponse::Ok().json(exc)),
        Some(_) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exclusion not found"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exclusion not found"
        }))),
    }
}

/// Create a new exclusion rule
#[utoipa::path(
    post,
    path = "/api/exclusions",
    tag = "Exclusions",
    security(
        ("bearer_auth" = [])
    ),
    request_body = exclusions::CreateExclusionRequest,
    responses(
        (status = 201, description = "Exclusion created", body = exclusions::ScanExclusion),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn create_exclusion(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<exclusions::CreateExclusionRequest>,
) -> Result<HttpResponse> {
    // Validate name
    if request.name.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Exclusion name is required"
        })));
    }

    if request.name.len() > 255 {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Exclusion name too long (max 255 characters)"
        })));
    }

    let exclusion = db::create_exclusion(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create exclusion: {}", e);
            actix_web::error::ErrorBadRequest(e.to_string())
        })?;

    // Create audit log
    let audit_log = AuditLog {
        id: Uuid::new_v4().to_string(),
        user_id: claims.sub.clone(),
        action: "exclusion_created".to_string(),
        target_type: Some("exclusion".to_string()),
        target_id: Some(exclusion.id.clone()),
        details: Some(format!(
            "Created exclusion rule: {} ({}={})",
            exclusion.name, exclusion.exclusion_type, exclusion.value
        )),
        ip_address: None,
        user_agent: None,
        created_at: Utc::now(),
    };
    let _ = db::create_audit_log(&pool, &audit_log).await;

    Ok(HttpResponse::Created().json(exclusion))
}

/// Update an exclusion rule
#[utoipa::path(
    put,
    path = "/api/exclusions/{id}",
    tag = "Exclusions",
    params(
        ("id" = String, Path, description = "Exclusion ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    request_body = exclusions::UpdateExclusionRequest,
    responses(
        (status = 200, description = "Exclusion updated", body = exclusions::ScanExclusion),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Exclusion not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn update_exclusion(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<exclusions::UpdateExclusionRequest>,
) -> Result<HttpResponse> {
    let exclusion_id = path.into_inner();

    // Validate name if provided
    if let Some(ref name) = request.name {
        if name.trim().is_empty() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Exclusion name cannot be empty"
            })));
        }
        if name.len() > 255 {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Exclusion name too long (max 255 characters)"
            })));
        }
    }

    let exclusion = db::update_exclusion(&pool, &exclusion_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update exclusion: {}", e);
            actix_web::error::ErrorBadRequest(e.to_string())
        })?;

    match exclusion {
        Some(exc) => {
            // Create audit log
            let audit_log = AuditLog {
                id: Uuid::new_v4().to_string(),
                user_id: claims.sub.clone(),
                action: "exclusion_updated".to_string(),
                target_type: Some("exclusion".to_string()),
                target_id: Some(exclusion_id.clone()),
                details: Some(format!("Updated exclusion rule: {}", exc.name)),
                ip_address: None,
                user_agent: None,
                created_at: Utc::now(),
            };
            let _ = db::create_audit_log(&pool, &audit_log).await;

            Ok(HttpResponse::Ok().json(exc))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exclusion not found"
        }))),
    }
}

/// Delete an exclusion rule
#[utoipa::path(
    delete,
    path = "/api/exclusions/{id}",
    tag = "Exclusions",
    params(
        ("id" = String, Path, description = "Exclusion ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Exclusion deleted"),
        (status = 404, description = "Exclusion not found"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn delete_exclusion(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let exclusion_id = path.into_inner();

    // Get exclusion details for audit log before deleting
    let exclusion_name = db::get_exclusion_by_id(&pool, &exclusion_id)
        .await
        .ok()
        .flatten()
        .map(|e| e.name)
        .unwrap_or_else(|| "Unknown".to_string());

    let deleted = db::delete_exclusion(&pool, &exclusion_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete exclusion: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete exclusion")
        })?;

    if deleted {
        // Create audit log
        let audit_log = AuditLog {
            id: Uuid::new_v4().to_string(),
            user_id: claims.sub.clone(),
            action: "exclusion_deleted".to_string(),
            target_type: Some("exclusion".to_string()),
            target_id: Some(exclusion_id.clone()),
            details: Some(format!("Deleted exclusion rule: {}", exclusion_name)),
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        };
        let _ = db::create_audit_log(&pool, &audit_log).await;

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Exclusion deleted successfully"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Exclusion not found"
        })))
    }
}

/// Request to validate an exclusion value
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ValidateExclusionRequest {
    pub exclusion_type: String,
    pub value: String,
}

/// Response from exclusion validation
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ValidateExclusionResponse {
    pub valid: bool,
    pub error: Option<String>,
    pub normalized_value: Option<String>,
}

/// Validate an exclusion value without creating it
#[utoipa::path(
    post,
    path = "/api/exclusions/validate",
    tag = "Exclusions",
    security(
        ("bearer_auth" = [])
    ),
    request_body = ValidateExclusionRequest,
    responses(
        (status = 200, description = "Validation result", body = ValidateExclusionResponse),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn validate_exclusion(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<ValidateExclusionRequest>,
) -> Result<HttpResponse> {
    // Validate exclusion type
    if ExclusionType::from_str(&request.exclusion_type).is_none() {
        return Ok(HttpResponse::Ok().json(ValidateExclusionResponse {
            valid: false,
            error: Some(format!(
                "Invalid exclusion type: {}. Valid types are: host, cidr, hostname, port, port_range",
                request.exclusion_type
            )),
            normalized_value: None,
        }));
    }

    // Validate value using the same validation function as create
    match validate_exclusion_value(&request.exclusion_type, &request.value) {
        Ok(normalized) => Ok(HttpResponse::Ok().json(ValidateExclusionResponse {
            valid: true,
            error: None,
            normalized_value: Some(normalized),
        })),
        Err(e) => Ok(HttpResponse::Ok().json(ValidateExclusionResponse {
            valid: false,
            error: Some(e),
            normalized_value: None,
        })),
    }
}

/// Validate exclusion value and return normalized form
fn validate_exclusion_value(exclusion_type: &str, value: &str) -> std::result::Result<String, String> {
    let value = value.trim();

    if value.is_empty() {
        return Err("Exclusion value cannot be empty".to_string());
    }

    match exclusion_type {
        "host" => {
            // Must be a valid IP address
            match value.parse::<std::net::IpAddr>() {
                Ok(ip) => Ok(ip.to_string()),
                Err(_) => Err(format!(
                    "Invalid host IP address: {}. Must be a valid IPv4 or IPv6 address",
                    value
                )),
            }
        }
        "cidr" => {
            // Must be a valid CIDR notation with explicit prefix
            if !value.contains('/') {
                return Err(format!(
                    "Invalid CIDR notation: {}. Must include subnet prefix (e.g., 192.168.1.0/24)",
                    value
                ));
            }
            match value.parse::<ipnetwork::IpNetwork>() {
                Ok(network) => Ok(network.to_string()),
                Err(_) => Err(format!(
                    "Invalid CIDR notation: {}. Example: 192.168.1.0/24",
                    value
                )),
            }
        }
        "hostname" => {
            // Allow wildcards in hostname patterns
            let pattern = value.replace('*', "x"); // Replace wildcards for validation
            if is_valid_hostname_pattern(&pattern) {
                Ok(value.to_lowercase())
            } else {
                Err(format!(
                    "Invalid hostname pattern: {}. Examples: *.internal.com, server.local",
                    value
                ))
            }
        }
        "port" => {
            // Must be a valid port number
            match value.parse::<u16>() {
                Ok(p) if p > 0 => Ok(p.to_string()),
                _ => Err(format!(
                    "Invalid port number: {}. Must be between 1 and 65535",
                    value
                )),
            }
        }
        "port_range" => {
            // Must be in format "start-end"
            let parts: Vec<&str> = value.split('-').collect();
            if parts.len() != 2 {
                return Err(format!(
                    "Invalid port range format: {}. Must be in format 'start-end' (e.g., 1-1000)",
                    value
                ));
            }
            let start: u16 = parts[0].trim().parse().map_err(|_| {
                format!("Invalid start port in range: {}", parts[0])
            })?;
            let end: u16 = parts[1].trim().parse().map_err(|_| {
                format!("Invalid end port in range: {}", parts[1])
            })?;
            if start == 0 || start > end {
                return Err(format!(
                    "Invalid port range: start ({}) must be >= 1 and <= end ({})",
                    start, end
                ));
            }
            Ok(format!("{}-{}", start, end))
        }
        _ => Err(format!("Unknown exclusion type: {}", exclusion_type)),
    }
}

/// Validate hostname pattern (allows wildcards)
fn is_valid_hostname_pattern(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    let labels: Vec<&str> = hostname.split('.').collect();

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }

        // Each label must start and end with alphanumeric (after wildcard replacement)
        let first_char = match label.chars().next() {
            Some(c) => c,
            None => return false,
        };
        let last_char = match label.chars().last() {
            Some(c) => c,
            None => return false,
        };

        if !first_char.is_alphanumeric() || !last_char.is_alphanumeric() {
            return false;
        }

        // Each label can only contain alphanumeric and hyphens
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Request for bulk importing exclusions
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkImportExclusionsRequest {
    /// The exclusion type to apply to all values
    pub exclusion_type: String,
    /// List of values to import (one per line or comma-separated)
    pub values: String,
    /// Whether to make all imported exclusions global
    pub is_global: bool,
    /// Optional name prefix for the imported exclusions
    pub name_prefix: Option<String>,
}

/// Response from bulk import
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkImportExclusionsResponse {
    pub imported: i32,
    pub failed: i32,
    pub errors: Vec<String>,
    pub created: Vec<exclusions::ScanExclusion>,
}

/// Bulk import exclusions from a list
#[utoipa::path(
    post,
    path = "/api/exclusions/bulk-import",
    tag = "Exclusions",
    security(
        ("bearer_auth" = [])
    ),
    request_body = BulkImportExclusionsRequest,
    responses(
        (status = 200, description = "Import results", body = BulkImportExclusionsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn bulk_import_exclusions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<BulkImportExclusionsRequest>,
) -> Result<HttpResponse> {
    // Validate exclusion type
    if ExclusionType::from_str(&request.exclusion_type).is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!(
                "Invalid exclusion type: {}. Valid types are: host, cidr, hostname, port, port_range",
                request.exclusion_type
            )
        })));
    }

    // Parse values (split by comma, newline, or semicolon)
    let values: Vec<&str> = request.values
        .split(|c| c == ',' || c == '\n' || c == ';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if values.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No values provided for import"
        })));
    }

    let name_prefix = request.name_prefix.as_deref().unwrap_or("Imported");
    let mut imported = 0;
    let mut failed = 0;
    let mut errors = Vec::new();
    let mut created = Vec::new();

    for (idx, value) in values.iter().enumerate() {
        // Validate the value
        match validate_exclusion_value(&request.exclusion_type, value) {
            Ok(normalized) => {
                // Create the exclusion
                let create_req = exclusions::CreateExclusionRequest {
                    name: format!("{} {}", name_prefix, idx + 1),
                    description: Some(format!("Bulk imported {}", request.exclusion_type)),
                    exclusion_type: request.exclusion_type.clone(),
                    value: normalized,
                    is_global: request.is_global,
                };

                match db::create_exclusion(&pool, &claims.sub, &create_req).await {
                    Ok(exc) => {
                        imported += 1;
                        created.push(exc);
                    }
                    Err(e) => {
                        failed += 1;
                        errors.push(format!("Failed to create '{}': {}", value, e));
                    }
                }
            }
            Err(e) => {
                failed += 1;
                errors.push(format!("Invalid value '{}': {}", value, e));
            }
        }
    }

    // Create audit log for bulk import
    if imported > 0 {
        let audit_log = AuditLog {
            id: Uuid::new_v4().to_string(),
            user_id: claims.sub.clone(),
            action: "exclusions_bulk_imported".to_string(),
            target_type: Some("exclusion".to_string()),
            target_id: None,
            details: Some(format!(
                "Bulk imported {} {} exclusions ({} failed)",
                imported, request.exclusion_type, failed
            )),
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        };
        let _ = db::create_audit_log(&pool, &audit_log).await;
    }

    Ok(HttpResponse::Ok().json(BulkImportExclusionsResponse {
        imported,
        failed,
        errors,
        created,
    }))
}

/// Configure routes for exclusions API
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/exclusions")
            .route("", web::get().to(list_exclusions))
            .route("", web::post().to(create_exclusion))
            .route("/global", web::get().to(list_global_exclusions))
            .route("/validate", web::post().to(validate_exclusion))
            .route("/bulk-import", web::post().to(bulk_import_exclusions))
            .route("/{id}", web::get().to(get_exclusion))
            .route("/{id}", web::put().to(update_exclusion))
            .route("/{id}", web::delete().to(delete_exclusion)),
    );
}
