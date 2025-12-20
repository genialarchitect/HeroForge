//! Scan Exclusions API endpoints
//!
//! Provides CRUD operations for host/port exclusion rules.
//! Exclusions can be global (automatically applied to all scans) or per-scan.

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::{self, exclusions, models::AuditLog};
use crate::web::auth;

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

/// Configure routes for exclusions API
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/exclusions")
            .route("", web::get().to(list_exclusions))
            .route("", web::post().to(create_exclusion))
            .route("/global", web::get().to(list_global_exclusions))
            .route("/{id}", web::get().to(get_exclusion))
            .route("/{id}", web::put().to(update_exclusion))
            .route("/{id}", web::delete().to(delete_exclusion)),
    );
}
