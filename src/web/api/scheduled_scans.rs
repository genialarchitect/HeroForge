use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;

/// Create a new scheduled scan
pub async fn create_scheduled_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateScheduledScanRequest>,
) -> Result<HttpResponse> {
    let scan = db::create_scheduled_scan(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create scheduled scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create scheduled scan")
        })?;

    Ok(HttpResponse::Ok().json(scan))
}

/// Get all scheduled scans for the current user
pub async fn get_scheduled_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let scans = db::get_user_scheduled_scans(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scheduled scans: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scheduled scans")
        })?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Get a specific scheduled scan by ID
pub async fn get_scheduled_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = db::get_scheduled_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch scheduled scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch scheduled scan")
        })?;

    match scan {
        Some(s) => {
            // Verify the scan belongs to the user
            if s.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
            Ok(HttpResponse::Ok().json(s))
        }
        None => Err(actix_web::error::ErrorNotFound("Scheduled scan not found")),
    }
}

/// Update a scheduled scan
pub async fn update_scheduled_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
    request: web::Json<models::UpdateScheduledScanRequest>,
) -> Result<HttpResponse> {
    // First check if scan exists and belongs to user
    let existing = db::get_scheduled_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    match existing {
        Some(s) => {
            if s.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Scheduled scan not found")),
    }

    let updated = db::update_scheduled_scan(&pool, &scan_id, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update scheduled scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update scheduled scan")
        })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete a scheduled scan
pub async fn delete_scheduled_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // First check if scan exists and belongs to user
    let existing = db::get_scheduled_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    match existing {
        Some(s) => {
            if s.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Scheduled scan not found")),
    }

    db::delete_scheduled_scan(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete scheduled scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete scheduled scan")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

/// Get execution history for a scheduled scan
pub async fn get_scheduled_scan_history(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // First check if scan exists and belongs to user
    let existing = db::get_scheduled_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    match existing {
        Some(s) => {
            if s.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Scheduled scan not found")),
    }

    // Get execution history
    let history = db::get_execution_history(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch execution history: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch execution history")
        })?;

    Ok(HttpResponse::Ok().json(history))
}
