use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;

/// Create a new target group
pub async fn create_target_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateTargetGroupRequest>,
) -> Result<HttpResponse> {
    let group = db::create_target_group(&pool, &claims.sub, &request)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to create target group"))?;

    Ok(HttpResponse::Ok().json(group))
}

/// Get all target groups for the current user
pub async fn get_target_groups(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let groups = db::get_user_target_groups(&pool, &claims.sub)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch target groups"))?;

    Ok(HttpResponse::Ok().json(groups))
}

/// Get a specific target group by ID
pub async fn get_target_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    group_id: web::Path<String>,
) -> Result<HttpResponse> {
    let group = db::get_target_group_by_id(&pool, &group_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch target group"))?;

    match group {
        Some(g) => {
            // Verify the group belongs to the user
            if g.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
            Ok(HttpResponse::Ok().json(g))
        }
        None => Err(actix_web::error::ErrorNotFound("Target group not found")),
    }
}

/// Update a target group
pub async fn update_target_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    group_id: web::Path<String>,
    request: web::Json<models::UpdateTargetGroupRequest>,
) -> Result<HttpResponse> {
    // First check if group exists and belongs to user
    let existing = db::get_target_group_by_id(&pool, &group_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Database error"))?;

    match existing {
        Some(g) => {
            if g.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Target group not found")),
    }

    let updated = db::update_target_group(&pool, &group_id, &request)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to update target group"))?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete a target group
pub async fn delete_target_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    group_id: web::Path<String>,
) -> Result<HttpResponse> {
    // First check if group exists and belongs to user
    let existing = db::get_target_group_by_id(&pool, &group_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Database error"))?;

    match existing {
        Some(g) => {
            if g.user_id != claims.sub {
                return Err(actix_web::error::ErrorForbidden("Access denied"));
            }
        }
        None => return Err(actix_web::error::ErrorNotFound("Target group not found")),
    }

    db::delete_target_group(&pool, &group_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to delete target group"))?;

    Ok(HttpResponse::NoContent().finish())
}
