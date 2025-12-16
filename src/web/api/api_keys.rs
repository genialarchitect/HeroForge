use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::web::auth;

/// Get all API keys for the current user
pub async fn get_api_keys(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let keys = db::get_user_api_keys(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch API keys: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(keys))
}

/// Create a new API key
pub async fn create_api_key(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateApiKeyRequest>,
) -> Result<HttpResponse> {
    let response = db::create_api_key(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create API key: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create API key. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(response))
}

/// Update an API key (name or permissions)
pub async fn update_api_key(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    key_id: web::Path<String>,
    request: web::Json<models::UpdateApiKeyRequest>,
) -> Result<HttpResponse> {
    // Check if key exists and belongs to user
    let existing = db::get_api_key_by_id(&pool, &key_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch API key: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred.")
        })?;

    if existing.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "API key not found"
        })));
    }

    let updated = db::update_api_key(&pool, &key_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update API key: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update API key.")
        })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete (revoke) an API key
pub async fn delete_api_key(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    key_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = db::delete_api_key(&pool, &key_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete API key: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete API key.")
        })?;

    if !deleted {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "API key not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "API key revoked successfully"
    })))
}
