use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::{models, assets};
use crate::web::auth;

/// Query parameters for listing assets
#[derive(Debug, Deserialize)]
pub struct AssetListQuery {
    status: Option<String>,
    tags: Option<String>, // Comma-separated tags
    days_inactive: Option<i64>,
}

/// Get all assets for the current user
pub async fn get_assets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AssetListQuery>,
) -> Result<HttpResponse> {
    // Parse tags if provided
    let tags: Option<Vec<String>> = query.tags.as_ref().map(|t| {
        t.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    });

    let assets_list = assets::get_user_assets(
        &pool,
        &claims.sub,
        query.status.as_deref(),
        tags.as_deref(),
        query.days_inactive,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assets: {}", e);
        actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
    })?;

    Ok(HttpResponse::Ok().json(assets_list))
}

/// Get a specific asset by ID with details
pub async fn get_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse> {
    let asset_detail = assets::get_asset_detail(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match asset_detail {
        Some(detail) => Ok(HttpResponse::Ok().json(detail)),
        None => Err(actix_web::error::ErrorNotFound("Asset not found")),
    }
}

/// Update asset metadata (status, tags, notes)
pub async fn update_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
    request: web::Json<models::UpdateAssetRequest>,
) -> Result<HttpResponse> {
    // First check if asset exists and belongs to user
    let existing = assets::get_asset_by_id(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Database error in update_asset: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    if existing.is_none() {
        return Err(actix_web::error::ErrorNotFound("Asset not found"));
    }

    let updated = assets::update_asset(&pool, &asset_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update asset: {}", e);
            actix_web::error::ErrorInternalServerError("Update failed. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Get asset history
pub async fn get_asset_history(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse> {
    let history = assets::get_asset_history(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset history: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(history))
}

/// Delete an asset
pub async fn delete_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse> {
    // First check if asset exists and belongs to user
    let existing = assets::get_asset_by_id(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Database error in delete_asset: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    if existing.is_none() {
        return Err(actix_web::error::ErrorNotFound("Asset not found"));
    }

    let deleted = assets::delete_asset(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete asset: {}", e);
            actix_web::error::ErrorInternalServerError("Delete failed. Please try again.")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Asset deleted successfully" })))
    } else {
        Err(actix_web::error::ErrorNotFound("Asset not found"))
    }
}
