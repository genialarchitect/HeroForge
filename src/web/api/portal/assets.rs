//! Customer Portal Assets API
//!
//! Provides read-only access for customers to view assets discovered
//! from scans linked to their engagements.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::assets;
use crate::web::api::portal::auth::PortalClaims;
use crate::web::error::ApiError;

/// Query parameters for listing assets
#[derive(Debug, Deserialize)]
pub struct PortalAssetQuery {
    pub status: Option<String>,
}

/// Get all assets for a specific engagement (customer portal)
/// Validates that the customer has access to this engagement
pub async fn get_engagement_assets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<PortalClaims>,
    engagement_id: web::Path<String>,
    query: web::Query<PortalAssetQuery>,
) -> Result<HttpResponse, ApiError> {
    // Verify the engagement belongs to this customer
    let engagement = crate::db::crm::get_engagement_by_id(pool.get_ref(), &engagement_id)
        .await
        .map_err(|_| ApiError::not_found("Engagement not found"))?;

    if engagement.customer_id != claims.customer_id {
        return Err(ApiError::forbidden("You don't have access to this engagement"));
    }

    let assets_list = assets::get_assets_by_engagement(
        &pool,
        &engagement_id,
        query.status.as_deref(),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch engagement assets for portal: {}", e);
        ApiError::internal("Failed to fetch assets")
    })?;

    Ok(HttpResponse::Ok().json(assets_list))
}

/// Get all assets for the customer across all engagements
pub async fn get_customer_assets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<PortalClaims>,
    query: web::Query<PortalAssetQuery>,
) -> Result<HttpResponse, ApiError> {
    let assets_list = assets::get_assets_by_customer(
        &pool,
        &claims.customer_id,
        query.status.as_deref(),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch customer assets for portal: {}", e);
        ApiError::internal("Failed to fetch assets")
    })?;

    Ok(HttpResponse::Ok().json(assets_list))
}

/// Get asset statistics for the customer
pub async fn get_customer_assets_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<PortalClaims>,
) -> Result<HttpResponse, ApiError> {
    let stats = assets::get_customer_asset_stats(
        &pool,
        &claims.customer_id,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch customer asset stats for portal: {}", e);
        ApiError::internal("Failed to fetch asset statistics")
    })?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Get asset statistics for a specific engagement
pub async fn get_engagement_assets_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<PortalClaims>,
    engagement_id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    // Verify the engagement belongs to this customer
    let engagement = crate::db::crm::get_engagement_by_id(pool.get_ref(), &engagement_id)
        .await
        .map_err(|_| ApiError::not_found("Engagement not found"))?;

    if engagement.customer_id != claims.customer_id {
        return Err(ApiError::forbidden("You don't have access to this engagement"));
    }

    let stats = assets::get_engagement_asset_stats(
        &pool,
        &engagement_id,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch engagement asset stats for portal: {}", e);
        ApiError::internal("Failed to fetch asset statistics")
    })?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Get a specific asset by ID (with customer access validation)
pub async fn get_asset_detail(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<PortalClaims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    // Get the asset and verify it belongs to this customer
    let asset = sqlx::query_as::<_, crate::db::models::Asset>(
        "SELECT * FROM assets WHERE id = ?1 AND customer_id = ?2",
    )
    .bind(asset_id.as_str())
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch asset for portal: {}", e);
        ApiError::internal("Failed to fetch asset")
    })?;

    match asset {
        Some(asset) => {
            // Get ports for this asset
            let ports = sqlx::query_as::<_, crate::db::models::AssetPort>(
                "SELECT * FROM asset_ports WHERE asset_id = ?1 ORDER BY port ASC",
            )
            .bind(&asset.id)
            .fetch_all(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to fetch asset ports for portal: {}", e);
                ApiError::internal("Failed to fetch asset details")
            })?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "asset": asset,
                "ports": ports
            })))
        }
        None => Err(ApiError::not_found("Asset not found")),
    }
}
