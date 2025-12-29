//! CRM Discovered Assets API
//!
//! Provides endpoints for managing discovered assets from recon scans
//! that are automatically linked to CRM customers.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::crm_asset_sync::{
    get_customer_discovered_assets,
    get_discovered_asset_by_id,
    create_discovered_asset,
    update_discovered_asset,
    delete_discovered_asset,
    get_discovered_assets_summary,
    bulk_update_in_scope,
    CreateDiscoveredAssetRequest,
    UpdateDiscoveredAssetRequest,
};
use crate::web::auth::Claims;
use crate::web::error::ApiError;

/// Query parameters for listing discovered assets
#[derive(Debug, Deserialize)]
pub struct ListAssetsQuery {
    pub asset_type: Option<String>,
    pub is_in_scope: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// List discovered assets for a customer
pub async fn list_customer_assets(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<ListAssetsQuery>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let customer_id = path.into_inner();

    let assets = get_customer_discovered_assets(
        pool.get_ref(),
        &customer_id,
        query.asset_type.as_deref(),
        query.is_in_scope,
        query.limit,
        query.offset,
    ).await?;

    Ok(HttpResponse::Ok().json(assets))
}

/// Get discovered assets summary for a customer
pub async fn get_assets_summary(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let customer_id = path.into_inner();

    let summary = get_discovered_assets_summary(pool.get_ref(), &customer_id).await?;

    Ok(HttpResponse::Ok().json(summary))
}

/// Get a specific discovered asset
pub async fn get_asset(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    match get_discovered_asset_by_id(pool.get_ref(), &asset_id).await? {
        Some(asset) => Ok(HttpResponse::Ok().json(asset)),
        None => Err(ApiError::not_found("Discovered asset not found")),
    }
}

/// Manually add a discovered asset
pub async fn create_asset(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateDiscoveredAssetRequest>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let customer_id = path.into_inner();

    let asset = create_discovered_asset(pool.get_ref(), &customer_id, body.into_inner()).await?;

    Ok(HttpResponse::Created().json(asset))
}

/// Update a discovered asset (set in_scope, notes, etc.)
pub async fn update_asset(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateDiscoveredAssetRequest>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    // Verify asset exists
    if get_discovered_asset_by_id(pool.get_ref(), &asset_id).await?.is_none() {
        return Err(ApiError::not_found("Discovered asset not found"));
    }

    let asset = update_discovered_asset(pool.get_ref(), &asset_id, body.into_inner()).await?;

    Ok(HttpResponse::Ok().json(asset))
}

/// Delete a discovered asset
pub async fn delete_asset(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    if delete_discovered_asset(pool.get_ref(), &asset_id).await? {
        Ok(HttpResponse::NoContent().finish())
    } else {
        Err(ApiError::not_found("Discovered asset not found"))
    }
}

/// Request for bulk scope update
#[derive(Debug, Deserialize)]
pub struct BulkScopeRequest {
    pub asset_ids: Vec<String>,
    pub is_in_scope: bool,
}

/// Bulk update assets' in_scope status
pub async fn bulk_set_scope(
    pool: web::Data<SqlitePool>,
    _path: web::Path<String>,
    body: web::Json<BulkScopeRequest>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse, ApiError> {
    let request = body.into_inner();

    let updated = bulk_update_in_scope(
        pool.get_ref(),
        &request.asset_ids,
        request.is_in_scope,
    ).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "updated": updated
    })))
}
