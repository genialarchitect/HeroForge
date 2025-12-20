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

// ============================================================================
// Asset Tags API Endpoints
// ============================================================================

/// Query parameters for listing assets with tag filtering
#[derive(Debug, Deserialize)]
pub struct AssetTagListQuery {
    status: Option<String>,
    tag_ids: Option<String>, // Comma-separated tag IDs
}

/// Get all asset tags for the current user
pub async fn get_asset_tags(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let tags = assets::get_user_asset_tags_with_counts(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset tags: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(tags))
}

/// Create a new asset tag
pub async fn create_asset_tag(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateAssetTagRequest>,
) -> Result<HttpResponse> {
    // Validate color format (hex color)
    if !request.color.starts_with('#') || request.color.len() != 7 {
        return Err(actix_web::error::ErrorBadRequest("Invalid color format. Use hex format like #22c55e"));
    }

    // Validate category
    let valid_categories = ["environment", "criticality", "owner", "department", "location", "compliance", "custom"];
    if !valid_categories.contains(&request.category.to_lowercase().as_str()) {
        return Err(actix_web::error::ErrorBadRequest(
            "Invalid category. Must be one of: environment, criticality, owner, department, location, compliance, custom"
        ));
    }

    let tag = assets::create_asset_tag(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create asset tag: {}", e);
            if e.to_string().contains("UNIQUE constraint failed") {
                actix_web::error::ErrorConflict("A tag with this name already exists")
            } else {
                actix_web::error::ErrorInternalServerError("Failed to create tag. Please try again.")
            }
        })?;

    Ok(HttpResponse::Created().json(tag))
}

/// Get a specific asset tag by ID
pub async fn get_asset_tag(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    tag_id: web::Path<String>,
) -> Result<HttpResponse> {
    let tag = assets::get_asset_tag_by_id(&pool, &tag_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset tag: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match tag {
        Some(t) => Ok(HttpResponse::Ok().json(t)),
        None => Err(actix_web::error::ErrorNotFound("Tag not found")),
    }
}

/// Update an asset tag
pub async fn update_asset_tag(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    tag_id: web::Path<String>,
    request: web::Json<models::UpdateAssetTagRequest>,
) -> Result<HttpResponse> {
    // Check if tag exists
    let existing = assets::get_asset_tag_by_id(&pool, &tag_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Database error in update_asset_tag: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    if existing.is_none() {
        return Err(actix_web::error::ErrorNotFound("Tag not found"));
    }

    // Validate color if provided
    if let Some(ref color) = request.color {
        if !color.starts_with('#') || color.len() != 7 {
            return Err(actix_web::error::ErrorBadRequest("Invalid color format. Use hex format like #22c55e"));
        }
    }

    // Validate category if provided
    if let Some(ref category) = request.category {
        let valid_categories = ["environment", "criticality", "owner", "department", "location", "compliance", "custom"];
        if !valid_categories.contains(&category.to_lowercase().as_str()) {
            return Err(actix_web::error::ErrorBadRequest(
                "Invalid category. Must be one of: environment, criticality, owner, department, location, compliance, custom"
            ));
        }
    }

    let updated = assets::update_asset_tag(&pool, &tag_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update asset tag: {}", e);
            actix_web::error::ErrorInternalServerError("Update failed. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete an asset tag
pub async fn delete_asset_tag(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    tag_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Check if tag exists
    let existing = assets::get_asset_tag_by_id(&pool, &tag_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Database error in delete_asset_tag: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    if existing.is_none() {
        return Err(actix_web::error::ErrorNotFound("Tag not found"));
    }

    let deleted = assets::delete_asset_tag(&pool, &tag_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete asset tag: {}", e);
            actix_web::error::ErrorInternalServerError("Delete failed. Please try again.")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Tag deleted successfully" })))
    } else {
        Err(actix_web::error::ErrorNotFound("Tag not found"))
    }
}

/// Add tags to an asset
pub async fn add_tags_to_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
    request: web::Json<models::AddAssetTagsRequest>,
) -> Result<HttpResponse> {
    assets::add_tags_to_asset(&pool, &asset_id, &request.tag_ids, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to add tags to asset: {}", e);
            if e.to_string().contains("Asset not found") {
                actix_web::error::ErrorNotFound("Asset not found")
            } else {
                actix_web::error::ErrorInternalServerError("Failed to add tags. Please try again.")
            }
        })?;

    // Return the updated asset with tags
    let asset_detail = assets::get_asset_detail_with_tags(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch updated asset: {}", e);
            actix_web::error::ErrorInternalServerError("Tags added but failed to fetch updated asset.")
        })?;

    match asset_detail {
        Some(detail) => Ok(HttpResponse::Ok().json(detail)),
        None => Err(actix_web::error::ErrorNotFound("Asset not found")),
    }
}

/// Remove a tag from an asset
pub async fn remove_tag_from_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (asset_id, tag_id) = path.into_inner();

    let removed = assets::remove_tag_from_asset(&pool, &asset_id, &tag_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to remove tag from asset: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to remove tag. Please try again.")
        })?;

    if removed {
        // Return the updated asset with tags
        let asset_detail = assets::get_asset_detail_with_tags(&pool, &asset_id, &claims.sub)
            .await
            .map_err(|e| {
                log::error!("Failed to fetch updated asset: {}", e);
                actix_web::error::ErrorInternalServerError("Tag removed but failed to fetch updated asset.")
            })?;

        match asset_detail {
            Some(detail) => Ok(HttpResponse::Ok().json(detail)),
            None => Err(actix_web::error::ErrorNotFound("Asset not found")),
        }
    } else {
        Err(actix_web::error::ErrorNotFound("Asset or tag not found"))
    }
}

/// Get asset with tags by ID
pub async fn get_asset_with_tags(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse> {
    let asset_detail = assets::get_asset_detail_with_tags(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset with tags: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match asset_detail {
        Some(detail) => Ok(HttpResponse::Ok().json(detail)),
        None => Err(actix_web::error::ErrorNotFound("Asset not found")),
    }
}

/// Get assets filtered by tags
pub async fn get_assets_by_tags(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AssetTagListQuery>,
) -> Result<HttpResponse> {
    // Parse tag IDs if provided
    let tag_ids: Vec<String> = query.tag_ids.as_ref().map(|t| {
        t.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }).unwrap_or_default();

    let assets_list = assets::get_assets_by_tags(
        &pool,
        &claims.sub,
        &tag_ids,
        query.status.as_deref(),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assets by tags: {}", e);
        actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
    })?;

    Ok(HttpResponse::Ok().json(assets_list))
}

// ============================================================================
// Asset Groups API Endpoints
// ============================================================================

/// Query parameters for listing assets by group
#[derive(Debug, Deserialize)]
pub struct AssetGroupListQuery {
    status: Option<String>,
    group_id: Option<String>,
}

/// Get all asset groups for the current user
pub async fn get_asset_groups(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let groups = assets::get_user_asset_groups_with_counts(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset groups: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(groups))
}

/// Create a new asset group
pub async fn create_asset_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::CreateAssetGroupRequest>,
) -> Result<HttpResponse> {
    // Validate color format (hex color)
    if !request.color.starts_with('#') || request.color.len() != 7 {
        return Err(actix_web::error::ErrorBadRequest("Invalid color format. Use hex format like #3b82f6"));
    }

    let group = assets::create_asset_group(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create asset group: {}", e);
            if e.to_string().contains("UNIQUE constraint failed") {
                actix_web::error::ErrorConflict("A group with this name already exists")
            } else {
                actix_web::error::ErrorInternalServerError("Failed to create group. Please try again.")
            }
        })?;

    Ok(HttpResponse::Created().json(group))
}

/// Get a specific asset group by ID
pub async fn get_asset_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    group_id: web::Path<String>,
) -> Result<HttpResponse> {
    let group_detail = assets::get_asset_group_with_members(&pool, &group_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset group: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match group_detail {
        Some(detail) => Ok(HttpResponse::Ok().json(detail)),
        None => Err(actix_web::error::ErrorNotFound("Asset group not found")),
    }
}

/// Update an asset group
pub async fn update_asset_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    group_id: web::Path<String>,
    request: web::Json<models::UpdateAssetGroupRequest>,
) -> Result<HttpResponse> {
    // Check if group exists
    let existing = assets::get_asset_group_by_id(&pool, &group_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Database error in update_asset_group: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    if existing.is_none() {
        return Err(actix_web::error::ErrorNotFound("Asset group not found"));
    }

    // Validate color if provided
    if let Some(ref color) = request.color {
        if !color.starts_with('#') || color.len() != 7 {
            return Err(actix_web::error::ErrorBadRequest("Invalid color format. Use hex format like #3b82f6"));
        }
    }

    let updated = assets::update_asset_group(&pool, &group_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update asset group: {}", e);
            actix_web::error::ErrorInternalServerError("Update failed. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete an asset group
pub async fn delete_asset_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    group_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Check if group exists
    let existing = assets::get_asset_group_by_id(&pool, &group_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Database error in delete_asset_group: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    if existing.is_none() {
        return Err(actix_web::error::ErrorNotFound("Asset group not found"));
    }

    let deleted = assets::delete_asset_group(&pool, &group_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete asset group: {}", e);
            actix_web::error::ErrorInternalServerError("Delete failed. Please try again.")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Asset group deleted successfully" })))
    } else {
        Err(actix_web::error::ErrorNotFound("Asset group not found"))
    }
}

/// Add assets to a group
pub async fn add_assets_to_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    group_id: web::Path<String>,
    request: web::Json<models::AddAssetsToGroupRequest>,
) -> Result<HttpResponse> {
    assets::add_assets_to_group(&pool, &group_id, &request.asset_ids, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to add assets to group: {}", e);
            if e.to_string().contains("Asset group not found") {
                actix_web::error::ErrorNotFound("Asset group not found")
            } else {
                actix_web::error::ErrorInternalServerError("Failed to add assets. Please try again.")
            }
        })?;

    // Return the updated group with members
    let group_detail = assets::get_asset_group_with_members(&pool, &group_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch updated group: {}", e);
            actix_web::error::ErrorInternalServerError("Assets added but failed to fetch updated group.")
        })?;

    match group_detail {
        Some(detail) => Ok(HttpResponse::Ok().json(detail)),
        None => Err(actix_web::error::ErrorNotFound("Asset group not found")),
    }
}

/// Remove an asset from a group
pub async fn remove_asset_from_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (group_id, asset_id) = path.into_inner();

    let removed = assets::remove_asset_from_group(&pool, &group_id, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to remove asset from group: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to remove asset. Please try again.")
        })?;

    if removed {
        // Return the updated group with members
        let group_detail = assets::get_asset_group_with_members(&pool, &group_id, &claims.sub)
            .await
            .map_err(|e| {
                log::error!("Failed to fetch updated group: {}", e);
                actix_web::error::ErrorInternalServerError("Asset removed but failed to fetch updated group.")
            })?;

        match group_detail {
            Some(detail) => Ok(HttpResponse::Ok().json(detail)),
            None => Err(actix_web::error::ErrorNotFound("Asset group not found")),
        }
    } else {
        Err(actix_web::error::ErrorNotFound("Asset group or asset not found"))
    }
}

/// Get assets filtered by group
pub async fn get_assets_by_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AssetGroupListQuery>,
) -> Result<HttpResponse> {
    let group_id = query.group_id.as_ref().ok_or_else(|| {
        actix_web::error::ErrorBadRequest("group_id query parameter is required")
    })?;

    let assets_list = assets::get_assets_by_group(
        &pool,
        &claims.sub,
        group_id,
        query.status.as_deref(),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assets by group: {}", e);
        actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
    })?;

    Ok(HttpResponse::Ok().json(assets_list))
}

/// Get asset with full details (tags and groups)
pub async fn get_asset_full(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    asset_id: web::Path<String>,
) -> Result<HttpResponse> {
    let asset_detail = assets::get_asset_detail_full(&pool, &asset_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch asset with full details: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    match asset_detail {
        Some(detail) => Ok(HttpResponse::Ok().json(detail)),
        None => Err(actix_web::error::ErrorNotFound("Asset not found")),
    }
}
