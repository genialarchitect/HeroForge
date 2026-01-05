//! Plugin Management API endpoints
//!
//! This module provides REST API endpoints for managing plugins:
//! - List installed plugins
//! - Install from file or URL
//! - Enable/disable plugins
//! - Uninstall plugins
//! - Manage plugin settings

#![allow(dead_code)]

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::io::Write;

use crate::db;
use crate::plugins::types::{
    InstallPluginRequest, PluginResponse, PluginType, UpdatePluginSettingsRequest,
};
use crate::plugins::{PluginLoader, PluginRegistry};
use crate::web::auth;

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct PluginListResponse {
    plugins: Vec<PluginResponse>,
    total: usize,
}

#[derive(Debug, Serialize)]
struct PluginStatsResponse {
    total: i64,
    enabled: i64,
    disabled: i64,
    error: i64,
    by_type: std::collections::HashMap<String, i64>,
}

#[derive(Debug, Serialize)]
struct InstallResponse {
    plugin: PluginResponse,
    message: String,
}

#[derive(Debug, Serialize)]
struct ValidationResponse {
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

// ============================================================================
// Query Parameters
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PluginListQuery {
    /// Filter by plugin type
    pub plugin_type: Option<String>,
    /// Filter by status
    pub status: Option<String>,
    /// Search query
    pub search: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// GET /api/plugins - List all installed plugins
pub async fn list_plugins(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<PluginListQuery>,
) -> Result<HttpResponse> {
    let plugins = if let Some(ref search) = query.search {
        db::plugins::search_plugins(&pool, search)
            .await
            .map_err(|e| {
                log::error!("Failed to search plugins: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to search plugins")
            })?
    } else if let Some(ref type_str) = query.plugin_type {
        let plugin_type: PluginType = type_str.parse().map_err(|_| {
            actix_web::error::ErrorBadRequest("Invalid plugin type")
        })?;
        db::plugins::list_plugins_by_type(&pool, plugin_type)
            .await
            .map_err(|e| {
                log::error!("Failed to list plugins: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to list plugins")
            })?
    } else {
        db::plugins::list_plugins(&pool)
            .await
            .map_err(|e| {
                log::error!("Failed to list plugins: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to list plugins")
            })?
    };

    // Filter by status if specified
    let plugins: Vec<_> = if let Some(ref status) = query.status {
        plugins
            .into_iter()
            .filter(|p| p.status.to_lowercase() == status.to_lowercase())
            .collect()
    } else {
        plugins
    };

    // Convert to response format
    let responses: Vec<PluginResponse> = plugins
        .into_iter()
        .filter_map(|p| p.try_into().ok())
        .collect();

    let total = responses.len();

    Ok(HttpResponse::Ok().json(PluginListResponse {
        plugins: responses,
        total,
    }))
}

/// GET /api/plugins/stats - Get plugin statistics
pub async fn get_plugin_stats(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let count = db::plugins::get_plugin_count(&pool)
        .await
        .map_err(|e| {
            log::error!("Failed to get plugin stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get plugin stats")
        })?;

    Ok(HttpResponse::Ok().json(PluginStatsResponse {
        total: count.total,
        enabled: count.enabled,
        disabled: count.disabled,
        error: count.error,
        by_type: count.by_type,
    }))
}

/// GET /api/plugins/types - Get available plugin types
pub async fn get_plugin_types() -> Result<HttpResponse> {
    #[derive(Serialize)]
    struct PluginTypeInfo {
        id: String,
        name: String,
        description: String,
    }

    let types = vec![
        PluginTypeInfo {
            id: "scanner".to_string(),
            name: "Scanner".to_string(),
            description: "Plugins that discover hosts, ports, or services".to_string(),
        },
        PluginTypeInfo {
            id: "detector".to_string(),
            name: "Detector".to_string(),
            description: "Plugins that identify vulnerabilities or misconfigurations".to_string(),
        },
        PluginTypeInfo {
            id: "reporter".to_string(),
            name: "Reporter".to_string(),
            description: "Plugins that generate custom report formats".to_string(),
        },
        PluginTypeInfo {
            id: "integration".to_string(),
            name: "Integration".to_string(),
            description: "Plugins that connect to external services".to_string(),
        },
    ];

    Ok(HttpResponse::Ok().json(types))
}

/// GET /api/plugins/{id} - Get a specific plugin
pub async fn get_plugin(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();

    let plugin = db::plugins::get_plugin_by_id(&pool, &plugin_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get plugin: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get plugin")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Plugin not found"))?;

    let response: PluginResponse = plugin.try_into().map_err(|e: anyhow::Error| {
        log::error!("Failed to convert plugin: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to convert plugin")
    })?;

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/plugins/install - Install a plugin from URL
pub async fn install_plugin_from_url(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<InstallPluginRequest>,
) -> Result<HttpResponse> {
    // Check admin permission
    let has_permission = db::has_permission(&pool, &claims.sub, "can_manage_settings")
        .await
        .unwrap_or(false);

    if !has_permission {
        return Err(actix_web::error::ErrorForbidden(
            "Admin permission required to install plugins",
        ));
    }

    let url = request.url.as_ref().ok_or_else(|| {
        actix_web::error::ErrorBadRequest("URL is required for URL-based installation")
    })?;

    let loader = PluginLoader::new();
    let registry = PluginRegistry::new(pool.get_ref().clone(), loader);

    let plugin = registry
        .install_from_url(url, &claims.sub, request.enable)
        .await
        .map_err(|e| {
            log::error!("Failed to install plugin: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Failed to install plugin: {}", e))
        })?;

    let response: PluginResponse = plugin.try_into().map_err(|e: anyhow::Error| {
        log::error!("Failed to convert plugin: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to convert plugin")
    })?;

    Ok(HttpResponse::Created().json(InstallResponse {
        plugin: response,
        message: "Plugin installed successfully".to_string(),
    }))
}

/// POST /api/plugins/upload - Install a plugin from uploaded file
pub async fn upload_plugin(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    mut payload: Multipart,
) -> Result<HttpResponse> {
    // Check admin permission
    let has_permission = db::has_permission(&pool, &claims.sub, "can_manage_settings")
        .await
        .unwrap_or(false);

    if !has_permission {
        return Err(actix_web::error::ErrorForbidden(
            "Admin permission required to install plugins",
        ));
    }

    // Create temp file path
    let temp_path = std::env::temp_dir().join(format!("plugin_upload_{}.zip", uuid::Uuid::new_v4()));
    let mut temp_file = std::fs::File::create(&temp_path).map_err(|e| {
        log::error!("Failed to create temp file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create temp file")
    })?;

    let mut enable = true;

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| {
            log::error!("Multipart error: {}", e);
            actix_web::error::ErrorBadRequest("Invalid multipart data")
        })?;

        let field_name = field
            .content_disposition()
            .and_then(|cd| cd.get_name().map(|s| s.to_string()))
            .unwrap_or_default();

        match field_name.as_str() {
            "file" => {
                while let Some(chunk) = field.next().await {
                    let data = chunk.map_err(|e| {
                        log::error!("Error reading chunk: {}", e);
                        actix_web::error::ErrorBadRequest("Error reading file")
                    })?;
                    temp_file.write_all(&data).map_err(|e| {
                        log::error!("Error writing chunk: {}", e);
                        actix_web::error::ErrorInternalServerError("Error writing file")
                    })?;
                }
            }
            "enable" => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    let chunk = chunk.map_err(|_| {
                        actix_web::error::ErrorBadRequest("Invalid form data")
                    })?;
                    data.extend_from_slice(&chunk);
                }
                if let Ok(s) = String::from_utf8(data) {
                    enable = s.to_lowercase() == "true" || s == "1";
                }
            }
            _ => {}
        }
    }

    let loader = PluginLoader::new();
    let registry = PluginRegistry::new(pool.get_ref().clone(), loader);

    let plugin = registry
        .install_from_file(&temp_path, &claims.sub, enable)
        .await
        .map_err(|e| {
            log::error!("Failed to install plugin: {}", e);
            let _ = std::fs::remove_file(&temp_path);
            actix_web::error::ErrorInternalServerError(format!("Failed to install plugin: {}", e))
        })?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    let response: PluginResponse = plugin.try_into().map_err(|e: anyhow::Error| {
        log::error!("Failed to convert plugin: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to convert plugin")
    })?;

    Ok(HttpResponse::Created().json(InstallResponse {
        plugin: response,
        message: "Plugin installed successfully".to_string(),
    }))
}

/// POST /api/plugins/validate - Validate a plugin package without installing
pub async fn validate_plugin(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    mut payload: Multipart,
) -> Result<HttpResponse> {
    // Check admin permission
    let has_permission = db::has_permission(&pool, &claims.sub, "can_manage_settings")
        .await
        .unwrap_or(false);

    if !has_permission {
        return Err(actix_web::error::ErrorForbidden(
            "Admin permission required to validate plugins",
        ));
    }

    // Create temp file path
    let temp_path = std::env::temp_dir().join(format!("plugin_validate_{}.zip", uuid::Uuid::new_v4()));
    let mut temp_file = std::fs::File::create(&temp_path).map_err(|e| {
        log::error!("Failed to create temp file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create temp file")
    })?;

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| {
            log::error!("Multipart error: {}", e);
            actix_web::error::ErrorBadRequest("Invalid multipart data")
        })?;

        let field_name = field
            .content_disposition()
            .and_then(|cd| cd.get_name().map(|s| s.to_string()))
            .unwrap_or_default();

        if field_name == "file" {
            while let Some(chunk) = field.next().await {
                let data = chunk.map_err(|e| {
                    log::error!("Error reading chunk: {}", e);
                    actix_web::error::ErrorBadRequest("Error reading file")
                })?;
                temp_file.write_all(&data).map_err(|e| {
                    log::error!("Error writing chunk: {}", e);
                    actix_web::error::ErrorInternalServerError("Error writing file")
                })?;
            }
        }
    }

    let loader = PluginLoader::new();
    let result = loader
        .validate_package(&temp_path)
        .await
        .map_err(|e| {
            log::error!("Failed to validate plugin: {}", e);
            let _ = std::fs::remove_file(&temp_path);
            actix_web::error::ErrorInternalServerError(format!("Failed to validate plugin: {}", e))
        })?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    Ok(HttpResponse::Ok().json(ValidationResponse {
        valid: result.valid,
        errors: result.errors,
        warnings: result.warnings,
    }))
}

/// POST /api/plugins/{id}/enable - Enable a plugin
pub async fn enable_plugin(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();

    // Check admin permission
    let has_permission = db::has_permission(&pool, &claims.sub, "can_manage_settings")
        .await
        .unwrap_or(false);

    if !has_permission {
        return Err(actix_web::error::ErrorForbidden(
            "Admin permission required to enable plugins",
        ));
    }

    let loader = PluginLoader::new();
    let registry = PluginRegistry::new(pool.get_ref().clone(), loader);

    let plugin = registry.enable(&plugin_id).await.map_err(|e| {
        log::error!("Failed to enable plugin: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to enable plugin: {}", e))
    })?;

    // Log audit
    db::log_audit(
        &pool,
        &claims.sub,
        "plugin.enabled",
        Some("plugin"),
        Some(&plugin_id),
        None,
        None,
    )
    .await
    .ok();

    let response: PluginResponse = plugin.try_into().map_err(|e: anyhow::Error| {
        log::error!("Failed to convert plugin: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to convert plugin")
    })?;

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/plugins/{id}/disable - Disable a plugin
pub async fn disable_plugin(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();

    // Check admin permission
    let has_permission = db::has_permission(&pool, &claims.sub, "can_manage_settings")
        .await
        .unwrap_or(false);

    if !has_permission {
        return Err(actix_web::error::ErrorForbidden(
            "Admin permission required to disable plugins",
        ));
    }

    let loader = PluginLoader::new();
    let registry = PluginRegistry::new(pool.get_ref().clone(), loader);

    let plugin = registry.disable(&plugin_id).await.map_err(|e| {
        log::error!("Failed to disable plugin: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to disable plugin: {}", e))
    })?;

    // Log audit
    db::log_audit(
        &pool,
        &claims.sub,
        "plugin.disabled",
        Some("plugin"),
        Some(&plugin_id),
        None,
        None,
    )
    .await
    .ok();

    let response: PluginResponse = plugin.try_into().map_err(|e: anyhow::Error| {
        log::error!("Failed to convert plugin: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to convert plugin")
    })?;

    Ok(HttpResponse::Ok().json(response))
}

/// DELETE /api/plugins/{id} - Uninstall a plugin
pub async fn uninstall_plugin(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();

    // Check admin permission
    let has_permission = db::has_permission(&pool, &claims.sub, "can_manage_settings")
        .await
        .unwrap_or(false);

    if !has_permission {
        return Err(actix_web::error::ErrorForbidden(
            "Admin permission required to uninstall plugins",
        ));
    }

    let loader = PluginLoader::new();
    let registry = PluginRegistry::new(pool.get_ref().clone(), loader);

    registry.uninstall(&plugin_id).await.map_err(|e| {
        log::error!("Failed to uninstall plugin: {}", e);
        actix_web::error::ErrorInternalServerError(format!("Failed to uninstall plugin: {}", e))
    })?;

    // Log audit
    db::log_audit(
        &pool,
        &claims.sub,
        "plugin.uninstalled",
        Some("plugin"),
        Some(&plugin_id),
        None,
        None,
    )
    .await
    .ok();

    Ok(HttpResponse::NoContent().finish())
}

/// GET /api/plugins/{id}/settings - Get plugin settings for current user
pub async fn get_plugin_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();

    let settings = db::plugins::get_plugin_settings(&pool, &plugin_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get plugin settings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get plugin settings")
        })?;

    Ok(HttpResponse::Ok().json(settings.unwrap_or(serde_json::Value::Object(
        serde_json::Map::new(),
    ))))
}

/// PUT /api/plugins/{id}/settings - Update plugin settings for current user
pub async fn update_plugin_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<UpdatePluginSettingsRequest>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();

    // Verify plugin exists
    let _plugin = db::plugins::get_plugin_by_id(&pool, &plugin_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get plugin: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get plugin")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Plugin not found"))?;

    db::plugins::update_plugin_settings(&pool, &plugin_id, &claims.sub, request.settings.clone())
        .await
        .map_err(|e| {
            log::error!("Failed to update plugin settings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update plugin settings")
        })?;

    Ok(HttpResponse::Ok().json(request.settings.clone()))
}

/// DELETE /api/plugins/{id}/settings - Delete plugin settings for current user
pub async fn delete_plugin_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();

    db::plugins::delete_plugin_settings(&pool, &plugin_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete plugin settings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete plugin settings")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Marketplace Handlers
// ============================================================================

use crate::plugins::marketplace::{
    PluginMarketplace, MarketplaceSearchFilters, MarketplaceSortField, SortOrder,
};

/// Query parameters for marketplace search
#[derive(Debug, Deserialize)]
pub struct MarketplaceSearchQuery {
    /// Search query
    pub q: Option<String>,
    /// Filter by plugin type
    pub plugin_type: Option<String>,
    /// Filter by certified only
    pub certified: Option<bool>,
    /// Minimum rating
    pub min_rating: Option<f32>,
    /// Filter by tags (comma-separated)
    pub tags: Option<String>,
    /// Filter by author
    pub author: Option<String>,
    /// Sort by field
    pub sort_by: Option<String>,
    /// Sort order (asc/desc)
    pub order: Option<String>,
    /// Page number
    pub page: Option<u32>,
    /// Results per page
    pub per_page: Option<u32>,
}

/// GET /api/plugins/marketplace/search - Search the plugin marketplace
pub async fn marketplace_search(
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<MarketplaceSearchQuery>,
) -> Result<HttpResponse> {
    let marketplace = PluginMarketplace::new();

    let search_query = query.q.as_deref().unwrap_or("");

    let filters = MarketplaceSearchFilters {
        plugin_type: query.plugin_type.clone(),
        certified_only: query.certified,
        min_rating: query.min_rating,
        tags: query.tags.as_ref().map(|t| t.split(',').map(|s| s.trim().to_string()).collect()),
        author: query.author.clone(),
        sort_by: query.sort_by.as_deref().map(|s| match s {
            "downloads" => MarketplaceSortField::Downloads,
            "rating" => MarketplaceSortField::Rating,
            "updated_at" => MarketplaceSortField::UpdatedAt,
            "created_at" => MarketplaceSortField::CreatedAt,
            "name" => MarketplaceSortField::Name,
            _ => MarketplaceSortField::Downloads,
        }),
        sort_order: query.order.as_deref().map(|s| match s {
            "asc" => SortOrder::Asc,
            _ => SortOrder::Desc,
        }),
        page: query.page,
        per_page: query.per_page,
    };

    let results = marketplace
        .search_with_filters(search_query, filters)
        .await
        .map_err(|e| {
            log::error!("Marketplace search failed: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Marketplace search failed: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(results))
}

/// GET /api/plugins/marketplace/featured - Get featured plugins
pub async fn marketplace_featured(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let marketplace = PluginMarketplace::new();

    let plugins = marketplace
        .get_featured()
        .await
        .map_err(|e| {
            log::error!("Failed to get featured plugins: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get featured plugins")
        })?;

    Ok(HttpResponse::Ok().json(plugins))
}

/// GET /api/plugins/marketplace/stats - Get marketplace statistics
pub async fn marketplace_stats(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let marketplace = PluginMarketplace::new();

    let stats = marketplace
        .get_stats()
        .await
        .map_err(|e| {
            log::error!("Failed to get marketplace stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get marketplace stats")
        })?;

    Ok(HttpResponse::Ok().json(stats))
}

/// GET /api/plugins/marketplace/{id} - Get plugin details from marketplace
pub async fn marketplace_get_plugin(
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();
    let marketplace = PluginMarketplace::new();

    let details = marketplace
        .get_plugin_details(&plugin_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get plugin details: {}", e);
            actix_web::error::ErrorNotFound(format!("Plugin not found: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(details))
}

/// Request body for marketplace install
#[derive(Debug, Deserialize)]
pub struct MarketplaceInstallRequest {
    pub plugin_id: String,
    pub version: Option<String>,
}

/// POST /api/plugins/marketplace/install - Install a plugin from the marketplace
pub async fn marketplace_install(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<MarketplaceInstallRequest>,
) -> Result<HttpResponse> {
    let marketplace = PluginMarketplace::new();

    // Download plugin package
    let package_data = marketplace
        .download_plugin(&body.plugin_id, body.version.as_deref())
        .await
        .map_err(|e| {
            log::error!("Failed to download plugin: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Failed to download plugin: {}", e))
        })?;

    // Write to temporary file
    let temp_dir = std::env::temp_dir().join("heroforge_marketplace");
    std::fs::create_dir_all(&temp_dir).map_err(|e| {
        log::error!("Failed to create temp dir: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create temp directory")
    })?;

    let temp_path = temp_dir.join(format!("{}.zip", body.plugin_id));
    std::fs::write(&temp_path, &package_data).map_err(|e| {
        log::error!("Failed to write plugin file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to write plugin file")
    })?;

    // Install using registry
    let loader = PluginLoader::new();
    let registry = PluginRegistry::new(pool.get_ref().clone(), loader);

    let plugin = registry
        .install_from_file(&temp_path, &claims.sub, true)
        .await
        .map_err(|e| {
            log::error!("Failed to install plugin from marketplace: {}", e);
            let _ = std::fs::remove_file(&temp_path);
            actix_web::error::ErrorInternalServerError(format!("Failed to install plugin: {}", e))
        })?;

    // Clean up
    let _ = std::fs::remove_file(&temp_path);

    let response: PluginResponse = plugin.try_into().map_err(|e: anyhow::Error| {
        log::error!("Failed to convert plugin: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to convert plugin")
    })?;

    Ok(HttpResponse::Ok().json(InstallResponse {
        plugin: response,
        message: format!("Successfully installed {} from marketplace", body.plugin_id),
    }))
}

/// GET /api/plugins/marketplace/updates - Check for plugin updates
pub async fn marketplace_check_updates(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Get all installed plugins
    let installed = db::plugins::list_plugins(&pool)
        .await
        .map_err(|e| {
            log::error!("Failed to list installed plugins: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list plugins")
        })?;

    // Build list of (plugin_id, version) tuples
    let installed_refs: Vec<(&str, &str)> = installed
        .iter()
        .map(|p| (p.id.as_str(), p.version.as_str()))
        .collect();

    let marketplace = PluginMarketplace::new();
    let updates = marketplace
        .check_updates(&installed_refs)
        .await
        .map_err(|e| {
            log::error!("Failed to check for updates: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to check for updates")
        })?;

    Ok(HttpResponse::Ok().json(updates))
}

/// POST /api/plugins/marketplace/update/{id} - Update a plugin to latest version
pub async fn marketplace_update_plugin(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let plugin_id = path.into_inner();
    let marketplace = PluginMarketplace::new();

    // Get latest version info
    let details = marketplace
        .get_plugin_details(&plugin_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get plugin details: {}", e);
            actix_web::error::ErrorNotFound(format!("Plugin not found: {}", e))
        })?;

    let latest_version = details.versions.first()
        .map(|v| v.version.as_str())
        .unwrap_or(&details.plugin.version);

    // Download and install latest version
    let package_data = marketplace
        .download_plugin(&plugin_id, Some(latest_version))
        .await
        .map_err(|e| {
            log::error!("Failed to download plugin: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Failed to download plugin: {}", e))
        })?;

    // Write to temporary file
    let temp_dir = std::env::temp_dir().join("heroforge_marketplace");
    std::fs::create_dir_all(&temp_dir).map_err(|e| {
        log::error!("Failed to create temp dir: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create temp directory")
    })?;

    let temp_path = temp_dir.join(format!("{}.zip", plugin_id));
    std::fs::write(&temp_path, &package_data).map_err(|e| {
        log::error!("Failed to write plugin file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to write plugin file")
    })?;

    // Uninstall old version first
    let loader = PluginLoader::new();
    let registry = PluginRegistry::new(pool.get_ref().clone(), loader);

    let _ = registry.uninstall(&plugin_id).await;

    // Install new version
    let plugin = registry
        .install_from_file(&temp_path, &claims.sub, true)
        .await
        .map_err(|e| {
            log::error!("Failed to install plugin update: {}", e);
            let _ = std::fs::remove_file(&temp_path);
            actix_web::error::ErrorInternalServerError(format!("Failed to update plugin: {}", e))
        })?;

    // Clean up
    let _ = std::fs::remove_file(&temp_path);

    let response: PluginResponse = plugin.try_into().map_err(|e: anyhow::Error| {
        log::error!("Failed to convert plugin: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to convert plugin")
    })?;

    Ok(HttpResponse::Ok().json(InstallResponse {
        plugin: response,
        message: format!("Successfully updated {} to version {}", plugin_id, latest_version),
    }))
}

/// Configure plugin routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/plugins")
            .route("", web::get().to(list_plugins))
            .route("/stats", web::get().to(get_plugin_stats))
            .route("/types", web::get().to(get_plugin_types))
            .route("/install", web::post().to(install_plugin_from_url))
            .route("/upload", web::post().to(upload_plugin))
            .route("/validate", web::post().to(validate_plugin))
            // Marketplace endpoints
            .route("/marketplace/search", web::get().to(marketplace_search))
            .route("/marketplace/featured", web::get().to(marketplace_featured))
            .route("/marketplace/stats", web::get().to(marketplace_stats))
            .route("/marketplace/install", web::post().to(marketplace_install))
            .route("/marketplace/updates", web::get().to(marketplace_check_updates))
            .route("/marketplace/{id}", web::get().to(marketplace_get_plugin))
            .route("/marketplace/update/{id}", web::post().to(marketplace_update_plugin))
            // Plugin-specific endpoints
            .route("/{id}", web::get().to(get_plugin))
            .route("/{id}", web::delete().to(uninstall_plugin))
            .route("/{id}/enable", web::post().to(enable_plugin))
            .route("/{id}/disable", web::post().to(disable_plugin))
            .route("/{id}/settings", web::get().to(get_plugin_settings))
            .route("/{id}/settings", web::put().to(update_plugin_settings))
            .route("/{id}/settings", web::delete().to(delete_plugin_settings)),
    );
}
