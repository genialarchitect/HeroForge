//! Cloud Asset Discovery API Endpoints
//!
//! This module provides REST API endpoints for passive cloud asset discovery:
//!
//! - POST /api/recon/cloud/discover - Start cloud asset discovery for a domain
//! - POST /api/recon/cloud/bucket-check - Check specific bucket names
//! - GET /api/recon/cloud/results - List discovery results
//! - GET /api/recon/cloud/results/{id} - Get a specific discovery result
//! - GET /api/recon/cloud/results/{id}/assets - Get assets from a discovery
//! - DELETE /api/recon/cloud/results/{id} - Delete a discovery result

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::cloud_discovery::{
    self, BucketCheckRequest, CreateCloudDiscoveryRequest, ListCloudDiscoveriesQuery,
};
use crate::scanner::cloud::cloud_discovery::{
    check_bucket_names, run_cloud_discovery, CloudDiscoveryConfig, CloudDiscoveryStatus,
    CloudProviderType,
};
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for discovery creation
#[derive(Debug, Serialize)]
pub struct CreateDiscoveryResponse {
    pub id: String,
    pub message: String,
}

/// Response for bucket check
#[derive(Debug, Serialize)]
pub struct BucketCheckResponse {
    pub buckets_checked: usize,
    pub assets_found: usize,
    pub assets: Vec<crate::scanner::cloud::cloud_discovery::CloudAsset>,
}

/// Query parameters for filtering assets
#[derive(Debug, Deserialize)]
pub struct AssetFilterQuery {
    pub provider: Option<String>,
    pub asset_type: Option<String>,
    pub accessibility: Option<String>,
}

// ============================================================================
// API Handlers
// ============================================================================

/// Start a cloud asset discovery scan for a domain
///
/// POST /api/recon/cloud/discover
pub async fn discover_cloud_assets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateCloudDiscoveryRequest>,
) -> Result<HttpResponse> {
    log::info!(
        "Starting cloud asset discovery for domain: {} (user: {})",
        request.domain,
        claims.sub
    );

    // Validate domain
    if request.domain.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("Domain is required"));
    }

    // Build configuration
    let providers: Vec<CloudProviderType> = if request.providers.is_empty() {
        vec![
            CloudProviderType::Aws,
            CloudProviderType::Azure,
            CloudProviderType::Gcp,
            CloudProviderType::DigitalOcean,
        ]
    } else {
        request
            .providers
            .iter()
            .filter_map(|p| p.parse().ok())
            .collect()
    };

    let config = CloudDiscoveryConfig {
        domain: request.domain.clone(),
        enable_dns_discovery: request.enable_dns_discovery,
        enable_bucket_enumeration: request.enable_bucket_enumeration,
        enable_ct_logs: request.enable_ct_logs,
        custom_bucket_patterns: request.custom_bucket_patterns.clone(),
        providers,
        check_accessibility: request.check_accessibility,
        ..Default::default()
    };

    // Create database record
    let discovery_id =
        cloud_discovery::create_cloud_discovery(&pool, &claims.sub, &request.domain, &config)
            .await
            .map_err(|e| {
                log::error!("Failed to create cloud discovery record: {}", e);
                actix_web::error::ErrorInternalServerError(
                    "Failed to start discovery. Please try again later.",
                )
            })?;

    // Clone values for background task
    let pool_clone = pool.get_ref().clone();
    let discovery_id_clone = discovery_id.clone();

    // Spawn background task to run the discovery
    tokio::spawn(async move {
        log::info!("Starting background cloud discovery: {}", discovery_id_clone);

        // Update status to running
        if let Err(e) = cloud_discovery::update_cloud_discovery_status(
            &pool_clone,
            &discovery_id_clone,
            CloudDiscoveryStatus::Running,
            None,
        )
        .await
        {
            log::error!("Failed to update discovery status to running: {}", e);
            return;
        }

        // Run the discovery
        match run_cloud_discovery(config).await {
            Ok(result) => {
                log::info!(
                    "Cloud discovery {} completed: {} assets found",
                    discovery_id_clone,
                    result.assets.len()
                );

                // Store discovered assets
                if let Err(e) =
                    cloud_discovery::store_cloud_assets(&pool_clone, &discovery_id_clone, &result.assets)
                        .await
                {
                    log::error!("Failed to store cloud assets: {}", e);
                }

                // Update statistics
                if let Err(e) = cloud_discovery::update_cloud_discovery_statistics(
                    &pool_clone,
                    &discovery_id_clone,
                    &result.statistics,
                )
                .await
                {
                    log::error!("Failed to update discovery statistics: {}", e);
                }

                // Mark as completed
                if let Err(e) = cloud_discovery::update_cloud_discovery_status(
                    &pool_clone,
                    &discovery_id_clone,
                    CloudDiscoveryStatus::Completed,
                    None,
                )
                .await
                {
                    log::error!("Failed to update discovery status to completed: {}", e);
                }
            }
            Err(e) => {
                log::error!("Cloud discovery {} failed: {}", discovery_id_clone, e);

                // Mark as failed
                if let Err(update_err) = cloud_discovery::update_cloud_discovery_status(
                    &pool_clone,
                    &discovery_id_clone,
                    CloudDiscoveryStatus::Failed,
                    Some(&e.to_string()),
                )
                .await
                {
                    log::error!("Failed to update discovery status to failed: {}", update_err);
                }
            }
        }
    });

    Ok(HttpResponse::Accepted().json(CreateDiscoveryResponse {
        id: discovery_id,
        message: "Cloud asset discovery started successfully".to_string(),
    }))
}

/// Check specific bucket names across cloud providers
///
/// POST /api/recon/cloud/bucket-check
pub async fn check_buckets(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<BucketCheckRequest>,
) -> Result<HttpResponse> {
    log::info!("Checking {} bucket names", request.bucket_names.len());

    if request.bucket_names.is_empty() {
        return Err(actix_web::error::ErrorBadRequest(
            "At least one bucket name is required",
        ));
    }

    // Limit the number of buckets to check
    if request.bucket_names.len() > 100 {
        return Err(actix_web::error::ErrorBadRequest(
            "Maximum 100 bucket names allowed per request",
        ));
    }

    // Parse providers
    let providers: Vec<CloudProviderType> = if request.providers.is_empty() {
        vec![
            CloudProviderType::Aws,
            CloudProviderType::Azure,
            CloudProviderType::Gcp,
            CloudProviderType::DigitalOcean,
        ]
    } else {
        request
            .providers
            .iter()
            .filter_map(|p| p.parse().ok())
            .collect()
    };

    // Run bucket check
    let assets = check_bucket_names(
        request.bucket_names.clone(),
        providers,
        request.check_accessibility,
    )
    .await
    .map_err(|e| {
        log::error!("Bucket check failed: {}", e);
        actix_web::error::ErrorInternalServerError("Bucket check failed")
    })?;

    Ok(HttpResponse::Ok().json(BucketCheckResponse {
        buckets_checked: request.bucket_names.len(),
        assets_found: assets.len(),
        assets,
    }))
}

/// List cloud discovery results for the current user
///
/// GET /api/recon/cloud/results
pub async fn list_discoveries(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListCloudDiscoveriesQuery>,
) -> Result<HttpResponse> {
    let discoveries = cloud_discovery::list_cloud_discoveries(&pool, &claims.sub, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to list cloud discoveries: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve discoveries. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(discoveries))
}

/// Get a specific cloud discovery result
///
/// GET /api/recon/cloud/results/{id}
pub async fn get_discovery(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    discovery_id: web::Path<String>,
) -> Result<HttpResponse> {
    let discovery = cloud_discovery::get_cloud_discovery(&pool, &discovery_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get cloud discovery: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve discovery. Please try again later.",
            )
        })?;

    match discovery {
        Some(d) => Ok(HttpResponse::Ok().json(d)),
        None => Err(actix_web::error::ErrorNotFound("Cloud discovery not found")),
    }
}

/// Get assets from a cloud discovery
///
/// GET /api/recon/cloud/results/{id}/assets
pub async fn get_discovery_assets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    discovery_id: web::Path<String>,
    query: web::Query<AssetFilterQuery>,
) -> Result<HttpResponse> {
    // Verify ownership
    let discovery = cloud_discovery::get_cloud_discovery(&pool, &discovery_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to verify discovery ownership: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve assets. Please try again later.",
            )
        })?;

    if discovery.is_none() {
        return Err(actix_web::error::ErrorNotFound("Cloud discovery not found"));
    }

    // Get filtered assets
    let assets = cloud_discovery::get_cloud_assets_filtered(
        &pool,
        &discovery_id,
        query.provider.as_deref(),
        query.asset_type.as_deref(),
        query.accessibility.as_deref(),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to get cloud assets: {}", e);
        actix_web::error::ErrorInternalServerError(
            "Failed to retrieve assets. Please try again later.",
        )
    })?;

    Ok(HttpResponse::Ok().json(assets))
}

/// Delete a cloud discovery result
///
/// DELETE /api/recon/cloud/results/{id}
pub async fn delete_discovery(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    discovery_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = cloud_discovery::delete_cloud_discovery(&pool, &discovery_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete cloud discovery: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to delete discovery. Please try again later.",
            )
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Cloud discovery deleted successfully"
        })))
    } else {
        Err(actix_web::error::ErrorNotFound("Cloud discovery not found"))
    }
}

/// Get supported cloud providers
///
/// GET /api/recon/cloud/providers
pub async fn list_providers() -> Result<HttpResponse> {
    let providers = serde_json::json!([
        {
            "id": "aws",
            "name": "Amazon Web Services",
            "services": [
                {"type": "storage_bucket", "name": "S3", "domain": "s3.amazonaws.com"},
                {"type": "cdn_endpoint", "name": "CloudFront", "domain": "cloudfront.net"},
                {"type": "web_application", "name": "Elastic Beanstalk", "domain": "elasticbeanstalk.com"},
                {"type": "api_gateway", "name": "API Gateway", "domain": "execute-api.amazonaws.com"},
                {"type": "load_balancer", "name": "ELB", "domain": "elb.amazonaws.com"}
            ]
        },
        {
            "id": "azure",
            "name": "Microsoft Azure",
            "services": [
                {"type": "storage_bucket", "name": "Blob Storage", "domain": "blob.core.windows.net"},
                {"type": "web_application", "name": "App Service", "domain": "azurewebsites.net"},
                {"type": "cdn_endpoint", "name": "Azure CDN", "domain": "azureedge.net"},
                {"type": "api_gateway", "name": "API Management", "domain": "azure-api.net"},
                {"type": "load_balancer", "name": "Traffic Manager", "domain": "trafficmanager.net"}
            ]
        },
        {
            "id": "gcp",
            "name": "Google Cloud Platform",
            "services": [
                {"type": "storage_bucket", "name": "Cloud Storage", "domain": "storage.googleapis.com"},
                {"type": "web_application", "name": "App Engine", "domain": "appspot.com"},
                {"type": "serverless_function", "name": "Cloud Functions", "domain": "cloudfunctions.net"},
                {"type": "container_service", "name": "Cloud Run", "domain": "run.app"}
            ]
        },
        {
            "id": "digitalocean",
            "name": "DigitalOcean",
            "services": [
                {"type": "storage_bucket", "name": "Spaces", "domain": "digitaloceanspaces.com"},
                {"type": "web_application", "name": "App Platform", "domain": "ondigitalocean.app"}
            ]
        }
    ]);

    Ok(HttpResponse::Ok().json(providers))
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure cloud discovery routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/recon/cloud")
            .route("/providers", web::get().to(list_providers))
            .route("/discover", web::post().to(discover_cloud_assets))
            .route("/bucket-check", web::post().to(check_buckets))
            .route("/results", web::get().to(list_discoveries))
            .route("/results/{id}", web::get().to(get_discovery))
            .route("/results/{id}", web::delete().to(delete_discovery))
            .route("/results/{id}/assets", web::get().to(get_discovery_assets)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_providers_json() {
        // Just ensure the JSON is valid
        let providers = serde_json::json!([
            {"id": "aws", "name": "Amazon Web Services"},
            {"id": "azure", "name": "Microsoft Azure"},
            {"id": "gcp", "name": "Google Cloud Platform"},
        ]);
        assert!(providers.is_array());
    }
}
