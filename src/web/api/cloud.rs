//! Cloud Infrastructure Scanning API Endpoints
//!
//! This module provides REST API endpoints for cloud security scanning:
//! - POST /api/cloud/scans - Create and start a cloud scan
//! - GET /api/cloud/scans - List cloud scans for the current user
//! - GET /api/cloud/scans/{id} - Get a specific cloud scan with summary
//! - DELETE /api/cloud/scans/{id} - Delete a cloud scan
//! - GET /api/cloud/scans/{id}/findings - Get findings for a scan
//! - GET /api/cloud/scans/{id}/resources - Get resources discovered in a scan
//! - PATCH /api/cloud/findings/{id}/status - Update finding status

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::cloud::{
    self, CreateCloudScanRequest, ListCloudScansQuery, ListFindingsQuery,
    UpdateFindingStatusRequest,
};
use crate::scanner::cloud::{
    run_cloud_scan, CloudProvider, CloudScanConfig, CloudScanStatus, CloudScanType,
    FindingStatus,
};
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request body for creating a cloud scan
#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub scan_types: Vec<String>,
    pub credentials_id: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Response for scan creation
#[derive(Debug, Serialize)]
pub struct CreateScanResponse {
    pub id: String,
    pub message: String,
}

/// Response for scan details
#[derive(Debug, Serialize)]
pub struct ScanDetailResponse {
    pub scan: crate::scanner::cloud::CloudScan,
    pub summary: Option<crate::scanner::cloud::CloudScanSummary>,
}

// ============================================================================
// API Handlers
// ============================================================================

/// Create and start a new cloud scan
///
/// POST /api/cloud/scans
pub async fn create_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateScanRequest>,
) -> Result<HttpResponse> {
    log::info!(
        "Creating cloud scan for user {} - provider: {}",
        claims.sub,
        request.provider
    );

    // Validate provider
    let provider: CloudProvider = request.provider.parse().map_err(|e: String| {
        log::warn!("Invalid provider: {}", e);
        actix_web::error::ErrorBadRequest(format!("Invalid provider: {}", e))
    })?;

    // Parse scan types, default to All if empty
    let scan_types: Vec<CloudScanType> = if request.scan_types.is_empty() {
        vec![CloudScanType::All]
    } else {
        request
            .scan_types
            .iter()
            .map(|s| match s.to_lowercase().as_str() {
                "iam" => CloudScanType::Iam,
                "storage" => CloudScanType::Storage,
                "compute" => CloudScanType::Compute,
                "network" => CloudScanType::Network,
                "database" => CloudScanType::Database,
                "all" => CloudScanType::All,
                _ => CloudScanType::All,
            })
            .collect()
    };

    // Create the database record
    let db_request = CreateCloudScanRequest {
        name: request.name.clone(),
        provider: request.provider.clone(),
        regions: request.regions.clone(),
        scan_types: request
            .scan_types
            .iter()
            .map(|s| s.to_lowercase())
            .collect(),
        credentials_id: request.credentials_id.clone(),
        customer_id: request.customer_id.clone(),
        engagement_id: request.engagement_id.clone(),
    };

    let scan = cloud::create_cloud_scan(&pool, &claims.sub, &db_request)
        .await
        .map_err(|e| {
            log::error!("Failed to create cloud scan: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to create scan. Please try again later.",
            )
        })?;

    let scan_id = scan.id.clone();

    // Clone what we need for the background task
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let regions = request.regions.clone();

    // Spawn background task to run the scan
    tokio::spawn(async move {
        log::info!("Starting background cloud scan: {}", scan_id_clone);

        // Update status to running
        if let Err(e) =
            cloud::update_cloud_scan_status(&pool_clone, &scan_id_clone, CloudScanStatus::Running, None)
                .await
        {
            log::error!("Failed to update scan status to running: {}", e);
            return;
        }

        // Lookup credentials from database if provided
        let credentials_id = if let Some(cred_id) = &db_request.credentials_id {
            // Verify credentials exist and belong to user
            let cred_exists = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM cloud_credentials WHERE id = ?"
            )
            .bind(cred_id)
            .fetch_one(&pool_clone)
            .await
            .unwrap_or(0);

            if cred_exists > 0 {
                Some(cred_id.clone())
            } else {
                log::warn!("Credentials {} not found, proceeding without", cred_id);
                None
            }
        } else {
            // Try to find default credentials for this provider
            let default_creds = sqlx::query_scalar::<_, String>(
                "SELECT id FROM cloud_credentials WHERE provider = ? AND is_default = 1 LIMIT 1"
            )
            .bind(format!("{:?}", provider).to_lowercase())
            .fetch_optional(&pool_clone)
            .await
            .ok()
            .flatten();

            if default_creds.is_some() {
                log::info!("Using default credentials for provider {:?}", provider);
            }

            default_creds
        };

        // Create scan config
        let config = CloudScanConfig {
            provider,
            regions: if regions.is_empty() {
                get_default_regions(provider)
            } else {
                regions
            },
            scan_types,
            credentials_id,
        };

        // Run the scan
        match run_cloud_scan(&config).await {
            Ok((resources, mut findings)) => {
                log::info!(
                    "Cloud scan {} completed: {} resources, {} findings",
                    scan_id_clone,
                    resources.len(),
                    findings.len()
                );

                // Set scan_id on all findings
                for finding in &mut findings {
                    finding.scan_id = scan_id_clone.clone();
                }

                // Store resources
                if let Err(e) = cloud::store_cloud_resources(&pool_clone, &scan_id_clone, &resources).await {
                    log::error!("Failed to store cloud resources: {}", e);
                }

                // Store findings
                if let Err(e) = cloud::store_cloud_findings(&pool_clone, &scan_id_clone, &findings).await {
                    log::error!("Failed to store cloud findings: {}", e);
                }

                // Update counts
                if let Err(e) = cloud::update_cloud_scan_counts(
                    &pool_clone,
                    &scan_id_clone,
                    resources.len() as i32,
                    findings.len() as i32,
                )
                .await
                {
                    log::error!("Failed to update scan counts: {}", e);
                }

                // Mark as completed
                if let Err(e) =
                    cloud::update_cloud_scan_status(&pool_clone, &scan_id_clone, CloudScanStatus::Completed, None)
                        .await
                {
                    log::error!("Failed to update scan status to completed: {}", e);
                }
            }
            Err(e) => {
                log::error!("Cloud scan {} failed: {}", scan_id_clone, e);

                // Mark as failed
                if let Err(update_err) = cloud::update_cloud_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    CloudScanStatus::Failed,
                    Some(&e.to_string()),
                )
                .await
                {
                    log::error!("Failed to update scan status to failed: {}", update_err);
                }
            }
        }
    });

    Ok(HttpResponse::Accepted().json(CreateScanResponse {
        id: scan_id,
        message: "Cloud scan started successfully".to_string(),
    }))
}

/// List cloud scans for the current user
///
/// GET /api/cloud/scans
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListCloudScansQuery>,
) -> Result<HttpResponse> {
    let scans = cloud::list_cloud_scans(&pool, &claims.sub, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to list cloud scans: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve scans. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Get a specific cloud scan with summary
///
/// GET /api/cloud/scans/{id}
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = cloud::get_cloud_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get cloud scan: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve scan. Please try again later.",
            )
        })?;

    match scan {
        Some(scan) => {
            let summary = cloud::get_cloud_scan_summary(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to get scan summary: {}", e);
                    actix_web::error::ErrorInternalServerError(
                        "Failed to retrieve scan summary. Please try again later.",
                    )
                })?;

            Ok(HttpResponse::Ok().json(ScanDetailResponse { scan, summary }))
        }
        None => Err(actix_web::error::ErrorNotFound("Cloud scan not found")),
    }
}

/// Delete a cloud scan
///
/// DELETE /api/cloud/scans/{id}
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = cloud::delete_cloud_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete cloud scan: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to delete scan. Please try again later.",
            )
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Cloud scan deleted successfully"
        })))
    } else {
        Err(actix_web::error::ErrorNotFound("Cloud scan not found"))
    }
}

/// Get findings for a cloud scan
///
/// GET /api/cloud/scans/{id}/findings
pub async fn get_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
    query: web::Query<ListFindingsQuery>,
) -> Result<HttpResponse> {
    // Verify scan ownership
    let scan = cloud::get_cloud_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve findings. Please try again later.",
            )
        })?;

    if scan.is_none() {
        return Err(actix_web::error::ErrorNotFound("Cloud scan not found"));
    }

    let findings = cloud::get_cloud_findings(&pool, &scan_id, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to get cloud findings: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve findings. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(findings))
}

/// Get resources discovered in a cloud scan
///
/// GET /api/cloud/scans/{id}/resources
pub async fn get_resources(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Verify scan ownership
    let scan = cloud::get_cloud_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve resources. Please try again later.",
            )
        })?;

    if scan.is_none() {
        return Err(actix_web::error::ErrorNotFound("Cloud scan not found"));
    }

    let resources = cloud::get_cloud_resources(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get cloud resources: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve resources. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(resources))
}

/// Update finding status
///
/// PATCH /api/cloud/findings/{id}/status
pub async fn update_finding_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    finding_id: web::Path<String>,
    request: web::Json<UpdateFindingStatusRequest>,
) -> Result<HttpResponse> {
    // Get the finding to verify it exists and get scan_id
    let finding = cloud::get_cloud_finding(&pool, &finding_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get finding: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to update finding. Please try again later.",
            )
        })?;

    let finding = match finding {
        Some(f) => f,
        None => return Err(actix_web::error::ErrorNotFound("Finding not found")),
    };

    // Verify scan ownership
    let scan = cloud::get_cloud_scan(&pool, &finding.scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to update finding. Please try again later.",
            )
        })?;

    if scan.is_none() {
        return Err(actix_web::error::ErrorForbidden(
            "You do not have permission to update this finding",
        ));
    }

    // Parse the new status
    let new_status: FindingStatus = request.status.parse().map_err(|e: String| {
        actix_web::error::ErrorBadRequest(format!("Invalid status: {}", e))
    })?;

    // Update the status
    let updated = cloud::update_finding_status(&pool, &finding_id, new_status)
        .await
        .map_err(|e| {
            log::error!("Failed to update finding status: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to update finding. Please try again later.",
            )
        })?;

    if updated {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Finding status updated successfully",
            "status": request.status
        })))
    } else {
        Err(actix_web::error::ErrorNotFound("Finding not found"))
    }
}

/// Get available cloud providers
///
/// GET /api/cloud/providers
pub async fn list_providers() -> Result<HttpResponse> {
    let providers = serde_json::json!([
        {
            "id": "aws",
            "name": "Amazon Web Services",
            "description": "Scan AWS resources including IAM, S3, EC2, RDS, and Security Groups",
            "regions": get_default_regions(CloudProvider::Aws),
            "scan_types": ["iam", "storage", "compute", "network", "database", "all"]
        },
        {
            "id": "azure",
            "name": "Microsoft Azure",
            "description": "Scan Azure resources including Service Principals, Storage Accounts, VMs, and NSGs",
            "regions": get_default_regions(CloudProvider::Azure),
            "scan_types": ["iam", "storage", "compute", "network", "database", "all"]
        },
        {
            "id": "gcp",
            "name": "Google Cloud Platform",
            "description": "Scan GCP resources including Service Accounts, Cloud Storage, Compute Engine, and Firewall Rules",
            "regions": get_default_regions(CloudProvider::Gcp),
            "scan_types": ["iam", "storage", "compute", "network", "database", "all"]
        }
    ]);

    Ok(HttpResponse::Ok().json(providers))
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure cloud scanning routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/cloud")
            .route("/providers", web::get().to(list_providers))
            .route("/scans", web::post().to(create_scan))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            .route("/scans/{id}/findings", web::get().to(get_findings))
            .route("/scans/{id}/resources", web::get().to(get_resources))
            .route("/findings/{id}/status", web::patch().to(update_finding_status)),
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get default regions for a cloud provider
fn get_default_regions(provider: CloudProvider) -> Vec<String> {
    match provider {
        CloudProvider::Aws => vec![
            "us-east-1".to_string(),
            "us-east-2".to_string(),
            "us-west-1".to_string(),
            "us-west-2".to_string(),
            "eu-west-1".to_string(),
            "eu-central-1".to_string(),
            "ap-southeast-1".to_string(),
            "ap-northeast-1".to_string(),
        ],
        CloudProvider::Azure => vec![
            "eastus".to_string(),
            "eastus2".to_string(),
            "westus".to_string(),
            "westus2".to_string(),
            "westeurope".to_string(),
            "northeurope".to_string(),
            "southeastasia".to_string(),
            "japaneast".to_string(),
        ],
        CloudProvider::Gcp => vec![
            "us-central1".to_string(),
            "us-east1".to_string(),
            "us-west1".to_string(),
            "europe-west1".to_string(),
            "europe-west2".to_string(),
            "asia-east1".to_string(),
            "asia-southeast1".to_string(),
            "australia-southeast1".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_regions() {
        let aws_regions = get_default_regions(CloudProvider::Aws);
        assert!(!aws_regions.is_empty());
        assert!(aws_regions.contains(&"us-east-1".to_string()));

        let azure_regions = get_default_regions(CloudProvider::Azure);
        assert!(!azure_regions.is_empty());
        assert!(azure_regions.contains(&"eastus".to_string()));

        let gcp_regions = get_default_regions(CloudProvider::Gcp);
        assert!(!gcp_regions.is_empty());
        assert!(gcp_regions.contains(&"us-central1".to_string()));
    }
}
