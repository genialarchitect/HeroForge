//! Container/Kubernetes Security Scanning API Endpoints
//!
//! This module provides REST API endpoints for container security scanning:
//! - POST /api/container/scans - Create and start a container scan
//! - GET /api/container/scans - List container scans for the current user
//! - GET /api/container/scans/{id} - Get a specific container scan with summary
//! - DELETE /api/container/scans/{id} - Delete a container scan
//! - GET /api/container/scans/{id}/findings - Get findings for a scan
//! - GET /api/container/scans/{id}/images - Get images discovered in a scan
//! - GET /api/container/scans/{id}/resources - Get K8s resources discovered in a scan
//! - PATCH /api/container/findings/{id}/status - Update finding status
//! - POST /api/container/analyze-dockerfile - Analyze a Dockerfile
//! - POST /api/container/analyze-manifest - Analyze a K8s manifest

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::container::{
    self, CreateContainerScanRequest, ListContainerScansQuery, ListFindingsQuery,
    UpdateFindingStatusRequest,
};
use crate::scanner::container::{
    run_container_scan, ContainerScanConfig, ContainerScanStatus, ContainerScanType,
    DockerfileAnalysis, FindingStatus, K8sManifestAnalysis,
};
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request body for creating a container scan
#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub name: String,
    #[serde(default)]
    pub scan_types: Vec<String>,
    #[serde(default)]
    pub images: Vec<String>,
    pub registry_url: Option<String>,
    pub registry_username: Option<String>,
    pub registry_password: Option<String>,
    pub dockerfile_content: Option<String>,
    pub manifest_content: Option<String>,
    pub k8s_context: Option<String>,
    pub k8s_namespace: Option<String>,
    #[serde(default)]
    pub demo_mode: bool,
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
    pub scan: crate::scanner::container::ContainerScan,
    pub summary: Option<crate::scanner::container::ContainerScanSummary>,
}

/// Request for Dockerfile analysis
#[derive(Debug, Deserialize)]
pub struct AnalyzeDockerfileRequest {
    pub content: String,
}

/// Request for K8s manifest analysis
#[derive(Debug, Deserialize)]
pub struct AnalyzeManifestRequest {
    pub content: String,
}

// ============================================================================
// API Handlers
// ============================================================================

/// Create and start a new container scan
///
/// POST /api/container/scans
pub async fn create_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateScanRequest>,
) -> Result<HttpResponse> {
    log::info!(
        "Creating container scan for user {} - demo_mode: {}",
        claims.sub,
        request.demo_mode
    );

    // Parse scan types, default to All if empty
    let scan_types: Vec<String> = if request.scan_types.is_empty() {
        vec!["all".to_string()]
    } else {
        request.scan_types.clone()
    };

    // Create the database record
    let db_request = CreateContainerScanRequest {
        name: request.name.clone(),
        scan_types: scan_types.clone(),
        demo_mode: request.demo_mode,
        customer_id: request.customer_id.clone(),
        engagement_id: request.engagement_id.clone(),
    };

    let scan = container::create_container_scan(&pool, &claims.sub, &db_request)
        .await
        .map_err(|e| {
            log::error!("Failed to create container scan: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to create scan. Please try again later.",
            )
        })?;

    let scan_id = scan.id.clone();

    // Clone what we need for the background task
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let images = request.images.clone();
    let registry_url = request.registry_url.clone();
    let registry_username = request.registry_username.clone();
    let registry_password = request.registry_password.clone();
    let dockerfile_content = request.dockerfile_content.clone();
    let manifest_content = request.manifest_content.clone();
    let k8s_context = request.k8s_context.clone();
    let k8s_namespace = request.k8s_namespace.clone();
    let demo_mode = request.demo_mode;
    let name = request.name.clone();
    let customer_id = request.customer_id.clone();
    let engagement_id = request.engagement_id.clone();

    // Convert scan types
    let parsed_scan_types: Vec<ContainerScanType> = scan_types
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    // Spawn background task to run the scan
    tokio::spawn(async move {
        log::info!("Starting background container scan: {}", scan_id_clone);

        // Update status to running
        if let Err(e) = container::update_container_scan_status(
            &pool_clone,
            &scan_id_clone,
            ContainerScanStatus::Running,
            None,
        )
        .await
        {
            log::error!("Failed to update scan status to running: {}", e);
            return;
        }

        // Create scan config
        let config = ContainerScanConfig {
            name,
            scan_types: parsed_scan_types,
            images,
            registry_url,
            registry_username,
            registry_password,
            dockerfile_content,
            manifest_content,
            k8s_context,
            k8s_namespace,
            demo_mode,
            customer_id,
            engagement_id,
        };

        // Run the scan
        match run_container_scan(&config).await {
            Ok((images, resources, mut findings)) => {
                log::info!(
                    "Container scan {} completed: {} images, {} resources, {} findings",
                    scan_id_clone,
                    images.len(),
                    resources.len(),
                    findings.len()
                );

                // Set scan_id on all findings
                for finding in &mut findings {
                    finding.scan_id = scan_id_clone.clone();
                }

                // Calculate counts
                let critical_count = findings.iter()
                    .filter(|f| f.severity == crate::scanner::container::ContainerFindingSeverity::Critical)
                    .count() as i32;
                let high_count = findings.iter()
                    .filter(|f| f.severity == crate::scanner::container::ContainerFindingSeverity::High)
                    .count() as i32;

                // Store images
                if let Err(e) = container::store_container_images(&pool_clone, &scan_id_clone, &images).await {
                    log::error!("Failed to store container images: {}", e);
                }

                // Store resources
                if let Err(e) = container::store_k8s_resources(&pool_clone, &scan_id_clone, &resources).await {
                    log::error!("Failed to store K8s resources: {}", e);
                }

                // Store findings
                if let Err(e) = container::store_container_findings(&pool_clone, &scan_id_clone, &findings).await {
                    log::error!("Failed to store container findings: {}", e);
                }

                // Update counts
                if let Err(e) = container::update_container_scan_counts(
                    &pool_clone,
                    &scan_id_clone,
                    images.len() as i32,
                    resources.len() as i32,
                    findings.len() as i32,
                    critical_count,
                    high_count,
                )
                .await
                {
                    log::error!("Failed to update scan counts: {}", e);
                }

                // Mark as completed
                if let Err(e) = container::update_container_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    ContainerScanStatus::Completed,
                    None,
                )
                .await
                {
                    log::error!("Failed to update scan status to completed: {}", e);
                }
            }
            Err(e) => {
                log::error!("Container scan {} failed: {}", scan_id_clone, e);

                // Mark as failed
                if let Err(update_err) = container::update_container_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    ContainerScanStatus::Failed,
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
        message: "Container scan started successfully".to_string(),
    }))
}

/// List container scans for the current user
///
/// GET /api/container/scans
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListContainerScansQuery>,
) -> Result<HttpResponse> {
    let scans = container::list_container_scans(&pool, &claims.sub, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to list container scans: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve scans. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(scans))
}

/// Get a specific container scan with summary
///
/// GET /api/container/scans/{id}
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = container::get_container_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get container scan: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve scan. Please try again later.",
            )
        })?;

    match scan {
        Some(scan) => {
            let summary = container::get_container_scan_summary(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to get scan summary: {}", e);
                    actix_web::error::ErrorInternalServerError(
                        "Failed to retrieve scan summary. Please try again later.",
                    )
                })?;

            Ok(HttpResponse::Ok().json(ScanDetailResponse { scan, summary }))
        }
        None => Err(actix_web::error::ErrorNotFound("Container scan not found")),
    }
}

/// Delete a container scan
///
/// DELETE /api/container/scans/{id}
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = container::delete_container_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete container scan: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to delete scan. Please try again later.",
            )
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Container scan deleted successfully"
        })))
    } else {
        Err(actix_web::error::ErrorNotFound("Container scan not found"))
    }
}

/// Get findings for a container scan
///
/// GET /api/container/scans/{id}/findings
pub async fn get_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
    query: web::Query<ListFindingsQuery>,
) -> Result<HttpResponse> {
    // Verify scan ownership
    let scan = container::get_container_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve findings. Please try again later.",
            )
        })?;

    if scan.is_none() {
        return Err(actix_web::error::ErrorNotFound("Container scan not found"));
    }

    let findings = container::get_container_findings(&pool, &scan_id, &query)
        .await
        .map_err(|e| {
            log::error!("Failed to get container findings: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve findings. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(findings))
}

/// Get images discovered in a container scan
///
/// GET /api/container/scans/{id}/images
pub async fn get_images(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Verify scan ownership
    let scan = container::get_container_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve images. Please try again later.",
            )
        })?;

    if scan.is_none() {
        return Err(actix_web::error::ErrorNotFound("Container scan not found"));
    }

    let images = container::get_container_images(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get container images: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve images. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(images))
}

/// Get K8s resources discovered in a container scan
///
/// GET /api/container/scans/{id}/resources
pub async fn get_resources(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Verify scan ownership
    let scan = container::get_container_scan(&pool, &scan_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve resources. Please try again later.",
            )
        })?;

    if scan.is_none() {
        return Err(actix_web::error::ErrorNotFound("Container scan not found"));
    }

    let resources = container::get_k8s_resources(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get K8s resources: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to retrieve resources. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(resources))
}

/// Update finding status
///
/// PATCH /api/container/findings/{id}/status
pub async fn update_finding_status(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    finding_id: web::Path<String>,
    request: web::Json<UpdateFindingStatusRequest>,
) -> Result<HttpResponse> {
    // Get the finding to verify it exists
    let finding = container::get_container_finding(&pool, &finding_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get finding: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to update finding. Please try again later.",
            )
        })?;

    if finding.is_none() {
        return Err(actix_web::error::ErrorNotFound("Finding not found"));
    }

    // Parse the new status
    let new_status: FindingStatus = request.status.parse().map_err(|e: String| {
        actix_web::error::ErrorBadRequest(format!("Invalid status: {}", e))
    })?;

    // Update the status
    let updated = container::update_finding_status(&pool, &finding_id, new_status)
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

/// Analyze a Dockerfile for security issues
///
/// POST /api/container/analyze-dockerfile
pub async fn analyze_dockerfile(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<AnalyzeDockerfileRequest>,
) -> Result<HttpResponse> {
    if request.content.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("Dockerfile content is required"));
    }

    let analysis = crate::scanner::container::dockerfile::analyze_dockerfile(&request.content, false)
        .await
        .map_err(|e| {
            log::error!("Failed to analyze Dockerfile: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to analyze Dockerfile. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(analysis))
}

/// Analyze a Kubernetes manifest for security issues
///
/// POST /api/container/analyze-manifest
pub async fn analyze_manifest(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<AnalyzeManifestRequest>,
) -> Result<HttpResponse> {
    if request.content.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("Manifest content is required"));
    }

    let analysis = crate::scanner::container::k8s_manifest::analyze_manifest(&request.content, false)
        .await
        .map_err(|e| {
            log::error!("Failed to analyze K8s manifest: {}", e);
            actix_web::error::ErrorInternalServerError(
                "Failed to analyze manifest. Please try again later.",
            )
        })?;

    Ok(HttpResponse::Ok().json(analysis))
}

/// Get available scan types
///
/// GET /api/container/scan-types
pub async fn list_scan_types() -> Result<HttpResponse> {
    let scan_types = serde_json::json!([
        {
            "id": "docker_image",
            "name": "Docker Image Scan",
            "description": "Scan Docker images for vulnerabilities in packages and dependencies"
        },
        {
            "id": "dockerfile",
            "name": "Dockerfile Analysis",
            "description": "Analyze Dockerfiles for security best practices and misconfigurations"
        },
        {
            "id": "container_runtime",
            "name": "Container Runtime Scan",
            "description": "Scan running containers for privilege escalation and misconfigurations"
        },
        {
            "id": "k8s_manifest",
            "name": "Kubernetes Manifest Analysis",
            "description": "Analyze K8s YAML manifests for RBAC, security contexts, and policy violations"
        },
        {
            "id": "k8s_cluster",
            "name": "Kubernetes Cluster Scan",
            "description": "Security assessment of a live Kubernetes cluster (requires kubectl access)"
        },
        {
            "id": "all",
            "name": "Comprehensive Scan",
            "description": "Run all available scan types"
        }
    ]);

    Ok(HttpResponse::Ok().json(scan_types))
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure container scanning routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/container")
            .route("/scan-types", web::get().to(list_scan_types))
            .route("/scans", web::post().to(create_scan))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            .route("/scans/{id}/findings", web::get().to(get_findings))
            .route("/scans/{id}/images", web::get().to(get_images))
            .route("/scans/{id}/resources", web::get().to(get_resources))
            .route("/findings/{id}/status", web::patch().to(update_finding_status))
            .route("/analyze-dockerfile", web::post().to(analyze_dockerfile))
            .route("/analyze-manifest", web::post().to(analyze_manifest)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_types_json() {
        let scan_types = vec!["docker_image", "dockerfile"];
        let json = serde_json::to_string(&scan_types).unwrap();
        assert!(json.contains("docker_image"));
    }
}
