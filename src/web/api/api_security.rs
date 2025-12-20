//! API Security Scanning Endpoints
//!
//! Provides REST API endpoints for API security scanning:
//! - POST /api/api-security/scans - Start a new API security scan
//! - GET /api/api-security/scans - List API scans
//! - GET /api/api-security/scans/{id} - Get scan details
//! - GET /api/api-security/scans/{id}/findings - Get scan findings
//! - GET /api/api-security/scans/{id}/endpoints - Get discovered endpoints
//! - POST /api/api-security/discover - Discover API endpoints from URL/spec
//! - DELETE /api/api-security/scans/{id} - Delete a scan

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::db::api_security::{
    self, ApiScan, ApiFinding, ApiEndpointRecord, CreateApiScanRequest,
};
use crate::scanner::api_security::{
    scan_api, ApiSecurityConfig, ApiSpecType, AuthConfig, AuthType, ScanOptions,
};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct StartApiScanRequest {
    pub name: String,
    pub target_url: String,
    pub spec_type: Option<String>,
    pub spec_content: Option<String>,
    pub auth_config: Option<AuthConfigRequest>,
    pub scan_options: Option<ScanOptionsRequest>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfigRequest {
    pub auth_type: String,
    pub credentials: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanOptionsRequest {
    pub test_auth_bypass: Option<bool>,
    pub test_injection: Option<bool>,
    pub test_rate_limit: Option<bool>,
    pub test_cors: Option<bool>,
    pub test_bola: Option<bool>,
    pub test_bfla: Option<bool>,
    pub discover_endpoints: Option<bool>,
    pub aggressive_mode: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct StartApiScanResponse {
    pub scan_id: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoverEndpointsRequest {
    pub target_url: String,
    pub spec_type: Option<String>,
    pub spec_content: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiscoverEndpointsResponse {
    pub endpoints: Vec<EndpointInfo>,
    pub spec_detected: bool,
    pub spec_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EndpointInfo {
    pub path: String,
    pub method: String,
    pub summary: Option<String>,
    pub auth_required: bool,
    pub parameters_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ApiScanDetailResponse {
    pub scan: ApiScan,
    pub endpoints: Vec<ApiEndpointRecord>,
    pub findings_summary: FindingsSummary,
}

#[derive(Debug, Serialize)]
pub struct FindingsSummary {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

// In-memory store for tracking running scans
type ScanStatusStore = Arc<Mutex<HashMap<String, String>>>;

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    let scan_store: ScanStatusStore = Arc::new(Mutex::new(HashMap::new()));

    cfg.app_data(web::Data::new(scan_store))
        .service(
            web::scope("/api-security")
                .route("/scans", web::post().to(start_api_scan))
                .route("/scans", web::get().to(list_api_scans))
                .route("/scans/{id}", web::get().to(get_api_scan))
                .route("/scans/{id}", web::delete().to(delete_api_scan))
                .route("/scans/{id}/findings", web::get().to(get_scan_findings))
                .route("/scans/{id}/endpoints", web::get().to(get_scan_endpoints))
                .route("/discover", web::post().to(discover_endpoints))
                .route("/stats", web::get().to(get_stats)),
        );
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /api/api-security/scans - Start a new API security scan
async fn start_api_scan(
    claims: web::ReqData<crate::web::auth::Claims>,
    pool: web::Data<SqlitePool>,
    scan_store: web::Data<ScanStatusStore>,
    req: web::Json<StartApiScanRequest>,
) -> Result<HttpResponse> {
    log::info!(
        "User {} starting API security scan for {}",
        claims.sub,
        req.target_url
    );

    // Validate URL
    if req.target_url.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "target_url is required"
        })));
    }

    let target_url = req.target_url.trim();
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "target_url must start with http:// or https://"
        })));
    }

    // Parse URL to validate
    if let Err(e) = url::Url::parse(target_url) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid URL format: {}", e)
        })));
    }

    // Security check: prevent scanning localhost/private IPs
    if let Ok(parsed) = url::Url::parse(target_url) {
        if let Some(host) = parsed.host_str() {
            if host == "localhost" || host == "127.0.0.1" || host == "::1" {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Scanning localhost is not allowed"
                })));
            }
        }
    }

    // Create scan record in database
    let db_request = CreateApiScanRequest {
        name: req.name.clone(),
        target_url: target_url.to_string(),
        spec_type: req.spec_type.clone(),
        spec_content: req.spec_content.clone(),
        auth_config: req.auth_config.as_ref().map(|c| serde_json::json!(c)),
        scan_options: req.scan_options.as_ref().map(|o| serde_json::json!(o)),
        customer_id: req.customer_id.clone(),
        engagement_id: req.engagement_id.clone(),
    };

    let scan = match api_security::create_api_scan(pool.get_ref(), &claims.sub, db_request).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to create API scan: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create scan"
            })));
        }
    };

    let scan_id = scan.id.clone();

    // Build scan configuration
    let config = build_scan_config(&req, target_url);

    // Clone data for background task
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let store_clone = scan_store.get_ref().clone();

    // Spawn background task to run the scan
    tokio::spawn(async move {
        log::info!("Starting API security scan task for {}", scan_id_clone);

        // Update status to running
        {
            let mut store = store_clone.lock().await;
            store.insert(scan_id_clone.clone(), "running".to_string());
        }

        if let Err(e) =
            api_security::update_api_scan_status(&pool_clone, &scan_id_clone, "running", None).await
        {
            log::error!("Failed to update scan status: {}", e);
        }

        // Run the scan
        match scan_api(config).await {
            Ok(result) => {
                log::info!(
                    "API security scan {} completed with {} findings",
                    scan_id_clone,
                    result.findings.len()
                );

                // Store discovered endpoints
                if let Err(e) = api_security::store_api_endpoints(
                    &pool_clone,
                    &scan_id_clone,
                    &result.discovered_endpoints,
                )
                .await
                {
                    log::error!("Failed to store endpoints: {}", e);
                }

                // Store findings
                if let Err(e) =
                    api_security::store_api_findings(&pool_clone, &scan_id_clone, &result.findings)
                        .await
                {
                    log::error!("Failed to store findings: {}", e);
                }

                // Update scan with results
                if let Err(e) = api_security::update_api_scan_results(
                    &pool_clone,
                    &scan_id_clone,
                    result.endpoints_discovered as i64,
                    result.endpoints_tested as i64,
                    result.findings.len() as i64,
                )
                .await
                {
                    log::error!("Failed to update scan results: {}", e);
                }

                // Mark as completed
                if let Err(e) = api_security::update_api_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    "completed",
                    None,
                )
                .await
                {
                    log::error!("Failed to update scan status: {}", e);
                }

                // Update store
                {
                    let mut store = store_clone.lock().await;
                    store.insert(scan_id_clone, "completed".to_string());
                }
            }
            Err(e) => {
                log::error!("API security scan {} failed: {}", scan_id_clone, e);

                // Mark as failed
                let _ = api_security::update_api_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    "failed",
                    Some(&e.to_string()),
                )
                .await;

                {
                    let mut store = store_clone.lock().await;
                    store.insert(scan_id_clone, "failed".to_string());
                }
            }
        }
    });

    Ok(HttpResponse::Ok().json(StartApiScanResponse {
        scan_id,
        status: "running".to_string(),
    }))
}

/// GET /api/api-security/scans - List API scans for user
async fn list_api_scans(
    claims: web::ReqData<crate::web::auth::Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    match api_security::get_user_api_scans(pool.get_ref(), &claims.sub).await {
        Ok(scans) => Ok(HttpResponse::Ok().json(scans)),
        Err(e) => {
            log::error!("Failed to fetch API scans: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch scans"
            })))
        }
    }
}

/// GET /api/api-security/scans/{id} - Get scan details
async fn get_api_scan(
    claims: web::ReqData<crate::web::auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Get scan
    let scan = match api_security::get_api_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to fetch API scan: {}", e);
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    // Verify ownership
    if scan.user_id != claims.sub {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })));
    }

    // Get endpoints
    let endpoints = api_security::get_api_endpoints(pool.get_ref(), &scan_id)
        .await
        .unwrap_or_default();

    // Get findings for summary
    let findings = api_security::get_api_findings(pool.get_ref(), &scan_id)
        .await
        .unwrap_or_default();

    let findings_summary = calculate_findings_summary(&findings);

    Ok(HttpResponse::Ok().json(ApiScanDetailResponse {
        scan,
        endpoints,
        findings_summary,
    }))
}

/// DELETE /api/api-security/scans/{id} - Delete a scan
async fn delete_api_scan(
    claims: web::ReqData<crate::web::auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    match api_security::delete_api_scan(pool.get_ref(), &scan_id, &claims.sub).await {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Scan deleted successfully"
        }))),
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found or access denied"
        }))),
        Err(e) => {
            log::error!("Failed to delete scan: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete scan"
            })))
        }
    }
}

/// GET /api/api-security/scans/{id}/findings - Get scan findings
async fn get_scan_findings(
    claims: web::ReqData<crate::web::auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Verify ownership
    match api_security::get_api_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(scan) if scan.user_id == claims.sub => {}
        Ok(_) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied"
            })))
        }
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })))
        }
    }

    match api_security::get_api_findings(pool.get_ref(), &scan_id).await {
        Ok(findings) => Ok(HttpResponse::Ok().json(findings)),
        Err(e) => {
            log::error!("Failed to fetch findings: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch findings"
            })))
        }
    }
}

/// GET /api/api-security/scans/{id}/endpoints - Get discovered endpoints
async fn get_scan_endpoints(
    claims: web::ReqData<crate::web::auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Verify ownership
    match api_security::get_api_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(scan) if scan.user_id == claims.sub => {}
        Ok(_) => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Access denied"
            })))
        }
        Err(_) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })))
        }
    }

    match api_security::get_api_endpoints(pool.get_ref(), &scan_id).await {
        Ok(endpoints) => Ok(HttpResponse::Ok().json(endpoints)),
        Err(e) => {
            log::error!("Failed to fetch endpoints: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch endpoints"
            })))
        }
    }
}

/// POST /api/api-security/discover - Discover API endpoints
async fn discover_endpoints(
    _claims: web::ReqData<crate::web::auth::Claims>,
    req: web::Json<DiscoverEndpointsRequest>,
) -> Result<HttpResponse> {
    let target_url = req.target_url.trim();

    // Validate URL
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "target_url must start with http:// or https://"
        })));
    }

    // Build discovery config
    let spec_type = req.spec_type.as_ref().and_then(|s| match s.as_str() {
        "openapi3" => Some(ApiSpecType::OpenApi3),
        "swagger2" => Some(ApiSpecType::Swagger2),
        "postman" => Some(ApiSpecType::Postman),
        _ => None,
    });

    let config = ApiSecurityConfig {
        target_url: target_url.to_string(),
        spec_type,
        spec_content: req.spec_content.clone(),
        auth_config: None,
        scan_options: ScanOptions {
            discover_endpoints: true,
            test_auth_bypass: false,
            test_injection: false,
            test_rate_limit: false,
            test_cors: false,
            test_bola: false,
            test_bfla: false,
            aggressive_mode: false,
        },
        ..Default::default()
    };

    // Create HTTP client
    let client = reqwest::Client::builder()
        .timeout(config.timeout)
        .user_agent(&config.user_agent)
        .build()
        .map_err(|e| {
            actix_web::error::ErrorInternalServerError(format!("Failed to create client: {}", e))
        })?;

    // Run discovery
    let discovery_result =
        crate::scanner::api_security::discovery::discover_endpoints(&client, &config)
            .await
            .map_err(|e| {
                actix_web::error::ErrorInternalServerError(format!("Discovery failed: {}", e))
            })?;

    // Convert to response
    let endpoints: Vec<EndpointInfo> = discovery_result
        .endpoints
        .iter()
        .map(|e| EndpointInfo {
            path: e.path.clone(),
            method: e.method.clone(),
            summary: e.summary.clone(),
            auth_required: e.auth_required,
            parameters_count: e.parameters.len(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(DiscoverEndpointsResponse {
        endpoints,
        spec_detected: discovery_result.spec_detected,
        spec_type: discovery_result.spec_type.map(|t| format!("{:?}", t)),
    }))
}

/// GET /api/api-security/stats - Get API security statistics
async fn get_stats(
    claims: web::ReqData<crate::web::auth::Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    match api_security::get_api_security_stats(pool.get_ref(), &claims.sub).await {
        Ok(stats) => Ok(HttpResponse::Ok().json(stats)),
        Err(e) => {
            log::error!("Failed to fetch stats: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch statistics"
            })))
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Build scan configuration from request
fn build_scan_config(req: &StartApiScanRequest, target_url: &str) -> ApiSecurityConfig {
    let spec_type = req.spec_type.as_ref().and_then(|s| match s.as_str() {
        "openapi3" => Some(ApiSpecType::OpenApi3),
        "swagger2" => Some(ApiSpecType::Swagger2),
        "postman" => Some(ApiSpecType::Postman),
        _ => None,
    });

    let auth_config = req.auth_config.as_ref().map(|c| {
        let auth_type = match c.auth_type.as_str() {
            "bearer" => AuthType::Bearer,
            "basic" => AuthType::Basic,
            "api_key" => AuthType::ApiKey,
            "oauth2" => AuthType::OAuth2,
            "custom" => AuthType::Custom,
            _ => AuthType::None,
        };
        AuthConfig {
            auth_type,
            credentials: c.credentials.clone(),
        }
    });

    let scan_options = req.scan_options.as_ref().map_or_else(ScanOptions::default, |o| {
        ScanOptions {
            test_auth_bypass: o.test_auth_bypass.unwrap_or(true),
            test_injection: o.test_injection.unwrap_or(true),
            test_rate_limit: o.test_rate_limit.unwrap_or(true),
            test_cors: o.test_cors.unwrap_or(true),
            test_bola: o.test_bola.unwrap_or(true),
            test_bfla: o.test_bfla.unwrap_or(false),
            discover_endpoints: o.discover_endpoints.unwrap_or(true),
            aggressive_mode: o.aggressive_mode.unwrap_or(false),
        }
    });

    ApiSecurityConfig {
        target_url: target_url.to_string(),
        spec_type,
        spec_content: req.spec_content.clone(),
        auth_config,
        scan_options,
        ..Default::default()
    }
}

/// Calculate findings summary from findings list
fn calculate_findings_summary(findings: &[ApiFinding]) -> FindingsSummary {
    let mut summary = FindingsSummary {
        total: findings.len() as i64,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for finding in findings {
        match finding.severity.to_lowercase().as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" | "info" => summary.low += 1,
            _ => {}
        }
    }

    summary
}
