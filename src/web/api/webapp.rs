use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;

use crate::scanner::webapp::{WebAppScanConfig, scan_webapp};
use crate::types::WebAppScanResult;
// Auth is extracted via web::ReqData

/// Valid security checks that can be enabled
const VALID_CHECKS: &[&str] = &["headers", "forms", "sqli", "xss", "info_disclosure"];

/// Maximum allowed crawl depth
const MAX_CRAWL_DEPTH: usize = 10;

/// Maximum allowed pages to crawl
const MAX_PAGES_LIMIT: usize = 1000;

/// Minimum pages to crawl
const MIN_PAGES_LIMIT: usize = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct StartWebAppScanRequest {
    pub target_url: String,
    pub max_depth: Option<usize>,
    pub max_pages: Option<usize>,
    pub respect_robots_txt: Option<bool>,
    pub checks_enabled: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct StartWebAppScanResponse {
    pub scan_id: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct WebAppScanStatusResponse {
    pub scan_id: String,
    pub status: String,
    pub result: Option<WebAppScanResult>,
}

// Simple in-memory storage for scan results
// In a production system, this should be stored in the database
type ScanStore = Arc<Mutex<HashMap<String, WebAppScanResult>>>;

pub fn configure(cfg: &mut web::ServiceConfig) {
    let scan_store: ScanStore = Arc::new(Mutex::new(HashMap::new()));

    cfg.app_data(web::Data::new(scan_store))
        .service(
            web::scope("/api/webapp")
                .route("/scan", web::post().to(start_webapp_scan))
                .route("/scan/{scan_id}", web::get().to(get_webapp_scan)),
        );
}

/// POST /api/webapp/scan - Start a new web application scan
async fn start_webapp_scan(
    claims: web::ReqData<crate::web::auth::Claims>,
    req: web::Json<StartWebAppScanRequest>,
    _pool: web::Data<SqlitePool>,
    scan_store: web::Data<ScanStore>,
) -> Result<HttpResponse> {
    log::info!("User {} starting webapp scan for {}", claims.sub, req.target_url);

    // Validate URL is not empty
    if req.target_url.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "target_url is required"
        })));
    }

    // Trim whitespace and validate URL format
    let target_url = req.target_url.trim();

    // Basic URL validation
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "target_url must start with http:// or https://"
        })));
    }

    // Parse and validate URL structure
    let parsed_url = match url::Url::parse(target_url) {
        Ok(url) => url,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid URL format: {}", e)
            })));
        }
    };

    // Security check: prevent scanning localhost/private IPs by default
    if let Some(host) = parsed_url.host_str() {
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Scanning localhost is not allowed"
            })));
        }

        // Check for private IP ranges
        if host.starts_with("192.168.") || host.starts_with("10.")
            || host.starts_with("172.16.") || host.starts_with("172.17.")
            || host.starts_with("172.18.") || host.starts_with("172.19.")
            || host.starts_with("172.20.") || host.starts_with("172.21.")
            || host.starts_with("172.22.") || host.starts_with("172.23.")
            || host.starts_with("172.24.") || host.starts_with("172.25.")
            || host.starts_with("172.26.") || host.starts_with("172.27.")
            || host.starts_with("172.28.") || host.starts_with("172.29.")
            || host.starts_with("172.30.") || host.starts_with("172.31.") {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Scanning private IP addresses is not allowed"
            })));
        }
    } else {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "URL must have a valid host"
        })));
    }

    // Validate max_depth
    if let Some(depth) = req.max_depth {
        if depth == 0 || depth > MAX_CRAWL_DEPTH {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("max_depth must be between 1 and {}", MAX_CRAWL_DEPTH)
            })));
        }
    }

    // Validate max_pages
    if let Some(pages) = req.max_pages {
        if pages < MIN_PAGES_LIMIT || pages > MAX_PAGES_LIMIT {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("max_pages must be between {} and {}", MIN_PAGES_LIMIT, MAX_PAGES_LIMIT)
            })));
        }
    }

    // Validate checks_enabled
    if let Some(checks) = &req.checks_enabled {
        if checks.is_empty() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "At least one security check must be enabled"
            })));
        }

        for check in checks {
            if !VALID_CHECKS.contains(&check.as_str()) {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid check '{}'. Valid checks are: {}", check, VALID_CHECKS.join(", "))
                })));
            }
        }
    }

    // Generate scan ID
    let scan_id = Uuid::new_v4().to_string();

    // Create scan configuration
    let mut config = WebAppScanConfig::default();
    config.target_url = target_url.to_string();

    if let Some(depth) = req.max_depth {
        config.max_depth = depth;
    }

    if let Some(pages) = req.max_pages {
        config.max_pages = pages;
    }

    if let Some(respect_robots) = req.respect_robots_txt {
        config.respect_robots_txt = respect_robots;
    }

    if let Some(checks) = &req.checks_enabled {
        config.checks_enabled = checks.clone();
    }

    // Clone scan_store for the background task
    let store = scan_store.get_ref().clone();
    let scan_id_clone = scan_id.clone();

    // Spawn background task to run the scan
    tokio::spawn(async move {
        log::info!("Starting webapp scan task for {}", scan_id_clone);

        match scan_webapp(config).await {
            Ok(result) => {
                log::info!("Webapp scan {} completed with {} findings", scan_id_clone, result.findings.len());
                let mut store = store.lock().await;
                store.insert(scan_id_clone.clone(), result);
            }
            Err(e) => {
                log::error!("Webapp scan {} failed: {}", scan_id_clone, e);
                // Store error result
                let error_result = WebAppScanResult {
                    url: "error".to_string(),
                    pages_crawled: 0,
                    findings: vec![],
                };
                let mut store = store.lock().await;
                store.insert(scan_id_clone.clone(), error_result);
            }
        }
    });

    Ok(HttpResponse::Ok().json(StartWebAppScanResponse {
        scan_id,
        status: "running".to_string(),
    }))
}

/// GET /api/webapp/scan/{scan_id} - Get web application scan results
async fn get_webapp_scan(
    _claims: web::ReqData<crate::web::auth::Claims>,
    scan_id: web::Path<String>,
    scan_store: web::Data<ScanStore>,
) -> Result<HttpResponse> {
    let store = scan_store.lock().await;

    if let Some(result) = store.get(scan_id.as_str()) {
        Ok(HttpResponse::Ok().json(WebAppScanStatusResponse {
            scan_id: scan_id.to_string(),
            status: "completed".to_string(),
            result: Some(result.clone()),
        }))
    } else {
        // Scan might still be running or doesn't exist
        Ok(HttpResponse::Ok().json(WebAppScanStatusResponse {
            scan_id: scan_id.to_string(),
            status: "running".to_string(),
            result: None,
        }))
    }
}
