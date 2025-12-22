//! Nuclei Scanner API Endpoints
//!
//! This module provides REST API endpoints for Nuclei vulnerability scanning:
//! - POST /api/nuclei/scans - Start a Nuclei scan
//! - GET /api/nuclei/scans - List Nuclei scans for the current user
//! - GET /api/nuclei/scans/{id} - Get a specific scan with results
//! - DELETE /api/nuclei/scans/{id} - Delete a scan
//! - POST /api/nuclei/scans/{id}/cancel - Cancel a running scan
//! - GET /api/nuclei/templates - List available templates
//! - GET /api/nuclei/templates/{id} - Get template details
//! - POST /api/nuclei/templates/update - Update templates from GitHub
//! - GET /api/nuclei/templates/stats - Get template statistics
//! - GET /api/nuclei/templates/tags - List all template tags
//! - GET /api/nuclei/status - Check Nuclei installation status

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::db::nuclei as db;
use crate::scanner::nuclei::{
    self, check_nuclei_available, get_nuclei_version, run_nuclei_scan, update_templates,
    CancellationToken, NucleiConfig, NucleiProgress, NucleiResult, NucleiScanStatus,
    NucleiSeverity, NucleiTemplate, TemplateStats,
};
use crate::web::auth;

// ============================================================================
// Shared State
// ============================================================================

/// Shared state for running Nuclei scans
pub struct NucleiState {
    /// Cancellation tokens for running scans
    cancellation_tokens: RwLock<HashMap<String, CancellationToken>>,
    /// Progress broadcast channels for running scans
    progress_channels: RwLock<HashMap<String, broadcast::Sender<NucleiProgress>>>,
}

impl NucleiState {
    pub fn new() -> Self {
        Self {
            cancellation_tokens: RwLock::new(HashMap::new()),
            progress_channels: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register_scan(&self, scan_id: &str) -> (CancellationToken, broadcast::Receiver<NucleiProgress>) {
        let token = CancellationToken::new();
        let (tx, rx) = broadcast::channel(100);

        let mut tokens = self.cancellation_tokens.write().await;
        tokens.insert(scan_id.to_string(), token.clone());

        let mut channels = self.progress_channels.write().await;
        channels.insert(scan_id.to_string(), tx);

        (token, rx)
    }

    pub async fn unregister_scan(&self, scan_id: &str) {
        let mut tokens = self.cancellation_tokens.write().await;
        tokens.remove(scan_id);

        let mut channels = self.progress_channels.write().await;
        channels.remove(scan_id);
    }

    pub async fn cancel_scan(&self, scan_id: &str) -> bool {
        let tokens = self.cancellation_tokens.read().await;
        if let Some(token) = tokens.get(scan_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    pub async fn get_progress_sender(&self, scan_id: &str) -> Option<broadcast::Sender<NucleiProgress>> {
        let channels = self.progress_channels.read().await;
        channels.get(scan_id).cloned()
    }
}

impl Default for NucleiState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create a Nuclei scan
#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub name: Option<String>,
    pub targets: Vec<String>,
    #[serde(default)]
    pub templates: Vec<String>,
    #[serde(default)]
    pub template_tags: Vec<String>,
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    #[serde(default)]
    pub severity: Vec<String>,
    pub rate_limit: Option<u32>,
    pub concurrency: Option<u32>,
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub headless: bool,
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub proxy: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Response for scan creation
#[derive(Debug, Serialize)]
pub struct CreateScanResponse {
    pub id: String,
    pub message: String,
}

/// Response for scan list
#[derive(Debug, Serialize)]
pub struct ScanListResponse {
    pub scans: Vec<ScanSummary>,
    pub total: i64,
}

/// Scan summary for list view
#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub name: Option<String>,
    pub status: String,
    pub targets_count: usize,
    pub results_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Response for scan details
#[derive(Debug, Serialize)]
pub struct ScanDetailResponse {
    pub id: String,
    pub name: Option<String>,
    pub status: String,
    pub targets: Vec<String>,
    pub results: Vec<NucleiResult>,
    pub results_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub info_count: u32,
    pub error_message: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Query parameters for results
#[derive(Debug, Deserialize)]
pub struct ResultsQuery {
    pub severity: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for templates list
#[derive(Debug, Serialize)]
pub struct TemplatesListResponse {
    pub templates: Vec<TemplateInfo>,
    pub total: usize,
}

/// Template info for API response
#[derive(Debug, Serialize)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub author: Vec<String>,
    pub description: Option<String>,
    pub cve_id: Option<String>,
}

impl From<NucleiTemplate> for TemplateInfo {
    fn from(t: NucleiTemplate) -> Self {
        Self {
            id: t.id,
            name: t.name,
            severity: t.severity.to_string(),
            tags: t.tags,
            author: t.author,
            description: t.description,
            cve_id: t.classification.and_then(|c| c.cve_id),
        }
    }
}

/// Query parameters for template search
#[derive(Debug, Deserialize)]
pub struct TemplateSearchQuery {
    pub query: Option<String>,
    pub tags: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
}

/// Nuclei installation status
#[derive(Debug, Serialize)]
pub struct NucleiStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub templates_path: String,
    pub templates_available: bool,
}

// ============================================================================
// API Handlers
// ============================================================================

/// Check Nuclei installation status
pub async fn get_status() -> Result<HttpResponse> {
    let installed = check_nuclei_available();
    let version = if installed {
        get_nuclei_version().await.ok()
    } else {
        None
    };

    let templates_path = nuclei::get_templates_path();
    let templates_available = templates_path.exists();

    Ok(HttpResponse::Ok().json(NucleiStatus {
        installed,
        version,
        templates_path: templates_path.to_string_lossy().to_string(),
        templates_available,
    }))
}

/// Start a new Nuclei scan
pub async fn create_scan(
    pool: web::Data<SqlitePool>,
    state: web::Data<Arc<NucleiState>>,
    claims: auth::Claims,
    req: web::Json<CreateScanRequest>,
) -> Result<HttpResponse> {
    // Check if Nuclei is installed
    if !check_nuclei_available() {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Nuclei is not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        })));
    }

    // Validate request
    if req.targets.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one target is required"
        })));
    }

    // Build config
    let severity: Vec<NucleiSeverity> = req
        .severity
        .iter()
        .map(|s| NucleiSeverity::from(s.as_str()))
        .collect();

    let config = NucleiConfig {
        targets: req.targets.clone(),
        templates: req.templates.clone(),
        template_tags: req.template_tags.clone(),
        exclude_tags: req.exclude_tags.clone(),
        severity: if severity.is_empty() {
            vec![NucleiSeverity::Critical, NucleiSeverity::High, NucleiSeverity::Medium]
        } else {
            severity
        },
        rate_limit: req.rate_limit.unwrap_or(150),
        concurrency: req.concurrency.unwrap_or(25),
        timeout: std::time::Duration::from_secs(req.timeout_secs.unwrap_or(10)),
        headless: req.headless,
        follow_redirects: req.follow_redirects,
        max_redirects: 10,
        headers: req.headers.clone(),
        proxy: req.proxy.clone(),
        custom_templates_path: None,
        auto_update_templates: false,
        silent: true,
    };

    // Create scan in database
    let scan_id = db::create_nuclei_scan(
        pool.get_ref(),
        &claims.sub,
        req.name.as_deref(),
        &req.targets,
        &config,
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Register scan for cancellation
    let (cancel_token, _rx) = state.register_scan(&scan_id).await;
    let progress_tx = state.get_progress_sender(&scan_id).await;

    // Spawn background task to run the scan
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let state_clone = state.get_ref().clone();

    tokio::spawn(async move {
        // Update status to running
        let _ = db::update_nuclei_scan_status(&pool_clone, &scan_id_clone, NucleiScanStatus::Running, None).await;

        // Run the scan
        match run_nuclei_scan(&config, progress_tx, Some(cancel_token)).await {
            Ok(results) => {
                // Count by severity
                let mut critical = 0u32;
                let mut high = 0u32;
                let mut medium = 0u32;
                let mut low = 0u32;
                let mut info = 0u32;

                for result in &results {
                    match result.severity {
                        NucleiSeverity::Critical => critical += 1,
                        NucleiSeverity::High => high += 1,
                        NucleiSeverity::Medium => medium += 1,
                        NucleiSeverity::Low => low += 1,
                        NucleiSeverity::Info => info += 1,
                        NucleiSeverity::Unknown => {}
                    }
                }

                // Save results
                let _ = db::save_nuclei_results(&pool_clone, &scan_id_clone, &results).await;
                let _ = db::update_nuclei_scan_counts(&pool_clone, &scan_id_clone, critical, high, medium, low, info).await;
                let _ = db::update_nuclei_scan_status(&pool_clone, &scan_id_clone, NucleiScanStatus::Completed, None).await;

                log::info!(
                    "Nuclei scan {} completed: {} results (critical: {}, high: {}, medium: {}, low: {}, info: {})",
                    scan_id_clone, results.len(), critical, high, medium, low, info
                );
            }
            Err(e) => {
                let _ = db::update_nuclei_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    NucleiScanStatus::Failed,
                    Some(&e.to_string()),
                ).await;
                log::error!("Nuclei scan {} failed: {}", scan_id_clone, e);
            }
        }

        // Unregister scan
        state_clone.unregister_scan(&scan_id_clone).await;
    });

    Ok(HttpResponse::Accepted().json(CreateScanResponse {
        id: scan_id,
        message: "Nuclei scan started".to_string(),
    }))
}

/// List Nuclei scans for the current user
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<ResultsQuery>,
) -> Result<HttpResponse> {
    let scans = db::get_user_nuclei_scans(pool.get_ref(), &claims.sub, query.limit, query.offset)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let total = db::count_user_nuclei_scans(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let summaries: Vec<ScanSummary> = scans
        .into_iter()
        .map(|s| ScanSummary {
            id: s.id,
            name: s.name,
            status: s.status.to_string(),
            targets_count: s.targets.len(),
            results_count: s.results_count,
            critical_count: s.critical_count,
            high_count: s.high_count,
            medium_count: s.medium_count,
            low_count: s.low_count,
            info_count: s.info_count,
            created_at: s.created_at.to_rfc3339(),
            completed_at: s.completed_at.map(|dt| dt.to_rfc3339()),
        })
        .collect();

    Ok(HttpResponse::Ok().json(ScanListResponse {
        scans: summaries,
        total,
    }))
}

/// Get a specific scan with results
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    query: web::Query<ResultsQuery>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    let scan = db::get_nuclei_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match scan {
        Some(s) => {
            // Check ownership
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            // Get results
            let results = db::get_nuclei_results(
                pool.get_ref(),
                &scan_id,
                query.severity.as_deref(),
                query.limit,
                query.offset,
            )
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(ScanDetailResponse {
                id: s.id,
                name: s.name,
                status: s.status.to_string(),
                targets: s.targets,
                results,
                results_count: s.results_count,
                critical_count: s.critical_count,
                high_count: s.high_count,
                medium_count: s.medium_count,
                low_count: s.low_count,
                info_count: s.info_count,
                error_message: s.error_message,
                created_at: s.created_at.to_rfc3339(),
                started_at: s.started_at.map(|dt| dt.to_rfc3339()),
                completed_at: s.completed_at.map(|dt| dt.to_rfc3339()),
            }))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// Delete a scan
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Check ownership
    let scan = db::get_nuclei_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match scan {
        Some(s) => {
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            db::delete_nuclei_scan(pool.get_ref(), &scan_id)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Scan deleted"
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// Cancel a running scan
pub async fn cancel_scan(
    pool: web::Data<SqlitePool>,
    state: web::Data<Arc<NucleiState>>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Check ownership
    let scan = db::get_nuclei_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match scan {
        Some(s) => {
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            if s.status != NucleiScanStatus::Running {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Scan is not running"
                })));
            }

            if state.cancel_scan(&scan_id).await {
                db::update_nuclei_scan_status(pool.get_ref(), &scan_id, NucleiScanStatus::Cancelled, None)
                    .await
                    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "message": "Scan cancelled"
                })))
            } else {
                Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Could not cancel scan (may have already completed)"
                })))
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// List available templates
pub async fn list_templates(
    _claims: auth::Claims,
    query: web::Query<TemplateSearchQuery>,
) -> Result<HttpResponse> {
    // Parse query parameters
    let tags: Option<Vec<String>> = query.tags.as_ref().map(|t| t.split(',').map(|s| s.trim().to_string()).collect());

    let severity: Option<Vec<NucleiSeverity>> = query.severity.as_ref().map(|s| {
        s.split(',')
            .map(|sev| NucleiSeverity::from(sev.trim()))
            .collect()
    });

    let templates = nuclei::search_templates(
        query.query.as_deref(),
        tags.as_deref(),
        severity.as_deref(),
        query.limit,
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let total = templates.len();
    let infos: Vec<TemplateInfo> = templates.into_iter().map(|t| t.into()).collect();

    Ok(HttpResponse::Ok().json(TemplatesListResponse {
        templates: infos,
        total,
    }))
}

/// Get template details
pub async fn get_template(
    _claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let template_id = path.into_inner();

    match nuclei::get_template(&template_id).await {
        Ok(template) => {
            let info: TemplateInfo = template.into();
            Ok(HttpResponse::Ok().json(info))
        }
        Err(e) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": e.to_string()
        }))),
    }
}

/// Get template content (raw YAML)
pub async fn get_template_content(
    _claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let template_id = path.into_inner();

    match nuclei::get_template_content(&template_id).await {
        Ok(content) => Ok(HttpResponse::Ok()
            .content_type("text/yaml")
            .body(content)),
        Err(e) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": e.to_string()
        }))),
    }
}

/// Update templates from GitHub
pub async fn update_templates_handler(_claims: auth::Claims) -> Result<HttpResponse> {
    if !check_nuclei_available() {
        return Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Nuclei is not installed"
        })));
    }

    match update_templates().await {
        Ok(output) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Templates updated successfully",
            "output": output
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }))),
    }
}

/// Get template statistics
pub async fn get_template_stats(_claims: auth::Claims) -> Result<HttpResponse> {
    match nuclei::get_template_stats().await {
        Ok(stats) => Ok(HttpResponse::Ok().json(stats)),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }))),
    }
}

/// List all template tags
pub async fn list_template_tags(_claims: auth::Claims) -> Result<HttpResponse> {
    match nuclei::list_tags().await {
        Ok(tags) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "tags": tags
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }))),
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure Nuclei API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/nuclei")
            .route("/status", web::get().to(get_status))
            .route("/scans", web::post().to(create_scan))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            .route("/scans/{id}/cancel", web::post().to(cancel_scan))
            .route("/templates", web::get().to(list_templates))
            .route("/templates/update", web::post().to(update_templates_handler))
            .route("/templates/stats", web::get().to(get_template_stats))
            .route("/templates/tags", web::get().to(list_template_tags))
            .route("/templates/{id}", web::get().to(get_template))
            .route("/templates/{id}/content", web::get().to(get_template_content)),
    );
}
