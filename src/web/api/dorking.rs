//! Google Dorking API Endpoints
//!
//! This module provides REST API endpoints for Google dorking reconnaissance.
//!
//! # WARNING: Responsible Use Required
//!
//! These endpoints should ONLY be used for:
//! - Authorized security assessments of your own domains
//! - Penetration tests with explicit written permission
//! - Bug bounty programs where allowed by scope
//!
//! # Endpoints
//!
//! - `POST /api/recon/dorks` - Run dorks against a domain
//! - `GET /api/recon/dorks/templates` - List available dork templates

#![allow(dead_code)]
//! - `GET /api/recon/dorks/categories` - List dork categories
//! - `POST /api/recon/dorks/custom` - Run a custom dork query
//! - `GET /api/recon/dorks/results/{id}` - Get dork scan results
//! - `GET /api/recon/dorks/results` - List user's dork scans
//! - `DELETE /api/recon/dorks/results/{id}` - Delete dork scan results

use actix_web::{web, HttpResponse};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::db::dorking as db;
use crate::scanner::google_dorking::{
    self, DorkCategory, DorkConfig, DorkResult, DorkScanSummary,
    DorkTemplate, SearchProviderType,
};
use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;

/// State for tracking running dork scans
pub struct DorkingState {
    pub running_scans: RwLock<HashSet<String>>,
}

impl Default for DorkingState {
    fn default() -> Self {
        Self {
            running_scans: RwLock::new(HashSet::new()),
        }
    }
}

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to start a dork scan
#[derive(Debug, Deserialize)]
pub struct RunDorksRequest {
    /// Target domain to scan
    pub domain: String,
    /// Categories to scan (if empty, scans all categories)
    #[serde(default)]
    pub categories: Vec<String>,
    /// Specific template IDs to run (if empty, runs all in categories)
    #[serde(default)]
    pub template_ids: Vec<String>,
    /// Maximum results per dork query
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Search provider to use (serpapi, placeholder)
    #[serde(default = "default_provider")]
    pub provider: String,
    /// SerpAPI key (required if provider is serpapi)
    pub serpapi_key: Option<String>,
    /// Delay between queries in milliseconds
    #[serde(default = "default_delay")]
    pub delay_ms: u64,
}

fn default_max_results() -> usize {
    10
}

fn default_provider() -> String {
    "placeholder".to_string()
}

fn default_delay() -> u64 {
    2000
}

/// Request to run a custom dork query
#[derive(Debug, Deserialize)]
pub struct CustomDorkRequest {
    /// Target domain
    pub domain: String,
    /// Custom dork query (supports {domain} placeholder)
    pub query: String,
    /// Optional name for the query
    pub name: Option<String>,
    /// Maximum results
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Search provider
    #[serde(default = "default_provider")]
    pub provider: String,
    /// SerpAPI key
    pub serpapi_key: Option<String>,
}

/// Request to save a custom dork template
#[derive(Debug, Deserialize)]
pub struct CreateCustomTemplateRequest {
    /// Template name
    pub name: String,
    /// Category (must be a valid DorkCategory)
    pub category: String,
    /// Query template with placeholders
    pub query_template: String,
    /// Description
    pub description: String,
    /// Risk level (info, low, medium, high, critical)
    #[serde(default = "default_risk_level")]
    pub risk_level: String,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_risk_level() -> String {
    "medium".to_string()
}

/// Response for starting a dork scan
#[derive(Debug, Serialize)]
pub struct StartDorkScanResponse {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub message: String,
    pub template_count: usize,
}

/// Response for listing templates
#[derive(Debug, Serialize)]
pub struct TemplatesResponse {
    pub templates: Vec<TemplateInfo>,
    pub total: usize,
}

/// Template information
#[derive(Debug, Serialize)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub query_template: String,
    pub risk_level: String,
    pub is_builtin: bool,
    pub tags: Vec<String>,
}

impl From<DorkTemplate> for TemplateInfo {
    fn from(t: DorkTemplate) -> Self {
        Self {
            id: t.id,
            name: t.name,
            category: t.category.display_name().to_string(),
            description: t.description,
            query_template: t.query_template,
            risk_level: t.risk_level,
            is_builtin: t.is_builtin,
            tags: t.tags,
        }
    }
}

/// Category information
#[derive(Debug, Serialize)]
pub struct CategoryInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub template_count: usize,
}

/// Response for listing categories
#[derive(Debug, Serialize)]
pub struct CategoriesResponse {
    pub categories: Vec<CategoryInfo>,
}

/// Dork scan result for API response
#[derive(Debug, Serialize)]
pub struct DorkScanResponse {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub results: Vec<DorkResult>,
    pub summary: Option<DorkScanSummary>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// List response for dork scans
#[derive(Debug, Serialize)]
pub struct DorkScanListResponse {
    pub scans: Vec<DorkScanListItem>,
    pub total: usize,
}

/// Summary item for list
#[derive(Debug, Serialize)]
pub struct DorkScanListItem {
    pub id: String,
    pub domain: String,
    pub status: String,
    pub dork_count: usize,
    pub result_count: usize,
    pub created_at: String,
    pub completed_at: Option<String>,
}

// =============================================================================
// Handlers
// =============================================================================

/// Run dorks against a domain
///
/// POST /api/recon/dorks
pub async fn run_dorks(
    pool: web::Data<SqlitePool>,
    state: web::Data<Arc<DorkingState>>,
    claims: Claims,
    req: web::Json<RunDorksRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate domain
    if req.domain.is_empty() {
        return Err(ApiError::bad_request("Domain is required"));
    }

    // Validate domain format (basic check)
    if !req.domain.contains('.') || req.domain.contains(' ') {
        return Err(ApiError::bad_request("Invalid domain format"));
    }

    info!(
        "User {} starting dork scan for domain: {}",
        claims.sub, req.domain
    );

    // Validate provider
    let provider = match req.provider.to_lowercase().as_str() {
        "serpapi" => {
            if req.serpapi_key.is_none() || req.serpapi_key.as_ref().unwrap().is_empty() {
                return Err(ApiError::bad_request(
                    "SerpAPI key is required when using serpapi provider",
                ));
            }
            SearchProviderType::SerpApi
        }
        "placeholder" | "" => SearchProviderType::Placeholder,
        _ => {
            return Err(ApiError::bad_request(
                "Invalid provider. Use 'serpapi' or 'placeholder'",
            ));
        }
    };

    // Build config
    let config = DorkConfig {
        max_results: req.max_results.min(50),
        delay_ms: req.delay_ms.max(1000), // Minimum 1 second delay
        timeout_secs: 30,
        provider,
        serpapi_key: req.serpapi_key.clone(),
        exact_domain_only: true,
    };

    // Determine which templates to run
    let templates = if !req.template_ids.is_empty() {
        // Run specific templates
        google_dorking::templates::get_all_templates()
            .into_iter()
            .filter(|t| req.template_ids.contains(&t.id))
            .collect::<Vec<_>>()
    } else if !req.categories.is_empty() {
        // Run templates from specified categories
        let mut templates = Vec::new();
        for cat_str in &req.categories {
            if let Some(cat) = parse_category(cat_str) {
                templates.extend(google_dorking::templates::get_templates_by_category(cat));
            }
        }
        templates
    } else {
        // Run all templates
        google_dorking::templates::get_all_templates()
    };

    if templates.is_empty() {
        return Err(ApiError::bad_request("No templates matched the criteria"));
    }

    let template_count = templates.len();

    // Create scan record
    let scan_id = db::create_dork_scan(pool.get_ref(), &claims.sub, &req.domain).await?;

    // Track running scan
    {
        let mut running = state.running_scans.write().await;
        running.insert(scan_id.clone());
    }

    // Spawn background task
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let domain = req.domain.clone();
    let state_clone = state.clone();

    tokio::spawn(async move {
        // Update status to running
        let _ = db::update_dork_scan_status(&pool_clone, &scan_id_clone, "running").await;

        let started_at = chrono::Utc::now();
        let mut all_results = Vec::new();

        // Run each template
        for template in templates {
            match google_dorking::run_dork(&domain, &template, &config).await {
                Ok(result) => {
                    // Save individual result
                    if let Err(e) = db::save_dork_result(&pool_clone, &scan_id_clone, &result).await
                    {
                        error!("Failed to save dork result: {}", e);
                    }
                    all_results.push(result);
                }
                Err(e) => {
                    warn!("Dork execution failed for {}: {}", template.id, e);
                }
            }

            // Rate limiting delay
            if config.delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(config.delay_ms)).await;
            }
        }

        // Generate summary
        let summary = google_dorking::summarize_results(&domain, &all_results, started_at);

        // Save summary and mark complete
        if let Err(e) = db::complete_dork_scan(&pool_clone, &scan_id_clone, &summary).await {
            error!("Failed to complete dork scan: {}", e);
        }

        // Remove from running scans
        let mut running = state_clone.running_scans.write().await;
        running.remove(&scan_id_clone);

        info!(
            "Dork scan {} completed: {} dorks, {} results",
            scan_id_clone, summary.total_dorks, summary.total_results
        );
    });

    Ok(HttpResponse::Ok().json(StartDorkScanResponse {
        id: scan_id,
        domain: req.domain.clone(),
        status: "running".to_string(),
        message: format!(
            "Dork scan started. Running {} templates against {}. \
             WARNING: Use only for authorized security testing.",
            template_count, req.domain
        ),
        template_count,
    }))
}

/// Run a custom dork query
///
/// POST /api/recon/dorks/custom
pub async fn run_custom_dork(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: web::Json<CustomDorkRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate inputs
    if req.domain.is_empty() {
        return Err(ApiError::bad_request("Domain is required"));
    }

    if req.query.is_empty() {
        return Err(ApiError::bad_request("Query is required"));
    }

    info!(
        "User {} running custom dork for domain: {}",
        claims.sub, req.domain
    );

    // Build config
    let provider = match req.provider.to_lowercase().as_str() {
        "serpapi" => {
            if req.serpapi_key.is_none() || req.serpapi_key.as_ref().unwrap().is_empty() {
                return Err(ApiError::bad_request("SerpAPI key is required"));
            }
            SearchProviderType::SerpApi
        }
        _ => SearchProviderType::Placeholder,
    };

    let config = DorkConfig {
        max_results: req.max_results.min(50),
        delay_ms: 0, // No delay for single query
        timeout_secs: 30,
        provider,
        serpapi_key: req.serpapi_key.clone(),
        exact_domain_only: true,
    };

    // Run the custom dork
    let result = google_dorking::run_custom_dork(&req.domain, &req.query, &config).await?;

    // Save to database
    let scan_id = db::create_dork_scan(pool.get_ref(), &claims.sub, &req.domain).await?;
    db::save_dork_result(pool.get_ref(), &scan_id, &result).await?;

    let started_at = chrono::Utc::now();
    let summary = google_dorking::summarize_results(&req.domain, &[result.clone()], started_at);
    db::complete_dork_scan(pool.get_ref(), &scan_id, &summary).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": scan_id,
        "domain": req.domain,
        "query": result.query,
        "result_count": result.result_count,
        "status": format!("{:?}", result.status).to_lowercase(),
        "results": result.results,
        "search_url": format!(
            "https://www.google.com/search?q={}",
            urlencoding::encode(&result.query)
        ),
        "warning": "Use only for authorized security testing"
    })))
}

/// List available dork templates
///
/// GET /api/recon/dorks/templates
pub async fn list_templates(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<TemplateQueryParams>,
) -> Result<HttpResponse, ApiError> {
    let mut templates: Vec<TemplateInfo> = google_dorking::templates::get_all_templates()
        .into_iter()
        .map(TemplateInfo::from)
        .collect();

    // Filter by category if specified
    if let Some(category) = &query.category {
        templates.retain(|t| t.category.eq_ignore_ascii_case(category));
    }

    // Filter by risk level if specified
    if let Some(risk) = &query.risk_level {
        templates.retain(|t| t.risk_level.eq_ignore_ascii_case(risk));
    }

    // Filter by search query if specified
    if let Some(q) = &query.q {
        let q_lower = q.to_lowercase();
        templates.retain(|t| {
            t.name.to_lowercase().contains(&q_lower)
                || t.description.to_lowercase().contains(&q_lower)
                || t.tags.iter().any(|tag| tag.to_lowercase().contains(&q_lower))
        });
    }

    // Add custom templates from database
    if let Ok(custom_templates) = db::get_user_custom_templates(pool.get_ref(), &claims.sub).await {
        for ct in custom_templates {
            templates.push(TemplateInfo {
                id: ct.id,
                name: ct.name,
                category: ct.category,
                description: ct.description.unwrap_or_default(),
                query_template: ct.query_template,
                risk_level: ct.risk_level.unwrap_or_else(|| "medium".to_string()),
                is_builtin: false,
                tags: serde_json::from_str(&ct.tags.unwrap_or_else(|| "[]".to_string()))
                    .unwrap_or_default(),
            });
        }
    }

    let total = templates.len();

    Ok(HttpResponse::Ok().json(TemplatesResponse { templates, total }))
}

#[derive(Debug, Deserialize)]
pub struct TemplateQueryParams {
    pub category: Option<String>,
    pub risk_level: Option<String>,
    pub q: Option<String>,
}

/// List dork categories
///
/// GET /api/recon/dorks/categories
pub async fn list_categories() -> Result<HttpResponse, ApiError> {
    let categories: Vec<CategoryInfo> = DorkCategory::all()
        .into_iter()
        .map(|cat| {
            let templates = google_dorking::templates::get_templates_by_category(cat);
            CategoryInfo {
                id: format!("{:?}", cat).to_lowercase(),
                name: cat.display_name().to_string(),
                description: cat.description().to_string(),
                template_count: templates.len(),
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(CategoriesResponse { categories }))
}

/// Get dork scan results
///
/// GET /api/recon/dorks/results/{id}
pub async fn get_scan_results(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Get scan record
    let scan = db::get_dork_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    // Verify ownership
    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    // Get results
    let results = db::get_dork_results(pool.get_ref(), &scan_id).await?;

    // Parse summary if available
    let summary: Option<DorkScanSummary> = scan
        .summary
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());

    Ok(HttpResponse::Ok().json(DorkScanResponse {
        id: scan.id,
        domain: scan.domain,
        status: scan.status,
        results,
        summary,
        created_at: scan.created_at,
        completed_at: scan.completed_at,
    }))
}

/// List user's dork scans
///
/// GET /api/recon/dorks/results
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50).min(100) as i64;
    let offset = query.offset.unwrap_or(0) as i64;

    let scans = db::get_user_dork_scans(pool.get_ref(), &claims.sub, limit, offset).await?;

    let items: Vec<DorkScanListItem> = scans
        .into_iter()
        .map(|s| DorkScanListItem {
            id: s.id,
            domain: s.domain,
            status: s.status,
            dork_count: s.dork_count as usize,
            result_count: s.result_count as usize,
            created_at: s.created_at,
            completed_at: s.completed_at,
        })
        .collect();

    let total = items.len();

    Ok(HttpResponse::Ok().json(DorkScanListResponse { scans: items, total }))
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Delete dork scan results
///
/// DELETE /api/recon/dorks/results/{id}
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let scan_id = path.into_inner();

    // Verify ownership
    let scan = db::get_dork_scan_by_id(pool.get_ref(), &scan_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Scan not found"))?;

    if scan.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    // Delete
    db::delete_dork_scan(pool.get_ref(), &scan_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Scan deleted",
        "id": scan_id
    })))
}

/// Create a custom dork template
///
/// POST /api/recon/dorks/templates
pub async fn create_custom_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: web::Json<CreateCustomTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    // Validate name
    if req.name.is_empty() {
        return Err(ApiError::bad_request("Template name is required"));
    }

    // Validate query template
    if req.query_template.is_empty() {
        return Err(ApiError::bad_request("Query template is required"));
    }

    // Validate category
    if parse_category(&req.category).is_none() {
        return Err(ApiError::bad_request(
            "Invalid category. Valid categories: sensitive_files, login_pages, config_files, \
             error_messages, admin_panels, directories, database_files, backup_files, \
             api_endpoints, cloud_storage, source_control, log_files",
        ));
    }

    // Validate risk level
    let valid_risks = ["info", "low", "medium", "high", "critical"];
    if !valid_risks.contains(&req.risk_level.to_lowercase().as_str()) {
        return Err(ApiError::bad_request(
            "Invalid risk level. Valid levels: info, low, medium, high, critical",
        ));
    }

    let template_id = db::create_custom_template(
        pool.get_ref(),
        &claims.sub,
        &req.name,
        &req.category,
        &req.query_template,
        &req.description,
        &req.risk_level,
        &req.tags,
    )
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": template_id,
        "name": req.name,
        "message": "Custom template created"
    })))
}

/// Delete a custom dork template
///
/// DELETE /api/recon/dorks/templates/{id}
pub async fn delete_custom_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Verify ownership
    let template = db::get_custom_template_by_id(pool.get_ref(), &template_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Template not found"))?;

    if template.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied"));
    }

    db::delete_custom_template(pool.get_ref(), &template_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Template deleted",
        "id": template_id
    })))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Parse category string to DorkCategory
fn parse_category(s: &str) -> Option<DorkCategory> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "sensitive_files" | "sensitivefiles" => Some(DorkCategory::SensitiveFiles),
        "login_pages" | "loginpages" => Some(DorkCategory::LoginPages),
        "config_files" | "configfiles" | "configuration_files" => Some(DorkCategory::ConfigFiles),
        "error_messages" | "errormessages" => Some(DorkCategory::ErrorMessages),
        "admin_panels" | "adminpanels" => Some(DorkCategory::AdminPanels),
        "directories" | "directory_listings" => Some(DorkCategory::Directories),
        "database_files" | "databasefiles" => Some(DorkCategory::DatabaseFiles),
        "backup_files" | "backupfiles" => Some(DorkCategory::BackupFiles),
        "api_endpoints" | "apiendpoints" => Some(DorkCategory::ApiEndpoints),
        "cloud_storage" | "cloudstorage" => Some(DorkCategory::CloudStorage),
        "source_control" | "sourcecontrol" => Some(DorkCategory::SourceControl),
        "log_files" | "logfiles" => Some(DorkCategory::LogFiles),
        _ => None,
    }
}

// =============================================================================
// Route Configuration
// =============================================================================

/// Configure dorking routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/recon/dorks")
            .route("", web::post().to(run_dorks))
            .route("/custom", web::post().to(run_custom_dork))
            .route("/templates", web::get().to(list_templates))
            .route("/templates", web::post().to(create_custom_template))
            .route("/templates/{id}", web::delete().to(delete_custom_template))
            .route("/categories", web::get().to(list_categories))
            .route("/results", web::get().to(list_scans))
            .route("/results/{id}", web::get().to(get_scan_results))
            .route("/results/{id}", web::delete().to(delete_scan)),
    );
}
