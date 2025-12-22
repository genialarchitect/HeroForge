//! Attack Surface Management (ASM) API endpoints
//!
//! Provides continuous external monitoring with scheduled discovery,
//! change detection, and risk scoring.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::asm::{
    AssetDiscoveryConfig, AlertConfig,
    monitor::AsmMonitorEngine,
};
use crate::db;
use crate::web::auth;

/// Configure ASM routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/asm")
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard))
            // Monitors
            .route("/monitors", web::post().to(create_monitor))
            .route("/monitors", web::get().to(list_monitors))
            .route("/monitors/{id}", web::get().to(get_monitor))
            .route("/monitors/{id}", web::put().to(update_monitor))
            .route("/monitors/{id}", web::delete().to(delete_monitor))
            .route("/monitors/{id}/run", web::post().to(run_monitor))
            .route("/monitors/{id}/enable", web::post().to(enable_monitor))
            .route("/monitors/{id}/disable", web::post().to(disable_monitor))
            // Baselines
            .route("/monitors/{id}/baselines", web::get().to(list_baselines))
            .route("/monitors/{id}/baselines", web::post().to(create_baseline))
            .route("/monitors/{monitor_id}/baselines/{baseline_id}/activate", web::post().to(activate_baseline))
            // Changes
            .route("/changes", web::get().to(list_all_changes))
            .route("/monitors/{id}/changes", web::get().to(list_monitor_changes))
            .route("/changes/{id}/acknowledge", web::post().to(acknowledge_change))
            // Risk Scores
            .route("/risk-scores", web::get().to(get_risk_scores))
            // Authorized Assets (Shadow IT whitelist)
            .route("/authorized-assets", web::get().to(list_authorized_assets))
            .route("/authorized-assets", web::post().to(create_authorized_asset))
            .route("/authorized-assets/{id}", web::delete().to(delete_authorized_asset))
            // Timeline
            .route("/monitors/{id}/timeline", web::get().to(get_monitor_timeline))
    );
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateMonitorRequest {
    pub name: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub discovery_config: Option<AssetDiscoveryConfig>,
    #[serde(default = "default_schedule")]
    pub schedule: String,
    #[serde(default)]
    pub alert_config: Option<AlertConfig>,
}

fn default_schedule() -> String {
    "0 0 * * *".to_string() // Daily at midnight
}

#[derive(Debug, Deserialize)]
pub struct UpdateMonitorRequest {
    pub name: Option<String>,
    pub domains: Option<Vec<String>>,
    pub discovery_config: Option<AssetDiscoveryConfig>,
    pub schedule: Option<String>,
    pub alert_config: Option<AlertConfig>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAuthorizedAssetRequest {
    pub hostname_pattern: String,
    pub ip_ranges: Option<Vec<String>>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangesFilter {
    pub severity: Option<String>,
    pub change_type: Option<String>,
    pub acknowledged: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct MonitorRunResponse {
    pub success: bool,
    pub message: String,
    pub assets_discovered: Option<usize>,
    pub changes_detected: Option<usize>,
    pub duration_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub severity: Option<String>,
    pub details: Option<serde_json::Value>,
}

// ============================================================================
// Dashboard Endpoint
// ============================================================================

/// Get ASM dashboard statistics
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let engine = AsmMonitorEngine::new(pool.get_ref().clone());

    match engine.get_dashboard(&claims.sub).await {
        Ok(dashboard) => HttpResponse::Ok().json(dashboard),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Monitor CRUD Endpoints
// ============================================================================

/// Create a new ASM monitor
pub async fn create_monitor(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateMonitorRequest>,
) -> HttpResponse {
    if body.domains.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one domain is required"
        }));
    }

    let req = crate::asm::CreateMonitorRequest {
        name: body.name.clone(),
        description: None,
        domains: body.domains.clone(),
        discovery_config: body.discovery_config.clone(),
        schedule: body.schedule.clone(),
        alert_config: body.alert_config.clone(),
    };

    match db::asm::create_monitor(pool.get_ref(), &claims.sub, &req).await {
        Ok(monitor) => HttpResponse::Created().json(monitor),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// List all monitors for the current user
pub async fn list_monitors(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match db::asm::get_user_monitors(pool.get_ref(), &claims.sub).await {
        Ok(monitors) => HttpResponse::Ok().json(monitors),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Get a specific monitor
pub async fn get_monitor(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to access this monitor"
                }));
            }
            HttpResponse::Ok().json(monitor)
        }
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Update a monitor
pub async fn update_monitor(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateMonitorRequest>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    // Get existing monitor to verify ownership
    let monitor = match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(m) => m,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    if monitor.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to modify this monitor"
        }));
    }

    // Validate domains if provided
    if let Some(domains) = &body.domains {
        if domains.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "At least one domain is required"
            }));
        }
    }

    let req = crate::asm::UpdateMonitorRequest {
        name: body.name.clone(),
        description: None,
        domains: body.domains.clone(),
        discovery_config: body.discovery_config.clone(),
        schedule: body.schedule.clone(),
        alert_config: body.alert_config.clone(),
        enabled: None,
    };

    match db::asm::update_monitor(pool.get_ref(), &monitor_id, &req).await {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Delete a monitor
pub async fn delete_monitor(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    // Verify ownership
    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to delete this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match db::asm::delete_monitor(pool.get_ref(), &monitor_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Run a monitor manually
pub async fn run_monitor(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    // Verify ownership
    let monitor = match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(m) => m,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    if monitor.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to run this monitor"
        }));
    }

    if !monitor.enabled {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Monitor is disabled"
        }));
    }

    // Run the monitor
    let engine = AsmMonitorEngine::new(pool.get_ref().clone());
    match engine.run_monitor(&monitor_id).await {
        Ok(result) => HttpResponse::Ok().json(MonitorRunResponse {
            success: result.error.is_none(),
            message: result.error.unwrap_or_else(|| "Monitor run completed".to_string()),
            assets_discovered: Some(result.assets_discovered),
            changes_detected: Some(result.changes_detected),
            duration_secs: Some(result.duration_secs),
        }),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Enable a monitor
pub async fn enable_monitor(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to modify this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match db::asm::set_monitor_enabled(pool.get_ref(), &monitor_id, true).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Monitor enabled"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Disable a monitor
pub async fn disable_monitor(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to modify this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match db::asm::set_monitor_enabled(pool.get_ref(), &monitor_id, false).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Monitor disabled"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Baseline Endpoints
// ============================================================================

/// List baselines for a monitor
pub async fn list_baselines(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    // Verify ownership
    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to access this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match db::asm::get_monitor_baselines(pool.get_ref(), &monitor_id).await {
        Ok(baselines) => HttpResponse::Ok().json(baselines),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Create a new baseline (snapshot current state)
pub async fn create_baseline(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    // Verify ownership
    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to access this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    // Get current active baseline assets, or empty if none
    let current_assets = match db::asm::get_active_baseline(pool.get_ref(), &monitor_id).await {
        Ok(baseline) => baseline.assets,
        Err(_) => vec![],
    };

    // Create new baseline from current assets
    let baseline = crate::asm::baseline::BaselineManager::create_baseline_from_assets(&monitor_id, current_assets);

    match db::asm::create_baseline(pool.get_ref(), &baseline).await {
        Ok(_) => HttpResponse::Created().json(baseline),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Activate a specific baseline
pub async fn activate_baseline(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (monitor_id, baseline_id) = path.into_inner();

    // Verify ownership
    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to access this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match db::asm::activate_baseline(pool.get_ref(), &baseline_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Baseline activated"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Change Endpoints
// ============================================================================

/// List all changes across all monitors
pub async fn list_all_changes(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ChangesFilter>,
) -> HttpResponse {
    match db::asm::get_user_changes(
        pool.get_ref(),
        &claims.sub,
        query.severity.as_deref(),
        query.change_type.as_deref(),
        query.acknowledged,
        query.limit.unwrap_or(100),
        query.offset.unwrap_or(0),
    ).await {
        Ok(changes) => HttpResponse::Ok().json(changes),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// List changes for a specific monitor
pub async fn list_monitor_changes(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<ChangesFilter>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    // Verify ownership
    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to access this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match db::asm::get_monitor_changes_filtered(
        pool.get_ref(),
        &monitor_id,
        query.severity.as_deref(),
        query.change_type.as_deref(),
        query.acknowledged,
        query.limit.unwrap_or(100),
        query.offset.unwrap_or(0),
    ).await {
        Ok(changes) => HttpResponse::Ok().json(changes),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Acknowledge a change
pub async fn acknowledge_change(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let change_id = path.into_inner();

    // Get the change and verify ownership through monitor
    let change = match db::asm::get_change(pool.get_ref(), &change_id).await {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    let monitor = match db::asm::get_monitor(pool.get_ref(), &change.monitor_id).await {
        Ok(m) => m,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    if monitor.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to acknowledge this change"
        }));
    }

    match db::asm::acknowledge_change(pool.get_ref(), &change_id, &claims.sub).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Change acknowledged"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Risk Score Endpoints
// ============================================================================

/// Get risk scores for user's assets
pub async fn get_risk_scores(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match db::asm::get_risk_scores(pool.get_ref(), &claims.sub).await {
        Ok(scores) => HttpResponse::Ok().json(scores),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Authorized Assets (Shadow IT Whitelist) Endpoints
// ============================================================================

/// List authorized asset patterns
pub async fn list_authorized_assets(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match db::asm::get_authorized_assets(pool.get_ref(), &claims.sub).await {
        Ok(assets) => HttpResponse::Ok().json(assets),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Create an authorized asset pattern
pub async fn create_authorized_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateAuthorizedAssetRequest>,
) -> HttpResponse {
    // Validate the hostname pattern is a valid regex
    if regex::Regex::new(&body.hostname_pattern).is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid hostname pattern (must be valid regex)"
        }));
    }

    match db::asm::create_authorized_asset(
        pool.get_ref(),
        &claims.sub,
        &body.hostname_pattern,
        &body.ip_ranges.clone().unwrap_or_default(),
        body.description.as_deref(),
    ).await {
        Ok(asset) => HttpResponse::Created().json(asset),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Delete an authorized asset pattern
pub async fn delete_authorized_asset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let asset_id = path.into_inner();

    // Verify ownership
    match db::asm::get_authorized_asset(pool.get_ref(), &asset_id).await {
        Ok(asset) => {
            if asset.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to delete this pattern"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match db::asm::delete_authorized_asset(pool.get_ref(), &asset_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Timeline Endpoints
// ============================================================================

/// Get a timeline of events for a monitor
pub async fn get_monitor_timeline(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let monitor_id = path.into_inner();

    // Verify ownership
    match db::asm::get_monitor(pool.get_ref(), &monitor_id).await {
        Ok(monitor) => {
            if monitor.user_id != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Not authorized to access this monitor"
                }));
            }
        }
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    // Get recent changes as timeline entries
    let changes = match db::asm::get_monitor_changes_filtered(
        pool.get_ref(),
        &monitor_id,
        None,
        None,
        None,
        50,
        0,
    ).await {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    let timeline: Vec<TimelineEntry> = changes.iter().map(|c| {
        TimelineEntry {
            timestamp: c.detected_at.to_rfc3339(),
            event_type: format!("{:?}", c.change_type),
            description: c.details.description.clone(),
            severity: Some(format!("{:?}", c.severity)),
            details: Some(serde_json::json!({
                "hostname": c.hostname,
                "acknowledged": c.acknowledged,
            })),
        }
    }).collect();

    HttpResponse::Ok().json(timeline)
}
