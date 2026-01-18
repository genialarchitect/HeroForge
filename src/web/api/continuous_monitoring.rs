//! Continuous Monitoring API Endpoints
//!
//! Provides REST API for managing the continuous monitoring engine.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::monitoring::{
    MonitoringEngine, MonitoringConfig, TargetState, DetectedChange,
    MonitoringStatus, Baseline, AlertTriggers, AlertDestination,
};
use crate::web::auth;

/// Shared monitoring engine state
pub type MonitoringEngineState = Arc<RwLock<Option<MonitoringEngine>>>;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct StartMonitoringRequest {
    pub targets: Vec<String>,
    pub light_scan_interval_secs: Option<u64>,
    pub full_scan_interval_secs: Option<u64>,
    pub alert_destinations: Option<Vec<AlertDestination>>,
    pub alert_triggers: Option<AlertTriggers>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTargetRequest {
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBaselineRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcknowledgeChangeRequest {
    pub change_id: String,
}

#[derive(Debug, Serialize)]
pub struct MonitoringResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> MonitoringResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> MonitoringResponse<()> {
        MonitoringResponse {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/// GET /api/monitoring/status - Get monitoring engine status
pub async fn get_status(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
) -> HttpResponse {
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            let status = engine.get_status().await;
            HttpResponse::Ok().json(MonitoringResponse::success(status))
        }
        None => {
            HttpResponse::Ok().json(MonitoringResponse::success(MonitoringStatus {
                is_running: false,
                targets_count: 0,
                last_light_scan: None,
                last_full_scan: None,
                changes_detected_today: 0,
                alerts_sent_today: 0,
                uptime_seconds: 0,
            }))
        }
    }
}

/// POST /api/monitoring/start - Start the monitoring engine
pub async fn start_monitoring(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    engine_state: web::Data<MonitoringEngineState>,
    req: web::Json<StartMonitoringRequest>,
) -> HttpResponse {
    log::info!("User {} starting continuous monitoring", claims.sub);

    // Validate targets
    if req.targets.is_empty() {
        return HttpResponse::BadRequest().json(MonitoringResponse::<()>::error(
            "At least one target is required",
        ));
    }

    // Build configuration
    let mut config = MonitoringConfig::default();
    config.targets = req.targets.clone();

    if let Some(interval) = req.light_scan_interval_secs {
        config.light_scan_interval_secs = interval.max(1); // Minimum 1 second
    }

    if let Some(interval) = req.full_scan_interval_secs {
        config.full_scan_interval_secs = interval.max(60); // Minimum 1 minute
    }

    if let Some(destinations) = &req.alert_destinations {
        config.alert_destinations = destinations.clone();
    }

    if let Some(triggers) = &req.alert_triggers {
        config.alert_on = triggers.clone();
    }

    // Create and start engine
    let engine = MonitoringEngine::new(Arc::new(pool.get_ref().clone()), config);

    if let Err(e) = engine.start().await {
        return HttpResponse::InternalServerError().json(MonitoringResponse::<()>::error(
            format!("Failed to start monitoring: {}", e),
        ));
    }

    // Store engine in state
    let mut engine_guard = engine_state.write().await;
    *engine_guard = Some(engine);

    HttpResponse::Ok().json(MonitoringResponse::success(serde_json::json!({
        "message": "Monitoring started",
        "targets_count": req.targets.len()
    })))
}

/// POST /api/monitoring/stop - Stop the monitoring engine
pub async fn stop_monitoring(
    claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
) -> HttpResponse {
    log::info!("User {} stopping continuous monitoring", claims.sub);

    let mut engine_guard = engine_state.write().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            engine.stop().await;
            *engine_guard = None;
            HttpResponse::Ok().json(MonitoringResponse::success(serde_json::json!({
                "message": "Monitoring stopped"
            })))
        }
        None => {
            HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running"))
        }
    }
}

/// GET /api/monitoring/config - Get current configuration
pub async fn get_config(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
) -> HttpResponse {
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            let config = engine.get_config().await;
            HttpResponse::Ok().json(MonitoringResponse::success(config))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running")),
    }
}

/// PUT /api/monitoring/config - Update configuration
pub async fn update_config(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
    req: web::Json<MonitoringConfig>,
) -> HttpResponse {
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            engine.update_config(req.into_inner()).await;
            HttpResponse::Ok().json(MonitoringResponse::success(serde_json::json!({
                "message": "Configuration updated"
            })))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running")),
    }
}

/// GET /api/monitoring/targets - Get all monitored targets and their states
pub async fn get_targets(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
) -> HttpResponse {
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            let states = engine.get_states().await;
            HttpResponse::Ok().json(MonitoringResponse::success(states))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::success(Vec::<TargetState>::new())),
    }
}

/// POST /api/monitoring/targets - Add a new target
pub async fn add_target(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
    req: web::Json<AddTargetRequest>,
) -> HttpResponse {
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            engine.add_target(req.target.clone()).await;
            HttpResponse::Ok().json(MonitoringResponse::success(serde_json::json!({
                "message": format!("Target {} added", req.target)
            })))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running")),
    }
}

/// DELETE /api/monitoring/targets/{target} - Remove a target
pub async fn remove_target(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
    path: web::Path<String>,
) -> HttpResponse {
    let target = path.into_inner();
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            engine.remove_target(&target).await;
            HttpResponse::Ok().json(MonitoringResponse::success(serde_json::json!({
                "message": format!("Target {} removed", target)
            })))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running")),
    }
}

/// GET /api/monitoring/changes - Get recent changes
pub async fn get_changes(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
    query: web::Query<LimitQuery>,
) -> HttpResponse {
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            let limit = query.limit.unwrap_or(100);
            let changes = engine.get_recent_changes(limit).await;
            HttpResponse::Ok().json(MonitoringResponse::success(changes))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::success(Vec::<DetectedChange>::new())),
    }
}

#[derive(Debug, Deserialize)]
pub struct LimitQuery {
    pub limit: Option<usize>,
}

/// POST /api/monitoring/changes/{change_id}/acknowledge - Acknowledge a change
pub async fn acknowledge_change(
    claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
    path: web::Path<String>,
) -> HttpResponse {
    let change_id = path.into_inner();
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            let acknowledged = engine.acknowledge_change(&change_id, &claims.sub).await;
            if acknowledged {
                HttpResponse::Ok().json(MonitoringResponse::success(serde_json::json!({
                    "message": "Change acknowledged"
                })))
            } else {
                HttpResponse::NotFound().json(MonitoringResponse::<()>::error("Change not found"))
            }
        }
        None => HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running")),
    }
}

/// POST /api/monitoring/baseline - Create a baseline from current state
pub async fn create_baseline(
    claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
    req: web::Json<CreateBaselineRequest>,
) -> HttpResponse {
    log::info!("User {} creating monitoring baseline: {}", claims.sub, req.name);

    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            let baseline = engine.create_baseline(req.name.clone(), req.description.clone()).await;
            HttpResponse::Ok().json(MonitoringResponse::success(baseline))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running")),
    }
}

/// POST /api/monitoring/baseline/set - Set the active baseline
pub async fn set_baseline(
    _claims: web::ReqData<auth::Claims>,
    engine_state: web::Data<MonitoringEngineState>,
    req: web::Json<Baseline>,
) -> HttpResponse {
    let engine_guard = engine_state.read().await;

    match engine_guard.as_ref() {
        Some(engine) => {
            engine.set_baseline(req.into_inner()).await;
            HttpResponse::Ok().json(MonitoringResponse::success(serde_json::json!({
                "message": "Baseline set"
            })))
        }
        None => HttpResponse::Ok().json(MonitoringResponse::<()>::error("Monitoring is not running")),
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    // Initialize shared engine state
    let engine_state: MonitoringEngineState = Arc::new(RwLock::new(None));

    cfg.app_data(web::Data::new(engine_state))
        .service(
            web::scope("/monitoring")
                // Status and control
                .route("/status", web::get().to(get_status))
                .route("/start", web::post().to(start_monitoring))
                .route("/stop", web::post().to(stop_monitoring))
                // Configuration
                .route("/config", web::get().to(get_config))
                .route("/config", web::put().to(update_config))
                // Targets
                .route("/targets", web::get().to(get_targets))
                .route("/targets", web::post().to(add_target))
                .route("/targets/{target}", web::delete().to(remove_target))
                // Changes
                .route("/changes", web::get().to(get_changes))
                .route("/changes/{change_id}/acknowledge", web::post().to(acknowledge_change))
                // Baselines
                .route("/baseline", web::post().to(create_baseline))
                .route("/baseline/set", web::post().to(set_baseline))
        );
}
