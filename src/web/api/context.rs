//! Cross-Team Context API
//!
//! Provides unified security context endpoints for users, assets, and threats.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};

use crate::web::auth::Claims;
use crate::web::error::ApiError;
use crate::db::cross_team;
use crate::context::{UserSecurityContext, AssetSecurityContext};
use crate::event_bus::{EventPublisher, SecurityEvent};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GetContextQuery {
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserContextResponse {
    pub context: UserSecurityContext,
}

#[derive(Debug, Serialize)]
pub struct AssetContextResponse {
    pub context: AssetSecurityContext,
}

#[derive(Debug, Serialize)]
pub struct HighRiskUsersResponse {
    pub users: Vec<cross_team::UserSecurityContext>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct HighRiskAssetsResponse {
    pub assets: Vec<cross_team::AssetSecurityContext>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct EventsResponse {
    pub events: Vec<cross_team::CrossTeamEvent>,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
pub struct PublishEventRequest {
    pub event: serde_json::Value,
}

// ============================================================================
// User Context Endpoints
// ============================================================================

/// GET /api/context/user/{user_id} - Get unified user security context
pub async fn get_user_context(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    let db_context = cross_team::get_user_context(&pool, &user_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get user context: {}", e)))?;

    // Convert database context to rich context
    let context = UserSecurityContext {
        user_id: db_context.user_id,
        username: db_context.username,
        email: db_context.email,
        department: db_context.department,
        role: db_context.role,
        orange_team: crate::context::user::OrangeTeamContext {
            training_completion_rate: db_context.training_completion_rate,
            phishing_click_rate: db_context.phishing_click_rate,
            security_awareness_score: db_context.security_awareness_score,
            last_training: db_context.last_training,
            training_modules_completed: 0, // TODO: fetch from orange team DB
            badges_earned: 0, // TODO: fetch from orange team DB
            gamification_rank: None, // TODO: fetch from orange team DB
        },
        green_team: crate::context::user::GreenTeamContext {
            incident_count: db_context.incident_count as usize,
            insider_threat_score: db_context.insider_threat_score,
            suspicious_activity_count: db_context.suspicious_activity_count as usize,
            last_incident: None, // TODO: fetch from green team DB
            anomaly_detections: 0, // TODO: fetch from green team DB
        },
        yellow_team: if db_context.secure_coding_score.is_some() {
            Some(crate::context::user::YellowTeamContext {
                secure_coding_score: db_context.secure_coding_score.unwrap_or(0.0),
                code_review_compliance: db_context.code_review_compliance.unwrap_or(0.0),
                vulnerabilities_introduced: 0, // TODO: fetch from yellow team DB
                security_champions: false, // TODO: fetch from yellow team DB
                last_code_scan: None, // TODO: fetch from yellow team DB
            })
        } else {
            None
        },
        white_team: crate::context::user::WhiteTeamContext {
            compliance_violations: db_context.compliance_violations as usize,
            policy_violations: db_context.policy_violations as usize,
            compliance_status: Vec::new(), // TODO: fetch from white team DB
            mandatory_training_complete: false, // TODO: fetch from white team DB
            risk_acknowledgements: 0, // TODO: fetch from white team DB
        },
        overall_risk_score: db_context.overall_risk_score,
        risk_level: crate::context::user::RiskLevel::from_score(db_context.overall_risk_score),
        updated_at: db_context.updated_at,
    };

    Ok(HttpResponse::Ok().json(UserContextResponse { context }))
}

/// GET /api/context/users/high-risk - Get high-risk users
pub async fn get_high_risk_users(
    pool: web::Data<SqlitePool>,
    query: web::Query<GetContextQuery>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(10);

    let users = cross_team::get_high_risk_users(&pool, limit)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get high-risk users: {}", e)))?;

    let total = users.len();

    Ok(HttpResponse::Ok().json(HighRiskUsersResponse { users, total }))
}

// ============================================================================
// Asset Context Endpoints
// ============================================================================

/// GET /api/context/asset/{asset_id} - Get unified asset security context
pub async fn get_asset_context(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    let db_context = cross_team::get_asset_context(&pool, &asset_id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get asset context: {}", e)))?;

    // Parse IP addresses from JSON string
    let ip_addresses: Vec<String> = serde_json::from_str(&db_context.ip_addresses)
        .unwrap_or_else(|_| vec![]);

    // Parse compliance scopes from JSON string
    let compliance_scopes: Vec<String> = serde_json::from_str(&db_context.compliance_scopes)
        .unwrap_or_else(|_| vec![]);

    // Convert database context to rich context
    let context = AssetSecurityContext {
        asset_id: db_context.asset_id,
        asset_type: parse_asset_type(&db_context.asset_type),
        hostname: db_context.hostname,
        ip_addresses,
        owner: db_context.owner,
        red_team: crate::context::asset::RedTeamContext {
            vulnerability_count: db_context.vulnerability_count as usize,
            critical_vuln_count: db_context.critical_vuln_count as usize,
            high_vuln_count: db_context.high_vuln_count as usize,
            medium_vuln_count: 0, // TODO: fetch from scan results
            low_vuln_count: 0, // TODO: fetch from scan results
            last_scan: db_context.last_scan,
            exploitability_score: db_context.exploitability_score,
            attack_surface_score: 0.0, // TODO: calculate from scan results
            open_ports: 0, // TODO: fetch from scan results
            exposed_services: Vec::new(), // TODO: fetch from scan results
        },
        blue_team: crate::context::asset::BlueTeamContext {
            detection_coverage: db_context.detection_coverage,
            monitored: db_context.monitored,
            detection_rule_count: db_context.detection_rule_count as usize,
            siem_integrated: false, // TODO: fetch from blue team DB
            edr_installed: false, // TODO: fetch from blue team DB
            last_detection: None, // TODO: fetch from blue team DB
        },
        green_team: crate::context::asset::AssetGreenTeamContext {
            incident_count: db_context.incident_count as usize,
            alert_count: db_context.alert_count as usize,
            last_incident: None, // TODO: fetch from green team DB
            mean_time_to_detect: None, // TODO: fetch from green team DB
            mean_time_to_respond: None, // TODO: fetch from green team DB
        },
        purple_team: crate::context::asset::PurpleTeamContext {
            attack_simulation_count: db_context.attack_simulation_count as usize,
            detection_gap_count: db_context.detection_gap_count as usize,
            last_exercise: None, // TODO: fetch from purple team DB
            detection_effectiveness: 0.0, // TODO: fetch from purple team DB
            mitre_coverage: 0.0, // TODO: fetch from purple team DB
        },
        white_team: crate::context::asset::AssetWhiteTeamContext {
            compliance_scopes,
            risk_rating: db_context.risk_rating,
            last_risk_assessment: None, // TODO: fetch from white team DB
            compliance_violations: 0, // TODO: fetch from white team DB
        },
        overall_risk_score: db_context.overall_risk_score,
        risk_level: db_context.risk_level,
        updated_at: db_context.updated_at,
    };

    Ok(HttpResponse::Ok().json(AssetContextResponse { context }))
}

/// GET /api/context/assets/high-risk - Get high-risk assets
pub async fn get_high_risk_assets(
    pool: web::Data<SqlitePool>,
    query: web::Query<GetContextQuery>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(10);

    let assets = cross_team::get_high_risk_assets(&pool, limit)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get high-risk assets: {}", e)))?;

    let total = assets.len();

    Ok(HttpResponse::Ok().json(HighRiskAssetsResponse { assets, total }))
}

// ============================================================================
// Event Bus Endpoints
// ============================================================================

/// GET /api/context/events - Get recent cross-team events
pub async fn get_recent_events(
    pool: web::Data<SqlitePool>,
    query: web::Query<GetContextQuery>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50);

    let events = cross_team::get_recent_events(&pool, limit)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get recent events: {}", e)))?;

    let total = events.len();

    Ok(HttpResponse::Ok().json(EventsResponse { events, total }))
}

/// GET /api/context/events/type/{event_type} - Get events by type
pub async fn get_events_by_type(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<GetContextQuery>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let event_type = path.into_inner();
    let limit = query.limit.unwrap_or(50);

    let events = cross_team::get_events_by_type(&pool, &event_type, limit)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get events by type: {}", e)))?;

    let total = events.len();

    Ok(HttpResponse::Ok().json(EventsResponse { events, total }))
}

/// GET /api/context/events/source/{source_team} - Get events by source team
pub async fn get_events_by_source(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<GetContextQuery>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    let source_team = path.into_inner();
    let limit = query.limit.unwrap_or(50);

    let events = cross_team::get_events_by_source(&pool, &source_team, limit)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get events by source: {}", e)))?;

    let total = events.len();

    Ok(HttpResponse::Ok().json(EventsResponse { events, total }))
}

/// POST /api/context/events - Publish event to event bus
pub async fn publish_event(
    pool: web::Data<SqlitePool>,
    publisher: web::Data<EventPublisher>,
    payload: web::Json<PublishEventRequest>,
    _claims: Claims,
) -> Result<HttpResponse, ApiError> {
    // Deserialize the event from the request
    let event: SecurityEvent = serde_json::from_value(payload.event.clone())
        .map_err(|e| ApiError::bad_request(format!("Invalid event format: {}", e)))?;

    // Publish the event
    publisher.publish(event).await
        .map_err(|e| ApiError::internal(format!("Failed to publish event: {}", e)))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Event published successfully"
    })))
}

// ============================================================================
// Helper Functions
// ============================================================================

fn parse_asset_type(asset_type: &str) -> crate::context::asset::AssetType {
    match asset_type.to_lowercase().as_str() {
        "server" => crate::context::asset::AssetType::Server,
        "workstation" => crate::context::asset::AssetType::Workstation,
        "network" => crate::context::asset::AssetType::Network,
        "cloud" => crate::context::asset::AssetType::Cloud,
        "container" => crate::context::asset::AssetType::Container,
        "database" => crate::context::asset::AssetType::Database,
        "webapp" => crate::context::asset::AssetType::WebApp,
        "mobile" => crate::context::asset::AssetType::Mobile,
        "iot" => crate::context::asset::AssetType::IoT,
        "ot" => crate::context::asset::AssetType::OT,
        _ => crate::context::asset::AssetType::Unknown,
    }
}

// ============================================================================
// Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/context")
            .route("/user/{user_id}", web::get().to(get_user_context))
            .route("/users/high-risk", web::get().to(get_high_risk_users))
            .route("/asset/{asset_id}", web::get().to(get_asset_context))
            .route("/assets/high-risk", web::get().to(get_high_risk_assets))
            .route("/events", web::get().to(get_recent_events))
            .route("/events", web::post().to(publish_event))
            .route("/events/type/{event_type}", web::get().to(get_events_by_type))
            .route("/events/source/{source_team}", web::get().to(get_events_by_source))
    );
}
