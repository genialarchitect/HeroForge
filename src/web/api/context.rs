//! Cross-Team Context API
//!
//! Provides unified security context endpoints for users, assets, and threats.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::web::auth::Claims;
use crate::web::error::ApiError;
use crate::db::cross_team;
use crate::context::{UserSecurityContext, AssetSecurityContext};
use crate::context::user::ComplianceStatus;
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

    // Fetch additional context data from various team databases
    let training_modules_completed = fetch_training_modules_completed(&pool, &user_id).await;
    let badges_earned = fetch_badges_earned(&pool, &user_id).await;
    let gamification_rank = fetch_gamification_rank(&pool, &user_id).await;
    let last_incident = fetch_last_incident(&pool, &user_id).await;
    let anomaly_detections = fetch_anomaly_detections(&pool, &user_id).await;
    let vulnerabilities_introduced = fetch_vulnerabilities_introduced(&pool, &user_id).await;
    let security_champions = fetch_security_champion_status(&pool, &user_id).await;
    let last_code_scan = fetch_last_code_scan(&pool, &user_id).await;
    let compliance_status = fetch_compliance_status(&pool, &user_id).await;
    let mandatory_training_complete = fetch_mandatory_training_complete(&pool, &user_id).await;
    let risk_acknowledgements = fetch_risk_acknowledgements(&pool, &user_id).await;

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
            training_modules_completed: training_modules_completed as usize,
            badges_earned: badges_earned as usize,
            gamification_rank,
        },
        green_team: crate::context::user::GreenTeamContext {
            incident_count: db_context.incident_count as usize,
            insider_threat_score: db_context.insider_threat_score,
            suspicious_activity_count: db_context.suspicious_activity_count as usize,
            last_incident,
            anomaly_detections,
        },
        yellow_team: if db_context.secure_coding_score.is_some() {
            Some(crate::context::user::YellowTeamContext {
                secure_coding_score: db_context.secure_coding_score.unwrap_or(0.0),
                code_review_compliance: db_context.code_review_compliance.unwrap_or(0.0),
                vulnerabilities_introduced,
                security_champions,
                last_code_scan,
            })
        } else {
            None
        },
        white_team: crate::context::user::WhiteTeamContext {
            compliance_violations: db_context.compliance_violations as usize,
            policy_violations: db_context.policy_violations as usize,
            compliance_status,
            mandatory_training_complete,
            risk_acknowledgements,
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

    // Fetch additional context data from various team databases
    let medium_vuln_count = fetch_medium_vuln_count(&pool, &asset_id).await;
    let low_vuln_count = fetch_low_vuln_count(&pool, &asset_id).await;
    let attack_surface_score = fetch_attack_surface_score(&pool, &asset_id).await;
    let open_ports = fetch_open_ports(&pool, &asset_id).await;
    let exposed_services = fetch_exposed_services(&pool, &asset_id).await;
    let siem_integrated = fetch_siem_integrated(&pool, &asset_id).await;
    let edr_installed = fetch_edr_installed(&pool, &asset_id).await;
    let last_detection = fetch_last_detection(&pool, &asset_id).await;
    let last_incident = fetch_asset_last_incident(&pool, &asset_id).await;
    let mean_time_to_detect = fetch_mean_time_to_detect(&pool, &asset_id).await;
    let mean_time_to_respond = fetch_mean_time_to_respond(&pool, &asset_id).await;
    let last_exercise = fetch_last_exercise(&pool, &asset_id).await;
    let detection_effectiveness = fetch_detection_effectiveness(&pool, &asset_id).await;
    let mitre_coverage = fetch_mitre_coverage(&pool, &asset_id).await;
    let last_risk_assessment = fetch_last_risk_assessment(&pool, &asset_id).await;
    let asset_compliance_violations = fetch_asset_compliance_violations(&pool, &asset_id).await;

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
            medium_vuln_count,
            low_vuln_count,
            last_scan: db_context.last_scan,
            exploitability_score: db_context.exploitability_score,
            attack_surface_score,
            open_ports,
            exposed_services,
        },
        blue_team: crate::context::asset::BlueTeamContext {
            detection_coverage: db_context.detection_coverage,
            monitored: db_context.monitored,
            detection_rule_count: db_context.detection_rule_count as usize,
            siem_integrated,
            edr_installed,
            last_detection,
        },
        green_team: crate::context::asset::AssetGreenTeamContext {
            incident_count: db_context.incident_count as usize,
            alert_count: db_context.alert_count as usize,
            last_incident,
            mean_time_to_detect,
            mean_time_to_respond,
        },
        purple_team: crate::context::asset::PurpleTeamContext {
            attack_simulation_count: db_context.attack_simulation_count as usize,
            detection_gap_count: db_context.detection_gap_count as usize,
            last_exercise,
            detection_effectiveness,
            mitre_coverage,
        },
        white_team: crate::context::asset::AssetWhiteTeamContext {
            compliance_scopes,
            risk_rating: db_context.risk_rating,
            last_risk_assessment,
            compliance_violations: asset_compliance_violations,
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
// User Context Database Queries
// ============================================================================

/// Fetch training modules completed count from orange team DB
async fn fetch_training_modules_completed(pool: &SqlitePool, user_id: &str) -> u32 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM training_enrollments WHERE user_id = ? AND status = 'completed'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as u32
}

/// Fetch badges earned count from orange team DB
async fn fetch_badges_earned(pool: &SqlitePool, user_id: &str) -> u32 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM user_badges WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as u32
}

/// Fetch gamification rank from orange team DB
async fn fetch_gamification_rank(pool: &SqlitePool, user_id: &str) -> Option<usize> {
    // Get user's points and calculate rank
    let result = sqlx::query_as::<_, (i64,)>(
        r#"SELECT COUNT(*) + 1 as rank FROM user_points
           WHERE points > (SELECT COALESCE(points, 0) FROM user_points WHERE user_id = ?)"#
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    result.map(|(rank,)| rank as usize)
}

/// Fetch last incident timestamp from green team DB
async fn fetch_last_incident(pool: &SqlitePool, user_id: &str) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, String>(
        "SELECT MAX(created_at) FROM incidents WHERE assignee_id = ? OR user_id = ?"
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)))
}

/// Fetch anomaly detection count from green team DB (UEBA)
async fn fetch_anomaly_detections(pool: &SqlitePool, user_id: &str) -> usize {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ueba_anomalies WHERE entity_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as usize
}

/// Fetch vulnerabilities introduced count from yellow team DB
async fn fetch_vulnerabilities_introduced(pool: &SqlitePool, user_id: &str) -> usize {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sast_findings WHERE author = ? OR introduced_by = ?"
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as usize
}

/// Check if user is a security champion from yellow team DB
async fn fetch_security_champion_status(pool: &SqlitePool, user_id: &str) -> bool {
    // Check if user has security champion badge or role
    let badge_count = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM user_badges ub
           JOIN training_badges tb ON ub.badge_id = tb.id
           WHERE ub.user_id = ? AND tb.category = 'security_champion'"#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    badge_count > 0
}

/// Fetch last code scan timestamp from yellow team DB
async fn fetch_last_code_scan(pool: &SqlitePool, user_id: &str) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, String>(
        "SELECT MAX(created_at) FROM sast_scans WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)))
}

/// Fetch compliance status list from white team DB
async fn fetch_compliance_status(pool: &SqlitePool, user_id: &str) -> Vec<ComplianceStatus> {
    #[derive(sqlx::FromRow)]
    struct ComplianceRow {
        framework: String,
        status: String,
        created_at: String,
    }

    let rows = sqlx::query_as::<_, ComplianceRow>(
        r#"SELECT DISTINCT ctr.framework, cts.status, cts.completed_at as created_at
           FROM compliance_training_status cts
           JOIN compliance_training_requirements ctr ON cts.requirement_id = ctr.id
           WHERE cts.user_id = ?"#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .filter_map(|row| {
            DateTime::parse_from_rfc3339(&row.created_at)
                .ok()
                .map(|dt| ComplianceStatus {
                    framework: row.framework,
                    status: row.status,
                    last_assessed: dt.with_timezone(&Utc),
                })
        })
        .collect()
}

/// Check if mandatory training is complete from white team DB
async fn fetch_mandatory_training_complete(pool: &SqlitePool, user_id: &str) -> bool {
    let incomplete = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM compliance_training_status
           WHERE user_id = ? AND status != 'completed'"#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(1);

    incomplete == 0
}

/// Fetch risk acknowledgements count from white team DB
async fn fetch_risk_acknowledgements(pool: &SqlitePool, user_id: &str) -> usize {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM grc_policy_acknowledgments WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as usize
}

// ============================================================================
// Asset Context Database Queries
// ============================================================================

/// Fetch medium vulnerability count for an asset
async fn fetch_medium_vuln_count(pool: &SqlitePool, asset_id: &str) -> usize {
    sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking
           WHERE asset_id = ? AND severity = 'medium' AND status NOT IN ('resolved', 'false_positive')"#
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as usize
}

/// Fetch low vulnerability count for an asset
async fn fetch_low_vuln_count(pool: &SqlitePool, asset_id: &str) -> usize {
    sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM vulnerability_tracking
           WHERE asset_id = ? AND severity = 'low' AND status NOT IN ('resolved', 'false_positive')"#
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as usize
}

/// Calculate attack surface score from scan results
async fn fetch_attack_surface_score(pool: &SqlitePool, asset_id: &str) -> f64 {
    // Attack surface score based on open ports and exposed services
    let open_ports = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM asset_ports WHERE asset_id = ? AND current_state = 'open'"
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    // Normalize to 0-100 scale (max 50 ports = 100 score)
    (open_ports as f64 / 50.0 * 100.0).min(100.0)
}

/// Fetch open ports count for an asset
async fn fetch_open_ports(pool: &SqlitePool, asset_id: &str) -> usize {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM asset_ports WHERE asset_id = ? AND current_state = 'open'"
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as usize
}

/// Fetch exposed services for an asset
async fn fetch_exposed_services(pool: &SqlitePool, asset_id: &str) -> Vec<String> {
    let services = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT service FROM asset_ports WHERE asset_id = ? AND current_state = 'open' AND service IS NOT NULL"
    )
    .bind(asset_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    services
}

/// Check if asset is SIEM integrated
async fn fetch_siem_integrated(pool: &SqlitePool, asset_id: &str) -> bool {
    let count = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM siem_log_sources
           WHERE (source_id = ? OR host = ?) AND status = 'active'"#
    )
    .bind(asset_id)
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    count > 0
}

/// Check if EDR is installed on asset (check for agent presence)
async fn fetch_edr_installed(pool: &SqlitePool, asset_id: &str) -> bool {
    let count = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM scan_agents
           WHERE asset_id = ? AND agent_type = 'edr' AND status = 'active'"#
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    count > 0
}

/// Fetch last detection timestamp for an asset
async fn fetch_last_detection(pool: &SqlitePool, asset_id: &str) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT MAX(created_at) FROM siem_alerts
           WHERE source_ip = ? OR destination_ip = ?"#
    )
    .bind(asset_id)
    .bind(asset_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)))
}

/// Fetch last incident for an asset from green team DB
async fn fetch_asset_last_incident(pool: &SqlitePool, asset_id: &str) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT MAX(i.created_at) FROM incidents i
           JOIN incident_alerts ia ON i.id = ia.incident_id
           JOIN siem_alerts sa ON ia.alert_id = sa.id
           WHERE sa.source_ip = ? OR sa.destination_ip = ?"#
    )
    .bind(asset_id)
    .bind(asset_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)))
}

/// Calculate mean time to detect for an asset
async fn fetch_mean_time_to_detect(pool: &SqlitePool, asset_id: &str) -> Option<u64> {
    // Calculate average time between event timestamp and alert creation
    let result = sqlx::query_scalar::<_, f64>(
        r#"SELECT AVG(
            (julianday(created_at) - julianday(event_timestamp)) * 86400000
        ) FROM siem_alerts
        WHERE (source_ip = ? OR destination_ip = ?)
        AND event_timestamp IS NOT NULL"#
    )
    .bind(asset_id)
    .bind(asset_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    result.map(|ms| ms as u64)
}

/// Calculate mean time to respond for an asset
async fn fetch_mean_time_to_respond(pool: &SqlitePool, asset_id: &str) -> Option<u64> {
    // Calculate average time between incident creation and resolution
    let result = sqlx::query_scalar::<_, f64>(
        r#"SELECT AVG(
            (julianday(closed_at) - julianday(created_at)) * 86400000
        ) FROM incidents i
        JOIN incident_alerts ia ON i.id = ia.incident_id
        JOIN siem_alerts sa ON ia.alert_id = sa.id
        WHERE (sa.source_ip = ? OR sa.destination_ip = ?)
        AND i.closed_at IS NOT NULL"#
    )
    .bind(asset_id)
    .bind(asset_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    result.map(|ms| ms as u64)
}

/// Fetch last purple team exercise for an asset
async fn fetch_last_exercise(pool: &SqlitePool, asset_id: &str) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT MAX(pe.created_at) FROM purple_attack_executions pe
           WHERE pe.target_asset = ?"#
    )
    .bind(asset_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)))
}

/// Calculate detection effectiveness from purple team results
async fn fetch_detection_effectiveness(pool: &SqlitePool, asset_id: &str) -> f64 {
    let result = sqlx::query_as::<_, (i64, i64)>(
        r#"SELECT
            COUNT(CASE WHEN detected = 1 THEN 1 END) as detected_count,
            COUNT(*) as total_count
        FROM purple_attack_executions
        WHERE target_asset = ?"#
    )
    .bind(asset_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    match result {
        Some((detected, total)) if total > 0 => (detected as f64 / total as f64) * 100.0,
        _ => 0.0,
    }
}

/// Calculate MITRE coverage from purple team data
async fn fetch_mitre_coverage(pool: &SqlitePool, asset_id: &str) -> f64 {
    // Count unique techniques tested vs total techniques in the matrix
    let tested = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(DISTINCT technique_id) FROM purple_attack_executions
           WHERE target_asset = ?"#
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    // Total MITRE techniques (approximately 200)
    let total_techniques = 200.0;
    (tested as f64 / total_techniques * 100.0).min(100.0)
}

/// Fetch last risk assessment for an asset from white team DB
async fn fetch_last_risk_assessment(pool: &SqlitePool, asset_id: &str) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, String>(
        r#"SELECT MAX(created_at) FROM grc_risk_assessments
           WHERE risk_id IN (SELECT id FROM grc_risks WHERE related_assets LIKE ?)"#
    )
    .bind(format!("%{}%", asset_id))
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)))
}

/// Fetch compliance violations count for an asset
async fn fetch_asset_compliance_violations(pool: &SqlitePool, asset_id: &str) -> usize {
    sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM grc_audit_findings
           WHERE asset_id = ? AND status NOT IN ('resolved', 'closed')"#
    )
    .bind(asset_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0) as usize
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
