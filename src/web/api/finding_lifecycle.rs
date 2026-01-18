//! Finding Lifecycle Management API
//!
//! REST API endpoints for managing finding lifecycle states, transitions,
//! SLA tracking, and metrics.

use actix_web::{web, HttpResponse, Scope};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::findings::lifecycle::{
    FindingLifecycle, FindingState, LifecycleManager, LifecycleMetrics, SlAConfig, StateTransition,
};
use crate::web::auth::jwt::Claims;

/// Configure finding lifecycle routes
pub fn configure() -> Scope {
    web::scope("/finding-lifecycle")
        .route("", web::get().to(list_lifecycles))
        .route("/metrics", web::get().to(get_metrics))
        .route("/sla-breached", web::get().to(get_sla_breached))
        .route("/by-state/{state}", web::get().to(get_by_state))
        .route("/{finding_id}", web::get().to(get_lifecycle))
        .route("/{finding_id}", web::post().to(init_lifecycle))
        .route("/{finding_id}/transition", web::post().to(transition_state))
        .route("/{finding_id}/history", web::get().to(get_history))
        .route("/bulk-transition", web::post().to(bulk_transition))
        .route("/sla-policies", web::get().to(list_sla_policies))
        .route("/sla-policies", web::post().to(create_sla_policy))
        .route("/update-sla-status", web::post().to(update_sla_status))
}

/// List lifecycles request
#[derive(Debug, Deserialize)]
pub struct ListLifecyclesQuery {
    pub state: Option<String>,
    pub severity: Option<String>,
    pub sla_breached: Option<bool>,
    pub assigned_to: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// List all finding lifecycles
async fn list_lifecycles(
    pool: web::Data<SqlitePool>,
    query: web::Query<ListLifecyclesQuery>,
    _claims: Claims,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    let mut sql = String::from(
        "SELECT id, finding_id, current_state, severity, title, affected_asset,
                discovered_at, sla_due_at, sla_breached, assigned_to,
                created_at, updated_at
         FROM finding_lifecycles WHERE 1=1"
    );

    if let Some(ref state) = query.state {
        sql.push_str(&format!(" AND current_state = '{}'", state));
    }
    if let Some(ref severity) = query.severity {
        sql.push_str(&format!(" AND severity = '{}'", severity));
    }
    if let Some(breached) = query.sla_breached {
        sql.push_str(&format!(" AND sla_breached = {}", if breached { 1 } else { 0 }));
    }
    if let Some(ref assigned) = query.assigned_to {
        sql.push_str(&format!(" AND assigned_to = '{}'", assigned));
    }

    sql.push_str(&format!(" ORDER BY updated_at DESC LIMIT {} OFFSET {}", limit, offset));

    match sqlx::query_as::<_, LifecycleRow>(&sql)
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(rows) => {
            let lifecycles: Vec<LifecycleResponse> = rows.into_iter().map(|r| r.into()).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "lifecycles": lifecycles,
                "count": lifecycles.len(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to fetch lifecycles: {}", e)
        })),
    }
}

/// Get lifecycle metrics
async fn get_metrics(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    let manager = LifecycleManager::new(pool.get_ref().clone());

    match manager.get_metrics().await {
        Ok(metrics) => HttpResponse::Ok().json(metrics),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get metrics: {}", e)
        })),
    }
}

/// Get SLA breached findings
async fn get_sla_breached(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    let manager = LifecycleManager::new(pool.get_ref().clone());

    match manager.get_sla_breached().await {
        Ok(findings) => HttpResponse::Ok().json(serde_json::json!({
            "breached_findings": findings,
            "count": findings.len(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get SLA breached findings: {}", e)
        })),
    }
}

/// Get findings by state
async fn get_by_state(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: Claims,
) -> HttpResponse {
    let state_str = path.into_inner();

    let state = match FindingState::from_str(&state_str) {
        Some(s) => s,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid state: {}", state_str)
            }));
        }
    };

    let manager = LifecycleManager::new(pool.get_ref().clone());

    match manager.get_findings_by_state(state).await {
        Ok(findings) => HttpResponse::Ok().json(serde_json::json!({
            "state": state_str,
            "findings": findings,
            "count": findings.len(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get findings by state: {}", e)
        })),
    }
}

/// Get a specific finding lifecycle
async fn get_lifecycle(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: Claims,
) -> HttpResponse {
    let finding_id = path.into_inner();

    let row = sqlx::query_as::<_, LifecycleRow>(
        "SELECT id, finding_id, current_state, severity, title, affected_asset,
                discovered_at, sla_due_at, sla_breached, assigned_to,
                created_at, updated_at
         FROM finding_lifecycles WHERE finding_id = ?"
    )
    .bind(&finding_id)
    .fetch_optional(pool.get_ref())
    .await;

    match row {
        Ok(Some(r)) => {
            let response: LifecycleResponse = r.into();
            HttpResponse::Ok().json(response)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Finding lifecycle not found"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Initialize lifecycle request
#[derive(Debug, Deserialize)]
pub struct InitLifecycleRequest {
    pub severity: String,
    pub title: String,
    pub affected_asset: Option<String>,
    pub engagement_id: Option<String>,
    pub customer_id: Option<String>,
}

/// Initialize a new finding lifecycle
async fn init_lifecycle(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<InitLifecycleRequest>,
    claims: Claims,
) -> HttpResponse {
    let finding_id = path.into_inner();

    // Check if lifecycle already exists
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM finding_lifecycles WHERE finding_id = ?"
    )
    .bind(&finding_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    if existing > 0 {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "Lifecycle already exists for this finding"
        }));
    }

    let manager = LifecycleManager::new(pool.get_ref().clone());

    match manager.init_finding(&finding_id, &body.severity).await {
        Ok(lifecycle) => {
            // Update additional fields
            let _ = sqlx::query(
                "UPDATE finding_lifecycles
                 SET title = ?, affected_asset = ?, engagement_id = ?, customer_id = ?
                 WHERE finding_id = ?"
            )
            .bind(&body.title)
            .bind(&body.affected_asset)
            .bind(&body.engagement_id)
            .bind(&body.customer_id)
            .bind(&finding_id)
            .execute(pool.get_ref())
            .await;

            // Log the initialization
            log::info!(
                "User {} initialized lifecycle for finding {}",
                claims.sub, finding_id
            );

            HttpResponse::Created().json(lifecycle)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to initialize lifecycle: {}", e)
        })),
    }
}

/// State transition request
#[derive(Debug, Deserialize)]
pub struct TransitionRequest {
    pub to_state: String,
    pub reason: Option<String>,
    pub notes: Option<String>,
}

/// Transition a finding to a new state
async fn transition_state(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<TransitionRequest>,
    claims: Claims,
) -> HttpResponse {
    let finding_id = path.into_inner();

    let to_state = match FindingState::from_str(&body.to_state) {
        Some(s) => s,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid state: {}", body.to_state),
                "valid_states": vec![
                    "discovered", "triaged", "acknowledged", "in_remediation",
                    "verification_pending", "verified", "closed", "false_positive", "risk_accepted"
                ]
            }));
        }
    };

    let manager = LifecycleManager::new(pool.get_ref().clone());

    match manager
        .transition_finding(
            &finding_id,
            to_state,
            &claims.sub,
            body.reason.clone(),
            body.notes.clone(),
        )
        .await
    {
        Ok(lifecycle) => {
            log::info!(
                "User {} transitioned finding {} to {:?}",
                claims.sub, finding_id, to_state
            );
            HttpResponse::Ok().json(lifecycle)
        }
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("Invalid transition") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_msg
                }))
            } else if error_msg.contains("not found") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Finding lifecycle not found"
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to transition: {}", e)
                }))
            }
        }
    }
}

/// Get transition history
async fn get_history(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: Claims,
) -> HttpResponse {
    let finding_id = path.into_inner();

    let rows = sqlx::query_as::<_, TransitionRow>(
        "SELECT id, finding_id, from_state, to_state, transitioned_by,
                transitioned_at, comment, metadata
         FROM finding_state_transitions
         WHERE finding_id = ?
         ORDER BY transitioned_at ASC"
    )
    .bind(&finding_id)
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let history: Vec<TransitionResponse> = rows.into_iter().map(|r| r.into()).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "finding_id": finding_id,
                "transitions": history,
                "count": history.len(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get history: {}", e)
        })),
    }
}

/// Bulk transition request
#[derive(Debug, Deserialize)]
pub struct BulkTransitionRequest {
    pub finding_ids: Vec<String>,
    pub to_state: String,
    pub reason: Option<String>,
}

/// Bulk transition multiple findings
async fn bulk_transition(
    pool: web::Data<SqlitePool>,
    body: web::Json<BulkTransitionRequest>,
    claims: Claims,
) -> HttpResponse {
    let to_state = match FindingState::from_str(&body.to_state) {
        Some(s) => s,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid state: {}", body.to_state)
            }));
        }
    };

    let manager = LifecycleManager::new(pool.get_ref().clone());

    match manager
        .bulk_transition(&body.finding_ids, to_state, &claims.sub, body.reason.clone())
        .await
    {
        Ok(results) => {
            let successful: Vec<_> = results
                .iter()
                .filter(|(_, r)| r.is_ok())
                .map(|(id, _)| id.clone())
                .collect();
            let failed: Vec<_> = results
                .iter()
                .filter(|(_, r)| r.is_err())
                .map(|(id, r)| (id.clone(), r.as_ref().err().unwrap().to_string()))
                .collect();

            HttpResponse::Ok().json(serde_json::json!({
                "successful": successful,
                "successful_count": successful.len(),
                "failed": failed,
                "failed_count": failed.len(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Bulk transition failed: {}", e)
        })),
    }
}

/// List SLA policies
async fn list_sla_policies(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    let rows = sqlx::query_as::<_, SlaPolicyRow>(
        "SELECT id, name, description, critical_hours, high_hours, medium_hours,
                low_hours, info_hours, organization_id, is_default, created_at, updated_at
         FROM sla_policies
         ORDER BY is_default DESC, name ASC"
    )
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let policies: Vec<SlaPolicyResponse> = rows.into_iter().map(|r| r.into()).collect();
            HttpResponse::Ok().json(serde_json::json!({
                "policies": policies,
                "count": policies.len(),
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list policies: {}", e)
        })),
    }
}

/// Create SLA policy request
#[derive(Debug, Deserialize)]
pub struct CreateSlaPolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub critical_hours: i32,
    pub high_hours: i32,
    pub medium_hours: i32,
    pub low_hours: i32,
    pub info_hours: Option<i32>,
    pub organization_id: Option<String>,
}

/// Create a new SLA policy
async fn create_sla_policy(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateSlaPolicyRequest>,
    claims: Claims,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let result = sqlx::query(
        "INSERT INTO sla_policies
         (id, name, description, critical_hours, high_hours, medium_hours, low_hours,
          info_hours, organization_id, is_default, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)"
    )
    .bind(&id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(body.critical_hours)
    .bind(body.high_hours)
    .bind(body.medium_hours)
    .bind(body.low_hours)
    .bind(body.info_hours)
    .bind(&body.organization_id)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            log::info!("User {} created SLA policy {}", claims.sub, id);
            HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "name": body.name,
                "message": "SLA policy created successfully"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create policy: {}", e)
        })),
    }
}

/// Update SLA breach status for all findings
async fn update_sla_status(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    let manager = LifecycleManager::new(pool.get_ref().clone());

    match manager.update_sla_status().await {
        Ok(updated_count) => HttpResponse::Ok().json(serde_json::json!({
            "updated_count": updated_count,
            "message": format!("{} findings marked as SLA breached", updated_count)
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to update SLA status: {}", e)
        })),
    }
}

// Database row types

#[derive(Debug, sqlx::FromRow)]
struct LifecycleRow {
    id: String,
    finding_id: String,
    current_state: String,
    severity: String,
    title: String,
    affected_asset: Option<String>,
    discovered_at: String,
    sla_due_at: Option<String>,
    sla_breached: bool,
    assigned_to: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct LifecycleResponse {
    id: String,
    finding_id: String,
    current_state: String,
    severity: String,
    title: String,
    affected_asset: Option<String>,
    discovered_at: String,
    sla_due_at: Option<String>,
    sla_breached: bool,
    assigned_to: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<LifecycleRow> for LifecycleResponse {
    fn from(row: LifecycleRow) -> Self {
        Self {
            id: row.id,
            finding_id: row.finding_id,
            current_state: row.current_state,
            severity: row.severity,
            title: row.title,
            affected_asset: row.affected_asset,
            discovered_at: row.discovered_at,
            sla_due_at: row.sla_due_at,
            sla_breached: row.sla_breached,
            assigned_to: row.assigned_to,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct TransitionRow {
    id: String,
    finding_id: String,
    from_state: Option<String>,
    to_state: String,
    transitioned_by: String,
    transitioned_at: String,
    comment: Option<String>,
    metadata: Option<String>,
}

#[derive(Debug, Serialize)]
struct TransitionResponse {
    id: String,
    finding_id: String,
    from_state: Option<String>,
    to_state: String,
    transitioned_by: String,
    transitioned_at: String,
    comment: Option<String>,
}

impl From<TransitionRow> for TransitionResponse {
    fn from(row: TransitionRow) -> Self {
        Self {
            id: row.id,
            finding_id: row.finding_id,
            from_state: row.from_state,
            to_state: row.to_state,
            transitioned_by: row.transitioned_by,
            transitioned_at: row.transitioned_at,
            comment: row.comment,
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct SlaPolicyRow {
    id: String,
    name: String,
    description: Option<String>,
    critical_hours: i32,
    high_hours: i32,
    medium_hours: i32,
    low_hours: i32,
    info_hours: Option<i32>,
    organization_id: Option<String>,
    is_default: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct SlaPolicyResponse {
    id: String,
    name: String,
    description: Option<String>,
    critical_hours: i32,
    high_hours: i32,
    medium_hours: i32,
    low_hours: i32,
    info_hours: Option<i32>,
    organization_id: Option<String>,
    is_default: bool,
    created_at: String,
    updated_at: String,
}

impl From<SlaPolicyRow> for SlaPolicyResponse {
    fn from(row: SlaPolicyRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            critical_hours: row.critical_hours,
            high_hours: row.high_hours,
            medium_hours: row.medium_hours,
            low_hours: row.low_hours,
            info_hours: row.info_hours,
            organization_id: row.organization_id,
            is_default: row.is_default,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
