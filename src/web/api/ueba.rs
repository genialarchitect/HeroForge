//! UEBA (User Entity Behavior Analytics) API endpoints
//!
//! This module provides comprehensive behavioral analytics APIs including:
//! - Entity management (users, hosts, service accounts)
//! - Activity recording and analysis
//! - Anomaly detection and management
//! - Risk scoring and monitoring
//! - Session tracking
//! - Baseline management
//! - Dashboard and statistics

#![allow(unused_imports)]

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::siem::ueba::{
    CreateEntityRequest, CreatePeerGroupRequest, PeerGroupCriteria,
    RecordActivityRequest, RecordSessionRequest, UebaActivity, UebaAnomaly,
    UebaBaseline, UebaEngine, UebaEntity, UebaPeerGroup, UebaRiskFactor,
    UebaSession, UpdateAnomalyRequest, UpdateEntityRequest,
};
use crate::web::auth;

// =============================================================================
// Response Types
// =============================================================================

#[derive(Debug, Serialize)]
pub struct EntityListResponse {
    pub entities: Vec<UebaEntity>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct PeerGroupListResponse {
    pub peer_groups: Vec<UebaPeerGroup>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct ActivityListResponse {
    pub activities: Vec<UebaActivity>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct AnomalyListResponse {
    pub anomalies: Vec<UebaAnomaly>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<UebaSession>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct BaselineListResponse {
    pub baselines: Vec<UebaBaseline>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct RiskFactorListResponse {
    pub risk_factors: Vec<UebaRiskFactor>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct ProcessActivityResponse {
    pub activity_id: String,
    pub is_anomalous: bool,
    pub anomaly_reasons: Vec<String>,
    pub detected_anomalies: Vec<String>,
    pub risk_contribution: i32,
}

// =============================================================================
// Query Parameters
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct EntityQuery {
    pub entity_type: Option<String>,
    pub risk_level: Option<String>,
    pub department: Option<String>,
    pub is_privileged: Option<bool>,
    pub is_active: Option<bool>,
    pub search: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ActivityQuery {
    pub entity_id: Option<String>,
    pub activity_type: Option<String>,
    pub is_anomalous: Option<bool>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AnomalyQuery {
    pub entity_id: Option<String>,
    pub anomaly_type: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct SessionQuery {
    pub entity_id: Option<String>,
    pub session_type: Option<String>,
    pub auth_status: Option<String>,
    pub is_anomalous: Option<bool>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct BaselineQuery {
    pub entity_id: Option<String>,
    pub peer_group_id: Option<String>,
    pub metric_category: Option<String>,
}

// =============================================================================
// Request Types
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct AddToWatchlistRequest {
    pub entity_id: String,
    pub reason: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkActivityRequest {
    pub activities: Vec<RecordActivityRequest>,
}

#[derive(Debug, Deserialize)]
pub struct RecalculateBaselineRequest {
    pub entity_id: Option<String>,
    pub peer_group_id: Option<String>,
    pub metric_category: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePeerGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub criteria: Option<PeerGroupCriteria>,
}

// =============================================================================
// Entity Handlers
// =============================================================================

/// GET /api/ueba/entities - List entities
pub async fn list_entities(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<EntityQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    // Build query conditions
    let mut conditions = vec!["user_id = ?".to_string()];
    let mut bind_values: Vec<String> = vec![user_id.clone()];

    if let Some(entity_type) = &query.entity_type {
        conditions.push("entity_type = ?".to_string());
        bind_values.push(entity_type.clone());
    }

    if let Some(risk_level) = &query.risk_level {
        conditions.push("risk_level = ?".to_string());
        bind_values.push(risk_level.clone());
    }

    if let Some(department) = &query.department {
        conditions.push("department = ?".to_string());
        bind_values.push(department.clone());
    }

    if let Some(is_privileged) = &query.is_privileged {
        conditions.push(format!("is_privileged = {}", if *is_privileged { 1 } else { 0 }));
    }

    if let Some(is_active) = &query.is_active {
        conditions.push(format!("is_active = {}", if *is_active { 1 } else { 0 }));
    }

    if let Some(search) = &query.search {
        conditions.push("(display_name LIKE ? OR entity_id LIKE ?)".to_string());
        bind_values.push(format!("%{}%", search));
        bind_values.push(format!("%{}%", search));
    }

    let where_clause = conditions.join(" AND ");

    // Get total count
    let count_sql = format!("SELECT COUNT(*) as count FROM ueba_entities WHERE {}", where_clause);
    let total: (i64,) = sqlx::query_as(&count_sql)
        .bind(&bind_values[0])
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    // Get entities
    let sql = format!(
        "SELECT * FROM ueba_entities WHERE {} ORDER BY risk_score DESC, last_activity_at DESC LIMIT ? OFFSET ?",
        where_clause
    );

    let entities: Vec<UebaEntity> = sqlx::query_as(&sql)
        .bind(&bind_values[0])
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(EntityListResponse {
        entities,
        total: total.0,
        offset,
        limit,
    }))
}

/// GET /api/ueba/entities/{id} - Get entity details
pub async fn get_entity(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let entity_id = path.into_inner();

    let entity: Option<UebaEntity> = sqlx::query_as(
        "SELECT * FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match entity {
        Some(e) => Ok(HttpResponse::Ok().json(e)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Entity not found"
        }))),
    }
}

/// POST /api/ueba/entities - Create entity
pub async fn create_entity(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateEntityRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    let tags_json = body.tags.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());
    let metadata_json = body.metadata.as_ref().map(|m| m.to_string());

    sqlx::query(
        r#"
        INSERT INTO ueba_entities (
            id, user_id, entity_type, entity_id, display_name, department, role,
            manager, location, risk_score, risk_level, is_privileged, is_service_account,
            is_active, tags, metadata, first_seen_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'low', ?, ?, 1, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.entity_type)
    .bind(&body.entity_id)
    .bind(&body.display_name)
    .bind(&body.department)
    .bind(&body.role)
    .bind(&body.manager)
    .bind(&body.location)
    .bind(body.is_privileged.unwrap_or(false))
    .bind(body.is_service_account.unwrap_or(false))
    .bind(&tags_json)
    .bind(&metadata_json)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let entity: UebaEntity = sqlx::query_as("SELECT * FROM ueba_entities WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(entity))
}

/// PUT /api/ueba/entities/{id} - Update entity
pub async fn update_entity(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateEntityRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let entity_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Verify ownership
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Entity not found"
        })));
    }

    let tags_json = body.tags.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());
    let metadata_json = body.metadata.as_ref().map(|m| m.to_string());

    // Build update query dynamically
    let mut updates = vec!["updated_at = ?".to_string()];

    if body.display_name.is_some() { updates.push("display_name = ?".to_string()); }
    if body.department.is_some() { updates.push("department = ?".to_string()); }
    if body.role.is_some() { updates.push("role = ?".to_string()); }
    if body.manager.is_some() { updates.push("manager = ?".to_string()); }
    if body.location.is_some() { updates.push("location = ?".to_string()); }
    if body.peer_group_id.is_some() { updates.push("peer_group_id = ?".to_string()); }
    if body.is_privileged.is_some() { updates.push("is_privileged = ?".to_string()); }
    if body.is_service_account.is_some() { updates.push("is_service_account = ?".to_string()); }
    if body.is_active.is_some() { updates.push("is_active = ?".to_string()); }
    if body.tags.is_some() { updates.push("tags = ?".to_string()); }
    if body.metadata.is_some() { updates.push("metadata = ?".to_string()); }

    let sql = format!(
        "UPDATE ueba_entities SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql).bind(&now);
    if let Some(v) = &body.display_name { query = query.bind(v); }
    if let Some(v) = &body.department { query = query.bind(v); }
    if let Some(v) = &body.role { query = query.bind(v); }
    if let Some(v) = &body.manager { query = query.bind(v); }
    if let Some(v) = &body.location { query = query.bind(v); }
    if let Some(v) = &body.peer_group_id { query = query.bind(v); }
    if let Some(v) = &body.is_privileged { query = query.bind(v); }
    if let Some(v) = &body.is_service_account { query = query.bind(v); }
    if let Some(v) = &body.is_active { query = query.bind(v); }
    if body.tags.is_some() { query = query.bind(&tags_json); }
    if body.metadata.is_some() { query = query.bind(&metadata_json); }
    query = query.bind(&entity_id);

    query.execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let entity: UebaEntity = sqlx::query_as("SELECT * FROM ueba_entities WHERE id = ?")
        .bind(&entity_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(entity))
}

/// DELETE /api/ueba/entities/{id} - Delete entity
pub async fn delete_entity(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let entity_id = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&entity_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Entity not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Entity deleted successfully"
    })))
}

// =============================================================================
// Peer Group Handlers
// =============================================================================

/// GET /api/ueba/peer-groups - List peer groups
pub async fn list_peer_groups(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let peer_groups: Vec<UebaPeerGroup> = sqlx::query_as(
        "SELECT * FROM ueba_peer_groups WHERE user_id = ? ORDER BY name",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let total = peer_groups.len() as i64;

    Ok(HttpResponse::Ok().json(PeerGroupListResponse {
        peer_groups,
        total,
    }))
}

/// GET /api/ueba/peer-groups/{id} - Get peer group details
pub async fn get_peer_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let group_id = path.into_inner();

    let group: Option<UebaPeerGroup> = sqlx::query_as(
        "SELECT * FROM ueba_peer_groups WHERE id = ? AND user_id = ?",
    )
    .bind(&group_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match group {
        Some(g) => Ok(HttpResponse::Ok().json(g)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Peer group not found"
        }))),
    }
}

/// POST /api/ueba/peer-groups - Create peer group
pub async fn create_peer_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreatePeerGroupRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    let criteria_json = serde_json::to_string(&body.criteria).unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO ueba_peer_groups (
            id, user_id, name, description, criteria, member_count,
            is_auto_generated, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&criteria_json)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let group: UebaPeerGroup = sqlx::query_as("SELECT * FROM ueba_peer_groups WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(group))
}

/// PUT /api/ueba/peer-groups/{id} - Update peer group
pub async fn update_peer_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdatePeerGroupRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let group_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Verify ownership
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_peer_groups WHERE id = ? AND user_id = ?",
    )
    .bind(&group_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Peer group not found"
        })));
    }

    let criteria_json = body.criteria.as_ref().map(|c| serde_json::to_string(c).unwrap_or_default());

    let mut updates = vec!["updated_at = ?".to_string()];
    if body.name.is_some() { updates.push("name = ?".to_string()); }
    if body.description.is_some() { updates.push("description = ?".to_string()); }
    if body.criteria.is_some() { updates.push("criteria = ?".to_string()); }

    let sql = format!(
        "UPDATE ueba_peer_groups SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql).bind(&now);
    if let Some(v) = &body.name { query = query.bind(v); }
    if let Some(v) = &body.description { query = query.bind(v); }
    if body.criteria.is_some() { query = query.bind(&criteria_json); }
    query = query.bind(&group_id);

    query.execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let group: UebaPeerGroup = sqlx::query_as("SELECT * FROM ueba_peer_groups WHERE id = ?")
        .bind(&group_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(group))
}

/// DELETE /api/ueba/peer-groups/{id} - Delete peer group
pub async fn delete_peer_group(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let group_id = path.into_inner();

    let result = sqlx::query(
        "DELETE FROM ueba_peer_groups WHERE id = ? AND user_id = ?",
    )
    .bind(&group_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Peer group not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Peer group deleted successfully"
    })))
}

/// GET /api/ueba/peer-groups/{id}/members - Get peer group members
pub async fn get_peer_group_members(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let group_id = path.into_inner();

    // Verify ownership
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_peer_groups WHERE id = ? AND user_id = ?",
    )
    .bind(&group_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Peer group not found"
        })));
    }

    let members: Vec<UebaEntity> = sqlx::query_as(
        "SELECT * FROM ueba_entities WHERE peer_group_id = ? ORDER BY display_name",
    )
    .bind(&group_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(members))
}

// =============================================================================
// Activity Handlers
// =============================================================================

/// GET /api/ueba/activities - List activities
pub async fn list_activities(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ActivityQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    // Get activities for entities owned by this user
    let mut sql = String::from(
        r#"
        SELECT a.* FROM ueba_activities a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE e.user_id = ?
        "#,
    );

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND a.entity_id = '{}'", entity_id));
    }

    if let Some(activity_type) = &query.activity_type {
        sql.push_str(&format!(" AND a.activity_type = '{}'", activity_type));
    }

    if let Some(is_anomalous) = &query.is_anomalous {
        sql.push_str(&format!(" AND a.is_anomalous = {}", if *is_anomalous { 1 } else { 0 }));
    }

    if let Some(start_time) = &query.start_time {
        sql.push_str(&format!(" AND a.timestamp >= '{}'", start_time));
    }

    if let Some(end_time) = &query.end_time {
        sql.push_str(&format!(" AND a.timestamp <= '{}'", end_time));
    }

    sql.push_str(" ORDER BY a.timestamp DESC LIMIT ? OFFSET ?");

    let activities: Vec<UebaActivity> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    // Get total count
    let count_sql = format!(
        r#"
        SELECT COUNT(*) FROM ueba_activities a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE e.user_id = ?
        "#,
    );

    let total: (i64,) = sqlx::query_as(&count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(ActivityListResponse {
        activities,
        total: total.0,
        offset,
        limit,
    }))
}

/// POST /api/ueba/activities - Record activity
pub async fn record_activity(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordActivityRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let engine = UebaEngine::new(pool.get_ref().clone());

    let result = engine.process_activity(user_id, &body)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(ProcessActivityResponse {
        activity_id: result.activity_id,
        is_anomalous: result.is_anomalous,
        anomaly_reasons: result.anomaly_reasons,
        detected_anomalies: result.detected_anomalies,
        risk_contribution: result.risk_contribution,
    }))
}

/// POST /api/ueba/activities/bulk - Record multiple activities
pub async fn record_activities_bulk(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<BulkActivityRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let engine = UebaEngine::new(pool.get_ref().clone());

    let mut results = Vec::new();
    let mut total_anomalies = 0;

    for activity in &body.activities {
        match engine.process_activity(user_id, activity).await {
            Ok(result) => {
                if result.is_anomalous {
                    total_anomalies += 1;
                }
                results.push(serde_json::json!({
                    "entity_id": activity.entity_id,
                    "is_anomalous": result.is_anomalous,
                    "detected_anomalies": result.detected_anomalies,
                    "risk_contribution": result.risk_contribution,
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "entity_id": activity.entity_id,
                    "error": e.to_string(),
                }));
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "processed": results.len(),
        "total_anomalies": total_anomalies,
        "results": results,
    })))
}

// =============================================================================
// Anomaly Handlers
// =============================================================================

/// GET /api/ueba/anomalies - List anomalies
pub async fn list_anomalies(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AnomalyQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let mut sql = String::from(
        r#"
        SELECT a.* FROM ueba_anomalies a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE e.user_id = ?
        "#,
    );

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND a.entity_id = '{}'", entity_id));
    }

    if let Some(anomaly_type) = &query.anomaly_type {
        sql.push_str(&format!(" AND a.anomaly_type = '{}'", anomaly_type));
    }

    if let Some(status) = &query.status {
        sql.push_str(&format!(" AND a.status = '{}'", status));
    }

    if let Some(severity) = &query.severity {
        sql.push_str(&format!(" AND a.severity = '{}'", severity));
    }

    if let Some(start_time) = &query.start_time {
        sql.push_str(&format!(" AND a.detected_at >= '{}'", start_time));
    }

    if let Some(end_time) = &query.end_time {
        sql.push_str(&format!(" AND a.detected_at <= '{}'", end_time));
    }

    sql.push_str(" ORDER BY a.detected_at DESC LIMIT ? OFFSET ?");

    let anomalies: Vec<UebaAnomaly> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    // Get total count
    let count_sql = format!(
        r#"
        SELECT COUNT(*) FROM ueba_anomalies a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE e.user_id = ?
        "#,
    );

    let total: (i64,) = sqlx::query_as(&count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(AnomalyListResponse {
        anomalies,
        total: total.0,
        offset,
        limit,
    }))
}

/// GET /api/ueba/anomalies/{id} - Get anomaly details
pub async fn get_anomaly(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let anomaly_id = path.into_inner();

    let anomaly: Option<UebaAnomaly> = sqlx::query_as(
        r#"
        SELECT a.* FROM ueba_anomalies a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE a.id = ? AND e.user_id = ?
        "#,
    )
    .bind(&anomaly_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match anomaly {
        Some(a) => Ok(HttpResponse::Ok().json(a)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Anomaly not found"
        }))),
    }
}

/// PUT /api/ueba/anomalies/{id} - Update anomaly
pub async fn update_anomaly(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateAnomalyRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let anomaly_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Verify ownership
    let exists: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT 1 FROM ueba_anomalies a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE a.id = ? AND e.user_id = ?
        "#,
    )
    .bind(&anomaly_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Anomaly not found"
        })));
    }

    let mut updates = vec!["updated_at = ?".to_string()];
    if body.status.is_some() { updates.push("status = ?".to_string()); }
    if body.priority.is_some() { updates.push("priority = ?".to_string()); }
    if body.assigned_to.is_some() { updates.push("assigned_to = ?".to_string()); }
    if body.resolution_notes.is_some() { updates.push("resolution_notes = ?".to_string()); }
    if body.false_positive.is_some() { updates.push("false_positive = ?".to_string()); }
    if body.suppressed.is_some() { updates.push("suppressed = ?".to_string()); }
    if body.suppression_reason.is_some() { updates.push("suppression_reason = ?".to_string()); }

    // Handle resolved/acknowledged timestamps
    if let Some(status) = &body.status {
        if status == "acknowledged" {
            updates.push("acknowledged_at = ?".to_string());
            updates.push("acknowledged_by = ?".to_string());
        } else if status == "resolved" {
            updates.push("resolved_at = ?".to_string());
            updates.push("resolved_by = ?".to_string());
        }
    }

    let sql = format!(
        "UPDATE ueba_anomalies SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql).bind(&now);
    if let Some(v) = &body.status { query = query.bind(v); }
    if let Some(v) = &body.priority { query = query.bind(v); }
    if let Some(v) = &body.assigned_to { query = query.bind(v); }
    if let Some(v) = &body.resolution_notes { query = query.bind(v); }
    if let Some(v) = &body.false_positive { query = query.bind(v); }
    if let Some(v) = &body.suppressed { query = query.bind(v); }
    if let Some(v) = &body.suppression_reason { query = query.bind(v); }

    // Bind timestamps and user for acknowledged/resolved
    if let Some(status) = &body.status {
        if status == "acknowledged" || status == "resolved" {
            query = query.bind(&now).bind(user_id);
        }
    }
    query = query.bind(&anomaly_id);

    query.execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let anomaly: UebaAnomaly = sqlx::query_as("SELECT * FROM ueba_anomalies WHERE id = ?")
        .bind(&anomaly_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(anomaly))
}

/// POST /api/ueba/anomalies/{id}/acknowledge - Acknowledge anomaly
pub async fn acknowledge_anomaly(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let anomaly_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        r#"
        UPDATE ueba_anomalies SET status = 'acknowledged', acknowledged_at = ?, acknowledged_by = ?, updated_at = ?
        WHERE id = ? AND EXISTS (
            SELECT 1 FROM ueba_entities e WHERE e.id = entity_id AND e.user_id = ?
        )
        "#,
    )
    .bind(&now)
    .bind(user_id)
    .bind(&now)
    .bind(&anomaly_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Anomaly not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Anomaly acknowledged successfully"
    })))
}

/// POST /api/ueba/anomalies/{id}/resolve - Resolve anomaly
pub async fn resolve_anomaly(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let anomaly_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let resolution_notes = body.get("resolution_notes").and_then(|v| v.as_str());
    let is_false_positive = body.get("false_positive").and_then(|v| v.as_bool()).unwrap_or(false);

    let result = sqlx::query(
        r#"
        UPDATE ueba_anomalies SET
            status = 'resolved',
            resolved_at = ?,
            resolved_by = ?,
            resolution_notes = ?,
            false_positive = ?,
            updated_at = ?
        WHERE id = ? AND EXISTS (
            SELECT 1 FROM ueba_entities e WHERE e.id = entity_id AND e.user_id = ?
        )
        "#,
    )
    .bind(&now)
    .bind(user_id)
    .bind(resolution_notes)
    .bind(is_false_positive)
    .bind(&now)
    .bind(&anomaly_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Anomaly not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Anomaly resolved successfully"
    })))
}

// =============================================================================
// Session Handlers
// =============================================================================

/// GET /api/ueba/sessions - List sessions
pub async fn list_sessions(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<SessionQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let mut sql = String::from(
        r#"
        SELECT s.* FROM ueba_sessions s
        JOIN ueba_entities e ON s.entity_id = e.id
        WHERE e.user_id = ?
        "#,
    );

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND s.entity_id = '{}'", entity_id));
    }

    if let Some(session_type) = &query.session_type {
        sql.push_str(&format!(" AND s.session_type = '{}'", session_type));
    }

    if let Some(auth_status) = &query.auth_status {
        sql.push_str(&format!(" AND s.auth_status = '{}'", auth_status));
    }

    if let Some(start_time) = &query.start_time {
        sql.push_str(&format!(" AND s.started_at >= '{}'", start_time));
    }

    if let Some(end_time) = &query.end_time {
        sql.push_str(&format!(" AND s.started_at <= '{}'", end_time));
    }

    sql.push_str(" ORDER BY s.started_at DESC LIMIT ? OFFSET ?");

    let sessions: Vec<UebaSession> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let count_sql = format!(
        r#"
        SELECT COUNT(*) FROM ueba_sessions s
        JOIN ueba_entities e ON s.entity_id = e.id
        WHERE e.user_id = ?
        "#,
    );

    let total: (i64,) = sqlx::query_as(&count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(SessionListResponse {
        sessions,
        total: total.0,
        offset,
        limit,
    }))
}

/// POST /api/ueba/sessions - Record session
pub async fn record_session(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordSessionRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    // Verify entity ownership
    let entity: Option<UebaEntity> = sqlx::query_as(
        "SELECT * FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&body.entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if entity.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Entity not found or not owned by user"
        })));
    }

    sqlx::query(
        r#"
        INSERT INTO ueba_sessions (
            id, entity_id, session_id, session_type, source_ip,
            source_country, source_city, source_lat, source_lon,
            user_agent, device_fingerprint, auth_method, auth_status,
            mfa_used, is_vpn, is_tor, is_proxy, risk_score,
            started_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&body.entity_id)
    .bind(&body.session_id)
    .bind(&body.session_type)
    .bind(&body.source_ip)
    .bind(&body.source_country)
    .bind(&body.source_city)
    .bind(&body.source_lat)
    .bind(&body.source_lon)
    .bind(&body.user_agent)
    .bind(&body.device_fingerprint)
    .bind(&body.auth_method)
    .bind(&body.auth_status)
    .bind(body.mfa_used.unwrap_or(false))
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let session: UebaSession = sqlx::query_as("SELECT * FROM ueba_sessions WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(session))
}

// =============================================================================
// Baseline Handlers
// =============================================================================

/// GET /api/ueba/baselines - List baselines
pub async fn list_baselines(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<BaselineQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let mut sql = String::from(
        r#"
        SELECT b.* FROM ueba_baselines b
        LEFT JOIN ueba_entities e ON b.entity_id = e.id
        LEFT JOIN ueba_peer_groups pg ON b.peer_group_id = pg.id
        WHERE (e.user_id = ? OR pg.user_id = ?)
        "#,
    );

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND b.entity_id = '{}'", entity_id));
    }

    if let Some(peer_group_id) = &query.peer_group_id {
        sql.push_str(&format!(" AND b.peer_group_id = '{}'", peer_group_id));
    }

    if let Some(metric_category) = &query.metric_category {
        sql.push_str(&format!(" AND b.metric_category = '{}'", metric_category));
    }

    sql.push_str(" ORDER BY b.metric_category, b.metric_name");

    let baselines: Vec<UebaBaseline> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(user_id)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let total = baselines.len() as i64;

    Ok(HttpResponse::Ok().json(BaselineListResponse {
        baselines,
        total,
    }))
}

/// GET /api/ueba/entities/{id}/baselines - Get entity baselines
pub async fn get_entity_baselines(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let entity_id = path.into_inner();

    // Verify ownership
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Entity not found"
        })));
    }

    let baselines: Vec<UebaBaseline> = sqlx::query_as(
        "SELECT * FROM ueba_baselines WHERE entity_id = ? ORDER BY metric_category, metric_name",
    )
    .bind(&entity_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(baselines))
}

// =============================================================================
// Risk Factor Handlers
// =============================================================================

/// GET /api/ueba/entities/{id}/risk-factors - Get entity risk factors
pub async fn get_entity_risk_factors(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let entity_id = path.into_inner();

    // Verify ownership
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Entity not found"
        })));
    }

    let risk_factors: Vec<UebaRiskFactor> = sqlx::query_as(
        "SELECT * FROM ueba_risk_factors WHERE entity_id = ? AND is_active = 1 ORDER BY contribution DESC",
    )
    .bind(&entity_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(RiskFactorListResponse {
        total: risk_factors.len() as i64,
        risk_factors,
    }))
}

// =============================================================================
// Dashboard Handlers
// =============================================================================

/// GET /api/ueba/dashboard - Get dashboard stats
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let engine = UebaEngine::new(pool.get_ref().clone());
    let stats = engine.get_dashboard_stats(user_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(stats))
}

/// GET /api/ueba/stats - Get summary statistics
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get entity counts by type and risk
    let entity_stats: Vec<(String, String, i64)> = sqlx::query_as(
        r#"
        SELECT entity_type, risk_level, COUNT(*) as count
        FROM ueba_entities WHERE user_id = ?
        GROUP BY entity_type, risk_level
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Get anomaly counts by type and status
    let anomaly_stats: Vec<(String, String, i64)> = sqlx::query_as(
        r#"
        SELECT a.anomaly_type, a.status, COUNT(*) as count
        FROM ueba_anomalies a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE e.user_id = ?
        GROUP BY a.anomaly_type, a.status
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Get activity counts by type
    let activity_stats: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT a.activity_type, COUNT(*) as count
        FROM ueba_activities a
        JOIN ueba_entities e ON a.entity_id = e.id
        WHERE e.user_id = ? AND a.timestamp >= datetime('now', '-7 days')
        GROUP BY a.activity_type
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "entity_stats": entity_stats.into_iter()
            .map(|(t, r, c)| serde_json::json!({"entity_type": t, "risk_level": r, "count": c}))
            .collect::<Vec<_>>(),
        "anomaly_stats": anomaly_stats.into_iter()
            .map(|(t, s, c)| serde_json::json!({"anomaly_type": t, "status": s, "count": c}))
            .collect::<Vec<_>>(),
        "activity_stats": activity_stats.into_iter()
            .map(|(t, c)| serde_json::json!({"activity_type": t, "count": c}))
            .collect::<Vec<_>>(),
    })))
}

// =============================================================================
// Watchlist Handlers
// =============================================================================

/// POST /api/ueba/watchlist - Add entity to watchlist
pub async fn add_to_watchlist(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<AddToWatchlistRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    // Verify entity ownership
    let exists: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&body.entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Entity not found or not owned by user"
        })));
    }

    sqlx::query(
        r#"
        INSERT INTO ueba_watchlist (
            id, entity_id, reason, added_by, added_at, expires_at, is_active, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        "#,
    )
    .bind(&id)
    .bind(&body.entity_id)
    .bind(&body.reason)
    .bind(user_id)
    .bind(&now)
    .bind(&body.expires_at)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "entity_id": body.entity_id,
        "reason": body.reason,
        "message": "Entity added to watchlist"
    })))
}

/// DELETE /api/ueba/watchlist/{entity_id} - Remove entity from watchlist
pub async fn remove_from_watchlist(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let entity_id = path.into_inner();

    let result = sqlx::query(
        r#"
        UPDATE ueba_watchlist SET is_active = 0
        WHERE entity_id = ? AND EXISTS (
            SELECT 1 FROM ueba_entities e WHERE e.id = entity_id AND e.user_id = ?
        )
        "#,
    )
    .bind(&entity_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Entity not found on watchlist"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Entity removed from watchlist"
    })))
}

// =============================================================================
// Sprint 4: Advanced Detection Types
// =============================================================================

#[derive(Debug, Serialize)]
pub struct AdvancedDetectionListResponse {
    pub detections: Vec<AdvancedDetection>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AdvancedDetection {
    pub id: String,
    pub user_id: String,
    pub entity_id: String,
    pub detection_type: String,
    pub severity: String,
    pub risk_score: i32,
    pub confidence: Option<f64>,
    pub title: String,
    pub description: Option<String>,
    pub evidence: String,
    pub mitre_techniques: Option<String>,
    pub related_activity_ids: Option<String>,
    pub related_anomaly_id: Option<String>,
    pub status: String,
    pub assigned_to: Option<String>,
    pub resolution: Option<String>,
    pub resolved_at: Option<String>,
    pub detected_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct BusinessHours {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub entity_id: Option<String>,
    pub name: String,
    pub timezone: String,
    pub monday_start: Option<String>,
    pub monday_end: Option<String>,
    pub tuesday_start: Option<String>,
    pub tuesday_end: Option<String>,
    pub wednesday_start: Option<String>,
    pub wednesday_end: Option<String>,
    pub thursday_start: Option<String>,
    pub thursday_end: Option<String>,
    pub friday_start: Option<String>,
    pub friday_end: Option<String>,
    pub saturday_start: Option<String>,
    pub saturday_end: Option<String>,
    pub sunday_start: Option<String>,
    pub sunday_end: Option<String>,
    pub holidays: Option<String>,
    pub is_default: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SensitiveResource {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub resource_type: String,
    pub resource_pattern: String,
    pub sensitivity_level: String,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub allowed_roles: Option<String>,
    pub alert_on_access: bool,
    pub require_justification: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct KnownVpn {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub ip_range: String,
    pub vpn_type: String,
    pub provider: Option<String>,
    pub is_corporate: bool,
    pub is_trusted: bool,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DetectionRule {
    pub id: String,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub rule_type: String,
    pub name: String,
    pub description: Option<String>,
    pub is_enabled: bool,
    pub severity: String,
    pub config: String,
    pub mitre_techniques: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DataAccess {
    pub id: String,
    pub user_id: String,
    pub entity_id: String,
    pub resource_id: Option<String>,
    pub resource_name: String,
    pub resource_type: String,
    pub access_type: String,
    pub sensitivity_level: Option<String>,
    pub source_ip: Option<String>,
    pub source_host: Option<String>,
    pub bytes_accessed: Option<i64>,
    pub records_accessed: Option<i64>,
    pub query_text: Option<String>,
    pub justification: Option<String>,
    pub is_anomalous: bool,
    pub anomaly_reasons: Option<String>,
    pub risk_score: i32,
    pub accessed_at: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct HostAccess {
    pub id: String,
    pub user_id: String,
    pub entity_id: String,
    pub source_host: String,
    pub destination_host: String,
    pub destination_ip: Option<String>,
    pub access_type: String,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub success: bool,
    pub authentication_method: Option<String>,
    pub tool_used: Option<String>,
    pub is_admin_access: bool,
    pub is_anomalous: bool,
    pub anomaly_reasons: Option<String>,
    pub duration_seconds: Option<i64>,
    pub bytes_transferred: Option<i64>,
    pub accessed_at: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DataTransfer {
    pub id: String,
    pub user_id: String,
    pub entity_id: String,
    pub transfer_type: String,
    pub source_path: Option<String>,
    pub destination: String,
    pub destination_type: String,
    pub bytes_transferred: i64,
    pub file_count: i32,
    pub file_types: Option<String>,
    pub is_encrypted: bool,
    pub is_compressed: bool,
    pub protocol: Option<String>,
    pub tool_used: Option<String>,
    pub is_external: bool,
    pub is_anomalous: bool,
    pub anomaly_reasons: Option<String>,
    pub risk_score: i32,
    pub transferred_at: String,
    pub created_at: String,
}

// Request types for advanced detection
#[derive(Debug, Deserialize)]
pub struct CreateBusinessHoursRequest {
    pub name: String,
    pub organization_id: Option<String>,
    pub entity_id: Option<String>,
    pub timezone: Option<String>,
    pub monday_start: Option<String>,
    pub monday_end: Option<String>,
    pub tuesday_start: Option<String>,
    pub tuesday_end: Option<String>,
    pub wednesday_start: Option<String>,
    pub wednesday_end: Option<String>,
    pub thursday_start: Option<String>,
    pub thursday_end: Option<String>,
    pub friday_start: Option<String>,
    pub friday_end: Option<String>,
    pub saturday_start: Option<String>,
    pub saturday_end: Option<String>,
    pub sunday_start: Option<String>,
    pub sunday_end: Option<String>,
    pub holidays: Option<Vec<String>>,
    pub is_default: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSensitiveResourceRequest {
    pub resource_type: String,
    pub resource_pattern: String,
    pub sensitivity_level: String,
    pub organization_id: Option<String>,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub allowed_roles: Option<Vec<String>>,
    pub alert_on_access: Option<bool>,
    pub require_justification: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKnownVpnRequest {
    pub name: String,
    pub ip_range: String,
    pub vpn_type: String,
    pub organization_id: Option<String>,
    pub provider: Option<String>,
    pub is_corporate: Option<bool>,
    pub is_trusted: Option<bool>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDetectionRuleRequest {
    pub rule_type: String,
    pub name: String,
    pub organization_id: Option<String>,
    pub description: Option<String>,
    pub is_enabled: Option<bool>,
    pub severity: Option<String>,
    pub config: serde_json::Value,
    pub mitre_techniques: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct RecordDataAccessRequest {
    pub entity_id: String,
    pub resource_name: String,
    pub resource_type: String,
    pub access_type: String,
    pub resource_id: Option<String>,
    pub sensitivity_level: Option<String>,
    pub source_ip: Option<String>,
    pub source_host: Option<String>,
    pub bytes_accessed: Option<i64>,
    pub records_accessed: Option<i64>,
    pub query_text: Option<String>,
    pub justification: Option<String>,
    pub accessed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecordHostAccessRequest {
    pub entity_id: String,
    pub source_host: String,
    pub destination_host: String,
    pub access_type: String,
    pub destination_ip: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub success: Option<bool>,
    pub authentication_method: Option<String>,
    pub tool_used: Option<String>,
    pub is_admin_access: Option<bool>,
    pub duration_seconds: Option<i64>,
    pub bytes_transferred: Option<i64>,
    pub accessed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecordDataTransferRequest {
    pub entity_id: String,
    pub transfer_type: String,
    pub destination: String,
    pub destination_type: String,
    pub bytes_transferred: i64,
    pub source_path: Option<String>,
    pub file_count: Option<i32>,
    pub file_types: Option<Vec<String>>,
    pub is_encrypted: Option<bool>,
    pub is_compressed: Option<bool>,
    pub protocol: Option<String>,
    pub tool_used: Option<String>,
    pub is_external: Option<bool>,
    pub transferred_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdvancedDetectionQuery {
    pub entity_id: Option<String>,
    pub detection_type: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RunDetectionRequest {
    pub entity_id: Option<String>,
    pub detection_types: Option<Vec<String>>,
    pub time_window_hours: Option<i32>,
}

// =============================================================================
// Sprint 4: Business Hours Handlers
// =============================================================================

/// GET /api/ueba/advanced/business-hours - List business hours configs
pub async fn list_business_hours(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let configs: Vec<BusinessHours> = sqlx::query_as(
        "SELECT * FROM ueba_business_hours WHERE user_id = ? ORDER BY is_default DESC, name",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(configs))
}

/// POST /api/ueba/advanced/business-hours - Create business hours config
pub async fn create_business_hours(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateBusinessHoursRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    let holidays_json = body.holidays.as_ref().map(|h| serde_json::to_string(h).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO ueba_business_hours (
            id, user_id, organization_id, entity_id, name, timezone,
            monday_start, monday_end, tuesday_start, tuesday_end,
            wednesday_start, wednesday_end, thursday_start, thursday_end,
            friday_start, friday_end, saturday_start, saturday_end,
            sunday_start, sunday_end, holidays, is_default, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.organization_id)
    .bind(&body.entity_id)
    .bind(&body.name)
    .bind(body.timezone.as_deref().unwrap_or("UTC"))
    .bind(&body.monday_start)
    .bind(&body.monday_end)
    .bind(&body.tuesday_start)
    .bind(&body.tuesday_end)
    .bind(&body.wednesday_start)
    .bind(&body.wednesday_end)
    .bind(&body.thursday_start)
    .bind(&body.thursday_end)
    .bind(&body.friday_start)
    .bind(&body.friday_end)
    .bind(&body.saturday_start)
    .bind(&body.saturday_end)
    .bind(&body.sunday_start)
    .bind(&body.sunday_end)
    .bind(&holidays_json)
    .bind(body.is_default.unwrap_or(false))
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let config: BusinessHours = sqlx::query_as("SELECT * FROM ueba_business_hours WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(config))
}

/// DELETE /api/ueba/advanced/business-hours/{id} - Delete business hours config
pub async fn delete_business_hours(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM ueba_business_hours WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Business hours config not found"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Business hours config deleted"})))
}

// =============================================================================
// Sprint 4: Sensitive Resources Handlers
// =============================================================================

/// GET /api/ueba/advanced/sensitive-resources - List sensitive resources
pub async fn list_sensitive_resources(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let resources: Vec<SensitiveResource> = sqlx::query_as(
        "SELECT * FROM ueba_sensitive_resources WHERE user_id = ? ORDER BY sensitivity_level DESC, resource_type",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(resources))
}

/// POST /api/ueba/advanced/sensitive-resources - Create sensitive resource
pub async fn create_sensitive_resource(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateSensitiveResourceRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    let roles_json = body.allowed_roles.as_ref().map(|r| serde_json::to_string(r).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO ueba_sensitive_resources (
            id, user_id, organization_id, resource_type, resource_pattern,
            sensitivity_level, description, owner, allowed_roles,
            alert_on_access, require_justification, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.organization_id)
    .bind(&body.resource_type)
    .bind(&body.resource_pattern)
    .bind(&body.sensitivity_level)
    .bind(&body.description)
    .bind(&body.owner)
    .bind(&roles_json)
    .bind(body.alert_on_access.unwrap_or(false))
    .bind(body.require_justification.unwrap_or(false))
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let resource: SensitiveResource = sqlx::query_as("SELECT * FROM ueba_sensitive_resources WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(resource))
}

/// DELETE /api/ueba/advanced/sensitive-resources/{id} - Delete sensitive resource
pub async fn delete_sensitive_resource(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM ueba_sensitive_resources WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Sensitive resource not found"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Sensitive resource deleted"})))
}

// =============================================================================
// Sprint 4: Known VPN Handlers
// =============================================================================

/// GET /api/ueba/advanced/known-vpns - List known VPNs
pub async fn list_known_vpns(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let vpns: Vec<KnownVpn> = sqlx::query_as(
        "SELECT * FROM ueba_known_vpns WHERE user_id = ? ORDER BY is_corporate DESC, name",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(vpns))
}

/// POST /api/ueba/advanced/known-vpns - Create known VPN
pub async fn create_known_vpn(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateKnownVpnRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO ueba_known_vpns (
            id, user_id, organization_id, name, ip_range, vpn_type,
            provider, is_corporate, is_trusted, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.organization_id)
    .bind(&body.name)
    .bind(&body.ip_range)
    .bind(&body.vpn_type)
    .bind(&body.provider)
    .bind(body.is_corporate.unwrap_or(false))
    .bind(body.is_trusted.unwrap_or(true))
    .bind(&body.notes)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let vpn: KnownVpn = sqlx::query_as("SELECT * FROM ueba_known_vpns WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(vpn))
}

/// DELETE /api/ueba/advanced/known-vpns/{id} - Delete known VPN
pub async fn delete_known_vpn(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM ueba_known_vpns WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Known VPN not found"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Known VPN deleted"})))
}

// =============================================================================
// Sprint 4: Detection Rules Handlers
// =============================================================================

/// GET /api/ueba/advanced/detection-rules - List detection rules
pub async fn list_detection_rules(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let rules: Vec<DetectionRule> = sqlx::query_as(
        "SELECT * FROM ueba_detection_rules WHERE user_id = ? ORDER BY rule_type, name",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(rules))
}

/// POST /api/ueba/advanced/detection-rules - Create detection rule
pub async fn create_detection_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateDetectionRuleRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    let config_json = serde_json::to_string(&body.config).unwrap_or_default();
    let mitre_json = body.mitre_techniques.as_ref().map(|m| serde_json::to_string(m).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO ueba_detection_rules (
            id, user_id, organization_id, rule_type, name, description,
            is_enabled, severity, config, mitre_techniques, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.organization_id)
    .bind(&body.rule_type)
    .bind(&body.name)
    .bind(&body.description)
    .bind(body.is_enabled.unwrap_or(true))
    .bind(body.severity.as_deref().unwrap_or("medium"))
    .bind(&config_json)
    .bind(&mitre_json)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let rule: DetectionRule = sqlx::query_as("SELECT * FROM ueba_detection_rules WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(rule))
}

/// PUT /api/ueba/advanced/detection-rules/{id}/toggle - Toggle rule enabled state
pub async fn toggle_detection_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE ueba_detection_rules SET is_enabled = NOT is_enabled, updated_at = ? WHERE id = ? AND user_id = ?",
    )
    .bind(&now)
    .bind(&id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Detection rule not found"})));
    }

    let rule: DetectionRule = sqlx::query_as("SELECT * FROM ueba_detection_rules WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(rule))
}

/// DELETE /api/ueba/advanced/detection-rules/{id} - Delete detection rule
pub async fn delete_detection_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM ueba_detection_rules WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(user_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Detection rule not found"})));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"message": "Detection rule deleted"})))
}

// =============================================================================
// Sprint 4: Data Access Recording Handlers
// =============================================================================

/// GET /api/ueba/advanced/data-accesses - List data accesses
pub async fn list_data_accesses(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ActivityQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let mut sql = String::from("SELECT * FROM ueba_data_accesses WHERE user_id = ?");

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND entity_id = '{}'", entity_id));
    }
    if let Some(is_anomalous) = &query.is_anomalous {
        sql.push_str(&format!(" AND is_anomalous = {}", if *is_anomalous { 1 } else { 0 }));
    }
    if let Some(start_time) = &query.start_time {
        sql.push_str(&format!(" AND accessed_at >= '{}'", start_time));
    }
    if let Some(end_time) = &query.end_time {
        sql.push_str(&format!(" AND accessed_at <= '{}'", end_time));
    }

    sql.push_str(" ORDER BY accessed_at DESC LIMIT ? OFFSET ?");

    let accesses: Vec<DataAccess> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let count_sql = "SELECT COUNT(*) FROM ueba_data_accesses WHERE user_id = ?";
    let total: (i64,) = sqlx::query_as(count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "data_accesses": accesses,
        "total": total.0,
        "offset": offset,
        "limit": limit,
    })))
}

/// POST /api/ueba/advanced/data-accesses - Record data access
pub async fn record_data_access(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordDataAccessRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    // Verify entity ownership
    let entity: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&body.entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if entity.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Entity not found"})));
    }

    let accessed_at = body.accessed_at.as_ref().unwrap_or(&now);

    sqlx::query(
        r#"
        INSERT INTO ueba_data_accesses (
            id, user_id, entity_id, resource_id, resource_name, resource_type,
            access_type, sensitivity_level, source_ip, source_host,
            bytes_accessed, records_accessed, query_text, justification,
            is_anomalous, risk_score, accessed_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.entity_id)
    .bind(&body.resource_id)
    .bind(&body.resource_name)
    .bind(&body.resource_type)
    .bind(&body.access_type)
    .bind(&body.sensitivity_level)
    .bind(&body.source_ip)
    .bind(&body.source_host)
    .bind(&body.bytes_accessed)
    .bind(&body.records_accessed)
    .bind(&body.query_text)
    .bind(&body.justification)
    .bind(accessed_at)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let access: DataAccess = sqlx::query_as("SELECT * FROM ueba_data_accesses WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(access))
}

// =============================================================================
// Sprint 4: Host Access Recording Handlers
// =============================================================================

/// GET /api/ueba/advanced/host-accesses - List host accesses
pub async fn list_host_accesses(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ActivityQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let mut sql = String::from("SELECT * FROM ueba_host_accesses WHERE user_id = ?");

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND entity_id = '{}'", entity_id));
    }
    if let Some(is_anomalous) = &query.is_anomalous {
        sql.push_str(&format!(" AND is_anomalous = {}", if *is_anomalous { 1 } else { 0 }));
    }
    if let Some(start_time) = &query.start_time {
        sql.push_str(&format!(" AND accessed_at >= '{}'", start_time));
    }
    if let Some(end_time) = &query.end_time {
        sql.push_str(&format!(" AND accessed_at <= '{}'", end_time));
    }

    sql.push_str(" ORDER BY accessed_at DESC LIMIT ? OFFSET ?");

    let accesses: Vec<HostAccess> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let count_sql = "SELECT COUNT(*) FROM ueba_host_accesses WHERE user_id = ?";
    let total: (i64,) = sqlx::query_as(count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "host_accesses": accesses,
        "total": total.0,
        "offset": offset,
        "limit": limit,
    })))
}

/// POST /api/ueba/advanced/host-accesses - Record host access
pub async fn record_host_access(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordHostAccessRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    // Verify entity ownership
    let entity: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&body.entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if entity.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Entity not found"})));
    }

    let accessed_at = body.accessed_at.as_ref().unwrap_or(&now);

    sqlx::query(
        r#"
        INSERT INTO ueba_host_accesses (
            id, user_id, entity_id, source_host, destination_host, destination_ip,
            access_type, protocol, port, success, authentication_method,
            tool_used, is_admin_access, is_anomalous, duration_seconds,
            bytes_transferred, accessed_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.entity_id)
    .bind(&body.source_host)
    .bind(&body.destination_host)
    .bind(&body.destination_ip)
    .bind(&body.access_type)
    .bind(&body.protocol)
    .bind(&body.port)
    .bind(body.success.unwrap_or(true))
    .bind(&body.authentication_method)
    .bind(&body.tool_used)
    .bind(body.is_admin_access.unwrap_or(false))
    .bind(&body.duration_seconds)
    .bind(&body.bytes_transferred)
    .bind(accessed_at)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let access: HostAccess = sqlx::query_as("SELECT * FROM ueba_host_accesses WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(access))
}

// =============================================================================
// Sprint 4: Data Transfer Recording Handlers
// =============================================================================

/// GET /api/ueba/advanced/data-transfers - List data transfers
pub async fn list_data_transfers(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ActivityQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let mut sql = String::from("SELECT * FROM ueba_data_transfers WHERE user_id = ?");

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND entity_id = '{}'", entity_id));
    }
    if let Some(is_anomalous) = &query.is_anomalous {
        sql.push_str(&format!(" AND is_anomalous = {}", if *is_anomalous { 1 } else { 0 }));
    }
    if let Some(start_time) = &query.start_time {
        sql.push_str(&format!(" AND transferred_at >= '{}'", start_time));
    }
    if let Some(end_time) = &query.end_time {
        sql.push_str(&format!(" AND transferred_at <= '{}'", end_time));
    }

    sql.push_str(" ORDER BY transferred_at DESC LIMIT ? OFFSET ?");

    let transfers: Vec<DataTransfer> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let count_sql = "SELECT COUNT(*) FROM ueba_data_transfers WHERE user_id = ?";
    let total: (i64,) = sqlx::query_as(count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "data_transfers": transfers,
        "total": total.0,
        "offset": offset,
        "limit": limit,
    })))
}

/// POST /api/ueba/advanced/data-transfers - Record data transfer
pub async fn record_data_transfer(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordDataTransferRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();

    // Verify entity ownership
    let entity: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM ueba_entities WHERE id = ? AND user_id = ?",
    )
    .bind(&body.entity_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if entity.is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({"error": "Entity not found"})));
    }

    let transferred_at = body.transferred_at.as_ref().unwrap_or(&now);
    let file_types_json = body.file_types.as_ref().map(|f| serde_json::to_string(f).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO ueba_data_transfers (
            id, user_id, entity_id, transfer_type, source_path, destination,
            destination_type, bytes_transferred, file_count, file_types,
            is_encrypted, is_compressed, protocol, tool_used, is_external,
            is_anomalous, risk_score, transferred_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.entity_id)
    .bind(&body.transfer_type)
    .bind(&body.source_path)
    .bind(&body.destination)
    .bind(&body.destination_type)
    .bind(&body.bytes_transferred)
    .bind(body.file_count.unwrap_or(1))
    .bind(&file_types_json)
    .bind(body.is_encrypted.unwrap_or(false))
    .bind(body.is_compressed.unwrap_or(false))
    .bind(&body.protocol)
    .bind(&body.tool_used)
    .bind(body.is_external.unwrap_or(false))
    .bind(transferred_at)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let transfer: DataTransfer = sqlx::query_as("SELECT * FROM ueba_data_transfers WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(transfer))
}

// =============================================================================
// Sprint 4: Advanced Detection Results Handlers
// =============================================================================

/// GET /api/ueba/advanced/detections - List advanced detections
pub async fn list_advanced_detections(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AdvancedDetectionQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let mut sql = String::from("SELECT * FROM ueba_advanced_detections WHERE user_id = ?");

    if let Some(entity_id) = &query.entity_id {
        sql.push_str(&format!(" AND entity_id = '{}'", entity_id));
    }
    if let Some(detection_type) = &query.detection_type {
        sql.push_str(&format!(" AND detection_type = '{}'", detection_type));
    }
    if let Some(severity) = &query.severity {
        sql.push_str(&format!(" AND severity = '{}'", severity));
    }
    if let Some(status) = &query.status {
        sql.push_str(&format!(" AND status = '{}'", status));
    }
    if let Some(start_time) = &query.start_time {
        sql.push_str(&format!(" AND detected_at >= '{}'", start_time));
    }
    if let Some(end_time) = &query.end_time {
        sql.push_str(&format!(" AND detected_at <= '{}'", end_time));
    }

    sql.push_str(" ORDER BY detected_at DESC LIMIT ? OFFSET ?");

    let detections: Vec<AdvancedDetection> = sqlx::query_as(&sql)
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let count_sql = "SELECT COUNT(*) FROM ueba_advanced_detections WHERE user_id = ?";
    let total: (i64,) = sqlx::query_as(count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(AdvancedDetectionListResponse {
        detections,
        total: total.0,
        offset,
        limit,
    }))
}

/// GET /api/ueba/advanced/detections/{id} - Get advanced detection details
pub async fn get_advanced_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let detection_id = path.into_inner();

    let detection: Option<AdvancedDetection> = sqlx::query_as(
        "SELECT * FROM ueba_advanced_detections WHERE id = ? AND user_id = ?",
    )
    .bind(&detection_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match detection {
        Some(d) => Ok(HttpResponse::Ok().json(d)),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Detection not found"}))),
    }
}

/// PUT /api/ueba/advanced/detections/{id}/status - Update detection status
pub async fn update_advanced_detection_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let detection_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("new");
    let resolution = body.get("resolution").and_then(|v| v.as_str());

    let resolved_at = if status == "resolved" { Some(&now) } else { None };

    let result = sqlx::query(
        r#"
        UPDATE ueba_advanced_detections SET status = ?, resolution = ?, resolved_at = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        "#,
    )
    .bind(status)
    .bind(resolution)
    .bind(resolved_at)
    .bind(&now)
    .bind(&detection_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({"error": "Detection not found"})));
    }

    let detection: AdvancedDetection = sqlx::query_as("SELECT * FROM ueba_advanced_detections WHERE id = ?")
        .bind(&detection_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().json(detection))
}

/// GET /api/ueba/advanced/stats - Get advanced detection statistics
pub async fn get_advanced_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Detection type counts
    let type_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT detection_type, COUNT(*) FROM ueba_advanced_detections WHERE user_id = ? GROUP BY detection_type",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Severity counts
    let severity_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*) FROM ueba_advanced_detections WHERE user_id = ? GROUP BY severity",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Status counts
    let status_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) FROM ueba_advanced_detections WHERE user_id = ? GROUP BY status",
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Recent detection count (last 24h)
    let recent_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ueba_advanced_detections WHERE user_id = ? AND detected_at >= datetime('now', '-24 hours')",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Config counts
    let business_hours_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ueba_business_hours WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let sensitive_resources_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ueba_sensitive_resources WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let detection_rules_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ueba_detection_rules WHERE user_id = ? AND is_enabled = 1",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let known_vpns_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ueba_known_vpns WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "detection_type_counts": type_counts.into_iter()
            .map(|(t, c)| serde_json::json!({"type": t, "count": c}))
            .collect::<Vec<_>>(),
        "severity_counts": severity_counts.into_iter()
            .map(|(s, c)| serde_json::json!({"severity": s, "count": c}))
            .collect::<Vec<_>>(),
        "status_counts": status_counts.into_iter()
            .map(|(s, c)| serde_json::json!({"status": s, "count": c}))
            .collect::<Vec<_>>(),
        "recent_detections_24h": recent_count.0,
        "config": {
            "business_hours_configs": business_hours_count.0,
            "sensitive_resources": sensitive_resources_count.0,
            "enabled_detection_rules": detection_rules_count.0,
            "known_vpns": known_vpns_count.0,
        }
    })))
}

// =============================================================================
// Route Configuration
// =============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ueba")
            // Dashboard & Stats
            .route("/dashboard", web::get().to(get_dashboard))
            .route("/stats", web::get().to(get_stats))
            // Entities
            .route("/entities", web::get().to(list_entities))
            .route("/entities", web::post().to(create_entity))
            .route("/entities/{id}", web::get().to(get_entity))
            .route("/entities/{id}", web::put().to(update_entity))
            .route("/entities/{id}", web::delete().to(delete_entity))
            .route("/entities/{id}/baselines", web::get().to(get_entity_baselines))
            .route("/entities/{id}/risk-factors", web::get().to(get_entity_risk_factors))
            // Peer Groups
            .route("/peer-groups", web::get().to(list_peer_groups))
            .route("/peer-groups", web::post().to(create_peer_group))
            .route("/peer-groups/{id}", web::get().to(get_peer_group))
            .route("/peer-groups/{id}", web::put().to(update_peer_group))
            .route("/peer-groups/{id}", web::delete().to(delete_peer_group))
            .route("/peer-groups/{id}/members", web::get().to(get_peer_group_members))
            // Activities
            .route("/activities", web::get().to(list_activities))
            .route("/activities", web::post().to(record_activity))
            .route("/activities/bulk", web::post().to(record_activities_bulk))
            // Anomalies
            .route("/anomalies", web::get().to(list_anomalies))
            .route("/anomalies/{id}", web::get().to(get_anomaly))
            .route("/anomalies/{id}", web::put().to(update_anomaly))
            .route("/anomalies/{id}/acknowledge", web::post().to(acknowledge_anomaly))
            .route("/anomalies/{id}/resolve", web::post().to(resolve_anomaly))
            // Sessions
            .route("/sessions", web::get().to(list_sessions))
            .route("/sessions", web::post().to(record_session))
            // Baselines
            .route("/baselines", web::get().to(list_baselines))
            // Watchlist
            .route("/watchlist", web::post().to(add_to_watchlist))
            .route("/watchlist/{entity_id}", web::delete().to(remove_from_watchlist))
            // Sprint 4: Advanced Detection
            .route("/advanced/stats", web::get().to(get_advanced_stats))
            .route("/advanced/detections", web::get().to(list_advanced_detections))
            .route("/advanced/detections/{id}", web::get().to(get_advanced_detection))
            .route("/advanced/detections/{id}/status", web::put().to(update_advanced_detection_status))
            // Business Hours
            .route("/advanced/business-hours", web::get().to(list_business_hours))
            .route("/advanced/business-hours", web::post().to(create_business_hours))
            .route("/advanced/business-hours/{id}", web::delete().to(delete_business_hours))
            // Sensitive Resources
            .route("/advanced/sensitive-resources", web::get().to(list_sensitive_resources))
            .route("/advanced/sensitive-resources", web::post().to(create_sensitive_resource))
            .route("/advanced/sensitive-resources/{id}", web::delete().to(delete_sensitive_resource))
            // Known VPNs
            .route("/advanced/known-vpns", web::get().to(list_known_vpns))
            .route("/advanced/known-vpns", web::post().to(create_known_vpn))
            .route("/advanced/known-vpns/{id}", web::delete().to(delete_known_vpn))
            // Detection Rules
            .route("/advanced/detection-rules", web::get().to(list_detection_rules))
            .route("/advanced/detection-rules", web::post().to(create_detection_rule))
            .route("/advanced/detection-rules/{id}/toggle", web::put().to(toggle_detection_rule))
            .route("/advanced/detection-rules/{id}", web::delete().to(delete_detection_rule))
            // Data Access
            .route("/advanced/data-accesses", web::get().to(list_data_accesses))
            .route("/advanced/data-accesses", web::post().to(record_data_access))
            // Host Access
            .route("/advanced/host-accesses", web::get().to(list_host_accesses))
            .route("/advanced/host-accesses", web::post().to(record_host_access))
            // Data Transfers
            .route("/advanced/data-transfers", web::get().to(list_data_transfers))
            .route("/advanced/data-transfers", web::post().to(record_data_transfer))
    );
}
