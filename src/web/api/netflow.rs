//! NetFlow/IPFIX/sFlow Analysis API endpoints
//!
//! This module provides network flow analysis APIs including:
//! - Flow collector management (create, configure, start/stop)
//! - Flow record queries and analysis
//! - Flow aggregation and statistics
//! - Top talkers analysis
//! - Anomaly detection and management
//! - Flow-based alerting rules
//! - Export and reporting

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::web::auth;

// =============================================================================
// Response Types
// =============================================================================

#[derive(Debug, Serialize)]
pub struct CollectorListResponse {
    pub collectors: Vec<FlowCollectorResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct FlowCollectorResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub collector_type: String,
    pub listen_address: String,
    pub listen_port: i32,
    pub status: String,
    pub packets_received: i64,
    pub flows_parsed: i64,
    pub parse_errors: i64,
    pub bytes_received: i64,
    pub last_packet_at: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct FlowRecordListResponse {
    pub flows: Vec<FlowRecordResponse>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct FlowRecordResponse {
    pub id: String,
    pub collector_id: String,
    pub exporter_ip: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: i32,
    pub dst_port: i32,
    pub protocol: i32,
    pub protocol_name: String,
    pub packets: i64,
    pub bytes: i64,
    pub tcp_flags: Option<i32>,
    pub start_time: String,
    pub end_time: String,
    pub duration_ms: i64,
    pub src_as: Option<i64>,
    pub dst_as: Option<i64>,
    pub application: Option<String>,
    pub src_country: Option<String>,
    pub dst_country: Option<String>,
    pub is_suspicious: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct FlowAggregateListResponse {
    pub aggregates: Vec<FlowAggregateResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct FlowAggregateResponse {
    pub id: String,
    pub period: String,
    pub period_start: String,
    pub period_end: String,
    pub total_flows: i64,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
    pub top_sources: Vec<TopTalkerResponse>,
    pub top_destinations: Vec<TopTalkerResponse>,
    pub protocol_distribution: Vec<ProtocolDistributionResponse>,
    pub avg_flow_duration_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct TopTalkerResponse {
    pub ip_address: String,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub flow_count: i64,
    pub percentage: f64,
    pub geo_location: Option<String>,
    pub as_number: Option<i64>,
    pub as_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProtocolDistributionResponse {
    pub protocol: i32,
    pub protocol_name: String,
    pub bytes: i64,
    pub packets: i64,
    pub flow_count: i64,
    pub percentage: f64,
}

#[derive(Debug, Serialize)]
pub struct FlowAnomalyListResponse {
    pub anomalies: Vec<FlowAnomalyResponse>,
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct FlowAnomalyResponse {
    pub id: String,
    pub collector_id: Option<String>,
    pub anomaly_type: String,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub affected_ports: Vec<i32>,
    pub evidence: serde_json::Value,
    pub first_seen: String,
    pub last_seen: String,
    pub flow_count: i64,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub is_acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct FlowStatsResponse {
    pub total_flows: i64,
    pub total_bytes: i64,
    pub total_packets: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub flows_per_second: f64,
    pub avg_flow_size: f64,
    pub avg_packet_size: f64,
    pub tcp_flows: i64,
    pub udp_flows: i64,
    pub icmp_flows: i64,
    pub other_flows: i64,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FlowDashboardResponse {
    pub stats: FlowStatsResponse,
    pub collectors: Vec<CollectorSummary>,
    pub recent_anomalies: Vec<FlowAnomalyResponse>,
    pub top_sources: Vec<TopTalkerResponse>,
    pub top_destinations: Vec<TopTalkerResponse>,
    pub protocol_distribution: Vec<ProtocolDistributionResponse>,
    pub timeline: Vec<TimelineEntryResponse>,
}

#[derive(Debug, Serialize)]
pub struct CollectorSummary {
    pub id: String,
    pub name: String,
    pub status: String,
    pub collector_type: String,
    pub flows_parsed: i64,
    pub bytes_received: i64,
}

#[derive(Debug, Serialize)]
pub struct TimelineEntryResponse {
    pub timestamp: String,
    pub flows: i64,
    pub bytes: i64,
    pub packets: i64,
    pub unique_sources: i64,
    pub unique_destinations: i64,
}

#[derive(Debug, Serialize)]
pub struct ExporterListResponse {
    pub exporters: Vec<FlowExporterResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct FlowExporterResponse {
    pub id: String,
    pub collector_id: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub device_type: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub total_packets: i64,
    pub total_flows: i64,
}

#[derive(Debug, Serialize)]
pub struct AlertRuleListResponse {
    pub rules: Vec<AlertRuleResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct AlertRuleResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_enabled: bool,
    pub rule_type: String,
    pub condition_type: String,
    pub threshold_value: f64,
    pub threshold_unit: Option<String>,
    pub time_window_minutes: i32,
    pub severity: String,
    pub last_triggered_at: Option<String>,
    pub trigger_count: i64,
    pub created_at: String,
}

// =============================================================================
// Request Types
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateCollectorRequest {
    pub name: String,
    pub description: Option<String>,
    pub collector_type: String,
    pub listen_address: Option<String>,
    pub listen_port: Option<i32>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCollectorRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub listen_address: Option<String>,
    pub listen_port: Option<i32>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAlertRuleRequest {
    pub name: String,
    pub description: Option<String>,
    pub collector_id: Option<String>,
    pub rule_type: String,
    pub condition_type: String,
    pub threshold_value: f64,
    pub threshold_unit: Option<String>,
    pub time_window_minutes: Option<i32>,
    pub severity: Option<String>,
    pub notification_channels: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_enabled: Option<bool>,
    pub threshold_value: Option<f64>,
    pub threshold_unit: Option<String>,
    pub time_window_minutes: Option<i32>,
    pub severity: Option<String>,
    pub notification_channels: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct AcknowledgeAnomalyRequest {
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunAnalysisRequest {
    pub collector_id: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub detect_anomalies: Option<bool>,
    pub aggregation_period: Option<String>,
}

// =============================================================================
// Query Parameters
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CollectorQuery {
    pub status: Option<String>,
    pub collector_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FlowQuery {
    pub collector_id: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub protocol: Option<i32>,
    pub application: Option<String>,
    pub is_suspicious: Option<bool>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AggregateQuery {
    pub collector_id: Option<String>,
    pub period: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AnomalyQuery {
    pub collector_id: Option<String>,
    pub anomaly_type: Option<String>,
    pub severity: Option<String>,
    pub is_acknowledged: Option<bool>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct TopTalkersQuery {
    pub collector_id: Option<String>,
    pub direction: Option<String>, // "source" or "destination"
    pub period: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    pub collector_id: Option<String>,
    pub period: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

// =============================================================================
// Collector Management Endpoints
// =============================================================================

/// List all flow collectors
pub async fn list_collectors(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<CollectorQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let mut sql = String::from(
        "SELECT id, name, description, collector_type, listen_address, listen_port,
                status, packets_received, flows_parsed, parse_errors, bytes_received,
                last_packet_at, error_message, created_at, updated_at
         FROM flow_collectors WHERE user_id = ?"
    );

    if let Some(status) = &query.status {
        sql.push_str(&format!(" AND status = '{}'", status));
    }
    if let Some(ct) = &query.collector_type {
        sql.push_str(&format!(" AND collector_type = '{}'", ct));
    }

    sql.push_str(" ORDER BY created_at DESC");

    let rows: Vec<(String, String, Option<String>, String, String, i32, String, i64, i64, i64, i64, Option<String>, Option<String>, String, String)> =
        sqlx::query_as(&sql)
            .bind(user_id)
            .fetch_all(pool.get_ref())
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let collectors: Vec<FlowCollectorResponse> = rows.into_iter()
        .map(|(id, name, description, collector_type, listen_address, listen_port, status, packets_received, flows_parsed, parse_errors, bytes_received, last_packet_at, error_message, created_at, updated_at)| {
            FlowCollectorResponse {
                id,
                name,
                description,
                collector_type,
                listen_address,
                listen_port,
                status,
                packets_received,
                flows_parsed,
                parse_errors,
                bytes_received,
                last_packet_at,
                error_message,
                created_at,
                updated_at,
            }
        })
        .collect();

    let total = collectors.len() as i64;

    Ok(HttpResponse::Ok().json(CollectorListResponse { collectors, total }))
}

/// Create a new flow collector
pub async fn create_collector(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateCollectorRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let listen_address = body.listen_address.clone().unwrap_or_else(|| "0.0.0.0".to_string());
    let listen_port = body.listen_port.unwrap_or(2055);
    let config_json = body.config.as_ref().map(|c| serde_json::to_string(c).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO flow_collectors (
            id, user_id, name, description, collector_type, listen_address, listen_port,
            status, packets_received, flows_parsed, parse_errors, bytes_received,
            config, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'stopped', 0, 0, 0, 0, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.collector_type)
    .bind(&listen_address)
    .bind(listen_port)
    .bind(&config_json)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": body.name,
        "status": "stopped",
        "message": "Collector created successfully"
    })))
}

/// Get a specific collector
pub async fn get_collector(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let collector_id = path.into_inner();
    let user_id = &claims.sub;

    let row: Option<(String, String, Option<String>, String, String, i32, String, i64, i64, i64, i64, Option<String>, Option<String>, String, String)> =
        sqlx::query_as(
            "SELECT id, name, description, collector_type, listen_address, listen_port,
                    status, packets_received, flows_parsed, parse_errors, bytes_received,
                    last_packet_at, error_message, created_at, updated_at
             FROM flow_collectors WHERE id = ? AND user_id = ?"
        )
        .bind(&collector_id)
        .bind(user_id)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    match row {
        Some((id, name, description, collector_type, listen_address, listen_port, status, packets_received, flows_parsed, parse_errors, bytes_received, last_packet_at, error_message, created_at, updated_at)) => {
            Ok(HttpResponse::Ok().json(FlowCollectorResponse {
                id,
                name,
                description,
                collector_type,
                listen_address,
                listen_port,
                status,
                packets_received,
                flows_parsed,
                parse_errors,
                bytes_received,
                last_packet_at,
                error_message,
                created_at,
                updated_at,
            }))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Collector not found"
        })))
    }
}

/// Update a collector
pub async fn update_collector(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateCollectorRequest>,
) -> Result<HttpResponse> {
    let collector_id = path.into_inner();
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?".to_string()];
    let mut values: Vec<String> = vec![now.clone()];

    if let Some(name) = &body.name {
        updates.push("name = ?".to_string());
        values.push(name.clone());
    }
    if let Some(desc) = &body.description {
        updates.push("description = ?".to_string());
        values.push(desc.clone());
    }
    if let Some(addr) = &body.listen_address {
        updates.push("listen_address = ?".to_string());
        values.push(addr.clone());
    }
    if let Some(port) = body.listen_port {
        updates.push(format!("listen_port = {}", port));
    }
    if let Some(config) = &body.config {
        updates.push("config = ?".to_string());
        values.push(serde_json::to_string(config).unwrap_or_default());
    }

    let sql = format!(
        "UPDATE flow_collectors SET {} WHERE id = ? AND user_id = ?",
        updates.join(", ")
    );

    let mut query = sqlx::query(&sql);
    for val in &values {
        query = query.bind(val);
    }
    query = query.bind(&collector_id).bind(user_id);

    let result = query.execute(pool.get_ref()).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Collector not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Collector updated successfully"
    })))
}

/// Delete a collector
pub async fn delete_collector(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let collector_id = path.into_inner();
    let user_id = &claims.sub;

    let result = sqlx::query(
        "DELETE FROM flow_collectors WHERE id = ? AND user_id = ?"
    )
    .bind(&collector_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Collector not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Collector deleted successfully"
    })))
}

/// Start a collector
pub async fn start_collector(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let collector_id = path.into_inner();
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();

    // Update status to running (actual UDP listening would be handled by a background service)
    let result = sqlx::query(
        "UPDATE flow_collectors SET status = 'running', updated_at = ? WHERE id = ? AND user_id = ?"
    )
    .bind(&now)
    .bind(&collector_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Collector not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Collector started",
        "status": "running"
    })))
}

/// Stop a collector
pub async fn stop_collector(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let collector_id = path.into_inner();
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE flow_collectors SET status = 'stopped', updated_at = ? WHERE id = ? AND user_id = ?"
    )
    .bind(&now)
    .bind(&collector_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Collector not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Collector stopped",
        "status": "stopped"
    })))
}

// =============================================================================
// Flow Records Endpoints
// =============================================================================

/// List flow records
pub async fn list_flows(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<FlowQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000);

    // Build query with filters
    let mut sql = String::from(
        "SELECT f.id, f.collector_id, f.exporter_ip, f.src_ip, f.dst_ip, f.src_port, f.dst_port,
                f.protocol, f.packets, f.bytes, f.tcp_flags, f.start_time, f.end_time,
                f.duration_ms, f.src_as, f.dst_as, f.application, f.src_country, f.dst_country,
                f.is_suspicious, f.created_at
         FROM flow_records f
         JOIN flow_collectors c ON f.collector_id = c.id
         WHERE c.user_id = ?"
    );

    if let Some(cid) = &query.collector_id {
        sql.push_str(&format!(" AND f.collector_id = '{}'", cid));
    }
    if let Some(src) = &query.src_ip {
        sql.push_str(&format!(" AND f.src_ip = '{}'", src));
    }
    if let Some(dst) = &query.dst_ip {
        sql.push_str(&format!(" AND f.dst_ip = '{}'", dst));
    }
    if let Some(sp) = query.src_port {
        sql.push_str(&format!(" AND f.src_port = {}", sp));
    }
    if let Some(dp) = query.dst_port {
        sql.push_str(&format!(" AND f.dst_port = {}", dp));
    }
    if let Some(proto) = query.protocol {
        sql.push_str(&format!(" AND f.protocol = {}", proto));
    }
    if let Some(app) = &query.application {
        sql.push_str(&format!(" AND f.application = '{}'", app));
    }
    if let Some(susp) = query.is_suspicious {
        sql.push_str(&format!(" AND f.is_suspicious = {}", if susp { 1 } else { 0 }));
    }
    if let Some(start) = &query.start_time {
        sql.push_str(&format!(" AND f.start_time >= '{}'", start));
    }
    if let Some(end) = &query.end_time {
        sql.push_str(&format!(" AND f.start_time <= '{}'", end));
    }

    // Count query
    let count_sql = format!("SELECT COUNT(*) as cnt FROM ({}) t", sql);
    let (total,): (i64,) = sqlx::query_as(&count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    sql.push_str(&format!(" ORDER BY f.start_time DESC LIMIT {} OFFSET {}", limit, offset));

    use sqlx::Row;
    let rows = sqlx::query(&sql)
        .bind(user_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let flows: Vec<FlowRecordResponse> = rows.into_iter()
        .map(|row| {
            let protocol: i32 = row.get(7);
            let is_suspicious: i32 = row.get(19);
            FlowRecordResponse {
                id: row.get(0),
                collector_id: row.get(1),
                exporter_ip: row.get(2),
                src_ip: row.get(3),
                dst_ip: row.get(4),
                src_port: row.get(5),
                dst_port: row.get(6),
                protocol,
                protocol_name: protocol_name(protocol as u8),
                packets: row.get(8),
                bytes: row.get(9),
                tcp_flags: row.get(10),
                start_time: row.get(11),
                end_time: row.get(12),
                duration_ms: row.get(13),
                src_as: row.get(14),
                dst_as: row.get(15),
                application: row.get(16),
                src_country: row.get(17),
                dst_country: row.get(18),
                is_suspicious: is_suspicious != 0,
                created_at: row.get(20),
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(FlowRecordListResponse { flows, total, offset, limit }))
}

// =============================================================================
// Flow Anomalies Endpoints
// =============================================================================

/// List flow anomalies
pub async fn list_anomalies(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AnomalyQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(500);

    let mut sql = String::from(
        "SELECT id, collector_id, anomaly_type, severity, title, description,
                source_ip, destination_ip, affected_ports, evidence, first_seen, last_seen,
                flow_count, total_bytes, total_packets, is_acknowledged, acknowledged_by,
                acknowledged_at, notes, created_at
         FROM flow_anomalies WHERE user_id = ?"
    );

    if let Some(cid) = &query.collector_id {
        sql.push_str(&format!(" AND collector_id = '{}'", cid));
    }
    if let Some(atype) = &query.anomaly_type {
        sql.push_str(&format!(" AND anomaly_type = '{}'", atype));
    }
    if let Some(sev) = &query.severity {
        sql.push_str(&format!(" AND severity = '{}'", sev));
    }
    if let Some(ack) = query.is_acknowledged {
        sql.push_str(&format!(" AND is_acknowledged = {}", if ack { 1 } else { 0 }));
    }
    if let Some(start) = &query.start_time {
        sql.push_str(&format!(" AND first_seen >= '{}'", start));
    }
    if let Some(end) = &query.end_time {
        sql.push_str(&format!(" AND first_seen <= '{}'", end));
    }

    let count_sql = format!("SELECT COUNT(*) as cnt FROM ({}) t", sql);
    let (total,): (i64,) = sqlx::query_as(&count_sql)
        .bind(user_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    sql.push_str(&format!(" ORDER BY first_seen DESC LIMIT {} OFFSET {}", limit, offset));

    use sqlx::Row;
    let rows = sqlx::query(&sql)
        .bind(user_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let anomalies: Vec<FlowAnomalyResponse> = rows.into_iter()
        .map(|row| {
            let affected_ports: Option<String> = row.get(8);
            let evidence: String = row.get(9);
            let is_acknowledged: i32 = row.get(15);
            FlowAnomalyResponse {
                id: row.get(0),
                collector_id: row.get(1),
                anomaly_type: row.get(2),
                severity: row.get(3),
                title: row.get(4),
                description: row.get(5),
                source_ip: row.get(6),
                destination_ip: row.get(7),
                affected_ports: parse_ports(&affected_ports),
                evidence: serde_json::from_str(&evidence).unwrap_or(serde_json::Value::Null),
                first_seen: row.get(10),
                last_seen: row.get(11),
                flow_count: row.get(12),
                total_bytes: row.get(13),
                total_packets: row.get(14),
                is_acknowledged: is_acknowledged != 0,
                acknowledged_by: row.get(16),
                acknowledged_at: row.get(17),
                notes: row.get(18),
                created_at: row.get(19),
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(FlowAnomalyListResponse { anomalies, total, offset, limit }))
}

/// Acknowledge an anomaly
pub async fn acknowledge_anomaly(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AcknowledgeAnomalyRequest>,
) -> Result<HttpResponse> {
    let anomaly_id = path.into_inner();
    let user_id = &claims.sub;
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE flow_anomalies SET is_acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?, notes = ?, updated_at = ?
         WHERE id = ? AND user_id = ?"
    )
    .bind(user_id)
    .bind(&now)
    .bind(&body.notes)
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
        "message": "Anomaly acknowledged"
    })))
}

// =============================================================================
// Flow Analysis Endpoints
// =============================================================================

/// Get flow statistics
pub async fn get_flow_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<FlowQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let mut sql = String::from(
        "SELECT COUNT(*) as flow_count,
                COALESCE(SUM(bytes), 0) as total_bytes,
                COALESCE(SUM(packets), 0) as total_packets,
                COUNT(DISTINCT src_ip) as unique_sources,
                COUNT(DISTINCT dst_ip) as unique_destinations,
                MIN(start_time) as min_time,
                MAX(end_time) as max_time,
                SUM(CASE WHEN protocol = 6 THEN 1 ELSE 0 END) as tcp_flows,
                SUM(CASE WHEN protocol = 17 THEN 1 ELSE 0 END) as udp_flows,
                SUM(CASE WHEN protocol = 1 THEN 1 ELSE 0 END) as icmp_flows
         FROM flow_records f
         JOIN flow_collectors c ON f.collector_id = c.id
         WHERE c.user_id = ?"
    );

    if let Some(cid) = &query.collector_id {
        sql.push_str(&format!(" AND f.collector_id = '{}'", cid));
    }
    if let Some(start) = &query.start_time {
        sql.push_str(&format!(" AND f.start_time >= '{}'", start));
    }
    if let Some(end) = &query.end_time {
        sql.push_str(&format!(" AND f.start_time <= '{}'", end));
    }

    let row: (i64, i64, i64, i64, i64, Option<String>, Option<String>, i64, i64, i64) =
        sqlx::query_as(&sql)
            .bind(user_id)
            .fetch_one(pool.get_ref())
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let (total_flows, total_bytes, total_packets, unique_sources, unique_destinations, min_time, max_time, tcp_flows, udp_flows, icmp_flows) = row;

    // Calculate rates
    let duration_secs = if let (Some(min), Some(max)) = (&min_time, &max_time) {
        chrono::DateTime::parse_from_rfc3339(max)
            .and_then(|m| chrono::DateTime::parse_from_rfc3339(min).map(|n| (m - n).num_seconds().max(1)))
            .unwrap_or(1)
    } else {
        1
    };

    let stats = FlowStatsResponse {
        total_flows,
        total_bytes,
        total_packets,
        unique_sources,
        unique_destinations,
        bytes_per_second: total_bytes as f64 / duration_secs as f64,
        packets_per_second: total_packets as f64 / duration_secs as f64,
        flows_per_second: total_flows as f64 / duration_secs as f64,
        avg_flow_size: if total_flows > 0 { total_bytes as f64 / total_flows as f64 } else { 0.0 },
        avg_packet_size: if total_packets > 0 { total_bytes as f64 / total_packets as f64 } else { 0.0 },
        tcp_flows,
        udp_flows,
        icmp_flows,
        other_flows: total_flows - tcp_flows - udp_flows - icmp_flows,
        period_start: min_time,
        period_end: max_time,
    };

    Ok(HttpResponse::Ok().json(stats))
}

/// Get top talkers
pub async fn get_top_talkers(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<TopTalkersQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let limit = query.limit.unwrap_or(10).min(100);
    let direction = query.direction.as_deref().unwrap_or("source");

    let ip_column = if direction == "destination" { "dst_ip" } else { "src_ip" };

    let mut sql = format!(
        "SELECT {} as ip, SUM(bytes) as total_bytes, SUM(packets) as total_packets, COUNT(*) as flow_count
         FROM flow_records f
         JOIN flow_collectors c ON f.collector_id = c.id
         WHERE c.user_id = ?",
        ip_column
    );

    if let Some(cid) = &query.collector_id {
        sql.push_str(&format!(" AND f.collector_id = '{}'", cid));
    }
    if let Some(start) = &query.start_time {
        sql.push_str(&format!(" AND f.start_time >= '{}'", start));
    }
    if let Some(end) = &query.end_time {
        sql.push_str(&format!(" AND f.start_time <= '{}'", end));
    }

    sql.push_str(&format!(" GROUP BY {} ORDER BY total_bytes DESC LIMIT {}", ip_column, limit));

    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(&sql)
        .bind(user_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let total_bytes: i64 = rows.iter().map(|(_, b, _, _)| *b).sum();

    let talkers: Vec<TopTalkerResponse> = rows.into_iter()
        .map(|(ip, bytes, packets, flows)| TopTalkerResponse {
            ip_address: ip,
            total_bytes: bytes,
            total_packets: packets,
            flow_count: flows,
            percentage: if total_bytes > 0 { (bytes as f64 / total_bytes as f64) * 100.0 } else { 0.0 },
            geo_location: None,
            as_number: None,
            as_name: None,
        })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "direction": direction,
        "talkers": talkers,
        "total": talkers.len()
    })))
}

/// Get flow timeline
pub async fn get_timeline(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<TimelineQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let period = query.period.as_deref().unwrap_or("hour");

    // Determine time grouping based on period
    let time_format = match period {
        "minute" => "%Y-%m-%dT%H:%M:00Z",
        "5minutes" => "%Y-%m-%dT%H:%M:00Z", // Will need post-processing
        "15minutes" => "%Y-%m-%dT%H:%M:00Z",
        "hour" => "%Y-%m-%dT%H:00:00Z",
        "day" => "%Y-%m-%dT00:00:00Z",
        _ => "%Y-%m-%dT%H:00:00Z",
    };

    let mut sql = format!(
        "SELECT strftime('{}', start_time) as period_time,
                COUNT(*) as flow_count,
                SUM(bytes) as total_bytes,
                SUM(packets) as total_packets,
                COUNT(DISTINCT src_ip) as unique_sources,
                COUNT(DISTINCT dst_ip) as unique_destinations
         FROM flow_records f
         JOIN flow_collectors c ON f.collector_id = c.id
         WHERE c.user_id = ?",
        time_format
    );

    if let Some(cid) = &query.collector_id {
        sql.push_str(&format!(" AND f.collector_id = '{}'", cid));
    }
    if let Some(start) = &query.start_time {
        sql.push_str(&format!(" AND f.start_time >= '{}'", start));
    }
    if let Some(end) = &query.end_time {
        sql.push_str(&format!(" AND f.start_time <= '{}'", end));
    }

    sql.push_str(" GROUP BY period_time ORDER BY period_time");

    let rows: Vec<(String, i64, i64, i64, i64, i64)> = sqlx::query_as(&sql)
        .bind(user_id)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let timeline: Vec<TimelineEntryResponse> = rows.into_iter()
        .map(|(timestamp, flows, bytes, packets, sources, destinations)| TimelineEntryResponse {
            timestamp,
            flows,
            bytes,
            packets,
            unique_sources: sources,
            unique_destinations: destinations,
        })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "period": period,
        "timeline": timeline,
        "total": timeline.len()
    })))
}

/// Get flow dashboard overview
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<FlowQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    // Get collectors summary
    let collectors: Vec<(String, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, name, status, collector_type, flows_parsed, bytes_received
         FROM flow_collectors WHERE user_id = ? ORDER BY created_at DESC LIMIT 10"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let collector_summaries: Vec<CollectorSummary> = collectors.into_iter()
        .map(|(id, name, status, collector_type, flows_parsed, bytes_received)| CollectorSummary {
            id,
            name,
            status,
            collector_type,
            flows_parsed,
            bytes_received,
        })
        .collect();

    // Get recent anomalies
    use sqlx::Row;
    let anomaly_rows = sqlx::query(
        "SELECT id, collector_id, anomaly_type, severity, title, description,
                source_ip, destination_ip, affected_ports, evidence, first_seen, last_seen,
                flow_count, total_bytes, total_packets, is_acknowledged, acknowledged_by,
                acknowledged_at, notes, created_at
         FROM flow_anomalies WHERE user_id = ? ORDER BY first_seen DESC LIMIT 5"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let recent_anomalies: Vec<FlowAnomalyResponse> = anomaly_rows.into_iter()
        .map(|row| {
            let affected_ports: Option<String> = row.get(8);
            let evidence: String = row.get(9);
            let is_acknowledged: i32 = row.get(15);
            FlowAnomalyResponse {
                id: row.get(0),
                collector_id: row.get(1),
                anomaly_type: row.get(2),
                severity: row.get(3),
                title: row.get(4),
                description: row.get(5),
                source_ip: row.get(6),
                destination_ip: row.get(7),
                affected_ports: parse_ports(&affected_ports),
                evidence: serde_json::from_str(&evidence).unwrap_or(serde_json::Value::Null),
                first_seen: row.get(10),
                last_seen: row.get(11),
                flow_count: row.get(12),
                total_bytes: row.get(13),
                total_packets: row.get(14),
                is_acknowledged: is_acknowledged != 0,
                acknowledged_by: row.get(16),
                acknowledged_at: row.get(17),
                notes: row.get(18),
                created_at: row.get(19),
            }
        })
        .collect();

    // Get basic stats
    let stats_row: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) as flows, COALESCE(SUM(bytes), 0), COALESCE(SUM(packets), 0),
                COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_ip)
         FROM flow_records f
         JOIN flow_collectors c ON f.collector_id = c.id
         WHERE c.user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let stats = FlowStatsResponse {
        total_flows: stats_row.0,
        total_bytes: stats_row.1,
        total_packets: stats_row.2,
        unique_sources: stats_row.3,
        unique_destinations: stats_row.4,
        bytes_per_second: 0.0,
        packets_per_second: 0.0,
        flows_per_second: 0.0,
        avg_flow_size: if stats_row.0 > 0 { stats_row.1 as f64 / stats_row.0 as f64 } else { 0.0 },
        avg_packet_size: if stats_row.2 > 0 { stats_row.1 as f64 / stats_row.2 as f64 } else { 0.0 },
        tcp_flows: 0,
        udp_flows: 0,
        icmp_flows: 0,
        other_flows: 0,
        period_start: None,
        period_end: None,
    };

    Ok(HttpResponse::Ok().json(FlowDashboardResponse {
        stats,
        collectors: collector_summaries,
        recent_anomalies,
        top_sources: vec![],
        top_destinations: vec![],
        protocol_distribution: vec![],
        timeline: vec![],
    }))
}

/// Get flow exporters for a collector
pub async fn list_exporters(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let collector_id = path.into_inner();
    let user_id = &claims.sub;

    // Verify collector belongs to user
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM flow_collectors WHERE id = ? AND user_id = ?"
    )
    .bind(&collector_id)
    .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Collector not found"
        })));
    }

    let rows: Vec<(String, String, String, Option<String>, Option<String>, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, collector_id, ip_address, hostname, device_type, first_seen, last_seen, total_packets, total_flows
         FROM flow_exporters WHERE collector_id = ? ORDER BY last_seen DESC"
    )
    .bind(&collector_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let exporters: Vec<FlowExporterResponse> = rows.into_iter()
        .map(|(id, collector_id, ip_address, hostname, device_type, first_seen, last_seen, total_packets, total_flows)| {
            FlowExporterResponse {
                id,
                collector_id,
                ip_address,
                hostname,
                device_type,
                first_seen,
                last_seen,
                total_packets,
                total_flows,
            }
        })
        .collect();

    let total = exporters.len() as i64;

    Ok(HttpResponse::Ok().json(ExporterListResponse { exporters, total }))
}

// =============================================================================
// Alert Rules Endpoints
// =============================================================================

/// List alert rules
pub async fn list_alert_rules(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let rows: Vec<(String, String, Option<String>, i32, String, String, f64, Option<String>, i32, String, Option<String>, i64, String)> = sqlx::query_as(
        "SELECT id, name, description, is_enabled, rule_type, condition_type, threshold_value,
                threshold_unit, time_window_minutes, severity, last_triggered_at, trigger_count, created_at
         FROM flow_alert_rules WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    let rules: Vec<AlertRuleResponse> = rows.into_iter()
        .map(|(id, name, description, is_enabled, rule_type, condition_type, threshold_value, threshold_unit, time_window_minutes, severity, last_triggered_at, trigger_count, created_at)| {
            AlertRuleResponse {
                id,
                name,
                description,
                is_enabled: is_enabled != 0,
                rule_type,
                condition_type,
                threshold_value,
                threshold_unit,
                time_window_minutes,
                severity,
                last_triggered_at,
                trigger_count,
                created_at,
            }
        })
        .collect();

    let total = rules.len() as i64;

    Ok(HttpResponse::Ok().json(AlertRuleListResponse { rules, total }))
}

/// Create an alert rule
pub async fn create_alert_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateAlertRuleRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let notification_channels = body.notification_channels.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO flow_alert_rules (
            id, user_id, collector_id, name, description, is_enabled, rule_type,
            condition_type, threshold_value, threshold_unit, time_window_minutes,
            severity, notification_channels, trigger_count, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        "#
    )
    .bind(&id)
    .bind(user_id)
    .bind(&body.collector_id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&body.rule_type)
    .bind(&body.condition_type)
    .bind(body.threshold_value)
    .bind(&body.threshold_unit)
    .bind(body.time_window_minutes.unwrap_or(5))
    .bind(body.severity.as_deref().unwrap_or("medium"))
    .bind(&notification_channels)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": body.name,
        "message": "Alert rule created successfully"
    })))
}

/// Delete an alert rule
pub async fn delete_alert_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let rule_id = path.into_inner();
    let user_id = &claims.sub;

    let result = sqlx::query(
        "DELETE FROM flow_alert_rules WHERE id = ? AND user_id = ?"
    )
    .bind(&rule_id)
    .bind(user_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Alert rule not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Alert rule deleted successfully"
    })))
}

// =============================================================================
// Helper Functions
// =============================================================================

fn protocol_name(proto: u8) -> String {
    match proto {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        47 => "GRE".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        89 => "OSPF".to_string(),
        132 => "SCTP".to_string(),
        _ => format!("Protocol {}", proto),
    }
}

fn parse_ports(ports_json: &Option<String>) -> Vec<i32> {
    ports_json.as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

// =============================================================================
// Route Configuration
// =============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/netflow")
            // Collectors
            .route("/collectors", web::get().to(list_collectors))
            .route("/collectors", web::post().to(create_collector))
            .route("/collectors/{id}", web::get().to(get_collector))
            .route("/collectors/{id}", web::put().to(update_collector))
            .route("/collectors/{id}", web::delete().to(delete_collector))
            .route("/collectors/{id}/start", web::post().to(start_collector))
            .route("/collectors/{id}/stop", web::post().to(stop_collector))
            .route("/collectors/{id}/exporters", web::get().to(list_exporters))
            // Flows
            .route("/flows", web::get().to(list_flows))
            .route("/stats", web::get().to(get_flow_stats))
            .route("/top-talkers", web::get().to(get_top_talkers))
            .route("/timeline", web::get().to(get_timeline))
            .route("/dashboard", web::get().to(get_dashboard))
            // Anomalies
            .route("/anomalies", web::get().to(list_anomalies))
            .route("/anomalies/{id}/acknowledge", web::post().to(acknowledge_anomaly))
            // Alert Rules
            .route("/alert-rules", web::get().to(list_alert_rules))
            .route("/alert-rules", web::post().to(create_alert_rule))
            .route("/alert-rules/{id}", web::delete().to(delete_alert_rule))
    );
}
