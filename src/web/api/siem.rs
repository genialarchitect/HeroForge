//! SIEM (Security Information and Event Management) API endpoints
//!
//! This module provides full SIEM capabilities including:
//! - Log source management (CRUD operations)
//! - Log entry querying and retrieval
//! - Detection rule management
//! - Alert management and resolution
//! - SIEM statistics

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::siem::{
    AlertStatus, LogFormat, LogSource, LogSourceStatus, RuleStatus, RuleType,
    SiemAlert, SiemRule, SiemSeverity, TransportProtocol,
};
use crate::web::auth;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to create a new log source
#[derive(Debug, Deserialize)]
pub struct CreateLogSourceRequest {
    pub name: String,
    pub description: Option<String>,
    pub source_type: String,
    pub host: Option<String>,
    pub format: String,
    pub protocol: String,
    pub port: Option<u16>,
    pub tags: Option<Vec<String>>,
    pub auto_enrich: Option<bool>,
    pub retention_days: Option<i32>,
}

/// Request to update a log source
#[derive(Debug, Deserialize)]
pub struct UpdateLogSourceRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub source_type: Option<String>,
    pub host: Option<String>,
    pub format: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub status: Option<String>,
    pub tags: Option<Vec<String>>,
    pub auto_enrich: Option<bool>,
    pub retention_days: Option<i32>,
}

/// Query parameters for listing log sources
#[derive(Debug, Deserialize)]
pub struct LogSourceQuery {
    pub status: Option<String>,
    pub source_type: Option<String>,
}

/// Query parameters for searching logs
#[derive(Debug, Deserialize)]
pub struct LogSearchQuery {
    pub query: Option<String>,
    pub source_id: Option<String>,
    pub min_severity: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub hostname: Option<String>,
    pub application: Option<String>,
    pub user: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub alerted: Option<bool>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// Request to create a detection rule
#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub severity: String,
    pub status: Option<String>,
    pub definition: serde_json::Value,
    pub source_ids: Option<Vec<String>>,
    pub categories: Option<Vec<String>>,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub response_actions: Option<Vec<String>>,
    pub time_window_seconds: Option<i64>,
    pub threshold_count: Option<i64>,
    pub group_by_fields: Option<Vec<String>>,
}

/// Request to update a detection rule
#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rule_type: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub definition: Option<serde_json::Value>,
    pub source_ids: Option<Vec<String>>,
    pub categories: Option<Vec<String>>,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub response_actions: Option<Vec<String>>,
    pub time_window_seconds: Option<i64>,
    pub threshold_count: Option<i64>,
    pub group_by_fields: Option<Vec<String>>,
}

/// Query parameters for listing rules
#[derive(Debug, Deserialize)]
pub struct RuleListQuery {
    pub status: Option<String>,
    pub rule_type: Option<String>,
    pub severity: Option<String>,
}

/// Query parameters for listing alerts
#[derive(Debug, Deserialize)]
pub struct AlertListQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub rule_id: Option<String>,
    pub assigned_to: Option<String>,
    pub limit: Option<u32>,
}

/// Request to update alert status
#[derive(Debug, Deserialize)]
pub struct UpdateAlertStatusRequest {
    pub status: String,
    pub assigned_to: Option<String>,
}

/// Request to resolve an alert
#[derive(Debug, Deserialize)]
pub struct ResolveAlertRequest {
    pub resolution_notes: Option<String>,
    pub is_false_positive: Option<bool>,
}

/// SIEM statistics response
#[derive(Debug, Serialize)]
pub struct SiemStatsResponse {
    pub total_sources: i64,
    pub active_sources: i64,
    pub total_logs_today: i64,
    pub total_logs_all: i64,
    pub logs_per_hour: f64,
    pub total_rules: i64,
    pub enabled_rules: i64,
    pub total_alerts: i64,
    pub open_alerts: i64,
    pub critical_alerts: i64,
    pub alerts_by_status: Vec<AlertStatusCount>,
    pub alerts_by_severity: Vec<AlertSeverityCount>,
    pub top_sources: Vec<TopSourceStats>,
    pub ingestion_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct AlertStatusCount {
    pub status: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct AlertSeverityCount {
    pub severity: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct TopSourceStats {
    pub id: String,
    pub name: String,
    pub log_count: i64,
    pub logs_per_hour: i64,
}

// =============================================================================
// Helper Functions
// =============================================================================

fn parse_log_format(s: &str) -> LogFormat {
    match s.to_lowercase().as_str() {
        "syslog_rfc3164" | "rfc3164" | "bsd" => LogFormat::SyslogRfc3164,
        "syslog_rfc5424" | "rfc5424" | "syslog" => LogFormat::SyslogRfc5424,
        "cef" => LogFormat::Cef,
        "leef" => LogFormat::Leef,
        "json" => LogFormat::Json,
        "windows_event" | "windows" | "evtx" => LogFormat::WindowsEvent,
        "raw" | "text" => LogFormat::Raw,
        "heroforge" | "internal" => LogFormat::HeroForge,
        _ => LogFormat::Raw,
    }
}

fn parse_transport_protocol(s: &str) -> TransportProtocol {
    match s.to_lowercase().as_str() {
        "udp" => TransportProtocol::Udp,
        "tcp" => TransportProtocol::Tcp,
        "tcp+tls" | "tls" => TransportProtocol::TcpTls,
        "http" => TransportProtocol::Http,
        "https" => TransportProtocol::Https,
        _ => TransportProtocol::Udp,
    }
}

fn parse_log_source_status(s: &str) -> LogSourceStatus {
    match s.to_lowercase().as_str() {
        "active" => LogSourceStatus::Active,
        "inactive" => LogSourceStatus::Inactive,
        "error" => LogSourceStatus::Error,
        _ => LogSourceStatus::Pending,
    }
}

fn parse_rule_type(s: &str) -> RuleType {
    match s.to_lowercase().as_str() {
        "pattern" => RuleType::Pattern,
        "regex" => RuleType::Regex,
        "threshold" => RuleType::Threshold,
        "correlation" => RuleType::Correlation,
        "anomaly" => RuleType::Anomaly,
        "machine_learning" | "ml" => RuleType::MachineLearning,
        "sigma" => RuleType::Sigma,
        "yara" => RuleType::Yara,
        _ => RuleType::Pattern,
    }
}

fn parse_rule_status(s: &str) -> RuleStatus {
    match s.to_lowercase().as_str() {
        "enabled" => RuleStatus::Enabled,
        "disabled" => RuleStatus::Disabled,
        "testing" => RuleStatus::Testing,
        _ => RuleStatus::Disabled,
    }
}

fn parse_severity(s: &str) -> SiemSeverity {
    match s.to_lowercase().as_str() {
        "debug" => SiemSeverity::Debug,
        "info" | "informational" => SiemSeverity::Info,
        "notice" => SiemSeverity::Notice,
        "warning" | "warn" => SiemSeverity::Warning,
        "error" | "err" => SiemSeverity::Error,
        "critical" | "crit" => SiemSeverity::Critical,
        "alert" => SiemSeverity::Alert,
        "emergency" | "emerg" => SiemSeverity::Emergency,
        _ => SiemSeverity::Info,
    }
}

fn parse_alert_status(s: &str) -> AlertStatus {
    match s.to_lowercase().as_str() {
        "new" => AlertStatus::New,
        "in_progress" | "inprogress" => AlertStatus::InProgress,
        "escalated" => AlertStatus::Escalated,
        "resolved" => AlertStatus::Resolved,
        "false_positive" | "falsepositive" => AlertStatus::FalsePositive,
        "ignored" => AlertStatus::Ignored,
        _ => AlertStatus::New,
    }
}

// =============================================================================
// Log Source Endpoints
// =============================================================================

/// List all log sources
pub async fn list_log_sources(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<LogSourceQuery>,
) -> Result<HttpResponse> {
    let mut sql = String::from(
        "SELECT id, name, description, source_type, host, format, protocol, port,
                status, last_seen, log_count, logs_per_hour, custom_patterns,
                field_mappings, tags, auto_enrich, retention_days, created_at,
                updated_at, created_by
         FROM siem_log_sources WHERE 1=1"
    );

    if let Some(ref status) = query.status {
        sql.push_str(&format!(" AND status = '{}'", status.replace('\'', "''")));
    }
    if let Some(ref source_type) = query.source_type {
        sql.push_str(&format!(" AND source_type = '{}'", source_type.replace('\'', "''")));
    }
    sql.push_str(" ORDER BY name");

    let rows: Vec<LogSourceRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch log sources: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch log sources")
        })?;

    let sources: Vec<LogSource> = rows
        .into_iter()
        .filter_map(|r| r.try_into().ok())
        .collect();

    Ok(HttpResponse::Ok().json(sources))
}

/// Create a new log source
pub async fn create_log_source(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateLogSourceRequest>,
) -> Result<HttpResponse> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let tags_json = serde_json::to_string(&request.tags.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO siem_log_sources (
            id, name, description, source_type, host, format, protocol, port,
            status, tags, auto_enrich, retention_days, created_at, updated_at, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.source_type)
    .bind(&request.host)
    .bind(&request.format)
    .bind(&request.protocol)
    .bind(request.port.map(|p| p as i32))
    .bind("pending")
    .bind(&tags_json)
    .bind(request.auto_enrich.unwrap_or(true))
    .bind(request.retention_days)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create log source: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create log source")
    })?;

    let source = LogSource {
        id,
        name: request.name.clone(),
        description: request.description.clone(),
        source_type: request.source_type.clone(),
        host: request.host.clone(),
        format: parse_log_format(&request.format),
        protocol: parse_transport_protocol(&request.protocol),
        port: request.port,
        status: LogSourceStatus::Pending,
        last_seen: None,
        log_count: 0,
        logs_per_hour: 0,
        custom_patterns: None,
        field_mappings: None,
        tags: request.tags.clone().unwrap_or_default(),
        auto_enrich: request.auto_enrich.unwrap_or(true),
        retention_days: request.retention_days,
        created_at: now,
        updated_at: now,
        created_by: Some(claims.sub.clone()),
    };

    Ok(HttpResponse::Created().json(source))
}

/// Get a single log source
pub async fn get_log_source(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let row: Option<LogSourceRow> = sqlx::query_as(
        "SELECT * FROM siem_log_sources WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch log source: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch log source")
    })?;

    match row {
        Some(r) => {
            let source: LogSource = r.try_into().map_err(|e| {
                log::error!("Failed to parse log source: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to parse log source")
            })?;
            Ok(HttpResponse::Ok().json(source))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Log source not found"
        }))),
    }
}

/// Update a log source
pub async fn update_log_source(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<UpdateLogSourceRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now();

    // Check if source exists
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM siem_log_sources WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Log source not found"
        })));
    }

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?"];
    let mut bindings: Vec<String> = vec![now.to_rfc3339()];

    if let Some(ref name) = request.name {
        updates.push("name = ?");
        bindings.push(name.clone());
    }
    if let Some(ref desc) = request.description {
        updates.push("description = ?");
        bindings.push(desc.clone());
    }
    if let Some(ref st) = request.source_type {
        updates.push("source_type = ?");
        bindings.push(st.clone());
    }
    if let Some(ref host) = request.host {
        updates.push("host = ?");
        bindings.push(host.clone());
    }
    if let Some(ref format) = request.format {
        updates.push("format = ?");
        bindings.push(format.clone());
    }
    if let Some(ref protocol) = request.protocol {
        updates.push("protocol = ?");
        bindings.push(protocol.clone());
    }
    if let Some(ref status) = request.status {
        updates.push("status = ?");
        bindings.push(status.clone());
    }
    if let Some(ref tags) = request.tags {
        updates.push("tags = ?");
        bindings.push(serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string()));
    }

    let sql = format!(
        "UPDATE siem_log_sources SET {} WHERE id = ?",
        updates.join(", ")
    );
    bindings.push(id.clone());

    let mut query = sqlx::query(&sql);
    for b in &bindings {
        query = query.bind(b);
    }

    // Handle port and optional fields separately
    if let Some(port) = request.port {
        sqlx::query("UPDATE siem_log_sources SET port = ? WHERE id = ?")
            .bind(port as i32)
            .bind(&id)
            .execute(pool.get_ref())
            .await
            .ok();
    }
    if let Some(auto_enrich) = request.auto_enrich {
        sqlx::query("UPDATE siem_log_sources SET auto_enrich = ? WHERE id = ?")
            .bind(auto_enrich)
            .bind(&id)
            .execute(pool.get_ref())
            .await
            .ok();
    }
    if let Some(retention) = request.retention_days {
        sqlx::query("UPDATE siem_log_sources SET retention_days = ? WHERE id = ?")
            .bind(retention)
            .bind(&id)
            .execute(pool.get_ref())
            .await
            .ok();
    }

    query.execute(pool.get_ref()).await.map_err(|e| {
        log::error!("Failed to update log source: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update log source")
    })?;

    // Fetch and return updated source
    let row: LogSourceRow = sqlx::query_as(
        "SELECT * FROM siem_log_sources WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch updated log source: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch updated log source")
    })?;

    let source: LogSource = row.try_into().map_err(|e| {
        log::error!("Failed to parse log source: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to parse log source")
    })?;

    Ok(HttpResponse::Ok().json(source))
}

/// Delete a log source
pub async fn delete_log_source(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM siem_log_sources WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete log source: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete log source")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Log source not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Log source deleted successfully"
    })))
}

// =============================================================================
// Log Entry Endpoints
// =============================================================================

/// Query log entries
pub async fn query_logs(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query_params: web::Query<LogSearchQuery>,
) -> Result<HttpResponse> {
    let limit = query_params.limit.unwrap_or(100).min(1000);
    let offset = query_params.offset.unwrap_or(0);

    let mut sql = String::from(
        "SELECT id, source_id, timestamp, received_at, severity, facility, format,
                source_ip, destination_ip, source_port, destination_port, protocol,
                hostname, application, pid, message_id, structured_data, message,
                raw, category, action, outcome, user, tags, alerted, alert_ids,
                partition_date
         FROM siem_log_entries WHERE 1=1"
    );

    if let Some(ref source_id) = query_params.source_id {
        sql.push_str(&format!(" AND source_id = '{}'", source_id.replace('\'', "''")));
    }
    if let Some(ref severity) = query_params.min_severity {
        let severities = get_severity_levels_above(severity);
        sql.push_str(&format!(" AND severity IN ({})", severities));
    }
    if let Some(ref source_ip) = query_params.source_ip {
        sql.push_str(&format!(" AND source_ip = '{}'", source_ip.replace('\'', "''")));
    }
    if let Some(ref dest_ip) = query_params.destination_ip {
        sql.push_str(&format!(" AND destination_ip = '{}'", dest_ip.replace('\'', "''")));
    }
    if let Some(ref hostname) = query_params.hostname {
        sql.push_str(&format!(" AND hostname LIKE '%{}%'", hostname.replace('\'', "''")));
    }
    if let Some(ref app) = query_params.application {
        sql.push_str(&format!(" AND application LIKE '%{}%'", app.replace('\'', "''")));
    }
    if let Some(ref user) = query_params.user {
        sql.push_str(&format!(" AND user = '{}'", user.replace('\'', "''")));
    }
    if let Some(ref start) = query_params.start_time {
        sql.push_str(&format!(" AND timestamp >= '{}'", start.replace('\'', "''")));
    }
    if let Some(ref end) = query_params.end_time {
        sql.push_str(&format!(" AND timestamp < '{}'", end.replace('\'', "''")));
    }
    if let Some(alerted) = query_params.alerted {
        sql.push_str(&format!(" AND alerted = {}", if alerted { 1 } else { 0 }));
    }
    if let Some(ref search) = query_params.query {
        let escaped = search.replace('\'', "''");
        sql.push_str(&format!(" AND (message LIKE '%{}%' OR raw LIKE '%{}%')", escaped, escaped));
    }

    // Count query
    let count_sql = sql.replace(
        "SELECT id, source_id, timestamp, received_at, severity, facility, format,\n                source_ip, destination_ip, source_port, destination_port, protocol,\n                hostname, application, pid, message_id, structured_data, message,\n                raw, category, action, outcome, user, tags, alerted, alert_ids,\n                partition_date\n         FROM siem_log_entries",
        "SELECT COUNT(*) FROM siem_log_entries"
    );

    sql.push_str(" ORDER BY timestamp DESC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    let start_time = std::time::Instant::now();

    let rows: Vec<LogEntryRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to query logs: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to query logs")
        })?;

    let total_count: (i64,) = sqlx::query_as(&count_sql)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to count logs: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to count logs")
        })?;

    let query_time_ms = start_time.elapsed().as_millis() as u64;

    let entries: Vec<LogEntryResponse> = rows.into_iter().map(|r| r.into()).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "entries": entries,
        "total_count": total_count.0,
        "query_time_ms": query_time_ms,
        "offset": offset,
        "limit": limit
    })))
}

/// Get a single log entry
pub async fn get_log_entry(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let row: Option<LogEntryRow> = sqlx::query_as(
        "SELECT * FROM siem_log_entries WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch log entry: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch log entry")
    })?;

    match row {
        Some(r) => {
            let entry: LogEntryResponse = r.into();
            Ok(HttpResponse::Ok().json(entry))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Log entry not found"
        }))),
    }
}

// =============================================================================
// Detection Rule Endpoints
// =============================================================================

/// List detection rules
pub async fn list_rules(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<RuleListQuery>,
) -> Result<HttpResponse> {
    let mut sql = String::from(
        "SELECT id, name, description, rule_type, severity, status, definition,
                source_ids, categories, mitre_tactics, mitre_techniques,
                false_positive_rate, trigger_count, last_triggered, tags,
                response_actions, time_window_seconds, threshold_count,
                group_by_fields, created_at, updated_at, created_by
         FROM siem_rules WHERE 1=1"
    );

    if let Some(ref status) = query.status {
        sql.push_str(&format!(" AND status = '{}'", status.replace('\'', "''")));
    }
    if let Some(ref rule_type) = query.rule_type {
        sql.push_str(&format!(" AND rule_type = '{}'", rule_type.replace('\'', "''")));
    }
    if let Some(ref severity) = query.severity {
        sql.push_str(&format!(" AND severity = '{}'", severity.replace('\'', "''")));
    }
    sql.push_str(" ORDER BY name");

    let rows: Vec<SiemRuleRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch rules: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch rules")
        })?;

    let rules: Vec<SiemRule> = rows
        .into_iter()
        .filter_map(|r| r.try_into().ok())
        .collect();

    Ok(HttpResponse::Ok().json(rules))
}

/// Create a detection rule
pub async fn create_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateRuleRequest>,
) -> Result<HttpResponse> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    let source_ids_json = serde_json::to_string(&request.source_ids.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let categories_json = serde_json::to_string(&request.categories.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let mitre_tactics_json = serde_json::to_string(&request.mitre_tactics.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let mitre_techniques_json = serde_json::to_string(&request.mitre_techniques.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let tags_json = serde_json::to_string(&request.tags.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let response_actions_json = serde_json::to_string(&request.response_actions.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let group_by_json = serde_json::to_string(&request.group_by_fields.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let definition_json = serde_json::to_string(&request.definition)
        .unwrap_or_else(|_| "{}".to_string());

    let status = request.status.clone().unwrap_or_else(|| "disabled".to_string());

    sqlx::query(
        r#"
        INSERT INTO siem_rules (
            id, name, description, rule_type, severity, status, definition,
            source_ids, categories, mitre_tactics, mitre_techniques, tags,
            response_actions, time_window_seconds, threshold_count, group_by_fields,
            created_at, updated_at, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.rule_type)
    .bind(&request.severity)
    .bind(&status)
    .bind(&definition_json)
    .bind(&source_ids_json)
    .bind(&categories_json)
    .bind(&mitre_tactics_json)
    .bind(&mitre_techniques_json)
    .bind(&tags_json)
    .bind(&response_actions_json)
    .bind(request.time_window_seconds)
    .bind(request.threshold_count)
    .bind(&group_by_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create rule")
    })?;

    let rule = SiemRule {
        id,
        name: request.name.clone(),
        description: request.description.clone(),
        rule_type: parse_rule_type(&request.rule_type),
        severity: parse_severity(&request.severity),
        status: parse_rule_status(&status),
        definition: request.definition.clone(),
        source_ids: request.source_ids.clone().unwrap_or_default(),
        categories: request.categories.clone().unwrap_or_default(),
        mitre_tactics: request.mitre_tactics.clone().unwrap_or_default(),
        mitre_techniques: request.mitre_techniques.clone().unwrap_or_default(),
        false_positive_rate: None,
        trigger_count: 0,
        last_triggered: None,
        tags: request.tags.clone().unwrap_or_default(),
        response_actions: request.response_actions.clone().unwrap_or_default(),
        time_window_seconds: request.time_window_seconds,
        threshold_count: request.threshold_count,
        group_by_fields: request.group_by_fields.clone().unwrap_or_default(),
        created_at: now,
        updated_at: now,
        created_by: Some(claims.sub.clone()),
    };

    Ok(HttpResponse::Created().json(rule))
}

/// Update a detection rule
pub async fn update_rule(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<UpdateRuleRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now();

    // Check if rule exists
    let exists: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM siem_rules WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found"
        })));
    }

    let mut updates = vec!["updated_at = ?"];
    let mut bindings: Vec<String> = vec![now.to_rfc3339()];

    if let Some(ref name) = request.name {
        updates.push("name = ?");
        bindings.push(name.clone());
    }
    if let Some(ref desc) = request.description {
        updates.push("description = ?");
        bindings.push(desc.clone());
    }
    if let Some(ref rule_type) = request.rule_type {
        updates.push("rule_type = ?");
        bindings.push(rule_type.clone());
    }
    if let Some(ref severity) = request.severity {
        updates.push("severity = ?");
        bindings.push(severity.clone());
    }
    if let Some(ref status) = request.status {
        updates.push("status = ?");
        bindings.push(status.clone());
    }
    if let Some(ref definition) = request.definition {
        updates.push("definition = ?");
        bindings.push(serde_json::to_string(definition).unwrap_or_else(|_| "{}".to_string()));
    }
    if let Some(ref source_ids) = request.source_ids {
        updates.push("source_ids = ?");
        bindings.push(serde_json::to_string(source_ids).unwrap_or_else(|_| "[]".to_string()));
    }
    if let Some(ref categories) = request.categories {
        updates.push("categories = ?");
        bindings.push(serde_json::to_string(categories).unwrap_or_else(|_| "[]".to_string()));
    }
    if let Some(ref tactics) = request.mitre_tactics {
        updates.push("mitre_tactics = ?");
        bindings.push(serde_json::to_string(tactics).unwrap_or_else(|_| "[]".to_string()));
    }
    if let Some(ref techniques) = request.mitre_techniques {
        updates.push("mitre_techniques = ?");
        bindings.push(serde_json::to_string(techniques).unwrap_or_else(|_| "[]".to_string()));
    }
    if let Some(ref tags) = request.tags {
        updates.push("tags = ?");
        bindings.push(serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string()));
    }
    if let Some(ref actions) = request.response_actions {
        updates.push("response_actions = ?");
        bindings.push(serde_json::to_string(actions).unwrap_or_else(|_| "[]".to_string()));
    }
    if let Some(ref group_by) = request.group_by_fields {
        updates.push("group_by_fields = ?");
        bindings.push(serde_json::to_string(group_by).unwrap_or_else(|_| "[]".to_string()));
    }

    let sql = format!(
        "UPDATE siem_rules SET {} WHERE id = ?",
        updates.join(", ")
    );
    bindings.push(id.clone());

    let mut query = sqlx::query(&sql);
    for b in &bindings {
        query = query.bind(b);
    }

    // Handle integer fields separately
    if let Some(time_window) = request.time_window_seconds {
        sqlx::query("UPDATE siem_rules SET time_window_seconds = ? WHERE id = ?")
            .bind(time_window)
            .bind(&id)
            .execute(pool.get_ref())
            .await
            .ok();
    }
    if let Some(threshold) = request.threshold_count {
        sqlx::query("UPDATE siem_rules SET threshold_count = ? WHERE id = ?")
            .bind(threshold)
            .bind(&id)
            .execute(pool.get_ref())
            .await
            .ok();
    }

    query.execute(pool.get_ref()).await.map_err(|e| {
        log::error!("Failed to update rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update rule")
    })?;

    // Fetch and return updated rule
    let row: SiemRuleRow = sqlx::query_as(
        "SELECT * FROM siem_rules WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch updated rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch updated rule")
    })?;

    let rule: SiemRule = row.try_into().map_err(|e| {
        log::error!("Failed to parse rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to parse rule")
    })?;

    Ok(HttpResponse::Ok().json(rule))
}

/// Delete a detection rule
pub async fn delete_rule(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM siem_rules WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete rule: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete rule")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Rule deleted successfully"
    })))
}

// =============================================================================
// Alert Endpoints
// =============================================================================

/// List alerts
pub async fn list_alerts(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<AlertListQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(100).min(500);

    let mut sql = String::from(
        "SELECT id, rule_id, rule_name, severity, status, title, description,
                log_entry_ids, event_count, source_ips, destination_ips, users,
                hosts, first_seen, last_seen, created_at, updated_at, assigned_to,
                resolved_by, resolved_at, resolution_notes, mitre_tactics,
                mitre_techniques, tags, context, related_alert_ids, external_ticket_id
         FROM siem_alerts WHERE 1=1"
    );

    if let Some(ref status) = query.status {
        sql.push_str(&format!(" AND status = '{}'", status.replace('\'', "''")));
    }
    if let Some(ref severity) = query.severity {
        sql.push_str(&format!(" AND severity = '{}'", severity.replace('\'', "''")));
    }
    if let Some(ref rule_id) = query.rule_id {
        sql.push_str(&format!(" AND rule_id = '{}'", rule_id.replace('\'', "''")));
    }
    if let Some(ref assigned_to) = query.assigned_to {
        sql.push_str(&format!(" AND assigned_to = '{}'", assigned_to.replace('\'', "''")));
    }

    sql.push_str(&format!(" ORDER BY created_at DESC LIMIT {}", limit));

    let rows: Vec<SiemAlertRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch alerts: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch alerts")
        })?;

    let alerts: Vec<SiemAlert> = rows
        .into_iter()
        .filter_map(|r| r.try_into().ok())
        .collect();

    Ok(HttpResponse::Ok().json(alerts))
}

/// Update alert status
pub async fn update_alert_status(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<UpdateAlertStatusRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now();

    let result = sqlx::query(
        "UPDATE siem_alerts SET status = ?, assigned_to = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&request.status)
    .bind(&request.assigned_to)
    .bind(now.to_rfc3339())
    .bind(&id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to update alert status: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update alert status")
    })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Alert not found"
        })));
    }

    // Fetch and return updated alert
    let row: SiemAlertRow = sqlx::query_as(
        "SELECT * FROM siem_alerts WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch updated alert: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch updated alert")
    })?;

    let alert: SiemAlert = row.try_into().map_err(|e| {
        log::error!("Failed to parse alert: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to parse alert")
    })?;

    Ok(HttpResponse::Ok().json(alert))
}

/// Resolve an alert
pub async fn resolve_alert(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<ResolveAlertRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now();
    let status = if request.is_false_positive.unwrap_or(false) {
        "false_positive"
    } else {
        "resolved"
    };

    let result = sqlx::query(
        r#"
        UPDATE siem_alerts SET
            status = ?,
            resolved_by = ?,
            resolved_at = ?,
            resolution_notes = ?,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(status)
    .bind(&claims.sub)
    .bind(now.to_rfc3339())
    .bind(&request.resolution_notes)
    .bind(now.to_rfc3339())
    .bind(&id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to resolve alert: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to resolve alert")
    })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Alert not found"
        })));
    }

    // Fetch and return updated alert
    let row: SiemAlertRow = sqlx::query_as(
        "SELECT * FROM siem_alerts WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch resolved alert: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch resolved alert")
    })?;

    let alert: SiemAlert = row.try_into().map_err(|e| {
        log::error!("Failed to parse alert: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to parse alert")
    })?;

    Ok(HttpResponse::Ok().json(alert))
}

// =============================================================================
// Statistics Endpoint
// =============================================================================

/// Get SIEM statistics
pub async fn get_siem_stats(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Total and active sources
    let total_sources: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM siem_log_sources")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let active_sources: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_log_sources WHERE status = 'active'"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Log counts
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let total_logs_today: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_log_entries WHERE partition_date = ?"
    )
    .bind(&today)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let total_logs_all: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM siem_log_entries")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    // Rule counts
    let total_rules: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM siem_rules")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let enabled_rules: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_rules WHERE status = 'enabled'"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Alert counts
    let total_alerts: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM siem_alerts")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    let open_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_alerts WHERE status IN ('new', 'in_progress', 'escalated')"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let critical_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_alerts WHERE severity IN ('critical', 'emergency', 'alert') AND status NOT IN ('resolved', 'false_positive', 'ignored')"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Alerts by status
    let status_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) FROM siem_alerts GROUP BY status"
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let alerts_by_status: Vec<AlertStatusCount> = status_rows
        .into_iter()
        .map(|(status, count)| AlertStatusCount { status, count })
        .collect();

    // Alerts by severity
    let severity_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, COUNT(*) FROM siem_alerts GROUP BY severity"
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let alerts_by_severity: Vec<AlertSeverityCount> = severity_rows
        .into_iter()
        .map(|(severity, count)| AlertSeverityCount { severity, count })
        .collect();

    // Top sources
    let top_source_rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, name, log_count, logs_per_hour FROM siem_log_sources ORDER BY log_count DESC LIMIT 10"
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let top_sources: Vec<TopSourceStats> = top_source_rows
        .into_iter()
        .map(|(id, name, log_count, logs_per_hour)| TopSourceStats {
            id,
            name,
            log_count,
            logs_per_hour,
        })
        .collect();

    // Calculate ingestion rate (logs per second in last hour)
    let hour_ago = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let logs_last_hour: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_log_entries WHERE received_at >= ?"
    )
    .bind(&hour_ago)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let ingestion_rate = logs_last_hour.0 as f64 / 3600.0;
    let logs_per_hour = logs_last_hour.0 as f64;

    let stats = SiemStatsResponse {
        total_sources: total_sources.0,
        active_sources: active_sources.0,
        total_logs_today: total_logs_today.0,
        total_logs_all: total_logs_all.0,
        logs_per_hour,
        total_rules: total_rules.0,
        enabled_rules: enabled_rules.0,
        total_alerts: total_alerts.0,
        open_alerts: open_alerts.0,
        critical_alerts: critical_alerts.0,
        alerts_by_status,
        alerts_by_severity,
        top_sources,
        ingestion_rate,
    };

    Ok(HttpResponse::Ok().json(stats))
}

// =============================================================================
// Route Configuration
// =============================================================================

/// Configure SIEM routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/siem")
            // Log sources
            .route("/sources", web::get().to(list_log_sources))
            .route("/sources", web::post().to(create_log_source))
            .route("/sources/{id}", web::get().to(get_log_source))
            .route("/sources/{id}", web::put().to(update_log_source))
            .route("/sources/{id}", web::delete().to(delete_log_source))
            // Log entries
            .route("/logs", web::get().to(query_logs))
            .route("/logs/{id}", web::get().to(get_log_entry))
            // Detection rules
            .route("/rules", web::get().to(list_rules))
            .route("/rules", web::post().to(create_rule))
            .route("/rules/{id}", web::put().to(update_rule))
            .route("/rules/{id}", web::delete().to(delete_rule))
            // Alerts
            .route("/alerts", web::get().to(list_alerts))
            .route("/alerts/{id}/status", web::put().to(update_alert_status))
            .route("/alerts/{id}/resolve", web::post().to(resolve_alert))
            // Statistics
            .route("/stats", web::get().to(get_siem_stats))
    );
}

// =============================================================================
// Database Row Types
// =============================================================================

fn get_severity_levels_above(min: &str) -> String {
    let levels: Vec<&str> = match min.to_lowercase().as_str() {
        "debug" => vec!["'debug'", "'info'", "'notice'", "'warning'", "'error'", "'critical'", "'alert'", "'emergency'"],
        "info" => vec!["'info'", "'notice'", "'warning'", "'error'", "'critical'", "'alert'", "'emergency'"],
        "notice" => vec!["'notice'", "'warning'", "'error'", "'critical'", "'alert'", "'emergency'"],
        "warning" => vec!["'warning'", "'error'", "'critical'", "'alert'", "'emergency'"],
        "error" => vec!["'error'", "'critical'", "'alert'", "'emergency'"],
        "critical" => vec!["'critical'", "'alert'", "'emergency'"],
        "alert" => vec!["'alert'", "'emergency'"],
        "emergency" => vec!["'emergency'"],
        _ => vec!["'debug'", "'info'", "'notice'", "'warning'", "'error'", "'critical'", "'alert'", "'emergency'"],
    };
    levels.join(",")
}

#[derive(sqlx::FromRow)]
struct LogSourceRow {
    id: String,
    name: String,
    description: Option<String>,
    source_type: String,
    host: Option<String>,
    format: String,
    protocol: String,
    port: Option<i32>,
    status: String,
    last_seen: Option<String>,
    log_count: i64,
    logs_per_hour: i64,
    custom_patterns: Option<String>,
    field_mappings: Option<String>,
    tags: String,
    auto_enrich: bool,
    retention_days: Option<i32>,
    created_at: String,
    updated_at: String,
    created_by: Option<String>,
}

impl TryFrom<LogSourceRow> for LogSource {
    type Error = anyhow::Error;

    fn try_from(row: LogSourceRow) -> std::result::Result<Self, Self::Error> {
        Ok(LogSource {
            id: row.id,
            name: row.name,
            description: row.description,
            source_type: row.source_type,
            host: row.host,
            format: parse_log_format(&row.format),
            protocol: parse_transport_protocol(&row.protocol),
            port: row.port.map(|p| p as u16),
            status: parse_log_source_status(&row.status),
            last_seen: row.last_seen.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            log_count: row.log_count,
            logs_per_hour: row.logs_per_hour,
            custom_patterns: row.custom_patterns.and_then(|s| serde_json::from_str(&s).ok()),
            field_mappings: row.field_mappings.and_then(|s| serde_json::from_str(&s).ok()),
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            auto_enrich: row.auto_enrich,
            retention_days: row.retention_days,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            created_by: row.created_by,
        })
    }
}

#[derive(sqlx::FromRow)]
struct LogEntryRow {
    id: String,
    source_id: String,
    timestamp: String,
    received_at: String,
    severity: String,
    facility: Option<i32>,
    format: String,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    source_port: Option<i32>,
    destination_port: Option<i32>,
    protocol: Option<String>,
    hostname: Option<String>,
    application: Option<String>,
    pid: Option<i64>,
    message_id: Option<String>,
    structured_data: String,
    message: String,
    raw: String,
    category: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    user: Option<String>,
    tags: String,
    alerted: bool,
    alert_ids: String,
    partition_date: String,
}

/// Simplified log entry response for API
#[derive(Debug, Serialize)]
struct LogEntryResponse {
    id: String,
    source_id: String,
    timestamp: String,
    received_at: String,
    severity: String,
    facility: Option<i32>,
    format: String,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    source_port: Option<i32>,
    destination_port: Option<i32>,
    protocol: Option<String>,
    hostname: Option<String>,
    application: Option<String>,
    pid: Option<i64>,
    message_id: Option<String>,
    structured_data: serde_json::Value,
    message: String,
    raw: String,
    category: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    user: Option<String>,
    tags: Vec<String>,
    alerted: bool,
    alert_ids: Vec<String>,
    partition_date: String,
}

impl From<LogEntryRow> for LogEntryResponse {
    fn from(row: LogEntryRow) -> Self {
        LogEntryResponse {
            id: row.id,
            source_id: row.source_id,
            timestamp: row.timestamp,
            received_at: row.received_at,
            severity: row.severity,
            facility: row.facility,
            format: row.format,
            source_ip: row.source_ip,
            destination_ip: row.destination_ip,
            source_port: row.source_port,
            destination_port: row.destination_port,
            protocol: row.protocol,
            hostname: row.hostname,
            application: row.application,
            pid: row.pid,
            message_id: row.message_id,
            structured_data: serde_json::from_str(&row.structured_data).unwrap_or(serde_json::json!({})),
            message: row.message,
            raw: row.raw,
            category: row.category,
            action: row.action,
            outcome: row.outcome,
            user: row.user,
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            alerted: row.alerted,
            alert_ids: serde_json::from_str(&row.alert_ids).unwrap_or_default(),
            partition_date: row.partition_date,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SiemRuleRow {
    id: String,
    name: String,
    description: Option<String>,
    rule_type: String,
    severity: String,
    status: String,
    definition: String,
    source_ids: String,
    categories: String,
    mitre_tactics: String,
    mitre_techniques: String,
    false_positive_rate: Option<f32>,
    trigger_count: i64,
    last_triggered: Option<String>,
    tags: String,
    response_actions: String,
    time_window_seconds: Option<i64>,
    threshold_count: Option<i64>,
    group_by_fields: String,
    created_at: String,
    updated_at: String,
    created_by: Option<String>,
}

impl TryFrom<SiemRuleRow> for SiemRule {
    type Error = anyhow::Error;

    fn try_from(row: SiemRuleRow) -> std::result::Result<Self, Self::Error> {
        Ok(SiemRule {
            id: row.id,
            name: row.name,
            description: row.description,
            rule_type: parse_rule_type(&row.rule_type),
            severity: parse_severity(&row.severity),
            status: parse_rule_status(&row.status),
            definition: serde_json::from_str(&row.definition).unwrap_or(serde_json::json!({})),
            source_ids: serde_json::from_str(&row.source_ids).unwrap_or_default(),
            categories: serde_json::from_str(&row.categories).unwrap_or_default(),
            mitre_tactics: serde_json::from_str(&row.mitre_tactics).unwrap_or_default(),
            mitre_techniques: serde_json::from_str(&row.mitre_techniques).unwrap_or_default(),
            false_positive_rate: row.false_positive_rate,
            trigger_count: row.trigger_count,
            last_triggered: row.last_triggered.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            response_actions: serde_json::from_str(&row.response_actions).unwrap_or_default(),
            time_window_seconds: row.time_window_seconds,
            threshold_count: row.threshold_count,
            group_by_fields: serde_json::from_str(&row.group_by_fields).unwrap_or_default(),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            created_by: row.created_by,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SiemAlertRow {
    id: String,
    rule_id: String,
    rule_name: String,
    severity: String,
    status: String,
    title: String,
    description: Option<String>,
    log_entry_ids: String,
    event_count: i64,
    source_ips: String,
    destination_ips: String,
    users: String,
    hosts: String,
    first_seen: String,
    last_seen: String,
    created_at: String,
    updated_at: String,
    assigned_to: Option<String>,
    resolved_by: Option<String>,
    resolved_at: Option<String>,
    resolution_notes: Option<String>,
    mitre_tactics: String,
    mitre_techniques: String,
    tags: String,
    context: String,
    related_alert_ids: String,
    external_ticket_id: Option<String>,
}

impl TryFrom<SiemAlertRow> for SiemAlert {
    type Error = anyhow::Error;

    fn try_from(row: SiemAlertRow) -> std::result::Result<Self, Self::Error> {
        Ok(SiemAlert {
            id: row.id,
            rule_id: row.rule_id,
            rule_name: row.rule_name,
            severity: parse_severity(&row.severity),
            status: parse_alert_status(&row.status),
            title: row.title,
            description: row.description,
            log_entry_ids: serde_json::from_str(&row.log_entry_ids).unwrap_or_default(),
            event_count: row.event_count,
            source_ips: serde_json::from_str(&row.source_ips).unwrap_or_default(),
            destination_ips: serde_json::from_str(&row.destination_ips).unwrap_or_default(),
            users: serde_json::from_str(&row.users).unwrap_or_default(),
            hosts: serde_json::from_str(&row.hosts).unwrap_or_default(),
            first_seen: DateTime::parse_from_rfc3339(&row.first_seen)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen: DateTime::parse_from_rfc3339(&row.last_seen)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            assigned_to: row.assigned_to,
            resolved_by: row.resolved_by,
            resolved_at: row.resolved_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            resolution_notes: row.resolution_notes,
            mitre_tactics: serde_json::from_str(&row.mitre_tactics).unwrap_or_default(),
            mitre_techniques: serde_json::from_str(&row.mitre_techniques).unwrap_or_default(),
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            context: serde_json::from_str(&row.context).unwrap_or(serde_json::json!({})),
            related_alert_ids: serde_json::from_str(&row.related_alert_ids).unwrap_or_default(),
            external_ticket_id: row.external_ticket_id,
        })
    }
}
