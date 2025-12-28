//! SIEM (Security Information and Event Management) API endpoints
//!
//! This module provides full SIEM capabilities including:
//! - Log source management (CRUD operations)
//! - Log entry querying and retrieval
//! - Detection rule management (including Sigma rules)
//! - Correlation rules for advanced threat detection
//! - Alert management and resolution (with deduplication)
//! - SIEM dashboards and saved searches
//! - SIEM statistics

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::siem::{
    AlertStatus, LogFormat, LogSource, LogSourceStatus, RuleStatus, RuleType,
    SiemAlert, SiemRule, SiemSeverity, TransportProtocol,
    sigma::{SigmaParser, CompiledSigmaRule, validate_sigma_rule, get_builtin_rules, SigmaSeverity},
    sigma_converter::{SigmaBackend, SigmaConverter, ConversionResult, FieldMappings, convert_to_all_backends},
    correlation::{CorrelationRule, CorrelationRuleType, CorrelationConditions, get_builtin_correlation_rules},
    dashboard::{SavedSearch, SiemDashboard, DashboardWidget, WidgetType, WidgetPosition, WidgetConfig, AlertWorkflow, TimeRange, get_default_dashboard},
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

// =============================================================================
// Sigma Rule Request/Response Types
// =============================================================================

/// Request to create a Sigma rule
#[derive(Debug, Deserialize)]
pub struct CreateSigmaRuleRequest {
    pub yaml_content: String,
    pub enabled: Option<bool>,
}

/// Request to validate a Sigma rule
#[derive(Debug, Deserialize)]
pub struct ValidateSigmaRuleRequest {
    pub yaml_content: String,
}

/// Request to test a Sigma rule
#[derive(Debug, Deserialize)]
pub struct TestSigmaRuleRequest {
    pub yaml_content: String,
    pub sample_logs: Vec<serde_json::Value>,
}

/// Sigma rule response
#[derive(Debug, Serialize)]
pub struct SigmaRuleResponse {
    pub id: String,
    pub name: String,
    pub level: String,
    pub status: String,
    pub enabled: bool,
    pub logsource_product: Option<String>,
    pub logsource_service: Option<String>,
    pub logsource_category: Option<String>,
    pub tags: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub author: Option<String>,
    pub trigger_count: i64,
    pub last_triggered: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Sigma validation response
#[derive(Debug, Serialize)]
pub struct SigmaValidationResponse {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Sigma test result response
#[derive(Debug, Serialize)]
pub struct SigmaTestResponse {
    pub rule_id: String,
    pub rule_title: String,
    pub total_logs_tested: usize,
    pub match_count: usize,
    pub matches: Vec<SigmaTestMatch>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaTestMatch {
    pub log_index: usize,
    pub message: String,
}

// =============================================================================
// Sigma Backend Conversion Types (Sprint 2)
// =============================================================================

/// Request to convert a Sigma rule to a specific backend
#[derive(Debug, Deserialize)]
pub struct ConvertSigmaRuleRequest {
    pub yaml_content: String,
    pub backend: String,
    #[serde(default)]
    pub field_mappings: Option<std::collections::HashMap<String, String>>,
}

/// Request to convert a Sigma rule to all backends
#[derive(Debug, Deserialize)]
pub struct ConvertSigmaRuleAllRequest {
    pub yaml_content: String,
    #[serde(default)]
    pub field_mappings: Option<std::collections::HashMap<String, String>>,
}

/// Response for single backend conversion
#[derive(Debug, Serialize)]
pub struct SigmaConversionResponse {
    pub backend: String,
    pub query: String,
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub field_mappings_used: std::collections::HashMap<String, String>,
    pub unsupported_features: Vec<String>,
}

/// Response for all backends conversion
#[derive(Debug, Serialize)]
pub struct SigmaConversionAllResponse {
    pub rule_id: String,
    pub rule_title: String,
    pub conversions: Vec<SigmaConversionResponse>,
}

/// Request to test a Sigma rule with storage
#[derive(Debug, Deserialize)]
pub struct TestSigmaRuleWithStorageRequest {
    pub sample_logs: Vec<serde_json::Value>,
    #[serde(default)]
    pub store_result: bool,
    #[serde(default)]
    pub description: Option<String>,
}

/// Response for enhanced Sigma rule testing
#[derive(Debug, Serialize)]
pub struct SigmaRuleTestResultResponse {
    pub id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub total_logs_tested: usize,
    pub match_count: usize,
    pub matches: Vec<SigmaTestMatch>,
    pub false_positive_count: i64,
    pub true_positive_count: i64,
    pub test_duration_ms: i64,
    pub tested_at: String,
    pub description: Option<String>,
}

/// Request to mark test result as TP/FP
#[derive(Debug, Deserialize)]
pub struct UpdateTestResultRequest {
    pub result_type: String, // "true_positive" or "false_positive"
    pub notes: Option<String>,
}

/// ATT&CK technique coverage entry
#[derive(Debug, Serialize)]
pub struct TechniqueCoverageEntry {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub rule_count: i64,
    pub rules: Vec<CoveringRuleInfo>,
}

/// Info about a rule covering a technique
#[derive(Debug, Serialize)]
pub struct CoveringRuleInfo {
    pub rule_id: String,
    pub rule_name: String,
    pub level: String,
}

/// ATT&CK coverage response
#[derive(Debug, Serialize)]
pub struct AttackCoverageResponse {
    pub total_techniques_covered: usize,
    pub total_rules: usize,
    pub coverage_by_tactic: std::collections::HashMap<String, TacticCoverage>,
    pub techniques: Vec<TechniqueCoverageEntry>,
}

/// Coverage stats for a single tactic
#[derive(Debug, Serialize)]
pub struct TacticCoverage {
    pub tactic_name: String,
    pub techniques_covered: usize,
    pub total_rules: usize,
}

/// Rule tuning recommendation
#[derive(Debug, Serialize)]
pub struct RuleTuningRecommendation {
    pub rule_id: String,
    pub rule_name: String,
    pub recommendation_type: String, // "disable", "tune_threshold", "add_exclusion", "review"
    pub reason: String,
    pub false_positive_rate: f64,
    pub suggested_actions: Vec<String>,
}

/// Rule tuning recommendations response
#[derive(Debug, Serialize)]
pub struct TuningRecommendationsResponse {
    pub recommendations: Vec<RuleTuningRecommendation>,
    pub total_rules_analyzed: usize,
    pub rules_needing_tuning: usize,
}

/// Query parameters for listing test results
#[derive(Debug, Deserialize)]
pub struct TestResultsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Sigma rule chain definition
#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaRuleChain {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub rule_ids: Vec<String>,
    pub chain_logic: String, // "sequence" or "parallel"
    pub time_window_secs: i64,
    pub enabled: bool,
    pub created_at: String,
    pub created_by: String,
}

/// Request to create a rule chain
#[derive(Debug, Deserialize)]
pub struct CreateRuleChainRequest {
    pub name: String,
    pub description: Option<String>,
    pub rule_ids: Vec<String>,
    pub chain_logic: String,
    pub time_window_secs: i64,
    pub enabled: Option<bool>,
}

// =============================================================================
// Correlation Rule Request/Response Types
// =============================================================================

/// Request to create a correlation rule
#[derive(Debug, Deserialize)]
pub struct CreateCorrelationRuleRequest {
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub time_window_secs: i64,
    pub threshold: Option<i64>,
    pub group_by: Option<Vec<String>>,
    pub severity: Option<String>,
    pub enabled: Option<bool>,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
}

/// Request to update a correlation rule
#[derive(Debug, Deserialize)]
pub struct UpdateCorrelationRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rule_type: Option<String>,
    pub conditions: Option<serde_json::Value>,
    pub time_window_secs: Option<i64>,
    pub threshold: Option<i64>,
    pub group_by: Option<Vec<String>>,
    pub severity: Option<String>,
    pub enabled: Option<bool>,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
}

/// Query parameters for listing correlation rules
#[derive(Debug, Deserialize)]
pub struct CorrelationRuleListQuery {
    pub enabled: Option<bool>,
    pub rule_type: Option<String>,
}

// =============================================================================
// Saved Search Request/Response Types
// =============================================================================

/// Request to create a saved search
#[derive(Debug, Deserialize)]
pub struct CreateSavedSearchRequest {
    pub name: String,
    pub description: Option<String>,
    pub query: String,
    pub schedule_cron: Option<String>,
    pub schedule_enabled: Option<bool>,
    pub alert_threshold: Option<i64>,
    pub alert_severity: Option<String>,
    pub email_recipients: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

/// Request to update a saved search
#[derive(Debug, Deserialize)]
pub struct UpdateSavedSearchRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub query: Option<String>,
    pub schedule_cron: Option<String>,
    pub schedule_enabled: Option<bool>,
    pub alert_threshold: Option<i64>,
    pub alert_severity: Option<String>,
    pub email_recipients: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

// =============================================================================
// Dashboard Request/Response Types
// =============================================================================

/// Request to create a dashboard
#[derive(Debug, Deserialize)]
pub struct CreateDashboardRequest {
    pub name: String,
    pub description: Option<String>,
    pub default_time_range: Option<String>,
    pub auto_refresh: Option<i32>,
    pub is_public: Option<bool>,
}

/// Request to update a dashboard
#[derive(Debug, Deserialize)]
pub struct UpdateDashboardRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub default_time_range: Option<String>,
    pub auto_refresh: Option<i32>,
    pub is_public: Option<bool>,
}

/// Request to create/update a dashboard widget
#[derive(Debug, Deserialize)]
pub struct WidgetRequest {
    pub widget_type: String,
    pub position_x: Option<i32>,
    pub position_y: Option<i32>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub config: serde_json::Value,
}

// =============================================================================
// Alert Enhancement Request/Response Types
// =============================================================================

/// Request to update alert status with workflow validation
#[derive(Debug, Deserialize)]
pub struct UpdateAlertStatusWorkflowRequest {
    pub status: String,
    pub assigned_to: Option<String>,
    pub notes: Option<String>,
}

/// Deduplicated alert group response
#[derive(Debug, Serialize)]
pub struct AlertGroupResponse {
    pub group_id: String,
    pub primary_alert: SiemAlert,
    pub alert_count: i64,
    pub alert_ids: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub suppressed: bool,
}

/// Alert status history entry
#[derive(Debug, Serialize)]
pub struct AlertStatusHistoryEntry {
    pub id: String,
    pub alert_id: String,
    pub old_status: Option<String>,
    pub new_status: String,
    pub changed_by: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
}

/// Dashboard overview response
#[derive(Debug, Serialize)]
pub struct DashboardOverviewResponse {
    pub total_alerts: i64,
    pub open_alerts: i64,
    pub critical_alerts: i64,
    pub high_alerts: i64,
    pub medium_alerts: i64,
    pub low_alerts: i64,
    pub alerts_by_status: Vec<AlertStatusCount>,
    pub top_rules: Vec<TopRuleCount>,
    pub top_sources: Vec<TopSourceStats>,
    pub alert_trend: Vec<TrendPoint>,
    pub active_correlation_rules: i64,
    pub active_sigma_rules: i64,
}

#[derive(Debug, Serialize)]
pub struct TopRuleCount {
    pub rule_id: String,
    pub rule_name: String,
    pub alert_count: i64,
}

#[derive(Debug, Serialize)]
pub struct TrendPoint {
    pub timestamp: String,
    pub value: i64,
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
// Sigma Rule Endpoints
// =============================================================================

/// List Sigma rules
pub async fn list_sigma_rules(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows: Vec<SigmaRuleRow> = sqlx::query_as(
        "SELECT * FROM sigma_rules ORDER BY name"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch Sigma rules: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch Sigma rules")
    })?;

    let rules: Vec<SigmaRuleResponse> = rows.into_iter().map(|r| r.into()).collect();
    Ok(HttpResponse::Ok().json(rules))
}

/// Create a Sigma rule
pub async fn create_sigma_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateSigmaRuleRequest>,
) -> Result<HttpResponse> {
    // Parse and validate the YAML
    let parsed = SigmaParser::parse(&request.yaml_content).map_err(|e| {
        log::warn!("Invalid Sigma rule YAML: {}", e);
        actix_web::error::ErrorBadRequest(format!("Invalid Sigma rule: {}", e))
    })?;

    // Try to compile to validate
    let _compiled = CompiledSigmaRule::compile(parsed.clone()).map_err(|e| {
        log::warn!("Failed to compile Sigma rule: {}", e);
        actix_web::error::ErrorBadRequest(format!("Failed to compile rule: {}", e))
    })?;

    let id = parsed.id.clone();
    let now = Utc::now();
    let enabled = request.enabled.unwrap_or(false);
    let tags_json = serde_json::to_string(&parsed.tags).unwrap_or_else(|_| "[]".to_string());
    let mitre_tactics: Vec<String> = parsed.tags.iter()
        .filter(|t| t.starts_with("attack.") && !t.contains('.', ))
        .cloned()
        .collect();
    let mitre_techniques: Vec<String> = parsed.tags.iter()
        .filter(|t| t.starts_with("attack.t"))
        .cloned()
        .collect();
    let tactics_json = serde_json::to_string(&mitre_tactics).unwrap_or_else(|_| "[]".to_string());
    let techniques_json = serde_json::to_string(&mitre_techniques).unwrap_or_else(|_| "[]".to_string());
    let refs_json = serde_json::to_string(&parsed.references).unwrap_or_else(|_| "[]".to_string());
    let fps_json = serde_json::to_string(&parsed.falsepositives).unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO sigma_rules (
            id, name, yaml_content, enabled, level, status,
            logsource_product, logsource_service, logsource_category,
            tags, mitre_tactics, mitre_techniques, author,
            references_json, false_positives, user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&parsed.title)
    .bind(&request.yaml_content)
    .bind(enabled)
    .bind(parsed.level.as_str())
    .bind(parsed.status.as_str())
    .bind(&parsed.logsource.product)
    .bind(&parsed.logsource.service)
    .bind(&parsed.logsource.category)
    .bind(&tags_json)
    .bind(&tactics_json)
    .bind(&techniques_json)
    .bind(&parsed.author)
    .bind(&refs_json)
    .bind(&fps_json)
    .bind(&claims.sub)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create Sigma rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create Sigma rule")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": parsed.title,
        "message": "Sigma rule created successfully"
    })))
}

/// Get a Sigma rule by ID
pub async fn get_sigma_rule(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let row: Option<SigmaRuleRow> = sqlx::query_as(
        "SELECT * FROM sigma_rules WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch Sigma rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch Sigma rule")
    })?;

    match row {
        Some(r) => {
            let response: SigmaRuleResponse = r.into();
            Ok(HttpResponse::Ok().json(response))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Sigma rule not found"
        }))),
    }
}

/// Delete a Sigma rule
pub async fn delete_sigma_rule(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM sigma_rules WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete Sigma rule: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete Sigma rule")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Sigma rule not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Sigma rule deleted successfully"
    })))
}

/// Validate a Sigma rule without saving
pub async fn validate_sigma(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<ValidateSigmaRuleRequest>,
) -> Result<HttpResponse> {
    let result = validate_sigma_rule(&request.yaml_content);

    Ok(HttpResponse::Ok().json(SigmaValidationResponse {
        is_valid: result.is_valid,
        errors: result.errors,
        warnings: result.warnings,
    }))
}

/// Test a Sigma rule against sample logs
pub async fn test_sigma_rule(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<TestSigmaRuleRequest>,
) -> Result<HttpResponse> {
    // Parse and compile the rule
    let parsed = SigmaParser::parse(&request.yaml_content).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Invalid Sigma rule: {}", e))
    })?;

    let compiled = CompiledSigmaRule::compile(parsed.clone()).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to compile rule: {}", e))
    })?;

    // Convert sample logs to LogEntry format and test
    let mut matches = Vec::new();
    for (index, log) in request.sample_logs.iter().enumerate() {
        // Create a simple log entry from the sample
        let message = log.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut entry = crate::siem::LogEntry::new(
            "test".to_string(),
            message.clone(),
            serde_json::to_string(log).unwrap_or_default(),
        );

        // Copy structured data from sample
        if let Some(obj) = log.as_object() {
            for (k, v) in obj {
                entry.structured_data.insert(k.clone(), v.clone());
            }
        }

        if compiled.evaluate(&entry) {
            matches.push(SigmaTestMatch {
                log_index: index,
                message,
            });
        }
    }

    Ok(HttpResponse::Ok().json(SigmaTestResponse {
        rule_id: parsed.id,
        rule_title: parsed.title,
        total_logs_tested: request.sample_logs.len(),
        match_count: matches.len(),
        matches,
    }))
}

/// Get built-in Sigma rules
pub async fn get_builtin_sigma_rules(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rules = get_builtin_rules();
    Ok(HttpResponse::Ok().json(rules))
}

// =============================================================================
// Sigma Backend Conversion Endpoints (Sprint 2)
// =============================================================================

/// Convert a Sigma rule to a specific backend query language
pub async fn convert_sigma_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<ConvertSigmaRuleRequest>,
) -> Result<HttpResponse> {
    // Parse the Sigma rule
    let parsed = SigmaParser::parse(&request.yaml_content).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Invalid Sigma rule: {}", e))
    })?;

    let compiled = CompiledSigmaRule::compile(parsed.clone()).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to compile rule: {}", e))
    })?;

    // Parse the backend
    let backend: SigmaBackend = request.backend.parse().map_err(|e: anyhow::Error| {
        actix_web::error::ErrorBadRequest(format!("Invalid backend: {}", e))
    })?;

    // Build field mappings
    let mut mappings = FieldMappings::default();
    if let Some(ref custom_mappings) = request.field_mappings {
        for (k, v) in custom_mappings {
            mappings.field_map.insert(k.clone(), v.clone());
        }
    }

    // Convert
    let converter = SigmaConverter::new(backend).with_field_mappings(mappings);
    let result = converter.convert(&parsed, &compiled);

    // Store conversion in database
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    let _ = sqlx::query(
        r#"
        INSERT OR REPLACE INTO sigma_conversions (id, sigma_rule_id, backend, converted_query, field_mappings, conversion_errors, conversion_warnings, is_valid, last_converted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&parsed.id)
    .bind(backend.to_string())
    .bind(&result.query)
    .bind(serde_json::to_string(&result.field_mappings_used).unwrap_or_default())
    .bind(serde_json::to_string(&result.errors).unwrap_or_default())
    .bind(serde_json::to_string(&result.warnings).unwrap_or_default())
    .bind(result.is_valid)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    Ok(HttpResponse::Ok().json(SigmaConversionResponse {
        backend: backend.to_string(),
        query: result.query,
        is_valid: result.is_valid,
        errors: result.errors,
        warnings: result.warnings,
        field_mappings_used: result.field_mappings_used,
        unsupported_features: result.unsupported_features,
    }))
}

/// Convert a Sigma rule to all supported backends
pub async fn convert_sigma_rule_all(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<ConvertSigmaRuleAllRequest>,
) -> Result<HttpResponse> {
    // Parse the Sigma rule
    let parsed = SigmaParser::parse(&request.yaml_content).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Invalid Sigma rule: {}", e))
    })?;

    let compiled = CompiledSigmaRule::compile(parsed.clone()).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to compile rule: {}", e))
    })?;

    // Note: Custom field mappings are ignored for batch conversion
    // since convert_to_all_backends uses default mappings

    // Convert to all backends
    let results = convert_to_all_backends(&parsed, &compiled);

    // Store conversions in database
    let now = Utc::now();
    for result in &results {
        let id = uuid::Uuid::new_v4().to_string();
        let _ = sqlx::query(
            r#"
            INSERT OR REPLACE INTO sigma_conversions (id, sigma_rule_id, backend, converted_query, field_mappings, conversion_errors, conversion_warnings, is_valid, last_converted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&parsed.id)
        .bind(result.backend.to_string())
        .bind(&result.query)
        .bind(serde_json::to_string(&result.field_mappings_used).unwrap_or_default())
        .bind(serde_json::to_string(&result.errors).unwrap_or_default())
        .bind(serde_json::to_string(&result.warnings).unwrap_or_default())
        .bind(result.is_valid)
        .bind(now.to_rfc3339())
        .execute(pool.get_ref())
        .await;
    }

    let conversions: Vec<SigmaConversionResponse> = results.into_iter().map(|r| {
        SigmaConversionResponse {
            backend: r.backend.to_string(),
            query: r.query,
            is_valid: r.is_valid,
            errors: r.errors,
            warnings: r.warnings,
            field_mappings_used: r.field_mappings_used,
            unsupported_features: r.unsupported_features,
        }
    }).collect();

    Ok(HttpResponse::Ok().json(SigmaConversionAllResponse {
        rule_id: parsed.id,
        rule_title: parsed.title,
        conversions,
    }))
}

/// Test a Sigma rule with result storage
pub async fn test_sigma_rule_with_storage(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<TestSigmaRuleWithStorageRequest>,
) -> Result<HttpResponse> {
    let rule_id = path.into_inner();
    let start_time = std::time::Instant::now();

    // Get the rule from database
    let row: Option<SigmaRuleRow> = sqlx::query_as(
        "SELECT * FROM sigma_rules WHERE id = ?"
    )
    .bind(&rule_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch Sigma rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rule")
    })?;

    let row = row.ok_or_else(|| actix_web::error::ErrorNotFound("Sigma rule not found"))?;

    // Parse and compile the rule
    let parsed = SigmaParser::parse(&row.yaml_content).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Invalid Sigma rule: {}", e))
    })?;

    let compiled = CompiledSigmaRule::compile(parsed.clone()).map_err(|e| {
        actix_web::error::ErrorBadRequest(format!("Failed to compile rule: {}", e))
    })?;

    // Test against sample logs
    let mut matches = Vec::new();
    for (index, log) in request.sample_logs.iter().enumerate() {
        let message = log.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut entry = crate::siem::LogEntry::new(
            "test".to_string(),
            message.clone(),
            serde_json::to_string(log).unwrap_or_default(),
        );

        if let Some(obj) = log.as_object() {
            for (k, v) in obj {
                entry.structured_data.insert(k.clone(), v.clone());
            }
        }

        if compiled.evaluate(&entry) {
            matches.push(SigmaTestMatch {
                log_index: index,
                message,
            });
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as i64;
    let now = Utc::now();
    let test_id = uuid::Uuid::new_v4().to_string();

    // Store result if requested
    if request.store_result {
        let sample_logs_json = serde_json::to_string(&request.sample_logs).unwrap_or_default();
        let matches_json = serde_json::to_string(&matches).unwrap_or_default();

        let test_name = request.description.clone().unwrap_or_else(|| format!("Test at {}", now.format("%Y-%m-%d %H:%M")));
        sqlx::query(
            r#"
            INSERT INTO sigma_rule_tests (
                id, sigma_rule_id, test_name, test_type, sample_logs,
                expected_matches, actual_matches, match_details, execution_time_ms,
                test_status, tested_by, tested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&test_id)
        .bind(&rule_id)
        .bind(&test_name)
        .bind("positive") // test_type
        .bind(&sample_logs_json)
        .bind(matches.len() as i64) // expected_matches
        .bind(matches.len() as i64) // actual_matches
        .bind(&matches_json) // match_details
        .bind(duration_ms)
        .bind("completed") // test_status
        .bind(&claims.sub)
        .bind(now.to_rfc3339())
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to store test result: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to store test result")
        })?;
    }

    Ok(HttpResponse::Ok().json(SigmaRuleTestResultResponse {
        id: test_id,
        rule_id: parsed.id,
        rule_title: parsed.title,
        total_logs_tested: request.sample_logs.len(),
        match_count: matches.len(),
        matches,
        false_positive_count: 0,
        true_positive_count: 0,
        test_duration_ms: duration_ms,
        tested_at: now.to_rfc3339(),
        description: request.description.clone(),
    }))
}

/// Get test results for a Sigma rule
pub async fn get_sigma_rule_test_results(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<TestResultsQuery>,
) -> Result<HttpResponse> {
    let rule_id = path.into_inner();
    let limit = query.limit.unwrap_or(20) as i64;
    let offset = query.offset.unwrap_or(0) as i64;

    let rows: Vec<SigmaRuleTestRow> = sqlx::query_as(
        r#"
        SELECT id, sigma_rule_id, test_name, sample_logs, actual_matches, match_details,
               execution_time_ms, test_status, tested_at, tested_by
        FROM sigma_rule_tests
        WHERE sigma_rule_id = ?
        ORDER BY tested_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(&rule_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch test results: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch test results")
    })?;

    let results: Vec<SigmaRuleTestResultResponse> = rows.into_iter().map(|r| {
        let matches: Vec<SigmaTestMatch> = r.match_details.as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();
        SigmaRuleTestResultResponse {
            id: r.id,
            rule_id: r.sigma_rule_id,
            rule_title: String::new(), // Would need a join to get this
            total_logs_tested: serde_json::from_str::<Vec<serde_json::Value>>(&r.sample_logs)
                .map(|v| v.len()).unwrap_or(0),
            match_count: r.actual_matches.unwrap_or(0) as usize,
            matches,
            false_positive_count: 0, // Not tracked in this schema
            true_positive_count: 0,  // Not tracked in this schema
            test_duration_ms: r.execution_time_ms.unwrap_or(0),
            tested_at: r.tested_at.unwrap_or_default(),
            description: Some(r.test_name),
        }
    }).collect();

    Ok(HttpResponse::Ok().json(results))
}

/// Update test result with TP/FP classification
pub async fn update_test_result(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<UpdateTestResultRequest>,
) -> Result<HttpResponse> {
    let test_id = path.into_inner();

    let column = match request.result_type.as_str() {
        "true_positive" => "true_positive_count",
        "false_positive" => "false_positive_count",
        _ => return Err(actix_web::error::ErrorBadRequest("Invalid result_type")),
    };

    let sql = format!(
        "UPDATE sigma_rule_tests SET {} = {} + 1 WHERE id = ?",
        column, column
    );

    sqlx::query(&sql)
        .bind(&test_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to update test result: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update test result")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "success": true })))
}

/// Get ATT&CK technique coverage from Sigma rules
pub async fn get_attack_coverage(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Get all enabled Sigma rules with their techniques
    let rows: Vec<SigmaRuleCoverageRow> = sqlx::query_as(
        r#"
        SELECT id, name, level, mitre_techniques, mitre_tactics
        FROM sigma_rules
        WHERE enabled = 1
        "#,
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch Sigma rules: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rules")
    })?;

    // Build coverage map
    let mut technique_map: std::collections::HashMap<String, Vec<CoveringRuleInfo>> = std::collections::HashMap::new();
    let mut tactic_counts: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();

    for row in &rows {
        let techniques: Vec<String> = serde_json::from_str(&row.mitre_techniques).unwrap_or_default();
        let tactics: Vec<String> = serde_json::from_str(&row.mitre_tactics).unwrap_or_default();

        for technique in &techniques {
            technique_map.entry(technique.clone()).or_default().push(CoveringRuleInfo {
                rule_id: row.id.clone(),
                rule_name: row.name.clone(),
                level: row.level.clone(),
            });
        }

        for tactic in &tactics {
            let entry = tactic_counts.entry(tactic.clone()).or_insert((0, 0));
            entry.1 += 1; // total rules
        }
    }

    // Count unique techniques per tactic
    for (technique, _) in &technique_map {
        // Map technique to tactic (simplified - in reality would use a proper mapping)
        let tactic = get_tactic_for_technique(technique);
        if let Some(entry) = tactic_counts.get_mut(&tactic) {
            entry.0 += 1; // techniques covered
        }
    }

    let coverage_by_tactic: std::collections::HashMap<String, TacticCoverage> = tactic_counts
        .into_iter()
        .map(|(tactic, (techniques, rules))| {
            (tactic.clone(), TacticCoverage {
                tactic_name: tactic,
                techniques_covered: techniques,
                total_rules: rules,
            })
        })
        .collect();

    let techniques: Vec<TechniqueCoverageEntry> = technique_map
        .into_iter()
        .map(|(technique_id, rules)| {
            TechniqueCoverageEntry {
                technique_id: technique_id.clone(),
                technique_name: get_technique_name(&technique_id),
                tactic: get_tactic_for_technique(&technique_id),
                rule_count: rules.len() as i64,
                rules,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(AttackCoverageResponse {
        total_techniques_covered: techniques.len(),
        total_rules: rows.len(),
        coverage_by_tactic,
        techniques,
    }))
}

/// Get tuning recommendations based on FP analysis
pub async fn get_tuning_recommendations(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Get rules with high false positive rates
    let rows: Vec<SigmaRuleTuningRow> = sqlx::query_as(
        r#"
        SELECT
            sr.id, sr.name, sr.level, sr.trigger_count,
            COALESCE(SUM(st.false_positive_count), 0) as total_fp,
            COALESCE(SUM(st.true_positive_count), 0) as total_tp,
            COALESCE(SUM(st.match_count), 0) as total_matches
        FROM sigma_rules sr
        LEFT JOIN sigma_rule_tests st ON sr.id = st.rule_id
        WHERE sr.enabled = 1
        GROUP BY sr.id, sr.name, sr.level, sr.trigger_count
        HAVING total_matches > 0
        ORDER BY (CAST(total_fp AS REAL) / NULLIF(total_matches, 0)) DESC
        "#,
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch tuning data: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch tuning data")
    })?;

    let mut recommendations = Vec::new();
    let total_rules = rows.len();

    for row in rows {
        let total_matches = row.total_matches.max(1) as f64;
        let fp_rate = row.total_fp as f64 / total_matches;

        if fp_rate > 0.5 {
            let (rec_type, reason, actions) = if fp_rate > 0.9 {
                (
                    "disable",
                    format!("Rule has {}% false positive rate", (fp_rate * 100.0) as i32),
                    vec![
                        "Consider disabling this rule".to_string(),
                        "Review rule logic for overly broad matches".to_string(),
                    ],
                )
            } else if fp_rate > 0.7 {
                (
                    "tune_threshold",
                    format!("Rule has {}% false positive rate", (fp_rate * 100.0) as i32),
                    vec![
                        "Add more specific detection criteria".to_string(),
                        "Consider adding exclusion patterns".to_string(),
                        "Review logsource filtering".to_string(),
                    ],
                )
            } else {
                (
                    "review",
                    format!("Rule has {}% false positive rate", (fp_rate * 100.0) as i32),
                    vec![
                        "Review recent false positive matches".to_string(),
                        "Consider environment-specific exclusions".to_string(),
                    ],
                )
            };

            recommendations.push(RuleTuningRecommendation {
                rule_id: row.id,
                rule_name: row.name,
                recommendation_type: rec_type.to_string(),
                reason,
                false_positive_rate: fp_rate,
                suggested_actions: actions,
            });
        }
    }

    let rules_needing_tuning = recommendations.len();

    Ok(HttpResponse::Ok().json(TuningRecommendationsResponse {
        recommendations,
        total_rules_analyzed: total_rules,
        rules_needing_tuning,
    }))
}

/// Create a Sigma rule chain
pub async fn create_rule_chain(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateRuleChainRequest>,
) -> Result<HttpResponse> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let enabled = request.enabled.unwrap_or(true);
    let rule_ids_json = serde_json::to_string(&request.rule_ids).unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO sigma_rule_chains (
            id, name, description, rule_ids, chain_condition,
            time_window_secs, severity, enabled, user_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'high', ?, ?, datetime('now'))
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&rule_ids_json)
    .bind(&request.chain_logic) // maps to chain_condition column
    .bind(request.time_window_secs)
    .bind(enabled)
    .bind(&claims.sub)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create rule chain: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create rule chain")
    })?;

    Ok(HttpResponse::Created().json(SigmaRuleChain {
        id,
        name: request.name.clone(),
        description: request.description.clone(),
        rule_ids: request.rule_ids.clone(),
        chain_logic: request.chain_logic.clone(),
        time_window_secs: request.time_window_secs,
        enabled,
        created_at: now.to_rfc3339(),
        created_by: claims.sub.clone(),
    }))
}

/// List Sigma rule chains
pub async fn list_rule_chains(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows: Vec<SigmaRuleChainRow> = sqlx::query_as(
        r#"
        SELECT id, name, description, rule_ids, chain_condition,
               time_window_secs, enabled, user_id, created_at
        FROM sigma_rule_chains
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch rule chains: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch rule chains")
    })?;

    let chains: Vec<SigmaRuleChain> = rows.into_iter().map(|r| {
        SigmaRuleChain {
            id: r.id,
            name: r.name,
            description: r.description,
            rule_ids: serde_json::from_str(&r.rule_ids).unwrap_or_default(),
            chain_logic: r.chain_condition, // DB column is chain_condition
            time_window_secs: r.time_window_secs,
            enabled: r.enabled,
            created_at: r.created_at,
            created_by: r.user_id.unwrap_or_default(), // DB column is user_id
        }
    }).collect();

    Ok(HttpResponse::Ok().json(chains))
}

/// Delete a Sigma rule chain
pub async fn delete_rule_chain(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    sqlx::query("DELETE FROM sigma_rule_chains WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete rule chain: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete rule chain")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

// Helper row types for queries
#[derive(sqlx::FromRow)]
struct SigmaRuleTestRow {
    id: String,
    sigma_rule_id: String,
    test_name: String,
    sample_logs: String,
    actual_matches: Option<i64>,
    match_details: Option<String>,
    execution_time_ms: Option<i64>,
    #[allow(dead_code)]
    test_status: String,
    tested_at: Option<String>,
    #[allow(dead_code)]
    tested_by: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SigmaRuleCoverageRow {
    id: String,
    name: String,
    level: String,
    mitre_techniques: String,
    mitre_tactics: String,
}

#[derive(sqlx::FromRow)]
struct SigmaRuleTuningRow {
    id: String,
    name: String,
    #[allow(dead_code)]
    level: String,
    #[allow(dead_code)]
    trigger_count: i64,
    total_fp: i64,
    #[allow(dead_code)]
    total_tp: i64,
    total_matches: i64,
}

#[derive(sqlx::FromRow)]
struct SigmaRuleChainRow {
    id: String,
    name: String,
    description: Option<String>,
    rule_ids: String,
    chain_condition: String,
    time_window_secs: i64,
    enabled: bool,
    user_id: Option<String>,
    created_at: String,
}

/// Helper function to map technique to tactic
fn get_tactic_for_technique(technique_id: &str) -> String {
    // Simplified mapping - in production would use a complete MITRE ATT&CK database
    if technique_id.starts_with("T1059") || technique_id.starts_with("T1204") {
        "execution".to_string()
    } else if technique_id.starts_with("T1547") || technique_id.starts_with("T1053") {
        "persistence".to_string()
    } else if technique_id.starts_with("T1548") || technique_id.starts_with("T1134") {
        "privilege_escalation".to_string()
    } else if technique_id.starts_with("T1562") || technique_id.starts_with("T1070") {
        "defense_evasion".to_string()
    } else if technique_id.starts_with("T1003") || technique_id.starts_with("T1558") {
        "credential_access".to_string()
    } else if technique_id.starts_with("T1087") || technique_id.starts_with("T1018") {
        "discovery".to_string()
    } else if technique_id.starts_with("T1021") || technique_id.starts_with("T1570") {
        "lateral_movement".to_string()
    } else if technique_id.starts_with("T1560") || technique_id.starts_with("T1005") {
        "collection".to_string()
    } else if technique_id.starts_with("T1071") || technique_id.starts_with("T1095") {
        "command_and_control".to_string()
    } else if technique_id.starts_with("T1041") || technique_id.starts_with("T1048") {
        "exfiltration".to_string()
    } else if technique_id.starts_with("T1190") || technique_id.starts_with("T1566") {
        "initial_access".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Helper function to get technique name
fn get_technique_name(technique_id: &str) -> String {
    // Simplified - in production would use a complete MITRE ATT&CK database
    match technique_id {
        "T1059.001" => "PowerShell".to_string(),
        "T1059.003" => "Windows Command Shell".to_string(),
        "T1003.001" => "LSASS Memory".to_string(),
        "T1003.002" => "Security Account Manager".to_string(),
        "T1547.001" => "Registry Run Keys".to_string(),
        "T1053.005" => "Scheduled Task".to_string(),
        "T1070.001" => "Clear Windows Event Logs".to_string(),
        "T1562.001" => "Disable or Modify Tools".to_string(),
        "T1021.001" => "Remote Desktop Protocol".to_string(),
        "T1021.002" => "SMB/Windows Admin Shares".to_string(),
        "T1071.001" => "Web Protocols".to_string(),
        "T1566.001" => "Spearphishing Attachment".to_string(),
        "T1190" => "Exploit Public-Facing Application".to_string(),
        _ => technique_id.to_string(),
    }
}

// =============================================================================
// Correlation Rule Endpoints
// =============================================================================

/// List correlation rules
pub async fn list_correlation_rules(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<CorrelationRuleListQuery>,
) -> Result<HttpResponse> {
    let mut sql = String::from("SELECT * FROM correlation_rules WHERE 1=1");

    if let Some(enabled) = query.enabled {
        sql.push_str(&format!(" AND enabled = {}", if enabled { 1 } else { 0 }));
    }
    if let Some(ref rule_type) = query.rule_type {
        sql.push_str(&format!(" AND rule_type = '{}'", rule_type.replace('\'', "''")));
    }
    sql.push_str(" ORDER BY name");

    let rows: Vec<CorrelationRuleRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch correlation rules: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch correlation rules")
        })?;

    let rules: Vec<CorrelationRuleResponse> = rows.into_iter().map(|r| r.into()).collect();
    Ok(HttpResponse::Ok().json(rules))
}

/// Create a correlation rule
pub async fn create_correlation_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateCorrelationRuleRequest>,
) -> Result<HttpResponse> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let enabled = request.enabled.unwrap_or(false);
    let severity = request.severity.clone().unwrap_or_else(|| "warning".to_string());
    let group_by = serde_json::to_string(&request.group_by.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let conditions = serde_json::to_string(&request.conditions)
        .unwrap_or_else(|_| "{}".to_string());
    let tactics = serde_json::to_string(&request.mitre_tactics.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let techniques = serde_json::to_string(&request.mitre_techniques.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO correlation_rules (
            id, name, description, rule_type, conditions_json, time_window_secs,
            threshold, group_by_fields, severity, enabled, mitre_tactics,
            mitre_techniques, user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.rule_type)
    .bind(&conditions)
    .bind(request.time_window_secs)
    .bind(request.threshold)
    .bind(&group_by)
    .bind(&severity)
    .bind(enabled)
    .bind(&tactics)
    .bind(&techniques)
    .bind(&claims.sub)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create correlation rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create correlation rule")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": request.name,
        "message": "Correlation rule created successfully"
    })))
}

/// Delete a correlation rule
pub async fn delete_correlation_rule(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM correlation_rules WHERE id = ?")
        .bind(&id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete correlation rule: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete correlation rule")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Correlation rule not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Correlation rule deleted successfully"
    })))
}

/// Get built-in correlation rules
pub async fn get_builtin_correlation_rules_handler(
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rules = get_builtin_correlation_rules();
    Ok(HttpResponse::Ok().json(rules))
}

// =============================================================================
// Alert Enhancement Endpoints
// =============================================================================

/// Get deduplicated alert groups
pub async fn get_deduplicated_alerts(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows: Vec<AlertGroupRow> = sqlx::query_as(
        "SELECT * FROM siem_alert_groups WHERE suppressed = 0 ORDER BY last_seen DESC LIMIT 100"
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch alert groups: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch alert groups")
    })?;

    let groups: Vec<AlertGroupResponse> = Vec::new();
    // Note: Full implementation would fetch primary_alert for each group
    // This is a simplified version

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "groups": groups,
        "total": rows.len()
    })))
}

/// Update alert status with workflow validation
pub async fn update_alert_status_workflow(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    request: web::Json<UpdateAlertStatusWorkflowRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();
    let now = Utc::now();

    // Get current alert status
    let current: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM siem_alerts WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch alert: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch alert")
    })?;

    let Some((current_status,)) = current else {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Alert not found"
        })));
    };

    // Validate transition
    let from_status = parse_alert_status(&current_status);
    let to_status = parse_alert_status(&request.status);

    if !AlertWorkflow::is_valid_transition(from_status, to_status) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid status transition from '{}' to '{}'", current_status, request.status),
            "valid_transitions": AlertWorkflow::get_valid_transitions(from_status)
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
        })));
    }

    // Update alert
    sqlx::query(
        "UPDATE siem_alerts SET status = ?, assigned_to = ?, updated_at = ? WHERE id = ?"
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

    // Record status history
    let history_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO siem_alert_status_history (id, alert_id, old_status, new_status, changed_by, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&history_id)
    .bind(&id)
    .bind(&current_status)
    .bind(&request.status)
    .bind(&claims.sub)
    .bind(&request.notes)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .ok(); // Don't fail if history insert fails

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Alert status updated",
        "old_status": current_status,
        "new_status": request.status
    })))
}

/// Get alert status history
pub async fn get_alert_history(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let rows: Vec<(String, String, Option<String>, String, Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT id, alert_id, old_status, new_status, changed_by, notes, created_at FROM siem_alert_status_history WHERE alert_id = ? ORDER BY created_at DESC"
    )
    .bind(&id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch alert history: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch alert history")
    })?;

    let history: Vec<AlertStatusHistoryEntry> = rows.into_iter().map(|(id, alert_id, old_status, new_status, changed_by, notes, created_at)| {
        AlertStatusHistoryEntry {
            id,
            alert_id,
            old_status,
            new_status,
            changed_by,
            notes,
            created_at,
        }
    }).collect();

    Ok(HttpResponse::Ok().json(history))
}

// =============================================================================
// Saved Search Endpoints
// =============================================================================

/// List saved searches
pub async fn list_saved_searches(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rows: Vec<SavedSearchRow> = sqlx::query_as(
        "SELECT * FROM siem_saved_searches WHERE user_id = ? OR EXISTS (SELECT 1 FROM siem_dashboards WHERE user_id = ? AND is_public = 1) ORDER BY name"
    )
    .bind(&claims.sub)
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch saved searches: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch saved searches")
    })?;

    let searches: Vec<SavedSearchResponse> = rows.into_iter().map(|r| r.into()).collect();
    Ok(HttpResponse::Ok().json(searches))
}

/// Create a saved search
pub async fn create_saved_search(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateSavedSearchRequest>,
) -> Result<HttpResponse> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let tags = serde_json::to_string(&request.tags.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());
    let recipients = serde_json::to_string(&request.email_recipients.clone().unwrap_or_default())
        .unwrap_or_else(|_| "[]".to_string());

    sqlx::query(
        r#"
        INSERT INTO siem_saved_searches (
            id, name, description, query, schedule_cron, schedule_enabled,
            alert_threshold, alert_severity, email_recipients, tags,
            user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.query)
    .bind(&request.schedule_cron)
    .bind(request.schedule_enabled.unwrap_or(false))
    .bind(request.alert_threshold)
    .bind(&request.alert_severity)
    .bind(&recipients)
    .bind(&tags)
    .bind(&claims.sub)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create saved search: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create saved search")
    })?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": request.name,
        "message": "Saved search created successfully"
    })))
}

/// Delete a saved search
pub async fn delete_saved_search(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let result = sqlx::query("DELETE FROM siem_saved_searches WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete saved search: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete saved search")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Saved search not found"
        })));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Saved search deleted successfully"
    })))
}

// =============================================================================
// Dashboard Endpoints
// =============================================================================

/// Get SIEM dashboard overview
pub async fn get_dashboard_overview(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Alert counts by severity
    let total_alerts: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM siem_alerts")
        .fetch_one(pool.get_ref()).await.unwrap_or((0,));

    let open_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_alerts WHERE status IN ('new', 'in_progress', 'escalated')"
    ).fetch_one(pool.get_ref()).await.unwrap_or((0,));

    let critical_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_alerts WHERE severity IN ('critical', 'emergency') AND status NOT IN ('resolved', 'false_positive')"
    ).fetch_one(pool.get_ref()).await.unwrap_or((0,));

    let high_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_alerts WHERE severity = 'error' AND status NOT IN ('resolved', 'false_positive')"
    ).fetch_one(pool.get_ref()).await.unwrap_or((0,));

    let medium_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_alerts WHERE severity = 'warning' AND status NOT IN ('resolved', 'false_positive')"
    ).fetch_one(pool.get_ref()).await.unwrap_or((0,));

    let low_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM siem_alerts WHERE severity IN ('notice', 'info') AND status NOT IN ('resolved', 'false_positive')"
    ).fetch_one(pool.get_ref()).await.unwrap_or((0,));

    // Alerts by status
    let status_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) FROM siem_alerts GROUP BY status"
    ).fetch_all(pool.get_ref()).await.unwrap_or_default();

    let alerts_by_status: Vec<AlertStatusCount> = status_rows.into_iter()
        .map(|(status, count)| AlertStatusCount { status, count })
        .collect();

    // Top alerting rules
    let rule_rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT rule_id, rule_name, COUNT(*) as cnt FROM siem_alerts GROUP BY rule_id ORDER BY cnt DESC LIMIT 10"
    ).fetch_all(pool.get_ref()).await.unwrap_or_default();

    let top_rules: Vec<TopRuleCount> = rule_rows.into_iter()
        .map(|(rule_id, rule_name, alert_count)| TopRuleCount { rule_id, rule_name, alert_count })
        .collect();

    // Top sources
    let source_rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, name, log_count, logs_per_hour FROM siem_log_sources ORDER BY log_count DESC LIMIT 10"
    ).fetch_all(pool.get_ref()).await.unwrap_or_default();

    let top_sources: Vec<TopSourceStats> = source_rows.into_iter()
        .map(|(id, name, log_count, logs_per_hour)| TopSourceStats { id, name, log_count, logs_per_hour })
        .collect();

    // Alert trend (last 24 hours by hour)
    let trend_rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT strftime('%Y-%m-%dT%H:00:00Z', created_at) as hour, COUNT(*) as cnt
        FROM siem_alerts
        WHERE created_at >= datetime('now', '-1 day')
        GROUP BY hour
        ORDER BY hour
        "#
    ).fetch_all(pool.get_ref()).await.unwrap_or_default();

    let alert_trend: Vec<TrendPoint> = trend_rows.into_iter()
        .map(|(timestamp, value)| TrendPoint { timestamp, value })
        .collect();

    // Active rules counts
    let active_correlation: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM correlation_rules WHERE enabled = 1"
    ).fetch_one(pool.get_ref()).await.unwrap_or((0,));

    let active_sigma: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sigma_rules WHERE enabled = 1"
    ).fetch_one(pool.get_ref()).await.unwrap_or((0,));

    Ok(HttpResponse::Ok().json(DashboardOverviewResponse {
        total_alerts: total_alerts.0,
        open_alerts: open_alerts.0,
        critical_alerts: critical_alerts.0,
        high_alerts: high_alerts.0,
        medium_alerts: medium_alerts.0,
        low_alerts: low_alerts.0,
        alerts_by_status,
        top_rules,
        top_sources,
        alert_trend,
        active_correlation_rules: active_correlation.0,
        active_sigma_rules: active_sigma.0,
    }))
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
            // Sigma Rules
            .route("/sigma/rules", web::get().to(list_sigma_rules))
            .route("/sigma/rules", web::post().to(create_sigma_rule))
            .route("/sigma/rules/{id}", web::get().to(get_sigma_rule))
            .route("/sigma/rules/{id}", web::delete().to(delete_sigma_rule))
            .route("/sigma/validate", web::post().to(validate_sigma))
            .route("/sigma/test", web::post().to(test_sigma_rule))
            .route("/sigma/builtin", web::get().to(get_builtin_sigma_rules))
            // Sigma Backend Conversion (Sprint 2)
            .route("/sigma/convert", web::post().to(convert_sigma_rule))
            .route("/sigma/convert-all", web::post().to(convert_sigma_rule_all))
            // Sigma Rule Testing with Storage (Sprint 2)
            .route("/sigma/rules/{id}/test", web::post().to(test_sigma_rule_with_storage))
            .route("/sigma/rules/{id}/test-results", web::get().to(get_sigma_rule_test_results))
            .route("/sigma/test-results/{id}", web::put().to(update_test_result))
            // Sigma ATT&CK Coverage (Sprint 2)
            .route("/sigma/coverage", web::get().to(get_attack_coverage))
            // Sigma Tuning Recommendations (Sprint 2)
            .route("/sigma/tuning/recommendations", web::get().to(get_tuning_recommendations))
            // Sigma Rule Chains (Sprint 2)
            .route("/sigma/chains", web::get().to(list_rule_chains))
            .route("/sigma/chains", web::post().to(create_rule_chain))
            .route("/sigma/chains/{id}", web::delete().to(delete_rule_chain))
            // Correlation Rules
            .route("/correlation/rules", web::get().to(list_correlation_rules))
            .route("/correlation/rules", web::post().to(create_correlation_rule))
            .route("/correlation/rules/{id}", web::delete().to(delete_correlation_rule))
            .route("/correlation/builtin", web::get().to(get_builtin_correlation_rules_handler))
            // Alert Enhancements (deduplicated alerts, status workflow, history)
            .route("/alerts/deduplicated", web::get().to(get_deduplicated_alerts))
            .route("/alerts/{id}/workflow", web::put().to(update_alert_status_workflow))
            .route("/alerts/{id}/history", web::get().to(get_alert_status_history))
            // Saved Searches
            .route("/saved-searches", web::get().to(list_saved_searches))
            .route("/saved-searches", web::post().to(create_saved_search))
            .route("/saved-searches/{id}", web::delete().to(delete_saved_search))
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard_overview))
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

// =============================================================================
// SIEM Enhancement Row Types
// =============================================================================

#[derive(sqlx::FromRow)]
struct SigmaRuleRow {
    id: String,
    name: String,
    yaml_content: String,
    compiled_query: Option<String>,
    enabled: bool,
    level: String,
    status: String,
    logsource_product: Option<String>,
    logsource_service: Option<String>,
    logsource_category: Option<String>,
    tags: String,
    mitre_tactics: String,
    mitre_techniques: String,
    author: Option<String>,
    references_json: String,
    false_positives: String,
    trigger_count: i64,
    last_triggered: Option<String>,
    user_id: Option<String>,
    organization_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<SigmaRuleRow> for SigmaRuleResponse {
    fn from(row: SigmaRuleRow) -> Self {
        SigmaRuleResponse {
            id: row.id,
            name: row.name,
            level: row.level,
            status: row.status,
            enabled: row.enabled,
            logsource_product: row.logsource_product,
            logsource_service: row.logsource_service,
            logsource_category: row.logsource_category,
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            mitre_tactics: serde_json::from_str(&row.mitre_tactics).unwrap_or_default(),
            mitre_techniques: serde_json::from_str(&row.mitre_techniques).unwrap_or_default(),
            author: row.author,
            trigger_count: row.trigger_count,
            last_triggered: row.last_triggered,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct CorrelationRuleRow {
    id: String,
    name: String,
    description: Option<String>,
    rule_type: String,
    conditions_json: String,
    time_window_secs: i64,
    threshold: Option<i64>,
    group_by_fields: String,
    severity: String,
    enabled: bool,
    mitre_tactics: String,
    mitre_techniques: String,
    trigger_count: i64,
    last_triggered: Option<String>,
    user_id: Option<String>,
    organization_id: Option<String>,
    created_at: String,
    updated_at: String,
}

/// Correlation rule response
#[derive(Debug, Serialize)]
pub struct CorrelationRuleResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub time_window_secs: i64,
    pub threshold: Option<i64>,
    pub group_by: Vec<String>,
    pub severity: String,
    pub enabled: bool,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub trigger_count: i64,
    pub last_triggered: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<CorrelationRuleRow> for CorrelationRuleResponse {
    fn from(row: CorrelationRuleRow) -> Self {
        CorrelationRuleResponse {
            id: row.id,
            name: row.name,
            description: row.description,
            rule_type: row.rule_type,
            conditions: serde_json::from_str(&row.conditions_json).unwrap_or(serde_json::json!({})),
            time_window_secs: row.time_window_secs,
            threshold: row.threshold,
            group_by: serde_json::from_str(&row.group_by_fields).unwrap_or_default(),
            severity: row.severity,
            enabled: row.enabled,
            mitre_tactics: serde_json::from_str(&row.mitre_tactics).unwrap_or_default(),
            mitre_techniques: serde_json::from_str(&row.mitre_techniques).unwrap_or_default(),
            trigger_count: row.trigger_count,
            last_triggered: row.last_triggered,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SavedSearchRow {
    id: String,
    name: String,
    description: Option<String>,
    query: String,
    query_params_json: String,
    schedule_cron: Option<String>,
    schedule_enabled: bool,
    alert_threshold: Option<i64>,
    alert_severity: Option<String>,
    email_recipients: String,
    last_run: Option<String>,
    last_result_count: Option<i64>,
    tags: String,
    user_id: String,
    organization_id: Option<String>,
    created_at: String,
    updated_at: String,
}

/// Saved search response
#[derive(Debug, Serialize)]
pub struct SavedSearchResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub query: String,
    pub query_params: serde_json::Value,
    pub schedule_cron: Option<String>,
    pub schedule_enabled: bool,
    pub alert_threshold: Option<i64>,
    pub alert_severity: Option<String>,
    pub email_recipients: Vec<String>,
    pub last_run: Option<String>,
    pub last_result_count: Option<i64>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<SavedSearchRow> for SavedSearchResponse {
    fn from(row: SavedSearchRow) -> Self {
        SavedSearchResponse {
            id: row.id,
            name: row.name,
            description: row.description,
            query: row.query,
            query_params: serde_json::from_str(&row.query_params_json).unwrap_or(serde_json::json!({})),
            schedule_cron: row.schedule_cron,
            schedule_enabled: row.schedule_enabled,
            alert_threshold: row.alert_threshold,
            alert_severity: row.alert_severity,
            email_recipients: serde_json::from_str(&row.email_recipients).unwrap_or_default(),
            last_run: row.last_run,
            last_result_count: row.last_result_count,
            tags: serde_json::from_str(&row.tags).unwrap_or_default(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AlertGroupRow {
    id: String,
    group_key: String,
    primary_alert_id: String,
    alert_count: i64,
    alert_ids: String,
    first_seen: String,
    last_seen: String,
    suppressed: bool,
    created_at: String,
    updated_at: String,
}

#[derive(sqlx::FromRow)]
struct AlertStatusHistoryRow {
    id: String,
    alert_id: String,
    old_status: Option<String>,
    new_status: String,
    changed_by: Option<String>,
    notes: Option<String>,
    created_at: String,
}

impl From<AlertStatusHistoryRow> for AlertStatusHistoryEntry {
    fn from(row: AlertStatusHistoryRow) -> Self {
        AlertStatusHistoryEntry {
            id: row.id,
            alert_id: row.alert_id,
            old_status: row.old_status,
            new_status: row.new_status,
            changed_by: row.changed_by,
            notes: row.notes,
            created_at: row.created_at,
        }
    }
}

// =============================================================================
// Alert Status History Endpoint
// =============================================================================

/// Get alert status history
pub async fn get_alert_status_history(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let alert_id = path.into_inner();

    let rows: Vec<AlertStatusHistoryRow> = sqlx::query_as(
        "SELECT id, alert_id, old_status, new_status, changed_by, notes, created_at
         FROM siem_alert_status_history
         WHERE alert_id = ?
         ORDER BY created_at DESC"
    )
    .bind(&alert_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch alert status history: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch alert status history")
    })?;

    let history: Vec<AlertStatusHistoryEntry> = rows.into_iter().map(|r| r.into()).collect();
    Ok(HttpResponse::Ok().json(history))
}
