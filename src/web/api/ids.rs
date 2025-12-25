#![allow(dead_code)]
//! IDS (Intrusion Detection System) API Endpoints
//!
//! This module provides REST API endpoints for managing IDS rules in HeroForge.
//! Supports Suricata/Snort rule format for blue team threat detection.
//!
//! ## Endpoints
//!
//! - `POST /api/detection/ids/rules` - Add IDS rule
//! - `GET /api/detection/ids/rules` - List rules (with filtering)
//! - `GET /api/detection/ids/rules/{sid}` - Get rule by SID
//! - `PUT /api/detection/ids/rules/{sid}` - Update rule
//! - `DELETE /api/detection/ids/rules/{sid}` - Delete rule
//! - `POST /api/detection/ids/import` - Import ruleset file
//! - `POST /api/detection/ids/validate` - Validate rule syntax
//! - `GET /api/detection/ids/categories` - List rule categories

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::scanner::ids::{
    parse_rule, validate_rule, IdsRule,
    RulesDatabase, RuleValidationError, rules_db::RULE_CATEGORIES,
};
use crate::web::auth;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to create a new IDS rule
#[derive(Debug, Deserialize)]
pub struct CreateIdsRuleRequest {
    /// Raw rule text in Suricata/Snort format
    pub rule_text: String,
    /// Whether the rule should be enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional category override
    pub category: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Request to update an IDS rule
#[derive(Debug, Deserialize)]
pub struct UpdateIdsRuleRequest {
    /// Updated rule text (optional)
    pub rule_text: Option<String>,
    /// Enable/disable the rule
    pub enabled: Option<bool>,
    /// Update category
    pub category: Option<String>,
    /// Update priority
    pub priority: Option<u8>,
}

/// Query parameters for listing IDS rules
#[derive(Debug, Deserialize)]
pub struct IdsRulesQuery {
    /// Filter by category
    pub category: Option<String>,
    /// Filter by enabled status
    pub enabled: Option<bool>,
    /// Filter by priority (1-4)
    pub priority: Option<u8>,
    /// Search in message
    pub search: Option<String>,
    /// Filter by protocol
    pub protocol: Option<String>,
    /// Filter by classtype
    pub classtype: Option<String>,
    /// Pagination offset
    pub offset: Option<u32>,
    /// Pagination limit
    pub limit: Option<u32>,
}

/// Request to import a ruleset file
#[derive(Debug, Deserialize)]
pub struct ImportRulesetRequest {
    /// Ruleset content (multiple rules, one per line)
    pub content: String,
    /// Default category for imported rules
    pub category: Option<String>,
    /// Whether to enable imported rules
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Skip rules that fail parsing
    #[serde(default)]
    pub skip_errors: bool,
}

/// Request to validate a rule
#[derive(Debug, Deserialize)]
pub struct ValidateRuleRequest {
    /// Rule text to validate
    pub rule_text: String,
}

/// Response for rule validation
#[derive(Debug, Serialize)]
pub struct ValidateRuleResponse {
    /// Whether the rule is valid
    pub valid: bool,
    /// Parsed rule (if valid)
    pub rule: Option<IdsRuleResponse>,
    /// Validation errors/warnings
    pub errors: Vec<RuleValidationError>,
    /// Parse error message (if parsing failed)
    pub parse_error: Option<String>,
}

/// Response for import operation
#[derive(Debug, Serialize)]
pub struct ImportRulesetResponse {
    /// Number of rules successfully imported
    pub imported: usize,
    /// Number of rules that failed to import
    pub failed: usize,
    /// Error messages for failed rules
    pub errors: Vec<ImportError>,
}

/// Import error details
#[derive(Debug, Serialize)]
pub struct ImportError {
    pub line: usize,
    pub rule_text: String,
    pub error: String,
}

/// IDS rule response
#[derive(Debug, Serialize)]
pub struct IdsRuleResponse {
    pub sid: u64,
    pub rev: u32,
    pub msg: String,
    pub action: String,
    pub protocol: String,
    pub src_addr: String,
    pub src_port: String,
    pub dst_addr: String,
    pub dst_port: String,
    pub classtype: Option<String>,
    pub priority: Option<u8>,
    pub category: Option<String>,
    pub enabled: bool,
    pub references: Vec<ReferenceResponse>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub tags: Vec<String>,
    pub raw_rule: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Reference response
#[derive(Debug, Serialize)]
pub struct ReferenceResponse {
    pub ref_type: String,
    pub value: String,
}

/// Rule category response
#[derive(Debug, Serialize)]
pub struct RuleCategoryResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub rule_count: i64,
}

/// IDS alert response
#[derive(Debug, Serialize)]
pub struct IdsAlertResponse {
    pub id: String,
    pub rule_sid: u64,
    pub rule_msg: String,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub payload_excerpt: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub severity: u8,
    pub category: Option<String>,
}

/// Query parameters for listing alerts
#[derive(Debug, Deserialize)]
pub struct IdsAlertsQuery {
    /// Filter by rule SID
    pub rule_sid: Option<u64>,
    /// Filter by source IP
    pub src_ip: Option<String>,
    /// Filter by destination IP
    pub dst_ip: Option<String>,
    /// Filter by min severity (1-4)
    pub min_severity: Option<u8>,
    /// Filter by category
    pub category: Option<String>,
    /// Start time filter
    pub start_time: Option<String>,
    /// End time filter
    pub end_time: Option<String>,
    /// Pagination offset
    pub offset: Option<u32>,
    /// Pagination limit
    pub limit: Option<u32>,
}

/// Paginated response
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub offset: u32,
    pub limit: u32,
}

// =============================================================================
// Helper Functions
// =============================================================================

impl From<&IdsRule> for IdsRuleResponse {
    fn from(rule: &IdsRule) -> Self {
        Self {
            sid: rule.sid,
            rev: rule.rev,
            msg: rule.msg.clone(),
            action: rule.action.to_string(),
            protocol: rule.protocol.to_string(),
            src_addr: rule.src_addr.to_string(),
            src_port: rule.src_port.to_string(),
            dst_addr: rule.dst_addr.to_string(),
            dst_port: rule.dst_port.to_string(),
            classtype: rule.classtype.as_ref().map(|c| c.name.clone()),
            priority: rule.priority.or_else(|| rule.classtype.as_ref().map(|c| c.priority)),
            category: rule.category.clone(),
            enabled: rule.enabled,
            references: rule.references.iter().map(|r| ReferenceResponse {
                ref_type: r.ref_type.clone(),
                value: r.value.clone(),
            }).collect(),
            mitre_tactics: rule.mitre_tactics.clone(),
            mitre_techniques: rule.mitre_techniques.clone(),
            tags: rule.tags.clone(),
            raw_rule: rule.raw_rule.clone(),
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        }
    }
}

// =============================================================================
// API Endpoints
// =============================================================================

/// Create a new IDS rule
pub async fn create_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateIdsRuleRequest>,
) -> Result<HttpResponse> {
    // Parse the rule
    let mut rule = match parse_rule(&request.rule_text) {
        Ok(r) => r,
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Failed to parse rule",
                "details": e.to_string()
            })));
        }
    };

    // Validate the rule
    let validation_errors = validate_rule(&rule).unwrap_or_default();
    let has_errors = validation_errors.iter().any(|e| {
        matches!(e.severity, crate::scanner::ids::ValidationSeverity::Error)
    });

    if has_errors {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Rule validation failed",
            "errors": validation_errors
        })));
    }

    // Apply overrides
    rule.enabled = request.enabled;
    if let Some(ref category) = request.category {
        rule.category = Some(category.clone());
    }
    rule.created_at = Some(Utc::now());
    rule.updated_at = Some(Utc::now());

    // Check if SID already exists
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT sid FROM ids_rules WHERE sid = ?"
    )
    .bind(rule.sid as i64)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to check existing rule: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if existing.is_some() {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "Rule with this SID already exists",
            "sid": rule.sid
        })));
    }

    // Insert into database
    let rule_json = serde_json::to_string(&rule).unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO ids_rules (
            sid, rev, msg, classtype, priority, rule_text, rule_json,
            enabled, category, user_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(rule.sid as i64)
    .bind(rule.rev as i32)
    .bind(&rule.msg)
    .bind(rule.classtype.as_ref().map(|c| &c.name))
    .bind(rule.priority.map(|p| p as i32))
    .bind(&rule.raw_rule)
    .bind(&rule_json)
    .bind(rule.enabled)
    .bind(&rule.category)
    .bind(&claims.sub)
    .bind(rule.created_at.map(|t| t.to_rfc3339()))
    .bind(rule.updated_at.map(|t| t.to_rfc3339()))
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to insert rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create rule")
    })?;

    // Log audit
    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "ids_rule_created",
        Some("ids_rule"),
        Some(&rule.sid.to_string()),
        Some(&format!("Created IDS rule: {}", rule.msg)),
        None,
    ).await;

    Ok(HttpResponse::Created().json(IdsRuleResponse::from(&rule)))
}

/// List IDS rules with filtering
pub async fn list_rules(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<IdsRulesQuery>,
) -> Result<HttpResponse> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(200);

    // Build dynamic query
    let mut sql = String::from(
        "SELECT sid, rev, msg, classtype, priority, rule_text, rule_json,
                enabled, category, created_at, updated_at
         FROM ids_rules WHERE 1=1"
    );
    let mut count_sql = String::from("SELECT COUNT(*) FROM ids_rules WHERE 1=1");

    let mut conditions = Vec::new();

    if let Some(ref category) = query.category {
        conditions.push(format!(" AND category = '{}'", category.replace('\'', "''")));
    }
    if let Some(enabled) = query.enabled {
        conditions.push(format!(" AND enabled = {}", if enabled { 1 } else { 0 }));
    }
    if let Some(priority) = query.priority {
        conditions.push(format!(" AND priority = {}", priority));
    }
    if let Some(ref search) = query.search {
        conditions.push(format!(" AND msg LIKE '%{}%'", search.replace('\'', "''")));
    }
    if let Some(ref classtype) = query.classtype {
        conditions.push(format!(" AND classtype = '{}'", classtype.replace('\'', "''")));
    }

    for condition in &conditions {
        sql.push_str(condition);
        count_sql.push_str(condition);
    }

    sql.push_str(" ORDER BY priority ASC, sid ASC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    // Get total count
    let total: (i64,) = sqlx::query_as(&count_sql)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to count rules: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    // Fetch rules
    let rows: Vec<IdsRuleRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to fetch rules: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    let rules: Vec<IdsRuleResponse> = rows
        .into_iter()
        .filter_map(|row| row.to_response().ok())
        .collect();

    Ok(HttpResponse::Ok().json(PaginatedResponse {
        items: rules,
        total: total.0,
        offset,
        limit,
    }))
}

/// Get a rule by SID
pub async fn get_rule(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<u64>,
) -> Result<HttpResponse> {
    let sid = path.into_inner();

    let row: Option<IdsRuleRow> = sqlx::query_as(
        "SELECT sid, rev, msg, classtype, priority, rule_text, rule_json,
                enabled, category, created_at, updated_at
         FROM ids_rules WHERE sid = ?"
    )
    .bind(sid as i64)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch rule: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    match row {
        Some(row) => {
            match row.to_response() {
                Ok(response) => Ok(HttpResponse::Ok().json(response)),
                Err(e) => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to parse rule",
                    "details": e.to_string()
                }))),
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found",
            "sid": sid
        }))),
    }
}

/// Update a rule
pub async fn update_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<u64>,
    request: web::Json<UpdateIdsRuleRequest>,
) -> Result<HttpResponse> {
    let sid = path.into_inner();

    // Fetch existing rule
    let existing: Option<IdsRuleRow> = sqlx::query_as(
        "SELECT sid, rev, msg, classtype, priority, rule_text, rule_json,
                enabled, category, created_at, updated_at
         FROM ids_rules WHERE sid = ?"
    )
    .bind(sid as i64)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch rule: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let existing = match existing {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Rule not found",
                "sid": sid
            })));
        }
    };

    // Parse and update rule
    let mut rule = if let Some(ref rule_text) = request.rule_text {
        match parse_rule(rule_text) {
            Ok(r) => r,
            Err(e) => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Failed to parse rule",
                    "details": e.to_string()
                })));
            }
        }
    } else {
        serde_json::from_str(&existing.rule_json).unwrap_or_default()
    };

    // Apply updates
    if let Some(enabled) = request.enabled {
        rule.enabled = enabled;
    }
    if let Some(ref category) = request.category {
        rule.category = Some(category.clone());
    }
    if let Some(priority) = request.priority {
        rule.priority = Some(priority);
    }
    rule.updated_at = Some(Utc::now());

    let rule_json = serde_json::to_string(&rule).unwrap_or_default();

    sqlx::query(
        r#"
        UPDATE ids_rules SET
            rev = ?, msg = ?, classtype = ?, priority = ?,
            rule_text = ?, rule_json = ?, enabled = ?,
            category = ?, updated_at = ?
        WHERE sid = ?
        "#
    )
    .bind(rule.rev as i32)
    .bind(&rule.msg)
    .bind(rule.classtype.as_ref().map(|c| &c.name))
    .bind(rule.priority.map(|p| p as i32))
    .bind(&rule.raw_rule)
    .bind(&rule_json)
    .bind(rule.enabled)
    .bind(&rule.category)
    .bind(rule.updated_at.map(|t| t.to_rfc3339()))
    .bind(sid as i64)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to update rule: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update rule")
    })?;

    // Log audit
    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "ids_rule_updated",
        Some("ids_rule"),
        Some(&sid.to_string()),
        Some("Updated IDS rule"),
        None,
    ).await;

    Ok(HttpResponse::Ok().json(IdsRuleResponse::from(&rule)))
}

/// Delete a rule
pub async fn delete_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<u64>,
) -> Result<HttpResponse> {
    let sid = path.into_inner();

    let result = sqlx::query("DELETE FROM ids_rules WHERE sid = ?")
        .bind(sid as i64)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete rule: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete rule")
        })?;

    if result.rows_affected() == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found",
            "sid": sid
        })));
    }

    // Log audit
    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "ids_rule_deleted",
        Some("ids_rule"),
        Some(&sid.to_string()),
        Some("Deleted IDS rule"),
        None,
    ).await;

    Ok(HttpResponse::NoContent().finish())
}

/// Import a ruleset file
pub async fn import_ruleset(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<ImportRulesetRequest>,
) -> Result<HttpResponse> {
    let mut imported = 0;
    let mut failed = 0;
    let mut errors = Vec::new();

    for (line_num, line) in request.content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match parse_rule(line) {
            Ok(mut rule) => {
                // Apply overrides
                rule.enabled = request.enabled;
                if let Some(ref category) = request.category {
                    rule.category = Some(category.clone());
                }
                rule.created_at = Some(Utc::now());
                rule.updated_at = Some(Utc::now());

                let rule_json = serde_json::to_string(&rule).unwrap_or_default();

                // Insert or update
                let result = sqlx::query(
                    r#"
                    INSERT INTO ids_rules (
                        sid, rev, msg, classtype, priority, rule_text, rule_json,
                        enabled, category, user_id, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sid) DO UPDATE SET
                        rev = excluded.rev,
                        msg = excluded.msg,
                        classtype = excluded.classtype,
                        priority = excluded.priority,
                        rule_text = excluded.rule_text,
                        rule_json = excluded.rule_json,
                        enabled = excluded.enabled,
                        category = excluded.category,
                        updated_at = excluded.updated_at
                    "#
                )
                .bind(rule.sid as i64)
                .bind(rule.rev as i32)
                .bind(&rule.msg)
                .bind(rule.classtype.as_ref().map(|c| &c.name))
                .bind(rule.priority.map(|p| p as i32))
                .bind(&rule.raw_rule)
                .bind(&rule_json)
                .bind(rule.enabled)
                .bind(&rule.category)
                .bind(&claims.sub)
                .bind(rule.created_at.map(|t| t.to_rfc3339()))
                .bind(rule.updated_at.map(|t| t.to_rfc3339()))
                .execute(pool.get_ref())
                .await;

                match result {
                    Ok(_) => imported += 1,
                    Err(e) => {
                        failed += 1;
                        if !request.skip_errors {
                            errors.push(ImportError {
                                line: line_num + 1,
                                rule_text: line.chars().take(100).collect(),
                                error: e.to_string(),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                failed += 1;
                if !request.skip_errors {
                    errors.push(ImportError {
                        line: line_num + 1,
                        rule_text: line.chars().take(100).collect(),
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    // Log audit
    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "ids_ruleset_imported",
        Some("ids_ruleset"),
        None,
        Some(&format!("Imported {} rules, {} failed", imported, failed)),
        None,
    ).await;

    Ok(HttpResponse::Ok().json(ImportRulesetResponse {
        imported,
        failed,
        errors,
    }))
}

/// Validate a rule without saving
pub async fn validate_rule_endpoint(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<ValidateRuleRequest>,
) -> Result<HttpResponse> {
    match parse_rule(&request.rule_text) {
        Ok(rule) => {
            let errors = validate_rule(&rule).unwrap_or_default();
            let valid = !errors.iter().any(|e| {
                matches!(e.severity, crate::scanner::ids::ValidationSeverity::Error)
            });

            Ok(HttpResponse::Ok().json(ValidateRuleResponse {
                valid,
                rule: Some(IdsRuleResponse::from(&rule)),
                errors,
                parse_error: None,
            }))
        }
        Err(e) => {
            Ok(HttpResponse::Ok().json(ValidateRuleResponse {
                valid: false,
                rule: None,
                errors: Vec::new(),
                parse_error: Some(e.to_string()),
            }))
        }
    }
}

/// List rule categories
pub async fn list_categories(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    // Get counts per category
    let counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT category, COUNT(*) as count FROM ids_rules WHERE category IS NOT NULL GROUP BY category"
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let count_map: std::collections::HashMap<String, i64> = counts.into_iter().collect();

    let categories: Vec<RuleCategoryResponse> = RULE_CATEGORIES
        .iter()
        .map(|cat| RuleCategoryResponse {
            id: cat.id.to_string(),
            name: cat.name.to_string(),
            description: cat.description.to_string(),
            rule_count: count_map.get(cat.id).copied().unwrap_or(0),
        })
        .collect();

    Ok(HttpResponse::Ok().json(categories))
}

/// List IDS alerts
pub async fn list_alerts(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    query: web::Query<IdsAlertsQuery>,
) -> Result<HttpResponse> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(200);

    let mut sql = String::from(
        "SELECT id, rule_sid, src_ip, src_port, dst_ip, dst_port,
                protocol, payload_excerpt, timestamp, severity, category
         FROM ids_alerts WHERE 1=1"
    );
    let mut count_sql = String::from("SELECT COUNT(*) FROM ids_alerts WHERE 1=1");

    let mut conditions = Vec::new();

    if let Some(rule_sid) = query.rule_sid {
        conditions.push(format!(" AND rule_sid = {}", rule_sid));
    }
    if let Some(ref src_ip) = query.src_ip {
        conditions.push(format!(" AND src_ip = '{}'", src_ip.replace('\'', "''")));
    }
    if let Some(ref dst_ip) = query.dst_ip {
        conditions.push(format!(" AND dst_ip = '{}'", dst_ip.replace('\'', "''")));
    }
    if let Some(min_severity) = query.min_severity {
        conditions.push(format!(" AND severity <= {}", min_severity)); // Lower number = higher severity
    }
    if let Some(ref category) = query.category {
        conditions.push(format!(" AND category = '{}'", category.replace('\'', "''")));
    }
    if let Some(ref start_time) = query.start_time {
        conditions.push(format!(" AND timestamp >= '{}'", start_time.replace('\'', "''")));
    }
    if let Some(ref end_time) = query.end_time {
        conditions.push(format!(" AND timestamp <= '{}'", end_time.replace('\'', "''")));
    }

    for condition in &conditions {
        sql.push_str(condition);
        count_sql.push_str(condition);
    }

    sql.push_str(" ORDER BY timestamp DESC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    // Get total count
    let total: (i64,) = sqlx::query_as(&count_sql)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or((0,));

    // Fetch alerts
    let rows: Vec<IdsAlertRow> = sqlx::query_as(&sql)
        .fetch_all(pool.get_ref())
        .await
        .unwrap_or_default();

    let alerts: Vec<IdsAlertResponse> = rows
        .into_iter()
        .map(|row| row.into())
        .collect();

    Ok(HttpResponse::Ok().json(PaginatedResponse {
        items: alerts,
        total: total.0,
        offset,
        limit,
    }))
}

/// Load built-in rules into database
pub async fn load_builtin_rules(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let db = RulesDatabase::new();
    let mut imported = 0;

    for rule in db.all_rules() {
        let rule_json = serde_json::to_string(rule).unwrap_or_default();

        let result = sqlx::query(
            r#"
            INSERT INTO ids_rules (
                sid, rev, msg, classtype, priority, rule_text, rule_json,
                enabled, category, user_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sid) DO NOTHING
            "#
        )
        .bind(rule.sid as i64)
        .bind(rule.rev as i32)
        .bind(&rule.msg)
        .bind(rule.classtype.as_ref().map(|c| &c.name))
        .bind(rule.priority.map(|p| p as i32))
        .bind(&rule.raw_rule)
        .bind(&rule_json)
        .bind(rule.enabled)
        .bind(&rule.category)
        .bind(&claims.sub)
        .bind(Utc::now().to_rfc3339())
        .bind(Utc::now().to_rfc3339())
        .execute(pool.get_ref())
        .await;

        if result.is_ok() {
            imported += 1;
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Built-in rules loaded",
        "imported": imported
    })))
}

// =============================================================================
// Database Row Types
// =============================================================================

#[derive(Debug, sqlx::FromRow)]
struct IdsRuleRow {
    sid: i64,
    rev: i32,
    msg: String,
    classtype: Option<String>,
    priority: Option<i32>,
    rule_text: String,
    rule_json: String,
    enabled: bool,
    category: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

impl IdsRuleRow {
    fn to_response(&self) -> anyhow::Result<IdsRuleResponse> {
        let rule: IdsRule = serde_json::from_str(&self.rule_json)?;
        let mut response = IdsRuleResponse::from(&rule);

        // Override with DB values
        response.enabled = self.enabled;
        response.category = self.category.clone();
        if let Some(p) = self.priority {
            response.priority = Some(p as u8);
        }
        if let Some(ref created) = self.created_at {
            response.created_at = chrono::DateTime::parse_from_rfc3339(created)
                .ok()
                .map(|t| t.with_timezone(&Utc));
        }
        if let Some(ref updated) = self.updated_at {
            response.updated_at = chrono::DateTime::parse_from_rfc3339(updated)
                .ok()
                .map(|t| t.with_timezone(&Utc));
        }

        Ok(response)
    }
}

#[derive(Debug, sqlx::FromRow)]
struct IdsAlertRow {
    id: String,
    rule_sid: i64,
    src_ip: Option<String>,
    src_port: Option<i32>,
    dst_ip: Option<String>,
    dst_port: Option<i32>,
    protocol: String,
    payload_excerpt: Option<String>,
    timestamp: String,
    severity: i32,
    category: Option<String>,
}

impl From<IdsAlertRow> for IdsAlertResponse {
    fn from(row: IdsAlertRow) -> Self {
        Self {
            id: row.id,
            rule_sid: row.rule_sid as u64,
            rule_msg: String::new(), // Would need join with rules table
            src_ip: row.src_ip,
            src_port: row.src_port.map(|p| p as u16),
            dst_ip: row.dst_ip,
            dst_port: row.dst_port.map(|p| p as u16),
            protocol: row.protocol,
            payload_excerpt: row.payload_excerpt,
            timestamp: chrono::DateTime::parse_from_rfc3339(&row.timestamp)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            severity: row.severity as u8,
            category: row.category,
        }
    }
}

// =============================================================================
// Route Configuration
// =============================================================================

/// Configure IDS API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/detection/ids")
            .route("/rules", web::post().to(create_rule))
            .route("/rules", web::get().to(list_rules))
            .route("/rules/{sid}", web::get().to(get_rule))
            .route("/rules/{sid}", web::put().to(update_rule))
            .route("/rules/{sid}", web::delete().to(delete_rule))
            .route("/import", web::post().to(import_ruleset))
            .route("/validate", web::post().to(validate_rule_endpoint))
            .route("/categories", web::get().to(list_categories))
            .route("/alerts", web::get().to(list_alerts))
            .route("/builtin", web::post().to(load_builtin_rules))
    );
}
