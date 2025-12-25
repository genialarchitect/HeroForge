//! YARA Scanner API Endpoints
//!
//! This module provides REST API endpoints for YARA-based threat detection:
//! - POST /api/detection/yara/scan - Scan file/bytes with YARA
//! - POST /api/detection/yara/rules - Add custom YARA rule
//! - GET /api/detection/yara/rules - List YARA rules
//! - GET /api/detection/yara/rules/{id} - Get rule details
//! - DELETE /api/detection/yara/rules/{id} - Delete custom rule
//! - POST /api/detection/yara/validate - Validate YARA rule syntax

#![allow(dead_code)]

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::db::yara as db;
use crate::scanner::yara::{
    self, validate_rule, parse_yara_rule_text, YaraMatch, YaraRule,
    YaraScanResult, YaraScanner,
};
use crate::web::auth;

// ============================================================================
// Shared State
// ============================================================================

/// Shared state for YARA scanning
pub struct YaraState {
    /// Active scans by ID
    active_scans: RwLock<HashMap<String, bool>>,
}

impl YaraState {
    pub fn new() -> Self {
        Self {
            active_scans: RwLock::new(HashMap::new()),
        }
    }

    pub async fn start_scan(&self, scan_id: &str) {
        let mut scans = self.active_scans.write().await;
        scans.insert(scan_id.to_string(), true);
    }

    pub async fn end_scan(&self, scan_id: &str) {
        let mut scans = self.active_scans.write().await;
        scans.remove(scan_id);
    }

    pub async fn is_scan_active(&self, scan_id: &str) -> bool {
        let scans = self.active_scans.read().await;
        scans.get(scan_id).copied().unwrap_or(false)
    }
}

impl Default for YaraState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to scan a file or directory
#[derive(Debug, Deserialize)]
pub struct ScanPathRequest {
    pub name: Option<String>,
    pub path: String,
    pub recursive: Option<bool>,
    /// Rule IDs to use (empty = all enabled rules)
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Categories to include
    #[serde(default)]
    pub categories: Vec<String>,
}

/// Request to scan raw bytes (base64 encoded)
#[derive(Debug, Deserialize)]
pub struct ScanBytesRequest {
    pub name: Option<String>,
    pub data: String,  // Base64 encoded
    /// Rule IDs to use (empty = all enabled rules)
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

/// Request to create a custom YARA rule
#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub rule_text: String,
    pub category: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Request to update a YARA rule
#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub rule_text: Option<String>,
    pub category: Option<String>,
    pub enabled: Option<bool>,
}

/// Request to validate YARA rule syntax
#[derive(Debug, Deserialize)]
pub struct ValidateRuleRequest {
    pub rule_text: String,
}

/// Response for scan creation
#[derive(Debug, Serialize)]
pub struct ScanCreatedResponse {
    pub id: String,
    pub message: String,
}

/// Response for scan list
#[derive(Debug, Serialize)]
pub struct ScanListResponse {
    pub scans: Vec<ScanSummary>,
    pub total: i64,
}

/// Scan summary for list view
#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub name: Option<String>,
    pub target_path: String,
    pub target_type: String,
    pub status: String,
    pub matches_count: u32,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub created_at: String,
    pub completed_at: Option<String>,
}

/// Response for scan details
#[derive(Debug, Serialize)]
pub struct ScanDetailResponse {
    pub id: String,
    pub name: Option<String>,
    pub target_path: String,
    pub target_type: String,
    pub status: String,
    pub matches: Vec<MatchResponse>,
    pub matches_count: u32,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub error_message: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Match response
#[derive(Debug, Serialize)]
pub struct MatchResponse {
    pub id: String,
    pub rule_name: String,
    pub file_path: Option<String>,
    pub matched_strings: Vec<MatchedStringResponse>,
    pub metadata: serde_json::Value,
    pub tags: Vec<String>,
}

/// Matched string response
#[derive(Debug, Serialize)]
pub struct MatchedStringResponse {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: String,
}

/// Response for rule list
#[derive(Debug, Serialize)]
pub struct RuleListResponse {
    pub rules: Vec<RuleResponse>,
    pub total: i64,
}

/// Rule response
#[derive(Debug, Serialize)]
pub struct RuleResponse {
    pub id: String,
    pub name: String,
    pub rule_text: String,
    pub metadata: serde_json::Value,
    pub is_builtin: bool,
    pub category: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

/// Response for rule validation
#[derive(Debug, Serialize)]
pub struct ValidationResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Query parameters for scans
#[derive(Debug, Deserialize)]
pub struct ScanQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Query parameters for rules
#[derive(Debug, Deserialize)]
pub struct RuleQuery {
    pub include_builtin: Option<bool>,
    pub category: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Scan result for immediate scans
#[derive(Debug, Serialize)]
pub struct ImmediateScanResponse {
    pub matches: Vec<MatchResponse>,
    pub scan_time_ms: u64,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
}

// ============================================================================
// API Handlers - Scans
// ============================================================================

/// Start a YARA scan on a path
pub async fn scan_path(
    pool: web::Data<SqlitePool>,
    state: web::Data<Arc<YaraState>>,
    claims: auth::Claims,
    req: web::Json<ScanPathRequest>,
) -> Result<HttpResponse> {
    // Validate path exists
    let path = std::path::Path::new(&req.path);
    if !path.exists() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Path does not exist"
        })));
    }

    let target_type = if path.is_dir() { "directory" } else { "file" };
    let recursive = req.recursive.unwrap_or(true);

    // Get rules to use
    let rule_ids: Vec<String> = if req.rule_ids.is_empty() {
        // Get all enabled rules
        let rules = db::get_enabled_yara_rules(pool.get_ref(), Some(&claims.sub)).await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        rules.into_iter().map(|r| r.id).collect()
    } else {
        req.rule_ids.clone()
    };

    // Create scan record
    let scan_id = db::create_yara_scan(
        pool.get_ref(),
        &claims.sub,
        req.name.as_deref(),
        &req.path,
        target_type,
        recursive,
        &rule_ids,
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Start scan in background
    let pool_clone = pool.get_ref().clone();
    let state_clone = state.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let path_clone = req.path.clone();
    let user_id = claims.sub.clone();

    tokio::spawn(async move {
        state_clone.start_scan(&scan_id_clone).await;

        // Update status to running
        let _ = db::update_yara_scan_status(&pool_clone, &scan_id_clone, db::YaraScanStatus::Running, None).await;

        // Load rules
        let rules = match load_rules_for_scan(&pool_clone, Some(&user_id)).await {
            Ok(r) => r,
            Err(e) => {
                let _ = db::update_yara_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    db::YaraScanStatus::Failed,
                    Some(&e.to_string()),
                ).await;
                state_clone.end_scan(&scan_id_clone).await;
                return;
            }
        };

        // Create scanner and run
        let mut scanner = YaraScanner::new();
        scanner.add_rules(rules);

        let path = std::path::Path::new(&path_clone);
        let result = if path.is_dir() {
            scanner.scan_directory(&path_clone, recursive).await
        } else {
            match scanner.scan_file(&path_clone).await {
                Ok(matches) => {
                    let files_matched = if matches.is_empty() { 0 } else { 1 };
                    Ok(YaraScanResult {
                        matches,
                        scan_time: std::time::Duration::from_secs(0),
                        stats: yara::YaraScanStats {
                            files_scanned: 1,
                            files_matched,
                            bytes_scanned: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                            ..Default::default()
                        },
                        errors: Vec::new(),
                    })
                }
                Err(e) => Err(e),
            }
        };

        match result {
            Ok(scan_result) => {
                // Save matches
                let _ = db::save_yara_matches(&pool_clone, &scan_id_clone, &scan_result.matches).await;

                // Update stats
                let _ = db::update_yara_scan_stats(
                    &pool_clone,
                    &scan_id_clone,
                    scan_result.matches.len() as u32,
                    scan_result.stats.files_scanned,
                    scan_result.stats.bytes_scanned,
                ).await;

                // Update status
                let _ = db::update_yara_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    db::YaraScanStatus::Completed,
                    None,
                ).await;

                log::info!(
                    "YARA scan {} completed: {} matches in {} files",
                    scan_id_clone, scan_result.matches.len(), scan_result.stats.files_scanned
                );
            }
            Err(e) => {
                let _ = db::update_yara_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    db::YaraScanStatus::Failed,
                    Some(&e.to_string()),
                ).await;
                log::error!("YARA scan {} failed: {}", scan_id_clone, e);
            }
        }

        state_clone.end_scan(&scan_id_clone).await;
    });

    Ok(HttpResponse::Accepted().json(ScanCreatedResponse {
        id: scan_id,
        message: "YARA scan started".to_string(),
    }))
}

/// Scan bytes (base64 encoded)
pub async fn scan_bytes(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    req: web::Json<ScanBytesRequest>,
) -> Result<HttpResponse> {
    // Decode base64
    let data = STANDARD.decode(&req.data)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid base64: {}", e)))?;

    // Load rules
    let rules = load_rules_for_scan(pool.get_ref(), Some(&claims.sub)).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Create scanner and run
    let mut scanner = YaraScanner::new();
    scanner.add_rules(rules);

    let start = std::time::Instant::now();
    let matches = scanner.scan_bytes(&data).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let response = ImmediateScanResponse {
        matches: matches.iter().map(|m| convert_match(m)).collect(),
        scan_time_ms: start.elapsed().as_millis() as u64,
        files_scanned: 1,
        bytes_scanned: data.len() as u64,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Scan uploaded file
pub async fn scan_upload(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    mut payload: Multipart,
) -> Result<HttpResponse> {
    let mut file_data = Vec::new();

    while let Some(item) = payload.next().await {
        let mut field = item.map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;
            file_data.extend_from_slice(&data);
        }
    }

    if file_data.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No file data received"
        })));
    }

    // Load rules
    let rules = load_rules_for_scan(pool.get_ref(), Some(&claims.sub)).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Create scanner and run
    let mut scanner = YaraScanner::new();
    scanner.add_rules(rules);

    let start = std::time::Instant::now();
    let matches = scanner.scan_bytes(&file_data).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let response = ImmediateScanResponse {
        matches: matches.iter().map(|m| convert_match(m)).collect(),
        scan_time_ms: start.elapsed().as_millis() as u64,
        files_scanned: 1,
        bytes_scanned: file_data.len() as u64,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// List YARA scans
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<ScanQuery>,
) -> Result<HttpResponse> {
    let scans = db::get_user_yara_scans(pool.get_ref(), &claims.sub, query.limit, query.offset)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let total = db::count_user_yara_scans(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let summaries: Vec<ScanSummary> = scans
        .into_iter()
        .map(|s| ScanSummary {
            id: s.id,
            name: s.name,
            target_path: s.target_path,
            target_type: s.target_type,
            status: s.status.to_string(),
            matches_count: s.matches_count,
            files_scanned: s.files_scanned,
            bytes_scanned: s.bytes_scanned,
            created_at: s.created_at.to_rfc3339(),
            completed_at: s.completed_at.map(|dt| dt.to_rfc3339()),
        })
        .collect();

    Ok(HttpResponse::Ok().json(ScanListResponse {
        scans: summaries,
        total,
    }))
}

/// Get scan details
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    query: web::Query<ScanQuery>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    let scan = db::get_yara_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match scan {
        Some(s) => {
            // Check ownership
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            // Get matches
            let matches = db::get_yara_matches(pool.get_ref(), &scan_id, query.limit, query.offset)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            let match_responses: Vec<MatchResponse> = matches
                .into_iter()
                .map(|m| {
                    let matched_strings: Vec<yara::MatchedString> =
                        serde_json::from_str(&m.matched_strings).unwrap_or_default();
                    let metadata: serde_json::Value =
                        serde_json::from_str(&m.metadata).unwrap_or(serde_json::json!({}));
                    let tags: Vec<String> =
                        serde_json::from_str(&m.tags).unwrap_or_default();

                    MatchResponse {
                        id: m.id,
                        rule_name: m.rule_name,
                        file_path: m.file_path,
                        matched_strings: matched_strings.iter().map(|ms| MatchedStringResponse {
                            identifier: ms.identifier.clone(),
                            offset: ms.offset,
                            length: ms.length,
                            data: ms.data.clone(),
                        }).collect(),
                        metadata,
                        tags,
                    }
                })
                .collect();

            Ok(HttpResponse::Ok().json(ScanDetailResponse {
                id: s.id,
                name: s.name,
                target_path: s.target_path,
                target_type: s.target_type,
                status: s.status.to_string(),
                matches: match_responses,
                matches_count: s.matches_count,
                files_scanned: s.files_scanned,
                bytes_scanned: s.bytes_scanned,
                error_message: s.error_message,
                created_at: s.created_at.to_rfc3339(),
                started_at: s.started_at.map(|dt| dt.to_rfc3339()),
                completed_at: s.completed_at.map(|dt| dt.to_rfc3339()),
            }))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

/// Delete a scan
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    // Check ownership
    let scan = db::get_yara_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match scan {
        Some(s) => {
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            db::delete_yara_scan(pool.get_ref(), &scan_id)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Scan deleted"
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        }))),
    }
}

// ============================================================================
// API Handlers - Rules
// ============================================================================

/// List YARA rules
pub async fn list_rules(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<RuleQuery>,
) -> Result<HttpResponse> {
    let include_builtin = query.include_builtin.unwrap_or(true);

    let rules = db::list_yara_rules(
        pool.get_ref(),
        include_builtin,
        Some(&claims.sub),
        query.category.as_deref(),
        query.limit,
        query.offset,
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let total = db::count_yara_rules(pool.get_ref(), Some(&claims.sub), include_builtin)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let rule_responses: Vec<RuleResponse> = rules
        .into_iter()
        .map(|r| {
            let metadata: serde_json::Value =
                serde_json::from_str(&r.metadata).unwrap_or(serde_json::json!({}));
            RuleResponse {
                id: r.id,
                name: r.name,
                rule_text: r.rule_text,
                metadata,
                is_builtin: r.is_builtin,
                category: r.category,
                enabled: r.enabled,
                created_at: r.created_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(RuleListResponse {
        rules: rule_responses,
        total,
    }))
}

/// Get rule details
pub async fn get_rule(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let rule_id = path.into_inner();

    let rule = db::get_yara_rule(pool.get_ref(), &rule_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match rule {
        Some(r) => {
            // Check access - allow access to builtin rules or user's own rules
            if !r.is_builtin && r.user_id.as_ref() != Some(&claims.sub) {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            let metadata: serde_json::Value =
                serde_json::from_str(&r.metadata).unwrap_or(serde_json::json!({}));

            Ok(HttpResponse::Ok().json(RuleResponse {
                id: r.id,
                name: r.name,
                rule_text: r.rule_text,
                metadata,
                is_builtin: r.is_builtin,
                category: r.category,
                enabled: r.enabled,
                created_at: r.created_at.to_rfc3339(),
            }))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found"
        }))),
    }
}

/// Create a custom YARA rule
pub async fn create_rule(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    req: web::Json<CreateRuleRequest>,
) -> Result<HttpResponse> {
    // Validate rule syntax
    let validation = validate_rule(&req.rule_text);
    if !validation.valid {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid YARA rule syntax",
            "details": validation.errors
        })));
    }

    // Check if rule name already exists
    let existing = db::get_yara_rule_by_name(pool.get_ref(), &req.name)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    if existing.is_some() {
        return Ok(HttpResponse::Conflict().json(serde_json::json!({
            "error": "A rule with this name already exists"
        })));
    }

    // Parse rule to extract metadata
    let parsed = parse_yara_rule_text(&req.rule_text)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Failed to parse rule: {}", e)))?;

    let metadata_json = serde_json::to_string(&parsed.metadata)
        .unwrap_or_else(|_| "{}".to_string());

    // Create rule
    let rule_id = db::create_yara_rule(
        pool.get_ref(),
        &req.name,
        &req.rule_text,
        &metadata_json,
        false,
        Some(&claims.sub),
        req.category.as_deref(),
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": rule_id,
        "message": "Rule created successfully",
        "warnings": validation.warnings
    })))
}

/// Update a custom YARA rule
pub async fn update_rule(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    req: web::Json<UpdateRuleRequest>,
) -> Result<HttpResponse> {
    let rule_id = path.into_inner();

    // Check ownership
    let rule = db::get_yara_rule(pool.get_ref(), &rule_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match rule {
        Some(r) => {
            if r.is_builtin {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot modify builtin rules"
                })));
            }

            if r.user_id.as_ref() != Some(&claims.sub) {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            // Validate new rule text if provided
            if let Some(rule_text) = &req.rule_text {
                let validation = validate_rule(rule_text);
                if !validation.valid {
                    return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "Invalid YARA rule syntax",
                        "details": validation.errors
                    })));
                }
            }

            // Update rule
            let updated = db::update_yara_rule(
                pool.get_ref(),
                &rule_id,
                req.name.as_deref(),
                req.rule_text.as_deref(),
                None,
                req.category.as_deref(),
                req.enabled,
            )
            .await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            if updated {
                Ok(HttpResponse::Ok().json(serde_json::json!({
                    "message": "Rule updated successfully"
                })))
            } else {
                Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update rule"
                })))
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found"
        }))),
    }
}

/// Delete a custom YARA rule
pub async fn delete_rule(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let rule_id = path.into_inner();

    // Check ownership
    let rule = db::get_yara_rule(pool.get_ref(), &rule_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match rule {
        Some(r) => {
            if r.is_builtin {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot delete builtin rules"
                })));
            }

            if r.user_id.as_ref() != Some(&claims.sub) {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            db::delete_yara_rule(pool.get_ref(), &rule_id)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "Rule deleted"
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found"
        }))),
    }
}

/// Validate YARA rule syntax
pub async fn validate_rule_endpoint(
    _claims: auth::Claims,
    req: web::Json<ValidateRuleRequest>,
) -> Result<HttpResponse> {
    let validation = validate_rule(&req.rule_text);

    Ok(HttpResponse::Ok().json(ValidationResponse {
        valid: validation.valid,
        errors: validation.errors,
        warnings: validation.warnings,
    }))
}

/// Get rule categories
pub async fn get_categories(
    _pool: web::Data<SqlitePool>,
    _claims: auth::Claims,
) -> Result<HttpResponse> {
    // Get categories from builtin rules
    use crate::scanner::yara::rules::get_all_categories;

    let categories: Vec<String> = get_all_categories()
        .iter()
        .map(|c| c.to_string())
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "categories": categories
    })))
}

/// Get builtin rule statistics
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse> {
    let total_rules = db::count_yara_rules(pool.get_ref(), Some(&claims.sub), true)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let custom_rules = db::count_yara_rules(pool.get_ref(), Some(&claims.sub), false)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let total_scans = db::count_user_yara_scans(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    use crate::scanner::yara::rules::get_rule_counts;
    let category_counts = get_rule_counts();

    let categories: HashMap<String, usize> = category_counts
        .iter()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_rules": total_rules,
        "builtin_rules": total_rules - custom_rules,
        "custom_rules": custom_rules,
        "total_scans": total_scans,
        "categories": categories
    })))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Load rules for scanning
async fn load_rules_for_scan(pool: &SqlitePool, user_id: Option<&str>) -> anyhow::Result<Vec<YaraRule>> {
    let stored_rules = db::get_enabled_yara_rules(pool, user_id).await?;

    let mut rules = Vec::new();
    for stored in stored_rules {
        if let Ok(rule) = parse_yara_rule_text(&stored.rule_text) {
            rules.push(rule);
        }
    }

    // If no rules from DB, use builtin
    if rules.is_empty() {
        rules = crate::scanner::yara::rules::get_builtin_rules();
    }

    Ok(rules)
}

/// Convert YaraMatch to MatchResponse
fn convert_match(m: &YaraMatch) -> MatchResponse {
    MatchResponse {
        id: uuid::Uuid::new_v4().to_string(),
        rule_name: m.rule_name.clone(),
        file_path: m.file_path.clone(),
        matched_strings: m.matched_strings.iter().map(|ms| MatchedStringResponse {
            identifier: ms.identifier.clone(),
            offset: ms.offset,
            length: ms.length,
            data: ms.data.clone(),
        }).collect(),
        metadata: serde_json::to_value(&m.metadata).unwrap_or(serde_json::json!({})),
        tags: m.tags.clone(),
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure YARA API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/detection/yara")
            // Scans
            .route("/scan", web::post().to(scan_path))
            .route("/scan/bytes", web::post().to(scan_bytes))
            .route("/scan/upload", web::post().to(scan_upload))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            // Rules
            .route("/rules", web::get().to(list_rules))
            .route("/rules", web::post().to(create_rule))
            .route("/rules/categories", web::get().to(get_categories))
            .route("/rules/stats", web::get().to(get_stats))
            .route("/rules/{id}", web::get().to(get_rule))
            .route("/rules/{id}", web::put().to(update_rule))
            .route("/rules/{id}", web::delete().to(delete_rule))
            // Validation
            .route("/validate", web::post().to(validate_rule_endpoint)),
    );
}
