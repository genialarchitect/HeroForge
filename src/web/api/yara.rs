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
    /// CRM customer ID
    pub customer_id: Option<String>,
    /// CRM engagement ID
    pub engagement_id: Option<String>,
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
    pub description: Option<String>,
    pub rule_text: String,
    pub category: String,
    pub severity: Option<String>,
    pub enabled: bool,
    pub is_builtin: bool,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
    pub match_count: i64,
    pub created_at: String,
    pub updated_at: String,
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
// Visual Rule Builder Types
// ============================================================================

/// Request to build a rule from visual components
#[derive(Debug, Deserialize)]
pub struct BuildRuleRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: Vec<MetadataEntry>,
    pub strings: Vec<StringDefinition>,
    pub condition: ConditionSpec,
}

/// Metadata key-value entry
#[derive(Debug, Deserialize)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
}

/// String definition for visual builder
#[derive(Debug, Deserialize)]
pub struct StringDefinition {
    pub identifier: String,
    pub string_type: StringType,
    pub value: String,
    #[serde(default)]
    pub modifiers: StringModifiers,
}

/// Type of YARA string
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringType {
    Text,
    Hex,
    Regex,
}

/// String modifiers
#[derive(Debug, Default, Deserialize)]
pub struct StringModifiers {
    #[serde(default)]
    pub nocase: bool,
    #[serde(default)]
    pub wide: bool,
    #[serde(default)]
    pub ascii: bool,
    #[serde(default)]
    pub fullword: bool,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub xor: bool,
    #[serde(default)]
    pub base64: bool,
}

/// Condition specification
#[derive(Debug, Deserialize)]
pub struct ConditionSpec {
    pub condition_type: ConditionType,
    pub count: Option<u32>,
    pub custom_expression: Option<String>,
}

/// Condition type
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionType {
    All,
    Any,
    Count,
    Custom,
}

/// Response for built rule
#[derive(Debug, Serialize)]
pub struct BuildRuleResponse {
    pub rule_text: String,
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

// ============================================================================
// Community Sources Types
// ============================================================================

/// Response for community sources list
#[derive(Debug, Serialize)]
pub struct CommunitySourcesResponse {
    pub sources: Vec<CommunitySourceInfo>,
}

/// Community source information
#[derive(Debug, Serialize)]
pub struct CommunitySourceInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub source_type: String,
    pub enabled: bool,
    pub auto_update: bool,
    pub rules_count: u32,
    pub last_updated_at: Option<String>,
}

/// Request to import rules from content
#[derive(Debug, Deserialize)]
pub struct ImportRulesRequest {
    pub content: String,
    pub source: Option<String>,
    pub category: Option<String>,
    #[serde(default)]
    pub overwrite_existing: bool,
}

/// Response for rule import
#[derive(Debug, Serialize)]
pub struct ImportRulesResponse {
    pub total_rules: u32,
    pub imported: u32,
    pub skipped: u32,
    pub errors: Vec<ImportError>,
    pub rules: Vec<ImportedRuleSummary>,
}

/// Import error
#[derive(Debug, Serialize)]
pub struct ImportError {
    pub rule_name: Option<String>,
    pub line: Option<u32>,
    pub message: String,
}

/// Summary of imported rule
#[derive(Debug, Serialize)]
pub struct ImportedRuleSummary {
    pub id: String,
    pub name: String,
    pub category: String,
}

/// Request to fetch from community source
#[derive(Debug, Deserialize)]
pub struct FetchCommunityRequest {
    pub source_id: String,
}

// ============================================================================
// Bulk Scan Types
// ============================================================================

/// Request for bulk scan
#[derive(Debug, Deserialize)]
pub struct BulkScanRequest {
    pub name: Option<String>,
    pub paths: Vec<String>,
    pub recursive: Option<bool>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    /// CRM customer ID
    pub customer_id: Option<String>,
    /// CRM engagement ID
    pub engagement_id: Option<String>,
}

/// Response for bulk scan status
#[derive(Debug, Serialize)]
pub struct BulkScanResponse {
    pub id: String,
    pub name: Option<String>,
    pub status: String,
    pub total_paths: u32,
    pub completed_paths: u32,
    pub total_matches: u32,
    pub total_files_scanned: u64,
    pub total_bytes_scanned: u64,
}

// ============================================================================
// API Handlers - Scans
// ============================================================================

/// Start a YARA scan on a path
pub async fn scan_path(
    pool: web::Data<SqlitePool>,
    state: web::Data<YaraState>,
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
        req.customer_id.as_deref(),
        req.engagement_id.as_deref(),
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Start scan in background
    let pool_clone = pool.get_ref().clone();
    let state_clone = state.into_inner();
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

    // Get match counts for all rules in this batch
    let rule_ids: Vec<String> = rules.iter().map(|r| r.id.clone()).collect();
    let match_counts = db::get_rule_match_counts(pool.get_ref(), &rule_ids)
        .await
        .unwrap_or_default();

    let rule_responses: Vec<RuleResponse> = rules
        .into_iter()
        .map(|r| {
            let metadata: serde_json::Value =
                serde_json::from_str(&r.metadata).unwrap_or(serde_json::json!({}));

            // Extract fields from metadata
            let description = metadata.get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let severity = metadata.get("severity")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let tags: Vec<String> = metadata.get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            // Get actual match count for this rule
            let match_count = match_counts.get(&r.id).copied().unwrap_or(0);

            RuleResponse {
                id: r.id,
                name: r.name,
                description,
                rule_text: r.rule_text,
                category: r.category.unwrap_or_else(|| "generic".to_string()),
                severity,
                enabled: r.enabled,
                is_builtin: r.is_builtin,
                tags,
                metadata,
                match_count,
                created_at: r.created_at.to_rfc3339(),
                updated_at: r.updated_at.to_rfc3339(),
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

            // Get actual match count for this rule
            let match_count = db::count_rule_matches(pool.get_ref(), &r.id)
                .await
                .unwrap_or(0);

            let metadata: serde_json::Value =
                serde_json::from_str(&r.metadata).unwrap_or(serde_json::json!({}));

            // Extract fields from metadata
            let description = metadata.get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let severity = metadata.get("severity")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let tags: Vec<String> = metadata.get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            Ok(HttpResponse::Ok().json(RuleResponse {
                id: r.id,
                name: r.name,
                description,
                rule_text: r.rule_text,
                category: r.category.unwrap_or_else(|| "generic".to_string()),
                severity,
                enabled: r.enabled,
                is_builtin: r.is_builtin,
                tags,
                metadata,
                match_count,
                created_at: r.created_at.to_rfc3339(),
                updated_at: r.updated_at.to_rfc3339(),
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
    let existing = db::get_yara_rule_by_name(pool.get_ref(), &req.name, Some(&claims.sub))
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
// Visual Rule Builder Handlers
// ============================================================================

/// Build a YARA rule from visual components
pub async fn build_rule(
    _claims: auth::Claims,
    req: web::Json<BuildRuleRequest>,
) -> Result<HttpResponse> {
    // Build the rule text from components
    let mut rule_text = String::new();

    // Rule declaration with tags
    if req.tags.is_empty() {
        rule_text.push_str(&format!("rule {} {{\n", req.name));
    } else {
        rule_text.push_str(&format!("rule {} : {} {{\n", req.name, req.tags.join(" ")));
    }

    // Metadata section
    if req.description.is_some() || !req.metadata.is_empty() {
        rule_text.push_str("    meta:\n");
        if let Some(desc) = &req.description {
            rule_text.push_str(&format!("        description = \"{}\"\n", escape_yara_string(desc)));
        }
        for entry in &req.metadata {
            rule_text.push_str(&format!("        {} = \"{}\"\n", entry.key, escape_yara_string(&entry.value)));
        }
    }

    // Strings section
    if !req.strings.is_empty() {
        rule_text.push_str("    strings:\n");
        for s in &req.strings {
            let value_str = match s.string_type {
                StringType::Text => format!("\"{}\"", escape_yara_string(&s.value)),
                StringType::Hex => format!("{{ {} }}", s.value),
                StringType::Regex => format!("/{}/", s.value),
            };

            let mut modifiers = Vec::new();
            if s.modifiers.nocase { modifiers.push("nocase"); }
            if s.modifiers.wide { modifiers.push("wide"); }
            if s.modifiers.ascii { modifiers.push("ascii"); }
            if s.modifiers.fullword { modifiers.push("fullword"); }
            if s.modifiers.private { modifiers.push("private"); }
            if s.modifiers.xor { modifiers.push("xor"); }
            if s.modifiers.base64 { modifiers.push("base64"); }

            if modifiers.is_empty() {
                rule_text.push_str(&format!("        {} = {}\n", s.identifier, value_str));
            } else {
                rule_text.push_str(&format!("        {} = {} {}\n", s.identifier, value_str, modifiers.join(" ")));
            }
        }
    }

    // Condition section
    rule_text.push_str("    condition:\n");
    let condition = match req.condition.condition_type {
        ConditionType::All => "all of them".to_string(),
        ConditionType::Any => "any of them".to_string(),
        ConditionType::Count => format!("{} of them", req.condition.count.unwrap_or(1)),
        ConditionType::Custom => req.condition.custom_expression.clone().unwrap_or_else(|| "any of them".to_string()),
    };
    rule_text.push_str(&format!("        {}\n", condition));

    rule_text.push_str("}\n");

    // Validate the generated rule
    let validation = validate_rule(&rule_text);

    Ok(HttpResponse::Ok().json(BuildRuleResponse {
        rule_text,
        valid: validation.valid,
        errors: validation.errors,
        warnings: validation.warnings,
    }))
}

/// Escape special characters in a string for YARA
fn escape_yara_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

// ============================================================================
// Community Sources Handlers
// ============================================================================

/// Get list of community rule sources
pub async fn get_community_sources(
    _claims: auth::Claims,
) -> Result<HttpResponse> {
    use crate::malware_analysis::yara::get_default_community_sources;

    let sources = get_default_community_sources();
    let response: Vec<CommunitySourceInfo> = sources.iter().map(|s| CommunitySourceInfo {
        id: s.id.clone(),
        name: s.name.clone(),
        description: s.description.clone(),
        url: s.url.clone(),
        source_type: format!("{:?}", s.source_type).to_lowercase(),
        enabled: s.enabled,
        auto_update: s.auto_update,
        rules_count: s.rules_count,
        last_updated_at: s.last_updated_at.map(|d| d.to_rfc3339()),
    }).collect();

    Ok(HttpResponse::Ok().json(CommunitySourcesResponse { sources: response }))
}

/// Fetch rules from a community source
pub async fn fetch_community_source(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    use crate::malware_analysis::yara::{get_default_community_sources, CommunityRuleFetcher};

    let source_id = path.into_inner();
    let sources = get_default_community_sources();

    let source = sources.iter()
        .find(|s| s.id == source_id)
        .ok_or_else(|| actix_web::error::ErrorNotFound("Community source not found"))?;

    let fetcher = CommunityRuleFetcher::new();
    let rules = fetcher.fetch_rules(source).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Failed to fetch rules: {}", e)))?;

    // Import the fetched rules
    let mut imported = 0u32;
    let mut skipped = 0u32;
    let mut errors = Vec::new();
    let mut imported_rules = Vec::new();

    for rule in &rules {
        let rule_id = uuid::Uuid::new_v4().to_string();

        // Check if rule already exists by name
        let existing = db::get_yara_rule_by_name(pool.get_ref(), &rule.name, Some(&claims.sub)).await;

        if existing.is_ok() {
            skipped += 1;
            continue;
        }

        // Create the rule
        let category_str = rule.category.to_string();
        match db::create_yara_rule(
            pool.get_ref(),
            &rule.name,
            &rule.rule_content,
            "{}",
            false,
            Some(&claims.sub),
            Some(category_str.as_str()),
        ).await {
            Ok(created_id) => {
                imported += 1;
                imported_rules.push(ImportedRuleSummary {
                    id: created_id,
                    name: rule.name.clone(),
                    category: category_str,
                });
            }
            Err(e) => {
                errors.push(ImportError {
                    rule_name: Some(rule.name.clone()),
                    line: None,
                    message: e.to_string(),
                });
            }
        }
    }

    Ok(HttpResponse::Ok().json(ImportRulesResponse {
        total_rules: rules.len() as u32,
        imported,
        skipped,
        errors,
        rules: imported_rules,
    }))
}

/// Import rules from content
pub async fn import_rules(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    req: web::Json<ImportRulesRequest>,
) -> Result<HttpResponse> {
    use crate::malware_analysis::yara::import_rules_from_content;
    use crate::malware_analysis::yara::types::{RuleSource, YaraCategory};

    // Parse source type
    let source = match req.source.as_deref() {
        Some("custom") | None => RuleSource::Custom,
        Some("community") => RuleSource::Community,
        Some("imported") => RuleSource::Imported,
        _ => RuleSource::Custom,
    };

    // Parse category override
    let category_override = req.category.as_ref().and_then(|c| {
        match c.to_lowercase().as_str() {
            "malware" => Some(YaraCategory::Malware),
            "packer" => Some(YaraCategory::Packer),
            "webshell" => Some(YaraCategory::Webshell),
            "exploit" => Some(YaraCategory::Exploit),
            "ransomware" => Some(YaraCategory::Ransomware),
            "rat" => Some(YaraCategory::Rat),
            "apt" => Some(YaraCategory::Apt),
            "backdoor" => Some(YaraCategory::Backdoor),
            "miner" => Some(YaraCategory::Miner),
            "stealer" => Some(YaraCategory::Stealer),
            _ => Some(YaraCategory::Generic),
        }
    });

    let import_result = import_rules_from_content(&req.content, source, category_override);

    // Import the parsed rules into the database
    let mut imported = 0u32;
    let mut skipped = 0u32;
    let mut errors = Vec::new();
    let mut imported_rules = Vec::new();

    for rule in &import_result.rules {
        let rule_id = uuid::Uuid::new_v4().to_string();

        // Check if rule already exists by name
        let existing = db::get_yara_rule_by_name(pool.get_ref(), &rule.name, Some(&claims.sub)).await;

        if existing.is_ok() && !req.overwrite_existing {
            skipped += 1;
            continue;
        }

        // If overwriting, delete the old rule first
        if existing.is_ok() && req.overwrite_existing {
            let _ = db::delete_yara_rule_by_name(pool.get_ref(), &rule.name, &claims.sub).await;
        }

        // Create the rule
        let cat_str = rule.category.to_string();
        match db::create_yara_rule(
            pool.get_ref(),
            &rule.name,
            &rule.rule_content,
            "{}",
            false,
            Some(&claims.sub),
            Some(cat_str.as_str()),
        ).await {
            Ok(created_id) => {
                imported += 1;
                imported_rules.push(ImportedRuleSummary {
                    id: created_id,
                    name: rule.name.clone(),
                    category: cat_str,
                });
            }
            Err(e) => {
                errors.push(ImportError {
                    rule_name: Some(rule.name.clone()),
                    line: None,
                    message: e.to_string(),
                });
            }
        }
    }

    Ok(HttpResponse::Ok().json(ImportRulesResponse {
        total_rules: import_result.total_rules,
        imported,
        skipped,
        errors,
        rules: imported_rules,
    }))
}

// ============================================================================
// Bulk Scan Handlers
// ============================================================================

/// Start a bulk scan on multiple paths
pub async fn bulk_scan(
    pool: web::Data<SqlitePool>,
    state: web::Data<YaraState>,
    claims: auth::Claims,
    req: web::Json<BulkScanRequest>,
) -> Result<HttpResponse> {
    // Validate paths exist
    for path in &req.paths {
        let p = std::path::Path::new(path);
        if !p.exists() {
            return Err(actix_web::error::ErrorBadRequest(format!(
                "Path does not exist: {}", path
            )));
        }
    }

    // Get rule IDs to use
    let rule_ids: Vec<String> = if req.rule_ids.is_empty() {
        // Get all enabled rules
        let rules = db::get_enabled_yara_rules(pool.get_ref(), Some(&claims.sub)).await
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        rules.into_iter().map(|r| r.id).collect()
    } else {
        req.rule_ids.clone()
    };

    let recursive = req.recursive.unwrap_or(false);
    let paths_json = serde_json::to_string(&req.paths).unwrap_or_default();

    // Create bulk scan record
    let scan_id = db::create_yara_scan(
        pool.get_ref(),
        &claims.sub,
        req.name.as_deref(),
        &paths_json,
        "bulk",
        recursive,
        &rule_ids,
        req.customer_id.as_deref(),
        req.engagement_id.as_deref(),
    ).await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Mark scan as active
    state.start_scan(&scan_id).await;

    // Clone necessary data for async task
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let paths = req.paths.clone();
    let user_id = claims.sub.clone();

    // Spawn async scan task
    tokio::spawn(async move {
        let rules = match load_rules_for_scan(&pool_clone, Some(&user_id)).await {
            Ok(r) => r,
            Err(e) => {
                let _ = db::update_yara_scan_error(&pool_clone, &scan_id_clone, &e.to_string()).await;
                return;
            }
        };

        let mut scanner = YaraScanner::new();
        scanner.add_rules(rules);

        let mut total_matches = 0u32;
        let mut total_files = 0u64;
        let mut total_bytes = 0u64;
        let mut all_matches = Vec::new();

        for path in &paths {
            let p = std::path::Path::new(path);
            if p.is_dir() {
                match scanner.scan_directory(path, recursive).await {
                    Ok(result) => {
                        total_files += result.stats.files_scanned;
                        total_bytes += result.stats.bytes_scanned;
                        total_matches += result.matches.len() as u32;
                        all_matches.extend(result.matches);
                    }
                    Err(e) => {
                        log::warn!("Error scanning {}: {}", path, e);
                    }
                }
            } else {
                match scanner.scan_file(path).await {
                    Ok(matches) => {
                        total_files += 1;
                        total_matches += matches.len() as u32;
                        all_matches.extend(matches);
                    }
                    Err(e) => {
                        log::warn!("Error scanning {}: {}", path, e);
                    }
                }
            }
        }

        // Save matches to database
        for m in &all_matches {
            let match_id = uuid::Uuid::new_v4().to_string();
            let _ = db::create_yara_match(
                &pool_clone,
                &match_id,
                &scan_id_clone,
                &m.rule_name,
                m.file_path.as_deref(),
                &m.matched_strings.iter().map(|s| s.identifier.clone()).collect::<Vec<_>>().join(", "),
                &serde_json::to_string(&m.metadata).unwrap_or_default(),
            ).await;
        }

        // Update scan completion
        let _ = db::complete_yara_scan(
            &pool_clone,
            &scan_id_clone,
            total_matches as i64,
            total_files as i64,
            total_bytes as i64,
        ).await;
    });

    Ok(HttpResponse::Accepted().json(ScanCreatedResponse {
        id: scan_id,
        message: "Bulk scan started".to_string(),
    }))
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
// Memory Scanning Types and Handlers
// ============================================================================

/// Request to scan a memory dump file
#[derive(Debug, Deserialize)]
pub struct MemoryScanRequest {
    /// Path to the memory dump file
    pub path: String,
    /// Name for the scan
    pub name: Option<String>,
    /// Rule IDs to use (empty = all enabled rules)
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Scan options
    #[serde(default)]
    pub options: MemoryScanOptionsRequest,
    /// CRM customer ID
    pub customer_id: Option<String>,
    /// CRM engagement ID
    pub engagement_id: Option<String>,
}

/// Memory scan options request
#[derive(Debug, Default, Deserialize)]
pub struct MemoryScanOptionsRequest {
    pub max_region_size: Option<u64>,
    pub min_region_size: Option<u64>,
    pub only_executable: Option<bool>,
    pub only_writable: Option<bool>,
    pub calculate_entropy: Option<bool>,
    pub flag_rwx_regions: Option<bool>,
}

/// Memory scan result response
#[derive(Debug, Serialize)]
pub struct MemoryScanResponse {
    pub id: String,
    pub format: String,
    pub dump_size: u64,
    pub region_count: usize,
    pub bytes_scanned: u64,
    pub matches: Vec<MemoryMatchResponse>,
    pub suspicious_regions: Vec<MemoryRegionResponse>,
    pub scan_time_ms: u64,
    pub errors: Vec<String>,
}

/// Memory match response
#[derive(Debug, Serialize)]
pub struct MemoryMatchResponse {
    pub rule_name: String,
    pub region: MemoryRegionResponse,
    pub matched_strings: Vec<MemoryMatchedStringResponse>,
    pub tags: Vec<String>,
}

/// Memory region response
#[derive(Debug, Serialize)]
pub struct MemoryRegionResponse {
    pub base_address: String,
    pub size: u64,
    pub protection: String,
    pub state: String,
    pub memory_type: String,
    pub module_name: Option<String>,
    pub entropy: Option<f64>,
}

/// Memory matched string response
#[derive(Debug, Serialize)]
pub struct MemoryMatchedStringResponse {
    pub identifier: String,
    pub virtual_address: String,
    pub file_offset: u64,
    pub length: usize,
    pub data: String,
}

/// Scan a memory dump file
pub async fn scan_memory_dump(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    req: web::Json<MemoryScanRequest>,
) -> Result<HttpResponse> {
    use crate::scanner::yara::{MemoryScanner, MemoryScanOptions};

    // Validate path exists
    let path = std::path::Path::new(&req.path);
    if !path.exists() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Memory dump file not found"
        })));
    }

    // Load rules
    let rules = load_rules_for_scan(pool.get_ref(), Some(&claims.sub)).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Build scan options
    let options = MemoryScanOptions {
        max_region_size: req.options.max_region_size.unwrap_or(100 * 1024 * 1024),
        min_region_size: req.options.min_region_size.unwrap_or(64),
        only_executable: req.options.only_executable.unwrap_or(false),
        only_writable: req.options.only_writable.unwrap_or(false),
        calculate_entropy: req.options.calculate_entropy.unwrap_or(true),
        flag_rwx_regions: req.options.flag_rwx_regions.unwrap_or(true),
        ..Default::default()
    };

    // Create memory scanner
    let mut scanner = MemoryScanner::with_options(options);

    // Collect rule names before moving rules
    let rules_used: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();

    scanner.load_rules(rules)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Perform scan
    let result = scanner.scan_file(&req.path).await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Create scan record
    let scan_id = db::create_yara_memory_scan(
        pool.get_ref(),
        &claims.sub,
        req.name.as_deref(),
        &result.format.to_string(),
        Some(&req.path),
        None, // process_id
        None, // process_name
        &rules_used,
        req.customer_id.as_deref(),
        req.engagement_id.as_deref(),
    ).await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    // Update scan status to completed with results
    let _ = db::update_yara_memory_scan_status(
        pool.get_ref(),
        &scan_id,
        "completed",
        Some(result.matches.len() as i32),
        Some(result.region_count as i32),
        Some(result.dump_size as i64),
        None, // error_message
    ).await;

    // Build response
    let response = MemoryScanResponse {
        id: scan_id,
        format: result.format.to_string(),
        dump_size: result.dump_size,
        region_count: result.region_count,
        bytes_scanned: result.bytes_scanned,
        matches: result.matches.iter().map(|m| MemoryMatchResponse {
            rule_name: m.rule_name.clone(),
            region: MemoryRegionResponse {
                base_address: format!("0x{:x}", m.region.base_address),
                size: m.region.size,
                protection: m.region.protection.to_string_short(),
                state: m.region.state.to_string(),
                memory_type: m.region.memory_type.to_string(),
                module_name: m.region.module_name.clone(),
                entropy: m.region.entropy,
            },
            matched_strings: m.matched_strings.iter().map(|s| MemoryMatchedStringResponse {
                identifier: s.identifier.clone(),
                virtual_address: format!("0x{:x}", s.virtual_address),
                file_offset: s.file_offset,
                length: s.length,
                data: s.data.clone(),
            }).collect(),
            tags: m.tags.clone(),
        }).collect(),
        suspicious_regions: result.suspicious_regions.iter().map(|r| MemoryRegionResponse {
            base_address: format!("0x{:x}", r.base_address),
            size: r.size,
            protection: r.protection.to_string_short(),
            state: r.state.to_string(),
            memory_type: r.memory_type.to_string(),
            module_name: r.module_name.clone(),
            entropy: r.entropy,
        }).collect(),
        scan_time_ms: result.scan_time_ms,
        errors: result.errors,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// List memory scans
pub async fn list_memory_scans(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<ScanQuery>,
) -> Result<HttpResponse> {
    let scans = db::list_yara_memory_scans(
        pool.get_ref(),
        &claims.sub,
        query.limit.unwrap_or(50),
        query.offset.unwrap_or(0),
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "scans": scans
    })))
}

/// Get memory scan details
pub async fn get_memory_scan(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    let scan = db::get_yara_memory_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match scan {
        Some(s) => {
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "scan": s
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Memory scan not found"
        }))),
    }
}

// ============================================================================
// File Monitor Types and Handlers
// ============================================================================

/// Request to create a file monitor
#[derive(Debug, Deserialize)]
pub struct CreateFileMonitorRequest {
    pub name: String,
    pub paths: Vec<String>,
    pub recursive: Option<bool>,
    #[serde(default)]
    pub include_extensions: Vec<String>,
    #[serde(default)]
    pub exclude_extensions: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    pub max_file_size: Option<u64>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    pub alert_on_create: Option<bool>,
    pub alert_on_modify: Option<bool>,
    pub alert_on_access: Option<bool>,
}

/// File monitor response
#[derive(Debug, Serialize)]
pub struct FileMonitorResponse {
    pub id: String,
    pub name: String,
    pub paths: Vec<String>,
    pub recursive: bool,
    pub status: String,
    pub enabled: bool,
    pub events_scanned: i64,
    pub alerts_generated: i64,
    pub created_at: String,
}

/// Create a file monitor
pub async fn create_file_monitor(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    req: web::Json<CreateFileMonitorRequest>,
) -> Result<HttpResponse> {
    // Validate paths exist
    for path in &req.paths {
        let p = std::path::Path::new(path);
        if !p.exists() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Path does not exist: {}", path)
            })));
        }
    }

    let paths_json = serde_json::to_string(&req.paths).unwrap_or_default();
    let include_ext_json = serde_json::to_string(&req.include_extensions).unwrap_or_default();
    let exclude_ext_json = serde_json::to_string(&req.exclude_extensions).unwrap_or_default();
    let exclude_paths_json = serde_json::to_string(&req.exclude_paths).unwrap_or_default();
    let rule_ids_json = serde_json::to_string(&req.rule_ids).unwrap_or_default();

    let monitor_id = db::create_yara_file_monitor_extended(
        pool.get_ref(),
        &claims.sub,
        &req.name,
        &paths_json,
        req.recursive.unwrap_or(true),
        &include_ext_json,
        &exclude_ext_json,
        &exclude_paths_json,
        req.max_file_size.unwrap_or(50 * 1024 * 1024) as i64,
        &rule_ids_json,
        req.alert_on_create.unwrap_or(true),
        req.alert_on_modify.unwrap_or(true),
        req.alert_on_access.unwrap_or(false),
    ).await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": monitor_id,
        "message": "File monitor created"
    })))
}

/// List file monitors
pub async fn list_file_monitors(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse> {
    let monitors = db::list_yara_file_monitors(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "monitors": monitors
    })))
}

/// Get file monitor details
pub async fn get_file_monitor(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let monitor_id = path.into_inner();

    let monitor = db::get_yara_file_monitor(pool.get_ref(), &monitor_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match monitor {
        Some(m) => {
            if m.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            // Get recent alerts
            let alerts = db::get_yara_monitor_alerts_simple(pool.get_ref(), &monitor_id, Some(50), None)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "monitor": m,
                "alerts": alerts
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "File monitor not found"
        }))),
    }
}

/// Start/stop a file monitor
pub async fn update_file_monitor_status(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    req: web::Json<HashMap<String, String>>,
) -> Result<HttpResponse> {
    let monitor_id = path.into_inner();

    let monitor = db::get_yara_file_monitor(pool.get_ref(), &monitor_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match monitor {
        Some(m) => {
            if m.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            let status = req.get("status").map(|s| s.as_str()).unwrap_or("stopped");

            db::update_yara_file_monitor_status_simple(pool.get_ref(), &monitor_id, status)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": format!("Monitor status updated to {}", status)
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "File monitor not found"
        }))),
    }
}

/// Delete a file monitor
pub async fn delete_file_monitor(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let monitor_id = path.into_inner();

    let monitor = db::get_yara_file_monitor(pool.get_ref(), &monitor_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match monitor {
        Some(m) => {
            if m.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            db::delete_yara_file_monitor_simple(pool.get_ref(), &monitor_id)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "File monitor deleted"
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "File monitor not found"
        }))),
    }
}

/// Get file monitor alerts
pub async fn get_file_monitor_alerts(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    query: web::Query<ScanQuery>,
) -> Result<HttpResponse> {
    let monitor_id = path.into_inner();

    let monitor = db::get_yara_file_monitor(pool.get_ref(), &monitor_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    match monitor {
        Some(m) => {
            if m.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }

            let alerts = db::get_yara_monitor_alerts_simple(pool.get_ref(), &monitor_id, query.limit, query.offset)
                .await
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "alerts": alerts
            })))
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "File monitor not found"
        }))),
    }
}

/// Acknowledge an alert
pub async fn acknowledge_alert(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    req: web::Json<HashMap<String, String>>,
) -> Result<HttpResponse> {
    let alert_id = path.into_inner();

    let notes = req.get("notes").map(|s| s.as_str());

    db::acknowledge_yara_monitor_alert(pool.get_ref(), &alert_id, &claims.sub, notes)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Alert acknowledged"
    })))
}

// ============================================================================
// Rule Effectiveness Types and Handlers
// ============================================================================

/// Rule effectiveness score response
#[derive(Debug, Serialize)]
pub struct RuleEffectivenessResponse {
    pub rule_id: String,
    pub rule_name: String,
    pub score: f64,
    pub grade: String,
    pub total_matches: i64,
    pub true_positives: i64,
    pub false_positives: i64,
    pub pending_verification: i64,
    pub false_positive_rate: f64,
    pub true_positive_rate: f64,
    pub avg_scan_time_ms: f64,
    pub trend: f64,
    pub confidence: f64,
    pub last_match_at: Option<String>,
    pub calculated_at: String,
}

/// Request to verify a match
#[derive(Debug, Deserialize)]
pub struct VerifyMatchRequest {
    pub status: String,  // "true_positive", "false_positive", "inconclusive"
    pub notes: Option<String>,
}

/// Get rule effectiveness scores
pub async fn get_rule_effectiveness(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse> {
    let scores = db::get_all_yara_rule_effectiveness(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let response: Vec<RuleEffectivenessResponse> = scores.iter().map(|s| {
        use crate::scanner::yara::effectiveness::EffectivenessGrade;

        let total_verified = s.true_positives + s.false_positives;
        let fp_rate = if total_verified > 0 {
            s.false_positives as f64 / total_verified as f64
        } else {
            0.0
        };
        let tp_rate = if total_verified > 0 {
            s.true_positives as f64 / total_verified as f64
        } else {
            0.0
        };

        RuleEffectivenessResponse {
            rule_id: s.rule_id.clone(),
            rule_name: s.rule_name.clone().unwrap_or_default(),
            score: s.score,
            grade: EffectivenessGrade::from_score(s.score).to_string(),
            total_matches: s.total_matches,
            true_positives: s.true_positives,
            false_positives: s.false_positives,
            pending_verification: s.pending_verification,
            false_positive_rate: fp_rate,
            true_positive_rate: tp_rate,
            avg_scan_time_ms: s.avg_scan_time_ms,
            trend: s.trend,
            confidence: s.confidence,
            last_match_at: s.last_match_at.map(|d| d.to_rfc3339()),
            calculated_at: s.calculated_at.to_rfc3339(),
        }
    }).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "scores": response
    })))
}

/// Get effectiveness for a specific rule
pub async fn get_rule_effectiveness_detail(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let rule_id = path.into_inner();

    let effectiveness = db::get_yara_rule_effectiveness(pool.get_ref(), &rule_id)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let history = db::get_yara_rule_effectiveness_history(pool.get_ref(), &rule_id, 30)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "effectiveness": effectiveness,
        "history": history
    })))
}

/// Verify a match (mark as true/false positive)
pub async fn verify_match(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    req: web::Json<VerifyMatchRequest>,
) -> Result<HttpResponse> {
    let match_id = path.into_inner();

    let status = match req.status.as_str() {
        "true_positive" => "true_positive",
        "false_positive" => "false_positive",
        "inconclusive" => "inconclusive",
        _ => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid status. Must be: true_positive, false_positive, or inconclusive"
        }))),
    };

    db::mark_yara_match_verification_extended(
        pool.get_ref(),
        &match_id,
        status,
        &claims.sub,
        req.notes.as_deref(),
    )
    .await
    .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Match marked as {}", status)
    })))
}

/// Get rules needing review (low effectiveness or high FP rate)
pub async fn get_rules_needing_review(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse> {
    let rules = db::get_yara_rules_needing_review(pool.get_ref(), &claims.sub, 70.0, 0.15)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "rules": rules
    })))
}

/// Get effectiveness summary
pub async fn get_effectiveness_summary(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse> {
    let summary = db::get_yara_effectiveness_summary(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(summary))
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
            .route("/scan/bulk", web::post().to(bulk_scan))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            // Rules
            .route("/rules", web::get().to(list_rules))
            .route("/rules", web::post().to(create_rule))
            .route("/rules/build", web::post().to(build_rule))
            .route("/rules/import", web::post().to(import_rules))
            .route("/rules/categories", web::get().to(get_categories))
            .route("/rules/stats", web::get().to(get_stats))
            .route("/rules/{id}", web::get().to(get_rule))
            .route("/rules/{id}", web::put().to(update_rule))
            .route("/rules/{id}", web::delete().to(delete_rule))
            // Validation
            .route("/validate", web::post().to(validate_rule_endpoint))
            // Community Sources
            .route("/community/sources", web::get().to(get_community_sources))
            .route("/community/fetch/{source_id}", web::post().to(fetch_community_source))
            // Memory Scanning (Sprint 1)
            .route("/memory/scan", web::post().to(scan_memory_dump))
            .route("/memory/scans", web::get().to(list_memory_scans))
            .route("/memory/scans/{id}", web::get().to(get_memory_scan))
            // File Monitors (Sprint 1)
            .route("/monitors", web::post().to(create_file_monitor))
            .route("/monitors", web::get().to(list_file_monitors))
            .route("/monitors/{id}", web::get().to(get_file_monitor))
            .route("/monitors/{id}/status", web::put().to(update_file_monitor_status))
            .route("/monitors/{id}", web::delete().to(delete_file_monitor))
            .route("/monitors/{id}/alerts", web::get().to(get_file_monitor_alerts))
            .route("/alerts/{id}/acknowledge", web::post().to(acknowledge_alert))
            // Rule Effectiveness (Sprint 1)
            .route("/effectiveness", web::get().to(get_rule_effectiveness))
            .route("/effectiveness/summary", web::get().to(get_effectiveness_summary))
            .route("/effectiveness/review", web::get().to(get_rules_needing_review))
            .route("/effectiveness/{id}", web::get().to(get_rule_effectiveness_detail))
            .route("/matches/{id}/verify", web::post().to(verify_match)),
    );
}
