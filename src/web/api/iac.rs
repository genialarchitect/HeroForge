#![allow(dead_code)]
//! Infrastructure-as-Code (IaC) Security Scanning API Endpoints
//!
//! This module provides REST API endpoints for IaC security scanning:
//! - POST /api/iac/scan - Start an IaC scan (JSON with files)
//! - GET /api/iac/scans - List IaC scans for the current user
//! - GET /api/iac/scans/{id} - Get a specific IaC scan with details
//! - DELETE /api/iac/scans/{id} - Delete an IaC scan
//! - GET /api/iac/scans/{id}/findings - Get findings for a scan
//! - GET /api/iac/scans/{id}/files - Get files analyzed in a scan
//! - PATCH /api/iac/findings/{id}/status - Update finding status
//! - POST /api/iac/analyze - Analyze a single file (immediate response)
//! - GET /api/iac/rules - List security rules
//! - POST /api/iac/rules - Create a custom rule
//! - PUT /api/iac/rules/{id} - Update a custom rule
//! - DELETE /api/iac/rules/{id} - Delete a custom rule
//! - GET /api/iac/platforms - List supported platforms

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::iac;
use crate::scanner::iac::{
    IacCloudProvider, IacFindingCategory, IacFindingStatus, IacPlatform,
    IacRule, IacScanStatus, IacScanner, IacSeverity, RulePatternType,
};
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

/// File data for upload
#[derive(Debug, Deserialize)]
pub struct FileData {
    pub filename: String,
    pub content: String, // Can be raw text or base64
}

/// Request body for creating an IaC scan
#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub name: Option<String>,
    pub files: Vec<FileData>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Response for scan creation
#[derive(Debug, Serialize)]
pub struct CreateScanResponse {
    pub id: String,
    pub message: String,
}

/// Response for scan details
#[derive(Debug, Serialize)]
pub struct ScanDetailResponse {
    pub scan: ScanInfo,
    pub files: Vec<IacFileInfo>,
    pub finding_summary: FindingSummary,
}

/// Scan info for API response
#[derive(Debug, Serialize)]
pub struct ScanInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub file_count: i32,
    pub resource_count: i32,
    pub finding_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub error_message: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// File info without content
#[derive(Debug, Serialize)]
pub struct IacFileInfo {
    pub id: String,
    pub filename: String,
    pub path: String,
    pub platform: String,
    pub provider: String,
    pub size_bytes: i64,
    pub line_count: i32,
    pub resource_count: i32,
    pub finding_count: i32,
}

/// Finding summary for a scan
#[derive(Debug, Serialize)]
pub struct FindingSummary {
    pub total: i32,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
    pub by_category: std::collections::HashMap<String, i32>,
}

/// Finding info for API response
#[derive(Debug, Serialize)]
pub struct FindingInfo {
    pub id: String,
    pub file_id: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub resource_type: Option<String>,
    pub resource_name: Option<String>,
    pub line_start: i32,
    pub line_end: i32,
    pub code_snippet: Option<String>,
    pub remediation: String,
    pub documentation_url: Option<String>,
    pub status: String,
}

/// Request for analyzing a single file
#[derive(Debug, Deserialize)]
pub struct AnalyzeFileRequest {
    pub filename: String,
    pub content: String,
    pub platform: Option<String>,
}

/// Response from file analysis
#[derive(Debug, Serialize)]
pub struct AnalyzeFileResponse {
    pub platform: String,
    pub provider: String,
    pub findings: Vec<FindingInfo>,
    pub resources: Vec<ResourceInfo>,
}

/// Resource info for API response
#[derive(Debug, Serialize)]
pub struct ResourceInfo {
    pub resource_type: String,
    pub resource_name: String,
    pub line_number: i32,
}

/// Request for updating finding status
#[derive(Debug, Deserialize)]
pub struct UpdateFindingStatusRequest {
    pub status: String,
    pub suppression_reason: Option<String>,
}

/// Request for creating a custom rule
#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub resource_types: Vec<String>,
    pub pattern: String,
    #[serde(default = "default_pattern_type")]
    pub pattern_type: String,
    pub remediation: String,
    pub documentation_url: Option<String>,
}

fn default_pattern_type() -> String {
    "regex".to_string()
}

/// Request for updating a rule
#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub pattern: Option<String>,
    pub remediation: Option<String>,
    pub is_enabled: Option<bool>,
}

/// Query params for listing scans
#[derive(Debug, Deserialize)]
pub struct ListScansQuery {
    #[serde(default = "default_limit")]
    pub limit: i32,
    #[serde(default)]
    pub offset: i32,
}

fn default_limit() -> i32 {
    50
}

// ============================================================================
// API Handlers
// ============================================================================

/// Create and start a new IaC scan from uploaded files
///
/// POST /api/iac/scan
pub async fn create_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateScanRequest>,
) -> Result<HttpResponse> {
    log::info!("Creating IaC scan for user {}", claims.sub);

    if request.files.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No files provided"
        })));
    }

    let scan_id = uuid::Uuid::new_v4().to_string();
    let scan_name = request.name.clone().unwrap_or_else(|| {
        format!("IaC Scan - {}", chrono::Utc::now().format("%Y-%m-%d %H:%M"))
    });

    // Filter valid IaC files
    let files: Vec<(String, String)> = request
        .files
        .iter()
        .filter(|f| crate::scanner::iac::is_iac_file(&f.filename))
        .map(|f| (f.filename.clone(), f.content.clone()))
        .collect();

    if files.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No valid IaC files provided. Supported formats: .tf, .tf.json, CloudFormation templates, ARM templates"
        })));
    }

    // Create the database record
    iac::create_scan(
        &pool,
        &scan_id,
        &claims.sub,
        &scan_name,
        "upload",
        None,
        request.customer_id.as_deref(),
        request.engagement_id.as_deref(),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to create IaC scan: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create scan")
    })?;

    // Clone for background task
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();

    // Spawn background task to run the scan
    tokio::spawn(async move {
        log::info!("Starting background IaC scan: {}", scan_id_clone);

        // Update status to running
        if let Err(e) = iac::update_scan_status(
            &pool_clone,
            &scan_id_clone,
            IacScanStatus::Running,
            None,
        )
        .await
        {
            log::error!("Failed to update scan status to running: {}", e);
            return;
        }

        // Run the scan
        let scanner = IacScanner::new();
        match scanner.scan_files(&files) {
            Ok(results) => {
                log::info!(
                    "IaC scan {} completed: {} files, {} findings",
                    scan_id_clone,
                    results.files.len(),
                    results.findings.len()
                );

                // Store files
                for file in &results.files {
                    if let Err(e) = iac::create_file(&pool_clone, file).await {
                        log::error!("Failed to store IaC file: {}", e);
                    }
                }

                // Store findings
                for finding in &results.findings {
                    if let Err(e) = iac::create_finding(&pool_clone, finding).await {
                        log::error!("Failed to store IaC finding: {}", e);
                    }
                }

                // Update scan results
                if let Err(e) = iac::update_scan_results(
                    &pool_clone,
                    &scan_id_clone,
                    &results.scan.platforms,
                    &results.scan.providers,
                    results.scan.file_count,
                    results.scan.resource_count,
                    results.scan.finding_count,
                    results.scan.critical_count,
                    results.scan.high_count,
                    results.scan.medium_count,
                    results.scan.low_count,
                    results.scan.info_count,
                )
                .await
                {
                    log::error!("Failed to update scan results: {}", e);
                }

                // Mark as completed
                if let Err(e) = iac::update_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    IacScanStatus::Completed,
                    None,
                )
                .await
                {
                    log::error!("Failed to update scan status to completed: {}", e);
                }
            }
            Err(e) => {
                log::error!("IaC scan {} failed: {}", scan_id_clone, e);

                if let Err(update_err) = iac::update_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    IacScanStatus::Failed,
                    Some(&e.to_string()),
                )
                .await
                {
                    log::error!("Failed to update scan status to failed: {}", update_err);
                }
            }
        }
    });

    Ok(HttpResponse::Accepted().json(CreateScanResponse {
        id: scan_id,
        message: "IaC scan started successfully".to_string(),
    }))
}

/// List IaC scans for the current user
///
/// GET /api/iac/scans
pub async fn list_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ListScansQuery>,
) -> Result<HttpResponse> {
    let scans = iac::list_scans(&pool, &claims.sub, query.limit, query.offset)
        .await
        .map_err(|e| {
            log::error!("Failed to list IaC scans: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to retrieve scans")
        })?;

    // Convert to API response format
    let scan_infos: Vec<ScanInfo> = scans
        .into_iter()
        .map(|s| ScanInfo {
            id: s.id,
            name: s.name,
            status: s.status.to_string(),
            file_count: s.file_count,
            resource_count: s.resource_count,
            finding_count: s.finding_count,
            critical_count: s.critical_count,
            high_count: s.high_count,
            medium_count: s.medium_count,
            low_count: s.low_count,
            info_count: s.info_count,
            error_message: s.error_message,
            created_at: s.created_at.to_rfc3339(),
            started_at: s.started_at.map(|dt| dt.to_rfc3339()),
            completed_at: s.completed_at.map(|dt| dt.to_rfc3339()),
        })
        .collect();

    Ok(HttpResponse::Ok().json(scan_infos))
}

/// Get a specific IaC scan with details
///
/// GET /api/iac/scans/{id}
pub async fn get_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = iac::get_scan(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get IaC scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to retrieve scan")
        })?;

    match scan {
        Some(scan) if scan.user_id == claims.sub => {
            // Get files
            let files = iac::get_files_for_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to get scan files: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to retrieve files")
                })?;

            // Get findings for summary
            let findings = iac::get_findings_for_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to get scan findings: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to retrieve findings")
                })?;

            // Build summary
            let mut by_category: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
            for finding in &findings {
                *by_category.entry(finding.category.to_string()).or_insert(0) += 1;
            }

            let finding_summary = FindingSummary {
                total: scan.finding_count,
                critical: scan.critical_count,
                high: scan.high_count,
                medium: scan.medium_count,
                low: scan.low_count,
                info: scan.info_count,
                by_category,
            };

            let scan_info = ScanInfo {
                id: scan.id,
                name: scan.name,
                status: scan.status.to_string(),
                file_count: scan.file_count,
                resource_count: scan.resource_count,
                finding_count: scan.finding_count,
                critical_count: scan.critical_count,
                high_count: scan.high_count,
                medium_count: scan.medium_count,
                low_count: scan.low_count,
                info_count: scan.info_count,
                error_message: scan.error_message,
                created_at: scan.created_at.to_rfc3339(),
                started_at: scan.started_at.map(|dt| dt.to_rfc3339()),
                completed_at: scan.completed_at.map(|dt| dt.to_rfc3339()),
            };

            let file_infos: Vec<IacFileInfo> = files
                .into_iter()
                .map(|f| IacFileInfo {
                    id: f.id,
                    filename: f.filename,
                    path: f.path,
                    platform: f.platform.to_string(),
                    provider: f.provider.to_string(),
                    size_bytes: f.size_bytes,
                    line_count: f.line_count,
                    resource_count: f.resource_count,
                    finding_count: f.finding_count,
                })
                .collect();

            Ok(HttpResponse::Ok().json(ScanDetailResponse {
                scan: scan_info,
                files: file_infos,
                finding_summary,
            }))
        }
        Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You do not have permission to view this scan"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "IaC scan not found"
        }))),
    }
}

/// Delete an IaC scan
///
/// DELETE /api/iac/scans/{id}
pub async fn delete_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = iac::get_scan(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get IaC scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete scan")
        })?;

    match scan {
        Some(scan) if scan.user_id == claims.sub => {
            iac::delete_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to delete IaC scan: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to delete scan")
                })?;

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": "IaC scan deleted successfully"
            })))
        }
        Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You do not have permission to delete this scan"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "IaC scan not found"
        }))),
    }
}

/// Get findings for an IaC scan
///
/// GET /api/iac/scans/{id}/findings
pub async fn get_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = iac::get_scan(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to retrieve findings")
        })?;

    match scan {
        Some(scan) if scan.user_id == claims.sub => {
            let findings = iac::get_findings_for_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to get IaC findings: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to retrieve findings")
                })?;

            let finding_infos: Vec<FindingInfo> = findings
                .into_iter()
                .map(|f| FindingInfo {
                    id: f.id,
                    file_id: f.file_id,
                    rule_id: f.rule_id,
                    severity: f.severity.to_string(),
                    category: f.category.to_string(),
                    title: f.title,
                    description: f.description,
                    resource_type: f.resource_type.map(|rt| rt.to_string()),
                    resource_name: f.resource_name,
                    line_start: f.line_start,
                    line_end: f.line_end,
                    code_snippet: f.code_snippet,
                    remediation: f.remediation,
                    documentation_url: f.documentation_url,
                    status: f.status.to_string(),
                })
                .collect();

            Ok(HttpResponse::Ok().json(finding_infos))
        }
        Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You do not have permission to view this scan"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "IaC scan not found"
        }))),
    }
}

/// Get files for an IaC scan
///
/// GET /api/iac/scans/{id}/files
pub async fn get_files(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    let scan = iac::get_scan(&pool, &scan_id)
        .await
        .map_err(|e| {
            log::error!("Failed to verify scan ownership: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to retrieve files")
        })?;

    match scan {
        Some(scan) if scan.user_id == claims.sub => {
            let files = iac::get_files_for_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to get IaC files: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to retrieve files")
                })?;

            Ok(HttpResponse::Ok().json(files))
        }
        Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You do not have permission to view this scan"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "IaC scan not found"
        }))),
    }
}

/// Get file details including content
///
/// GET /api/iac/files/{id}
pub async fn get_file(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    file_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Get file to find scan_id
    let file_info: Option<(String, String)> = sqlx::query_as(
        "SELECT id, scan_id FROM iac_files WHERE id = ?",
    )
    .bind(file_id.as_str())
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to retrieve file")
    })?;

    match file_info {
        Some((_, scan_id)) => {
            let scan = iac::get_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to verify scan ownership: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to retrieve file")
                })?;

            match scan {
                Some(scan) if scan.user_id == claims.sub => {
                    let files = iac::get_files_for_scan(&pool, &scan_id)
                        .await
                        .map_err(|e| {
                            log::error!("Failed to get files: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to retrieve file")
                        })?;

                    let file = files.into_iter().find(|f| f.id == *file_id);
                    match file {
                        Some(f) => Ok(HttpResponse::Ok().json(f)),
                        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
                            "error": "File not found"
                        }))),
                    }
                }
                Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "You do not have permission to view this file"
                }))),
                None => Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Scan not found"
                }))),
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "File not found"
        }))),
    }
}

/// Get findings for a file
///
/// GET /api/iac/files/{id}/findings
pub async fn get_file_findings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    file_id: web::Path<String>,
) -> Result<HttpResponse> {
    let file_info: Option<(String, String)> = sqlx::query_as(
        "SELECT id, scan_id FROM iac_files WHERE id = ?",
    )
    .bind(file_id.as_str())
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get file: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to retrieve findings")
    })?;

    match file_info {
        Some((_, scan_id)) => {
            let scan = iac::get_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to verify scan ownership: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to retrieve findings")
                })?;

            match scan {
                Some(scan) if scan.user_id == claims.sub => {
                    let findings = iac::get_findings_for_file(&pool, &file_id)
                        .await
                        .map_err(|e| {
                            log::error!("Failed to get file findings: {}", e);
                            actix_web::error::ErrorInternalServerError("Failed to retrieve findings")
                        })?;

                    let finding_infos: Vec<FindingInfo> = findings
                        .into_iter()
                        .map(|f| FindingInfo {
                            id: f.id,
                            file_id: f.file_id,
                            rule_id: f.rule_id,
                            severity: f.severity.to_string(),
                            category: f.category.to_string(),
                            title: f.title,
                            description: f.description,
                            resource_type: f.resource_type.map(|rt| rt.to_string()),
                            resource_name: f.resource_name,
                            line_start: f.line_start,
                            line_end: f.line_end,
                            code_snippet: f.code_snippet,
                            remediation: f.remediation,
                            documentation_url: f.documentation_url,
                            status: f.status.to_string(),
                        })
                        .collect();

                    Ok(HttpResponse::Ok().json(finding_infos))
                }
                Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "You do not have permission to view this file"
                }))),
                None => Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Scan not found"
                }))),
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "File not found"
        }))),
    }
}

/// Update finding status
///
/// PATCH /api/iac/findings/{id}/status
pub async fn update_finding_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    finding_id: web::Path<String>,
    request: web::Json<UpdateFindingStatusRequest>,
) -> Result<HttpResponse> {
    let finding_info: Option<(String, String)> = sqlx::query_as(
        "SELECT id, scan_id FROM iac_findings WHERE id = ?",
    )
    .bind(finding_id.as_str())
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get finding: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update finding")
    })?;

    match finding_info {
        Some((_, scan_id)) => {
            let scan = iac::get_scan(&pool, &scan_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to verify scan ownership: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to update finding")
                })?;

            match scan {
                Some(scan) if scan.user_id == claims.sub => {
                    let status: IacFindingStatus = match request.status.to_lowercase().as_str() {
                        "open" => IacFindingStatus::Open,
                        "resolved" => IacFindingStatus::Resolved,
                        "false_positive" => IacFindingStatus::FalsePositive,
                        "accepted" => IacFindingStatus::Accepted,
                        "suppressed" => IacFindingStatus::Suppressed,
                        _ => {
                            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                                "error": format!("Invalid status: {}", request.status)
                            })));
                        }
                    };

                    iac::update_finding_status(
                        &pool,
                        &finding_id,
                        status,
                        request.suppression_reason.as_deref(),
                    )
                    .await
                    .map_err(|e| {
                        log::error!("Failed to update finding status: {}", e);
                        actix_web::error::ErrorInternalServerError("Failed to update finding")
                    })?;

                    Ok(HttpResponse::Ok().json(serde_json::json!({
                        "message": "Finding status updated successfully",
                        "status": request.status
                    })))
                }
                Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "You do not have permission to update this finding"
                }))),
                None => Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Scan not found"
                }))),
            }
        }
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Finding not found"
        }))),
    }
}

/// Analyze a single file immediately (no database storage)
///
/// POST /api/iac/analyze
pub async fn analyze_file(
    _claims: web::ReqData<auth::Claims>,
    request: web::Json<AnalyzeFileRequest>,
) -> Result<HttpResponse> {
    let scanner = IacScanner::new();

    let result = if let Some(ref platform_str) = request.platform {
        let platform: IacPlatform = match platform_str.to_lowercase().as_str() {
            "terraform" => IacPlatform::Terraform,
            "cloudformation" => IacPlatform::CloudFormation,
            "azure_arm" | "arm" => IacPlatform::AzureArm,
            _ => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Unknown platform: {}. Supported: terraform, cloudformation, azure_arm", platform_str)
                })));
            }
        };

        scanner.analyze_content_with_platform(&request.filename, &request.content, platform)
    } else {
        scanner.analyze_content(&request.filename, &request.content)
    };

    match result {
        Ok(analysis) => {
            let findings: Vec<FindingInfo> = analysis.findings.iter().map(|f| FindingInfo {
                id: f.id.clone(),
                file_id: f.file_id.clone(),
                rule_id: f.rule_id.clone(),
                severity: f.severity.to_string(),
                category: f.category.to_string(),
                title: f.title.clone(),
                description: f.description.clone(),
                resource_type: f.resource_type.as_ref().map(|rt| rt.to_string()),
                resource_name: f.resource_name.clone(),
                line_start: f.line_start,
                line_end: f.line_end,
                code_snippet: f.code_snippet.clone(),
                remediation: f.remediation.clone(),
                documentation_url: f.documentation_url.clone(),
                status: f.status.to_string(),
            }).collect();

            let resources: Vec<ResourceInfo> = analysis
                .resources
                .iter()
                .map(|r| ResourceInfo {
                    resource_type: r.resource_type.to_string(),
                    resource_name: r.resource_name.clone(),
                    line_number: r.line_start,
                })
                .collect();

            Ok(HttpResponse::Ok().json(AnalyzeFileResponse {
                platform: analysis.platform.to_string(),
                provider: analysis.provider.to_string(),
                findings,
                resources,
            }))
        }
        Err(e) => {
            log::warn!("Failed to analyze file {}: {}", request.filename, e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Failed to analyze file: {}", e)
            })))
        }
    }
}

/// List security rules (builtin + user's custom)
///
/// GET /api/iac/rules
pub async fn list_rules(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let rules = iac::list_rules(&pool, Some(&claims.sub))
        .await
        .map_err(|e| {
            log::error!("Failed to list IaC rules: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to retrieve rules")
        })?;

    Ok(HttpResponse::Ok().json(rules))
}

/// Create a custom rule
///
/// POST /api/iac/rules
pub async fn create_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateRuleRequest>,
) -> Result<HttpResponse> {
    let severity: IacSeverity = match request.severity.to_lowercase().as_str() {
        "critical" => IacSeverity::Critical,
        "high" => IacSeverity::High,
        "medium" => IacSeverity::Medium,
        "low" => IacSeverity::Low,
        "info" => IacSeverity::Info,
        _ => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid severity: {}", request.severity)
            })));
        }
    };

    let category: IacFindingCategory = match request.category.to_lowercase().as_str() {
        "hardcoded_secret" => IacFindingCategory::HardcodedSecret,
        "iam_misconfiguration" => IacFindingCategory::IamMisconfiguration,
        "public_storage" => IacFindingCategory::PublicStorage,
        "missing_encryption" => IacFindingCategory::MissingEncryption,
        "missing_logging" => IacFindingCategory::MissingLogging,
        "network_exposure" => IacFindingCategory::NetworkExposure,
        "missing_tags" => IacFindingCategory::MissingTags,
        "deprecated_resource" => IacFindingCategory::DeprecatedResource,
        "weak_cryptography" => IacFindingCategory::WeakCryptography,
        "insecure_default" => IacFindingCategory::InsecureDefault,
        "compliance_violation" => IacFindingCategory::ComplianceViolation,
        "best_practice" => IacFindingCategory::BestPractice,
        _ => IacFindingCategory::BestPractice,
    };

    let platforms: Vec<IacPlatform> = request
        .platforms
        .iter()
        .filter_map(|p| match p.to_lowercase().as_str() {
            "terraform" => Some(IacPlatform::Terraform),
            "cloudformation" => Some(IacPlatform::CloudFormation),
            "azure_arm" | "arm" => Some(IacPlatform::AzureArm),
            _ => None,
        })
        .collect();

    let providers: Vec<IacCloudProvider> = request
        .providers
        .iter()
        .filter_map(|p| match p.to_lowercase().as_str() {
            "aws" => Some(IacCloudProvider::Aws),
            "azure" => Some(IacCloudProvider::Azure),
            "gcp" => Some(IacCloudProvider::Gcp),
            _ => None,
        })
        .collect();

    let pattern_type: RulePatternType = match request.pattern_type.to_lowercase().as_str() {
        "regex" => RulePatternType::Regex,
        "jsonpath" => RulePatternType::JsonPath,
        "custom" => RulePatternType::Custom,
        _ => RulePatternType::Regex,
    };

    // Validate regex pattern if type is regex
    if pattern_type == RulePatternType::Regex {
        if let Err(e) = regex::Regex::new(&request.pattern) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid regex pattern: {}", e)
            })));
        }
    }

    let rule_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let rule = IacRule {
        id: rule_id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        severity,
        category,
        platforms,
        providers,
        resource_types: request.resource_types.clone(),
        pattern: request.pattern.clone(),
        pattern_type,
        remediation: request.remediation.clone(),
        documentation_url: request.documentation_url.clone(),
        compliance_mappings: Vec::new(),
        is_builtin: false,
        is_enabled: true,
        user_id: Some(claims.sub.clone()),
        created_at: now,
        updated_at: now,
    };

    iac::create_rule(&pool, &rule)
        .await
        .map_err(|e| {
            log::error!("Failed to create IaC rule: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create rule")
        })?;

    Ok(HttpResponse::Created().json(rule))
}

/// Update a custom rule
///
/// PUT /api/iac/rules/{id}
pub async fn update_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    rule_id: web::Path<String>,
    request: web::Json<UpdateRuleRequest>,
) -> Result<HttpResponse> {
    let rule = iac::get_rule(&pool, &rule_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get rule: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update rule")
        })?;

    match rule {
        Some(rule) if rule.user_id.as_ref() == Some(&claims.sub) && !rule.is_builtin => {
            let severity = request.severity.as_ref().and_then(|s| {
                match s.to_lowercase().as_str() {
                    "critical" => Some(IacSeverity::Critical),
                    "high" => Some(IacSeverity::High),
                    "medium" => Some(IacSeverity::Medium),
                    "low" => Some(IacSeverity::Low),
                    "info" => Some(IacSeverity::Info),
                    _ => None,
                }
            });

            iac::update_rule(
                &pool,
                &rule_id,
                request.name.as_deref(),
                request.description.as_deref(),
                severity,
                request.category.as_deref(),
                request.pattern.as_deref(),
                request.remediation.as_deref(),
                request.is_enabled,
            )
            .await
            .map_err(|e| {
                log::error!("Failed to update rule: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to update rule")
            })?;

            let updated_rule = iac::get_rule(&pool, &rule_id)
                .await
                .map_err(|e| {
                    log::error!("Failed to get updated rule: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to retrieve updated rule")
                })?;

            Ok(HttpResponse::Ok().json(updated_rule))
        }
        Some(rule) if rule.is_builtin => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Cannot modify builtin rules"
        }))),
        Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "You do not have permission to update this rule"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found"
        }))),
    }
}

/// Delete a custom rule
///
/// DELETE /api/iac/rules/{id}
pub async fn delete_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    rule_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = iac::delete_rule(&pool, &rule_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete rule: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete rule")
        })?;

    if deleted {
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Rule deleted successfully"
        })))
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rule not found or you do not have permission to delete it"
        })))
    }
}

/// List supported platforms
///
/// GET /api/iac/platforms
pub async fn list_platforms() -> Result<HttpResponse> {
    let platforms = serde_json::json!([
        {
            "id": "terraform",
            "name": "Terraform",
            "description": "HashiCorp Terraform HCL files",
            "file_extensions": [".tf", ".tf.json"],
            "providers": ["aws", "azure", "gcp"]
        },
        {
            "id": "cloudformation",
            "name": "AWS CloudFormation",
            "description": "AWS CloudFormation templates in JSON or YAML",
            "file_extensions": [".template", ".template.json", ".template.yaml", ".template.yml"],
            "providers": ["aws"]
        },
        {
            "id": "azure_arm",
            "name": "Azure ARM",
            "description": "Azure Resource Manager templates",
            "file_extensions": [".arm.json", "azuredeploy.json", "mainTemplate.json"],
            "providers": ["azure"]
        }
    ]);

    Ok(HttpResponse::Ok().json(platforms))
}

/// Seed builtin rules on startup
pub async fn seed_builtin_rules(pool: &SqlitePool) -> anyhow::Result<()> {
    iac::seed_builtin_rules(pool).await
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure IaC scanning routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/iac")
            .route("/platforms", web::get().to(list_platforms))
            .route("/scan", web::post().to(create_scan))
            .route("/scans", web::get().to(list_scans))
            .route("/scans/{id}", web::get().to(get_scan))
            .route("/scans/{id}", web::delete().to(delete_scan))
            .route("/scans/{id}/findings", web::get().to(get_findings))
            .route("/scans/{id}/files", web::get().to(get_files))
            .route("/files/{id}", web::get().to(get_file))
            .route("/files/{id}/findings", web::get().to(get_file_findings))
            .route("/findings/{id}/status", web::patch().to(update_finding_status))
            .route("/analyze", web::post().to(analyze_file))
            .route("/rules", web::get().to(list_rules))
            .route("/rules", web::post().to(create_rule))
            .route("/rules/{id}", web::put().to(update_rule))
            .route("/rules/{id}", web::delete().to(delete_rule)),
    );
}
