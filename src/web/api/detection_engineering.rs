//! Detection Engineering API Endpoints
//!
//! This module provides REST API endpoints for detection engineering capabilities:
//! - Detection CRUD with versioning
//! - Coverage analysis and gap detection
//! - False positive management
//! - Detection testing framework
//!
//! ## Endpoints
//!
//! ### Detections
//! - `POST /api/detections` - Create detection
//! - `GET /api/detections` - List detections
//! - `GET /api/detections/{id}` - Get detection
//! - `PUT /api/detections/{id}` - Update detection
//! - `DELETE /api/detections/{id}` - Delete detection
//! - `GET /api/detections/{id}/versions` - Get version history
//! - `POST /api/detections/{id}/deploy` - Deploy detection
//! - `POST /api/detections/validate` - Validate detection
//!
//! ### Coverage
//! - `GET /api/detections/coverage` - Coverage analysis
//! - `GET /api/detections/coverage/gaps` - Coverage gaps
//!
//! ### False Positives
//! - `POST /api/detections/{id}/false-positives` - Report FP
//! - `GET /api/detections/{id}/false-positives` - List FPs
//! - `POST /api/detections/{id}/tune` - Apply tuning
//!
//! ### Testing
//! - `POST /api/detections/{id}/tests` - Create test
//! - `GET /api/detections/{id}/tests` - List tests
//! - `POST /api/detections/{id}/tests/{tid}/run` - Run test
//!
//! ### Dashboard
//! - `GET /api/detections/dashboard` - Dashboard stats

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::detection_engineering::{self as db};
use crate::detection_engineering::{
    detections::{Detection, DetectionSeverity, DetectionStatus, DataSource, DetectionLogic, DetectionMetadata},
    coverage::CoverageAnalyzer,
    testing::{DetectionTest, ExpectedResult, TestType, TestPriority, TestExecutor, SampleLogGenerator},
};
use crate::web::auth::Claims;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Request to create a detection
#[derive(Debug, Deserialize)]
pub struct CreateDetectionRequest {
    pub name: String,
    pub description: String,
    pub logic_yaml: String,
    #[serde(default)]
    pub data_sources: Vec<DataSourceInput>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub confidence: Option<f64>,
}

fn default_severity() -> String {
    "medium".to_string()
}

fn default_status() -> String {
    "draft".to_string()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataSourceInput {
    pub name: String,
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default = "default_true")]
    pub required: bool,
    pub description: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Request to update a detection
#[derive(Debug, Deserialize)]
pub struct UpdateDetectionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub logic_yaml: Option<String>,
    pub data_sources: Option<Vec<DataSourceInput>>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub mitre_techniques: Option<Vec<String>>,
    pub mitre_tactics: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub confidence: Option<f64>,
    #[serde(default)]
    pub change_notes: String,
}

/// Query parameters for listing detections
#[derive(Debug, Deserialize)]
pub struct ListDetectionsQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub search: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// Request to deploy a detection
#[derive(Debug, Deserialize)]
pub struct DeployDetectionRequest {
    pub target_status: String,
    pub notes: Option<String>,
}

/// Request to validate a detection
#[derive(Debug, Deserialize)]
pub struct ValidateDetectionRequest {
    pub yaml: String,
}

/// Detection response
#[derive(Debug, Serialize)]
pub struct DetectionResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub logic_yaml: String,
    pub data_sources: Vec<DataSourceInput>,
    pub severity: String,
    pub status: String,
    pub author_id: String,
    pub author_name: Option<String>,
    pub version: i32,
    pub mitre_techniques: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub tags: Vec<String>,
    pub fp_rate: Option<f64>,
    pub confidence: Option<f64>,
    pub enabled: bool,
    pub quality_score: f64,
    pub created_at: String,
    pub updated_at: String,
}

/// Version history response
#[derive(Debug, Serialize)]
pub struct DetectionVersionResponse {
    pub id: String,
    pub detection_id: String,
    pub version: i32,
    pub logic_yaml: String,
    pub change_notes: String,
    pub created_by: String,
    pub created_by_name: Option<String>,
    pub created_at: String,
}

/// Validation result response
#[derive(Debug, Serialize)]
pub struct ValidationResponse {
    pub valid: bool,
    pub parsed: bool,
    pub errors: Vec<ValidationErrorResponse>,
    pub quality_score: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct ValidationErrorResponse {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub location: Option<String>,
    pub suggestion: Option<String>,
}

/// Request to report false positive
#[derive(Debug, Deserialize)]
pub struct ReportFalsePositiveRequest {
    pub alert_id: String,
    pub reason: String,
    pub explanation: Option<String>,
    pub evidence: Option<String>,
    pub exception_rule: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: String,
    pub alert_data: Option<serde_json::Value>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_priority() -> String {
    "medium".to_string()
}

/// Query for listing false positives
#[derive(Debug, Deserialize)]
pub struct ListFalsePositivesQuery {
    pub status: Option<String>,
    pub offset: Option<u32>,
    pub limit: Option<u32>,
}

/// False positive response
#[derive(Debug, Serialize)]
pub struct FalsePositiveResponse {
    pub id: String,
    pub detection_id: String,
    pub alert_id: String,
    pub reason: String,
    pub explanation: Option<String>,
    pub evidence: Option<String>,
    pub pattern: Option<serde_json::Value>,
    pub exception_rule: Option<String>,
    pub status: String,
    pub priority: String,
    pub reported_by: String,
    pub reported_by_name: Option<String>,
    pub assigned_to: Option<String>,
    pub resolution_notes: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<String>,
    pub alert_data: Option<serde_json::Value>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to update FP status
#[derive(Debug, Deserialize)]
pub struct UpdateFalsePositiveRequest {
    pub status: String,
    pub resolution_notes: Option<String>,
}

/// Request to apply tuning
#[derive(Debug, Deserialize)]
pub struct ApplyTuningRequest {
    pub tuning_type: String,
    pub original_value: String,
    pub new_value: String,
    pub reason: String,
    #[serde(default)]
    pub related_fp_ids: Vec<String>,
}

/// Tuning record response
#[derive(Debug, Serialize)]
pub struct TuningResponse {
    pub id: String,
    pub detection_id: String,
    pub tuning_type: String,
    pub original_value: String,
    pub new_value: String,
    pub reason: String,
    pub related_fp_ids: Vec<String>,
    pub applied_at: String,
    pub applied_by: String,
    pub applied_by_name: Option<String>,
    pub active: bool,
    pub rolled_back_at: Option<String>,
}

/// Request to create a test
#[derive(Debug, Deserialize)]
pub struct CreateTestRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_test_type")]
    pub test_type: String,
    pub input_logs: Vec<serde_json::Value>,
    pub expected_result: ExpectedResultInput,
    #[serde(default = "default_priority")]
    pub priority: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_test_type() -> String {
    "unit".to_string()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExpectedResultInput {
    pub should_alert: bool,
    pub alert_count: Option<u32>,
    pub severity: Option<String>,
    pub expected_fields: Option<std::collections::HashMap<String, serde_json::Value>>,
    pub max_execution_ms: Option<u64>,
}

/// Test response
#[derive(Debug, Serialize)]
pub struct TestResponse {
    pub id: String,
    pub detection_id: String,
    pub name: String,
    pub description: Option<String>,
    pub test_type: String,
    pub input_logs: Vec<serde_json::Value>,
    pub expected_result: serde_json::Value,
    pub priority: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_run: Option<TestRunResponse>,
}

/// Test run response
#[derive(Debug, Serialize)]
pub struct TestRunResponse {
    pub id: String,
    pub test_id: String,
    pub detection_id: String,
    pub passed: bool,
    pub result: serde_json::Value,
    pub actual_output: serde_json::Value,
    pub detection_version: i32,
    pub environment: String,
    pub triggered_by: Option<String>,
    pub run_at: String,
}

/// Coverage analysis response
#[derive(Debug, Serialize)]
pub struct CoverageResponse {
    pub overall_percentage: f64,
    pub weighted_score: f64,
    pub total_techniques: u32,
    pub covered_techniques: u32,
    pub fully_covered: u32,
    pub production_detections: u32,
    pub total_detections: u32,
    pub tactic_scores: serde_json::Value,
    pub data_source_coverage: serde_json::Value,
}

/// Coverage gap response
#[derive(Debug, Serialize)]
pub struct CoverageGapResponse {
    pub technique_id: String,
    pub technique_name: String,
    pub tactics: Vec<String>,
    pub priority: String,
    pub required_data_sources: Vec<String>,
    pub available_data_sources: Vec<String>,
    pub suggestions: Vec<String>,
    pub references: Vec<String>,
    pub estimated_effort: Option<f64>,
}

/// Dashboard stats response
#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub total_detections: i64,
    pub production_detections: i64,
    pub testing_detections: i64,
    pub draft_detections: i64,
    pub pending_false_positives: i64,
    pub total_tests: i64,
    pub passing_tests: i64,
    pub test_pass_rate: f64,
    pub unique_techniques_covered: i64,
    pub recent_activity: Vec<serde_json::Value>,
}

/// Paginated response wrapper
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub offset: u32,
    pub limit: u32,
}

/// Sample log request for testing
#[derive(Debug, Deserialize)]
pub struct GenerateSampleLogsRequest {
    pub technique_id: Option<String>,
    pub sample_type: Option<String>,
    pub count: Option<u32>,
}

// =============================================================================
// Detection CRUD Endpoints
// =============================================================================

/// Create a new detection
pub async fn create_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    request: web::Json<CreateDetectionRequest>,
) -> Result<HttpResponse> {
    let id = format!("DET-{}", Uuid::new_v4().to_string()[..8].to_uppercase());

    let data_sources_json = serde_json::to_string(&request.data_sources).unwrap_or_default();
    let mitre_techniques_json = serde_json::to_string(&request.mitre_techniques).unwrap_or_default();
    let mitre_tactics_json = serde_json::to_string(&request.mitre_tactics).unwrap_or_default();
    let tags_json = serde_json::to_string(&request.tags).unwrap_or_default();

    db::create_detection(
        pool.get_ref(),
        &id,
        &request.name,
        &request.description,
        &request.logic_yaml,
        &data_sources_json,
        &request.severity,
        &request.status,
        &claims.sub,
        &mitre_techniques_json,
        &mitre_tactics_json,
        &tags_json,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to create detection: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create detection")
    })?;

    // Log audit
    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "detection_created",
        Some("detection"),
        Some(&id),
        Some(&format!("Created detection: {}", request.name)),
        None,
    )
    .await;

    let detection = db::get_detection_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch created detection: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch detection")
        })?
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Detection not found"))?;

    Ok(HttpResponse::Created().json(row_to_detection_response(&detection)))
}

/// List detections with pagination
pub async fn list_detections(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    query: web::Query<ListDetectionsQuery>,
) -> Result<HttpResponse> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(200);

    let (rows, total) = db::list_detections(
        pool.get_ref(),
        query.status.as_deref(),
        query.severity.as_deref(),
        query.search.as_deref(),
        offset,
        limit,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to list detections: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list detections")
    })?;

    let items: Vec<DetectionResponse> = rows.iter().map(row_to_detection_response).collect();

    Ok(HttpResponse::Ok().json(PaginatedResponse {
        items,
        total,
        offset,
        limit,
    }))
}

/// Get detection by ID
pub async fn get_detection(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let detection = db::get_detection_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to get detection: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get detection")
        })?;

    match detection {
        Some(row) => Ok(HttpResponse::Ok().json(row_to_detection_response(&row))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Detection not found"
        }))),
    }
}

/// Update a detection
pub async fn update_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    request: web::Json<UpdateDetectionRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let data_sources_json = request.data_sources.as_ref().map(|ds| serde_json::to_string(ds).unwrap_or_default());
    let mitre_techniques_json = request.mitre_techniques.as_ref().map(|mt| serde_json::to_string(mt).unwrap_or_default());
    let mitre_tactics_json = request.mitre_tactics.as_ref().map(|mt| serde_json::to_string(mt).unwrap_or_default());
    let tags_json = request.tags.as_ref().map(|t| serde_json::to_string(t).unwrap_or_default());

    let change_notes = if request.change_notes.is_empty() {
        "Updated detection".to_string()
    } else {
        request.change_notes.clone()
    };

    let new_version = db::update_detection(
        pool.get_ref(),
        &id,
        request.name.as_deref(),
        request.description.as_deref(),
        request.logic_yaml.as_deref(),
        data_sources_json.as_deref(),
        request.severity.as_deref(),
        request.status.as_deref(),
        mitre_techniques_json.as_deref(),
        mitre_tactics_json.as_deref(),
        tags_json.as_deref(),
        request.enabled,
        &claims.sub,
        &change_notes,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to update detection: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update detection")
    })?;

    // Log audit
    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "detection_updated",
        Some("detection"),
        Some(&id),
        Some(&format!("Updated detection to version {}", new_version)),
        None,
    )
    .await;

    let detection = db::get_detection_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch updated detection: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch detection")
        })?
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Detection not found"))?;

    Ok(HttpResponse::Ok().json(row_to_detection_response(&detection)))
}

/// Delete a detection
pub async fn delete_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let deleted = db::delete_detection(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete detection: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete detection")
        })?;

    if deleted {
        let _ = crate::db::log_audit(
            pool.get_ref(),
            &claims.sub,
            "detection_deleted",
            Some("detection"),
            Some(&id),
            Some("Deleted detection"),
            None,
        )
        .await;

        Ok(HttpResponse::NoContent().finish())
    } else {
        Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Detection not found"
        })))
    }
}

/// Get detection version history
pub async fn get_detection_versions(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let versions = db::get_detection_versions(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to get detection versions: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get versions")
        })?;

    let responses: Vec<DetectionVersionResponse> = versions
        .into_iter()
        .map(|v| DetectionVersionResponse {
            id: v.id,
            detection_id: v.detection_id,
            version: v.version,
            logic_yaml: v.logic_yaml,
            change_notes: v.change_notes,
            created_by: v.created_by,
            created_by_name: v.created_by_name,
            created_at: v.created_at,
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

/// Deploy detection (change status)
pub async fn deploy_detection(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    request: web::Json<DeployDetectionRequest>,
) -> Result<HttpResponse> {
    let id = path.into_inner();

    let valid_statuses = ["draft", "testing", "production", "deprecated", "disabled"];
    if !valid_statuses.contains(&request.target_status.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid target status",
            "valid_statuses": valid_statuses
        })));
    }

    let change_notes = request.notes.clone().unwrap_or_else(|| {
        format!("Deployed to {}", request.target_status)
    });

    let new_version = db::update_detection(
        pool.get_ref(),
        &id,
        None,
        None,
        None,
        None,
        None,
        Some(&request.target_status),
        None,
        None,
        None,
        None,
        &claims.sub,
        &change_notes,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to deploy detection: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to deploy detection")
    })?;

    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "detection_deployed",
        Some("detection"),
        Some(&id),
        Some(&format!("Deployed detection to {} (version {})", request.target_status, new_version)),
        None,
    )
    .await;

    let detection = db::get_detection_by_id(pool.get_ref(), &id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch detection: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch detection")
        })?
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Detection not found"))?;

    Ok(HttpResponse::Ok().json(row_to_detection_response(&detection)))
}

/// Validate detection YAML
pub async fn validate_detection(
    _claims: web::ReqData<Claims>,
    request: web::Json<ValidateDetectionRequest>,
) -> Result<HttpResponse> {
    let result = crate::detection_engineering::detections::lint_detection_yaml(&request.yaml);

    let errors: Vec<ValidationErrorResponse> = result
        .errors
        .into_iter()
        .map(|e| ValidationErrorResponse {
            severity: format!("{:?}", e.severity).to_lowercase(),
            code: e.code,
            message: e.message,
            location: e.location,
            suggestion: e.suggestion,
        })
        .collect();

    let quality_score = if result.parsed {
        Detection::from_yaml(&request.yaml)
            .ok()
            .map(|d| d.quality_score())
    } else {
        None
    };

    Ok(HttpResponse::Ok().json(ValidationResponse {
        valid: result.valid,
        parsed: result.parsed,
        errors,
        quality_score,
    }))
}

// =============================================================================
// Coverage Endpoints
// =============================================================================

/// Get coverage analysis
pub async fn get_coverage(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    // Fetch all production and testing detections
    let (rows, _) = db::list_detections(
        pool.get_ref(),
        None,
        None,
        None,
        0,
        1000, // Get all for analysis
    )
    .await
    .map_err(|e| {
        log::error!("Failed to list detections: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to analyze coverage")
    })?;

    // Convert to Detection structs for analysis
    let detections: Vec<Detection> = rows
        .iter()
        .filter_map(|row| row_to_detection(row).ok())
        .collect();

    let analyzer = CoverageAnalyzer::new();
    let score = analyzer.analyze(&detections);

    Ok(HttpResponse::Ok().json(CoverageResponse {
        overall_percentage: score.overall_percentage,
        weighted_score: score.weighted_score,
        total_techniques: score.total_techniques,
        covered_techniques: score.covered_techniques,
        fully_covered: score.fully_covered,
        production_detections: score.production_detections,
        total_detections: score.total_detections,
        tactic_scores: serde_json::to_value(&score.tactic_scores).unwrap_or_default(),
        data_source_coverage: serde_json::to_value(&score.data_source_coverage).unwrap_or_default(),
    }))
}

/// Get coverage gaps
pub async fn get_coverage_gaps(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let (rows, _) = db::list_detections(
        pool.get_ref(),
        None,
        None,
        None,
        0,
        1000,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to list detections: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to analyze gaps")
    })?;

    let detections: Vec<Detection> = rows
        .iter()
        .filter_map(|row| row_to_detection(row).ok())
        .collect();

    let analyzer = CoverageAnalyzer::new();
    let score = analyzer.analyze(&detections);

    let gaps: Vec<CoverageGapResponse> = score
        .top_gaps
        .into_iter()
        .map(|g| CoverageGapResponse {
            technique_id: g.technique_id,
            technique_name: g.technique_name,
            tactics: g.tactics,
            priority: format!("{:?}", g.priority).to_lowercase(),
            required_data_sources: g.required_data_sources,
            available_data_sources: g.available_data_sources,
            suggestions: g.suggestions,
            references: g.references,
            estimated_effort: g.estimated_effort,
        })
        .collect();

    Ok(HttpResponse::Ok().json(gaps))
}

// =============================================================================
// False Positive Endpoints
// =============================================================================

/// Report a false positive
pub async fn report_false_positive(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    request: web::Json<ReportFalsePositiveRequest>,
) -> Result<HttpResponse> {
    let detection_id = path.into_inner();
    let fp_id = format!("FP-{}", Uuid::new_v4().to_string()[..8].to_uppercase());

    let alert_data_json = request.alert_data.as_ref().map(|d| d.to_string());
    let tags_json = serde_json::to_string(&request.tags).unwrap_or_default();

    db::report_false_positive(
        pool.get_ref(),
        &fp_id,
        &detection_id,
        &request.alert_id,
        &request.reason,
        request.explanation.as_deref(),
        request.evidence.as_deref(),
        None, // pattern
        request.exception_rule.as_deref(),
        &request.priority,
        &claims.sub,
        alert_data_json.as_deref(),
        &tags_json,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to report false positive: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to report false positive")
    })?;

    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "fp_reported",
        Some("false_positive"),
        Some(&fp_id),
        Some(&format!("Reported FP for detection {}: {}", detection_id, request.reason)),
        None,
    )
    .await;

    let fp = db::get_false_positive_by_id(pool.get_ref(), &fp_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch FP: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch FP")
        })?
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("FP not found"))?;

    Ok(HttpResponse::Created().json(row_to_fp_response(&fp)))
}

/// List false positives for a detection
pub async fn list_false_positives(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    path: web::Path<String>,
    query: web::Query<ListFalsePositivesQuery>,
) -> Result<HttpResponse> {
    let detection_id = path.into_inner();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(200);

    let (rows, total) = db::list_detection_false_positives(
        pool.get_ref(),
        &detection_id,
        query.status.as_deref(),
        offset,
        limit,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to list FPs: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to list false positives")
    })?;

    let items: Vec<FalsePositiveResponse> = rows.iter().map(row_to_fp_response).collect();

    Ok(HttpResponse::Ok().json(PaginatedResponse {
        items,
        total,
        offset,
        limit,
    }))
}

/// Update false positive status
pub async fn update_false_positive(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<(String, String)>,
    request: web::Json<UpdateFalsePositiveRequest>,
) -> Result<HttpResponse> {
    let (detection_id, fp_id) = path.into_inner();

    let updated = db::update_false_positive_status(
        pool.get_ref(),
        &fp_id,
        &request.status,
        request.resolution_notes.as_deref(),
        if request.status == "resolved" || request.status == "rejected" {
            Some(&claims.sub)
        } else {
            None
        },
    )
    .await
    .map_err(|e| {
        log::error!("Failed to update FP: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update false positive")
    })?;

    if !updated {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "False positive not found"
        })));
    }

    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "fp_updated",
        Some("false_positive"),
        Some(&fp_id),
        Some(&format!("Updated FP status to {}", request.status)),
        None,
    )
    .await;

    let fp = db::get_false_positive_by_id(pool.get_ref(), &fp_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch FP: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch FP")
        })?
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("FP not found"))?;

    Ok(HttpResponse::Ok().json(row_to_fp_response(&fp)))
}

/// Apply tuning to a detection
pub async fn apply_tuning(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    request: web::Json<ApplyTuningRequest>,
) -> Result<HttpResponse> {
    let detection_id = path.into_inner();
    let tuning_id = format!("TUN-{}", Uuid::new_v4().to_string()[..8].to_uppercase());

    let related_fp_ids_json = serde_json::to_string(&request.related_fp_ids).unwrap_or_default();

    db::apply_detection_tuning(
        pool.get_ref(),
        &tuning_id,
        &detection_id,
        &request.tuning_type,
        &request.original_value,
        &request.new_value,
        &request.reason,
        &related_fp_ids_json,
        &claims.sub,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to apply tuning: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to apply tuning")
    })?;

    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "detection_tuned",
        Some("detection"),
        Some(&detection_id),
        Some(&format!("Applied {} tuning: {}", request.tuning_type, request.reason)),
        None,
    )
    .await;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": tuning_id,
        "detection_id": detection_id,
        "tuning_type": request.tuning_type,
        "applied": true
    })))
}

/// Get tuning history
pub async fn get_tuning_history(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let detection_id = path.into_inner();

    let history = db::get_detection_tuning_history(pool.get_ref(), &detection_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get tuning history: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get tuning history")
        })?;

    let responses: Vec<TuningResponse> = history
        .into_iter()
        .map(|t| TuningResponse {
            id: t.id,
            detection_id: t.detection_id,
            tuning_type: t.tuning_type,
            original_value: t.original_value,
            new_value: t.new_value,
            reason: t.reason,
            related_fp_ids: serde_json::from_str(&t.related_fp_ids).unwrap_or_default(),
            applied_at: t.applied_at,
            applied_by: t.applied_by,
            applied_by_name: t.applied_by_name,
            active: t.active,
            rolled_back_at: t.rolled_back_at,
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

// =============================================================================
// Testing Endpoints
// =============================================================================

/// Create a test case
pub async fn create_test(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<String>,
    request: web::Json<CreateTestRequest>,
) -> Result<HttpResponse> {
    let detection_id = path.into_inner();
    let test_id = format!("TEST-{}", Uuid::new_v4().to_string()[..8].to_uppercase());

    let input_logs_json = serde_json::to_string(&request.input_logs).unwrap_or_default();
    let expected_result_json = serde_json::to_string(&request.expected_result).unwrap_or_default();
    let tags_json = serde_json::to_string(&request.tags).unwrap_or_default();

    db::create_detection_test(
        pool.get_ref(),
        &test_id,
        &detection_id,
        &request.name,
        request.description.as_deref(),
        &request.test_type,
        &input_logs_json,
        &expected_result_json,
        &request.priority,
        &tags_json,
        &claims.sub,
    )
    .await
    .map_err(|e| {
        log::error!("Failed to create test: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create test")
    })?;

    let _ = crate::db::log_audit(
        pool.get_ref(),
        &claims.sub,
        "test_created",
        Some("detection_test"),
        Some(&test_id),
        Some(&format!("Created test '{}' for detection {}", request.name, detection_id)),
        None,
    )
    .await;

    let test = db::get_detection_test_by_id(pool.get_ref(), &test_id)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch test: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch test")
        })?
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Test not found"))?;

    Ok(HttpResponse::Created().json(row_to_test_response(&test, None)))
}

/// List tests for a detection
pub async fn list_tests(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let detection_id = path.into_inner();

    let tests = db::list_detection_tests(pool.get_ref(), &detection_id)
        .await
        .map_err(|e| {
            log::error!("Failed to list tests: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to list tests")
        })?;

    // Get latest runs for each test
    let runs = db::get_latest_test_runs_for_detection(pool.get_ref(), &detection_id)
        .await
        .unwrap_or_default();

    let run_map: std::collections::HashMap<_, _> = runs.into_iter()
        .map(|r| (r.test_id.clone(), r))
        .collect();

    let responses: Vec<TestResponse> = tests
        .iter()
        .map(|t| {
            let last_run = run_map.get(&t.id).map(row_to_test_run_response);
            row_to_test_response(t, last_run)
        })
        .collect();

    Ok(HttpResponse::Ok().json(responses))
}

/// Run a test
pub async fn run_test(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<Claims>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (detection_id, test_id) = path.into_inner();

    // Get the detection
    let detection_row = db::get_detection_by_id(pool.get_ref(), &detection_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get detection: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get detection")
        })?
        .ok_or_else(|| {
            actix_web::error::ErrorNotFound("Detection not found")
        })?;

    let detection = row_to_detection(&detection_row)
        .map_err(|e| {
            log::error!("Failed to parse detection: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to parse detection")
        })?;

    // Get the test
    let test_row = db::get_detection_test_by_id(pool.get_ref(), &test_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get test: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get test")
        })?
        .ok_or_else(|| {
            actix_web::error::ErrorNotFound("Test not found")
        })?;

    // Parse test inputs
    let input_logs: Vec<serde_json::Value> = serde_json::from_str(&test_row.input_logs_json)
        .unwrap_or_default();
    let expected_result: ExpectedResultInput = serde_json::from_str(&test_row.expected_result)
        .unwrap_or_else(|_| ExpectedResultInput {
            should_alert: true,
            alert_count: None,
            severity: None,
            expected_fields: None,
            max_execution_ms: None,
        });

    // Create test object
    let test = DetectionTest {
        id: test_row.id.clone(),
        detection_id: test_row.detection_id.clone(),
        name: test_row.name.clone(),
        description: test_row.description.clone(),
        test_type: test_row.test_type.parse().unwrap_or(TestType::Unit),
        input_logs,
        expected_result: ExpectedResult {
            should_alert: expected_result.should_alert,
            alert_count: expected_result.alert_count,
            severity: expected_result.severity.and_then(|s| s.parse().ok()),
            expected_fields: expected_result.expected_fields,
            field_patterns: None,
            max_execution_ms: expected_result.max_execution_ms,
        },
        priority: test_row.priority.parse().unwrap_or(TestPriority::Medium),
        tags: serde_json::from_str(&test_row.tags).unwrap_or_default(),
        enabled: test_row.enabled,
        created_by: test_row.created_by.clone(),
        created_at: chrono::DateTime::parse_from_rfc3339(&test_row.created_at)
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        updated_at: chrono::DateTime::parse_from_rfc3339(&test_row.updated_at)
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    };

    // Run the test
    let executor = TestExecutor::new(detection);
    let result = executor.run_test(&test);

    // Store the result
    let run_id = format!("RUN-{}", Uuid::new_v4().to_string()[..8].to_uppercase());
    let result_json = serde_json::to_string(&result).unwrap_or_default();
    let actual_output_json = serde_json::to_string(&result.actual_alerts).unwrap_or_default();

    db::record_test_run(
        pool.get_ref(),
        &run_id,
        &test_id,
        &detection_id,
        &result_json,
        &actual_output_json,
        result.passed,
        detection_row.version as u32,
        "test",
        Some(&claims.sub),
    )
    .await
    .map_err(|e| {
        log::error!("Failed to record test run: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to record test run")
    })?;

    Ok(HttpResponse::Ok().json(TestRunResponse {
        id: run_id,
        test_id,
        detection_id,
        passed: result.passed,
        result: serde_json::to_value(&result).unwrap_or_default(),
        actual_output: serde_json::to_value(&result.actual_alerts).unwrap_or_default(),
        detection_version: detection_row.version,
        environment: "test".to_string(),
        triggered_by: Some(claims.sub.clone()),
        run_at: Utc::now().to_rfc3339(),
    }))
}

/// Generate sample logs for testing
pub async fn generate_sample_logs(
    _claims: web::ReqData<Claims>,
    request: web::Json<GenerateSampleLogsRequest>,
) -> Result<HttpResponse> {
    let mut logs = Vec::new();

    if let Some(ref technique) = request.technique_id {
        logs.extend(SampleLogGenerator::attack_sample(technique));
    }

    if let Some(ref sample_type) = request.sample_type {
        logs.extend(SampleLogGenerator::benign_sample(sample_type));
    }

    if logs.is_empty() {
        // Generate a default sample
        logs.push(SampleLogGenerator::sysmon_process_creation(
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c echo test",
            "C:\\Windows\\explorer.exe",
            "DOMAIN\\user",
        ));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "logs": logs,
        "count": logs.len()
    })))
}

// =============================================================================
// Dashboard Endpoint
// =============================================================================

/// Get detection engineering dashboard
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<Claims>,
) -> Result<HttpResponse> {
    let stats = db::get_detection_dashboard_stats(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to get dashboard stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get dashboard stats")
        })?;

    let test_pass_rate = if stats.total_tests > 0 {
        (stats.passing_tests as f64 / stats.total_tests as f64) * 100.0
    } else {
        0.0
    };

    // Get recent activity - last 10 updated detections
    let recent_activity = get_recent_detection_activity(pool.get_ref()).await.unwrap_or_default();

    Ok(HttpResponse::Ok().json(DashboardResponse {
        total_detections: stats.total_detections,
        production_detections: stats.production_detections,
        testing_detections: stats.testing_detections,
        draft_detections: stats.draft_detections,
        pending_false_positives: stats.pending_false_positives,
        total_tests: stats.total_tests,
        passing_tests: stats.passing_tests,
        test_pass_rate,
        unique_techniques_covered: stats.unique_techniques_covered,
        recent_activity,
    }))
}

// =============================================================================
// Helper Functions
// =============================================================================

fn row_to_detection_response(row: &db::DetectionRow) -> DetectionResponse {
    let data_sources: Vec<DataSourceInput> = serde_json::from_str(&row.data_sources).unwrap_or_default();
    let mitre_techniques: Vec<String> = row.mitre_techniques.as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let mitre_tactics: Vec<String> = row.mitre_tactics.as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let tags: Vec<String> = row.tags.as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    // Calculate quality score
    let quality_score = row_to_detection(row)
        .map(|d| d.quality_score())
        .unwrap_or(0.0);

    DetectionResponse {
        id: row.id.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        logic_yaml: row.logic_yaml.clone(),
        data_sources,
        severity: row.severity.clone(),
        status: row.status.clone(),
        author_id: row.author_id.clone(),
        author_name: row.author_name.clone(),
        version: row.version,
        mitre_techniques,
        mitre_tactics,
        tags,
        fp_rate: row.fp_rate,
        confidence: row.confidence,
        enabled: row.enabled,
        quality_score,
        created_at: row.created_at.clone(),
        updated_at: row.updated_at.clone(),
    }
}

fn row_to_detection(row: &db::DetectionRow) -> anyhow::Result<Detection> {
    let data_sources: Vec<DataSource> = serde_json::from_str(&row.data_sources)
        .map(|ds: Vec<DataSourceInput>| {
            ds.into_iter()
                .map(|d| DataSource {
                    name: d.name,
                    event_ids: d.event_ids,
                    required: d.required,
                    description: d.description,
                })
                .collect()
        })
        .unwrap_or_default();

    let mitre_techniques: Vec<String> = row.mitre_techniques.as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let mitre_tactics: Vec<String> = row.mitre_tactics.as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let tags: Vec<String> = row.tags.as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = chrono::DateTime::parse_from_rfc3339(&row.updated_at)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(Detection {
        id: row.id.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        severity: row.severity.parse().unwrap_or(DetectionSeverity::Medium),
        status: row.status.parse().unwrap_or(DetectionStatus::Draft),
        logic: DetectionLogic {
            language: "custom".to_string(),
            query: row.logic_yaml.clone(),
            field_mappings: std::collections::HashMap::new(),
            aggregation: None,
            threshold: None,
            timeframe: None,
            condition: None,
        },
        data_sources,
        mitre_techniques,
        mitre_tactics,
        metadata: DetectionMetadata {
            author: row.author_id.clone(),
            author_email: None,
            created_at,
            updated_at,
            references: Vec::new(),
            related_detections: Vec::new(),
            tags,
            license: None,
            source: None,
        },
        version: row.version as u32,
        fp_rate: row.fp_rate,
        confidence: row.confidence,
        enabled: row.enabled,
    })
}

fn row_to_fp_response(row: &db::FalsePositiveRow) -> FalsePositiveResponse {
    let pattern: Option<serde_json::Value> = row.pattern.as_ref()
        .and_then(|p| serde_json::from_str(p).ok());
    let alert_data: Option<serde_json::Value> = row.alert_data.as_ref()
        .and_then(|d| serde_json::from_str(d).ok());
    let tags: Vec<String> = serde_json::from_str(&row.tags).unwrap_or_default();

    FalsePositiveResponse {
        id: row.id.clone(),
        detection_id: row.detection_id.clone(),
        alert_id: row.alert_id.clone(),
        reason: row.reason.clone(),
        explanation: row.explanation.clone(),
        evidence: row.evidence.clone(),
        pattern,
        exception_rule: row.exception_rule.clone(),
        status: row.status.clone(),
        priority: row.priority.clone(),
        reported_by: row.reported_by.clone(),
        reported_by_name: row.reported_by_name.clone(),
        assigned_to: row.assigned_to.clone(),
        resolution_notes: row.resolution_notes.clone(),
        resolved_by: row.resolved_by.clone(),
        resolved_at: row.resolved_at.clone(),
        alert_data,
        tags,
        created_at: row.created_at.clone(),
        updated_at: row.updated_at.clone(),
    }
}

fn row_to_test_response(row: &db::DetectionTestRow, last_run: Option<TestRunResponse>) -> TestResponse {
    let input_logs: Vec<serde_json::Value> = serde_json::from_str(&row.input_logs_json).unwrap_or_default();
    let expected_result: serde_json::Value = serde_json::from_str(&row.expected_result).unwrap_or_default();
    let tags: Vec<String> = serde_json::from_str(&row.tags).unwrap_or_default();

    TestResponse {
        id: row.id.clone(),
        detection_id: row.detection_id.clone(),
        name: row.name.clone(),
        description: row.description.clone(),
        test_type: row.test_type.clone(),
        input_logs,
        expected_result,
        priority: row.priority.clone(),
        tags,
        enabled: row.enabled,
        created_by: row.created_by.clone(),
        created_at: row.created_at.clone(),
        updated_at: row.updated_at.clone(),
        last_run,
    }
}

fn row_to_test_run_response(row: &db::TestRunRow) -> TestRunResponse {
    let result: serde_json::Value = serde_json::from_str(&row.result).unwrap_or_default();
    let actual_output: serde_json::Value = serde_json::from_str(&row.actual_output).unwrap_or_default();

    TestRunResponse {
        id: row.id.clone(),
        test_id: row.test_id.clone(),
        detection_id: row.detection_id.clone(),
        passed: row.passed,
        result,
        actual_output,
        detection_version: row.detection_version,
        environment: row.environment.clone(),
        triggered_by: row.triggered_by.clone(),
        run_at: row.run_at.clone(),
    }
}

/// Get recent detection activity for dashboard
async fn get_recent_detection_activity(pool: &sqlx::SqlitePool) -> anyhow::Result<Vec<serde_json::Value>> {
    // Query recent detection updates
    let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
        r#"
        SELECT d.id, d.name, d.status, d.updated_at, COALESCE(u.username, 'Unknown')
        FROM detections d
        LEFT JOIN users u ON d.author_id = u.id
        ORDER BY d.updated_at DESC
        LIMIT 10
        "#
    )
    .fetch_all(pool)
    .await?;

    let mut activities = Vec::new();
    for (id, name, status, updated_at, author) in rows {
        activities.push(serde_json::json!({
            "id": id,
            "name": name,
            "type": "detection_update",
            "status": status,
            "timestamp": updated_at,
            "author": author,
            "description": format!("Detection '{}' was updated", name)
        }));
    }

    // Also get recent false positives
    let fp_rows = sqlx::query_as::<_, (String, String, String, String)>(
        r#"
        SELECT fp.id, d.name, fp.status, fp.created_at
        FROM detection_false_positives fp
        JOIN detections d ON fp.detection_id = d.id
        ORDER BY fp.created_at DESC
        LIMIT 5
        "#
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (fp_id, detection_name, status, created_at) in fp_rows {
        activities.push(serde_json::json!({
            "id": fp_id,
            "name": detection_name,
            "type": "false_positive",
            "status": status,
            "timestamp": created_at,
            "description": format!("False positive reported for '{}'", detection_name)
        }));
    }

    // Sort by timestamp descending
    activities.sort_by(|a, b| {
        let ts_a = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_b.cmp(ts_a)
    });

    // Return top 10 combined
    activities.truncate(10);

    Ok(activities)
}

// =============================================================================
// Route Configuration
// =============================================================================

/// Configure detection engineering API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/detection-engineering")
            // Detection CRUD
            .route("/detections", web::post().to(create_detection))
            .route("/detections", web::get().to(list_detections))
            .route("/detections/validate", web::post().to(validate_detection))
            .route("/detections/coverage", web::get().to(get_coverage))
            .route("/detections/coverage/gaps", web::get().to(get_coverage_gaps))
            .route("/detections/dashboard", web::get().to(get_dashboard))
            .route("/detections/sample-logs", web::post().to(generate_sample_logs))
            .route("/detections/{id}", web::get().to(get_detection))
            .route("/detections/{id}", web::put().to(update_detection))
            .route("/detections/{id}", web::delete().to(delete_detection))
            .route("/detections/{id}/versions", web::get().to(get_detection_versions))
            .route("/detections/{id}/deploy", web::post().to(deploy_detection))
            // False positives
            .route("/detections/{id}/false-positives", web::post().to(report_false_positive))
            .route("/detections/{id}/false-positives", web::get().to(list_false_positives))
            .route("/detections/{detection_id}/false-positives/{fp_id}", web::put().to(update_false_positive))
            // Tuning
            .route("/detections/{id}/tune", web::post().to(apply_tuning))
            .route("/detections/{id}/tuning-history", web::get().to(get_tuning_history))
            // Testing
            .route("/detections/{id}/tests", web::post().to(create_test))
            .route("/detections/{id}/tests", web::get().to(list_tests))
            .route("/detections/{detection_id}/tests/{test_id}/run", web::post().to(run_test))
    );
}
