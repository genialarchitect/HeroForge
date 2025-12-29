//! Yellow Team API endpoints
//!
//! Provides REST API endpoints for:
//! - DevSecOps dashboard
//! - Metrics retrieval and recording
//! - MTTR analysis
//! - Vulnerability density trends
//! - SLA compliance monitoring
//! - Security debt analysis
//! - Pipeline gate management
//! - SBOM (Software Bill of Materials) generation and analysis
//! - API Security Scanner (OpenAPI, Swagger, GraphQL)

use actix_multipart::Multipart;
use actix_web::{web, HttpResponse};
use chrono::NaiveDate;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db::devsecops;
use crate::db::sbom as sbom_db;
use crate::db::threat_modeling as tm_db;
use crate::db::yellow_team as yt_db;
use crate::web::auth;
use crate::yellow_team::devsecops::{
    CreatePipelineGateRequest, UpdatePipelineGateRequest, EvaluateGateRequest,
    MetricsQuery, ProjectHealthQuery,
};
use crate::yellow_team::sbom::SbomGenerator;
use crate::yellow_team::api_security::ApiSecurityScanner;
use crate::yellow_team::types::{
    ApiSpecFormat, ApiSpecType, SbomFormat, ApiSecurityFinding, ApiEndpoint, Severity,
    ApiSecurityCategory, ApiSecurityFindingType, HttpMethod, RemediationEffort,
    CreateThreatModelRequest, UpdateThreatModelRequest,
    AddComponentRequest, AddDataFlowRequest, AddTrustBoundaryRequest, AddMitigationRequest,
    UpdateThreatStatusRequest, ThreatModelAnalyzer, get_architecture_templates,
    Sbom, FullSbom, SbomComponent, SbomStats, SourceFile, ComponentVuln,
    SastFinding, SastLanguage, SastSourceType, StartSastScanRequest as SastScanRequest,
};

// ============================================================================
// API Security Helper Types and Functions
// ============================================================================

/// API scan result containing findings and metadata
#[derive(Debug, Clone)]
pub struct ApiScanResult {
    pub spec_version: Option<String>,
    pub endpoints: Vec<ApiEndpoint>,
    pub findings: Vec<ApiSecurityFinding>,
    pub summary: ApiScanSummary,
}

/// Summary statistics for an API scan
#[derive(Debug, Clone, Default)]
pub struct ApiScanSummary {
    pub total_endpoints: usize,
    pub endpoints_with_auth: usize,
    pub endpoints_without_auth: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub security_score: f32,
}

/// Detect API specification type from content
fn detect_spec_type(content: &str) -> ApiSpecType {
    // Try to parse as JSON first
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        return detect_from_json(&json);
    }

    // Try YAML
    if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(content) {
        return detect_from_json(&yaml);
    }

    // Check for GraphQL schema patterns
    if content.contains("type Query") || content.contains("schema {") || content.contains("type Mutation") {
        return ApiSpecType::GraphQL;
    }

    ApiSpecType::Unknown
}

/// Helper to detect spec type from parsed JSON/YAML
fn detect_from_json(json: &serde_json::Value) -> ApiSpecType {
    // OpenAPI 3.x
    if json.get("openapi").is_some() {
        return ApiSpecType::OpenApi3;
    }

    // Swagger 2.x
    if json.get("swagger").is_some() {
        return ApiSpecType::Swagger2;
    }

    // AsyncAPI
    if json.get("asyncapi").is_some() {
        return ApiSpecType::AsyncApi;
    }

    ApiSpecType::Unknown
}

/// Scan an API specification and return findings
fn scan_api_spec(content: &str, spec_type: ApiSpecType) -> Result<ApiScanResult, String> {
    let mut scanner = ApiSecurityScanner::new();
    let format = match spec_type {
        ApiSpecType::OpenApi3 => ApiSpecFormat::OpenApi3,
        ApiSpecType::Swagger2 | ApiSpecType::OpenApi2 => ApiSpecFormat::OpenApi2,
        ApiSpecType::GraphQL => ApiSpecFormat::GraphQL,
        ApiSpecType::AsyncApi => ApiSpecFormat::AsyncApi,
        _ => return Err("Unsupported API specification type".to_string()),
    };

    let findings = scanner.scan_openapi(content, format)
        .map_err(|e| e.to_string())?;

    // Parse endpoints from spec
    let endpoints = parse_endpoints(content, spec_type);

    // Get spec version
    let spec_version = extract_spec_version(content);

    // Calculate summary
    let summary = calculate_summary(&endpoints, &findings);

    Ok(ApiScanResult {
        spec_version,
        endpoints,
        findings,
        summary,
    })
}

/// Parse endpoints from API spec
fn parse_endpoints(content: &str, spec_type: ApiSpecType) -> Vec<ApiEndpoint> {
    let mut endpoints = Vec::new();

    let json: serde_json::Value = serde_json::from_str(content)
        .or_else(|_| serde_yaml::from_str(content))
        .unwrap_or_default();

    if let Some(paths) = json.get("paths").and_then(|p| p.as_object()) {
        for (path, path_item) in paths {
            let methods = ["get", "post", "put", "patch", "delete", "head", "options"];
            for method_str in methods {
                if let Some(operation) = path_item.get(method_str) {
                    let http_method = match method_str {
                        "get" => HttpMethod::Get,
                        "post" => HttpMethod::Post,
                        "put" => HttpMethod::Put,
                        "patch" => HttpMethod::Patch,
                        "delete" => HttpMethod::Delete,
                        "head" => HttpMethod::Head,
                        "options" => HttpMethod::Options,
                        _ => HttpMethod::Get,
                    };

                    let has_auth = operation.get("security").is_some()
                        || path_item.get("security").is_some()
                        || json.get("security").is_some();

                    endpoints.push(ApiEndpoint {
                        id: Uuid::new_v4().to_string(),
                        scan_id: String::new(),
                        path: path.clone(),
                        method: http_method,
                        operation_id: operation.get("operationId").and_then(|v| v.as_str()).map(String::from),
                        summary: operation.get("summary").and_then(|v| v.as_str()).map(String::from),
                        description: operation.get("description").and_then(|v| v.as_str()).map(String::from),
                        security_requirements: Vec::new(),
                        parameters: Vec::new(),
                        request_body: None,
                        responses: Vec::new(),
                        has_auth,
                        tags: operation.get("tags")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                            .unwrap_or_default(),
                        deprecated: operation.get("deprecated").and_then(|v| v.as_bool()).unwrap_or(false),
                        created_at: chrono::Utc::now(),
                    });
                }
            }
        }
    }

    endpoints
}

/// Extract API spec version
fn extract_spec_version(content: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(content)
        .or_else(|_| serde_yaml::from_str(content))
        .ok()?;

    json.get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Calculate scan summary statistics
fn calculate_summary(endpoints: &[ApiEndpoint], findings: &[ApiSecurityFinding]) -> ApiScanSummary {
    let total_endpoints = endpoints.len();
    let endpoints_with_auth = endpoints.iter().filter(|e| e.has_auth).count();
    let endpoints_without_auth = total_endpoints - endpoints_with_auth;

    let total_findings = findings.len();
    let critical_findings = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high_findings = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
    let medium_findings = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
    let low_findings = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count();
    let info_findings = findings.iter().filter(|f| matches!(f.severity, Severity::Info)).count();

    // Calculate security score (0-100)
    let base_score = 100.0f32;
    let penalty = (critical_findings * 20 + high_findings * 10 + medium_findings * 5 + low_findings * 2) as f32;
    let auth_penalty = if total_endpoints > 0 {
        (endpoints_without_auth as f32 / total_endpoints as f32) * 20.0
    } else {
        0.0
    };
    let security_score = (base_score - penalty - auth_penalty).max(0.0);

    ApiScanSummary {
        total_endpoints,
        endpoints_with_auth,
        endpoints_without_auth,
        total_findings,
        critical_findings,
        high_findings,
        medium_findings,
        low_findings,
        info_findings,
        security_score,
    }
}

// ============================================================================
// SBOM Helper Types and Functions
// ============================================================================

/// Dependency file type detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyFileType {
    CargoToml,      // Rust
    PackageJson,    // Node.js
    RequirementsTxt, // Python
    GoMod,          // Go
    PomXml,         // Java Maven
    BuildGradle,    // Java Gradle
    GemfileLock,    // Ruby
    ComposerJson,   // PHP
    Unknown,
}

impl DependencyFileType {
    pub fn from_filename(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.ends_with("cargo.toml") { return DependencyFileType::CargoToml; }
        if lower.ends_with("package.json") { return DependencyFileType::PackageJson; }
        if lower.ends_with("requirements.txt") || lower.ends_with("requirements-dev.txt") { return DependencyFileType::RequirementsTxt; }
        if lower.ends_with("go.mod") { return DependencyFileType::GoMod; }
        if lower.ends_with("pom.xml") { return DependencyFileType::PomXml; }
        if lower.ends_with("build.gradle") || lower.ends_with("build.gradle.kts") { return DependencyFileType::BuildGradle; }
        if lower.ends_with("gemfile.lock") { return DependencyFileType::GemfileLock; }
        if lower.ends_with("composer.json") { return DependencyFileType::ComposerJson; }
        DependencyFileType::Unknown
    }
}

impl std::fmt::Display for DependencyFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyFileType::CargoToml => write!(f, "cargo_toml"),
            DependencyFileType::PackageJson => write!(f, "package_json"),
            DependencyFileType::RequirementsTxt => write!(f, "requirements_txt"),
            DependencyFileType::GoMod => write!(f, "go_mod"),
            DependencyFileType::PomXml => write!(f, "pom_xml"),
            DependencyFileType::BuildGradle => write!(f, "build_gradle"),
            DependencyFileType::GemfileLock => write!(f, "gemfile_lock"),
            DependencyFileType::ComposerJson => write!(f, "composer_json"),
            DependencyFileType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Generate SBOM from dependency files
fn generate_sbom(
    user_id: &str,
    project_name: &str,
    project_version: Option<&str>,
    files: Vec<(String, String)>,
    format: SbomFormat,
) -> Result<crate::yellow_team::types::FullSbom, String> {
    use crate::yellow_team::types::*;
    use chrono::Utc;

    let sbom_id = Uuid::new_v4().to_string();
    let mut all_components = Vec::new();
    let mut source_files = Vec::new();

    for (filename, content) in files {
        source_files.push(SourceFile {
            path: filename.clone(),
            file_type: DependencyFileType::from_filename(&filename).to_string(),
            checksum: None,
        });

        let file_type = DependencyFileType::from_filename(&filename);
        let mut generator = SbomGenerator::new(project_name, project_version, &filename);

        match file_type {
            DependencyFileType::CargoToml => { let _ = generator.parse_cargo_toml(&content); }
            DependencyFileType::PackageJson => { let _ = generator.parse_package_json(&content); }
            DependencyFileType::RequirementsTxt => { let _ = generator.parse_requirements_txt(&content); }
            DependencyFileType::GoMod => { let _ = generator.parse_go_mod(&content); }
            _ => {}
        }

        // Use components directly from generator (already SbomComponent type)
        for mut comp in generator.components {
            // Update project_id to link to this SBOM
            comp.project_id = sbom_id.clone();
            all_components.push(comp);
        }
    }

    // Calculate stats
    let stats = SbomStats {
        total_components: all_components.len() as i32,
        direct_dependencies: all_components.iter()
            .filter(|c| c.is_direct())
            .count() as i32,
        transitive_dependencies: all_components.iter()
            .filter(|c| !c.is_direct())
            .count() as i32,
        vulnerabilities_found: 0,
        critical_vulns: 0,
        high_vulns: 0,
        medium_vulns: 0,
        low_vulns: 0,
        copyleft_licenses: 0,
        permissive_licenses: 0,
        unknown_licenses: 0,
    };

    Ok(Sbom {
        id: sbom_id,
        user_id: user_id.to_string(),
        project_name: project_name.to_string(),
        project_version: project_version.map(String::from),
        format,
        stats,
        source_files,
        components: all_components,
        vulnerabilities: Vec::new(),
        licenses: Vec::new(),
        dependencies: Vec::new(),
        generated_at: Utc::now(),
        created_at: Utc::now(),
    })
}

/// Export SBOM to CycloneDX format
fn export_cyclonedx(sbom: &crate::yellow_team::types::FullSbom) -> Result<String, String> {
    serde_json::to_string_pretty(sbom).map_err(|e| e.to_string())
}

/// Export SBOM to SPDX format
fn export_spdx(sbom: &crate::yellow_team::types::FullSbom) -> Result<String, String> {
    // For now, export as JSON with SPDX-like structure
    serde_json::to_string_pretty(sbom).map_err(|e| e.to_string())
}

/// Correlate vulnerabilities with components
async fn correlate_vulnerabilities(
    _pool: &SqlitePool,
    sbom: &crate::yellow_team::types::FullSbom,
    _nvd_api_key: Option<String>,
) -> Result<VulnCorrelationResult, String> {
    // Placeholder implementation - in production would query CVE databases
    // Return vulnerabilities from the SBOM itself for now
    Ok(VulnCorrelationResult {
        total_components: sbom.components.len(),
        vulnerable_components: sbom.vulnerabilities.len().min(sbom.components.len()),
        total_vulnerabilities: sbom.vulnerabilities.len(),
        critical_count: sbom.stats.critical_vulns as usize,
        high_count: sbom.stats.high_vulns as usize,
        medium_count: sbom.stats.medium_vulns as usize,
        low_count: sbom.stats.low_vulns as usize,
        vulnerabilities: sbom.vulnerabilities.clone(),
    })
}

/// Vulnerability correlation result
#[derive(Debug, Clone, Serialize)]
pub struct VulnCorrelationResult {
    pub total_components: usize,
    pub vulnerable_components: usize,
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub vulnerabilities: Vec<ComponentVuln>,
}

// ============================================================================
// Query Parameters
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct DashboardQuery {
    pub project_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct DateRangeQuery {
    pub project_id: Option<Uuid>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct MttrQuery {
    pub project_id: Option<Uuid>,
    pub days: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct SlaQuery {
    pub project_id: Option<Uuid>,
    pub days: Option<i32>,
    pub limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct GateListQuery {
    pub project_id: Option<Uuid>,
}

// ============================================================================
// SBOM Query Parameters
// ============================================================================

/// Query parameters for listing SBOMs
#[derive(Debug, Deserialize)]
pub struct ListSbomsQueryParams {
    #[serde(default)]
    pub project_name: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Query parameters for listing components
#[derive(Debug, Deserialize)]
pub struct ListComponentsQueryParams {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub has_vulns: Option<bool>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Query parameters for listing vulnerabilities
#[derive(Debug, Deserialize)]
pub struct ListVulnsQueryParams {
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub has_fix: Option<bool>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Export format path parameter
#[derive(Debug, Deserialize)]
pub struct ExportPath {
    pub id: String,
    pub format: String,
}

/// Response for SBOM generation
#[derive(Debug, Serialize)]
pub struct GenerateSbomResponse {
    pub id: String,
    pub project_name: String,
    pub total_components: usize,
    pub format: String,
    pub message: String,
}

/// Supported file types response
#[derive(Debug, Serialize)]
pub struct SupportedFileType {
    pub name: String,
    pub file_type: String,
    pub ecosystem: String,
    pub description: String,
}

// ============================================================================
// API Security Request/Response Types
// ============================================================================

/// Request to start a new API security scan
#[derive(Debug, Deserialize)]
pub struct StartApiSecurityScanRequest {
    /// Name for the API being scanned
    pub api_name: String,
    /// API specification content (JSON string for OpenAPI/Swagger, SDL for GraphQL)
    pub spec_content: String,
    /// Type of specification: "openapi3", "swagger2", "graphql", or "auto"
    #[serde(default)]
    pub spec_type: Option<String>,
    /// Base URL of the API (optional, extracted from spec if not provided)
    pub base_url: Option<String>,
    /// Customer ID for CRM integration
    pub customer_id: Option<String>,
    /// Engagement ID for CRM integration
    pub engagement_id: Option<String>,
}

/// Response for starting a scan
#[derive(Debug, Serialize)]
pub struct StartApiSecurityScanResponse {
    pub scan_id: String,
    pub status: String,
}

/// Detailed scan response with endpoints and findings summary
#[derive(Debug, Serialize)]
pub struct ApiSecurityScanDetailResponse {
    pub scan: yt_db::ApiSecurityScanRecord,
    pub endpoints: Vec<yt_db::ApiEndpointRecord>,
    pub findings_summary: ApiSecurityFindingsSummary,
}

/// Summary of findings by severity
#[derive(Debug, Serialize)]
pub struct ApiSecurityFindingsSummary {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

/// Request to update finding status
#[derive(Debug, Deserialize)]
pub struct UpdateApiSecurityFindingStatusRequest {
    pub status: String,
}

/// Request to detect spec type
#[derive(Debug, Deserialize)]
pub struct DetectSpecTypeRequest {
    pub spec_content: String,
}

/// Response for spec type detection
#[derive(Debug, Serialize)]
pub struct DetectSpecTypeResponse {
    pub spec_type: String,
    pub display_name: String,
}

// In-memory store for tracking running API security scans
type ApiSecurityScanStatusStore = Arc<Mutex<HashMap<String, String>>>;

// ============================================================================
// Request Bodies
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RecordMetricsRequest {
    pub project_id: Option<Uuid>,
    pub metric_date: Option<String>,
    pub mttr_critical_hours: Option<f64>,
    pub mttr_high_hours: Option<f64>,
    pub mttr_medium_hours: Option<f64>,
    pub mttr_low_hours: Option<f64>,
    pub vulnerability_density: f64,
    pub fix_rate: f64,
    pub sla_compliance_rate: f64,
    pub open_critical: u32,
    pub open_high: u32,
    pub open_medium: u32,
    pub open_low: u32,
    pub security_debt_hours: f64,
    pub pipeline_pass_rate: f64,
    pub scan_coverage: f64,
}

// ============================================================================
// Dashboard Endpoints
// ============================================================================

/// Get DevSecOps dashboard overview
///
/// Returns current metrics, trends, top vulnerabilities, project health,
/// recent fixes, and SLA breaches.
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    query: web::Query<DashboardQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let project_id = query.project_id.map(|p| p.to_string());

    match devsecops::build_dashboard(
        pool.get_ref(),
        org_id,
        project_id.as_deref(),
    ).await {
        Ok(dashboard) => HttpResponse::Ok().json(dashboard),
        Err(e) => {
            log::error!("Failed to build DevSecOps dashboard: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to build dashboard",
                "details": e.to_string()
            }))
        }
    }
}

// ============================================================================
// Metrics Endpoints
// ============================================================================

/// Get historical metrics
///
/// Returns metrics over time for trend analysis.
pub async fn get_metrics(
    pool: web::Data<SqlitePool>,
    query: web::Query<DateRangeQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let project_id = query.project_id.map(|p| p.to_string());

    let start_date = query.start_date.as_ref().and_then(|s| {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
    });
    let end_date = query.end_date.as_ref().and_then(|s| {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
    });

    match devsecops::get_metrics_history(
        pool.get_ref(),
        org_id,
        project_id.as_deref(),
        start_date,
        end_date,
        query.limit,
    ).await {
        Ok(metrics) => HttpResponse::Ok().json(metrics),
        Err(e) => {
            log::error!("Failed to get metrics history: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get metrics history"
            }))
        }
    }
}

/// Record new metrics snapshot
pub async fn record_metrics(
    pool: web::Data<SqlitePool>,
    body: web::Json<RecordMetricsRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let project_id = body.project_id.map(|p| p.to_string());

    let metric_date = body.metric_date.as_ref()
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| chrono::Utc::now().date_naive());

    match devsecops::record_metrics(
        pool.get_ref(),
        org_id,
        project_id.as_deref(),
        metric_date,
        body.mttr_critical_hours,
        body.mttr_high_hours,
        body.mttr_medium_hours,
        body.mttr_low_hours,
        body.vulnerability_density,
        body.fix_rate,
        body.sla_compliance_rate,
        body.open_critical,
        body.open_high,
        body.open_medium,
        body.open_low,
        body.security_debt_hours,
        body.pipeline_pass_rate,
        body.scan_coverage,
    ).await {
        Ok(metrics) => HttpResponse::Created().json(metrics),
        Err(e) => {
            log::error!("Failed to record metrics: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record metrics"
            }))
        }
    }
}

// ============================================================================
// MTTR Endpoints
// ============================================================================

/// Get MTTR breakdown by severity
pub async fn get_mttr(
    pool: web::Data<SqlitePool>,
    query: web::Query<MttrQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let days = query.days.unwrap_or(30);

    match devsecops::get_mttr_breakdown(pool.get_ref(), org_id, days).await {
        Ok((critical, high, medium, low)) => {
            HttpResponse::Ok().json(serde_json::json!({
                "period_days": days,
                "mttr_critical_hours": critical,
                "mttr_high_hours": high,
                "mttr_medium_hours": medium,
                "mttr_low_hours": low,
                "mttr_critical_days": critical.map(|h| h / 24.0),
                "mttr_high_days": high.map(|h| h / 24.0),
                "mttr_medium_days": medium.map(|h| h / 24.0),
                "mttr_low_days": low.map(|h| h / 24.0)
            }))
        }
        Err(e) => {
            log::error!("Failed to get MTTR breakdown: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get MTTR breakdown"
            }))
        }
    }
}

// ============================================================================
// Vulnerability Density Endpoints
// ============================================================================

/// Get vulnerability density trends
pub async fn get_density(
    pool: web::Data<SqlitePool>,
    query: web::Query<DateRangeQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let project_id = query.project_id.map(|p| p.to_string());

    let start_date = query.start_date.as_ref().and_then(|s| {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
    });
    let end_date = query.end_date.as_ref().and_then(|s| {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
    });

    match devsecops::get_metrics_history(
        pool.get_ref(),
        org_id,
        project_id.as_deref(),
        start_date,
        end_date,
        query.limit,
    ).await {
        Ok(metrics) => {
            let density_data: Vec<serde_json::Value> = metrics.iter().map(|m| {
                serde_json::json!({
                    "date": m.metric_date.to_string(),
                    "vulnerability_density": m.vulnerability_density,
                    "open_vulns": m.total_open_vulns()
                })
            }).collect();

            HttpResponse::Ok().json(serde_json::json!({
                "density_trend": density_data
            }))
        }
        Err(e) => {
            log::error!("Failed to get density trends: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get density trends"
            }))
        }
    }
}

// ============================================================================
// SLA Endpoints
// ============================================================================

/// Get SLA compliance statistics
pub async fn get_sla(
    pool: web::Data<SqlitePool>,
    query: web::Query<SlaQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let days = query.days.unwrap_or(30);

    match devsecops::get_sla_statistics(pool.get_ref(), org_id, days).await {
        Ok((within_sla, total_resolved, compliance_rate)) => {
            HttpResponse::Ok().json(serde_json::json!({
                "period_days": days,
                "within_sla": within_sla,
                "total_resolved": total_resolved,
                "compliance_rate": compliance_rate,
                "sla_targets": {
                    "critical_hours": 24,
                    "high_hours": 72,
                    "medium_hours": 168,
                    "low_hours": 720
                }
            }))
        }
        Err(e) => {
            log::error!("Failed to get SLA statistics: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get SLA statistics"
            }))
        }
    }
}

/// Get SLA breaches
pub async fn get_sla_breaches(
    pool: web::Data<SqlitePool>,
    query: web::Query<SlaQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match devsecops::get_sla_breaches(pool.get_ref(), org_id, query.limit).await {
        Ok(breaches) => HttpResponse::Ok().json(breaches),
        Err(e) => {
            log::error!("Failed to get SLA breaches: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get SLA breaches"
            }))
        }
    }
}

// ============================================================================
// Security Debt Endpoints
// ============================================================================

/// Get security debt analysis
pub async fn get_debt(
    pool: web::Data<SqlitePool>,
    query: web::Query<DashboardQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    // Get vulnerability counts
    let counts = match devsecops::get_vulnerability_counts(pool.get_ref(), org_id).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to get vulnerability counts: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get vulnerability counts"
            }));
        }
    };

    let (critical, high, medium, low) = counts;
    let debt = devsecops::get_security_debt(pool.get_ref(), org_id).await.unwrap_or(0.0);

    HttpResponse::Ok().json(serde_json::json!({
        "security_debt_hours": debt,
        "security_debt_days": debt / 8.0,  // Assuming 8-hour workday
        "breakdown": {
            "critical": {
                "count": critical,
                "hours_each": 8.0,
                "total_hours": critical as f64 * 8.0
            },
            "high": {
                "count": high,
                "hours_each": 4.0,
                "total_hours": high as f64 * 4.0
            },
            "medium": {
                "count": medium,
                "hours_each": 2.0,
                "total_hours": medium as f64 * 2.0
            },
            "low": {
                "count": low,
                "hours_each": 1.0,
                "total_hours": low as f64 * 1.0
            }
        },
        "total_open_vulns": critical + high + medium + low
    }))
}

// ============================================================================
// Pipeline Gate Endpoints
// ============================================================================

/// Create a new pipeline gate
pub async fn create_gate(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreatePipelineGateRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match devsecops::create_pipeline_gate(pool.get_ref(), body.into_inner()).await {
        Ok(gate) => HttpResponse::Created().json(gate),
        Err(e) => {
            log::error!("Failed to create pipeline gate: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create pipeline gate"
            }))
        }
    }
}

/// List pipeline gates
pub async fn list_gates(
    pool: web::Data<SqlitePool>,
    query: web::Query<GateListQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let project_id = query.project_id.map(|p| p.to_string());

    match devsecops::list_pipeline_gates(pool.get_ref(), project_id.as_deref()).await {
        Ok(gates) => HttpResponse::Ok().json(gates),
        Err(e) => {
            log::error!("Failed to list pipeline gates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list pipeline gates"
            }))
        }
    }
}

/// Get a specific pipeline gate
pub async fn get_gate(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let gate_id = path.into_inner();

    match devsecops::get_pipeline_gate(pool.get_ref(), &gate_id).await {
        Ok(Some(gate)) => HttpResponse::Ok().json(gate),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Pipeline gate not found"
        })),
        Err(e) => {
            log::error!("Failed to get pipeline gate: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get pipeline gate"
            }))
        }
    }
}

/// Update a pipeline gate
pub async fn update_gate(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdatePipelineGateRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let gate_id = path.into_inner();

    match devsecops::update_pipeline_gate(pool.get_ref(), &gate_id, body.into_inner()).await {
        Ok(gate) => HttpResponse::Ok().json(gate),
        Err(e) => {
            log::error!("Failed to update pipeline gate: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update pipeline gate",
                "details": e.to_string()
            }))
        }
    }
}

/// Delete a pipeline gate
pub async fn delete_gate(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let gate_id = path.into_inner();

    match devsecops::delete_pipeline_gate(pool.get_ref(), &gate_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete pipeline gate: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete pipeline gate"
            }))
        }
    }
}

/// Evaluate a gate for a specific scan
pub async fn evaluate_gate(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<EvaluateGateRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let gate_id = path.into_inner();
    let scan_id = body.scan_id.to_string();

    match devsecops::evaluate_gate(pool.get_ref(), &gate_id, &scan_id).await {
        Ok(evaluation) => {
            let status_code = if evaluation.passed {
                actix_web::http::StatusCode::OK
            } else {
                actix_web::http::StatusCode::OK  // Still 200, client checks 'passed' field
            };
            HttpResponse::build(status_code).json(evaluation)
        }
        Err(e) => {
            log::error!("Failed to evaluate pipeline gate: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to evaluate pipeline gate",
                "details": e.to_string()
            }))
        }
    }
}

/// Get gate evaluation history
pub async fn get_gate_evaluations(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<SlaQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let gate_id = path.into_inner();

    match devsecops::get_gate_evaluations(pool.get_ref(), &gate_id, query.limit).await {
        Ok(evaluations) => HttpResponse::Ok().json(evaluations),
        Err(e) => {
            log::error!("Failed to get gate evaluations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get gate evaluations"
            }))
        }
    }
}

// ============================================================================
// Project Health Endpoints
// ============================================================================

/// Get project health list
pub async fn get_projects(
    pool: web::Data<SqlitePool>,
    query: web::Query<SlaQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    // Get top vulnerabilities grouped by project/scan
    match devsecops::get_top_vulnerabilities(pool.get_ref(), org_id, query.limit).await {
        Ok(vulns) => HttpResponse::Ok().json(serde_json::json!({
            "top_vulnerabilities": vulns,
            "message": "Project health requires project configuration. Top vulnerabilities shown as alternative."
        })),
        Err(e) => {
            log::error!("Failed to get project health: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get project health"
            }))
        }
    }
}

// ============================================================================
// API Security Endpoints
// ============================================================================

/// POST /api/yellow-team/api-security/scan - Start a new API security scan
async fn api_security_start_scan(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    scan_store: web::Data<ApiSecurityScanStatusStore>,
    req: web::Json<StartApiSecurityScanRequest>,
) -> HttpResponse {
    log::info!(
        "User {} starting Yellow Team API security scan for {}",
        claims.sub,
        req.api_name
    );

    // Validate request
    if req.api_name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "api_name is required"
        }));
    }

    if req.spec_content.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "spec_content is required"
        }));
    }

    // Detect or use provided spec type
    let spec_type_str = req.spec_type.as_ref()
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "auto".to_string());

    let detected_type = if spec_type_str == "auto" {
        detect_spec_type(&req.spec_content)
    } else {
        match spec_type_str.as_str() {
            "openapi3" | "openapi" => ApiSpecType::OpenApi3,
            "swagger2" | "swagger" => ApiSpecType::Swagger2,
            "graphql" => ApiSpecType::GraphQL,
            _ => ApiSpecType::Unknown,
        }
    };

    if detected_type == ApiSpecType::Unknown {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Unable to detect API specification type. Please specify spec_type as 'openapi3', 'swagger2', or 'graphql'."
        }));
    }

    // Create scan record in database
    let db_request = yt_db::CreateApiSecurityScanRequest {
        api_name: req.api_name.clone(),
        spec_type: format!("{:?}", detected_type),
        spec_content: Some(req.spec_content.clone()),
        base_url: req.base_url.clone(),
        customer_id: req.customer_id.clone(),
        engagement_id: req.engagement_id.clone(),
    };

    let scan = match yt_db::create_scan(pool.get_ref(), &claims.sub, &db_request).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to create API security scan: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create scan"
            }));
        }
    };

    let scan_id = scan.id.clone();
    let spec_content = req.spec_content.clone();

    // Clone data for background task
    let pool_clone = pool.get_ref().clone();
    let scan_id_clone = scan_id.clone();
    let store_clone = scan_store.get_ref().clone();

    // Spawn background task to run the scan
    tokio::spawn(async move {
        log::info!("Starting Yellow Team API security scan task for {}", scan_id_clone);

        // Update status to running
        {
            let mut store = store_clone.lock().await;
            store.insert(scan_id_clone.clone(), "running".to_string());
        }

        if let Err(e) = yt_db::update_scan_status(&pool_clone, &scan_id_clone, "running", None).await {
            log::error!("Failed to update scan status: {}", e);
        }

        // Run the scan
        match scan_api_spec(&spec_content, detected_type) {
            Ok(result) => {
                log::info!(
                    "Yellow Team API security scan {} completed with {} findings",
                    scan_id_clone,
                    result.findings.len()
                );

                // Store endpoints
                if let Err(e) = yt_db::store_endpoints(&pool_clone, &scan_id_clone, &result.endpoints).await {
                    log::error!("Failed to store endpoints: {}", e);
                }

                // Store findings
                if let Err(e) = yt_db::store_findings(&pool_clone, &scan_id_clone, &result.findings).await {
                    log::error!("Failed to store findings: {}", e);
                }

                // Update scan with results
                if let Err(e) = yt_db::update_scan_results(
                    &pool_clone,
                    &scan_id_clone,
                    result.spec_version.as_deref(),
                    result.summary.total_endpoints as i64,
                    result.summary.endpoints_with_auth as i64,
                    result.summary.endpoints_without_auth as i64,
                    result.summary.total_findings as i64,
                    result.summary.critical_findings as i64,
                    result.summary.high_findings as i64,
                    result.summary.medium_findings as i64,
                    result.summary.low_findings as i64,
                    result.summary.info_findings as i64,
                    result.summary.security_score as f64,
                ).await {
                    log::error!("Failed to update scan results: {}", e);
                }

                // Mark as completed
                if let Err(e) = yt_db::update_scan_status(&pool_clone, &scan_id_clone, "completed", None).await {
                    log::error!("Failed to update scan status: {}", e);
                }

                // Update store
                {
                    let mut store = store_clone.lock().await;
                    store.insert(scan_id_clone, "completed".to_string());
                }
            }
            Err(e) => {
                log::error!("Yellow Team API security scan {} failed: {}", scan_id_clone, e);

                // Mark as failed
                let _ = yt_db::update_scan_status(
                    &pool_clone,
                    &scan_id_clone,
                    "failed",
                    Some(&e.to_string()),
                ).await;

                {
                    let mut store = store_clone.lock().await;
                    store.insert(scan_id_clone, "failed".to_string());
                }
            }
        }
    });

    HttpResponse::Accepted().json(StartApiSecurityScanResponse {
        scan_id,
        status: "running".to_string(),
    })
}

/// GET /api/yellow-team/api-security/scans - List API scans for user
async fn api_security_list_scans(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    match yt_db::get_user_scans(pool.get_ref(), &claims.sub).await {
        Ok(scans) => HttpResponse::Ok().json(scans),
        Err(e) => {
            log::error!("Failed to fetch API security scans: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch scans"
            }))
        }
    }
}

/// GET /api/yellow-team/api-security/scans/{id} - Get scan details
async fn api_security_get_scan(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    // Get scan
    let scan = match yt_db::get_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to fetch API security scan: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            }));
        }
    };

    // Verify ownership
    if scan.user_id != claims.sub {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        }));
    }

    // Get endpoints
    let endpoints = yt_db::get_scan_endpoints(pool.get_ref(), &scan_id)
        .await
        .unwrap_or_default();

    // Get findings summary
    let findings = yt_db::get_scan_findings(pool.get_ref(), &scan_id)
        .await
        .unwrap_or_default();

    let findings_summary = calculate_api_security_findings_summary(&findings);

    HttpResponse::Ok().json(ApiSecurityScanDetailResponse {
        scan,
        endpoints,
        findings_summary,
    })
}

/// DELETE /api/yellow-team/api-security/scans/{id} - Delete a scan
async fn api_security_delete_scan(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    match yt_db::delete_scan(pool.get_ref(), &scan_id, &claims.sub).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Scan deleted successfully"
        })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found or access denied"
        })),
        Err(e) => {
            log::error!("Failed to delete scan: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete scan"
            }))
        }
    }
}

/// GET /api/yellow-team/api-security/scans/{id}/endpoints - Get scan endpoints
async fn api_security_get_endpoints(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    // Verify ownership
    match yt_db::get_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(scan) if scan.user_id == claims.sub => {}
        Ok(_) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Err(_) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        })),
    }

    match yt_db::get_scan_endpoints(pool.get_ref(), &scan_id).await {
        Ok(endpoints) => HttpResponse::Ok().json(endpoints),
        Err(e) => {
            log::error!("Failed to fetch endpoints: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch endpoints"
            }))
        }
    }
}

/// GET /api/yellow-team/api-security/scans/{id}/findings - Get scan findings
async fn api_security_get_findings(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    // Verify ownership
    match yt_db::get_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(scan) if scan.user_id == claims.sub => {}
        Ok(_) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Err(_) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Scan not found"
        })),
    }

    match yt_db::get_scan_findings(pool.get_ref(), &scan_id).await {
        Ok(findings) => HttpResponse::Ok().json(findings),
        Err(e) => {
            log::error!("Failed to fetch findings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch findings"
            }))
        }
    }
}

/// PUT /api/yellow-team/api-security/findings/{id}/status - Update finding status
async fn api_security_update_finding_status(
    _claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateApiSecurityFindingStatusRequest>,
) -> HttpResponse {
    let finding_id = path.into_inner();

    // Validate status
    let valid_statuses = ["open", "acknowledged", "fixed", "false_positive", "accepted"];
    if !valid_statuses.contains(&body.status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid status. Must be one of: {:?}", valid_statuses)
        }));
    }

    match yt_db::update_finding_status(pool.get_ref(), &finding_id, &body.status).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Finding status updated"
        })),
        Err(e) => {
            log::error!("Failed to update finding status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update finding status"
            }))
        }
    }
}

/// GET /api/yellow-team/api-security/stats - Get API security statistics
async fn api_security_get_stats(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
) -> HttpResponse {
    match yt_db::get_stats(pool.get_ref(), &claims.sub).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Failed to fetch stats: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to fetch statistics"
            }))
        }
    }
}

/// POST /api/yellow-team/api-security/detect-type - Detect API spec type
async fn api_security_detect_type(
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<DetectSpecTypeRequest>,
) -> HttpResponse {
    let detected = detect_spec_type(&body.spec_content);

    HttpResponse::Ok().json(DetectSpecTypeResponse {
        spec_type: format!("{:?}", detected).to_lowercase(),
        display_name: detected.to_string(),
    })
}

/// OWASP API Top 10 reference item
#[derive(Debug, Serialize)]
pub struct OwaspApiTop10Item {
    pub id: String,
    pub name: String,
    pub description: String,
    pub risk_description: String,
    pub prevention: Vec<String>,
    pub examples: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub severity: String,
}

/// GET /api/yellow-team/api-security/owasp-mapping - Get OWASP API Top 10 reference
async fn api_security_get_owasp_mapping(
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let owasp_api_top_10 = vec![
        OwaspApiTop10Item {
            id: "API1:2023".to_string(),
            name: "Broken Object Level Authorization (BOLA)".to_string(),
            description: "APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Object level authorization checks should be considered in every function that accesses a data source using an ID from the user.".to_string(),
            risk_description: "Attackers can exploit API endpoints that are vulnerable to broken object-level authorization by manipulating the ID of an object that is sent within the request. Object IDs can be anything from sequential integers, UUIDs, or generic strings.".to_string(),
            prevention: vec![
                "Implement proper authorization mechanism that relies on user policies and hierarchy".to_string(),
                "Use random and unpredictable values as GUIDs for records IDs".to_string(),
                "Write tests to evaluate the vulnerability of the authorization mechanism".to_string(),
                "Do not rely on IDs that the client sends. Use IDs stored in the session object instead".to_string(),
            ],
            examples: vec![
                "GET /api/users/{user_id}/orders - accessing other users' orders".to_string(),
                "PUT /api/accounts/{account_id} - modifying another user's account".to_string(),
            ],
            cwe_ids: vec!["CWE-639".to_string(), "CWE-284".to_string()],
            severity: "High".to_string(),
        },
        OwaspApiTop10Item {
            id: "API2:2023".to_string(),
            name: "Broken Authentication".to_string(),
            description: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws to assume other users' identities temporarily or permanently.".to_string(),
            risk_description: "Poor implementation of authentication mechanisms allows attackers to compromise authentication tokens or to exploit implementation flaws to assume other users' identities.".to_string(),
            prevention: vec![
                "Make sure you know all possible flows to authenticate to the API".to_string(),
                "Use standard authentication, token generation, password storage, and MFA".to_string(),
                "Use short-lived access tokens".to_string(),
                "Implement rate limiting and lockout mechanisms".to_string(),
                "Use stronger authentication for sensitive operations".to_string(),
            ],
            examples: vec![
                "Weak password requirements".to_string(),
                "Credential stuffing attacks".to_string(),
                "Missing rate limiting on authentication endpoints".to_string(),
            ],
            cwe_ids: vec!["CWE-287".to_string(), "CWE-306".to_string(), "CWE-798".to_string()],
            severity: "Critical".to_string(),
        },
        OwaspApiTop10Item {
            id: "API3:2023".to_string(),
            name: "Broken Object Property Level Authorization".to_string(),
            description: "This category combines API3:2019 Excessive Data Exposure and API6:2019 Mass Assignment, focusing on the common root cause: lack of or improper authorization validation at the object property level.".to_string(),
            risk_description: "APIs tend to expose endpoints that return all object's properties. This is particularly valid for REST APIs. For other protocols such as GraphQL, it may require crafted requests to specify which properties should be returned.".to_string(),
            prevention: vec![
                "Ensure users can only access legitimate, permitted fields".to_string(),
                "Return only the minimum amount of data required".to_string(),
                "Implement schema-based response validation".to_string(),
                "Define and enforce which object properties can be modified".to_string(),
            ],
            examples: vec![
                "Excessive data exposure in API responses".to_string(),
                "Mass assignment allowing role escalation".to_string(),
            ],
            cwe_ids: vec!["CWE-213".to_string(), "CWE-915".to_string()],
            severity: "High".to_string(),
        },
        OwaspApiTop10Item {
            id: "API4:2023".to_string(),
            name: "Unrestricted Resource Consumption".to_string(),
            description: "APIs do not restrict the size or number of resources that can be requested by the client/user. Not only can this impact the API server performance, leading to Denial of Service (DoS), but also leaves the door open to authentication flaws such as brute force.".to_string(),
            risk_description: "Exploitation requires simple API requests. Multiple concurrent requests can be performed from a single local computer or by using cloud computing resources.".to_string(),
            prevention: vec![
                "Implement rate limiting".to_string(),
                "Limit payload sizes".to_string(),
                "Implement pagination with reasonable defaults and maximums".to_string(),
                "Define and enforce maximum data/records per request".to_string(),
                "Limit expensive operations (e.g., string comparisons, file uploads)".to_string(),
            ],
            examples: vec![
                "Missing rate limiting allows brute force attacks".to_string(),
                "No pagination allows resource exhaustion".to_string(),
                "Large file upload without size limits".to_string(),
            ],
            cwe_ids: vec!["CWE-770".to_string(), "CWE-400".to_string(), "CWE-799".to_string()],
            severity: "Medium".to_string(),
        },
        OwaspApiTop10Item {
            id: "API5:2023".to_string(),
            name: "Broken Function Level Authorization (BFLA)".to_string(),
            description: "Complex access control policies with different hierarchies, groups, and roles, and an unclear separation between administrative and regular functions, tend to lead to authorization flaws.".to_string(),
            risk_description: "Administrative functions are a key target for attackers. Authorization checks for a function or resource are usually managed via configuration or code level.".to_string(),
            prevention: vec![
                "Enforce consistent authorization mechanism across all endpoints".to_string(),
                "Deny all access by default".to_string(),
                "Review API endpoints against function-level flaws".to_string(),
                "Implement role-based access control (RBAC)".to_string(),
                "Make sure administrative controllers inherit from admin base class".to_string(),
            ],
            examples: vec![
                "Regular user accessing admin endpoints".to_string(),
                "Missing authorization checks on sensitive operations".to_string(),
            ],
            cwe_ids: vec!["CWE-285".to_string()],
            severity: "High".to_string(),
        },
        OwaspApiTop10Item {
            id: "API6:2023".to_string(),
            name: "Unrestricted Access to Sensitive Business Flows".to_string(),
            description: "APIs vulnerable to this risk expose a business flow - such as buying a ticket, or posting a comment - without compensating for how the functionality could harm the business if used excessively in an automated manner.".to_string(),
            risk_description: "This doesn't necessarily come from implementation bugs. The threat agent would understand the business model and find sensitive business flows.".to_string(),
            prevention: vec![
                "Identify business flows that could harm if excessively used".to_string(),
                "Implement device fingerprinting".to_string(),
                "Implement human detection (CAPTCHA, biometrics)".to_string(),
                "Analyze user flow to detect non-human patterns".to_string(),
                "Block suspicious IP addresses (Tor, proxies, data centers)".to_string(),
            ],
            examples: vec![
                "Automated ticket scalping".to_string(),
                "Automated comment spam".to_string(),
                "Mass account creation".to_string(),
            ],
            cwe_ids: vec!["CWE-799".to_string(), "CWE-837".to_string()],
            severity: "Medium".to_string(),
        },
        OwaspApiTop10Item {
            id: "API7:2023".to_string(),
            name: "Server Side Request Forgery (SSRF)".to_string(),
            description: "Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote resource without validating the user-supplied URL. This enables an attacker to coerce the application to send a crafted request to an unexpected destination.".to_string(),
            risk_description: "Successful exploitation might lead to internal services enumeration (e.g., port scanning), information disclosure, bypassing firewalls, or other security mechanisms.".to_string(),
            prevention: vec![
                "Isolate resource fetching in separate network".to_string(),
                "Use allowlist of permitted URLs/destinations".to_string(),
                "Disable HTTP redirections".to_string(),
                "Use well-tested URL parsers to avoid inconsistencies".to_string(),
                "Do not send raw responses to clients".to_string(),
            ],
            examples: vec![
                "URL parameter used to fetch external resources".to_string(),
                "Webhook URL pointing to internal services".to_string(),
            ],
            cwe_ids: vec!["CWE-918".to_string()],
            severity: "High".to_string(),
        },
        OwaspApiTop10Item {
            id: "API8:2023".to_string(),
            name: "Security Misconfiguration".to_string(),
            description: "APIs and their supporting systems typically contain complex configurations that make them more customizable. However, misconfigurations can happen at any level of the API stack.".to_string(),
            risk_description: "Misconfigurations can expose sensitive user data, as well as system details that can lead to full server compromise.".to_string(),
            prevention: vec![
                "Implement hardening procedures".to_string(),
                "Review and update configurations across the stack".to_string(),
                "Automate configuration assessment".to_string(),
                "Ensure proper CORS configuration".to_string(),
                "Use TLS for all communications".to_string(),
                "Implement proper error handling without stack traces".to_string(),
            ],
            examples: vec![
                "Verbose error messages exposing stack traces".to_string(),
                "Missing TLS or weak cipher suites".to_string(),
                "Overly permissive CORS".to_string(),
                "Debug endpoints exposed in production".to_string(),
            ],
            cwe_ids: vec!["CWE-16".to_string(), "CWE-200".to_string(), "CWE-942".to_string()],
            severity: "Medium".to_string(),
        },
        OwaspApiTop10Item {
            id: "API9:2023".to_string(),
            name: "Improper Inventory Management".to_string(),
            description: "APIs tend to expose more endpoints than traditional web applications, making proper and updated documentation highly important. A proper inventory of hosts and deployed API versions also are important to mitigate issues such as deprecated API versions and exposed debug endpoints.".to_string(),
            risk_description: "Outdated documentation makes it harder to find and/or fix vulnerabilities. Lack of assets inventory and retirement strategies leads to running unpatched systems.".to_string(),
            prevention: vec![
                "Inventory all API hosts and document each environment".to_string(),
                "Inventory integrated services and document aspects".to_string(),
                "Document all aspects of your API such as authentication, errors, redirects, rate limiting, CORS policy".to_string(),
                "Generate documentation automatically using open standards".to_string(),
                "Make API documentation available to authorized users".to_string(),
                "Use external protection measures such as API security firewalls".to_string(),
            ],
            examples: vec![
                "Outdated API versions still accessible".to_string(),
                "Undocumented debug endpoints".to_string(),
                "Shadow APIs".to_string(),
            ],
            cwe_ids: vec!["CWE-1059".to_string()],
            severity: "Low".to_string(),
        },
        OwaspApiTop10Item {
            id: "API10:2023".to_string(),
            name: "Unsafe Consumption of APIs".to_string(),
            description: "Developers tend to trust data received from third-party APIs more than user input. This is especially true for APIs offered by well-known companies. Because of that, developers tend to adopt weaker security standards.".to_string(),
            risk_description: "Attackers target third-party services that the API integrates with, instead of trying to compromise the target API directly.".to_string(),
            prevention: vec![
                "Evaluate security controls of third-party APIs".to_string(),
                "Ensure all API interactions use secure communication (TLS)".to_string(),
                "Always validate and sanitize data from external APIs".to_string(),
                "Maintain an allowlist of known locations integrated APIs may redirect to".to_string(),
            ],
            examples: vec![
                "Trusting unvalidated data from third-party APIs".to_string(),
                "Following redirects from external APIs without validation".to_string(),
            ],
            cwe_ids: vec!["CWE-20".to_string(), "CWE-295".to_string()],
            severity: "Medium".to_string(),
        },
    ];

    HttpResponse::Ok().json(serde_json::json!({
        "title": "OWASP API Security Top 10 - 2023",
        "version": "2023",
        "source": "https://owasp.org/API-Security/",
        "items": owasp_api_top_10
    }))
}

// ============================================================================
// Threat Modeling Endpoints
// ============================================================================

/// Query parameters for listing threat models
#[derive(Debug, Deserialize)]
pub struct ListThreatModelsQuery {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i32>,
    #[serde(default)]
    pub offset: Option<i32>,
}

/// Query parameters for exporting threat model
#[derive(Debug, Deserialize)]
pub struct ExportThreatModelQuery {
    #[serde(default = "default_export_format")]
    pub format: String,
}

fn default_export_format() -> String {
    "json".to_string()
}

/// GET /api/yellow-team/threat-models - List threat models
async fn list_threat_models(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    _query: web::Query<ListThreatModelsQuery>,
) -> HttpResponse {
    match tm_db::get_user_threat_models(pool.get_ref(), &claims.sub).await {
        Ok(models) => HttpResponse::Ok().json(models),
        Err(e) => {
            log::error!("Failed to list threat models: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list threat models"
            }))
        }
    }
}

/// POST /api/yellow-team/threat-models - Create threat model
async fn create_threat_model(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateThreatModelRequest>,
) -> HttpResponse {
    if body.name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "name is required"
        }));
    }

    match tm_db::create_threat_model(pool.get_ref(), &claims.sub, &body).await {
        Ok(model) => HttpResponse::Created().json(model),
        Err(e) => {
            log::error!("Failed to create threat model: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create threat model"
            }))
        }
    }
}

/// GET /api/yellow-team/threat-models/{id} - Get threat model
async fn get_threat_model(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let model_id = path.into_inner();

    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) => {
            // Check ownership
            if model.user_id.to_string() != claims.sub {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                }));
            }
            HttpResponse::Ok().json(model)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(e) => {
            log::error!("Failed to get threat model: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get threat model"
            }))
        }
    }
}

/// PUT /api/yellow-team/threat-models/{id} - Update threat model
async fn update_threat_model(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateThreatModelRequest>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(e) => {
            log::error!("Failed to get threat model: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify ownership"
            }));
        }
    }

    match tm_db::update_threat_model(pool.get_ref(), &model_id, &body).await {
        Ok(_) => {
            match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
                Ok(Some(model)) => HttpResponse::Ok().json(model),
                _ => HttpResponse::Ok().json(serde_json::json!({
                    "message": "Threat model updated"
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to update threat model: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update threat model"
            }))
        }
    }
}

/// DELETE /api/yellow-team/threat-models/{id} - Delete threat model
async fn delete_threat_model(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(e) => {
            log::error!("Failed to get threat model: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify ownership"
            }));
        }
    }

    match tm_db::delete_threat_model(pool.get_ref(), &model_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete threat model: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete threat model"
            }))
        }
    }
}

/// POST /api/yellow-team/threat-models/{id}/components - Add component
async fn add_component(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AddComponentRequest>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(e) => {
            log::error!("Failed to get threat model: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify ownership"
            }));
        }
    }

    if body.name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "name is required"
        }));
    }

    match tm_db::add_component(pool.get_ref(), &model_id, &body).await {
        Ok(component) => HttpResponse::Created().json(component),
        Err(e) => {
            log::error!("Failed to add component: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add component"
            }))
        }
    }
}

/// DELETE /api/yellow-team/threat-models/{model_id}/components/{id} - Delete component
async fn delete_component(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (model_id, component_id) = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    match tm_db::delete_component(pool.get_ref(), &component_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete component: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete component"
            }))
        }
    }
}

/// POST /api/yellow-team/threat-models/{id}/data-flows - Add data flow
async fn add_data_flow(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AddDataFlowRequest>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    if body.name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "name is required"
        }));
    }

    match tm_db::add_data_flow(pool.get_ref(), &model_id, &body).await {
        Ok(flow) => HttpResponse::Created().json(flow),
        Err(e) => {
            log::error!("Failed to add data flow: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add data flow"
            }))
        }
    }
}

/// DELETE /api/yellow-team/threat-models/{model_id}/data-flows/{id} - Delete data flow
async fn delete_data_flow(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (model_id, flow_id) = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    match tm_db::delete_data_flow(pool.get_ref(), &flow_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete data flow: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete data flow"
            }))
        }
    }
}

/// POST /api/yellow-team/threat-models/{id}/trust-boundaries - Add trust boundary
async fn add_trust_boundary(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AddTrustBoundaryRequest>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    if body.name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "name is required"
        }));
    }

    match tm_db::add_trust_boundary(pool.get_ref(), &model_id, &body).await {
        Ok(boundary) => HttpResponse::Created().json(boundary),
        Err(e) => {
            log::error!("Failed to add trust boundary: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add trust boundary"
            }))
        }
    }
}

/// DELETE /api/yellow-team/threat-models/{model_id}/trust-boundaries/{id} - Delete trust boundary
async fn delete_trust_boundary(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (model_id, boundary_id) = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    match tm_db::delete_trust_boundary(pool.get_ref(), &boundary_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete trust boundary: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete trust boundary"
            }))
        }
    }
}

/// POST /api/yellow-team/threat-models/{id}/threats - Add a manual threat
async fn add_threat(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<crate::yellow_team::AddThreatRequest>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    // Validate required fields
    if body.title.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "title is required"
        }));
    }
    if body.description.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "description is required"
        }));
    }

    match tm_db::add_threat(pool.get_ref(), &model_id, &body).await {
        Ok(threat) => HttpResponse::Created().json(threat),
        Err(e) => {
            log::error!("Failed to add threat: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add threat"
            }))
        }
    }
}

/// PUT /api/yellow-team/threat-models/{model_id}/threats/{threat_id} - Update a threat
async fn update_threat(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
    body: web::Json<crate::yellow_team::UpdateThreatRequest>,
) -> HttpResponse {
    let (model_id, threat_id) = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    // Verify threat exists and belongs to this model
    match tm_db::get_threat_by_id(pool.get_ref(), &threat_id).await {
        Ok(Some(threat)) if threat.threat_model_id.to_string() == model_id => {}
        Ok(Some(_)) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Threat does not belong to this model"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to get threat"
        })),
    }

    match tm_db::update_threat(pool.get_ref(), &threat_id, &body).await {
        Ok(_) => {
            // Return updated threat
            match tm_db::get_threat_by_id(pool.get_ref(), &threat_id).await {
                Ok(Some(threat)) => HttpResponse::Ok().json(threat),
                Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Threat not found after update"
                })),
                Err(e) => {
                    log::error!("Failed to get updated threat: {}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Updated but failed to retrieve threat"
                    }))
                }
            }
        }
        Err(e) => {
            log::error!("Failed to update threat: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update threat"
            }))
        }
    }
}

/// DELETE /api/yellow-team/threat-models/{model_id}/threats/{threat_id} - Delete a threat
async fn delete_threat(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (model_id, threat_id) = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    // Verify threat exists and belongs to this model
    match tm_db::get_threat_by_id(pool.get_ref(), &threat_id).await {
        Ok(Some(threat)) if threat.threat_model_id.to_string() == model_id => {}
        Ok(Some(_)) => return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Threat does not belong to this model"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to get threat"
        })),
    }

    match tm_db::delete_threat(pool.get_ref(), &threat_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete threat: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete threat"
            }))
        }
    }
}

/// POST /api/yellow-team/threat-models/{id}/analyze - Run STRIDE analysis
async fn analyze_threat_model(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Get and verify ownership
    let model = match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => model,
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(e) => {
            log::error!("Failed to get threat model: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get threat model"
            }));
        }
    };

    // Run STRIDE analysis
    let analysis_result = ThreatModelAnalyzer::analyze_model(&model);

    // Note: analysis_result.threats contains ArchitectureThreat which is different from StrideTheat
    // For now we don't persist these as they're computed on-the-fly for display
    // The threat model's own threats are managed separately via the threats endpoints

    // Calculate and update risk score
    let risk_score = calculate_risk_score(&analysis_result);
    if let Err(e) = tm_db::update_risk_score(pool.get_ref(), &model_id, risk_score).await {
        log::error!("Failed to update risk score: {}", e);
    }

    HttpResponse::Ok().json(analysis_result)
}

/// Calculate overall risk score from analysis result
fn calculate_risk_score(result: &crate::yellow_team::architecture::StrideAnalysisResult) -> f64 {
    let critical = result.threats_by_risk.get("critical").unwrap_or(&0);
    let high = result.threats_by_risk.get("high").unwrap_or(&0);
    let medium = result.threats_by_risk.get("medium").unwrap_or(&0);
    let low = result.threats_by_risk.get("low").unwrap_or(&0);

    // Weighted score (0-100, lower is better)
    let total_threats = result.threats.len() as f64;
    if total_threats == 0.0 {
        return 0.0;
    }

    let weighted_sum = (*critical as f64 * 40.0)
        + (*high as f64 * 25.0)
        + (*medium as f64 * 10.0)
        + (*low as f64 * 5.0);

    // Normalize to 0-100
    (weighted_sum / total_threats).min(100.0)
}

/// PUT /api/yellow-team/threats/{id}/status - Update threat status
async fn update_threat_status(
    _claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateThreatStatusRequest>,
) -> HttpResponse {
    let threat_id = path.into_inner();

    match tm_db::update_threat_status(pool.get_ref(), &threat_id, &body).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Threat status updated"
        })),
        Err(e) => {
            log::error!("Failed to update threat status: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update threat status"
            }))
        }
    }
}

/// POST /api/yellow-team/threat-models/{id}/mitigations - Add mitigation
async fn add_mitigation(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AddMitigationRequest>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    if body.title.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "title is required"
        }));
    }

    match tm_db::add_mitigation(pool.get_ref(), &model_id, &body).await {
        Ok(mitigation) => HttpResponse::Created().json(mitigation),
        Err(e) => {
            log::error!("Failed to add mitigation: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to add mitigation"
            }))
        }
    }
}

/// DELETE /api/yellow-team/threat-models/{model_id}/mitigations/{id} - Delete mitigation
async fn delete_mitigation(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (model_id, mitigation_id) = path.into_inner();

    // Verify ownership
    match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => {}
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to verify ownership"
        })),
    }

    match tm_db::delete_mitigation(pool.get_ref(), &mitigation_id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete mitigation: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete mitigation"
            }))
        }
    }
}

/// GET /api/yellow-team/threat-models/{id}/export - Export threat model
async fn export_threat_model(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<ExportThreatModelQuery>,
) -> HttpResponse {
    let model_id = path.into_inner();

    // Get and verify ownership
    let model = match tm_db::get_threat_model_by_id(pool.get_ref(), &model_id).await {
        Ok(Some(model)) if model.user_id.to_string() == claims.sub => model,
        Ok(Some(_)) => return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })),
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Threat model not found"
        })),
        Err(e) => {
            log::error!("Failed to get threat model: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get threat model"
            }));
        }
    };

    match query.format.to_lowercase().as_str() {
        "json" => {
            HttpResponse::Ok()
                .content_type("application/json")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}.json\"", model.name)))
                .json(&model)
        }
        "markdown" | "md" => {
            let markdown = ThreatModelAnalyzer::generate_markdown_report(&model);
            HttpResponse::Ok()
                .content_type("text/markdown")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}.md\"", model.name)))
                .body(markdown)
        }
        _ => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Unsupported export format. Use 'json' or 'markdown'."
        }))
    }
}

/// GET /api/yellow-team/threat-models/templates - Get available architecture templates
async fn get_templates(
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let templates = get_architecture_templates();
    HttpResponse::Ok().json(templates)
}

/// Helper function to calculate findings summary
fn calculate_api_security_findings_summary(findings: &[yt_db::ApiSecurityFindingRecord]) -> ApiSecurityFindingsSummary {
    let mut summary = ApiSecurityFindingsSummary {
        total: findings.len() as i64,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };

    for finding in findings {
        match finding.severity.to_lowercase().as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" => summary.low += 1,
            "info" => summary.info += 1,
            _ => {}
        }
    }

    summary
}

// ============================================================================
// SBOM Handlers
// ============================================================================

/// Generate SBOM from uploaded dependency files
async fn sbom_generate(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    mut payload: Multipart,
) -> HttpResponse {
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid user ID" })),
    };

    let mut project_name: Option<String> = None;
    let mut project_version: Option<String> = None;
    let mut format = SbomFormat::CycloneDX;
    let mut files: Vec<(String, String)> = Vec::new();

    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                log::error!("Multipart error: {}", e);
                return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid multipart data" }));
            }
        };

        let content_disposition = match field.content_disposition() {
            Some(cd) => cd,
            None => continue,
        };
        let field_name = content_disposition.get_name().unwrap_or("");

        match field_name {
            "project_name" => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(chunk) = chunk { data.extend_from_slice(&chunk); }
                }
                project_name = Some(String::from_utf8_lossy(&data).trim().to_string());
            }
            "project_version" => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(chunk) = chunk { data.extend_from_slice(&chunk); }
                }
                let version = String::from_utf8_lossy(&data).trim().to_string();
                if !version.is_empty() { project_version = Some(version); }
            }
            "format" => {
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(chunk) = chunk { data.extend_from_slice(&chunk); }
                }
                let fmt_str = String::from_utf8_lossy(&data).trim().to_lowercase();
                format = fmt_str.parse().unwrap_or(SbomFormat::CycloneDX);
            }
            "files" | "file" => {
                let filename = content_disposition.get_filename().unwrap_or("unknown").to_string();
                let file_type = DependencyFileType::from_filename(&filename);
                if file_type == DependencyFileType::Unknown { continue; }

                let mut content = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(chunk) = chunk { content.extend_from_slice(&chunk); }
                }
                if content.len() > 10 * 1024 * 1024 {
                    return HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("File {} exceeds 10MB", filename) }));
                }
                files.push((filename, String::from_utf8_lossy(&content).to_string()));
            }
            _ => {}
        }
    }

    let project_name = match project_name {
        Some(name) if !name.is_empty() => name,
        _ => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "project_name is required" })),
    };

    if files.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "At least one dependency file is required" }));
    }

    let user_id_str = user_id.to_string();
    let sbom = match generate_sbom(&user_id_str, &project_name, project_version.as_deref(), files, format) {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("Failed to generate SBOM: {}", e) })),
    };

    let total_components = sbom.components.len();
    if let Err(e) = sbom_db::create_sbom(&pool, &sbom).await {
        log::error!("Failed to store SBOM: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to store SBOM" }));
    }

    HttpResponse::Created().json(GenerateSbomResponse {
        id: sbom.id.to_string(),
        project_name,
        total_components,
        format: format.to_string(),
        message: format!("SBOM generated successfully with {} components", total_components),
    })
}

/// List user's SBOMs
async fn sbom_list(pool: web::Data<SqlitePool>, claims: web::ReqData<auth::Claims>, query: web::Query<ListSbomsQueryParams>) -> HttpResponse {
    let db_query = sbom_db::ListSbomsQuery { project_name: query.project_name.clone(), format: query.format.clone(), limit: query.limit, offset: query.offset };
    match sbom_db::list_sboms(&pool, &claims.sub, &db_query).await {
        Ok(sboms) => HttpResponse::Ok().json(sboms),
        Err(e) => { log::error!("Failed to list SBOMs: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to retrieve SBOMs" })) }
    }
}

/// Get SBOM details
async fn sbom_get(pool: web::Data<SqlitePool>, claims: web::ReqData<auth::Claims>, sbom_id: web::Path<String>) -> HttpResponse {
    match sbom_db::get_sbom(&pool, &sbom_id, &claims.sub).await {
        Ok(Some(s)) => HttpResponse::Ok().json(s),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({ "error": "SBOM not found" })),
        Err(e) => { log::error!("Failed to get SBOM: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to retrieve SBOM" })) }
    }
}

/// Get SBOM components
async fn sbom_components(pool: web::Data<SqlitePool>, claims: web::ReqData<auth::Claims>, sbom_id: web::Path<String>, query: web::Query<ListComponentsQueryParams>) -> HttpResponse {
    match sbom_db::get_sbom(&pool, &sbom_id, &claims.sub).await {
        Ok(Some(_)) => {},
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({ "error": "SBOM not found" })),
        Err(e) => { log::error!("Failed to verify SBOM: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to verify access" })); }
    }
    let db_query = sbom_db::ListComponentsQuery { name: query.name.clone(), license: query.license.clone(), has_vulns: query.has_vulns, limit: query.limit, offset: query.offset };
    match sbom_db::get_sbom_components_filtered(&pool, &sbom_id, &db_query).await {
        Ok(c) => HttpResponse::Ok().json(c),
        Err(e) => { log::error!("Failed to get components: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to retrieve components" })) }
    }
}

/// Get SBOM vulnerabilities
async fn sbom_vulns(pool: web::Data<SqlitePool>, claims: web::ReqData<auth::Claims>, sbom_id: web::Path<String>, query: web::Query<ListVulnsQueryParams>) -> HttpResponse {
    match sbom_db::get_sbom(&pool, &sbom_id, &claims.sub).await {
        Ok(Some(_)) => {},
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({ "error": "SBOM not found" })),
        Err(e) => { log::error!("Failed to verify SBOM: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to verify access" })); }
    }
    let db_query = sbom_db::ListVulnsQuery { severity: query.severity.clone(), has_fix: query.has_fix, limit: query.limit, offset: query.offset };
    match sbom_db::get_sbom_vulnerabilities(&pool, &sbom_id, &db_query).await {
        Ok(v) => HttpResponse::Ok().json(v),
        Err(e) => { log::error!("Failed to get vulns: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to retrieve vulnerabilities" })) }
    }
}

/// Get SBOM licenses
async fn sbom_licenses(pool: web::Data<SqlitePool>, claims: web::ReqData<auth::Claims>, sbom_id: web::Path<String>) -> HttpResponse {
    match sbom_db::get_sbom(&pool, &sbom_id, &claims.sub).await {
        Ok(Some(_)) => {},
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({ "error": "SBOM not found" })),
        Err(e) => { log::error!("Failed to verify SBOM: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to verify access" })); }
    }
    match sbom_db::get_sbom_licenses(&pool, &sbom_id).await {
        Ok(l) => HttpResponse::Ok().json(l),
        Err(e) => { log::error!("Failed to get licenses: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to retrieve licenses" })) }
    }
}

/// Export SBOM
async fn sbom_export(pool: web::Data<SqlitePool>, claims: web::ReqData<auth::Claims>, path: web::Path<ExportPath>) -> HttpResponse {
    let sbom_data = match sbom_db::get_sbom(&pool, &path.id, &claims.sub).await {
        Ok(Some(s)) => s,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({ "error": "SBOM not found" })),
        Err(e) => { log::error!("Failed to get SBOM: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to retrieve SBOM" })); }
    };
    let export_format: SbomFormat = match path.format.parse() {
        Ok(f) => f,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Invalid format" })),
    };
    let (content, filename) = match export_format {
        SbomFormat::CycloneDx | SbomFormat::CycloneDX => match export_cyclonedx(&sbom_data) {
            Ok(j) => (j, format!("{}-sbom-cyclonedx.json", sbom_data.project_name)),
            Err(e) => { log::error!("Export failed: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Export failed" })); }
        },
        SbomFormat::Spdx => match export_spdx(&sbom_data) {
            Ok(j) => (j, format!("{}-sbom-spdx.json", sbom_data.project_name)),
            Err(e) => { log::error!("Export failed: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Export failed" })); }
        },
        SbomFormat::Json => match serde_json::to_string_pretty(&sbom_data) {
            Ok(j) => (j, format!("{}-sbom.json", sbom_data.project_name)),
            Err(e) => { log::error!("Export failed: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Export failed" })); }
        },
    };
    HttpResponse::Ok().content_type("application/json").insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename))).body(content)
}

/// Delete SBOM
async fn sbom_delete(pool: web::Data<SqlitePool>, claims: web::ReqData<auth::Claims>, sbom_id: web::Path<String>) -> HttpResponse {
    match sbom_db::delete_sbom(&pool, &sbom_id, &claims.sub).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({ "message": "SBOM deleted" })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({ "error": "SBOM not found" })),
        Err(e) => { log::error!("Failed to delete SBOM: {}", e); HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to delete" })) }
    }
}

/// Get supported file types
async fn sbom_file_types() -> HttpResponse {
    let file_types = vec![
        SupportedFileType { name: "Cargo.lock".into(), file_type: "cargolock".into(), ecosystem: "cargo".into(), description: "Rust lockfile".into() },
        SupportedFileType { name: "package-lock.json".into(), file_type: "packagelockjson".into(), ecosystem: "npm".into(), description: "npm lockfile".into() },
        SupportedFileType { name: "package.json".into(), file_type: "packagejson".into(), ecosystem: "npm".into(), description: "npm manifest".into() },
        SupportedFileType { name: "yarn.lock".into(), file_type: "yarnlock".into(), ecosystem: "npm".into(), description: "Yarn lockfile".into() },
        SupportedFileType { name: "requirements.txt".into(), file_type: "requirementstxt".into(), ecosystem: "pypi".into(), description: "Python requirements".into() },
        SupportedFileType { name: "Pipfile.lock".into(), file_type: "pipfilelock".into(), ecosystem: "pypi".into(), description: "Pipenv lockfile".into() },
        SupportedFileType { name: "poetry.lock".into(), file_type: "poetrylock".into(), ecosystem: "pypi".into(), description: "Poetry lockfile".into() },
        SupportedFileType { name: "go.mod".into(), file_type: "gomod".into(), ecosystem: "golang".into(), description: "Go module".into() },
        SupportedFileType { name: "go.sum".into(), file_type: "gosum".into(), ecosystem: "golang".into(), description: "Go checksums".into() },
        SupportedFileType { name: "pom.xml".into(), file_type: "pomxml".into(), ecosystem: "maven".into(), description: "Maven POM".into() },
        SupportedFileType { name: "build.gradle".into(), file_type: "buildgradle".into(), ecosystem: "maven".into(), description: "Gradle build".into() },
        SupportedFileType { name: "Gemfile.lock".into(), file_type: "gemfilelock".into(), ecosystem: "gem".into(), description: "Ruby Bundler".into() },
        SupportedFileType { name: "composer.lock".into(), file_type: "composerlock".into(), ecosystem: "composer".into(), description: "PHP Composer".into() },
    ];
    HttpResponse::Ok().json(file_types)
}

/// Response for SBOM rescan
#[derive(Debug, Serialize)]
pub struct RescanSbomResponse {
    pub sbom_id: String,
    pub total_components: usize,
    pub vulnerable_components: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub message: String,
}

/// Rescan SBOM for vulnerabilities
///
/// POST /api/yellow-team/sbom/records/{id}/rescan
///
/// Re-correlates the SBOM components against the CVE database to check for
/// newly discovered vulnerabilities.
async fn sbom_rescan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    sbom_id: web::Path<String>,
) -> HttpResponse {
    log::info!("User {} requesting SBOM rescan for {}", claims.sub, sbom_id.as_str());

    // Verify ownership first
    match sbom_db::get_sbom(&pool, &sbom_id, &claims.sub).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "SBOM not found"
            }));
        }
        Err(e) => {
            log::error!("Failed to verify SBOM ownership: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to verify access"
            }));
        }
    };

    // Get full SBOM with components for correlation
    let full_sbom = match sbom_db::get_full_sbom(&pool, &sbom_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "SBOM data not found"
            }));
        }
        Err(e) => {
            log::error!("Failed to get full SBOM for rescan: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve SBOM data"
            }));
        }
    };

    // Get NVD API key from environment if available
    let nvd_api_key = std::env::var("NVD_API_KEY").ok();

    // Correlate vulnerabilities
    let correlation_result = match correlate_vulnerabilities(pool.get_ref(), &full_sbom, nvd_api_key).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to correlate vulnerabilities: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to scan for vulnerabilities"
            }));
        }
    };

    // Delete existing vulnerabilities for this SBOM
    if let Err(e) = sbom_db::delete_sbom_vulnerabilities(&pool, &sbom_id).await {
        log::warn!("Failed to clear old vulnerabilities: {}", e);
    }

    // Store new vulnerabilities
    for vuln in &correlation_result.vulnerabilities {
        if let Err(e) = sbom_db::add_sbom_vulnerability(&pool, &sbom_id, vuln).await {
            log::warn!("Failed to store vulnerability {}: {}", vuln.cve_id, e);
        }
    }

    // Update SBOM stats
    if let Err(e) = sbom_db::update_sbom_vuln_stats(
        &pool,
        &sbom_id,
        correlation_result.vulnerable_components as i64,
        correlation_result.critical_count as i64,
        correlation_result.high_count as i64,
        correlation_result.medium_count as i64,
        correlation_result.low_count as i64,
    ).await {
        log::warn!("Failed to update SBOM stats: {}", e);
    }

    log::info!(
        "SBOM rescan complete for {}: {} vulnerable components, {} vulnerabilities found",
        sbom_id.as_str(),
        correlation_result.vulnerable_components,
        correlation_result.vulnerabilities.len()
    );

    HttpResponse::Ok().json(RescanSbomResponse {
        sbom_id: sbom_id.to_string(),
        total_components: correlation_result.total_components,
        vulnerable_components: correlation_result.vulnerable_components,
        critical_count: correlation_result.critical_count,
        high_count: correlation_result.high_count,
        medium_count: correlation_result.medium_count,
        low_count: correlation_result.low_count,
        message: format!(
            "Rescan complete. Found {} vulnerabilities across {} components.",
            correlation_result.vulnerabilities.len(),
            correlation_result.vulnerable_components
        ),
    })
}

// ============================================================================
// DevSecOps Enhanced Endpoints - Coverage, MTTR, Trends, Security Debt
// ============================================================================

/// Query parameters for security coverage
#[derive(Debug, Deserialize)]
pub struct SecurityCoverageQuery {
    pub project_name: Option<String>,
}

/// Query parameters for trends
#[derive(Debug, Deserialize)]
pub struct TrendQuery {
    pub days: Option<i32>,
    pub project_name: Option<String>,
}

/// Query parameters for security debt
#[derive(Debug, Deserialize)]
pub struct SecurityDebtQuery {
    pub limit: Option<i32>,
    pub project_name: Option<String>,
}

/// Request to record a finding (for MTTR tracking)
#[derive(Debug, Deserialize)]
pub struct RecordFindingRequest {
    pub finding_id: String,
    pub finding_type: String,
    pub severity: String,
    pub project_name: Option<String>,
    pub source: Option<String>,
}

/// Request to resolve a finding
#[derive(Debug, Deserialize)]
pub struct ResolveFindingRequestBody {
    pub finding_id: String,
}

/// Get security coverage status
///
/// Returns which DevSecOps tools are enabled and when they were last run.
pub async fn get_security_coverage(
    pool: web::Data<SqlitePool>,
    query: web::Query<SecurityCoverageQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match devsecops::get_security_coverage(
        pool.get_ref(),
        &claims.sub,
        query.project_name.as_deref(),
    ).await {
        Ok(coverage) => {
            // Add coverage percentage to response
            let coverage_pct = coverage.coverage_percentage();
            HttpResponse::Ok().json(serde_json::json!({
                "coverage": coverage,
                "coverage_percentage": coverage_pct
            }))
        }
        Err(e) => {
            log::error!("Failed to get security coverage: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get security coverage",
                "details": e.to_string()
            }))
        }
    }
}

/// Get detailed MTTR breakdown by severity
///
/// Returns MTTR for each severity level with sample sizes and trend information.
pub async fn get_mttr_breakdown(
    pool: web::Data<SqlitePool>,
    query: web::Query<MttrQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let days = query.days.unwrap_or(30);

    match devsecops::get_detailed_mttr_breakdown(
        pool.get_ref(),
        &claims.sub,
        days,
    ).await {
        Ok(breakdown) => HttpResponse::Ok().json(breakdown),
        Err(e) => {
            log::error!("Failed to get MTTR breakdown: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get MTTR breakdown",
                "details": e.to_string()
            }))
        }
    }
}

/// Get findings trend over time
///
/// Returns daily counts of findings by severity for the specified period.
pub async fn get_findings_trend(
    pool: web::Data<SqlitePool>,
    query: web::Query<TrendQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let days = query.days.unwrap_or(30);

    match devsecops::get_findings_trend(
        pool.get_ref(),
        &claims.sub,
        days,
    ).await {
        Ok(trend) => HttpResponse::Ok().json(trend),
        Err(e) => {
            log::error!("Failed to get findings trend: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get findings trend",
                "details": e.to_string()
            }))
        }
    }
}

/// Get security debt items
///
/// Returns open findings ordered by severity and age with remediation estimates.
pub async fn get_security_debt_items_endpoint(
    pool: web::Data<SqlitePool>,
    query: web::Query<SecurityDebtQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match devsecops::get_security_debt_items(
        pool.get_ref(),
        &claims.sub,
        query.limit,
    ).await {
        Ok(items) => HttpResponse::Ok().json(items),
        Err(e) => {
            log::error!("Failed to get security debt items: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get security debt items",
                "details": e.to_string()
            }))
        }
    }
}

/// Get security debt summary
///
/// Returns aggregate security debt by severity and source with top items.
pub async fn get_security_debt_summary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match devsecops::get_security_debt_summary(
        pool.get_ref(),
        &claims.sub,
    ).await {
        Ok(summary) => HttpResponse::Ok().json(summary),
        Err(e) => {
            log::error!("Failed to get security debt summary: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get security debt summary",
                "details": e.to_string()
            }))
        }
    }
}

/// Record a finding for MTTR tracking
///
/// Call this when a finding is discovered to start tracking resolution time.
pub async fn record_finding(
    pool: web::Data<SqlitePool>,
    body: web::Json<RecordFindingRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    use crate::yellow_team::devsecops::CreateFindingResolutionRequest;

    let request = CreateFindingResolutionRequest {
        finding_id: body.finding_id.clone(),
        finding_type: body.finding_type.clone(),
        severity: body.severity.clone(),
        project_name: body.project_name.clone(),
        source: body.source.clone(),
    };

    match devsecops::create_finding_resolution(
        pool.get_ref(),
        &claims.sub,
        &request,
    ).await {
        Ok(resolution) => HttpResponse::Created().json(serde_json::json!({
            "id": resolution.id.to_string(),
            "finding_id": resolution.finding_id,
            "created_at": resolution.created_at.to_rfc3339()
        })),
        Err(e) => {
            log::error!("Failed to record finding: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record finding",
                "details": e.to_string()
            }))
        }
    }
}

/// Mark a finding as resolved
///
/// Call this when a finding is remediated to calculate resolution time.
pub async fn resolve_finding(
    pool: web::Data<SqlitePool>,
    body: web::Json<ResolveFindingRequestBody>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match devsecops::resolve_finding(
        pool.get_ref(),
        &body.finding_id,
    ).await {
        Ok(Some(hours)) => HttpResponse::Ok().json(serde_json::json!({
            "finding_id": body.finding_id,
            "resolution_hours": hours,
            "message": "Finding marked as resolved"
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Finding not found or already resolved"
        })),
        Err(e) => {
            log::error!("Failed to resolve finding: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to resolve finding",
                "details": e.to_string()
            }))
        }
    }
}

// ============================================================================
// SAST Request/Response Types
// ============================================================================

/// API-specific SAST scan request with inline code
#[derive(Debug, Clone, Deserialize)]
pub struct InlineSastScanRequest {
    /// Name for the scan
    pub name: String,
    /// Source code content (map of filename to content)
    pub code: HashMap<String, String>,
    /// Languages to scan (auto-detect if empty)
    #[serde(default)]
    pub languages: Vec<String>,
    /// Specific rules to enable (empty = all)
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    /// Rules to disable
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    /// CRM customer ID
    pub customer_id: Option<String>,
    /// CRM engagement ID
    pub engagement_id: Option<String>,
}

/// Response for starting a SAST scan
#[derive(Debug, Serialize)]
pub struct StartSastScanResponse {
    pub scan_id: String,
    pub status: String,
    pub message: String,
}

/// Detailed SAST scan response
#[derive(Debug, Serialize)]
pub struct SastScanDetailResponse {
    pub scan: yt_db::SastScanRecord,
    pub findings_summary: SastFindingsSummary,
}

/// Summary of SAST findings by severity
#[derive(Debug, Serialize)]
pub struct SastFindingsSummary {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

/// Query parameters for listing SAST rules
#[derive(Debug, Deserialize)]
pub struct ListSastRulesQuery {
    #[serde(default)]
    pub language: Option<String>,
}

// ============================================================================
// SAST API Handlers
// ============================================================================

use crate::yellow_team::sast::{SastScanner, get_all_rules};

/// Start a new SAST scan
///
/// POST /api/yellow-team/sast/scan
pub async fn sast_start_scan(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<InlineSastScanRequest>,
) -> HttpResponse {
    let user_id = &claims.sub;

    // Create scan record in database
    let create_request = yt_db::CreateSastScanRequest {
        name: body.name.clone(),
        repository_url: None,
        branch: None,
        languages: body.languages.clone(),
        customer_id: None,
        engagement_id: None,
    };

    let scan_record = match yt_db::create_sast_scan(pool.get_ref(), user_id, &create_request).await {
        Ok(record) => record,
        Err(e) => {
            log::error!("Failed to create SAST scan record: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create scan record",
                "details": e.to_string()
            }));
        }
    };

    let scan_id = scan_record.id.clone();
    let pool_clone = pool.get_ref().clone();

    // Update status to running
    if let Err(e) = yt_db::update_sast_scan_status(&pool_clone, &scan_id, "running", None).await {
        log::error!("Failed to update scan status: {}", e);
    }

    // Run the SAST scan on each code file
    let scanner = SastScanner::new();
    let mut all_findings: Vec<SastFinding> = Vec::new();
    let files_scanned = body.code.len();

    for (filename, content) in &body.code {
        // Determine language from file extension
        let language = std::path::Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
            .map(SastLanguage::from_extension)
            .unwrap_or(SastLanguage::Unknown);

        // Create a scan request for this file
        let scan_request = SastScanRequest {
            name: body.name.clone(),
            project_name: filename.clone(),
            source_type: SastSourceType::Upload,
            source_path: filename.clone(),
            code: Some(content.clone()),
            language: Some(language),
            languages: None,
            rule_ids: None,
            enabled_rules: if body.enabled_rules.is_empty() { None } else { Some(body.enabled_rules.clone()) },
            disabled_rules: if body.disabled_rules.is_empty() { None } else { Some(body.disabled_rules.clone()) },
            customer_id: None,
            engagement_id: None,
        };

        let result = scanner.run_scan(&scan_request);
        all_findings.extend(result.findings);
    }

    // Create a combined result
    let result = crate::yellow_team::sast::SastScanResult {
        findings: all_findings,
        files_scanned,
        rules_applied: scanner.rules.len(),
        duration_ms: 0,
    };

    // Count findings by severity
    let mut critical_count = 0i64;
    let mut high_count = 0i64;
    let mut medium_count = 0i64;
    let mut low_count = 0i64;

    // Store findings in database
    for finding in &result.findings {
        match finding.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => high_count += 1,
            Severity::Medium => medium_count += 1,
            Severity::Low | Severity::Info => low_count += 1,
        }

        if let Err(e) = yt_db::create_sast_finding(
            &pool_clone,
            &scan_id,
            &finding.rule_id,
            &finding.file_path,
            finding.location.line_start as i64,
            finding.location.column_start.map(|c| c as i64),
            finding.code_snippet.as_deref(),
            &format!("{:?}", finding.severity).to_lowercase(),
            &format!("{:?}", finding.category).to_lowercase(),
            &finding.message,
            finding.cwe_id.as_deref(),
            None, // owasp_category
            finding.remediation.as_deref(),
        ).await {
            log::error!("Failed to create SAST finding: {}", e);
        }
    }

    let total_findings = result.findings.len() as i64;

    // Update scan results
    let info_count = 0i64; // No info severity in our findings yet
    if let Err(e) = yt_db::update_sast_scan_results(
        &pool_clone,
        &scan_id,
        total_findings,
        critical_count,
        high_count,
        medium_count,
        low_count,
        info_count,
        result.files_scanned as i64,
        0i64, // lines_scanned not tracked currently
    ).await {
        log::error!("Failed to update scan results: {}", e);
        if let Err(e) = yt_db::update_sast_scan_status(&pool_clone, &scan_id, "failed", Some(&e.to_string())).await {
            log::error!("Failed to update scan status to failed: {}", e);
        }
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to update scan results",
            "details": e.to_string()
        }));
    }

    HttpResponse::Ok().json(StartSastScanResponse {
        scan_id: scan_id.clone(),
        status: "completed".to_string(),
        message: format!(
            "Scan completed. Found {} findings ({} critical, {} high, {} medium, {} low)",
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count
        ),
    })
}

/// List SAST scans for the current user
///
/// GET /api/yellow-team/sast/scans
pub async fn sast_list_scans(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    match yt_db::list_sast_scans(pool.get_ref(), user_id).await {
        Ok(scans) => HttpResponse::Ok().json(scans),
        Err(e) => {
            log::error!("Failed to list SAST scans: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list scans",
                "details": e.to_string()
            }))
        }
    }
}

/// Get a specific SAST scan by ID
///
/// GET /api/yellow-team/sast/scans/{id}
pub async fn sast_get_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    match yt_db::get_sast_scan_by_id(pool.get_ref(), &scan_id).await {
        Ok(scan) => {
            let response = SastScanDetailResponse {
                findings_summary: SastFindingsSummary {
                    total: scan.total_findings,
                    critical: scan.critical_count,
                    high: scan.high_count,
                    medium: scan.medium_count,
                    low: scan.low_count,
                    info: scan.info_count,
                },
                scan,
            };
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            log::error!("Failed to get SAST scan: {}", e);
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found",
                "details": e.to_string()
            }))
        }
    }
}

/// Delete a SAST scan
///
/// DELETE /api/yellow-team/sast/scans/{id}
pub async fn sast_delete_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let scan_id = path.into_inner();
    let user_id = &claims.sub;

    match yt_db::delete_sast_scan(pool.get_ref(), &scan_id, user_id).await {
        Ok(deleted) => {
            if deleted {
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "Scan deleted successfully"
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Scan not found or not authorized"
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to delete SAST scan: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete scan",
                "details": e.to_string()
            }))
        }
    }
}

/// Get findings for a specific SAST scan
///
/// GET /api/yellow-team/sast/scans/{id}/findings
pub async fn sast_get_findings(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let scan_id = path.into_inner();

    match yt_db::get_sast_findings(pool.get_ref(), &scan_id).await {
        Ok(findings) => HttpResponse::Ok().json(findings),
        Err(e) => {
            log::error!("Failed to get SAST findings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get findings",
                "details": e.to_string()
            }))
        }
    }
}

/// Update a SAST finding (mark as false positive, etc.)
///
/// PUT /api/yellow-team/sast/findings/{id}
pub async fn sast_update_finding(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<yt_db::UpdateSastFindingRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let finding_id = path.into_inner();

    match yt_db::update_sast_finding(pool.get_ref(), &finding_id, &body).await {
        Ok(_) => {
            match yt_db::get_sast_finding_by_id(pool.get_ref(), &finding_id).await {
                Ok(finding) => HttpResponse::Ok().json(finding),
                Err(e) => {
                    log::error!("Failed to get updated finding: {}", e);
                    HttpResponse::Ok().json(serde_json::json!({
                        "message": "Finding updated successfully"
                    }))
                }
            }
        }
        Err(e) => {
            log::error!("Failed to update SAST finding: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update finding",
                "details": e.to_string()
            }))
        }
    }
}

/// List available SAST rules
///
/// GET /api/yellow-team/sast/rules
pub async fn sast_list_rules(
    pool: web::Data<SqlitePool>,
    query: web::Query<ListSastRulesQuery>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // First try to get rules from database
    match yt_db::get_sast_rules(pool.get_ref(), query.language.as_deref()).await {
        Ok(db_rules) if !db_rules.is_empty() => {
            return HttpResponse::Ok().json(db_rules);
        }
        _ => {}
    }

    // If no rules in DB, return built-in rules
    let all_rules = get_all_rules();
    let filtered_rules: Vec<_> = if let Some(lang) = &query.language {
        all_rules.into_iter()
            .filter(|r| r.language.to_string() == *lang)
            .collect()
    } else {
        all_rules
    };

    HttpResponse::Ok().json(filtered_rules)
}

/// Create a custom SAST rule
///
/// POST /api/yellow-team/sast/rules
pub async fn sast_create_rule(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<yt_db::CreateSastRuleRequest>,
) -> HttpResponse {
    let user_id = &claims.sub;

    // Validate the regex pattern
    if let Err(e) = regex::Regex::new(&body.pattern) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid regex pattern",
            "details": e.to_string()
        }));
    }

    match yt_db::create_sast_rule(pool.get_ref(), user_id, &body).await {
        Ok(rule) => HttpResponse::Created().json(rule),
        Err(e) => {
            log::error!("Failed to create SAST rule: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create rule",
                "details": e.to_string()
            }))
        }
    }
}

/// Delete a custom SAST rule
///
/// DELETE /api/yellow-team/sast/rules/{id}
pub async fn sast_delete_rule(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let rule_id = path.into_inner();
    let user_id = &claims.sub;

    match yt_db::delete_sast_rule(pool.get_ref(), &rule_id, user_id).await {
        Ok(deleted) => {
            if deleted {
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "Rule deleted successfully"
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Rule not found or cannot be deleted (only custom rules can be deleted)"
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to delete SAST rule: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete rule",
                "details": e.to_string()
            }))
        }
    }
}

/// Get SAST statistics for the current user
///
/// GET /api/yellow-team/sast/stats
pub async fn sast_get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let user_id = &claims.sub;

    match yt_db::get_sast_stats(pool.get_ref(), user_id).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Failed to get SAST stats: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get stats",
                "details": e.to_string()
            }))
        }
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    // Create scan status store for API security
    let api_security_scan_store: ApiSecurityScanStatusStore = Arc::new(Mutex::new(HashMap::new()));

    cfg.app_data(web::Data::new(api_security_scan_store))
        // SBOM routes - supports both /sbom/{id} and /sbom/records/{id} patterns
        .service(
            web::scope("/yellow-team/sbom")
                .route("/generate", web::post().to(sbom_generate))
                .route("/file-types", web::get().to(sbom_file_types))
                // Direct access pattern (backwards compatible)
                .route("", web::get().to(sbom_list))
                .route("/{id}", web::get().to(sbom_get))
                .route("/{id}", web::delete().to(sbom_delete))
                .route("/{id}/components", web::get().to(sbom_components))
                .route("/{id}/vulns", web::get().to(sbom_vulns))
                .route("/{id}/vulnerabilities", web::get().to(sbom_vulns))
                .route("/{id}/licenses", web::get().to(sbom_licenses))
                .route("/{id}/export/{format}", web::get().to(sbom_export))
                .route("/{id}/rescan", web::post().to(sbom_rescan))
                // Records pattern (as specified in API spec)
                .route("/records", web::get().to(sbom_list))
                .route("/records/{id}", web::get().to(sbom_get))
                .route("/records/{id}", web::delete().to(sbom_delete))
                .route("/records/{id}/components", web::get().to(sbom_components))
                .route("/records/{id}/vulnerabilities", web::get().to(sbom_vulns))
                .route("/records/{id}/licenses", web::get().to(sbom_licenses))
                .route("/records/{id}/export/{format}", web::get().to(sbom_export))
                .route("/records/{id}/rescan", web::post().to(sbom_rescan))
        )
        // API Security routes
        .service(
            web::scope("/yellow-team/api-security")
                .route("/scan", web::post().to(api_security_start_scan))
                .route("/scans", web::get().to(api_security_list_scans))
                .route("/scans/{id}", web::get().to(api_security_get_scan))
                .route("/scans/{id}", web::delete().to(api_security_delete_scan))
                .route("/scans/{id}/endpoints", web::get().to(api_security_get_endpoints))
                .route("/scans/{id}/findings", web::get().to(api_security_get_findings))
                .route("/findings/{id}/status", web::put().to(api_security_update_finding_status))
                .route("/stats", web::get().to(api_security_get_stats))
                .route("/detect-type", web::post().to(api_security_detect_type))
                .route("/owasp-mapping", web::get().to(api_security_get_owasp_mapping))
        )
        // DevSecOps routes
        .service(
            web::scope("/yellow-team/devsecops")
            // Dashboard
            .route("/dashboard", web::get().to(get_dashboard))
            // Metrics
            .route("/metrics", web::get().to(get_metrics))
            .route("/metrics", web::post().to(record_metrics))
            // MTTR - basic and detailed breakdown
            .route("/mttr", web::get().to(get_mttr))
            .route("/mttr/breakdown", web::get().to(get_mttr_breakdown))
            // Findings trend
            .route("/trend", web::get().to(get_findings_trend))
            // Security coverage
            .route("/coverage", web::get().to(get_security_coverage))
            // Vulnerability density
            .route("/density", web::get().to(get_density))
            // SLA
            .route("/sla", web::get().to(get_sla))
            .route("/sla/breaches", web::get().to(get_sla_breaches))
            // Security debt - summary and items
            .route("/debt", web::get().to(get_debt))
            .route("/security-debt", web::get().to(get_security_debt_summary))
            .route("/security-debt/items", web::get().to(get_security_debt_items_endpoint))
            // Finding resolution tracking (for MTTR calculation)
            .route("/findings", web::post().to(record_finding))
            .route("/findings/resolve", web::post().to(resolve_finding))
            // Pipeline gates
            .route("/gates", web::post().to(create_gate))
            .route("/gates", web::get().to(list_gates))
            .route("/gates/{id}", web::get().to(get_gate))
            .route("/gates/{id}", web::put().to(update_gate))
            .route("/gates/{id}", web::delete().to(delete_gate))
            .route("/gates/{id}/evaluate", web::post().to(evaluate_gate))
            .route("/gates/{id}/evaluations", web::get().to(get_gate_evaluations))
            // Project health
            .route("/projects", web::get().to(get_projects)),
        )
        // Threat Modeling routes
        .service(
            web::scope("/yellow-team/threat-models")
                // Templates (must come before {id} routes)
                .route("/templates", web::get().to(get_templates))
                // CRUD operations
                .route("", web::get().to(list_threat_models))
                .route("", web::post().to(create_threat_model))
                .route("/{id}", web::get().to(get_threat_model))
                .route("/{id}", web::put().to(update_threat_model))
                .route("/{id}", web::delete().to(delete_threat_model))
                // Components
                .route("/{id}/components", web::post().to(add_component))
                .route("/{model_id}/components/{id}", web::delete().to(delete_component))
                // Data flows
                .route("/{id}/data-flows", web::post().to(add_data_flow))
                .route("/{model_id}/data-flows/{id}", web::delete().to(delete_data_flow))
                // Trust boundaries
                .route("/{id}/trust-boundaries", web::post().to(add_trust_boundary))
                .route("/{model_id}/trust-boundaries/{id}", web::delete().to(delete_trust_boundary))
                // Mitigations
                .route("/{id}/mitigations", web::post().to(add_mitigation))
                .route("/{model_id}/mitigations/{id}", web::delete().to(delete_mitigation))
                // Threats (manual add/update/delete)
                .route("/{id}/threats", web::post().to(add_threat))
                .route("/{model_id}/threats/{id}", web::put().to(update_threat))
                .route("/{model_id}/threats/{id}", web::delete().to(delete_threat))
                // Analysis
                .route("/{id}/analyze", web::post().to(analyze_threat_model))
                // Export
                .route("/{id}/export", web::get().to(export_threat_model))
        )
        // Threat status updates (separate scope for individual threats)
        .route("/yellow-team/threats/{id}/status", web::put().to(update_threat_status))
        // SAST (Static Application Security Testing) routes
        .service(
            web::scope("/yellow-team/sast")
                .route("/scan", web::post().to(sast_start_scan))
                .route("/scans", web::get().to(sast_list_scans))
                .route("/scans/{id}", web::get().to(sast_get_scan))
                .route("/scans/{id}", web::delete().to(sast_delete_scan))
                .route("/scans/{id}/findings", web::get().to(sast_get_findings))
                .route("/findings/{id}", web::put().to(sast_update_finding))
                .route("/rules", web::get().to(sast_list_rules))
                .route("/rules", web::post().to(sast_create_rule))
                .route("/rules/{id}", web::delete().to(sast_delete_rule))
                .route("/stats", web::get().to(sast_get_stats))
        );
}
