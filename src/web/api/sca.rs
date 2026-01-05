//! Software Composition Analysis (SCA) API endpoints
//!
//! Provides REST API endpoints for:
//! - SCA project management
//! - Dependency analysis
//! - Vulnerability detection via OSV
//! - Update recommendations

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db::sca as sca_db;
use crate::web::auth;
use crate::yellow_team::sca::{
    ScaAnalyzer, Ecosystem, assess_license_risk, generate_purl,
    CreateScaProjectRequest as ScaCreateReq,
};
use crate::yellow_team::sbom::SbomGenerator;

/// Configure SCA routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/sca")
            // Dashboard
            .route("/stats", web::get().to(get_stats))
            // Projects
            .route("/projects", web::post().to(create_project))
            .route("/projects", web::get().to(list_projects))
            .route("/projects/{id}", web::get().to(get_project))
            .route("/projects/{id}", web::put().to(update_project))
            .route("/projects/{id}", web::delete().to(delete_project))
            // Analysis
            .route("/projects/{id}/analyze", web::post().to(analyze_project))
            // Dependencies
            .route("/projects/{id}/dependencies", web::get().to(get_dependencies))
            // Vulnerabilities
            .route("/projects/{id}/vulnerabilities", web::get().to(get_vulnerabilities))
            .route("/projects/{id}/vulnerabilities/{vuln_id}/status", web::put().to(update_vuln_status))
            // Updates
            .route("/projects/{id}/updates", web::get().to(get_updates))
            // SBOM Export
            .route("/projects/{id}/sbom", web::get().to(export_sbom))
    );
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub repository_url: Option<String>,
    #[serde(default)]
    pub ecosystem: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProjectRequest {
    pub name: Option<String>,
    pub repository_url: Option<String>,
    pub ecosystem: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    /// Base64 encoded manifest content (e.g., package.json, Cargo.toml)
    pub manifest_content: Option<String>,
    /// Manifest file name for type detection
    pub manifest_filename: Option<String>,
    /// Whether to check for available updates
    #[serde(default = "default_true")]
    pub check_updates: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct DependencyFilter {
    pub is_direct: Option<bool>,
    pub has_vulnerabilities: Option<bool>,
    pub license_risk: Option<String>,
    pub update_available: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct VulnerabilityFilter {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub exploited_in_wild: Option<bool>,
    pub has_fix: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct AnalysisResponse {
    pub project_id: String,
    pub dependencies_found: i32,
    pub vulnerabilities_found: i32,
    pub license_issues_found: i32,
    pub updates_available: i32,
    pub analysis_duration_ms: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateRecommendation {
    pub package_name: String,
    pub current_version: String,
    pub latest_version: String,
    pub update_type: String,
    pub fixes_vulnerabilities: bool,
}

// ============================================================================
// Dashboard Endpoint
// ============================================================================

/// Get SCA dashboard statistics
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match sca_db::get_user_stats(pool.get_ref(), &claims.sub).await {
        Ok(stats) => {
            // Also get vulns by ecosystem and top vulnerable packages
            let vulns_by_eco = sca_db::get_vulns_by_ecosystem(pool.get_ref(), &claims.sub)
                .await
                .unwrap_or_default();
            let top_vulns = sca_db::get_top_vulnerable_packages(pool.get_ref(), &claims.sub, 10)
                .await
                .unwrap_or_default();

            HttpResponse::Ok().json(serde_json::json!({
                "stats": stats,
                "vulns_by_ecosystem": vulns_by_eco,
                "top_vulnerable_packages": top_vulns,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Project CRUD Endpoints
// ============================================================================

/// Create a new SCA project
pub async fn create_project(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateProjectRequest>,
) -> HttpResponse {
    let ecosystem = body.ecosystem.as_deref().unwrap_or("npm");

    let request = sca_db::CreateScaProjectRequest {
        name: body.name.clone(),
        repository_url: body.repository_url.clone(),
        ecosystem: ecosystem.to_string(),
        customer_id: body.customer_id.clone(),
        engagement_id: body.engagement_id.clone(),
    };

    match sca_db::create_project(pool.get_ref(), &claims.sub, &request).await {
        Ok(project) => HttpResponse::Created().json(project),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// List all SCA projects for the current user
pub async fn list_projects(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match sca_db::get_user_projects(pool.get_ref(), &claims.sub).await {
        Ok(projects) => HttpResponse::Ok().json(projects),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Get a specific SCA project
pub async fn get_project(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let project_id = path.into_inner();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to access this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match sca_db::get_project_by_id(pool.get_ref(), &project_id).await {
        Ok(project) => HttpResponse::Ok().json(project),
        Err(e) => HttpResponse::NotFound().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Update an SCA project
pub async fn update_project(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<UpdateProjectRequest>,
) -> HttpResponse {
    let project_id = path.into_inner();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to modify this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    let request = sca_db::UpdateScaProjectRequest {
        name: body.name.clone(),
        repository_url: body.repository_url.clone(),
        ecosystem: body.ecosystem.clone(),
        customer_id: body.customer_id.clone(),
        engagement_id: body.engagement_id.clone(),
    };

    match sca_db::update_project(pool.get_ref(), &project_id, &request).await {
        Ok(project) => HttpResponse::Ok().json(project),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Delete an SCA project
pub async fn delete_project(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let project_id = path.into_inner();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to delete this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match sca_db::delete_project(pool.get_ref(), &project_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Analysis Endpoint
// ============================================================================

/// Analyze a project for dependencies and vulnerabilities
pub async fn analyze_project(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    body: web::Json<AnalyzeRequest>,
) -> HttpResponse {
    let project_id = path.into_inner();
    let start = std::time::Instant::now();
    let mut errors = Vec::new();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to analyze this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    // Get project to determine ecosystem
    let project = match sca_db::get_project_by_id(pool.get_ref(), &project_id).await {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    let ecosystem = Ecosystem::from_str(&project.ecosystem);

    // Parse manifest content if provided
    let manifest_content = if let Some(b64) = &body.manifest_content {
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => Some(s),
                Err(e) => {
                    errors.push(format!("Invalid UTF-8 in manifest: {}", e));
                    None
                }
            },
            Err(e) => {
                errors.push(format!("Invalid base64 encoding: {}", e));
                None
            }
        }
    } else {
        None
    };

    // Clear existing dependencies and vulnerabilities
    if let Err(e) = sca_db::delete_project_vulnerabilities(pool.get_ref(), &project_id).await {
        errors.push(format!("Failed to clear vulnerabilities: {}", e));
    }
    if let Err(e) = sca_db::delete_project_dependencies(pool.get_ref(), &project_id).await {
        errors.push(format!("Failed to clear dependencies: {}", e));
    }

    let mut dependencies_found = 0i32;
    let mut vulnerabilities_found = 0i32;
    let mut license_issues_found = 0i32;
    let mut updates_available = 0i32;
    let mut manifest_files = Vec::new();

    // Parse dependencies using SBOM generator
    if let Some(content) = manifest_content {
        let filename = body.manifest_filename.as_deref().unwrap_or("package.json");
        manifest_files.push(filename.to_string());

        // Create a temporary directory-like structure for SBOM generator
        let mut sbom = SbomGenerator::new(&project.name, None, ".");

        // Determine parser based on filename
        let parse_result = match filename {
            f if f.ends_with("package.json") => sbom.parse_package_json(&content).map_err(|e| anyhow::anyhow!(e)),
            f if f.ends_with("Cargo.toml") => sbom.parse_cargo_toml(&content).map_err(|e| anyhow::anyhow!(e)),
            f if f.ends_with("requirements.txt") => sbom.parse_requirements_txt(&content).map_err(|e| anyhow::anyhow!(e)),
            f if f.ends_with("go.mod") => sbom.parse_go_mod(&content).map_err(|e| anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Unsupported manifest file type. Supported: package.json, Cargo.toml, requirements.txt, go.mod")),
        };

        if let Err(e) = parse_result {
            errors.push(format!("Failed to parse {}: {}", filename, e));
        }

        // Create SCA analyzer
        let analyzer = ScaAnalyzer::new();

        // Process each component
        let mut dep_requests = Vec::new();

        for component in &sbom.components {
            let license = component.license();
            let license_risk = license
                .as_ref()
                .map(|l| assess_license_risk(l))
                .unwrap_or(crate::yellow_team::sca::LicenseRiskLevel::Unknown);

            if matches!(license_risk, crate::yellow_team::sca::LicenseRiskLevel::High) {
                license_issues_found += 1;
            }

            let purl = generate_purl(&component.name, &component.version, ecosystem);

            dep_requests.push(sca_db::CreateDependencyRequest {
                name: component.name.clone(),
                version: component.version.clone(),
                ecosystem: ecosystem.to_string(),
                purl: Some(purl),
                is_direct: component.dependency_type == crate::yellow_team::types::DependencyType::Direct,
                parent_id: None,
                depth: if component.dependency_type == crate::yellow_team::types::DependencyType::Direct { 0 } else { 1 },
                license: license,
                license_risk: license_risk.to_string(),
                latest_version: None,
                update_available: false,
            });
        }

        // Store dependencies
        match sca_db::create_dependencies_bulk(pool.get_ref(), &project_id, &dep_requests).await {
            Ok(count) => dependencies_found = count as i32,
            Err(e) => errors.push(format!("Failed to store dependencies: {}", e)),
        }

        // Check for vulnerabilities
        let matched_vulns = analyzer.analyze_components(&sbom.components, ecosystem).await;

        // Get dependency IDs for vulnerability mapping
        let deps = sca_db::get_project_dependencies(
            pool.get_ref(),
            &project_id,
            None, None, None, None, None, None,
        )
        .await
        .unwrap_or_default();

        let dep_map: std::collections::HashMap<String, String> = deps
            .iter()
            .map(|d| (format!("{}@{}", d.name, d.version), d.id.clone()))
            .collect();

        // Store vulnerabilities
        for component in &sbom.components {
            let key = format!("{}@{}", component.name, component.version);
            if let Some(dep_id) = dep_map.get(&key) {
                // Query OSV for this package
                if let Ok(vulns) = analyzer.osv_client
                    .query_package(&component.name, &component.version, ecosystem.to_osv_ecosystem())
                    .await
                {
                    for vuln in vulns {
                        let vuln_req = sca_db::CreateVulnerabilityRequest {
                            dependency_id: dep_id.clone(),
                            vuln_id: vuln.id.clone(),
                            source: "osv".to_string(),
                            severity: vuln.severity_level().to_string(),
                            cvss_score: vuln.cvss_score(),
                            cvss_vector: None,
                            epss_score: None,
                            title: vuln.summary.clone(),
                            description: vuln.details.clone(),
                            affected_versions: None,
                            fixed_version: vuln.fixed_version(ecosystem.to_osv_ecosystem(), &component.name),
                            references: vuln.reference_urls().iter().map(|s| s.to_string()).collect(),
                            exploited_in_wild: false,
                        };

                        if let Err(e) = sca_db::create_vulnerability(pool.get_ref(), &project_id, &vuln_req).await {
                            log::warn!("Failed to store vulnerability {}: {}", vuln.id, e);
                        } else {
                            vulnerabilities_found += 1;
                        }
                    }
                }
            }
        }

        // Check for updates if requested
        if body.check_updates {
            for component in &sbom.components {
                let key = format!("{}@{}", component.name, component.version);
                if let Some(_dep_id) = dep_map.get(&key) {
                    if let Ok(Some(recommendation)) = analyzer.update_checker
                        .get_update_recommendation(&component.name, &component.version, ecosystem.to_osv_ecosystem())
                        .await
                    {
                        updates_available += 1;
                        // Update the dependency record
                        // Note: In a full implementation, we'd update the record with latest_version
                    }
                }
            }
        }
    }

    // Update project statistics
    let vuln_deps = if vulnerabilities_found > 0 {
        // Count unique vulnerable dependencies
        sca_db::get_project_vulnerabilities(pool.get_ref(), &project_id, None, None, None, None, None, None)
            .await
            .map(|v| {
                let unique: std::collections::HashSet<_> = v.iter().map(|x| &x.dependency_id).collect();
                unique.len() as i64
            })
            .unwrap_or(0)
    } else {
        0
    };

    if let Err(e) = sca_db::update_project_stats(
        pool.get_ref(),
        &project_id,
        dependencies_found as i64,
        vuln_deps,
        license_issues_found as i64,
        &manifest_files,
    ).await {
        errors.push(format!("Failed to update project stats: {}", e));
    }

    HttpResponse::Ok().json(AnalysisResponse {
        project_id,
        dependencies_found,
        vulnerabilities_found,
        license_issues_found,
        updates_available,
        analysis_duration_ms: start.elapsed().as_millis() as u64,
        errors,
    })
}

// ============================================================================
// Dependencies Endpoint
// ============================================================================

/// Get dependencies for a project
pub async fn get_dependencies(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<DependencyFilter>,
) -> HttpResponse {
    let project_id = path.into_inner();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to access this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match sca_db::get_project_dependencies(
        pool.get_ref(),
        &project_id,
        query.is_direct,
        query.has_vulnerabilities,
        query.license_risk.as_deref(),
        query.update_available,
        query.limit,
        query.offset,
    ).await {
        Ok(deps) => HttpResponse::Ok().json(deps),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Vulnerabilities Endpoint
// ============================================================================

/// Get vulnerabilities for a project
pub async fn get_vulnerabilities(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<VulnerabilityFilter>,
) -> HttpResponse {
    let project_id = path.into_inner();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to access this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    match sca_db::get_project_vulnerabilities(
        pool.get_ref(),
        &project_id,
        query.severity.as_deref(),
        query.status.as_deref(),
        query.exploited_in_wild,
        query.has_fix,
        query.limit,
        query.offset,
    ).await {
        Ok(vulns) => HttpResponse::Ok().json(vulns),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

/// Update vulnerability status
pub async fn update_vuln_status(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<(String, String)>,
    body: web::Json<UpdateStatusRequest>,
) -> HttpResponse {
    let (project_id, vuln_id) = path.into_inner();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to modify this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    // Validate status
    let valid_statuses = ["new", "acknowledged", "in_progress", "fixed", "ignored", "false_positive"];
    if !valid_statuses.contains(&body.status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid status. Must be one of: {:?}", valid_statuses)
        }));
    }

    match sca_db::update_vulnerability_status(pool.get_ref(), &vuln_id, &body.status).await {
        Ok(vuln) => HttpResponse::Ok().json(vuln),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

// ============================================================================
// Updates Endpoint
// ============================================================================

/// Get update recommendations for a project
pub async fn get_updates(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> HttpResponse {
    let project_id = path.into_inner();

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to access this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    // Get project
    let project = match sca_db::get_project_by_id(pool.get_ref(), &project_id).await {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    let ecosystem = Ecosystem::from_str(&project.ecosystem);

    // Get dependencies with updates available
    let deps = match sca_db::get_project_dependencies(
        pool.get_ref(),
        &project_id,
        Some(true), // Direct dependencies only
        None,
        None,
        Some(true), // Update available
        None,
        None,
    ).await {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    let analyzer = ScaAnalyzer::new();
    let mut recommendations = Vec::new();

    for dep in deps {
        if let Ok(Some(rec)) = analyzer.update_checker
            .get_update_recommendation(&dep.name, &dep.version, ecosystem.to_osv_ecosystem())
            .await
        {
            // Check if this update fixes any vulnerabilities
            let fixes_vulns = sca_db::get_project_vulnerabilities(
                pool.get_ref(),
                &project_id,
                None, None, None, None, None, None,
            )
            .await
            .map(|vulns| {
                vulns.iter().any(|v| {
                    v.dependency_id == dep.id && v.fixed_version.is_some()
                })
            })
            .unwrap_or(false);

            recommendations.push(UpdateRecommendation {
                package_name: dep.name.clone(),
                current_version: dep.version.clone(),
                latest_version: rec.latest_version,
                update_type: rec.update_type.to_string(),
                fixes_vulnerabilities: fixes_vulns,
            });
        }
    }

    HttpResponse::Ok().json(recommendations)
}

// ============================================================================
// SBOM Export Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SbomExportQuery {
    /// Export format: "cyclonedx" or "spdx"
    pub format: Option<String>,
}

/// Export SBOM (Software Bill of Materials) in CycloneDX or SPDX format
pub async fn export_sbom(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<SbomExportQuery>,
) -> HttpResponse {
    let project_id = path.into_inner();
    let format = query.format.as_deref().unwrap_or("cyclonedx");

    // Verify ownership
    match sca_db::user_owns_project(pool.get_ref(), &claims.sub, &project_id).await {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to access this project"
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    }

    // Get project
    let project = match sca_db::get_project_by_id(pool.get_ref(), &project_id).await {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    // Get all dependencies
    let deps = match sca_db::get_project_dependencies(
        pool.get_ref(),
        &project_id,
        None, None, None, None, None, None,
    ).await {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }));
        }
    };

    // Get vulnerabilities for each dependency
    let vulns = sca_db::get_project_vulnerabilities(
        pool.get_ref(),
        &project_id,
        None, None, None, None, None, None,
    ).await.unwrap_or_default();

    let timestamp = chrono::Utc::now().to_rfc3339();

    match format.to_lowercase().as_str() {
        "cyclonedx" => {
            // Generate CycloneDX 1.5 JSON format
            let components: Vec<serde_json::Value> = deps.iter().map(|dep| {
                let dep_vulns: Vec<serde_json::Value> = vulns.iter()
                    .filter(|v| v.dependency_id == dep.id)
                    .map(|v| {
                        serde_json::json!({
                            "id": v.vuln_id,
                            "source": {
                                "name": v.source,
                                "url": format!("https://nvd.nist.gov/vuln/detail/{}", v.vuln_id)
                            },
                            "ratings": [{
                                "score": v.cvss_score.unwrap_or(0.0),
                                "severity": v.severity,
                                "method": "CVSSv3"
                            }],
                            "description": v.description
                        })
                    })
                    .collect();

                let mut component = serde_json::json!({
                    "type": "library",
                    "bom-ref": format!("{}@{}", dep.name, dep.version),
                    "name": dep.name,
                    "version": dep.version,
                    "purl": format!("pkg:{}/{}@{}",
                        match dep.ecosystem.as_str() {
                            "npm" => "npm",
                            "cargo" => "cargo",
                            "pypi" => "pypi",
                            "go" => "golang",
                            "maven" => "maven",
                            _ => "generic"
                        },
                        dep.name,
                        dep.version
                    )
                });

                if let Some(license) = &dep.license {
                    component["licenses"] = serde_json::json!([{
                        "license": { "id": license }
                    }]);
                }

                if !dep_vulns.is_empty() {
                    component["vulnerabilities"] = serde_json::json!(dep_vulns);
                }

                component
            }).collect();

            let sbom = serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "version": 1,
                "metadata": {
                    "timestamp": timestamp,
                    "tools": [{
                        "vendor": "HeroForge",
                        "name": "HeroForge SCA",
                        "version": "0.2.0"
                    }],
                    "component": {
                        "type": "application",
                        "name": project.name,
                        "version": "1.0.0"
                    }
                },
                "components": components
            });

            HttpResponse::Ok()
                .content_type("application/json")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}-sbom-cyclonedx.json\"", project.name)))
                .json(sbom)
        }
        "spdx" => {
            // Generate SPDX 2.3 JSON format
            let packages: Vec<serde_json::Value> = deps.iter().enumerate().map(|(idx, dep)| {
                let mut pkg = serde_json::json!({
                    "SPDXID": format!("SPDXRef-Package-{}", idx + 1),
                    "name": dep.name,
                    "versionInfo": dep.version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "externalRefs": [{
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": format!("pkg:{}/{}@{}",
                            match dep.ecosystem.as_str() {
                                "npm" => "npm",
                                "cargo" => "cargo",
                                "pypi" => "pypi",
                                "go" => "golang",
                                "maven" => "maven",
                                _ => "generic"
                            },
                            dep.name,
                            dep.version
                        )
                    }]
                });

                if let Some(license) = &dep.license {
                    pkg["licenseConcluded"] = serde_json::json!(license);
                    pkg["licenseDeclared"] = serde_json::json!(license);
                } else {
                    pkg["licenseConcluded"] = serde_json::json!("NOASSERTION");
                    pkg["licenseDeclared"] = serde_json::json!("NOASSERTION");
                }

                // Add vulnerability annotations
                let dep_vulns: Vec<&_> = vulns.iter()
                    .filter(|v| v.dependency_id == dep.id)
                    .collect();

                if !dep_vulns.is_empty() {
                    let vuln_refs: Vec<serde_json::Value> = dep_vulns.iter().map(|v| {
                        serde_json::json!({
                            "referenceCategory": "SECURITY",
                            "referenceType": "cve",
                            "referenceLocator": format!("https://nvd.nist.gov/vuln/detail/{}", v.vuln_id)
                        })
                    }).collect();

                    if let Some(refs) = pkg.get_mut("externalRefs") {
                        if let Some(arr) = refs.as_array_mut() {
                            arr.extend(vuln_refs);
                        }
                    }
                }

                pkg
            }).collect();

            let relationships: Vec<serde_json::Value> = packages.iter().map(|pkg| {
                serde_json::json!({
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": pkg["SPDXID"],
                    "relationshipType": "DESCRIBES"
                })
            }).collect();

            let sbom = serde_json::json!({
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": format!("{}-sbom", project.name),
                "documentNamespace": format!("https://heroforge.io/spdx/{}/{}", project.id, uuid::Uuid::new_v4()),
                "creationInfo": {
                    "created": timestamp,
                    "creators": ["Tool: HeroForge-SCA-0.2.0"]
                },
                "packages": packages,
                "relationships": relationships
            });

            HttpResponse::Ok()
                .content_type("application/json")
                .insert_header(("Content-Disposition", format!("attachment; filename=\"{}-sbom-spdx.json\"", project.name)))
                .json(sbom)
        }
        _ => {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid format. Supported formats: cyclonedx, spdx"
            }))
        }
    }
}
