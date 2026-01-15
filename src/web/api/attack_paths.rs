//! Attack Path Analysis API Endpoints
//!
//! Provides REST API endpoints for analyzing and retrieving attack paths.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::db::attack_paths::{self, AttackPathStats};
use crate::scanner::attack_paths::analyze_scan_for_attack_paths;
use crate::web::auth::Claims;
use crate::web::error::ApiErrorKind;

/// Query parameters for listing attack paths
#[derive(Debug, Deserialize, ToSchema)]
pub struct ListAttackPathsQuery {
    /// Maximum number of paths to return (default: 50)
    pub limit: Option<i64>,
    /// Offset for pagination (default: 0)
    pub offset: Option<i64>,
}

/// Response for listing all attack paths
#[derive(Debug, Serialize, ToSchema)]
pub struct ListAttackPathsResponse {
    pub paths: Vec<AttackPathSummary>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Summary of an attack path (lightweight for listing)
#[derive(Debug, Serialize, ToSchema)]
pub struct AttackPathSummary {
    pub id: String,
    pub scan_id: String,
    pub name: Option<String>,
    pub risk_level: String,
    pub probability: f64,
    pub total_cvss: f64,
    pub path_length: i32,
    pub created_at: String,
}

/// Request to analyze attack paths
#[derive(Debug, Deserialize, ToSchema)]
pub struct AnalyzeAttackPathsRequest {
    /// Force re-analysis even if paths already exist
    #[serde(default)]
    pub force: bool,
}

/// Response for attack path analysis
#[derive(Debug, Serialize, ToSchema)]
pub struct AnalyzeAttackPathsResponse {
    pub scan_id: String,
    pub paths_found: usize,
    pub critical_paths: usize,
    pub highest_risk: String,
    pub message: String,
}

/// Response for getting attack paths
#[derive(Debug, Serialize, ToSchema)]
pub struct GetAttackPathsResponse {
    pub scan_id: String,
    pub paths: Vec<AttackPathResponse>,
    pub stats: AttackPathStats,
}

/// Attack path in response format
#[derive(Debug, Serialize, ToSchema)]
pub struct AttackPathResponse {
    pub id: String,
    pub name: Option<String>,
    pub risk_level: String,
    pub probability: f64,
    pub total_cvss: f64,
    pub path_length: i32,
    pub description: Option<String>,
    pub mitigation_steps: Vec<String>,
    pub nodes: Vec<AttackNodeResponse>,
    pub edges: Vec<AttackEdgeResponse>,
}

/// Attack node in response format
#[derive(Debug, Serialize, ToSchema)]
pub struct AttackNodeResponse {
    pub id: String,
    pub host_ip: Option<String>,
    pub port: Option<i32>,
    pub service: Option<String>,
    pub vulnerability_ids: Vec<String>,
    pub node_type: String,
    pub position_x: f64,
    pub position_y: f64,
}

/// Attack edge in response format
#[derive(Debug, Serialize, ToSchema)]
pub struct AttackEdgeResponse {
    pub id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub attack_technique: Option<String>,
    pub technique_id: Option<String>,
    pub likelihood: f64,
    pub impact: f64,
    pub description: Option<String>,
}

/// List all attack paths for the current user
///
/// GET /api/attack-paths
#[utoipa::path(
    get,
    path = "/api/attack-paths",
    tag = "Attack Paths",
    params(
        ("limit" = Option<i64>, Query, description = "Max paths to return (default: 50)"),
        ("offset" = Option<i64>, Query, description = "Pagination offset (default: 0)")
    ),
    responses(
        (status = 200, description = "Attack paths list", body = ListAttackPathsResponse),
        (status = 500, description = "Failed to retrieve paths")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_attack_paths(
    pool: web::Data<SqlitePool>,
    query: web::Query<ListAttackPathsQuery>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    // Get paths for this user
    let paths = attack_paths::get_attack_paths_by_user(pool.get_ref(), &claims.sub, Some(limit), Some(offset))
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Get total count
    let total = attack_paths::count_attack_paths_by_user(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Convert to summaries
    let summaries: Vec<AttackPathSummary> = paths
        .into_iter()
        .map(|p| AttackPathSummary {
            id: p.id,
            scan_id: p.scan_id,
            name: p.name,
            risk_level: p.risk_level,
            probability: p.probability.unwrap_or(0.0),
            total_cvss: p.total_cvss.unwrap_or(0.0),
            path_length: p.path_length.unwrap_or(0),
            created_at: p.created_at.to_rfc3339(),
        })
        .collect();

    let response = ListAttackPathsResponse {
        paths: summaries,
        total,
        limit,
        offset,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Analyze a scan for attack paths
///
/// POST /api/attack-paths/analyze/{scan_id}
#[utoipa::path(
    post,
    path = "/api/attack-paths/analyze/{scan_id}",
    tag = "Attack Paths",
    request_body = AnalyzeAttackPathsRequest,
    responses(
        (status = 200, description = "Analysis completed", body = AnalyzeAttackPathsResponse),
        (status = 404, description = "Scan not found"),
        (status = 403, description = "Not authorized to access this scan"),
        (status = 500, description = "Analysis failed")
    ),
    security(("bearer_auth" = []))
)]
pub async fn analyze_attack_paths(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AnalyzeAttackPathsRequest>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let scan_id = path.into_inner();
    log::info!("Analyzing attack paths for scan: {}", scan_id);

    // Get the scan and verify ownership
    let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Scan not found".to_string()))?;

    if scan.user_id != claims.sub {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to access this scan".to_string(),
        ));
    }

    if scan.status != "completed" {
        return Err(ApiErrorKind::BadRequest(
            "Scan must be completed before analysis".to_string(),
        ));
    }

    // Check if analysis already exists
    let exists = attack_paths::attack_paths_exist(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    if exists && !body.force {
        return Err(ApiErrorKind::Conflict(
            "Attack paths already analyzed. Use force=true to re-analyze.".to_string(),
        ));
    }

    // Delete existing paths if re-analyzing
    if exists && body.force {
        attack_paths::delete_attack_paths_by_scan(pool.get_ref(), &scan_id)
            .await
            .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;
    }

    // Parse scan results
    let hosts: Vec<crate::types::HostInfo> = scan
        .results
        .as_ref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or_default();

    if hosts.is_empty() {
        return Err(ApiErrorKind::BadRequest(
            "No scan results to analyze".to_string(),
        ));
    }

    // Run the analysis
    let analysis_result = analyze_scan_for_attack_paths(&scan_id, &hosts)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Store results in database
    for path in &analysis_result.paths {
        attack_paths::create_attack_path(pool.get_ref(), &scan_id, &claims.sub, path)
            .await
            .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;
    }

    let response = AnalyzeAttackPathsResponse {
        scan_id: scan_id.clone(),
        paths_found: analysis_result.paths.len(),
        critical_paths: analysis_result.critical_paths.len(),
        highest_risk: analysis_result.highest_risk.as_str().to_string(),
        message: format!(
            "Found {} attack paths ({} critical/high risk)",
            analysis_result.paths.len(),
            analysis_result.critical_paths.len()
        ),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get attack paths for a scan
///
/// GET /api/attack-paths/{scan_id}
#[utoipa::path(
    get,
    path = "/api/attack-paths/{scan_id}",
    tag = "Attack Paths",
    responses(
        (status = 200, description = "Attack paths retrieved", body = GetAttackPathsResponse),
        (status = 404, description = "Scan not found or no paths analyzed"),
        (status = 403, description = "Not authorized to access this scan")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_attack_paths(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let scan_id = path.into_inner();

    // Verify ownership
    let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Scan not found".to_string()))?;

    if scan.user_id != claims.sub {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to access this scan".to_string(),
        ));
    }

    // Get paths from database
    let path_records = attack_paths::get_attack_paths_by_scan(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Get stats
    let stats = attack_paths::get_attack_path_stats(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Convert to response format with nodes and edges
    let mut paths = Vec::new();
    for record in path_records {
        let nodes = attack_paths::get_attack_nodes(pool.get_ref(), &record.id)
            .await
            .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

        let edges = attack_paths::get_attack_edges(pool.get_ref(), &record.id)
            .await
            .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

        let mitigation_steps: Vec<String> = record
            .mitigation_steps
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();

        paths.push(AttackPathResponse {
            id: record.id,
            name: record.name,
            risk_level: record.risk_level,
            probability: record.probability.unwrap_or(0.0),
            total_cvss: record.total_cvss.unwrap_or(0.0),
            path_length: record.path_length.unwrap_or(0),
            description: record.description,
            mitigation_steps,
            nodes: nodes
                .into_iter()
                .map(|n| {
                    let vuln_ids: Vec<String> = n
                        .vulnerability_ids
                        .as_ref()
                        .and_then(|v| serde_json::from_str(v).ok())
                        .unwrap_or_default();

                    AttackNodeResponse {
                        id: n.id,
                        host_ip: n.host_ip,
                        port: n.port,
                        service: n.service,
                        vulnerability_ids: vuln_ids,
                        node_type: n.node_type,
                        position_x: n.position_x.unwrap_or(0.0),
                        position_y: n.position_y.unwrap_or(0.0),
                    }
                })
                .collect(),
            edges: edges
                .into_iter()
                .map(|e| AttackEdgeResponse {
                    id: e.id,
                    source_node_id: e.source_node_id,
                    target_node_id: e.target_node_id,
                    attack_technique: e.attack_technique,
                    technique_id: e.technique_id,
                    likelihood: e.likelihood.unwrap_or(0.5),
                    impact: e.impact.unwrap_or(5.0),
                    description: e.description,
                })
                .collect(),
        });
    }

    let response = GetAttackPathsResponse {
        scan_id,
        paths,
        stats,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get critical attack paths for a scan
///
/// GET /api/attack-paths/{scan_id}/critical
#[utoipa::path(
    get,
    path = "/api/attack-paths/{scan_id}/critical",
    tag = "Attack Paths",
    responses(
        (status = 200, description = "Critical attack paths retrieved", body = GetAttackPathsResponse),
        (status = 404, description = "Scan not found"),
        (status = 403, description = "Not authorized to access this scan")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_critical_attack_paths(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let scan_id = path.into_inner();

    // Verify ownership
    let scan = crate::db::get_scan_by_id(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Scan not found".to_string()))?;

    if scan.user_id != claims.sub {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to access this scan".to_string(),
        ));
    }

    // Get critical paths from database
    let path_records = attack_paths::get_critical_attack_paths(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Get stats
    let stats = attack_paths::get_attack_path_stats(pool.get_ref(), &scan_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Convert to response format with nodes and edges
    let mut paths = Vec::new();
    for record in path_records {
        let nodes = attack_paths::get_attack_nodes(pool.get_ref(), &record.id)
            .await
            .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

        let edges = attack_paths::get_attack_edges(pool.get_ref(), &record.id)
            .await
            .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

        let mitigation_steps: Vec<String> = record
            .mitigation_steps
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();

        paths.push(AttackPathResponse {
            id: record.id,
            name: record.name,
            risk_level: record.risk_level,
            probability: record.probability.unwrap_or(0.0),
            total_cvss: record.total_cvss.unwrap_or(0.0),
            path_length: record.path_length.unwrap_or(0),
            description: record.description,
            mitigation_steps,
            nodes: nodes
                .into_iter()
                .map(|n| {
                    let vuln_ids: Vec<String> = n
                        .vulnerability_ids
                        .as_ref()
                        .and_then(|v| serde_json::from_str(v).ok())
                        .unwrap_or_default();

                    AttackNodeResponse {
                        id: n.id,
                        host_ip: n.host_ip,
                        port: n.port,
                        service: n.service,
                        vulnerability_ids: vuln_ids,
                        node_type: n.node_type,
                        position_x: n.position_x.unwrap_or(0.0),
                        position_y: n.position_y.unwrap_or(0.0),
                    }
                })
                .collect(),
            edges: edges
                .into_iter()
                .map(|e| AttackEdgeResponse {
                    id: e.id,
                    source_node_id: e.source_node_id,
                    target_node_id: e.target_node_id,
                    attack_technique: e.attack_technique,
                    technique_id: e.technique_id,
                    likelihood: e.likelihood.unwrap_or(0.5),
                    impact: e.impact.unwrap_or(5.0),
                    description: e.description,
                })
                .collect(),
        });
    }

    let response = GetAttackPathsResponse {
        scan_id,
        paths,
        stats,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Get a single attack path with full details
///
/// GET /api/attack-paths/path/{path_id}
#[utoipa::path(
    get,
    path = "/api/attack-paths/path/{path_id}",
    tag = "Attack Paths",
    responses(
        (status = 200, description = "Attack path details retrieved", body = AttackPathResponse),
        (status = 404, description = "Attack path not found"),
        (status = 403, description = "Not authorized to access this path")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_attack_path_detail(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let path_id = path.into_inner();

    // Get path details
    let path_with_details = attack_paths::get_attack_path_with_details(pool.get_ref(), &path_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Attack path not found".to_string()))?;

    // Verify ownership via scan
    if path_with_details.path.user_id != claims.sub {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to access this attack path".to_string(),
        ));
    }

    let record = path_with_details.path;
    let mitigation_steps: Vec<String> = record
        .mitigation_steps
        .as_ref()
        .and_then(|m| serde_json::from_str(m).ok())
        .unwrap_or_default();

    let response = AttackPathResponse {
        id: record.id,
        name: record.name,
        risk_level: record.risk_level,
        probability: record.probability.unwrap_or(0.0),
        total_cvss: record.total_cvss.unwrap_or(0.0),
        path_length: record.path_length.unwrap_or(0),
        description: record.description,
        mitigation_steps,
        nodes: path_with_details
            .nodes
            .into_iter()
            .map(|n| {
                let vuln_ids: Vec<String> = n
                    .vulnerability_ids
                    .as_ref()
                    .and_then(|v| serde_json::from_str(v).ok())
                    .unwrap_or_default();

                AttackNodeResponse {
                    id: n.id,
                    host_ip: n.host_ip,
                    port: n.port,
                    service: n.service,
                    vulnerability_ids: vuln_ids,
                    node_type: n.node_type,
                    position_x: n.position_x.unwrap_or(0.0),
                    position_y: n.position_y.unwrap_or(0.0),
                }
            })
            .collect(),
        edges: path_with_details
            .edges
            .into_iter()
            .map(|e| AttackEdgeResponse {
                id: e.id,
                source_node_id: e.source_node_id,
                target_node_id: e.target_node_id,
                attack_technique: e.attack_technique,
                technique_id: e.technique_id,
                likelihood: e.likelihood.unwrap_or(0.5),
                impact: e.impact.unwrap_or(5.0),
                description: e.description,
            })
            .collect(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Configure attack paths routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/attack-paths")
            .route("", web::get().to(list_attack_paths))
            .route("/analyze/{scan_id}", web::post().to(analyze_attack_paths))
            .route("/path/{path_id}", web::get().to(get_attack_path_detail))
            .route("/{scan_id}", web::get().to(get_attack_paths))
            .route("/{scan_id}/critical", web::get().to(get_critical_attack_paths)),
    );
}
