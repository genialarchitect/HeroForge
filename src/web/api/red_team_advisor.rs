//! AI Red Team Advisor API endpoints
//!
//! Provides endpoints for AI-powered red team recommendations based on network topology.

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};

use crate::ai::red_team_advisor::{RedTeamAdvisor, TopologyForAnalysis, TopologyNode, TopologyEdge, TopologyMetadata};
use crate::db::models::{AnalyzeTopologyRequest, UpdateRecommendationRequest, ExecuteRecommendationRequest};
use crate::web::auth;

/// Analyze topology and generate recommendations
///
/// POST /api/ai/red-team/analyze
#[utoipa::path(
    post,
    path = "/api/ai/red-team/analyze",
    request_body = AnalyzeTopologyWithDataRequest,
    responses(
        (status = 200, description = "Analysis complete with recommendations"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Analysis failed")
    ),
    tag = "AI Red Team Advisor"
)]
pub async fn analyze_topology(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<AnalyzeTopologyWithDataRequest>,
) -> HttpResponse {
    let user_id = claims.sub.clone();

    let advisor = RedTeamAdvisor::new(pool.get_ref().clone());

    // Convert request to internal types
    let topology = TopologyForAnalysis {
        nodes: body.topology.nodes.iter().map(|n| TopologyNode {
            id: n.id.clone(),
            label: n.label.clone(),
            device_type: n.device_type.clone(),
            security_zone: n.security_zone.clone(),
            ip_address: n.ip_address.clone(),
            hostname: n.hostname.clone(),
            os: n.os.clone(),
            compliance_status: n.compliance_status.clone(),
            vulnerabilities: n.vulnerabilities,
            open_ports: n.open_ports.clone(),
            services: n.services.clone(),
        }).collect(),
        edges: body.topology.edges.iter().map(|e| TopologyEdge {
            source: e.source.clone(),
            target: e.target.clone(),
            protocol: e.protocol.clone(),
            port: e.port,
            encrypted: e.encrypted,
            data_classification: e.data_classification.clone(),
        }).collect(),
        metadata: body.topology.metadata.as_ref().map(|m| TopologyMetadata {
            name: m.name.clone(),
            organization: m.organization.clone(),
            industry: m.industry.clone(),
            compliance_frameworks: m.compliance_frameworks.clone(),
        }),
    };

    let request = AnalyzeTopologyRequest {
        topology_id: body.topology_id.clone(),
        scan_id: body.scan_id.clone(),
        engagement_id: body.engagement_id.clone(),
        analysis_type: body.analysis_type.clone(),
        focus_areas: body.focus_areas.clone(),
        exclude_node_ids: body.exclude_node_ids.clone(),
        max_recommendations: body.max_recommendations,
    };

    match advisor.analyze_topology(&user_id, topology, request).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => {
            log::error!("AI analysis failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Analysis failed: {}", e)
            }))
        }
    }
}

/// Get recommendations for a topology/scan
///
/// GET /api/ai/red-team/recommendations
#[utoipa::path(
    get,
    path = "/api/ai/red-team/recommendations",
    params(
        ("topology_id" = Option<String>, Query, description = "Filter by topology ID"),
        ("scan_id" = Option<String>, Query, description = "Filter by scan ID"),
        ("status" = Option<String>, Query, description = "Filter by status (pending/accepted/rejected/running/completed/failed)")
    ),
    responses(
        (status = 200, description = "List of recommendations"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "AI Red Team Advisor"
)]
pub async fn get_recommendations(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<GetRecommendationsQuery>,
) -> HttpResponse {
    let user_id = claims.sub.clone();

    let advisor = RedTeamAdvisor::new(pool.get_ref().clone());

    match advisor.get_recommendations(
        &user_id,
        query.topology_id.as_deref(),
        query.scan_id.as_deref(),
        query.status.as_deref(),
    ).await {
        Ok(recommendations) => HttpResponse::Ok().json(recommendations),
        Err(e) => {
            log::error!("Failed to get recommendations: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get recommendations: {}", e)
            }))
        }
    }
}

/// Get recommendations summary
///
/// GET /api/ai/red-team/summary
#[utoipa::path(
    get,
    path = "/api/ai/red-team/summary",
    params(
        ("topology_id" = Option<String>, Query, description = "Filter by topology ID"),
        ("scan_id" = Option<String>, Query, description = "Filter by scan ID")
    ),
    responses(
        (status = 200, description = "Recommendations summary"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "AI Red Team Advisor"
)]
pub async fn get_summary(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<GetRecommendationsQuery>,
) -> HttpResponse {
    let user_id = claims.sub.clone();

    let advisor = RedTeamAdvisor::new(pool.get_ref().clone());

    match advisor.get_summary(
        &user_id,
        query.topology_id.as_deref(),
        query.scan_id.as_deref(),
    ).await {
        Ok(summary) => HttpResponse::Ok().json(summary),
        Err(e) => {
            log::error!("Failed to get summary: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get summary: {}", e)
            }))
        }
    }
}

/// Update recommendation status (accept/reject)
///
/// PUT /api/ai/red-team/recommendations/{id}/status
#[utoipa::path(
    put,
    path = "/api/ai/red-team/recommendations/{id}/status",
    request_body = UpdateRecommendationRequest,
    responses(
        (status = 200, description = "Recommendation updated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Recommendation not found")
    ),
    tag = "AI Red Team Advisor"
)]
pub async fn update_recommendation_status(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateRecommendationRequest>,
) -> HttpResponse {
    let user_id = claims.sub.clone();

    let recommendation_id = path.into_inner();
    let advisor = RedTeamAdvisor::new(pool.get_ref().clone());

    // Validate status
    let valid_statuses = ["pending", "accepted", "rejected", "running", "completed", "failed"];
    if !valid_statuses.contains(&body.status.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid status. Must be one of: {:?}", valid_statuses)
        }));
    }

    match advisor.update_recommendation_status(&recommendation_id, &user_id, &body.status).await {
        Ok(recommendation) => HttpResponse::Ok().json(recommendation),
        Err(e) => {
            log::error!("Failed to update recommendation: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to update recommendation: {}", e)
            }))
        }
    }
}

/// Accept all pending recommendations
///
/// POST /api/ai/red-team/recommendations/accept-all
#[utoipa::path(
    post,
    path = "/api/ai/red-team/recommendations/accept-all",
    params(
        ("topology_id" = Option<String>, Query, description = "Filter by topology ID")
    ),
    responses(
        (status = 200, description = "All recommendations accepted"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "AI Red Team Advisor"
)]
pub async fn accept_all_recommendations(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<TopologyIdQuery>,
) -> HttpResponse {
    let user_id = claims.sub.clone();

    let advisor = RedTeamAdvisor::new(pool.get_ref().clone());

    match advisor.accept_all(&user_id, query.topology_id.as_deref()).await {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "accepted_count": count,
            "message": format!("{} recommendations accepted", count)
        })),
        Err(e) => {
            log::error!("Failed to accept all: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to accept all: {}", e)
            }))
        }
    }
}

/// Reject all pending recommendations
///
/// POST /api/ai/red-team/recommendations/reject-all
#[utoipa::path(
    post,
    path = "/api/ai/red-team/recommendations/reject-all",
    params(
        ("topology_id" = Option<String>, Query, description = "Filter by topology ID")
    ),
    responses(
        (status = 200, description = "All recommendations rejected"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "AI Red Team Advisor"
)]
pub async fn reject_all_recommendations(
    claims: web::ReqData<auth::Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<TopologyIdQuery>,
) -> HttpResponse {
    let user_id = claims.sub.clone();

    let advisor = RedTeamAdvisor::new(pool.get_ref().clone());

    match advisor.reject_all(&user_id, query.topology_id.as_deref()).await {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "rejected_count": count,
            "message": format!("{} recommendations rejected", count)
        })),
        Err(e) => {
            log::error!("Failed to reject all: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to reject all: {}", e)
            }))
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AnalyzeTopologyWithDataRequest {
    pub topology: TopologyRequestData,
    pub topology_id: Option<String>,
    pub scan_id: Option<String>,
    pub engagement_id: Option<String>,
    pub analysis_type: Option<String>,
    pub focus_areas: Option<Vec<String>>,
    pub exclude_node_ids: Option<Vec<String>>,
    pub max_recommendations: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TopologyRequestData {
    pub nodes: Vec<TopologyNodeRequest>,
    pub edges: Vec<TopologyEdgeRequest>,
    pub metadata: Option<TopologyMetadataRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TopologyNodeRequest {
    pub id: String,
    pub label: String,
    pub device_type: String,
    pub security_zone: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub compliance_status: String,
    pub vulnerabilities: Option<i32>,
    pub open_ports: Option<Vec<i32>>,
    pub services: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TopologyEdgeRequest {
    pub source: String,
    pub target: String,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub encrypted: Option<bool>,
    pub data_classification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TopologyMetadataRequest {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub industry: Option<String>,
    pub compliance_frameworks: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GetRecommendationsQuery {
    pub topology_id: Option<String>,
    pub scan_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TopologyIdQuery {
    pub topology_id: Option<String>,
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure AI Red Team Advisor routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/red-team-advisor/analyze", web::post().to(analyze_topology))
        .route("/red-team-advisor/recommendations", web::get().to(get_recommendations))
        .route("/red-team-advisor/summary", web::get().to(get_summary))
        .route("/red-team-advisor/recommendations/{id}/status", web::put().to(update_recommendation_status))
        .route("/red-team-advisor/recommendations/accept-all", web::post().to(accept_all_recommendations))
        .route("/red-team-advisor/recommendations/reject-all", web::post().to(reject_all_recommendations));
}
