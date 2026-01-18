//! Agent API endpoints for distributed scanning
//!
//! This module provides REST API endpoints for managing scan agents:
//! - Agent registration and management
//! - Agent group management
//! - Agent heartbeat and health monitoring
//! - Task distribution and result collection

use actix_web::{delete, get, post, put, web, HttpRequest, HttpResponse, Result};
use actix_web::error::{ErrorForbidden, ErrorInternalServerError, ErrorNotFound, ErrorUnauthorized};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::agents::{
    generate_agent_token, get_token_prefix, AgentManager, AgentTask,
    AgentWithGroups, AssignAgentsToGroupRequest, CreateAgentGroupRequest, HeartbeatRequest,
    RegisterAgentRequest, SubmitResultRequest,
    TaskStatus, UpdateAgentGroupRequest, UpdateAgentRequest,
};
use crate::db;
use crate::web::auth::jwt::Claims;

// ============================================================================
// Agent Management Endpoints
// ============================================================================

/// Register a new scan agent
///
/// POST /api/agents/register
#[post("/agents/register")]
pub async fn register_agent(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<RegisterAgentRequest>,
) -> Result<HttpResponse> {
    let manager = AgentManager::new(pool.get_ref().clone());

    let response = manager
        .register_agent(&claims.sub, body.into_inner())
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Created().json(response))
}

/// List all agents for the current user
///
/// GET /api/agents
#[get("/agents")]
pub async fn list_agents(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse> {
    let agents = db::agents::get_user_agents(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    // Fetch groups for each agent
    let mut agents_with_groups = Vec::new();
    for agent in agents {
        let groups = db::agents::get_agent_groups(pool.get_ref(), &agent.id)
            .await
            .unwrap_or_default();
        agents_with_groups.push(AgentWithGroups { agent, groups });
    }

    Ok(HttpResponse::Ok().json(agents_with_groups))
}

/// Get agent details by ID
///
/// GET /api/agents/{id}
#[get("/agents/{id}")]
pub async fn get_agent(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    // Verify ownership
    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to access this agent"));
    }

    let groups = db::agents::get_agent_groups(pool.get_ref(), &agent_id)
        .await
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(AgentWithGroups { agent, groups }))
}

/// Update an agent
///
/// PUT /api/agents/{id}
#[put("/agents/{id}")]
pub async fn update_agent(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<UpdateAgentRequest>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify ownership
    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this agent"));
    }

    let req = body.into_inner();
    db::agents::update_agent(
        pool.get_ref(),
        &agent_id,
        req.name.as_deref(),
        req.description.as_deref(),
        req.network_zones.as_deref(),
        req.max_concurrent_tasks,
        req.status.as_deref(),
    )
    .await
    .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    // Return updated agent
    let updated = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    let groups = db::agents::get_agent_groups(pool.get_ref(), &agent_id)
        .await
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(AgentWithGroups {
        agent: updated,
        groups,
    }))
}

/// Delete (deregister) an agent
///
/// DELETE /api/agents/{id}
#[delete("/agents/{id}")]
pub async fn delete_agent(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify ownership
    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to delete this agent"));
    }

    db::agents::delete_agent(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

/// Get agent statistics
///
/// GET /api/agents/stats
#[get("/agents/stats")]
pub async fn get_agent_stats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse> {
    let manager = AgentManager::new(pool.get_ref().clone());

    let stats = manager
        .get_stats(&claims.sub)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Regenerate token for an agent (returns new token once)
///
/// POST /api/agents/{id}/regenerate-token
#[post("/agents/{id}/regenerate-token")]
pub async fn regenerate_agent_token(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify ownership
    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this agent"));
    }

    // Generate new token
    let new_token = generate_agent_token();
    let token_prefix = get_token_prefix(&new_token);
    let token_hash = bcrypt::hash(&new_token, crate::db::BCRYPT_COST.clone())
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    // Update agent with new token hash
    sqlx::query(
        "UPDATE scan_agents SET token_hash = ?1, token_prefix = ?2, updated_at = datetime('now') WHERE id = ?3",
    )
    .bind(&token_hash)
    .bind(&token_prefix)
    .bind(&agent_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "token": new_token,
        "token_prefix": token_prefix
    })))
}

// ============================================================================
// Agent Group Endpoints
// ============================================================================

/// Create a new agent group
///
/// POST /api/agents/groups
#[post("/agents/groups")]
pub async fn create_agent_group(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateAgentGroupRequest>,
) -> Result<HttpResponse> {
    let req = body.into_inner();

    let group = db::agents::create_agent_group(
        pool.get_ref(),
        &claims.sub,
        &req.name,
        req.description.as_deref(),
        req.network_ranges.as_deref(),
        &req.color,
    )
    .await
    .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Created().json(group))
}

/// List all agent groups for the current user
///
/// GET /api/agents/groups
#[get("/agents/groups")]
pub async fn list_agent_groups(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse> {
    let groups = db::agents::get_user_agent_groups(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    // Add agent counts
    let mut groups_with_counts = Vec::new();
    for group in groups {
        let count = db::agents::get_group_agent_count(pool.get_ref(), &group.id)
            .await
            .unwrap_or(0);
        groups_with_counts.push(serde_json::json!({
            "id": group.id,
            "user_id": group.user_id,
            "name": group.name,
            "description": group.description,
            "network_ranges": group.network_ranges,
            "color": group.color,
            "created_at": group.created_at,
            "updated_at": group.updated_at,
            "agent_count": count
        }));
    }

    Ok(HttpResponse::Ok().json(groups_with_counts))
}

/// Get agent group details
///
/// GET /api/agents/groups/{id}
#[get("/agents/groups/{id}")]
pub async fn get_agent_group(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let group_id = path.into_inner();

    let group = db::agents::get_agent_group_by_id(pool.get_ref(), &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Group not found"))?;

    // Verify ownership
    if group.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to access this group"));
    }

    // Get agents in group
    let agents = db::agents::get_group_agents(pool.get_ref(), &group_id)
        .await
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": group.id,
        "user_id": group.user_id,
        "name": group.name,
        "description": group.description,
        "network_ranges": group.network_ranges,
        "color": group.color,
        "created_at": group.created_at,
        "updated_at": group.updated_at,
        "agents": agents
    })))
}

/// Update an agent group
///
/// PUT /api/agents/groups/{id}
#[put("/agents/groups/{id}")]
pub async fn update_agent_group(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<UpdateAgentGroupRequest>,
) -> Result<HttpResponse> {
    let group_id = path.into_inner();

    // Verify ownership
    let group = db::agents::get_agent_group_by_id(pool.get_ref(), &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Group not found"))?;

    if group.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this group"));
    }

    let req = body.into_inner();
    db::agents::update_agent_group(
        pool.get_ref(),
        &group_id,
        req.name.as_deref(),
        req.description.as_deref(),
        req.network_ranges.as_deref(),
        req.color.as_deref(),
    )
    .await
    .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    // Return updated group
    let updated = db::agents::get_agent_group_by_id(pool.get_ref(), &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Group not found"))?;

    Ok(HttpResponse::Ok().json(updated))
}

/// Delete an agent group
///
/// DELETE /api/agents/groups/{id}
#[delete("/agents/groups/{id}")]
pub async fn delete_agent_group(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let group_id = path.into_inner();

    // Verify ownership
    let group = db::agents::get_agent_group_by_id(pool.get_ref(), &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Group not found"))?;

    if group.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to delete this group"));
    }

    db::agents::delete_agent_group(pool.get_ref(), &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

/// Assign agents to a group
///
/// PUT /api/agents/groups/{id}/agents
#[put("/agents/groups/{id}/agents")]
pub async fn assign_agents_to_group(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<AssignAgentsToGroupRequest>,
) -> Result<HttpResponse> {
    let group_id = path.into_inner();

    // Verify group ownership
    let group = db::agents::get_agent_group_by_id(pool.get_ref(), &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Group not found"))?;

    if group.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this group"));
    }

    let req = body.into_inner();

    // Verify agent ownership and add to group
    for agent_id in &req.agent_ids {
        let agent = db::agents::get_agent_by_id(pool.get_ref(), agent_id)
            .await
            .map_err(|e| ErrorInternalServerError(e.to_string()))?;

        if let Some(agent) = agent {
            if agent.user_id == claims.sub {
                db::agents::add_agent_to_group(pool.get_ref(), agent_id, &group_id)
                    .await
                    .ok();
            }
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Agents assigned to group"
    })))
}

/// Remove an agent from a group
///
/// DELETE /api/agents/groups/{group_id}/agents/{agent_id}
#[delete("/agents/groups/{group_id}/agents/{agent_id}")]
pub async fn remove_agent_from_group(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (group_id, agent_id) = path.into_inner();

    // Verify group ownership
    let group = db::agents::get_agent_group_by_id(pool.get_ref(), &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Group not found"))?;

    if group.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this group"));
    }

    db::agents::remove_agent_from_group(pool.get_ref(), &agent_id, &group_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Agent Communication Endpoints (used by agents themselves)
// ============================================================================

/// Agent heartbeat endpoint
///
/// POST /api/agents/{id}/heartbeat
/// Note: This endpoint uses agent token auth, not user JWT
#[post("/agents/{id}/heartbeat")]
pub async fn agent_heartbeat(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<HeartbeatRequest>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify agent token
    let token = extract_agent_token(&req)?;
    let manager = AgentManager::new(pool.get_ref().clone());

    let agent = manager
        .verify_agent_token(&token)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorUnauthorized("Invalid agent token"))?;

    if agent.id != agent_id {
        return Err(ErrorForbidden("Token does not match agent"));
    }

    // Update IP address from request
    if let Some(ip) = req.peer_addr() {
        sqlx::query("UPDATE scan_agents SET ip_address = ?1, updated_at = datetime('now') WHERE id = ?2")
            .bind(ip.ip().to_string())
            .bind(&agent_id)
            .execute(pool.get_ref())
            .await
            .ok();
    }

    // Process heartbeat
    let response = manager
        .process_heartbeat(&agent_id, body.into_inner())
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(response))
}

/// Get pending tasks for an agent
///
/// GET /api/agents/{id}/tasks
/// Note: This endpoint uses agent token auth, not user JWT
#[get("/agents/{id}/tasks")]
pub async fn get_agent_tasks(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    query: web::Query<GetTasksQuery>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify agent token
    let token = extract_agent_token(&req)?;
    let manager = AgentManager::new(pool.get_ref().clone());

    let agent = manager
        .verify_agent_token(&token)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorUnauthorized("Invalid agent token"))?;

    if agent.id != agent_id {
        return Err(ErrorForbidden("Token does not match agent"));
    }

    let max_tasks = query.max_tasks.unwrap_or(5);
    let tasks = manager
        .task_distributor()
        .get_tasks_for_agent(&agent_id, max_tasks)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(tasks))
}

#[derive(Debug, Deserialize)]
pub struct GetTasksQuery {
    max_tasks: Option<i32>,
}

/// Submit task results from an agent
///
/// POST /api/agents/{id}/results
/// Note: This endpoint uses agent token auth, not user JWT
#[post("/agents/{id}/results")]
pub async fn submit_agent_results(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<SubmitResultRequest>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify agent token
    let token = extract_agent_token(&req)?;
    let manager = AgentManager::new(pool.get_ref().clone());

    let agent = manager
        .verify_agent_token(&token)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorUnauthorized("Invalid agent token"))?;

    if agent.id != agent_id {
        return Err(ErrorForbidden("Token does not match agent"));
    }

    let req_body = body.into_inner();

    // Update task status
    let status = TaskStatus::from_str(&req_body.status)
        .unwrap_or(TaskStatus::Completed);

    manager
        .task_distributor()
        .complete_task(&req_body.task_id, status, req_body.error_message.clone())
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    // Store result if provided
    if let Some(result_data) = &req_body.result_data {
        manager
            .result_collector()
            .store_result(
                &req_body.task_id,
                &agent_id,
                result_data,
                req_body.hosts_discovered.unwrap_or(0),
                req_body.ports_found.unwrap_or(0),
                req_body.vulnerabilities_found.unwrap_or(0),
            )
            .await
            .map_err(|e| ErrorInternalServerError(e.to_string()))?;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Results submitted successfully"
    })))
}

/// Mark a task as started
///
/// POST /api/agents/{agent_id}/tasks/{task_id}/start
#[post("/agents/{agent_id}/tasks/{task_id}/start")]
pub async fn start_agent_task(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (agent_id, task_id) = path.into_inner();

    // Verify agent token
    let token = extract_agent_token(&req)?;
    let manager = AgentManager::new(pool.get_ref().clone());

    let agent = manager
        .verify_agent_token(&token)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorUnauthorized("Invalid agent token"))?;

    if agent.id != agent_id {
        return Err(ErrorForbidden("Token does not match agent"));
    }

    manager
        .task_distributor()
        .start_task(&task_id, &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Task started"
    })))
}

/// Get agent heartbeat history
///
/// GET /api/agents/{id}/heartbeats
#[get("/agents/{id}/heartbeats")]
pub async fn get_agent_heartbeats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    query: web::Query<HeartbeatHistoryQuery>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify ownership
    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to access this agent"));
    }

    let limit = query.limit.unwrap_or(100);
    let heartbeats = db::agents::get_agent_heartbeats(pool.get_ref(), &agent_id, limit)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(heartbeats))
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatHistoryQuery {
    limit: Option<i32>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract agent token from request headers
fn extract_agent_token(req: &HttpRequest) -> Result<String> {
    // Check X-Agent-Token header first
    if let Some(token) = req.headers().get("X-Agent-Token") {
        return token
            .to_str()
            .map(String::from)
            .map_err(|_| ErrorUnauthorized("Invalid token header"));
    }

    // Fall back to Authorization: Bearer <token>
    if let Some(auth) = req.headers().get("Authorization") {
        let auth_str = auth
            .to_str()
            .map_err(|_| ErrorUnauthorized("Invalid auth header"))?;

        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            return Ok(token.to_string());
        }
    }

    Err(ErrorUnauthorized("Missing agent token"))
}

// ============================================================================
// Route Configuration
// ============================================================================

// ============================================================================
// Mesh Network Endpoints
// ============================================================================

/// Get mesh peer status for all user agents
///
/// GET /api/agents/mesh/peers
#[get("/agents/mesh/peers")]
pub async fn get_mesh_peers(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse> {
    // Get all agents for the user that have mesh enabled
    let agents = db::agents::get_user_agents(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    let mut peer_data = Vec::new();
    for agent in agents {
        // Get mesh config for this agent
        if let Ok(Some(mesh_config)) = db::agent_mesh::get_mesh_config(pool.get_ref(), &agent.id).await {
            if mesh_config.enabled {
                // Get peer connections for this agent
                let peers = db::agent_mesh::get_agent_peer_connections(pool.get_ref(), &agent.id)
                    .await
                    .unwrap_or_default();

                // Get connection stats
                let stats = db::agent_mesh::get_peer_connection_stats(pool.get_ref(), &agent.id)
                    .await
                    .ok();

                peer_data.push(serde_json::json!({
                    "agent_id": agent.id,
                    "agent_name": agent.name,
                    "mesh_config": mesh_config,
                    "peers": peers,
                    "stats": stats
                }));
            }
        }
    }

    Ok(HttpResponse::Ok().json(peer_data))
}

/// Get all clusters for the user
///
/// GET /api/agents/mesh/clusters
#[get("/agents/mesh/clusters")]
pub async fn get_mesh_clusters(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse> {
    let clusters = db::agent_mesh::get_user_clusters(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    let mut cluster_data = Vec::new();
    for cluster in clusters {
        let member_count = db::agent_mesh::get_cluster_member_count(pool.get_ref(), &cluster.id)
            .await
            .unwrap_or(0);

        let members = db::agent_mesh::get_cluster_agents(pool.get_ref(), &cluster.id)
            .await
            .unwrap_or_default();

        cluster_data.push(serde_json::json!({
            "id": cluster.id,
            "name": cluster.name,
            "description": cluster.description,
            "leader_agent_id": cluster.leader_agent_id,
            "config_json": cluster.config_json,
            "health_json": cluster.health_json,
            "member_count": member_count,
            "members": members,
            "created_at": cluster.created_at,
            "updated_at": cluster.updated_at
        }));
    }

    Ok(HttpResponse::Ok().json(cluster_data))
}

/// Create a new cluster
///
/// POST /api/agents/mesh/clusters
#[post("/agents/mesh/clusters")]
pub async fn create_mesh_cluster(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateClusterRequest>,
) -> Result<HttpResponse> {
    let req = body.into_inner();

    let cluster = db::agent_mesh::create_cluster(
        pool.get_ref(),
        &claims.sub,
        &req.name,
        req.description.as_deref(),
        None,
        req.config_json.as_deref(),
    )
    .await
    .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Created().json(cluster))
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateClusterRequest {
    pub name: String,
    pub description: Option<String>,
    pub config_json: Option<String>,
}

/// Get a specific cluster
///
/// GET /api/agents/mesh/clusters/{id}
#[get("/agents/mesh/clusters/{id}")]
pub async fn get_mesh_cluster(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let cluster_id = path.into_inner();

    let cluster = db::agent_mesh::get_cluster_by_id(pool.get_ref(), &cluster_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Cluster not found"))?;

    // Verify ownership
    if cluster.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to access this cluster"));
    }

    let members = db::agent_mesh::get_cluster_agents(pool.get_ref(), &cluster_id)
        .await
        .unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": cluster.id,
        "name": cluster.name,
        "description": cluster.description,
        "leader_agent_id": cluster.leader_agent_id,
        "config_json": cluster.config_json,
        "health_json": cluster.health_json,
        "members": members,
        "created_at": cluster.created_at,
        "updated_at": cluster.updated_at
    })))
}

/// Update a cluster
///
/// PUT /api/agents/mesh/clusters/{id}
#[put("/agents/mesh/clusters/{id}")]
pub async fn update_mesh_cluster(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<UpdateClusterRequest>,
) -> Result<HttpResponse> {
    let cluster_id = path.into_inner();

    // Verify ownership
    let cluster = db::agent_mesh::get_cluster_by_id(pool.get_ref(), &cluster_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Cluster not found"))?;

    if cluster.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this cluster"));
    }

    let req = body.into_inner();
    db::agent_mesh::update_cluster(
        pool.get_ref(),
        &cluster_id,
        req.name.as_deref(),
        req.description.as_deref(),
        None,
        req.config_json.as_deref(),
        req.health_json.as_deref(),
    )
    .await
    .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    // Return updated cluster
    let updated = db::agent_mesh::get_cluster_by_id(pool.get_ref(), &cluster_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Cluster not found"))?;

    Ok(HttpResponse::Ok().json(updated))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateClusterRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config_json: Option<String>,
    pub health_json: Option<String>,
}

/// Delete a cluster
///
/// DELETE /api/agents/mesh/clusters/{id}
#[delete("/agents/mesh/clusters/{id}")]
pub async fn delete_mesh_cluster(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let cluster_id = path.into_inner();

    // Verify ownership
    let cluster = db::agent_mesh::get_cluster_by_id(pool.get_ref(), &cluster_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Cluster not found"))?;

    if cluster.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to delete this cluster"));
    }

    db::agent_mesh::delete_cluster(pool.get_ref(), &cluster_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

/// Add agent to cluster
///
/// POST /api/agents/mesh/clusters/{id}/agents/{agent_id}
#[post("/agents/mesh/clusters/{id}/agents/{agent_id}")]
pub async fn add_agent_to_cluster(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (cluster_id, agent_id) = path.into_inner();

    // Verify cluster ownership
    let cluster = db::agent_mesh::get_cluster_by_id(pool.get_ref(), &cluster_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Cluster not found"))?;

    if cluster.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this cluster"));
    }

    // Verify agent ownership
    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to add this agent"));
    }

    // Check if agent has mesh config, create one if not
    if db::agent_mesh::get_mesh_config(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .is_none()
    {
        db::agent_mesh::create_mesh_config(
            pool.get_ref(),
            &agent_id,
            true,
            9876,
            None,
            Some(&cluster_id),
            Some("member"),
            None,
        )
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;
    } else {
        db::agent_mesh::add_agent_to_cluster(pool.get_ref(), &agent_id, &cluster_id)
            .await
            .map_err(|e| ErrorInternalServerError(e.to_string()))?;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Agent added to cluster"
    })))
}

/// Remove agent from cluster
///
/// DELETE /api/agents/mesh/clusters/{id}/agents/{agent_id}
#[delete("/agents/mesh/clusters/{id}/agents/{agent_id}")]
pub async fn remove_agent_from_cluster(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse> {
    let (cluster_id, agent_id) = path.into_inner();

    // Verify cluster ownership
    let cluster = db::agent_mesh::get_cluster_by_id(pool.get_ref(), &cluster_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Cluster not found"))?;

    if cluster.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this cluster"));
    }

    db::agent_mesh::remove_agent_from_cluster(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

/// Get all tasks for the current user
///
/// GET /api/agents/tasks
#[get("/agents/tasks")]
pub async fn list_all_agent_tasks(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<TasksListQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(100);
    let status = query.status.as_deref();

    // Get tasks for all user's agents
    let tasks: Vec<AgentTask> = if let Some(status_filter) = status {
        sqlx::query_as::<_, AgentTask>(
            r#"
            SELECT t.* FROM agent_tasks t
            INNER JOIN scan_agents a ON t.agent_id = a.id OR t.user_id = a.user_id
            WHERE a.user_id = ?1 AND t.status = ?2
            ORDER BY t.created_at DESC
            LIMIT ?3
            "#,
        )
        .bind(&claims.sub)
        .bind(status_filter)
        .bind(limit)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
    } else {
        sqlx::query_as::<_, AgentTask>(
            r#"
            SELECT t.* FROM agent_tasks t
            WHERE t.user_id = ?1
            ORDER BY t.created_at DESC
            LIMIT ?2
            "#,
        )
        .bind(&claims.sub)
        .bind(limit)
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
    };

    Ok(HttpResponse::Ok().json(tasks))
}

#[derive(Debug, Deserialize)]
pub struct TasksListQuery {
    limit: Option<i32>,
    status: Option<String>,
}

/// Get mesh config for an agent
///
/// GET /api/agents/{id}/mesh
#[get("/agents/{id}/mesh")]
pub async fn get_agent_mesh_config(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify ownership
    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to access this agent"));
    }

    let mesh_config = db::agent_mesh::get_mesh_config(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(mesh_config))
}

/// Update mesh config for an agent
///
/// PUT /api/agents/{id}/mesh
#[put("/agents/{id}/mesh")]
pub async fn update_agent_mesh_config(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    body: web::Json<UpdateMeshConfigRequest>,
) -> Result<HttpResponse> {
    let agent_id = path.into_inner();

    // Verify ownership
    let agent = db::agents::get_agent_by_id(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .ok_or_else(|| ErrorNotFound("Agent not found"))?;

    if agent.user_id != claims.sub {
        return Err(ErrorForbidden("Not authorized to modify this agent"));
    }

    let req = body.into_inner();

    // Check if config exists
    if db::agent_mesh::get_mesh_config(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?
        .is_some()
    {
        // Update existing
        db::agent_mesh::update_mesh_config(
            pool.get_ref(),
            &agent_id,
            req.enabled,
            req.mesh_port,
            req.external_address.as_deref(),
            req.cluster_id.as_deref(),
            req.cluster_role.as_deref(),
            req.config_json.as_deref(),
        )
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;
    } else {
        // Create new
        db::agent_mesh::create_mesh_config(
            pool.get_ref(),
            &agent_id,
            req.enabled.unwrap_or(false),
            req.mesh_port.unwrap_or(9876),
            req.external_address.as_deref(),
            req.cluster_id.as_deref(),
            req.cluster_role.as_deref(),
            req.config_json.as_deref(),
        )
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;
    }

    let updated = db::agent_mesh::get_mesh_config(pool.get_ref(), &agent_id)
        .await
        .map_err(|e| ErrorInternalServerError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(updated))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateMeshConfigRequest {
    pub enabled: Option<bool>,
    pub mesh_port: Option<i32>,
    pub external_address: Option<String>,
    pub cluster_id: Option<String>,
    pub cluster_role: Option<String>,
    pub config_json: Option<String>,
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure agent routes
/// NOTE: Route registration order matters! More specific routes must come before wildcards.
/// e.g., /agents/groups must be registered before /agents/{id}
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(register_agent)
        .service(list_agents)
        // Static paths BEFORE wildcard /agents/{id}
        .service(get_agent_stats)
        .service(list_agent_groups)
        .service(create_agent_group)
        .service(list_all_agent_tasks)
        // Mesh endpoints (static paths)
        .service(get_mesh_peers)
        .service(get_mesh_clusters)
        .service(create_mesh_cluster)
        // Wildcard routes AFTER static paths
        .service(get_agent)
        .service(update_agent)
        .service(delete_agent)
        .service(regenerate_agent_token)
        .service(get_agent_group)
        .service(update_agent_group)
        .service(delete_agent_group)
        .service(assign_agents_to_group)
        .service(remove_agent_from_group)
        .service(agent_heartbeat)
        .service(get_agent_tasks)
        .service(submit_agent_results)
        .service(start_agent_task)
        .service(get_agent_heartbeats)
        .service(get_mesh_cluster)
        .service(update_mesh_cluster)
        .service(delete_mesh_cluster)
        .service(add_agent_to_cluster)
        .service(remove_agent_from_cluster)
        .service(get_agent_mesh_config)
        .service(update_agent_mesh_config);
}
