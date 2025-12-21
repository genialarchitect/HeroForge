//! Agent API endpoints for distributed scanning
//!
//! This module provides REST API endpoints for managing scan agents:
//! - Agent registration and management
//! - Agent group management
//! - Agent heartbeat and health monitoring
//! - Task distribution and result collection

use actix_web::{delete, get, post, put, web, HttpRequest, HttpResponse, Result};
use actix_web::error::{ErrorBadRequest, ErrorForbidden, ErrorInternalServerError, ErrorNotFound, ErrorUnauthorized};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::agents::{
    generate_agent_token, get_token_prefix, AgentManager,
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

/// Configure agent routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(register_agent)
        .service(list_agents)
        .service(get_agent_stats)
        .service(get_agent)
        .service(update_agent)
        .service(delete_agent)
        .service(regenerate_agent_token)
        .service(create_agent_group)
        .service(list_agent_groups)
        .service(get_agent_group)
        .service(update_agent_group)
        .service(delete_agent_group)
        .service(assign_agents_to_group)
        .service(remove_agent_from_group)
        .service(agent_heartbeat)
        .service(get_agent_tasks)
        .service(submit_agent_results)
        .service(start_agent_task)
        .service(get_agent_heartbeats);
}
