//! Workflow API endpoints
//!
//! Provides REST API for managing remediation workflows:
//! - Template management (CRUD)
//! - Workflow instances (start, approve, reject)
//! - Pending approvals
//! - Workflow statistics

use actix_web::{web, HttpResponse, HttpRequest};
use sqlx::SqlitePool;

use crate::db;
use crate::db::workflows;
use crate::web::auth::jwt::Claims;
use crate::workflows::{
    WorkflowExecutor,
    CreateWorkflowTemplateRequest,
    UpdateWorkflowTemplateRequest,
    StartWorkflowRequest,
    ApproveWorkflowRequest,
    RejectWorkflowRequest,
    UpdateWorkflowRequest,
};

// ============================================================================
// Template Endpoints
// ============================================================================

/// List all workflow templates
#[utoipa::path(
    get,
    path = "/api/workflows/templates",
    tag = "Workflows",
    responses(
        (status = 200, description = "List of workflow templates"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_templates(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    match workflows::get_all_templates(pool.get_ref()).await {
        Ok(templates) => HttpResponse::Ok().json(templates),
        Err(e) => {
            log::error!("Failed to list workflow templates: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list workflow templates"
            }))
        }
    }
}

/// Get a workflow template with stages
#[utoipa::path(
    get,
    path = "/api/workflows/templates/{id}",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Workflow template with stages"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_template(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let template_id = path.into_inner();

    match workflows::get_template_with_stages(pool.get_ref(), &template_id).await {
        Ok(template) => HttpResponse::Ok().json(template),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Template not found"
                }))
            } else {
                log::error!("Failed to get workflow template: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get workflow template"
                }))
            }
        }
    }
}

/// Create a new workflow template
#[utoipa::path(
    post,
    path = "/api/workflows/templates",
    tag = "Workflows",
    request_body = CreateWorkflowTemplateRequest,
    responses(
        (status = 201, description = "Workflow template created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    request: web::Json<CreateWorkflowTemplateRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let request = request.into_inner();

    // Validate request
    if request.name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Template name is required"
        }));
    }

    if request.stages.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one stage is required"
        }));
    }

    match workflows::create_user_template(pool.get_ref(), &claims.sub, request).await {
        Ok(template) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_template_created",
                Some("workflow_template"),
                Some(&template.id),
                Some(&format!("Created workflow template: {}", template.name)),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Created().json(template)
        }
        Err(e) => {
            log::error!("Failed to create workflow template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create workflow template"
            }))
        }
    }
}

/// Update a workflow template
#[utoipa::path(
    put,
    path = "/api/workflows/templates/{id}",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    request_body = UpdateWorkflowTemplateRequest,
    responses(
        (status = 200, description = "Workflow template updated"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot modify system templates"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<UpdateWorkflowTemplateRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let template_id = path.into_inner();

    // Check if template exists and is not a system template
    match workflows::get_template(pool.get_ref(), &template_id).await {
        Ok(template) => {
            if template.is_system {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot modify system templates"
                }));
            }

            // Check ownership
            if template.created_by.as_ref() != Some(&claims.sub) {
                // Check if admin
                let roles = db::get_user_roles(pool.get_ref(), &claims.sub).await.unwrap_or_default();
                if !roles.iter().any(|r| r.name == "admin") {
                    return HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "You can only modify your own templates"
                    }));
                }
            }
        }
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Template not found"
            }));
        }
    }

    match workflows::update_template(pool.get_ref(), &template_id, request.into_inner()).await {
        Ok(template) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_template_updated",
                Some("workflow_template"),
                Some(&template_id),
                Some(&format!("Updated workflow template: {}", template.name)),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Ok().json(template)
        }
        Err(e) => {
            log::error!("Failed to update workflow template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update workflow template"
            }))
        }
    }
}

/// Delete a workflow template
#[utoipa::path(
    delete,
    path = "/api/workflows/templates/{id}",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Template ID")
    ),
    responses(
        (status = 204, description = "Workflow template deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot delete system templates"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_template(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let template_id = path.into_inner();

    // Check if template exists and is not a system template
    match workflows::get_template(pool.get_ref(), &template_id).await {
        Ok(template) => {
            if template.is_system {
                return HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Cannot delete system templates"
                }));
            }

            // Check ownership
            if template.created_by.as_ref() != Some(&claims.sub) {
                let roles = db::get_user_roles(pool.get_ref(), &claims.sub).await.unwrap_or_default();
                if !roles.iter().any(|r| r.name == "admin") {
                    return HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "You can only delete your own templates"
                    }));
                }
            }
        }
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "Template not found"
            }));
        }
    }

    match workflows::delete_template(pool.get_ref(), &template_id).await {
        Ok(()) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_template_deleted",
                Some("workflow_template"),
                Some(&template_id),
                Some("Deleted workflow template"),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::NoContent().finish()
        }
        Err(e) => {
            log::error!("Failed to delete workflow template: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete workflow template"
            }))
        }
    }
}

// ============================================================================
// Workflow Instance Endpoints
// ============================================================================

/// Start a workflow for a vulnerability
#[utoipa::path(
    post,
    path = "/api/vulnerabilities/{id}/workflow",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Vulnerability tracking ID")
    ),
    request_body = StartWorkflowRequest,
    responses(
        (status = 201, description = "Workflow started"),
        (status = 400, description = "Invalid request or workflow already exists"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Vulnerability not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn start_workflow(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<StartWorkflowRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let vulnerability_id = path.into_inner();
    let request = request.into_inner();

    // Verify vulnerability exists
    if db::get_vulnerability_detail(pool.get_ref(), &vulnerability_id).await.is_err() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Vulnerability not found"
        }));
    }

    let executor = WorkflowExecutor::new(pool.get_ref().clone());

    match executor.start_workflow(
        &vulnerability_id,
        &request.template_id,
        &claims.sub,
        request.notes,
    ).await {
        Ok(instance) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_started",
                Some("workflow_instance"),
                Some(&instance.id),
                Some(&format!("Started workflow for vulnerability {}", vulnerability_id)),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Created().json(instance)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("already has an active workflow") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_str
                }))
            } else {
                log::error!("Failed to start workflow: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to start workflow"
                }))
            }
        }
    }
}

/// List workflow instances
#[utoipa::path(
    get,
    path = "/api/workflows/instances",
    tag = "Workflows",
    params(
        ("status" = Option<String>, Query, description = "Filter by status (active, completed, cancelled, on_hold, rejected)"),
        ("vulnerability_id" = Option<String>, Query, description = "Filter by vulnerability ID")
    ),
    responses(
        (status = 200, description = "List of workflow instances"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_instances(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    query: web::Query<InstanceListQuery>,
) -> HttpResponse {
    let instances = if let Some(vuln_id) = &query.vulnerability_id {
        workflows::get_workflows_for_vulnerability(pool.get_ref(), vuln_id).await
    } else if let Some(status) = &query.status {
        workflows::get_workflows_by_status(pool.get_ref(), status).await
    } else {
        workflows::get_active_workflows(pool.get_ref()).await
    };

    match instances {
        Ok(instances) => HttpResponse::Ok().json(instances),
        Err(e) => {
            log::error!("Failed to list workflow instances: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list workflow instances"
            }))
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct InstanceListQuery {
    pub status: Option<String>,
    pub vulnerability_id: Option<String>,
}

/// Get workflow instance details
#[utoipa::path(
    get,
    path = "/api/workflows/instances/{id}",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Workflow instance ID")
    ),
    responses(
        (status = 200, description = "Workflow instance details"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_instance(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
    path: web::Path<String>,
) -> HttpResponse {
    let instance_id = path.into_inner();

    match workflows::get_workflow_instance_detail(pool.get_ref(), &instance_id).await {
        Ok(detail) => HttpResponse::Ok().json(detail),
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Workflow instance not found"
                }))
            } else {
                log::error!("Failed to get workflow instance: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to get workflow instance"
                }))
            }
        }
    }
}

/// Approve the current stage of a workflow
#[utoipa::path(
    post,
    path = "/api/workflows/instances/{id}/approve",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Workflow instance ID")
    ),
    request_body = ApproveWorkflowRequest,
    responses(
        (status = 200, description = "Stage approved"),
        (status = 400, description = "Cannot approve (already approved, not active, etc)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "User does not have permission to approve"),
        (status = 404, description = "Instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_stage(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<ApproveWorkflowRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let instance_id = path.into_inner();
    let request = request.into_inner();

    let executor = WorkflowExecutor::new(pool.get_ref().clone());

    match executor.approve_stage(&instance_id, &claims.sub, request.comment).await {
        Ok(instance) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_stage_approved",
                Some("workflow_instance"),
                Some(&instance_id),
                Some("Approved workflow stage"),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Ok().json(instance)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("permission") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("already") || error_str.contains("not active") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Workflow instance not found"
                }))
            } else {
                log::error!("Failed to approve workflow stage: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to approve workflow stage"
                }))
            }
        }
    }
}

/// Advance the current stage of a workflow (for stages with 0 required approvals)
#[utoipa::path(
    post,
    path = "/api/workflows/instances/{id}/advance",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Workflow instance ID")
    ),
    request_body = ApproveWorkflowRequest,
    responses(
        (status = 200, description = "Stage advanced"),
        (status = 400, description = "Cannot advance (stage requires approvals)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn advance_stage(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<ApproveWorkflowRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let instance_id = path.into_inner();
    let request = request.into_inner();

    let executor = WorkflowExecutor::new(pool.get_ref().clone());

    match executor.advance_stage(&instance_id, &claims.sub, request.comment).await {
        Ok(instance) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_stage_advanced",
                Some("workflow_instance"),
                Some(&instance_id),
                Some("Advanced workflow stage"),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Ok().json(instance)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("requires") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Workflow instance not found"
                }))
            } else {
                log::error!("Failed to advance workflow stage: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to advance workflow stage"
                }))
            }
        }
    }
}

/// Reject the current stage of a workflow
#[utoipa::path(
    post,
    path = "/api/workflows/instances/{id}/reject",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Workflow instance ID")
    ),
    request_body = RejectWorkflowRequest,
    responses(
        (status = 200, description = "Stage rejected"),
        (status = 400, description = "Cannot reject (not active, etc)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "User does not have permission to reject"),
        (status = 404, description = "Instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_stage(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<RejectWorkflowRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let instance_id = path.into_inner();
    let request = request.into_inner();

    let executor = WorkflowExecutor::new(pool.get_ref().clone());

    match executor.reject_stage(
        &instance_id,
        &claims.sub,
        request.comment,
        request.restart_from_stage,
    ).await {
        Ok(instance) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_stage_rejected",
                Some("workflow_instance"),
                Some(&instance_id),
                Some("Rejected workflow stage"),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Ok().json(instance)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("permission") {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("not active") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Workflow instance not found"
                }))
            } else {
                log::error!("Failed to reject workflow stage: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to reject workflow stage"
                }))
            }
        }
    }
}

/// Cancel a workflow
#[utoipa::path(
    post,
    path = "/api/workflows/instances/{id}/cancel",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Workflow instance ID")
    ),
    request_body = UpdateWorkflowRequest,
    responses(
        (status = 200, description = "Workflow cancelled"),
        (status = 400, description = "Cannot cancel (not active)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cancel_workflow(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<UpdateWorkflowRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let instance_id = path.into_inner();
    let request = request.into_inner();

    let executor = WorkflowExecutor::new(pool.get_ref().clone());

    match executor.cancel_workflow(&instance_id, &claims.sub, request.notes).await {
        Ok(instance) => {
            // Create audit log
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_cancelled",
                Some("workflow_instance"),
                Some(&instance_id),
                Some("Cancelled workflow"),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Ok().json(instance)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("not active") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Workflow instance not found"
                }))
            } else {
                log::error!("Failed to cancel workflow: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to cancel workflow"
                }))
            }
        }
    }
}

/// Put a workflow on hold
#[utoipa::path(
    post,
    path = "/api/workflows/instances/{id}/hold",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Workflow instance ID")
    ),
    request_body = UpdateWorkflowRequest,
    responses(
        (status = 200, description = "Workflow put on hold"),
        (status = 400, description = "Cannot hold (not active)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn hold_workflow(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    request: web::Json<UpdateWorkflowRequest>,
    req: HttpRequest,
) -> HttpResponse {
    let instance_id = path.into_inner();
    let request = request.into_inner();

    let executor = WorkflowExecutor::new(pool.get_ref().clone());

    match executor.hold_workflow(&instance_id, &claims.sub, request.notes).await {
        Ok(instance) => {
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_held",
                Some("workflow_instance"),
                Some(&instance_id),
                Some("Put workflow on hold"),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Ok().json(instance)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("not active") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Workflow instance not found"
                }))
            } else {
                log::error!("Failed to hold workflow: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to hold workflow"
                }))
            }
        }
    }
}

/// Resume a workflow from hold
#[utoipa::path(
    post,
    path = "/api/workflows/instances/{id}/resume",
    tag = "Workflows",
    params(
        ("id" = String, Path, description = "Workflow instance ID")
    ),
    responses(
        (status = 200, description = "Workflow resumed"),
        (status = 400, description = "Cannot resume (not on hold)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Instance not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn resume_workflow(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
    req: HttpRequest,
) -> HttpResponse {
    let instance_id = path.into_inner();

    let executor = WorkflowExecutor::new(pool.get_ref().clone());

    match executor.resume_workflow(&instance_id, &claims.sub).await {
        Ok(instance) => {
            let ip = req.connection_info().peer_addr().map(|s| s.to_string());
            let _ = db::log_audit_full(
                pool.get_ref(),
                &claims.sub,
                "workflow_resumed",
                Some("workflow_instance"),
                Some(&instance_id),
                Some("Resumed workflow from hold"),
                ip.as_deref(),
                req.headers()
                    .get("user-agent")
                    .and_then(|h| h.to_str().ok()),
            )
            .await;

            HttpResponse::Ok().json(instance)
        }
        Err(e) => {
            let error_str = e.to_string();
            if error_str.contains("not on hold") {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": error_str
                }))
            } else if error_str.contains("no rows") {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Workflow instance not found"
                }))
            } else {
                log::error!("Failed to resume workflow: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to resume workflow"
                }))
            }
        }
    }
}

// ============================================================================
// Pending Approvals and Statistics
// ============================================================================

/// Get pending approvals for the current user
#[utoipa::path(
    get,
    path = "/api/workflows/pending",
    tag = "Workflows",
    responses(
        (status = 200, description = "List of pending approvals"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_pending_approvals(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> HttpResponse {
    match workflows::get_pending_approvals_for_user(pool.get_ref(), &claims.sub).await {
        Ok(pending) => HttpResponse::Ok().json(pending),
        Err(e) => {
            log::error!("Failed to get pending approvals: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get pending approvals"
            }))
        }
    }
}

/// Get workflow statistics
#[utoipa::path(
    get,
    path = "/api/workflows/stats",
    tag = "Workflows",
    responses(
        (status = 200, description = "Workflow statistics"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    _claims: Claims,
) -> HttpResponse {
    match workflows::get_workflow_stats(pool.get_ref()).await {
        Ok(stats) => HttpResponse::Ok().json(stats),
        Err(e) => {
            log::error!("Failed to get workflow stats: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get workflow statistics"
            }))
        }
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

/// Configure workflow routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/workflows")
            // Template routes
            .route("/templates", web::get().to(list_templates))
            .route("/templates", web::post().to(create_template))
            .route("/templates/{id}", web::get().to(get_template))
            .route("/templates/{id}", web::put().to(update_template))
            .route("/templates/{id}", web::delete().to(delete_template))
            // Instance routes
            .route("/instances", web::get().to(list_instances))
            .route("/instances/{id}", web::get().to(get_instance))
            .route("/instances/{id}/approve", web::post().to(approve_stage))
            .route("/instances/{id}/advance", web::post().to(advance_stage))
            .route("/instances/{id}/reject", web::post().to(reject_stage))
            .route("/instances/{id}/cancel", web::post().to(cancel_workflow))
            .route("/instances/{id}/hold", web::post().to(hold_workflow))
            .route("/instances/{id}/resume", web::post().to(resume_workflow))
            // Pending and stats
            .route("/pending", web::get().to(get_pending_approvals))
            .route("/stats", web::get().to(get_stats))
    );
}
