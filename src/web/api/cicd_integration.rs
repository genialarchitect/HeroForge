//! CI/CD Pipeline Integration API Endpoints
//!
//! Provides endpoints for managing CI/CD pipeline integrations, quality gates,
//! and workflow templates.

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::devsecops::cicd::{
    CiCdPipeline, CiCdPipelineRun, CiCdPolicy, CiCdWorkflowTemplate, CreatePipelineRequest,
    CreatePolicyRequest, GenerateTemplateRequest, PolicyActions, PolicyConditions,
    PolicyEvaluator, QualityGateDetails, TemplateGenerator, UpdatePipelineRequest,
    UpdatePolicyRequest,
};
use crate::web::auth::{jwt, Claims};
use crate::web::error::ApiError;

/// Configure CI/CD integration API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/cicd")
            // Pipelines
            .route("/pipelines", web::get().to(list_pipelines))
            .route("/pipelines", web::post().to(create_pipeline))
            .route("/pipelines/{id}", web::get().to(get_pipeline))
            .route("/pipelines/{id}", web::put().to(update_pipeline))
            .route("/pipelines/{id}", web::delete().to(delete_pipeline))
            // Pipeline Runs
            .route("/runs", web::get().to(list_runs))
            .route("/runs/{id}", web::get().to(get_run))
            .route("/runs/{id}/gate-status", web::get().to(get_gate_status))
            // Webhooks
            .route("/webhook/{platform}", web::post().to(handle_webhook))
            // Policies
            .route("/policies", web::get().to(list_policies))
            .route("/policies", web::post().to(create_policy))
            .route("/policies/{id}", web::get().to(get_policy))
            .route("/policies/{id}", web::put().to(update_policy))
            .route("/policies/{id}", web::delete().to(delete_policy))
            // Templates
            .route("/templates", web::get().to(list_templates))
            .route("/templates/platforms", web::get().to(list_platforms))
            .route("/templates/{platform}", web::get().to(get_template))
            .route("/templates/generate", web::post().to(generate_template)),
    );
}

// ============================================================================
// Pipeline Endpoints
// ============================================================================

/// List all pipelines for the current user
#[utoipa::path(
    get,
    path = "/api/cicd/pipelines",
    responses(
        (status = 200, description = "List of pipelines", body = Vec<CiCdPipeline>),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn list_pipelines(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let pipelines: Vec<CiCdPipeline> = sqlx::query_as(
        "SELECT * FROM cicd_pipelines WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch pipelines: {}", e)))?;

    Ok(HttpResponse::Ok().json(pipelines))
}

/// Create a new pipeline
#[utoipa::path(
    post,
    path = "/api/cicd/pipelines",
    request_body = CreatePipelineRequest,
    responses(
        (status = 201, description = "Pipeline created", body = CiCdPipeline),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn create_pipeline(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreatePipelineRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let webhook_secret = Uuid::new_v4().to_string();

    // Validate platform
    let platform = body.platform.to_lowercase();
    if !["github_actions", "gitlab_ci", "jenkins", "azure_devops"].contains(&platform.as_str()) {
        return Err(ApiError::bad_request(
            "Invalid platform. Must be: github_actions, gitlab_ci, jenkins, or azure_devops",
        ));
    }

    let config_json = body
        .config
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO cicd_pipelines (
            id, user_id, name, platform, repository_url, webhook_secret, enabled,
            config, customer_id, engagement_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.name)
    .bind(&platform)
    .bind(&body.repository_url)
    .bind(&webhook_secret)
    .bind(&config_json)
    .bind(&body.customer_id)
    .bind(&body.engagement_id)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create pipeline: {}", e)))?;

    let pipeline: CiCdPipeline = sqlx::query_as("SELECT * FROM cicd_pipelines WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch pipeline: {}", e)))?;

    Ok(HttpResponse::Created().json(pipeline))
}

/// Get a specific pipeline
#[utoipa::path(
    get,
    path = "/api/cicd/pipelines/{id}",
    params(
        ("id" = String, Path, description = "Pipeline ID")
    ),
    responses(
        (status = 200, description = "Pipeline details", body = CiCdPipeline),
        (status = 404, description = "Pipeline not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn get_pipeline(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let pipeline_id = path.into_inner();

    let pipeline: CiCdPipeline =
        sqlx::query_as("SELECT * FROM cicd_pipelines WHERE id = ? AND user_id = ?")
            .bind(&pipeline_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch pipeline: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Pipeline not found"))?;

    Ok(HttpResponse::Ok().json(pipeline))
}

/// Update a pipeline
#[utoipa::path(
    put,
    path = "/api/cicd/pipelines/{id}",
    params(
        ("id" = String, Path, description = "Pipeline ID")
    ),
    request_body = UpdatePipelineRequest,
    responses(
        (status = 200, description = "Pipeline updated", body = CiCdPipeline),
        (status = 404, description = "Pipeline not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn update_pipeline(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdatePipelineRequest>,
) -> Result<HttpResponse, ApiError> {
    let pipeline_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Verify ownership
    let _: CiCdPipeline =
        sqlx::query_as("SELECT * FROM cicd_pipelines WHERE id = ? AND user_id = ?")
            .bind(&pipeline_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch pipeline: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Pipeline not found"))?;

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?"];
    let mut params: Vec<String> = vec![now.clone()];

    if let Some(ref name) = body.name {
        updates.push("name = ?");
        params.push(name.clone());
    }
    if let Some(ref repo_url) = body.repository_url {
        updates.push("repository_url = ?");
        params.push(repo_url.clone());
    }
    if let Some(enabled) = body.enabled {
        updates.push("enabled = ?");
        params.push(if enabled { "1" } else { "0" }.to_string());
    }
    if let Some(ref config) = body.config {
        updates.push("config = ?");
        params.push(serde_json::to_string(config).unwrap_or_default());
    }

    let query = format!(
        "UPDATE cicd_pipelines SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for param in &params {
        query_builder = query_builder.bind(param);
    }
    query_builder = query_builder.bind(&pipeline_id);

    query_builder
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update pipeline: {}", e)))?;

    let pipeline: CiCdPipeline = sqlx::query_as("SELECT * FROM cicd_pipelines WHERE id = ?")
        .bind(&pipeline_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch pipeline: {}", e)))?;

    Ok(HttpResponse::Ok().json(pipeline))
}

/// Delete a pipeline
#[utoipa::path(
    delete,
    path = "/api/cicd/pipelines/{id}",
    params(
        ("id" = String, Path, description = "Pipeline ID")
    ),
    responses(
        (status = 204, description = "Pipeline deleted"),
        (status = 404, description = "Pipeline not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn delete_pipeline(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let pipeline_id = path.into_inner();

    let result = sqlx::query("DELETE FROM cicd_pipelines WHERE id = ? AND user_id = ?")
        .bind(&pipeline_id)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to delete pipeline: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Pipeline not found"));
    }

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Pipeline Run Endpoints
// ============================================================================

/// List pipeline runs
#[utoipa::path(
    get,
    path = "/api/cicd/runs",
    params(
        ("pipeline_id" = Option<String>, Query, description = "Filter by pipeline ID"),
        ("status" = Option<String>, Query, description = "Filter by status"),
        ("limit" = Option<i32>, Query, description = "Maximum results"),
    ),
    responses(
        (status = 200, description = "List of runs", body = Vec<CiCdPipelineRun>),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn list_runs(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    query: web::Query<ListRunsQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(100);

    let mut sql = String::from(
        r#"
        SELECT r.* FROM cicd_pipeline_runs r
        JOIN cicd_pipelines p ON r.pipeline_id = p.id
        WHERE p.user_id = ?
        "#,
    );

    let mut params: Vec<String> = vec![claims.sub.clone()];

    if let Some(ref pipeline_id) = query.pipeline_id {
        sql.push_str(" AND r.pipeline_id = ?");
        params.push(pipeline_id.clone());
    }
    if let Some(ref status) = query.status {
        sql.push_str(" AND r.status = ?");
        params.push(status.clone());
    }

    sql.push_str(" ORDER BY r.created_at DESC LIMIT ?");

    let mut query_builder = sqlx::query_as::<_, CiCdPipelineRun>(&sql);
    for param in &params {
        query_builder = query_builder.bind(param);
    }
    query_builder = query_builder.bind(limit);

    let runs = query_builder
        .fetch_all(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch runs: {}", e)))?;

    Ok(HttpResponse::Ok().json(runs))
}

#[derive(Debug, serde::Deserialize)]
struct ListRunsQuery {
    pipeline_id: Option<String>,
    status: Option<String>,
    limit: Option<i32>,
}

/// Get a specific run
#[utoipa::path(
    get,
    path = "/api/cicd/runs/{id}",
    params(
        ("id" = String, Path, description = "Run ID")
    ),
    responses(
        (status = 200, description = "Run details", body = CiCdPipelineRun),
        (status = 404, description = "Run not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn get_run(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let run_id = path.into_inner();

    let run: CiCdPipelineRun = sqlx::query_as(
        r#"
        SELECT r.* FROM cicd_pipeline_runs r
        JOIN cicd_pipelines p ON r.pipeline_id = p.id
        WHERE r.id = ? AND p.user_id = ?
        "#,
    )
    .bind(&run_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch run: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Run not found"))?;

    Ok(HttpResponse::Ok().json(run))
}

/// Get quality gate status for a run
#[utoipa::path(
    get,
    path = "/api/cicd/runs/{id}/gate-status",
    params(
        ("id" = String, Path, description = "Run ID")
    ),
    responses(
        (status = 200, description = "Quality gate status"),
        (status = 404, description = "Run not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn get_gate_status(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let run_id = path.into_inner();

    // Get the run
    let run: CiCdPipelineRun = sqlx::query_as(
        r#"
        SELECT r.* FROM cicd_pipeline_runs r
        JOIN cicd_pipelines p ON r.pipeline_id = p.id
        WHERE r.id = ? AND p.user_id = ?
        "#,
    )
    .bind(&run_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch run: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Run not found"))?;

    // Get policies for this pipeline
    let policies: Vec<CiCdPolicy> = sqlx::query_as(
        r#"
        SELECT pol.* FROM cicd_policies pol
        JOIN cicd_pipeline_policies pp ON pol.id = pp.policy_id
        WHERE pp.pipeline_id = ? AND pol.enabled = 1
        "#,
    )
    .bind(&run.pipeline_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // If no policies, return passed
    if policies.is_empty() {
        return Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "passed",
            "message": "No policies configured",
            "run_id": run_id
        })));
    }

    // Evaluate against each policy
    let details = QualityGateDetails {
        new_findings: run.findings_new,
        fixed_findings: run.findings_fixed,
        total_findings: run.findings_total,
        critical_count: run.critical_count,
        high_count: run.high_count,
        medium_count: run.medium_count,
        low_count: run.low_count,
        info_count: 0,
        coverage: None,
    };

    let mut overall_result = None;

    for policy in &policies {
        let conditions: PolicyConditions =
            serde_json::from_str(&policy.conditions).unwrap_or_default();
        let result = PolicyEvaluator::evaluate(&conditions, &details);

        if overall_result.is_none() || result.status == crate::devsecops::cicd::GateStatus::Failed {
            overall_result = Some(result);
        }
    }

    Ok(HttpResponse::Ok().json(overall_result.unwrap()))
}

// ============================================================================
// Webhook Endpoint
// ============================================================================

/// Handle webhook from CI/CD platform
#[utoipa::path(
    post,
    path = "/api/cicd/webhook/{platform}",
    params(
        ("platform" = String, Path, description = "CI/CD platform")
    ),
    responses(
        (status = 200, description = "Webhook processed"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn handle_webhook(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> Result<HttpResponse, ApiError> {
    let platform = path.into_inner();

    // Get authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("Missing or invalid authorization"))?;

    // Verify token and get user
    let claims = jwt::verify_jwt(auth_header)
        .map_err(|_| ApiError::unauthorized("Invalid token"))?;

    // Find matching pipeline
    let pipeline: Option<CiCdPipeline> = sqlx::query_as(
        "SELECT * FROM cicd_pipelines WHERE user_id = ? AND platform = ? AND enabled = 1",
    )
    .bind(&claims.sub)
    .bind(&platform)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch pipeline: {}", e)))?;

    let pipeline = pipeline.ok_or_else(|| {
        ApiError::not_found(format!("No enabled pipeline found for platform: {}", platform))
    })?;

    // Create a new run
    let run_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Extract webhook data
    let branch = body
        .get("branch")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let commit = body
        .get("commit")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let trigger = body
        .get("trigger")
        .and_then(|v| v.as_str())
        .unwrap_or("webhook");
    let pr_number = body
        .get("pr_number")
        .and_then(|v| v.as_i64())
        .map(|n| n as i32)
        .or_else(|| {
            body.get("mr_iid")
                .and_then(|v| v.as_i64())
                .map(|n| n as i32)
        });
    let external_run_id = body
        .get("pipeline_id")
        .or_else(|| body.get("build_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    sqlx::query(
        r#"
        INSERT INTO cicd_pipeline_runs (
            id, pipeline_id, external_run_id, branch, commit_sha, trigger_type,
            pr_number, status, created_at, updated_at, started_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
        "#,
    )
    .bind(&run_id)
    .bind(&pipeline.id)
    .bind(&external_run_id)
    .bind(&branch)
    .bind(&commit)
    .bind(trigger)
    .bind(pr_number)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create run: {}", e)))?;

    // Update pipeline last run
    let _ = sqlx::query("UPDATE cicd_pipelines SET last_run_at = ?, last_run_status = 'pending', updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&now)
        .bind(&pipeline.id)
        .execute(pool.get_ref())
        .await;

    // If files are provided, trigger a scan
    if let Some(files) = body.get("files").and_then(|f| f.as_array()) {
        // Process files in background
        log::info!(
            "Received {} files for scanning in run {}",
            files.len(),
            run_id
        );
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "run_id": run_id,
        "pipeline_id": pipeline.id,
        "status": "pending",
        "message": "Webhook received and run created"
    })))
}

// ============================================================================
// Policy Endpoints
// ============================================================================

/// List all policies
#[utoipa::path(
    get,
    path = "/api/cicd/policies",
    responses(
        (status = 200, description = "List of policies", body = Vec<CiCdPolicy>),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn list_policies(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let policies: Vec<CiCdPolicy> =
        sqlx::query_as("SELECT * FROM cicd_policies WHERE user_id = ? ORDER BY created_at DESC")
            .bind(&claims.sub)
            .fetch_all(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch policies: {}", e)))?;

    Ok(HttpResponse::Ok().json(policies))
}

/// Create a new policy
#[utoipa::path(
    post,
    path = "/api/cicd/policies",
    request_body = CreatePolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = CiCdPolicy),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn create_policy(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    body: web::Json<CreatePolicyRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Validate policy type
    let policy_type = body.policy_type.to_lowercase();
    if !["quality_gate", "block_merge", "notification"].contains(&policy_type.as_str()) {
        return Err(ApiError::bad_request(
            "Invalid policy type. Must be: quality_gate, block_merge, or notification",
        ));
    }

    let conditions_json = serde_json::to_string(&body.conditions)
        .map_err(|e| ApiError::bad_request(format!("Invalid conditions: {}", e)))?;
    let actions_json = serde_json::to_string(&body.actions)
        .map_err(|e| ApiError::bad_request(format!("Invalid actions: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO cicd_policies (
            id, user_id, name, description, policy_type, conditions, actions,
            severity_threshold, max_new_findings, max_total_findings, block_on_critical,
            enabled, customer_id, engagement_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&policy_type)
    .bind(&conditions_json)
    .bind(&actions_json)
    .bind(&body.severity_threshold)
    .bind(body.max_new_findings)
    .bind(body.max_total_findings)
    .bind(body.block_on_critical.unwrap_or(true))
    .bind(&body.customer_id)
    .bind(&body.engagement_id)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create policy: {}", e)))?;

    let policy: CiCdPolicy = sqlx::query_as("SELECT * FROM cicd_policies WHERE id = ?")
        .bind(&id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?;

    Ok(HttpResponse::Created().json(policy))
}

/// Get a specific policy
async fn get_policy(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let policy_id = path.into_inner();

    let policy: CiCdPolicy =
        sqlx::query_as("SELECT * FROM cicd_policies WHERE id = ? AND user_id = ?")
            .bind(&policy_id)
            .bind(&claims.sub)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?
            .ok_or_else(|| ApiError::not_found("Policy not found"))?;

    Ok(HttpResponse::Ok().json(policy))
}

/// Update a policy
async fn update_policy(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdatePolicyRequest>,
) -> Result<HttpResponse, ApiError> {
    let policy_id = path.into_inner();
    let now = Utc::now().to_rfc3339();

    // Verify ownership
    let _: CiCdPolicy = sqlx::query_as("SELECT * FROM cicd_policies WHERE id = ? AND user_id = ?")
        .bind(&policy_id)
        .bind(&claims.sub)
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?
        .ok_or_else(|| ApiError::not_found("Policy not found"))?;

    // Build dynamic update
    let mut updates = vec!["updated_at = ?"];
    let mut params: Vec<String> = vec![now.clone()];

    if let Some(ref name) = body.name {
        updates.push("name = ?");
        params.push(name.clone());
    }
    if let Some(ref desc) = body.description {
        updates.push("description = ?");
        params.push(desc.clone());
    }
    if let Some(ref conditions) = body.conditions {
        updates.push("conditions = ?");
        params.push(serde_json::to_string(conditions).unwrap_or_default());
    }
    if let Some(ref actions) = body.actions {
        updates.push("actions = ?");
        params.push(serde_json::to_string(actions).unwrap_or_default());
    }
    if let Some(enabled) = body.enabled {
        updates.push("enabled = ?");
        params.push(if enabled { "1" } else { "0" }.to_string());
    }

    let query = format!(
        "UPDATE cicd_policies SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for param in &params {
        query_builder = query_builder.bind(param);
    }
    query_builder = query_builder.bind(&policy_id);

    query_builder
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update policy: {}", e)))?;

    let policy: CiCdPolicy = sqlx::query_as("SELECT * FROM cicd_policies WHERE id = ?")
        .bind(&policy_id)
        .fetch_one(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?;

    Ok(HttpResponse::Ok().json(policy))
}

/// Delete a policy
async fn delete_policy(
    claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let policy_id = path.into_inner();

    let result = sqlx::query("DELETE FROM cicd_policies WHERE id = ? AND user_id = ?")
        .bind(&policy_id)
        .bind(&claims.sub)
        .execute(pool.get_ref())
        .await
        .map_err(|e| ApiError::internal(format!("Failed to delete policy: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Policy not found"));
    }

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Template Endpoints
// ============================================================================

/// List available templates
#[utoipa::path(
    get,
    path = "/api/cicd/templates",
    responses(
        (status = 200, description = "List of templates", body = Vec<CiCdWorkflowTemplate>),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn list_templates(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let templates: Vec<CiCdWorkflowTemplate> = sqlx::query_as(
        "SELECT * FROM cicd_workflow_templates ORDER BY is_builtin DESC, name ASC",
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch templates: {}", e)))?;

    Ok(HttpResponse::Ok().json(templates))
}

/// List available platforms
#[utoipa::path(
    get,
    path = "/api/cicd/templates/platforms",
    responses(
        (status = 200, description = "List of platforms"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn list_platforms(_claims: web::ReqData<Claims>) -> Result<HttpResponse, ApiError> {
    let platforms = TemplateGenerator::get_available_platforms();
    Ok(HttpResponse::Ok().json(platforms))
}

/// Get template for a specific platform
#[utoipa::path(
    get,
    path = "/api/cicd/templates/{platform}",
    params(
        ("platform" = String, Path, description = "CI/CD platform")
    ),
    responses(
        (status = 200, description = "Template content"),
        (status = 404, description = "Template not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn get_template(
    _claims: web::ReqData<Claims>,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let platform = path.into_inner();

    let template: Option<CiCdWorkflowTemplate> =
        sqlx::query_as("SELECT * FROM cicd_workflow_templates WHERE platform = ? AND is_builtin = 1")
            .bind(&platform)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch template: {}", e)))?;

    match template {
        Some(t) => Ok(HttpResponse::Ok().json(t)),
        None => Err(ApiError::not_found(format!(
            "No template found for platform: {}",
            platform
        ))),
    }
}

/// Generate a custom template
#[utoipa::path(
    post,
    path = "/api/cicd/templates/generate",
    request_body = GenerateTemplateRequest,
    responses(
        (status = 200, description = "Generated template"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "CI/CD Integration"
)]
async fn generate_template(
    _claims: web::ReqData<Claims>,
    body: web::Json<GenerateTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let template = TemplateGenerator::generate(&body)
        .map_err(|e| ApiError::bad_request(format!("Failed to generate template: {}", e)))?;

    Ok(HttpResponse::Ok().json(template))
}
