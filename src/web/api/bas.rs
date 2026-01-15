//! Breach & Attack Simulation API Endpoints
//!
//! Provides REST API endpoints for BAS scenarios, simulations, and results.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::db::bas::{self, BasStats};
use crate::scanner::bas::{
    BasConfig, BasEngine, ExecutionMode, MitreTactic, ScenarioStatus,
    SimulationScenario, TechniqueLibrary,
};
use crate::web::auth::Claims;
use crate::web::error::ApiErrorKind;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request to create a new BAS scenario
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScenarioRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub execution_mode: String,
    pub technique_ids: Vec<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub parallel_execution: bool,
    #[serde(default = "default_true")]
    pub continue_on_failure: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_timeout() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

/// Request to update a scenario
#[allow(dead_code)]
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateScenarioRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub execution_mode: Option<String>,
    pub technique_ids: Option<Vec<String>>,
    pub targets: Option<Vec<String>>,
    pub timeout_secs: Option<u64>,
    pub parallel_execution: Option<bool>,
    pub continue_on_failure: Option<bool>,
    pub tags: Option<Vec<String>>,
}

/// Request to start a simulation
#[derive(Debug, Deserialize, ToSchema)]
pub struct StartSimulationRequest {
    /// Scenario ID to run
    pub scenario_id: String,
    /// Optional override for execution mode
    pub execution_mode: Option<String>,
}

/// Response for technique list
#[derive(Debug, Serialize, ToSchema)]
pub struct TechniqueResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tactic: String,
    pub tactic_name: String,
    pub mitre_url: String,
    pub platforms: Vec<String>,
    pub permissions_required: Vec<String>,
    pub data_sources: Vec<String>,
    pub detection: String,
    pub payloads: Vec<String>,
    pub is_safe: bool,
    pub risk_level: u8,
}

/// Tactic information
#[derive(Debug, Serialize, ToSchema)]
pub struct TacticInfo {
    pub id: String,
    pub name: String,
}

/// Response for scenario list
#[derive(Debug, Serialize, ToSchema)]
pub struct ScenarioListResponse {
    pub scenarios: Vec<ScenarioSummary>,
    pub total: usize,
}

/// Scenario summary
#[derive(Debug, Serialize, ToSchema)]
pub struct ScenarioSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub execution_mode: String,
    pub technique_count: usize,
    pub target_count: usize,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Response for simulation list
#[derive(Debug, Serialize, ToSchema)]
pub struct SimulationListResponse {
    pub simulations: Vec<SimulationSummary>,
    pub total: usize,
}

/// Simulation summary
#[derive(Debug, Serialize, ToSchema)]
pub struct SimulationSummary {
    pub id: String,
    pub scenario_id: String,
    pub status: String,
    pub execution_mode: String,
    pub total_techniques: i32,
    pub detection_rate: f64,
    pub security_score: i32,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<i64>,
}

/// Full simulation details
#[derive(Debug, Serialize, ToSchema)]
pub struct SimulationDetailsResponse {
    pub id: String,
    pub scenario_id: String,
    pub status: String,
    pub execution_mode: String,
    pub summary: SimulationStats,
    pub executions: Vec<TechniqueExecutionResponse>,
    pub detection_gaps: Vec<DetectionGapResponse>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
}

/// Simulation statistics
#[derive(Debug, Serialize, ToSchema)]
pub struct SimulationStats {
    pub total_techniques: i32,
    pub succeeded: i32,
    pub blocked: i32,
    pub detected: i32,
    pub failed: i32,
    pub skipped: i32,
    pub detection_rate: f64,
    pub block_rate: f64,
    pub security_score: i32,
}

/// Technique execution response
#[derive(Debug, Serialize, ToSchema)]
pub struct TechniqueExecutionResponse {
    pub id: String,
    pub technique_id: String,
    pub target: Option<String>,
    pub status: String,
    pub detection_observed: bool,
    pub detection_details: Option<String>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
}

/// Detection gap response
#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionGapResponse {
    pub id: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactics: Vec<String>,
    pub severity: i32,
    pub reason: Option<String>,
    pub recommendations: Vec<String>,
    pub acknowledged: bool,
}

/// Acknowledge gap request
#[derive(Debug, Deserialize, ToSchema)]
pub struct AcknowledgeGapRequest {
    pub notes: Option<String>,
}

// ============================================================================
// API Endpoints
// ============================================================================

/// List available attack techniques
///
/// GET /api/bas/techniques
#[utoipa::path(
    get,
    path = "/api/bas/techniques",
    tag = "BAS",
    params(
        ("tactic" = Option<String>, Query, description = "Filter by tactic ID (e.g., TA0002)"),
        ("platform" = Option<String>, Query, description = "Filter by platform"),
        ("safe_only" = Option<bool>, Query, description = "Only show safe techniques")
    ),
    responses(
        (status = 200, description = "List of techniques", body = Vec<TechniqueResponse>),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_techniques(
    query: web::Query<TechniqueQuery>,
    _claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let library = TechniqueLibrary::new();

    let mut techniques: Vec<&crate::scanner::bas::AttackTechnique> = if let Some(ref tactic_id) = query.tactic {
        if let Some(tactic) = MitreTactic::from_id(tactic_id) {
            library.by_tactic(tactic)
        } else {
            library.all_techniques()
        }
    } else {
        library.all_techniques()
    };

    // Filter by platform
    if let Some(ref platform) = query.platform {
        techniques.retain(|t| {
            t.platforms.iter().any(|p| p.eq_ignore_ascii_case(platform))
        });
    }

    // Filter safe only
    if query.safe_only.unwrap_or(false) {
        techniques.retain(|t| t.is_safe);
    }

    let techniques_list: Vec<TechniqueResponse> = techniques
        .into_iter()
        .map(|t| {
            // Get primary tactic (first one if multiple)
            let (tactic_id, tactic_name) = t.tactics.first()
                .map(|tac| (tac.id().to_string(), tac.name().to_string()))
                .unwrap_or_else(|| ("unknown".to_string(), "Unknown".to_string()));

            // Build MITRE URL
            let mitre_url = format!(
                "https://attack.mitre.org/techniques/{}/",
                t.technique_id.replace('.', "/")
            );

            // Map payload types to strings
            let payloads: Vec<String> = t.payload_types
                .iter()
                .map(|p| p.as_str().to_string())
                .collect();

            TechniqueResponse {
                id: t.technique_id.clone(),
                name: t.name.clone(),
                description: t.description.clone(),
                tactic: tactic_id,
                tactic_name,
                mitre_url,
                platforms: t.platforms.clone(),
                permissions_required: Vec::new(), // Not tracked in current model
                data_sources: t.detection_sources.clone(),
                detection: t.detection_sources.join(", "),
                payloads,
                is_safe: t.is_safe,
                risk_level: t.risk_level,
            }
        })
        .collect();

    let total = techniques_list.len();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "techniques": techniques_list,
        "total": total
    })))
}

#[derive(Debug, Deserialize)]
pub struct TechniqueQuery {
    pub tactic: Option<String>,
    pub platform: Option<String>,
    pub safe_only: Option<bool>,
}

/// List MITRE ATT&CK tactics
///
/// GET /api/bas/tactics
#[utoipa::path(
    get,
    path = "/api/bas/tactics",
    tag = "BAS",
    responses(
        (status = 200, description = "List of tactics", body = Vec<TacticInfo>),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tactics(_claims: Claims) -> Result<HttpResponse, ApiErrorKind> {
    let tactics_list: Vec<TacticInfo> = MitreTactic::all()
        .into_iter()
        .map(|t| TacticInfo {
            id: t.id().to_string(),
            name: t.name().to_string(),
        })
        .collect();

    let total = tactics_list.len();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "tactics": tactics_list,
        "total": total
    })))
}

/// List user's BAS scenarios
///
/// GET /api/bas/scenarios
#[utoipa::path(
    get,
    path = "/api/bas/scenarios",
    tag = "BAS",
    responses(
        (status = 200, description = "List of scenarios", body = ScenarioListResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scenarios(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let scenarios = bas::get_user_scenarios(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    let summaries: Vec<ScenarioSummary> = scenarios
        .into_iter()
        .map(|s| {
            let technique_ids: Vec<String> =
                serde_json::from_str(&s.techniques).unwrap_or_default();
            let tags: Vec<String> =
                serde_json::from_str(&s.tactics).unwrap_or_default();

            ScenarioSummary {
                id: s.id,
                name: s.name,
                description: s.description,
                status: if s.is_builtin != 0 { "builtin".to_string() } else { "ready".to_string() },
                execution_mode: s.execution_mode,
                technique_count: technique_ids.len(),
                target_count: 0, // No targets in this schema
                tags,
                created_at: s.created_at.clone(),
                updated_at: s.updated_at.clone(),
            }
        })
        .collect();

    let total = summaries.len();

    Ok(HttpResponse::Ok().json(ScenarioListResponse {
        scenarios: summaries,
        total,
    }))
}

/// Create a new BAS scenario
///
/// POST /api/bas/scenarios
#[utoipa::path(
    post,
    path = "/api/bas/scenarios",
    tag = "BAS",
    request_body = CreateScenarioRequest,
    responses(
        (status = 201, description = "Scenario created", body = ScenarioSummary),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_scenario(
    pool: web::Data<SqlitePool>,
    body: web::Json<CreateScenarioRequest>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    // Validate execution mode
    let execution_mode = ExecutionMode::from_str(&body.execution_mode).ok_or_else(|| {
        ApiErrorKind::BadRequest(format!("Invalid execution mode: {}", body.execution_mode))
    })?;

    // Validate techniques exist
    let library = TechniqueLibrary::new();
    for technique_id in &body.technique_ids {
        if !library.exists(technique_id) {
            return Err(ApiErrorKind::BadRequest(format!(
                "Unknown technique: {}",
                technique_id
            )));
        }
    }

    let now = chrono::Utc::now();
    let scenario = SimulationScenario {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.clone(),
        description: body.description.clone(),
        user_id: claims.sub.clone(),
        status: ScenarioStatus::Draft,
        execution_mode,
        technique_ids: body.technique_ids.clone(),
        targets: body.targets.clone(),
        payload_configs: std::collections::HashMap::new(),
        timeout_secs: body.timeout_secs,
        parallel_execution: body.parallel_execution,
        continue_on_failure: body.continue_on_failure,
        tags: body.tags.clone(),
        created_at: now,
        updated_at: now,
    };

    let record = bas::create_scenario(pool.get_ref(), &scenario)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    let summary = ScenarioSummary {
        id: record.id,
        name: record.name,
        description: record.description,
        status: "ready".to_string(),
        execution_mode: record.execution_mode,
        technique_count: body.technique_ids.len(),
        target_count: body.targets.len(),
        tags: body.tags.clone(),
        created_at: record.created_at.clone(),
        updated_at: record.updated_at.clone(),
    };

    Ok(HttpResponse::Created().json(summary))
}

/// Get a specific scenario
///
/// GET /api/bas/scenarios/{id}
#[utoipa::path(
    get,
    path = "/api/bas/scenarios/{id}",
    tag = "BAS",
    responses(
        (status = 200, description = "Scenario details"),
        (status = 404, description = "Scenario not found"),
        (status = 403, description = "Not authorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_scenario(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let scenario_id = path.into_inner();

    let scenario = bas::get_scenario_by_id(pool.get_ref(), &scenario_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Scenario not found".to_string()))?;

    // Allow access if user created the scenario or it's a builtin
    if scenario.created_by.as_deref() != Some(&claims.sub) && scenario.is_builtin == 0 {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to access this scenario".to_string(),
        ));
    }

    Ok(HttpResponse::Ok().json(scenario.to_domain()))
}

/// Delete a scenario
///
/// DELETE /api/bas/scenarios/{id}
#[utoipa::path(
    delete,
    path = "/api/bas/scenarios/{id}",
    tag = "BAS",
    responses(
        (status = 204, description = "Scenario deleted"),
        (status = 404, description = "Scenario not found"),
        (status = 403, description = "Not authorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_scenario(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let scenario_id = path.into_inner();

    let scenario = bas::get_scenario_by_id(pool.get_ref(), &scenario_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Scenario not found".to_string()))?;

    // Cannot delete builtin scenarios
    if scenario.is_builtin != 0 {
        return Err(ApiErrorKind::Forbidden(
            "Cannot delete builtin scenarios".to_string(),
        ));
    }

    if scenario.created_by.as_deref() != Some(&claims.sub) {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to delete this scenario".to_string(),
        ));
    }

    bas::delete_scenario(pool.get_ref(), &scenario_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    Ok(HttpResponse::NoContent().finish())
}

/// Start a BAS simulation
///
/// POST /api/bas/simulations
#[utoipa::path(
    post,
    path = "/api/bas/simulations",
    tag = "BAS",
    request_body = StartSimulationRequest,
    responses(
        (status = 202, description = "Simulation started", body = SimulationSummary),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Scenario not found"),
        (status = 403, description = "Not authorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn start_simulation(
    pool: web::Data<SqlitePool>,
    body: web::Json<StartSimulationRequest>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    // Get scenario
    let scenario_record = bas::get_scenario_by_id(pool.get_ref(), &body.scenario_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Scenario not found".to_string()))?;

    // Allow access if user created the scenario or it's a builtin
    if scenario_record.created_by.as_deref() != Some(&claims.sub) && scenario_record.is_builtin == 0 {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to run this scenario".to_string(),
        ));
    }

    let mut scenario = scenario_record.to_domain();
    // Set the user_id to the current user for the simulation
    scenario.user_id = claims.sub.clone();

    // Override execution mode if provided
    if let Some(ref mode_str) = body.execution_mode {
        scenario.execution_mode = ExecutionMode::from_str(mode_str).ok_or_else(|| {
            ApiErrorKind::BadRequest(format!("Invalid execution mode: {}", mode_str))
        })?;
    }

    // Create engine and run simulation
    let engine = BasEngine::new(BasConfig::default());

    let result = engine
        .run_simulation(scenario, None)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Store result
    let record = bas::create_simulation(pool.get_ref(), &result)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    let summary = SimulationSummary {
        id: record.id,
        scenario_id: record.scenario_id,
        status: record.status,
        execution_mode: record.execution_mode,
        total_techniques: record.techniques_total as i32,
        detection_rate: record.detection_rate.unwrap_or(0.0),
        security_score: (record.detection_rate.unwrap_or(0.0) * 100.0) as i32,
        started_at: record.started_at.clone().unwrap_or_default(),
        completed_at: record.completed_at.clone(),
        duration_ms: None, // Not tracked in new schema
    };

    Ok(HttpResponse::Accepted().json(summary))
}

/// List user's simulations
///
/// GET /api/bas/simulations
#[utoipa::path(
    get,
    path = "/api/bas/simulations",
    tag = "BAS",
    responses(
        (status = 200, description = "List of simulations", body = SimulationListResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_simulations(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let simulations = bas::get_user_simulations(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    let summaries: Vec<SimulationSummary> = simulations
        .into_iter()
        .map(|s| SimulationSummary {
            id: s.id,
            scenario_id: s.scenario_id,
            status: s.status,
            execution_mode: s.execution_mode,
            total_techniques: s.techniques_total as i32,
            detection_rate: s.detection_rate.unwrap_or(0.0),
            security_score: (s.detection_rate.unwrap_or(0.0) * 100.0) as i32,
            started_at: s.started_at.clone().unwrap_or_default(),
            completed_at: s.completed_at.clone(),
            duration_ms: None,
        })
        .collect();

    let total = summaries.len();

    Ok(HttpResponse::Ok().json(SimulationListResponse {
        simulations: summaries,
        total,
    }))
}

/// Get simulation details
///
/// GET /api/bas/simulations/{id}
#[utoipa::path(
    get,
    path = "/api/bas/simulations/{id}",
    tag = "BAS",
    responses(
        (status = 200, description = "Simulation details", body = SimulationDetailsResponse),
        (status = 404, description = "Simulation not found"),
        (status = 403, description = "Not authorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_simulation(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let simulation_id = path.into_inner();

    let simulation = bas::get_simulation_by_id(pool.get_ref(), &simulation_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?
        .ok_or_else(|| ApiErrorKind::NotFound("Simulation not found".to_string()))?;

    if simulation.user_id != claims.sub {
        return Err(ApiErrorKind::Forbidden(
            "Not authorized to access this simulation".to_string(),
        ));
    }

    // Get executions
    let executions = bas::get_technique_executions(pool.get_ref(), &simulation_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Get detection gaps
    let gaps = bas::get_detection_gaps(pool.get_ref(), &simulation_id)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    // Calculate statistics from the new schema
    let total = simulation.techniques_total as i32;
    let detected = simulation.techniques_detected as i32;
    let failed = simulation.techniques_failed as i32;
    let executed = simulation.techniques_executed as i32;
    let detection_rate = simulation.detection_rate.unwrap_or(0.0);

    let response = SimulationDetailsResponse {
        id: simulation.id,
        scenario_id: simulation.scenario_id,
        status: simulation.status,
        execution_mode: simulation.execution_mode,
        summary: SimulationStats {
            total_techniques: total,
            succeeded: executed - detected - failed,
            blocked: 0,
            detected,
            failed,
            skipped: total - executed,
            detection_rate,
            block_rate: 0.0,
            security_score: (detection_rate * 100.0) as i32,
        },
        executions: executions
            .into_iter()
            .map(|e| TechniqueExecutionResponse {
                id: e.id,
                technique_id: e.technique_id,
                target: None,
                status: e.status,
                detection_observed: e.was_detected != 0,
                detection_details: e.detection_source,
                duration_ms: e.detection_time_ms,
                error: e.error_message,
            })
            .collect(),
        detection_gaps: gaps
            .into_iter()
            .map(|g| {
                // Parse severity to int (critical=5, high=4, medium=3, low=2)
                let severity_int = match g.severity.as_str() {
                    "critical" => 5,
                    "high" => 4,
                    "medium" => 3,
                    "low" => 2,
                    _ => 3,
                };

                DetectionGapResponse {
                    id: g.id,
                    technique_id: g.technique_id,
                    technique_name: g.technique_name,
                    tactics: vec![g.tactic],
                    severity: severity_int,
                    reason: g.recommendation.clone(),
                    recommendations: g.recommendation.into_iter().collect(),
                    acknowledged: g.is_acknowledged != 0,
                }
            })
            .collect(),
        started_at: simulation.started_at.clone().unwrap_or_default(),
        completed_at: simulation.completed_at.clone(),
        duration_ms: None,
        error: simulation.error_message,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Acknowledge a detection gap
///
/// POST /api/bas/gaps/{id}/acknowledge
#[utoipa::path(
    post,
    path = "/api/bas/gaps/{id}/acknowledge",
    tag = "BAS",
    request_body = AcknowledgeGapRequest,
    responses(
        (status = 200, description = "Gap acknowledged"),
        (status = 404, description = "Gap not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn acknowledge_gap(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<AcknowledgeGapRequest>,
    _claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let gap_id = path.into_inner();

    let acknowledged = bas::acknowledge_detection_gap(
        pool.get_ref(),
        &gap_id,
        body.notes.as_deref(),
    )
    .await
    .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    if !acknowledged {
        return Err(ApiErrorKind::NotFound("Detection gap not found".to_string()));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({"acknowledged": true})))
}

/// Get BAS statistics
///
/// GET /api/bas/stats
#[utoipa::path(
    get,
    path = "/api/bas/stats",
    tag = "BAS",
    responses(
        (status = 200, description = "BAS statistics", body = BasStats),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let stats = bas::get_user_stats(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Get unacknowledged detection gaps
///
/// GET /api/bas/gaps/unacknowledged
#[utoipa::path(
    get,
    path = "/api/bas/gaps/unacknowledged",
    tag = "BAS",
    responses(
        (status = 200, description = "Unacknowledged gaps", body = Vec<DetectionGapResponse>),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_unacknowledged_gaps(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, ApiErrorKind> {
    let gaps = bas::get_unacknowledged_gaps(pool.get_ref(), &claims.sub)
        .await
        .map_err(|e| ApiErrorKind::InternalError(e.to_string()))?;

    let response: Vec<DetectionGapResponse> = gaps
        .into_iter()
        .map(|g| {
            // Parse severity to int (critical=5, high=4, medium=3, low=2)
            let severity_int = match g.severity.as_str() {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                _ => 3,
            };

            DetectionGapResponse {
                id: g.id,
                technique_id: g.technique_id,
                technique_name: g.technique_name,
                tactics: vec![g.tactic],
                severity: severity_int,
                reason: g.recommendation.clone(),
                recommendations: g.recommendation.into_iter().collect(),
                acknowledged: g.is_acknowledged != 0,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(response))
}

/// Configure BAS routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/bas")
            // Techniques
            .route("/techniques", web::get().to(list_techniques))
            .route("/tactics", web::get().to(list_tactics))
            // Scenarios
            .route("/scenarios", web::get().to(list_scenarios))
            .route("/scenarios", web::post().to(create_scenario))
            .route("/scenarios/{id}", web::get().to(get_scenario))
            .route("/scenarios/{id}", web::delete().to(delete_scenario))
            // Simulations
            .route("/simulations", web::get().to(list_simulations))
            .route("/simulations", web::post().to(start_simulation))
            .route("/simulations/{id}", web::get().to(get_simulation))
            // Detection Gaps
            .route("/gaps/unacknowledged", web::get().to(get_unacknowledged_gaps))
            .route("/gaps/{id}/acknowledge", web::post().to(acknowledge_gap))
            // Stats
            .route("/stats", web::get().to(get_stats)),
    );
}
