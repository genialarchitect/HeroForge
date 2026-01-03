use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde_json::json;

use crate::threat_hunting::{
    hypothesis, analytics, automation, collaboration,
    types::*,
    query_dsl::QueryParser,
};
use crate::web::auth::jwt::Claims;

/// POST /api/threat-hunting/hypotheses - Create hypothesis
pub async fn create_hypothesis(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateHypothesisRequest>,
) -> HttpResponse {
    // Extract user ID from JWT claims
    let user_id = Some(claims.sub.clone());

    match hypothesis::create_hypothesis(&pool, body.into_inner(), user_id).await {
        Ok(hypothesis) => HttpResponse::Ok().json(hypothesis),
        Err(e) => {
            log::error!("Failed to create hypothesis: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to create hypothesis",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/threat-hunting/hypotheses - List hypotheses
pub async fn list_hypotheses(pool: web::Data<SqlitePool>) -> HttpResponse {
    match hypothesis::list_hypotheses(&pool).await {
        Ok(hypotheses) => HttpResponse::Ok().json(hypotheses),
        Err(e) => {
            log::error!("Failed to list hypotheses: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to list hypotheses",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/threat-hunting/hypotheses/{id} - Get hypothesis
pub async fn get_hypothesis(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();

    match hypothesis::get_hypothesis(&pool, &id).await {
        Ok(Some(hypothesis)) => HttpResponse::Ok().json(hypothesis),
        Ok(None) => HttpResponse::NotFound().json(json!({
            "error": "Hypothesis not found"
        })),
        Err(e) => {
            log::error!("Failed to get hypothesis: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to get hypothesis",
                "details": e.to_string()
            }))
        }
    }
}

/// PUT /api/threat-hunting/hypotheses/{id} - Update hypothesis
pub async fn update_hypothesis(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateHypothesisRequest>,
) -> HttpResponse {
    let id = path.into_inner();

    match hypothesis::update_hypothesis(&pool, &id, body.into_inner()).await {
        Ok(Some(hypothesis)) => HttpResponse::Ok().json(hypothesis),
        Ok(None) => HttpResponse::NotFound().json(json!({
            "error": "Hypothesis not found"
        })),
        Err(e) => {
            log::error!("Failed to update hypothesis: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to update hypothesis",
                "details": e.to_string()
            }))
        }
    }
}

/// DELETE /api/threat-hunting/hypotheses/{id} - Delete hypothesis
pub async fn delete_hypothesis(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let id = path.into_inner();

    match hypothesis::delete_hypothesis(&pool, &id).await {
        Ok(true) => HttpResponse::NoContent().finish(),
        Ok(false) => HttpResponse::NotFound().json(json!({
            "error": "Hypothesis not found"
        })),
        Err(e) => {
            log::error!("Failed to delete hypothesis: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to delete hypothesis",
                "details": e.to_string()
            }))
        }
    }
}

/// POST /api/threat-hunting/hypotheses/{id}/execute - Execute hunt
pub async fn execute_hypothesis(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> HttpResponse {
    let hypothesis_id = path.into_inner();

    match automation::execute_hunt(&pool, &hypothesis_id, None).await {
        Ok(execution) => HttpResponse::Ok().json(execution),
        Err(e) => {
            log::error!("Failed to execute hunt: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to execute hunt",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/threat-hunting/campaigns - List campaigns
pub async fn list_campaigns(pool: web::Data<SqlitePool>) -> HttpResponse {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<String>, String, Option<String>, String)>(
        "SELECT id, name, description, start_date, end_date, status, created_by, created_at FROM hunt_campaigns ORDER BY created_at DESC"
    )
    .fetch_all(pool.get_ref())
    .await;

    match rows {
        Ok(rows) => {
            let campaigns: Vec<HuntCampaign> = rows.into_iter().filter_map(|(id, name, description, start_date, end_date, status, created_by, created_at)| {
                Some(HuntCampaign {
                    id,
                    name,
                    description,
                    start_date: start_date.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&chrono::Utc))),
                    end_date: end_date.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&chrono::Utc))),
                    status: status.parse().unwrap_or(CampaignStatus::Planning),
                    created_by,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created_at).ok().map(|dt| dt.with_timezone(&chrono::Utc)).unwrap_or_else(chrono::Utc::now),
                })
            }).collect();
            HttpResponse::Ok().json(campaigns)
        }
        Err(e) => {
            log::error!("Failed to list campaigns: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to list campaigns",
                "details": e.to_string()
            }))
        }
    }
}

/// POST /api/threat-hunting/campaigns - Create campaign
pub async fn create_campaign(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<CreateCampaignRequest>,
) -> HttpResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let request = body.into_inner();

    let result = sqlx::query(
        "INSERT INTO hunt_campaigns (id, name, description, start_date, end_date, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(request.start_date.map(|d| d.to_rfc3339()))
    .bind(request.end_date.map(|d| d.to_rfc3339()))
    .bind(CampaignStatus::Planning.to_string())
    .bind(&claims.sub)
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => {
            let campaign = HuntCampaign {
                id,
                name: request.name,
                description: request.description,
                start_date: request.start_date,
                end_date: request.end_date,
                status: CampaignStatus::Planning,
                created_by: Some(claims.sub.clone()),
                created_at: now,
            };
            HttpResponse::Created().json(campaign)
        }
        Err(e) => {
            log::error!("Failed to create campaign: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to create campaign",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/threat-hunting/executions - List hunt executions
pub async fn list_executions(pool: web::Data<SqlitePool>) -> HttpResponse {
    match automation::get_execution_history(pool.get_ref(), None, 100).await {
        Ok(executions) => HttpResponse::Ok().json(executions),
        Err(e) => {
            log::error!("Failed to list executions: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to list executions",
                "details": e.to_string()
            }))
        }
    }
}

/// POST /api/threat-hunting/queries/parse - Parse DSL query
pub async fn parse_query(body: web::Json<ParseQueryRequest>) -> HttpResponse {
    let mut parser = QueryParser::new(body.query.clone());

    match parser.parse() {
        Ok(ast) => HttpResponse::Ok().json(ParseQueryResponse {
            valid: true,
            ast: Some(serde_json::to_value(&ast).unwrap()),
            error: None,
        }),
        Err(e) => HttpResponse::Ok().json(ParseQueryResponse {
            valid: false,
            ast: None,
            error: Some(e.to_string()),
        }),
    }
}

/// POST /api/threat-hunting/queries/execute - Execute query
pub async fn execute_query(
    pool: web::Data<SqlitePool>,
    body: web::Json<ExecuteQueryRequest>,
) -> HttpResponse {
    let start_time = std::time::Instant::now();
    let mut parser = QueryParser::new(body.query.clone());

    match parser.parse() {
        Ok(ast) => {
            // Create query context from request parameters
            let now = chrono::Utc::now();
            let time_range = body.time_range.clone().unwrap_or(TimeRange {
                start: now - chrono::Duration::days(7),
                end: now,
            });
            let limit = body.limit.unwrap_or(1000);

            let context = crate::threat_hunting::query_dsl::QueryContext {
                start_time: time_range.start,
                end_time: time_range.end,
                source_filter: None,
                max_results: limit,
                offset: 0,
            };

            // Execute the query
            let mut executor = crate::threat_hunting::query_dsl::QueryExecutor::new(pool.get_ref().clone());
            match executor.execute_with_context(&ast, &context).await {
                Ok(results) => {
                    let execution_time = start_time.elapsed();
                    let count = results.len() as i64;
                    HttpResponse::Ok().json(ExecuteQueryResponse {
                        results,
                        count,
                        execution_time_ms: execution_time.as_millis() as i64,
                    })
                }
                Err(e) => {
                    log::error!("Query execution failed: {}", e);
                    HttpResponse::InternalServerError().json(json!({
                        "error": "Query execution failed",
                        "details": e.to_string()
                    }))
                }
            }
        }
        Err(e) => {
            HttpResponse::BadRequest().json(json!({
                "error": "Invalid query",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/threat-hunting/analytics - Get hunt analytics
pub async fn get_analytics(pool: web::Data<SqlitePool>) -> HttpResponse {
    match analytics::get_hunt_analytics(&pool).await {
        Ok(analytics) => HttpResponse::Ok().json(analytics),
        Err(e) => {
            log::error!("Failed to get hunt analytics: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to get hunt analytics",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/threat-hunting/notebooks - List notebooks
pub async fn list_notebooks(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> HttpResponse {
    let user_id = claims.sub.clone();

    match collaboration::list_notebooks(&pool, &user_id).await {
        Ok(notebooks) => HttpResponse::Ok().json(notebooks),
        Err(e) => {
            log::error!("Failed to list notebooks: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to list notebooks",
                "details": e.to_string()
            }))
        }
    }
}

/// POST /api/threat-hunting/notebooks - Create notebook
pub async fn create_notebook(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let user_id = Some(claims.sub.clone());

    let name = body.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled Notebook")
        .to_string();

    match collaboration::create_notebook(&pool, name, user_id).await {
        Ok(notebook) => HttpResponse::Ok().json(notebook),
        Err(e) => {
            log::error!("Failed to create notebook: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "error": "Failed to create notebook",
                "details": e.to_string()
            }))
        }
    }
}

/// GET /api/threat-hunting/templates - Get hypothesis templates
pub async fn get_templates() -> HttpResponse {
    let templates = hypothesis::get_hypothesis_templates();
    HttpResponse::Ok().json(templates)
}

/// Configure threat hunting API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/threat-hunting")
            .route("/hypotheses", web::post().to(create_hypothesis))
            .route("/hypotheses", web::get().to(list_hypotheses))
            .route("/hypotheses/{id}", web::get().to(get_hypothesis))
            .route("/hypotheses/{id}", web::put().to(update_hypothesis))
            .route("/hypotheses/{id}", web::delete().to(delete_hypothesis))
            .route("/hypotheses/{id}/execute", web::post().to(execute_hypothesis))
            .route("/campaigns", web::get().to(list_campaigns))
            .route("/campaigns", web::post().to(create_campaign))
            .route("/executions", web::get().to(list_executions))
            .route("/queries/parse", web::post().to(parse_query))
            .route("/queries/execute", web::post().to(execute_query))
            .route("/analytics", web::get().to(get_analytics))
            .route("/notebooks", web::get().to(list_notebooks))
            .route("/notebooks", web::post().to(create_notebook))
            .route("/templates", web::get().to(get_templates))
    );
}
