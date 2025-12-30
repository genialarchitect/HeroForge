use actix_web::{web, HttpResponse, HttpRequest};
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
    req: HttpRequest,
    body: web::Json<CreateHypothesisRequest>,
) -> HttpResponse {
    // Extract user ID from JWT claims
    let user_id = req.extensions().get::<Claims>()
        .map(|claims| claims.sub.clone());

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
    // TODO: Implement campaign listing
    let _ = pool;
    HttpResponse::Ok().json(Vec::<HuntCampaign>::new())
}

/// POST /api/threat-hunting/campaigns - Create campaign
pub async fn create_campaign(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Json<CreateCampaignRequest>,
) -> HttpResponse {
    // TODO: Implement campaign creation
    let _ = (pool, req, body);
    HttpResponse::NotImplemented().json(json!({
        "error": "Campaign creation not yet implemented"
    }))
}

/// GET /api/threat-hunting/executions - List hunt executions
pub async fn list_executions(pool: web::Data<SqlitePool>) -> HttpResponse {
    // TODO: Implement execution listing
    let _ = pool;
    HttpResponse::Ok().json(Vec::<HuntExecution>::new())
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
pub async fn execute_query(body: web::Json<ExecuteQueryRequest>) -> HttpResponse {
    let mut parser = QueryParser::new(body.query.clone());

    match parser.parse() {
        Ok(_ast) => {
            // TODO: Execute query against data lake
            HttpResponse::Ok().json(ExecuteQueryResponse {
                results: vec![],
                count: 0,
                execution_time_ms: 0,
            })
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
    req: HttpRequest,
) -> HttpResponse {
    let user_id = req.extensions().get::<Claims>()
        .map(|claims| claims.sub.clone())
        .unwrap_or_default();

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
    req: HttpRequest,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let user_id = req.extensions().get::<Claims>()
        .map(|claims| claims.sub.clone());

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
