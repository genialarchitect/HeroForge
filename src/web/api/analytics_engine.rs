//! Analytics engine API endpoints

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;
use anyhow::Result;

use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;
use crate::analytics_engine;

#[derive(Debug, Deserialize)]
pub struct ExecuteQueryRequest {
    pub query: analytics_engine::AnalyticsQuery,
}

/// Execute analytics query
pub async fn execute_query(
    _claims: Claims,
    _pool: web::Data<SqlitePool>,
    req: web::Json<ExecuteQueryRequest>,
) -> Result<HttpResponse, ApiError> {
    let result = analytics_engine::run_analytics_query(&req.query)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Debug, Deserialize)]
pub struct SaveQueryRequest {
    pub name: String,
    pub description: Option<String>,
    pub query_definition: analytics_engine::AnalyticsQuery,
    pub is_shared: bool,
}

/// Save analytics query for reuse
pub async fn save_query(
    claims: Claims,
    pool: web::Data<SqlitePool>,
    req: web::Json<SaveQueryRequest>,
) -> Result<HttpResponse, ApiError> {
    let query_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let query_def = serde_json::to_string(&req.query_definition)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    sqlx::query(
        r#"
        INSERT INTO analytics_saved_queries (id, user_id, name, description, query_definition, is_shared, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&query_id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&query_def)
    .bind(req.is_shared)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": query_id,
        "name": req.name,
        "created_at": now,
    })))
}

/// List saved queries
pub async fn list_saved_queries(
    claims: Claims,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let queries = sqlx::query_as::<_, (String, String, String, String, bool)>(
        r#"
        SELECT id, name, description, query_definition, is_shared
        FROM analytics_saved_queries
        WHERE user_id = ? OR is_shared = 1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let results: Vec<_> = queries
        .into_iter()
        .map(|(id, name, description, _definition, is_shared)| {
            serde_json::json!({
                "id": id,
                "name": name,
                "description": description,
                "is_shared": is_shared,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(results))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/analytics")
            .route("/query", web::post().to(execute_query))
            .route("/saved-queries", web::post().to(save_query))
            .route("/saved-queries", web::get().to(list_saved_queries)),
    );
}
