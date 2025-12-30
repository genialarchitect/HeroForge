//! Performance optimization API endpoints

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use anyhow::Result;

use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;
use crate::performance;

#[derive(Debug, Deserialize)]
pub struct CreatePerformanceReportRequest {
    pub report_name: String,
    pub config: performance::PerformanceConfig,
}

#[derive(Debug, Serialize)]
pub struct PerformanceReportResponse {
    pub id: String,
    pub report_name: String,
    pub status: String,
    pub created_at: String,
}

/// Create a new performance optimization report
pub async fn create_report(
    claims: Claims,
    pool: web::Data<SqlitePool>,
    req: web::Json<CreatePerformanceReportRequest>,
) -> Result<HttpResponse, ApiError> {
    let report_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let optimization_types = serde_json::to_string(&serde_json::json!({
        "edge": req.config.optimize_edge,
        "database": req.config.optimize_database,
        "api": req.config.optimize_api,
        "frontend": req.config.optimize_frontend,
        "scaling": req.config.optimize_scaling,
        "partitioning": req.config.optimize_partitioning,
    }))
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // Store report in database
    sqlx::query(
        r#"
        INSERT INTO performance_reports (id, user_id, report_name, optimization_types, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&report_id)
    .bind(&claims.sub)
    .bind(&req.report_name)
    .bind(&optimization_types)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    // TODO: Queue optimization for background processing

    Ok(HttpResponse::Ok().json(PerformanceReportResponse {
        id: report_id,
        report_name: req.report_name.clone(),
        status: "pending".to_string(),
        created_at: now,
    }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/performance")
            .route("/reports", web::post().to(create_report)),
    );
}
