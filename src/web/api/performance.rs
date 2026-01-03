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
        INSERT INTO performance_reports (id, user_id, report_name, optimization_types, created_at, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
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

    // Queue optimization for background processing
    let pool_clone = pool.get_ref().clone();
    let report_id_clone = report_id.clone();
    let config_clone = req.config.clone();

    tokio::spawn(async move {
        log::info!("Starting performance optimization: {}", report_id_clone);

        // Update status to running
        let _ = sqlx::query(
            "UPDATE performance_reports SET status = 'running' WHERE id = ?"
        )
        .bind(&report_id_clone)
        .execute(&pool_clone)
        .await;

        // Run the optimization analysis
        match performance::optimize_performance(&config_clone).await {
            Ok(report) => {
                // Store results
                let results_json = serde_json::to_string(&report).unwrap_or_default();
                let completed_at = chrono::Utc::now().to_rfc3339();

                // Calculate recommendations count
                let recommendations = calculate_recommendations(&report);

                let _ = sqlx::query(
                    r#"
                    UPDATE performance_reports
                    SET status = 'completed', results = ?, recommendations_count = ?, completed_at = ?
                    WHERE id = ?
                    "#,
                )
                .bind(&results_json)
                .bind(recommendations as i32)
                .bind(&completed_at)
                .bind(&report_id_clone)
                .execute(&pool_clone)
                .await;

                log::info!(
                    "Performance optimization {} completed with {} recommendations",
                    report_id_clone,
                    recommendations
                );
            }
            Err(e) => {
                log::error!("Performance optimization {} failed: {}", report_id_clone, e);

                let _ = sqlx::query(
                    "UPDATE performance_reports SET status = 'failed', error_message = ? WHERE id = ?"
                )
                .bind(format!("{}", e))
                .bind(&report_id_clone)
                .execute(&pool_clone)
                .await;
            }
        }
    });

    Ok(HttpResponse::Ok().json(PerformanceReportResponse {
        id: report_id,
        report_name: req.report_name.clone(),
        status: "pending".to_string(),
        created_at: now,
    }))
}

/// Calculate the number of recommendations from performance report
fn calculate_recommendations(report: &performance::PerformanceReport) -> usize {
    let mut count = 0;

    // Edge recommendations
    if report.edge_metrics.locations_deployed > 0 {
        count += 1;
    }
    if report.edge_metrics.cache_hit_rate < 0.8 {
        count += 1;
    }

    // Database recommendations
    if report.database_metrics.query_optimization_applied > 0 {
        count += report.database_metrics.query_optimization_applied;
    }
    if report.database_metrics.cache_hit_rate < 0.9 {
        count += 1;
    }

    // API recommendations
    if report.api_metrics.compression_ratio < 0.5 {
        count += 1;
    }
    if report.api_metrics.average_response_time_ms > 100.0 {
        count += 1;
    }

    // Frontend recommendations
    if report.frontend_metrics.lighthouse_score < 90.0 {
        count += 1;
    }
    if report.frontend_metrics.bundle_size_kb > 500.0 {
        count += 1;
    }

    // Scaling recommendations
    if report.scaling_metrics.cpu_utilization > 70.0 {
        count += 1;
    }
    if report.scaling_metrics.memory_utilization > 80.0 {
        count += 1;
    }

    // Partitioning recommendations
    if report.partitioning_metrics.rebalancing_required {
        count += 1;
    }

    count
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/performance")
            .route("/reports", web::post().to(create_report)),
    );
}
