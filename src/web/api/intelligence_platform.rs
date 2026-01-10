//! Intelligence platform API endpoints

use actix_web::{web, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;
use anyhow::Result;

use crate::web::auth::jwt::Claims;
use crate::web::error::ApiError;
use crate::intelligence_platform;

#[derive(Debug, Deserialize)]
pub struct InitializePlatformRequest {
    pub config: intelligence_platform::PlatformConfig,
}

/// Initialize intelligence platform
pub async fn initialize_platform(
    _claims: Claims,
    _pool: web::Data<SqlitePool>,
    req: web::Json<InitializePlatformRequest>,
) -> Result<HttpResponse, ApiError> {
    let platform = intelligence_platform::initialize_platform(&req.config)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(platform))
}

/// Get intelligence hub status
pub async fn get_hub_status(
    _claims: Claims,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let total_indicators: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM intel_timeline_events"
    )
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    let sources = sqlx::query_as::<_, (String, String, bool, String, i64)>(
        r#"
        SELECT id, name, is_enabled, last_updated, indicator_count
        FROM intel_sources
        ORDER BY last_updated DESC
        "#,
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_indicators": total_indicators,
        "sources": sources,
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateReportRequest {
    pub title: String,
    pub report_type: String,
    pub content: String,
    pub distribution_level: String,
}

/// Create intelligence report
pub async fn create_report(
    claims: Claims,
    pool: web::Data<SqlitePool>,
    req: web::Json<CreateReportRequest>,
) -> Result<HttpResponse, ApiError> {
    let report_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO intel_reports (id, user_id, title, report_type, content, distribution_level, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&report_id)
    .bind(&claims.sub)
    .bind(&req.title)
    .bind(&req.report_type)
    .bind(&req.content)
    .bind(&req.distribution_level)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": report_id,
        "title": req.title,
        "created_at": now,
    })))
}

/// List intelligence reports
pub async fn list_reports(
    claims: Claims,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let reports = sqlx::query_as::<_, (String, String, String, String, String)>(
        r#"
        SELECT id, title, report_type, distribution_level, created_at
        FROM intel_reports
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(reports))
}

/// Get marketplace feeds
pub async fn list_marketplace_feeds(
    _claims: Claims,
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse, ApiError> {
    let feeds = sqlx::query_as::<_, (String, String, String, String, String, String, f64, f64, i64)>(
        r#"
        SELECT id, name, provider, description, category, pricing_model, pricing_value, rating, review_count
        FROM intel_marketplace_feeds
        ORDER BY rating DESC
        "#,
    )
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(HttpResponse::Ok().json(feeds))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/intelligence")
            .route("/initialize", web::post().to(initialize_platform))
            .route("/hub/status", web::get().to(get_hub_status))
            .route("/reports", web::post().to(create_report))
            .route("/reports", web::get().to(list_reports))
            .route("/marketplace/feeds", web::get().to(list_marketplace_feeds)),
    );
}
