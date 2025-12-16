use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db;
use crate::web::auth;

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    #[serde(default = "default_days")]
    days: i64,
}

#[derive(Debug, Deserialize)]
pub struct ServicesQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_days() -> i64 {
    30
}

fn default_limit() -> i64 {
    10
}

/// GET /api/analytics/summary?days=30
/// Get overall analytics summary for the authenticated user
pub async fn get_summary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AnalyticsQuery>,
) -> Result<HttpResponse> {
    let summary = db::get_analytics_summary(&pool, &claims.sub, query.days)
        .await
        .map_err(|e| {
            log::error!("Failed to get analytics summary: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch analytics summary")
        })?;

    Ok(HttpResponse::Ok().json(summary))
}

/// GET /api/analytics/hosts?days=30
/// Get host count time series data for charts
pub async fn get_hosts_over_time(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AnalyticsQuery>,
) -> Result<HttpResponse> {
    let data = db::get_hosts_over_time(&pool, &claims.sub, query.days)
        .await
        .map_err(|e| {
            log::error!("Failed to get hosts over time: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch hosts data")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/vulnerabilities?days=30
/// Get vulnerability trend data with severity breakdown
pub async fn get_vulnerabilities_over_time(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AnalyticsQuery>,
) -> Result<HttpResponse> {
    let data = db::get_vulnerabilities_over_time(&pool, &claims.sub, query.days)
        .await
        .map_err(|e| {
            log::error!("Failed to get vulnerabilities over time: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch vulnerability data")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/services?limit=10
/// Get top services found across all scans
pub async fn get_top_services(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ServicesQuery>,
) -> Result<HttpResponse> {
    let data = db::get_top_services(&pool, &claims.sub, query.limit)
        .await
        .map_err(|e| {
            log::error!("Failed to get top services: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch services data")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/frequency?days=30
/// Get scan frequency data (scans per day)
pub async fn get_scan_frequency(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AnalyticsQuery>,
) -> Result<HttpResponse> {
    let data = db::get_scan_frequency(&pool, &claims.sub, query.days)
        .await
        .map_err(|e| {
            log::error!("Failed to get scan frequency: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch frequency data")
        })?;

    Ok(HttpResponse::Ok().json(data))
}
