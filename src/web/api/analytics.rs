use actix_web::{web, HttpResponse, Result};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db;
use crate::db::models::{
    CustomerSecurityTrends, ExecutiveSummary, RemediationVelocity,
    RiskTrendPoint, MethodologyCoverage, ExecutiveDashboard,
};
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

// ============================================================================
// Executive Analytics Endpoints
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct CustomerTrendsQuery {
    #[serde(default = "default_months")]
    months: i64,
}

#[derive(Debug, Deserialize)]
pub struct ExecutiveDashboardQuery {
    customer_id: Option<String>,
    #[serde(default = "default_months")]
    months: i64,
}

fn default_months() -> i64 {
    6
}

/// GET /api/analytics/customer/{id}/trends?months=6
/// Get security trends for a specific customer
#[utoipa::path(
    get,
    path = "/api/analytics/customer/{id}/trends",
    params(
        ("id" = String, Path, description = "Customer ID"),
        ("months" = Option<i64>, Query, description = "Number of months to analyze (default: 6)")
    ),
    responses(
        (status = 200, description = "Customer security trends", body = CustomerSecurityTrends),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Customer not found")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Executive Analytics"
)]
pub async fn get_customer_trends(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
    query: web::Query<CustomerTrendsQuery>,
) -> Result<HttpResponse> {
    let customer_id = path.into_inner();

    let data = db::get_customer_security_trends(&pool, &customer_id, query.months)
        .await
        .map_err(|e| {
            log::error!("Failed to get customer security trends: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch customer trends")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/customer/{id}/summary
/// Get executive summary for a specific customer
#[utoipa::path(
    get,
    path = "/api/analytics/customer/{id}/summary",
    params(
        ("id" = String, Path, description = "Customer ID")
    ),
    responses(
        (status = 200, description = "Customer executive summary", body = ExecutiveSummary),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Customer not found")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Executive Analytics"
)]
pub async fn get_customer_summary(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let customer_id = path.into_inner();

    let data = db::get_customer_executive_summary(&pool, &customer_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get customer executive summary: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch customer summary")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/remediation-velocity?days=90
/// Get remediation velocity metrics
#[utoipa::path(
    get,
    path = "/api/analytics/remediation-velocity",
    params(
        ("days" = Option<i64>, Query, description = "Number of days to analyze (default: 90)")
    ),
    responses(
        (status = 200, description = "Remediation velocity metrics", body = RemediationVelocity),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Executive Analytics"
)]
pub async fn get_remediation_velocity(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<AnalyticsQuery>,
) -> Result<HttpResponse> {
    let data = db::get_remediation_velocity(&pool, &claims.sub, query.days)
        .await
        .map_err(|e| {
            log::error!("Failed to get remediation velocity: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch remediation velocity")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/risk-trends?months=6
/// Get risk trend analysis
#[utoipa::path(
    get,
    path = "/api/analytics/risk-trends",
    params(
        ("months" = Option<i64>, Query, description = "Number of months to analyze (default: 6)")
    ),
    responses(
        (status = 200, description = "Risk trends", body = Vec<RiskTrendPoint>),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Executive Analytics"
)]
pub async fn get_risk_trends(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<CustomerTrendsQuery>,
) -> Result<HttpResponse> {
    let data = db::get_risk_trends(&pool, &claims.sub, query.months)
        .await
        .map_err(|e| {
            log::error!("Failed to get risk trends: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch risk trends")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/methodology-coverage
/// Get methodology testing coverage statistics
#[utoipa::path(
    get,
    path = "/api/analytics/methodology-coverage",
    responses(
        (status = 200, description = "Methodology coverage statistics", body = MethodologyCoverage),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Executive Analytics"
)]
pub async fn get_methodology_coverage(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let data = db::get_methodology_coverage(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to get methodology coverage: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch methodology coverage")
        })?;

    Ok(HttpResponse::Ok().json(data))
}

/// GET /api/analytics/executive-dashboard?customer_id=xxx&months=6
/// Get combined executive dashboard data
#[utoipa::path(
    get,
    path = "/api/analytics/executive-dashboard",
    params(
        ("customer_id" = Option<String>, Query, description = "Optional customer ID for customer-specific data"),
        ("months" = Option<i64>, Query, description = "Number of months to analyze (default: 6)")
    ),
    responses(
        (status = 200, description = "Executive dashboard data", body = ExecutiveDashboard),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Executive Analytics"
)]
pub async fn get_executive_dashboard(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<ExecutiveDashboardQuery>,
) -> Result<HttpResponse> {
    let data = db::get_executive_dashboard(
        &pool,
        &claims.sub,
        query.customer_id.as_deref(),
        query.months
    )
        .await
        .map_err(|e| {
            log::error!("Failed to get executive dashboard: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch executive dashboard")
        })?;

    Ok(HttpResponse::Ok().json(data))
}
