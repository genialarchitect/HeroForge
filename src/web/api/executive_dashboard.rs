//! Executive Dashboard API endpoints
//!
//! Provides endpoints for:
//! - Executive overview
//! - Risk trends
//! - Compliance posture
//! - MTTR metrics
//! - Scan coverage
//! - KPIs
//! - Dashboard configuration

use actix_web::{web, HttpResponse};
use sqlx::SqlitePool;
use serde::Deserialize;

use crate::db::executive_dashboard::{
    CreateDashboardConfigRequest, get_executive_overview, get_risk_score_trend,
    get_compliance_posture_summary, get_mttr_metrics, get_latest_scan_coverage,
    get_latest_kpis, create_dashboard_config, get_user_dashboard_configs,
    get_dashboard_config_by_id, get_default_dashboard_config, update_dashboard_config,
    delete_dashboard_config, get_cached_metric, cache_metric, cleanup_expired_cache,
    record_risk_score, record_compliance_posture, record_mttr_metrics, record_scan_coverage,
    record_kpi, calculate_mttr,
};
use crate::web::auth;

// ============================================================================
// Query Parameters
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct TimeframeQuery {
    pub days: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct MetricCacheQuery {
    pub metric_type: String,
    pub metric_key: String,
    pub timeframe: String,
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RecordRiskScoreRequest {
    pub scan_id: Option<String>,
    pub risk_score: f64,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
    pub asset_count: i32,
    pub compliant_assets: i32,
    pub factors: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecordComplianceRequest {
    pub framework_id: String,
    pub framework_name: String,
    pub total_controls: i32,
    pub passing_controls: i32,
    pub failing_controls: i32,
    pub not_applicable: i32,
    pub details: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecordMttrRequest {
    pub severity: String,
    pub period_type: String,
    pub period_start: String,
    pub period_end: String,
    pub avg_mttr_hours: f64,
    pub min_mttr: Option<f64>,
    pub max_mttr: Option<f64>,
    pub p50_mttr: Option<f64>,
    pub p90_mttr: Option<f64>,
    pub sample_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct RecordCoverageRequest {
    pub period_start: String,
    pub period_end: String,
    pub total_assets: i32,
    pub scanned_assets: i32,
    pub scan_types: Option<String>,
    pub avg_scan_frequency_days: Option<f64>,
    pub last_full_scan_at: Option<String>,
    pub stale_asset_count: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct RecordKpiRequest {
    pub kpi_type: String,
    pub kpi_name: String,
    pub target_value: Option<f64>,
    pub current_value: Option<f64>,
    pub unit: Option<String>,
    pub period_start: String,
    pub period_end: String,
}

#[derive(Debug, Deserialize)]
pub struct CacheMetricRequest {
    pub metric_type: String,
    pub metric_key: String,
    pub timeframe: String,
    pub data: String,
    pub ttl_minutes: Option<i32>,
}

// ============================================================================
// Overview Endpoints
// ============================================================================

/// Get executive overview
pub async fn get_overview(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_executive_overview(pool.get_ref(), org_id).await {
        Ok(overview) => HttpResponse::Ok().json(overview),
        Err(e) => {
            log::error!("Failed to get executive overview: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get executive overview"
            }))
        }
    }
}

// ============================================================================
// Risk Trend Endpoints
// ============================================================================

/// Get risk score trend
pub async fn get_risk_trend(
    pool: web::Data<SqlitePool>,
    query: web::Query<TimeframeQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let days = query.days.unwrap_or(30);

    match get_risk_score_trend(pool.get_ref(), org_id, days).await {
        Ok(trend) => HttpResponse::Ok().json(trend),
        Err(e) => {
            log::error!("Failed to get risk trend: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get risk trend"
            }))
        }
    }
}

/// Record a new risk score
pub async fn post_risk_score(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordRiskScoreRequest>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match record_risk_score(
        pool.get_ref(),
        org_id,
        body.scan_id.as_deref(),
        body.risk_score,
        body.critical,
        body.high,
        body.medium,
        body.low,
        body.info,
        body.asset_count,
        body.compliant_assets,
        body.factors.as_deref(),
    )
    .await
    {
        Ok(score) => HttpResponse::Created().json(score),
        Err(e) => {
            log::error!("Failed to record risk score: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record risk score"
            }))
        }
    }
}

// ============================================================================
// Compliance Posture Endpoints
// ============================================================================

/// Get compliance posture summary
pub async fn get_compliance_summary(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_compliance_posture_summary(pool.get_ref(), org_id).await {
        Ok(posture) => HttpResponse::Ok().json(posture),
        Err(e) => {
            log::error!("Failed to get compliance posture: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get compliance posture"
            }))
        }
    }
}

/// Record compliance posture
pub async fn post_compliance_posture(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordComplianceRequest>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match record_compliance_posture(
        pool.get_ref(),
        org_id,
        &body.framework_id,
        &body.framework_name,
        body.total_controls,
        body.passing_controls,
        body.failing_controls,
        body.not_applicable,
        body.details.as_deref(),
    )
    .await
    {
        Ok(posture) => HttpResponse::Created().json(posture),
        Err(e) => {
            log::error!("Failed to record compliance posture: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record compliance posture"
            }))
        }
    }
}

// ============================================================================
// MTTR Endpoints
// ============================================================================

/// Get MTTR metrics
pub async fn get_mttr(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_mttr_metrics(pool.get_ref(), org_id).await {
        Ok(metrics) => HttpResponse::Ok().json(metrics),
        Err(e) => {
            log::error!("Failed to get MTTR metrics: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get MTTR metrics"
            }))
        }
    }
}

/// Record MTTR metrics
pub async fn post_mttr(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordMttrRequest>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match record_mttr_metrics(
        pool.get_ref(),
        org_id,
        &body.severity,
        &body.period_type,
        &body.period_start,
        &body.period_end,
        body.avg_mttr_hours,
        body.min_mttr,
        body.max_mttr,
        body.p50_mttr,
        body.p90_mttr,
        body.sample_count,
    )
    .await
    {
        Ok(metrics) => HttpResponse::Created().json(metrics),
        Err(e) => {
            log::error!("Failed to record MTTR metrics: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record MTTR metrics"
            }))
        }
    }
}

/// Calculate and return current MTTR for severity
pub async fn calculate_current_mttr(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<TimeframeQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let severity = path.into_inner();
    let days = query.days.unwrap_or(30);

    match calculate_mttr(pool.get_ref(), org_id, &severity, days).await {
        Ok(Some(mttr)) => HttpResponse::Ok().json(serde_json::json!({
            "severity": severity,
            "mttr_hours": mttr,
            "mttr_days": mttr / 24.0,
            "period_days": days
        })),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "severity": severity,
            "mttr_hours": null,
            "message": "No resolved vulnerabilities in period"
        })),
        Err(e) => {
            log::error!("Failed to calculate MTTR: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to calculate MTTR"
            }))
        }
    }
}

// ============================================================================
// Scan Coverage Endpoints
// ============================================================================

/// Get scan coverage
pub async fn get_coverage(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_latest_scan_coverage(pool.get_ref(), org_id).await {
        Ok(Some(coverage)) => HttpResponse::Ok().json(coverage),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "message": "No scan coverage data available"
        })),
        Err(e) => {
            log::error!("Failed to get scan coverage: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get scan coverage"
            }))
        }
    }
}

/// Record scan coverage
pub async fn post_coverage(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordCoverageRequest>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match record_scan_coverage(
        pool.get_ref(),
        org_id,
        &body.period_start,
        &body.period_end,
        body.total_assets,
        body.scanned_assets,
        body.scan_types.as_deref(),
        body.avg_scan_frequency_days,
        body.last_full_scan_at.as_deref(),
        body.stale_asset_count,
    )
    .await
    {
        Ok(coverage) => HttpResponse::Created().json(coverage),
        Err(e) => {
            log::error!("Failed to record scan coverage: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record scan coverage"
            }))
        }
    }
}

// ============================================================================
// KPI Endpoints
// ============================================================================

/// Get KPIs
pub async fn get_kpis(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_latest_kpis(pool.get_ref(), org_id).await {
        Ok(kpis) => HttpResponse::Ok().json(kpis),
        Err(e) => {
            log::error!("Failed to get KPIs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get KPIs"
            }))
        }
    }
}

/// Record KPI
pub async fn post_kpi(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<RecordKpiRequest>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match record_kpi(
        pool.get_ref(),
        org_id,
        &body.kpi_type,
        &body.kpi_name,
        body.target_value,
        body.current_value,
        body.unit.as_deref(),
        &body.period_start,
        &body.period_end,
    )
    .await
    {
        Ok(kpi) => HttpResponse::Created().json(kpi),
        Err(e) => {
            log::error!("Failed to record KPI: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to record KPI"
            }))
        }
    }
}

// ============================================================================
// Dashboard Configuration Endpoints
// ============================================================================

/// Create dashboard configuration
pub async fn create_config(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateDashboardConfigRequest>,
) -> HttpResponse {
    match create_dashboard_config(pool.get_ref(), &claims.sub, body.into_inner()).await {
        Ok(config) => HttpResponse::Created().json(config),
        Err(e) => {
            log::error!("Failed to create dashboard config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create dashboard config"
            }))
        }
    }
}

/// Get user's dashboard configurations
pub async fn get_configs(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_user_dashboard_configs(pool.get_ref(), &claims.sub).await {
        Ok(configs) => HttpResponse::Ok().json(configs),
        Err(e) => {
            log::error!("Failed to get dashboard configs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get dashboard configs"
            }))
        }
    }
}

/// Get dashboard config by ID
pub async fn get_config(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_dashboard_config_by_id(pool.get_ref(), &id).await {
        Ok(Some(config)) => HttpResponse::Ok().json(config),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Dashboard config not found"
        })),
        Err(e) => {
            log::error!("Failed to get dashboard config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get dashboard config"
            }))
        }
    }
}

/// Get user's default dashboard config
pub async fn get_default_config(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match get_default_dashboard_config(pool.get_ref(), &claims.sub).await {
        Ok(Some(config)) => HttpResponse::Ok().json(config),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "No default dashboard config found"
        })),
        Err(e) => {
            log::error!("Failed to get default dashboard config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get default config"
            }))
        }
    }
}

/// Update dashboard config
pub async fn put_config(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
    body: web::Json<CreateDashboardConfigRequest>,
) -> HttpResponse {
    match update_dashboard_config(pool.get_ref(), &id, body.into_inner()).await {
        Ok(config) => HttpResponse::Ok().json(config),
        Err(e) => {
            log::error!("Failed to update dashboard config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update dashboard config"
            }))
        }
    }
}

/// Delete dashboard config
pub async fn delete_config(
    pool: web::Data<SqlitePool>,
    id: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match delete_dashboard_config(pool.get_ref(), &id).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => {
            log::error!("Failed to delete dashboard config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to delete dashboard config"
            }))
        }
    }
}

// ============================================================================
// Metrics Cache Endpoints
// ============================================================================

/// Get cached metric
pub async fn get_metric_cache(
    pool: web::Data<SqlitePool>,
    query: web::Query<MetricCacheQuery>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();

    match get_cached_metric(
        pool.get_ref(),
        org_id,
        &query.metric_type,
        &query.metric_key,
        &query.timeframe,
    )
    .await
    {
        Ok(Some(cached)) => HttpResponse::Ok().json(cached),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Metric not cached or expired"
        })),
        Err(e) => {
            log::error!("Failed to get cached metric: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get cached metric"
            }))
        }
    }
}

/// Cache a metric
pub async fn post_metric_cache(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    body: web::Json<CacheMetricRequest>,
) -> HttpResponse {
    let org_id = claims.org_id.as_deref();
    let ttl = body.ttl_minutes.unwrap_or(15);

    match cache_metric(
        pool.get_ref(),
        org_id,
        &body.metric_type,
        &body.metric_key,
        &body.timeframe,
        &body.data,
        ttl,
        None,
    )
    .await
    {
        Ok(cached) => HttpResponse::Created().json(cached),
        Err(e) => {
            log::error!("Failed to cache metric: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to cache metric"
            }))
        }
    }
}

/// Cleanup expired cache entries (admin endpoint)
pub async fn cleanup_cache(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    match cleanup_expired_cache(pool.get_ref()).await {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Cache cleanup completed",
            "entries_removed": count
        })),
        Err(e) => {
            log::error!("Failed to cleanup cache: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to cleanup cache"
            }))
        }
    }
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/executive")
            // Overview
            .route("/overview", web::get().to(get_overview))
            // Risk trends
            .route("/risk-trend", web::get().to(get_risk_trend))
            .route("/risk-score", web::post().to(post_risk_score))
            // Compliance
            .route("/compliance-posture", web::get().to(get_compliance_summary))
            .route("/compliance-posture", web::post().to(post_compliance_posture))
            // MTTR
            .route("/mttr", web::get().to(get_mttr))
            .route("/mttr", web::post().to(post_mttr))
            .route("/mttr/{severity}/calculate", web::get().to(calculate_current_mttr))
            // Coverage
            .route("/scan-coverage", web::get().to(get_coverage))
            .route("/scan-coverage", web::post().to(post_coverage))
            // KPIs
            .route("/kpis", web::get().to(get_kpis))
            .route("/kpis", web::post().to(post_kpi))
            // Dashboard config
            .route("/dashboard/configs", web::post().to(create_config))
            .route("/dashboard/configs", web::get().to(get_configs))
            .route("/dashboard/configs/default", web::get().to(get_default_config))
            .route("/dashboard/configs/{id}", web::get().to(get_config))
            .route("/dashboard/configs/{id}", web::put().to(put_config))
            .route("/dashboard/configs/{id}", web::delete().to(delete_config))
            // Cache
            .route("/cache", web::get().to(get_metric_cache))
            .route("/cache", web::post().to(post_metric_cache))
            .route("/cache/cleanup", web::post().to(cleanup_cache)),
    );
}
