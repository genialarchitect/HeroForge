//! Executive Dashboard database operations
//!
//! This module provides functions for:
//! - Dashboard configuration management
//! - Metrics caching
//! - Risk score tracking
//! - Compliance posture monitoring
//! - MTTR (Mean Time To Remediate) metrics
//! - Scan coverage tracking
//! - KPI management

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Dashboard configuration record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ExecutiveDashboardConfig {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub layout: String,
    pub widgets: String,
    pub default_timeframe_days: i32,
    pub auto_refresh_seconds: Option<i32>,
    pub theme: Option<String>,
    pub filters: Option<String>,
    pub is_default: bool,
    pub is_shared: bool,
    pub shared_with: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Dashboard metrics cache record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DashboardMetricsCache {
    pub id: String,
    pub organization_id: Option<String>,
    pub metric_type: String,
    pub metric_key: String,
    pub timeframe: String,
    pub computed_at: String,
    pub expires_at: String,
    pub data: String,
    pub computation_time_ms: Option<i32>,
}

/// Risk score history record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RiskScoreHistory {
    pub id: String,
    pub organization_id: Option<String>,
    pub scan_id: Option<String>,
    pub overall_risk_score: f64,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub asset_count: i32,
    pub compliant_assets: i32,
    pub factors: Option<String>,
    pub computed_at: String,
}

/// Compliance posture record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CompliancePosture {
    pub id: String,
    pub organization_id: Option<String>,
    pub framework_id: String,
    pub framework_name: String,
    pub total_controls: i32,
    pub passing_controls: i32,
    pub failing_controls: i32,
    pub not_applicable: i32,
    pub compliance_percentage: f64,
    pub previous_percentage: Option<f64>,
    pub trend: Option<String>,
    pub details: Option<String>,
    pub computed_at: String,
}

/// MTTR metrics record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MttrMetrics {
    pub id: String,
    pub organization_id: Option<String>,
    pub severity: String,
    pub period_type: String,
    pub period_start: String,
    pub period_end: String,
    pub avg_mttr_hours: f64,
    pub min_mttr_hours: Option<f64>,
    pub max_mttr_hours: Option<f64>,
    pub p50_mttr_hours: Option<f64>,
    pub p90_mttr_hours: Option<f64>,
    pub sample_count: i32,
    pub trend_percentage: Option<f64>,
    pub computed_at: String,
}

/// Scan coverage record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ScanCoverage {
    pub id: String,
    pub organization_id: Option<String>,
    pub period_start: String,
    pub period_end: String,
    pub total_assets: i32,
    pub scanned_assets: i32,
    pub coverage_percentage: f64,
    pub scan_types: Option<String>,
    pub avg_scan_frequency_days: Option<f64>,
    pub last_full_scan_at: Option<String>,
    pub stale_asset_count: Option<i32>,
    pub computed_at: String,
}

/// Executive KPI record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ExecutiveKpi {
    pub id: String,
    pub organization_id: Option<String>,
    pub kpi_type: String,
    pub kpi_name: String,
    pub target_value: Option<f64>,
    pub current_value: Option<f64>,
    pub unit: Option<String>,
    pub trend: Option<String>,
    pub trend_percentage: Option<f64>,
    pub period_start: String,
    pub period_end: String,
    pub computed_at: String,
}

/// Executive report configuration
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ExecutiveReport {
    pub id: String,
    pub organization_id: Option<String>,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub report_type: String,
    pub template_config: Option<String>,
    pub schedule_cron: Option<String>,
    pub recipients: Option<String>,
    pub last_generated_at: Option<String>,
    pub last_report_id: Option<String>,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Executive overview summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveOverview {
    pub overall_risk_score: f64,
    pub risk_trend: String,
    pub risk_trend_percentage: f64,
    pub total_vulnerabilities: i64,
    pub critical_vulnerabilities: i64,
    pub high_vulnerabilities: i64,
    pub medium_vulnerabilities: i64,
    pub low_vulnerabilities: i64,
    pub open_vulnerabilities: i64,
    pub resolved_last_30_days: i64,
    pub mttr_hours: f64,
    pub mttr_trend: String,
    pub scan_coverage: f64,
    pub compliance_score: f64,
    pub assets_total: i64,
    pub assets_at_risk: i64,
}

/// Risk trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTrendPoint {
    pub date: String,
    pub risk_score: f64,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

/// Create dashboard config request
#[derive(Debug, Clone, Deserialize)]
pub struct CreateDashboardConfigRequest {
    pub name: Option<String>,
    pub layout: String,
    pub widgets: String,
    pub default_timeframe_days: Option<i32>,
    pub auto_refresh_seconds: Option<i32>,
    pub theme: Option<String>,
    pub filters: Option<String>,
    pub is_default: Option<bool>,
}

// ============================================================================
// Dashboard Configuration
// ============================================================================

/// Create a new dashboard configuration
pub async fn create_dashboard_config(
    pool: &SqlitePool,
    user_id: &str,
    request: CreateDashboardConfigRequest,
) -> Result<ExecutiveDashboardConfig> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let name = request.name.unwrap_or_else(|| "My Dashboard".to_string());
    let timeframe = request.default_timeframe_days.unwrap_or(30);
    let is_default = request.is_default.unwrap_or(false);

    // If setting as default, unset other defaults
    if is_default {
        sqlx::query("UPDATE executive_dashboard_config SET is_default = 0 WHERE user_id = ?1")
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    let result = sqlx::query_as::<_, ExecutiveDashboardConfig>(
        r#"
        INSERT INTO executive_dashboard_config
        (id, user_id, name, layout, widgets, default_timeframe_days, auto_refresh_seconds,
         theme, filters, is_default, is_shared, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?12)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&name)
    .bind(&request.layout)
    .bind(&request.widgets)
    .bind(timeframe)
    .bind(request.auto_refresh_seconds)
    .bind(&request.theme)
    .bind(&request.filters)
    .bind(is_default)
    .bind(&now)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get user's dashboard configurations
pub async fn get_user_dashboard_configs(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ExecutiveDashboardConfig>> {
    let results = sqlx::query_as::<_, ExecutiveDashboardConfig>(
        "SELECT * FROM executive_dashboard_config WHERE user_id = ?1 ORDER BY is_default DESC, name ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

/// Get dashboard config by ID
pub async fn get_dashboard_config_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<ExecutiveDashboardConfig>> {
    let result = sqlx::query_as::<_, ExecutiveDashboardConfig>(
        "SELECT * FROM executive_dashboard_config WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Get user's default dashboard config
pub async fn get_default_dashboard_config(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<ExecutiveDashboardConfig>> {
    let result = sqlx::query_as::<_, ExecutiveDashboardConfig>(
        "SELECT * FROM executive_dashboard_config WHERE user_id = ?1 AND is_default = 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Update dashboard config
pub async fn update_dashboard_config(
    pool: &SqlitePool,
    id: &str,
    request: CreateDashboardConfigRequest,
) -> Result<ExecutiveDashboardConfig> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, ExecutiveDashboardConfig>(
        r#"
        UPDATE executive_dashboard_config
        SET name = COALESCE(?1, name),
            layout = ?2,
            widgets = ?3,
            default_timeframe_days = COALESCE(?4, default_timeframe_days),
            auto_refresh_seconds = ?5,
            theme = ?6,
            filters = ?7,
            updated_at = ?8
        WHERE id = ?9
        RETURNING *
        "#,
    )
    .bind(&request.name)
    .bind(&request.layout)
    .bind(&request.widgets)
    .bind(request.default_timeframe_days)
    .bind(request.auto_refresh_seconds)
    .bind(&request.theme)
    .bind(&request.filters)
    .bind(&now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Delete dashboard config
pub async fn delete_dashboard_config(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM executive_dashboard_config WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Metrics Cache
// ============================================================================

/// Cache metric data
pub async fn cache_metric(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    metric_type: &str,
    metric_key: &str,
    timeframe: &str,
    data: &str,
    ttl_minutes: i32,
    computation_time_ms: Option<i32>,
) -> Result<DashboardMetricsCache> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let computed_at = now.to_rfc3339();
    let expires_at = (now + Duration::minutes(ttl_minutes as i64)).to_rfc3339();

    let result = sqlx::query_as::<_, DashboardMetricsCache>(
        r#"
        INSERT INTO dashboard_metrics_cache
        (id, organization_id, metric_type, metric_key, timeframe, computed_at, expires_at, data, computation_time_ms)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(organization_id, metric_type, metric_key, timeframe) DO UPDATE SET
            computed_at = excluded.computed_at,
            expires_at = excluded.expires_at,
            data = excluded.data,
            computation_time_ms = excluded.computation_time_ms
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(metric_type)
    .bind(metric_key)
    .bind(timeframe)
    .bind(&computed_at)
    .bind(&expires_at)
    .bind(data)
    .bind(computation_time_ms)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get cached metric
pub async fn get_cached_metric(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    metric_type: &str,
    metric_key: &str,
    timeframe: &str,
) -> Result<Option<DashboardMetricsCache>> {
    let now = Utc::now().to_rfc3339();

    let result = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, DashboardMetricsCache>(
            r#"
            SELECT * FROM dashboard_metrics_cache
            WHERE organization_id = ?1 AND metric_type = ?2 AND metric_key = ?3 AND timeframe = ?4 AND expires_at > ?5
            "#,
        )
        .bind(org_id)
        .bind(metric_type)
        .bind(metric_key)
        .bind(timeframe)
        .bind(&now)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as::<_, DashboardMetricsCache>(
            r#"
            SELECT * FROM dashboard_metrics_cache
            WHERE organization_id IS NULL AND metric_type = ?1 AND metric_key = ?2 AND timeframe = ?3 AND expires_at > ?4
            "#,
        )
        .bind(metric_type)
        .bind(metric_key)
        .bind(timeframe)
        .bind(&now)
        .fetch_optional(pool)
        .await?
    };

    Ok(result)
}

/// Clean up expired cache entries
pub async fn cleanup_expired_cache(pool: &SqlitePool) -> Result<u64> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query("DELETE FROM dashboard_metrics_cache WHERE expires_at < ?1")
        .bind(&now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

// ============================================================================
// Risk Score History
// ============================================================================

/// Record risk score
pub async fn record_risk_score(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    scan_id: Option<&str>,
    risk_score: f64,
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
    info: i32,
    asset_count: i32,
    compliant_assets: i32,
    factors: Option<&str>,
) -> Result<RiskScoreHistory> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, RiskScoreHistory>(
        r#"
        INSERT INTO risk_score_history
        (id, organization_id, scan_id, overall_risk_score, critical_count, high_count, medium_count,
         low_count, info_count, asset_count, compliant_assets, factors, computed_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(scan_id)
    .bind(risk_score)
    .bind(critical)
    .bind(high)
    .bind(medium)
    .bind(low)
    .bind(info)
    .bind(asset_count)
    .bind(compliant_assets)
    .bind(factors)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get risk score trend
pub async fn get_risk_score_trend(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    days: i32,
) -> Result<Vec<RiskTrendPoint>> {
    let cutoff = (Utc::now() - Duration::days(days as i64)).to_rfc3339();

    let results: Vec<RiskScoreHistory> = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT * FROM risk_score_history
            WHERE organization_id = ?1 AND computed_at > ?2
            ORDER BY computed_at ASC
            "#,
        )
        .bind(org_id)
        .bind(&cutoff)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT * FROM risk_score_history
            WHERE organization_id IS NULL AND computed_at > ?1
            ORDER BY computed_at ASC
            "#,
        )
        .bind(&cutoff)
        .fetch_all(pool)
        .await?
    };

    Ok(results
        .into_iter()
        .map(|r| RiskTrendPoint {
            date: r.computed_at,
            risk_score: r.overall_risk_score,
            critical: r.critical_count,
            high: r.high_count,
            medium: r.medium_count,
            low: r.low_count,
        })
        .collect())
}

/// Get latest risk score
pub async fn get_latest_risk_score(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<Option<RiskScoreHistory>> {
    let result = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, RiskScoreHistory>(
            "SELECT * FROM risk_score_history WHERE organization_id = ?1 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(org_id)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as::<_, RiskScoreHistory>(
            "SELECT * FROM risk_score_history WHERE organization_id IS NULL ORDER BY computed_at DESC LIMIT 1",
        )
        .fetch_optional(pool)
        .await?
    };

    Ok(result)
}

// ============================================================================
// Compliance Posture
// ============================================================================

/// Record compliance posture
pub async fn record_compliance_posture(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    framework_id: &str,
    framework_name: &str,
    total_controls: i32,
    passing_controls: i32,
    failing_controls: i32,
    not_applicable: i32,
    details: Option<&str>,
) -> Result<CompliancePosture> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let compliance_percentage = if total_controls > 0 {
        (passing_controls as f64 / total_controls as f64) * 100.0
    } else {
        0.0
    };

    // Get previous percentage for trend calculation
    let previous: Option<(f64,)> = if let Some(org_id) = organization_id {
        sqlx::query_as(
            "SELECT compliance_percentage FROM compliance_posture WHERE organization_id = ?1 AND framework_id = ?2 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(org_id)
        .bind(framework_id)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT compliance_percentage FROM compliance_posture WHERE organization_id IS NULL AND framework_id = ?1 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(framework_id)
        .fetch_optional(pool)
        .await?
    };

    let trend = previous.map(|(prev,)| {
        if compliance_percentage > prev {
            "up".to_string()
        } else if compliance_percentage < prev {
            "down".to_string()
        } else {
            "stable".to_string()
        }
    });

    let result = sqlx::query_as::<_, CompliancePosture>(
        r#"
        INSERT INTO compliance_posture
        (id, organization_id, framework_id, framework_name, total_controls, passing_controls,
         failing_controls, not_applicable, compliance_percentage, previous_percentage, trend, details, computed_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(framework_id)
    .bind(framework_name)
    .bind(total_controls)
    .bind(passing_controls)
    .bind(failing_controls)
    .bind(not_applicable)
    .bind(compliance_percentage)
    .bind(previous.map(|(p,)| p))
    .bind(&trend)
    .bind(details)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get latest compliance posture for all frameworks
pub async fn get_compliance_posture_summary(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<Vec<CompliancePosture>> {
    let results = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, CompliancePosture>(
            r#"
            SELECT cp.* FROM compliance_posture cp
            INNER JOIN (
                SELECT framework_id, MAX(computed_at) as max_computed
                FROM compliance_posture WHERE organization_id = ?1
                GROUP BY framework_id
            ) latest ON cp.framework_id = latest.framework_id AND cp.computed_at = latest.max_computed
            WHERE cp.organization_id = ?1
            ORDER BY cp.framework_name
            "#,
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, CompliancePosture>(
            r#"
            SELECT cp.* FROM compliance_posture cp
            INNER JOIN (
                SELECT framework_id, MAX(computed_at) as max_computed
                FROM compliance_posture WHERE organization_id IS NULL
                GROUP BY framework_id
            ) latest ON cp.framework_id = latest.framework_id AND cp.computed_at = latest.max_computed
            WHERE cp.organization_id IS NULL
            ORDER BY cp.framework_name
            "#,
        )
        .fetch_all(pool)
        .await?
    };

    Ok(results)
}

// ============================================================================
// MTTR Metrics
// ============================================================================

/// Record MTTR metrics
pub async fn record_mttr_metrics(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    severity: &str,
    period_type: &str,
    period_start: &str,
    period_end: &str,
    avg_mttr_hours: f64,
    min_mttr: Option<f64>,
    max_mttr: Option<f64>,
    p50_mttr: Option<f64>,
    p90_mttr: Option<f64>,
    sample_count: i32,
) -> Result<MttrMetrics> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Get previous MTTR for trend calculation
    let previous: Option<(f64,)> = if let Some(org_id) = organization_id {
        sqlx::query_as(
            "SELECT avg_mttr_hours FROM mttr_metrics WHERE organization_id = ?1 AND severity = ?2 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(org_id)
        .bind(severity)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT avg_mttr_hours FROM mttr_metrics WHERE organization_id IS NULL AND severity = ?1 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(severity)
        .fetch_optional(pool)
        .await?
    };

    let trend_percentage = previous.map(|(prev,)| {
        if prev > 0.0 {
            ((avg_mttr_hours - prev) / prev) * 100.0
        } else {
            0.0
        }
    });

    let result = sqlx::query_as::<_, MttrMetrics>(
        r#"
        INSERT INTO mttr_metrics
        (id, organization_id, severity, period_type, period_start, period_end,
         avg_mttr_hours, min_mttr_hours, max_mttr_hours, p50_mttr_hours, p90_mttr_hours,
         sample_count, trend_percentage, computed_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(severity)
    .bind(period_type)
    .bind(period_start)
    .bind(period_end)
    .bind(avg_mttr_hours)
    .bind(min_mttr)
    .bind(max_mttr)
    .bind(p50_mttr)
    .bind(p90_mttr)
    .bind(sample_count)
    .bind(trend_percentage)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get latest MTTR metrics by severity
pub async fn get_mttr_metrics(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<Vec<MttrMetrics>> {
    let results = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, MttrMetrics>(
            r#"
            SELECT m.* FROM mttr_metrics m
            INNER JOIN (
                SELECT severity, MAX(computed_at) as max_computed
                FROM mttr_metrics WHERE organization_id = ?1
                GROUP BY severity
            ) latest ON m.severity = latest.severity AND m.computed_at = latest.max_computed
            WHERE m.organization_id = ?1
            ORDER BY CASE m.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
            "#,
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, MttrMetrics>(
            r#"
            SELECT m.* FROM mttr_metrics m
            INNER JOIN (
                SELECT severity, MAX(computed_at) as max_computed
                FROM mttr_metrics WHERE organization_id IS NULL
                GROUP BY severity
            ) latest ON m.severity = latest.severity AND m.computed_at = latest.max_computed
            WHERE m.organization_id IS NULL
            ORDER BY CASE m.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
            "#,
        )
        .fetch_all(pool)
        .await?
    };

    Ok(results)
}

/// Calculate MTTR from vulnerability data
pub async fn calculate_mttr(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    severity: &str,
    days: i32,
) -> Result<Option<f64>> {
    let cutoff = (Utc::now() - Duration::days(days as i64)).to_rfc3339();

    let result: Option<(Option<f64>,)> = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT AVG((julianday(resolved_at) - julianday(created_at)) * 24) as avg_hours
            FROM vulnerability_tracking
            WHERE organization_id = ?1
              AND severity = ?2
              AND status IN ('resolved', 'verified')
              AND resolved_at > ?3
            "#,
        )
        .bind(org_id)
        .bind(severity)
        .bind(&cutoff)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT AVG((julianday(resolved_at) - julianday(created_at)) * 24) as avg_hours
            FROM vulnerability_tracking
            WHERE severity = ?1
              AND status IN ('resolved', 'verified')
              AND resolved_at > ?2
            "#,
        )
        .bind(severity)
        .bind(&cutoff)
        .fetch_optional(pool)
        .await?
    };

    Ok(result.and_then(|(avg,)| avg))
}

// ============================================================================
// Scan Coverage
// ============================================================================

/// Record scan coverage metrics
pub async fn record_scan_coverage(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    period_start: &str,
    period_end: &str,
    total_assets: i32,
    scanned_assets: i32,
    scan_types: Option<&str>,
    avg_scan_frequency_days: Option<f64>,
    last_full_scan_at: Option<&str>,
    stale_asset_count: Option<i32>,
) -> Result<ScanCoverage> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let coverage_percentage = if total_assets > 0 {
        (scanned_assets as f64 / total_assets as f64) * 100.0
    } else {
        0.0
    };

    let result = sqlx::query_as::<_, ScanCoverage>(
        r#"
        INSERT INTO scan_coverage
        (id, organization_id, period_start, period_end, total_assets, scanned_assets,
         coverage_percentage, scan_types, avg_scan_frequency_days, last_full_scan_at, stale_asset_count, computed_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(period_start)
    .bind(period_end)
    .bind(total_assets)
    .bind(scanned_assets)
    .bind(coverage_percentage)
    .bind(scan_types)
    .bind(avg_scan_frequency_days)
    .bind(last_full_scan_at)
    .bind(stale_asset_count)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get latest scan coverage
pub async fn get_latest_scan_coverage(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<Option<ScanCoverage>> {
    let result = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, ScanCoverage>(
            "SELECT * FROM scan_coverage WHERE organization_id = ?1 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(org_id)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as::<_, ScanCoverage>(
            "SELECT * FROM scan_coverage WHERE organization_id IS NULL ORDER BY computed_at DESC LIMIT 1",
        )
        .fetch_optional(pool)
        .await?
    };

    Ok(result)
}

// ============================================================================
// Executive Overview
// ============================================================================

/// Get executive overview data
pub async fn get_executive_overview(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<ExecutiveOverview> {
    let thirty_days_ago = (Utc::now() - Duration::days(30)).to_rfc3339();

    // Get vulnerability counts
    let vuln_counts: (i64, i64, i64, i64, i64, i64) = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT
                COUNT(*),
                SUM(CASE WHEN severity = 'critical' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'high' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'medium' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'low' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN status IN ('open', 'in_progress') THEN 1 ELSE 0 END)
            FROM vulnerability_tracking WHERE organization_id = ?1
            "#,
        )
        .bind(org_id)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                COUNT(*),
                SUM(CASE WHEN severity = 'critical' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'high' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'medium' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'low' AND status NOT IN ('resolved', 'verified', 'false_positive') THEN 1 ELSE 0 END),
                SUM(CASE WHEN status IN ('open', 'in_progress') THEN 1 ELSE 0 END)
            FROM vulnerability_tracking
            "#,
        )
        .fetch_one(pool)
        .await?
    };

    // Get resolved count last 30 days
    let resolved_30d: (i64,) = if let Some(org_id) = organization_id {
        sqlx::query_as(
            "SELECT COUNT(*) FROM vulnerability_tracking WHERE organization_id = ?1 AND status IN ('resolved', 'verified') AND resolved_at > ?2",
        )
        .bind(org_id)
        .bind(&thirty_days_ago)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT COUNT(*) FROM vulnerability_tracking WHERE status IN ('resolved', 'verified') AND resolved_at > ?1",
        )
        .bind(&thirty_days_ago)
        .fetch_one(pool)
        .await?
    };

    // Get asset counts
    let asset_counts: (i64, i64) = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT COUNT(*), SUM(CASE WHEN risk_score > 50 THEN 1 ELSE 0 END)
            FROM assets WHERE organization_id = ?1
            "#,
        )
        .bind(org_id)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT COUNT(*), SUM(CASE WHEN risk_score > 50 THEN 1 ELSE 0 END) FROM assets",
        )
        .fetch_one(pool)
        .await?
    };

    // Get latest risk score
    let latest_risk = get_latest_risk_score(pool, organization_id).await?;

    // Get latest MTTR
    let mttr_metrics = get_mttr_metrics(pool, organization_id).await?;
    let avg_mttr = mttr_metrics.iter().map(|m| m.avg_mttr_hours).sum::<f64>()
        / mttr_metrics.len().max(1) as f64;

    // Get latest scan coverage
    let scan_cov = get_latest_scan_coverage(pool, organization_id).await?;

    // Get compliance summary
    let compliance_summary = get_compliance_posture_summary(pool, organization_id).await?;
    let avg_compliance = compliance_summary
        .iter()
        .map(|c| c.compliance_percentage)
        .sum::<f64>()
        / compliance_summary.len().max(1) as f64;

    // Calculate risk trend
    let risk_trend = get_risk_score_trend(pool, organization_id, 30).await?;
    let (risk_trend_str, risk_trend_pct) = if risk_trend.len() >= 2 {
        let first = risk_trend.first().map(|r| r.risk_score).unwrap_or(0.0);
        let last = risk_trend.last().map(|r| r.risk_score).unwrap_or(0.0);
        let pct = if first > 0.0 {
            ((last - first) / first) * 100.0
        } else {
            0.0
        };
        if pct > 0.0 {
            ("up".to_string(), pct)
        } else if pct < 0.0 {
            ("down".to_string(), pct.abs())
        } else {
            ("stable".to_string(), 0.0)
        }
    } else {
        ("stable".to_string(), 0.0)
    };

    // MTTR trend
    let mttr_trend = if mttr_metrics.iter().any(|m| m.trend_percentage.unwrap_or(0.0) < 0.0) {
        "improving"
    } else if mttr_metrics.iter().any(|m| m.trend_percentage.unwrap_or(0.0) > 0.0) {
        "worsening"
    } else {
        "stable"
    };

    Ok(ExecutiveOverview {
        overall_risk_score: latest_risk.as_ref().map(|r| r.overall_risk_score).unwrap_or(0.0),
        risk_trend: risk_trend_str,
        risk_trend_percentage: risk_trend_pct,
        total_vulnerabilities: vuln_counts.0,
        critical_vulnerabilities: vuln_counts.1,
        high_vulnerabilities: vuln_counts.2,
        medium_vulnerabilities: vuln_counts.3,
        low_vulnerabilities: vuln_counts.4,
        open_vulnerabilities: vuln_counts.5,
        resolved_last_30_days: resolved_30d.0,
        mttr_hours: avg_mttr,
        mttr_trend: mttr_trend.to_string(),
        scan_coverage: scan_cov.map(|s| s.coverage_percentage).unwrap_or(0.0),
        compliance_score: avg_compliance,
        assets_total: asset_counts.0,
        assets_at_risk: asset_counts.1,
    })
}

// ============================================================================
// Executive KPIs
// ============================================================================

/// Record KPI value
pub async fn record_kpi(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    kpi_type: &str,
    kpi_name: &str,
    target_value: Option<f64>,
    current_value: Option<f64>,
    unit: Option<&str>,
    period_start: &str,
    period_end: &str,
) -> Result<ExecutiveKpi> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Calculate trend from previous value
    let previous: Option<(Option<f64>,)> = if let Some(org_id) = organization_id {
        sqlx::query_as(
            "SELECT current_value FROM executive_kpis WHERE organization_id = ?1 AND kpi_type = ?2 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(org_id)
        .bind(kpi_type)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT current_value FROM executive_kpis WHERE organization_id IS NULL AND kpi_type = ?1 ORDER BY computed_at DESC LIMIT 1",
        )
        .bind(kpi_type)
        .fetch_optional(pool)
        .await?
    };

    let (trend, trend_percentage) = if let (Some(curr), Some(Some(prev))) = (current_value, previous.map(|(p,)| p)) {
        if prev > 0.0 {
            let pct = ((curr - prev) / prev) * 100.0;
            if pct > 0.0 {
                (Some("up".to_string()), Some(pct))
            } else if pct < 0.0 {
                (Some("down".to_string()), Some(pct.abs()))
            } else {
                (Some("stable".to_string()), Some(0.0))
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let result = sqlx::query_as::<_, ExecutiveKpi>(
        r#"
        INSERT INTO executive_kpis
        (id, organization_id, kpi_type, kpi_name, target_value, current_value, unit,
         trend, trend_percentage, period_start, period_end, computed_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(kpi_type)
    .bind(kpi_name)
    .bind(target_value)
    .bind(current_value)
    .bind(unit)
    .bind(&trend)
    .bind(trend_percentage)
    .bind(period_start)
    .bind(period_end)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get latest KPIs
pub async fn get_latest_kpis(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<Vec<ExecutiveKpi>> {
    let results = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, ExecutiveKpi>(
            r#"
            SELECT k.* FROM executive_kpis k
            INNER JOIN (
                SELECT kpi_type, MAX(computed_at) as max_computed
                FROM executive_kpis WHERE organization_id = ?1
                GROUP BY kpi_type
            ) latest ON k.kpi_type = latest.kpi_type AND k.computed_at = latest.max_computed
            WHERE k.organization_id = ?1
            ORDER BY k.kpi_type
            "#,
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, ExecutiveKpi>(
            r#"
            SELECT k.* FROM executive_kpis k
            INNER JOIN (
                SELECT kpi_type, MAX(computed_at) as max_computed
                FROM executive_kpis WHERE organization_id IS NULL
                GROUP BY kpi_type
            ) latest ON k.kpi_type = latest.kpi_type AND k.computed_at = latest.max_computed
            WHERE k.organization_id IS NULL
            ORDER BY k.kpi_type
            "#,
        )
        .fetch_all(pool)
        .await?
    };

    Ok(results)
}
