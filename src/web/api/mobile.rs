#![allow(dead_code)]
//! Mobile-optimized API endpoints
//!
//! These endpoints are designed for mobile apps with optimized payloads,
//! minimal data transfer, and efficient pagination.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, SqlitePool};

use crate::web::auth::jwt::Claims;

// ============================================================================
// Pagination Types
// ============================================================================

/// Query parameters for pagination
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    20
}

impl PaginationParams {
    fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.limit
    }

    fn validated_limit(&self) -> u32 {
        self.limit.min(100).max(1)
    }
}

/// Pagination metadata
#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub page: u32,
    pub limit: u32,
    pub total: u64,
    pub total_pages: u32,
    pub has_next: bool,
    pub has_prev: bool,
}

impl PaginationMeta {
    fn new(page: u32, limit: u32, total: u64) -> Self {
        let total_pages = ((total as f64) / (limit as f64)).ceil() as u32;
        Self {
            page,
            limit,
            total,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        }
    }
}

// ============================================================================
// Dashboard Types
// ============================================================================

/// Mobile dashboard summary data (lightweight)
#[derive(Debug, Serialize)]
pub struct MobileDashboard {
    /// Quick stats
    pub stats: DashboardStats,
    /// Recent scans (last 5)
    pub recent_scans: Vec<ScanSummary>,
    /// Critical/high vulnerabilities needing attention
    pub urgent_vulns_count: u64,
    /// Active scans in progress
    pub active_scans_count: u64,
}

/// Dashboard statistics
#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_scans: u64,
    pub total_hosts: u64,
    pub total_vulns: u64,
    pub critical_vulns: u64,
    pub high_vulns: u64,
    pub medium_vulns: u64,
    pub low_vulns: u64,
    pub open_vulns: u64,
    pub resolved_vulns: u64,
}

/// Minimal scan info for mobile
#[derive(Debug, Serialize, FromRow)]
pub struct ScanSummary {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    #[sqlx(default)]
    pub host_count: Option<i64>,
    #[sqlx(default)]
    pub vuln_count: Option<i64>,
}

/// Minimal scan info for list view
#[derive(Debug, Serialize)]
pub struct MobileScanItem {
    pub id: String,
    pub name: String,
    pub status: String,
    pub targets: String,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub host_count: u32,
    pub vuln_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
}

/// Paginated scans response
#[derive(Debug, Serialize)]
pub struct MobileScansResponse {
    pub scans: Vec<MobileScanItem>,
    pub pagination: PaginationMeta,
}

/// Critical vulnerability for mobile view
#[derive(Debug, Serialize)]
pub struct CriticalVulnItem {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub host_ip: String,
    pub port: Option<i32>,
    pub service: Option<String>,
    pub status: String,
    pub scan_id: String,
    pub scan_name: String,
    pub created_at: String,
}

/// Critical vulnerabilities response
#[derive(Debug, Serialize)]
pub struct CriticalVulnsResponse {
    pub vulnerabilities: Vec<CriticalVulnItem>,
    pub pagination: PaginationMeta,
}

// ============================================================================
// API Endpoints
// ============================================================================

/// Get lightweight dashboard data for mobile
///
/// GET /api/mobile/dashboard
#[utoipa::path(
    get,
    path = "/api/mobile/dashboard",
    tag = "Mobile",
    responses(
        (status = 200, description = "Mobile dashboard data"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mobile_dashboard(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = &claims.sub;

    // Get aggregate stats
    let stats = get_dashboard_stats(pool.get_ref(), user_id)
        .await
        .map_err(|e| {
            log::error!("Failed to get dashboard stats: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to get dashboard stats")
        })?;

    // Get recent scans (last 5)
    let recent_scans = sqlx::query_as::<_, ScanSummary>(
        r#"
        SELECT
            sr.id,
            sr.name,
            sr.status,
            sr.created_at,
            (SELECT COUNT(DISTINCT vt.host_ip) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id) as host_count,
            (SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id) as vuln_count
        FROM scan_results sr
        WHERE sr.user_id = ?
        ORDER BY sr.created_at DESC
        LIMIT 5
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get recent scans: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get recent scans")
    })?;

    // Count urgent vulnerabilities (critical/high and open)
    let urgent_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?
          AND vt.severity IN ('critical', 'high')
          AND vt.status IN ('open', 'in_progress')
        "#,
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Count active scans
    let active_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM scan_results WHERE user_id = ? AND status IN ('pending', 'running')",
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(MobileDashboard {
        stats,
        recent_scans,
        urgent_vulns_count: urgent_count.0 as u64,
        active_scans_count: active_count.0 as u64,
    }))
}

/// Get paginated scan list for mobile
///
/// GET /api/mobile/scans
#[utoipa::path(
    get,
    path = "/api/mobile/scans",
    tag = "Mobile",
    params(
        ("page" = Option<u32>, Query, description = "Page number (1-based)"),
        ("limit" = Option<u32>, Query, description = "Items per page (max 100)")
    ),
    responses(
        (status = 200, description = "Paginated scan list"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mobile_scans(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<PaginationParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = &claims.sub;
    let limit = query.validated_limit();
    let offset = query.offset();

    // Get total count
    let total: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM scan_results WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool.get_ref())
            .await
            .unwrap_or((0,));

    // Get scans with vulnerability counts
    let rows = sqlx::query(
        r#"
        SELECT
            sr.id,
            sr.name,
            sr.status,
            sr.targets,
            sr.created_at,
            sr.completed_at,
            COALESCE((SELECT COUNT(DISTINCT vt.host_ip) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id), 0) as host_count,
            COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id), 0) as vuln_count,
            COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id AND vt.severity = 'critical'), 0) as critical_count,
            COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id AND vt.severity = 'high'), 0) as high_count
        FROM scan_results sr
        WHERE sr.user_id = ?
        ORDER BY sr.created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get scans: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get scans")
    })?;

    let scans: Vec<MobileScanItem> = rows
        .into_iter()
        .map(|row| MobileScanItem {
            id: row.get("id"),
            name: row.get("name"),
            status: row.get("status"),
            targets: row.get("targets"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            host_count: row.get::<i64, _>("host_count") as u32,
            vuln_count: row.get::<i64, _>("vuln_count") as u32,
            critical_count: row.get::<i64, _>("critical_count") as u32,
            high_count: row.get::<i64, _>("high_count") as u32,
        })
        .collect();

    Ok(HttpResponse::Ok().json(MobileScansResponse {
        scans,
        pagination: PaginationMeta::new(query.page, limit, total.0 as u64),
    }))
}

/// Scan filter parameters
#[derive(Debug, Deserialize)]
pub struct ScanFilterParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Filter by status
    pub status: Option<String>,
}

/// Get paginated scan list with optional status filter
///
/// GET /api/mobile/scans/filtered
pub async fn get_mobile_scans_filtered(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<ScanFilterParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = &claims.sub;
    let limit = query.limit.min(100).max(1);
    let offset = (query.page.saturating_sub(1)) * limit;

    // Build query with optional status filter
    let (count_query, data_query) = if query.status.is_some() {
        (
            "SELECT COUNT(*) FROM scan_results WHERE user_id = ? AND status = ?".to_string(),
            format!(
                r#"
                SELECT
                    sr.id, sr.name, sr.status, sr.targets, sr.created_at, sr.completed_at,
                    COALESCE((SELECT COUNT(DISTINCT vt.host_ip) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id), 0) as host_count,
                    COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id), 0) as vuln_count,
                    COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id AND vt.severity = 'critical'), 0) as critical_count,
                    COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id AND vt.severity = 'high'), 0) as high_count
                FROM scan_results sr
                WHERE sr.user_id = ? AND sr.status = ?
                ORDER BY sr.created_at DESC
                LIMIT ? OFFSET ?
                "#
            ),
        )
    } else {
        (
            "SELECT COUNT(*) FROM scan_results WHERE user_id = ?".to_string(),
            r#"
            SELECT
                sr.id, sr.name, sr.status, sr.targets, sr.created_at, sr.completed_at,
                COALESCE((SELECT COUNT(DISTINCT vt.host_ip) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id), 0) as host_count,
                COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id), 0) as vuln_count,
                COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id AND vt.severity = 'critical'), 0) as critical_count,
                COALESCE((SELECT COUNT(*) FROM vulnerability_tracking vt WHERE vt.scan_id = sr.id AND vt.severity = 'high'), 0) as high_count
            FROM scan_results sr
            WHERE sr.user_id = ?
            ORDER BY sr.created_at DESC
            LIMIT ? OFFSET ?
            "#
            .to_string(),
        )
    };

    // Get total count
    let total: (i64,) = if let Some(ref status) = query.status {
        sqlx::query_as(&count_query)
            .bind(user_id)
            .bind(status)
            .fetch_one(pool.get_ref())
            .await
            .unwrap_or((0,))
    } else {
        sqlx::query_as(&count_query)
            .bind(user_id)
            .fetch_one(pool.get_ref())
            .await
            .unwrap_or((0,))
    };

    // Get scans
    let rows = if let Some(ref status) = query.status {
        sqlx::query(&data_query)
            .bind(user_id)
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool.get_ref())
            .await
    } else {
        sqlx::query(&data_query)
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool.get_ref())
            .await
    }
    .map_err(|e| {
        log::error!("Failed to get scans: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get scans")
    })?;

    let scans: Vec<MobileScanItem> = rows
        .into_iter()
        .map(|row| MobileScanItem {
            id: row.get("id"),
            name: row.get("name"),
            status: row.get("status"),
            targets: row.get("targets"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            host_count: row.get::<i64, _>("host_count") as u32,
            vuln_count: row.get::<i64, _>("vuln_count") as u32,
            critical_count: row.get::<i64, _>("critical_count") as u32,
            high_count: row.get::<i64, _>("high_count") as u32,
        })
        .collect();

    Ok(HttpResponse::Ok().json(MobileScansResponse {
        scans,
        pagination: PaginationMeta::new(query.page, limit, total.0 as u64),
    }))
}

/// Get critical vulnerabilities only
///
/// GET /api/mobile/vulnerabilities/critical
#[utoipa::path(
    get,
    path = "/api/mobile/vulnerabilities/critical",
    tag = "Mobile",
    params(
        ("page" = Option<u32>, Query, description = "Page number (1-based)"),
        ("limit" = Option<u32>, Query, description = "Items per page (max 100)")
    ),
    responses(
        (status = 200, description = "Critical vulnerabilities list"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_critical_vulnerabilities(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    query: web::Query<PaginationParams>,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = &claims.sub;
    let limit = query.validated_limit();
    let offset = query.offset();

    // Get total count
    let total: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?
          AND vt.severity IN ('critical', 'high')
          AND vt.status IN ('open', 'in_progress')
        "#,
    )
    .bind(user_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Get vulnerabilities with scan info
    let rows = sqlx::query(
        r#"
        SELECT
            vt.id,
            vt.title,
            vt.severity,
            vt.host_ip,
            vt.port,
            vt.service,
            vt.status,
            vt.scan_id,
            sr.name as scan_name,
            vt.created_at
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?
          AND vt.severity IN ('critical', 'high')
          AND vt.status IN ('open', 'in_progress')
        ORDER BY
            CASE vt.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END,
            vt.created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get critical vulnerabilities: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get vulnerabilities")
    })?;

    let vulnerabilities: Vec<CriticalVulnItem> = rows
        .into_iter()
        .map(|row| CriticalVulnItem {
            id: row.get("id"),
            title: row.get("title"),
            severity: row.get("severity"),
            host_ip: row.get("host_ip"),
            port: row.get("port"),
            service: row.get("service"),
            status: row.get("status"),
            scan_id: row.get("scan_id"),
            scan_name: row.get("scan_name"),
            created_at: row.get("created_at"),
        })
        .collect();

    Ok(HttpResponse::Ok().json(CriticalVulnsResponse {
        vulnerabilities,
        pagination: PaginationMeta::new(query.page, limit, total.0 as u64),
    }))
}

/// Get quick vulnerability counts by severity
///
/// GET /api/mobile/vulnerabilities/counts
pub async fn get_vulnerability_counts(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = &claims.sub;

    let counts = sqlx::query(
        r#"
        SELECT
            vt.severity,
            vt.status,
            COUNT(*) as count
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?
        GROUP BY vt.severity, vt.status
        "#,
    )
    .bind(user_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to get vulnerability counts: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to get counts")
    })?;

    let mut by_severity = serde_json::json!({
        "critical": {"open": 0, "in_progress": 0, "resolved": 0, "total": 0},
        "high": {"open": 0, "in_progress": 0, "resolved": 0, "total": 0},
        "medium": {"open": 0, "in_progress": 0, "resolved": 0, "total": 0},
        "low": {"open": 0, "in_progress": 0, "resolved": 0, "total": 0}
    });

    let mut total_open = 0i64;
    let mut total_count = 0i64;

    for row in counts {
        let severity: String = row.get("severity");
        let status: String = row.get("status");
        let count: i64 = row.get("count");

        if let Some(sev_obj) = by_severity.get_mut(&severity) {
            if let Some(status_count) = sev_obj.get_mut(&status) {
                *status_count = serde_json::json!(count);
            }
            if let Some(total) = sev_obj.get_mut("total") {
                let current = total.as_i64().unwrap_or(0);
                *total = serde_json::json!(current + count);
            }
        }

        if status == "open" || status == "in_progress" {
            total_open += count;
        }
        total_count += count;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "by_severity": by_severity,
        "total_open": total_open,
        "total": total_count
    })))
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn get_dashboard_stats(pool: &SqlitePool, user_id: &str) -> Result<DashboardStats, sqlx::Error> {
    // Get scan count
    let scan_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM scan_results WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await?;

    // Get host count (distinct hosts across all scans)
    let host_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT vt.host_ip)
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    // Get vulnerability counts by severity and status
    let vuln_stats = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN status IN ('open', 'in_progress') THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(DashboardStats {
        total_scans: scan_count.0 as u64,
        total_hosts: host_count.0 as u64,
        total_vulns: vuln_stats.get::<i64, _>("total") as u64,
        critical_vulns: vuln_stats.get::<i64, _>("critical") as u64,
        high_vulns: vuln_stats.get::<i64, _>("high") as u64,
        medium_vulns: vuln_stats.get::<i64, _>("medium") as u64,
        low_vulns: vuln_stats.get::<i64, _>("low") as u64,
        open_vulns: vuln_stats.get::<i64, _>("open") as u64,
        resolved_vulns: vuln_stats.get::<i64, _>("resolved") as u64,
    })
}

/// Configure mobile API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/mobile")
            .route("/dashboard", web::get().to(get_mobile_dashboard))
            .route("/scans", web::get().to(get_mobile_scans))
            .route("/scans/filtered", web::get().to(get_mobile_scans_filtered))
            .route(
                "/vulnerabilities/critical",
                web::get().to(get_critical_vulnerabilities),
            )
            .route(
                "/vulnerabilities/counts",
                web::get().to(get_vulnerability_counts),
            ),
    );
}
