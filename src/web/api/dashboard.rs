use actix_web::{get, put, web, HttpResponse};
use serde_json::json;
use sqlx::{Row, SqlitePool};

use crate::compliance::analyzer::ComplianceAnalyzer;
use crate::compliance::types::ComplianceFramework;
use crate::db::models::*;
use crate::db::models_dashboard::*;
use crate::web::auth::jwt::Claims;

/// Get user's dashboard configuration
#[get("/api/dashboard/widgets")]
async fn get_dashboard_config(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, actix_web::Error> {
    // Try to fetch existing configuration
    let config = sqlx::query_as::<_, UserDashboardConfig>(
        "SELECT user_id, widgets, created_at, updated_at FROM user_dashboard_config WHERE user_id = ?"
    )
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        eprintln!("Database error fetching dashboard config: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch dashboard configuration")
    })?;

    match config {
        Some(cfg) => {
            // Parse widgets JSON
            let widgets: Vec<WidgetConfig> = serde_json::from_str(&cfg.widgets)
                .unwrap_or_else(|_| get_default_widgets());

            Ok(HttpResponse::Ok().json(json!({
                "widgets": widgets,
                "updated_at": cfg.updated_at
            })))
        }
        None => {
            // Return default configuration
            Ok(HttpResponse::Ok().json(json!({
                "widgets": get_default_widgets(),
                "updated_at": null
            })))
        }
    }
}

/// Update user's dashboard configuration
#[put("/api/dashboard/widgets")]
async fn update_dashboard_config(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: web::Json<UpdateDashboardConfigRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let widgets_json = serde_json::to_string(&req.widgets)
        .map_err(|e| {
            eprintln!("JSON serialization error: {}", e);
            actix_web::error::ErrorBadRequest("Invalid widget configuration")
        })?;

    let now = chrono::Utc::now();

    // Upsert dashboard configuration
    sqlx::query(
        r#"
        INSERT INTO user_dashboard_config (user_id, widgets, created_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            widgets = excluded.widgets,
            updated_at = excluded.updated_at
        "#
    )
    .bind(&claims.sub)
    .bind(&widgets_json)
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        eprintln!("Database error updating dashboard config: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update dashboard configuration")
    })?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "updated_at": now
    })))
}

/// Get data for a specific widget type
#[get("/api/dashboard/data/{widget_type}")]
async fn get_widget_data(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    widget_type: web::Path<String>,
) -> Result<HttpResponse, actix_web::Error> {
    let widget_type = widget_type.into_inner();

    let data = match widget_type.as_str() {
        "recent_scans" => get_recent_scans_data(&pool, &claims.sub).await?,
        "vulnerability_summary" => get_vulnerability_summary_data(&pool, &claims.sub).await?,
        "compliance_scores" => get_compliance_scores_data(&pool, &claims.sub).await?,
        "scan_activity_chart" => get_scan_activity_chart_data(&pool, &claims.sub).await?,
        "top_risky_hosts" => get_top_risky_hosts_data(&pool, &claims.sub).await?,
        "critical_vulns" => get_critical_vulns_data(&pool, &claims.sub).await?,
        "upcoming_scheduled_scans" => get_upcoming_scans_data(&pool, &claims.sub).await?,
        _ => return Ok(HttpResponse::BadRequest().json(json!({"error": "Unknown widget type"}))),
    };

    Ok(HttpResponse::Ok().json(data))
}

// Helper functions to fetch widget data

async fn get_recent_scans_data(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    let scans = sqlx::query_as::<_, ScanResult>(
        "SELECT * FROM scan_results WHERE user_id = ? ORDER BY created_at DESC LIMIT 5"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        eprintln!("Database error fetching recent scans: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch recent scans")
    })?;

    Ok(json!({ "scans": scans }))
}

async fn get_vulnerability_summary_data(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    let stats = sqlx::query_as::<_, VulnerabilityStats>(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
            SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive,
            SUM(CASE WHEN status = 'accepted_risk' THEN 1 ELSE 0 END) as accepted_risk,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ?
        "#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(VulnerabilityStats {
        total: 0,
        open: 0,
        in_progress: 0,
        resolved: 0,
        false_positive: 0,
        accepted_risk: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    });

    Ok(json!(stats))
}

async fn get_compliance_scores_data(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    // Query the most recent completed scan with results for this user
    let scan = sqlx::query_as::<_, ScanResult>(
        r#"
        SELECT * FROM scan_results
        WHERE user_id = ? AND status = 'completed' AND results IS NOT NULL
        ORDER BY completed_at DESC
        LIMIT 1
        "#
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        eprintln!("Database error fetching scan for compliance scores: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch compliance data")
    })?;

    // If no completed scans with results exist, return empty scores
    let scan = match scan {
        Some(s) => s,
        None => return Ok(json!({ "scores": [] })),
    };

    // Parse scan results to get host info
    let hosts: Vec<crate::types::HostInfo> = match &scan.results {
        Some(results_json) => {
            serde_json::from_str(results_json).unwrap_or_default()
        }
        None => return Ok(json!({ "scores": [] })),
    };

    // If no hosts were found in scan results, return empty scores
    if hosts.is_empty() {
        return Ok(json!({ "scores": [] }));
    }

    // Run compliance analysis with common frameworks
    let frameworks = vec![
        ComplianceFramework::PciDss4,
        ComplianceFramework::Nist80053,
        ComplianceFramework::CisBenchmarks,
        ComplianceFramework::OwaspTop10,
    ];

    let analyzer = ComplianceAnalyzer::new(frameworks);
    let summary = match analyzer.analyze(&hosts, &scan.id).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Compliance analysis error: {}", e);
            return Ok(json!({ "scores": [] }));
        }
    };

    // Convert framework summaries to the expected format
    let scores: Vec<serde_json::Value> = summary
        .frameworks
        .iter()
        .map(|fw| {
            json!({
                "framework": fw.framework.name(),
                "score": fw.compliance_score.round() as i32,
                "total": fw.total_controls
            })
        })
        .collect();

    Ok(json!({ "scores": scores }))
}

async fn get_scan_activity_chart_data(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    // Get scan activity for the last 30 days
    let data = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT DATE(created_at) as date, COUNT(*) as count
        FROM scan_results
        WHERE user_id = ? AND created_at >= datetime('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        eprintln!("Database error fetching scan activity: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch scan activity")
    })?;

    let chart_data: Vec<_> = data.into_iter()
        .map(|(date, count)| json!({ "date": date, "count": count }))
        .collect();

    Ok(json!({ "data": chart_data }))
}

async fn get_top_risky_hosts_data(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    let hosts = sqlx::query(
        r#"
        SELECT
            vt.host_ip as ip,
            COUNT(*) as vulnerability_count,
            SUM(CASE WHEN vt.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN vt.severity = 'high' THEN 1 ELSE 0 END) as high_count,
            (SUM(CASE WHEN vt.severity = 'critical' THEN 10 ELSE 0 END) +
             SUM(CASE WHEN vt.severity = 'high' THEN 5 ELSE 0 END) +
             SUM(CASE WHEN vt.severity = 'medium' THEN 2 ELSE 0 END) +
             SUM(CASE WHEN vt.severity = 'low' THEN 1 ELSE 0 END)) as risk_score
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ? AND vt.status IN ('open', 'in_progress')
        GROUP BY vt.host_ip
        ORDER BY risk_score DESC
        LIMIT 10
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        eprintln!("Database error fetching risky hosts: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch risky hosts")
    })?;

    let hosts_data: Vec<_> = hosts.into_iter()
        .map(|row| {
            json!({
                "ip": row.get::<String, _>("ip"),
                "hostname": None::<String>,
                "vulnerability_count": row.get::<i64, _>("vulnerability_count"),
                "critical_count": row.get::<i64, _>("critical_count"),
                "high_count": row.get::<i64, _>("high_count"),
                "risk_score": row.get::<i64, _>("risk_score") as f64
            })
        })
        .collect();

    Ok(json!({ "hosts": hosts_data }))
}

async fn get_critical_vulns_data(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    let vulns = sqlx::query_as::<_, VulnerabilityTracking>(
        r#"
        SELECT vt.*
        FROM vulnerability_tracking vt
        INNER JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.user_id = ? AND vt.severity = 'critical' AND vt.status IN ('open', 'in_progress')
        ORDER BY vt.created_at DESC
        LIMIT 10
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        eprintln!("Database error fetching critical vulns: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch critical vulnerabilities")
    })?;

    Ok(json!({ "vulnerabilities": vulns }))
}

async fn get_upcoming_scans_data(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<serde_json::Value, actix_web::Error> {
    let scans = sqlx::query_as::<_, ScheduledScan>(
        "SELECT * FROM scheduled_scans WHERE user_id = ? AND is_active = 1 ORDER BY next_run_at LIMIT 5"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        eprintln!("Database error fetching upcoming scans: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch upcoming scans")
    })?;

    Ok(json!({ "scans": scans }))
}

/// Get default widget layout for new users
fn get_default_widgets() -> Vec<WidgetConfig> {
    vec![
        WidgetConfig {
            id: "recent_scans_1".to_string(),
            widget_type: "recent_scans".to_string(),
            x: 0,
            y: 0,
            w: 6,
            h: 2,
            config: None,
        },
        WidgetConfig {
            id: "vulnerability_summary_1".to_string(),
            widget_type: "vulnerability_summary".to_string(),
            x: 6,
            y: 0,
            w: 6,
            h: 2,
            config: None,
        },
        WidgetConfig {
            id: "scan_activity_chart_1".to_string(),
            widget_type: "scan_activity_chart".to_string(),
            x: 0,
            y: 2,
            w: 8,
            h: 3,
            config: None,
        },
        WidgetConfig {
            id: "top_risky_hosts_1".to_string(),
            widget_type: "top_risky_hosts".to_string(),
            x: 8,
            y: 2,
            w: 4,
            h: 3,
            config: None,
        },
        WidgetConfig {
            id: "critical_vulns_1".to_string(),
            widget_type: "critical_vulns".to_string(),
            x: 0,
            y: 5,
            w: 6,
            h: 2,
            config: None,
        },
        WidgetConfig {
            id: "upcoming_scheduled_scans_1".to_string(),
            widget_type: "upcoming_scheduled_scans".to_string(),
            x: 6,
            y: 5,
            w: 6,
            h: 2,
            config: None,
        },
    ]
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_dashboard_config)
        .service(update_dashboard_config)
        .service(get_widget_data);
}
