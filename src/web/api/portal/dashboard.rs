//! Portal Dashboard
//!
//! Provides dashboard statistics for the customer portal.

use actix_web::{web, HttpRequest, HttpResponse, HttpMessage, Result};
use serde::Serialize;
use sqlx::SqlitePool;

use super::auth::PortalClaims;

/// Dashboard statistics for portal user
#[derive(Debug, Serialize)]
pub struct PortalDashboardStats {
    pub customer_name: String,
    pub active_engagements: i64,
    pub total_engagements: i64,
    pub open_vulnerabilities: i64,
    pub critical_vulnerabilities: i64,
    pub high_vulnerabilities: i64,
    pub available_reports: i64,
    pub recent_scans: Vec<RecentScan>,
    pub upcoming_milestones: Vec<UpcomingMilestone>,
}

#[derive(Debug, Serialize)]
pub struct RecentScan {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
    pub total_hosts: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UpcomingMilestone {
    pub id: String,
    pub name: String,
    pub engagement_name: String,
    pub due_date: Option<String>,
    pub status: String,
}

/// Get portal dashboard statistics
pub async fn get_dashboard(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let customer_id = &claims.customer_id;

    // Get customer name
    let customer_name: String = sqlx::query_scalar(
        "SELECT name FROM customers WHERE id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or_else(|_| "Unknown".to_string());

    // Get engagement counts
    let (total_engagements,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM engagements WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let (active_engagements,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM engagements WHERE customer_id = ? AND status IN ('planning', 'in_progress')"
    )
    .bind(customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Get vulnerability counts from scan results linked to this customer
    let (open_vulnerabilities,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.status NOT IN ('resolved', 'false_positive')
        "#
    )
    .bind(customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let (critical_vulnerabilities,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.status NOT IN ('resolved', 'false_positive')
        AND vt.severity = 'critical'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    let (high_vulnerabilities,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.status NOT IN ('resolved', 'false_positive')
        AND vt.severity = 'high'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Get report count
    let (available_reports,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM reports r
        JOIN engagements e ON r.engagement_id = e.id
        WHERE e.customer_id = ? AND r.status = 'completed'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Get recent scans
    let recent_scans: Vec<RecentScan> = sqlx::query_as::<_, (String, String, String, String)>(
        r#"
        SELECT id, name, status, created_at
        FROM scan_results
        WHERE customer_id = ?
        ORDER BY created_at DESC
        LIMIT 5
        "#
    )
    .bind(customer_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, status, created_at)| RecentScan {
        id,
        name,
        status,
        created_at,
        total_hosts: None,
    })
    .collect();

    // Get upcoming milestones
    let upcoming_milestones: Vec<UpcomingMilestone> = sqlx::query_as::<_, (String, String, String, Option<String>, String)>(
        r#"
        SELECT em.id, em.name, e.name as engagement_name, em.due_date, em.status
        FROM engagement_milestones em
        JOIN engagements e ON em.engagement_id = e.id
        WHERE e.customer_id = ? AND em.status != 'completed'
        ORDER BY em.due_date ASC
        LIMIT 5
        "#
    )
    .bind(customer_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, engagement_name, due_date, status)| UpcomingMilestone {
        id,
        name,
        engagement_name,
        due_date,
        status,
    })
    .collect();

    Ok(HttpResponse::Ok().json(PortalDashboardStats {
        customer_name,
        active_engagements,
        total_engagements,
        open_vulnerabilities,
        critical_vulnerabilities,
        high_vulnerabilities,
        available_reports,
        recent_scans,
        upcoming_milestones,
    }))
}
