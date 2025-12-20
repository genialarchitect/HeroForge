//! Portal Vulnerabilities
//!
//! Provides access to vulnerabilities for portal users with limited write capabilities.

use actix_web::{web, HttpRequest, HttpResponse, HttpMessage, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::auth::PortalClaims;

/// Query parameters for vulnerability list
#[derive(Debug, Deserialize)]
pub struct VulnerabilityQuery {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub engagement_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Vulnerability summary for portal
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PortalVulnerability {
    pub id: String,
    pub scan_id: String,
    pub host: String,
    pub port: Option<i32>,
    pub service: Option<String>,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub cve_ids: Option<String>,
    pub cvss_score: Option<f64>,
    pub discovered_at: String,
}

/// Vulnerability detail for portal
#[derive(Debug, Serialize)]
pub struct PortalVulnerabilityDetail {
    pub vulnerability: PortalVulnerability,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<String>,
    pub engagement_name: Option<String>,
    pub scan_name: String,
}

/// Vulnerability statistics
#[derive(Debug, Serialize)]
pub struct VulnerabilityStats {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub open: i64,
    pub in_progress: i64,
    pub resolved: i64,
}

/// List vulnerabilities for the customer
pub async fn list_vulnerabilities(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    query: web::Query<VulnerabilityQuery>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    // Build query with filters
    let mut sql = r#"
        SELECT vt.id, vt.scan_id, vt.host, vt.port, vt.service, vt.title,
               vt.severity, vt.status, vt.cve_ids, vt.cvss_score, vt.discovered_at
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ?
    "#.to_string();

    let mut params: Vec<String> = vec![claims.customer_id.clone()];

    if let Some(severity) = &query.severity {
        sql.push_str(" AND vt.severity = ?");
        params.push(severity.clone());
    }

    if let Some(status) = &query.status {
        sql.push_str(" AND vt.status = ?");
        params.push(status.clone());
    }

    if let Some(engagement_id) = &query.engagement_id {
        sql.push_str(" AND sr.engagement_id = ?");
        params.push(engagement_id.clone());
    }

    sql.push_str(" ORDER BY CASE vt.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, vt.discovered_at DESC");
    sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

    // Execute query with dynamic parameters
    let vulnerabilities: Vec<PortalVulnerability> = match params.len() {
        1 => {
            sqlx::query_as(&sql)
                .bind(&params[0])
                .fetch_all(pool.get_ref())
                .await
                .unwrap_or_default()
        }
        2 => {
            sqlx::query_as(&sql)
                .bind(&params[0])
                .bind(&params[1])
                .fetch_all(pool.get_ref())
                .await
                .unwrap_or_default()
        }
        3 => {
            sqlx::query_as(&sql)
                .bind(&params[0])
                .bind(&params[1])
                .bind(&params[2])
                .fetch_all(pool.get_ref())
                .await
                .unwrap_or_default()
        }
        4 => {
            sqlx::query_as(&sql)
                .bind(&params[0])
                .bind(&params[1])
                .bind(&params[2])
                .bind(&params[3])
                .fetch_all(pool.get_ref())
                .await
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };

    // Get statistics
    let stats = get_vulnerability_stats(&pool, &claims.customer_id).await;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "vulnerabilities": vulnerabilities,
        "stats": stats,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": stats.total
        }
    })))
}

/// Get vulnerability statistics for customer
async fn get_vulnerability_stats(pool: &SqlitePool, customer_id: &str) -> VulnerabilityStats {
    let (total,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ?
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (critical,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.severity = 'critical'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (high,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.severity = 'high'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (medium,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.severity = 'medium'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (low,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.severity = 'low'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (open,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.status = 'open'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (in_progress,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.status = 'in_progress'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (resolved,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.customer_id = ? AND vt.status = 'resolved'
        "#
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    VulnerabilityStats {
        total,
        critical,
        high,
        medium,
        low,
        open,
        in_progress,
        resolved,
    }
}

/// Get a specific vulnerability detail
pub async fn get_vulnerability(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let vuln_id = path.into_inner();

    // Get vulnerability (ensuring it belongs to customer's scans)
    let vuln = sqlx::query_as::<_, PortalVulnerability>(
        r#"
        SELECT vt.id, vt.scan_id, vt.host, vt.port, vt.service, vt.title,
               vt.severity, vt.status, vt.cve_ids, vt.cvss_score, vt.discovered_at
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE vt.id = ? AND sr.customer_id = ?
        "#
    )
    .bind(&vuln_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch vulnerability: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch vulnerability")
    })?;

    let vuln = match vuln {
        Some(v) => v,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Vulnerability not found"
            })));
        }
    };

    // Get additional details
    let details: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT description, remediation, reference_urls FROM vulnerability_tracking WHERE id = ?"
    )
    .bind(&vuln_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    // Get scan name and engagement
    let scan_info: Option<(String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT sr.name, e.name
        FROM scan_results sr
        LEFT JOIN engagements e ON sr.engagement_id = e.id
        WHERE sr.id = ?
        "#
    )
    .bind(&vuln.scan_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    let (description, remediation, references) = details.unwrap_or((None, None, None));
    let (scan_name, engagement_name) = scan_info.unwrap_or(("Unknown".to_string(), None));

    Ok(HttpResponse::Ok().json(PortalVulnerabilityDetail {
        vulnerability: vuln,
        description,
        remediation,
        references,
        engagement_name,
        scan_name,
    }))
}

// ============================================================================
// Write Endpoints
// ============================================================================

/// Status update request
#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
    pub comment: Option<String>,
}

/// Comment model
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct VulnerabilityComment {
    pub id: String,
    pub vulnerability_id: String,
    pub user_id: String,
    pub user_email: String,
    pub comment: String,
    pub created_at: String,
}

/// Add comment request
#[derive(Debug, Deserialize)]
pub struct AddCommentRequest {
    pub comment: String,
}

/// Portal-allowed status values
const PORTAL_ALLOWED_STATUSES: [&str; 4] = ["in_progress", "pending_verification", "accepted_risk", "resolved"];

/// Validate status transition for portal users
fn is_valid_portal_status_transition(current: &str, new: &str) -> bool {
    // Portal users have limited status change options
    match (current, new) {
        // From open: can start working or accept risk
        ("open", "in_progress") => true,
        ("open", "accepted_risk") => true,
        // From in_progress: can request verification, accept risk, or mark resolved
        ("in_progress", "pending_verification") => true,
        ("in_progress", "accepted_risk") => true,
        ("in_progress", "resolved") => true,
        // From pending_verification: can go back to in_progress
        ("pending_verification", "in_progress") => true,
        // Any status can be marked as accepted_risk
        (_, "accepted_risk") => true,
        _ => false,
    }
}

/// Update vulnerability status
pub async fn update_status(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UpdateStatusRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let vuln_id = path.into_inner();
    let new_status = body.status.to_lowercase();

    // Validate status is allowed for portal users
    if !PORTAL_ALLOWED_STATUSES.contains(&new_status.as_str()) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid status. Allowed values: {:?}", PORTAL_ALLOWED_STATUSES)
        })));
    }

    // Verify vulnerability belongs to customer
    let current: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT vt.status, sr.customer_id
        FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE vt.id = ?
        "#
    )
    .bind(&vuln_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch vulnerability: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let (current_status, customer_id) = match current {
        Some((status, cid)) => (status, cid),
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Vulnerability not found"
            })));
        }
    };

    // Verify customer ownership
    if customer_id != claims.customer_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied"
        })));
    }

    // Validate status transition
    if !is_valid_portal_status_transition(&current_status, &new_status) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Cannot transition from '{}' to '{}'", current_status, new_status)
        })));
    }

    let now = Utc::now().to_rfc3339();

    // Update vulnerability status
    let mut update_sql = "UPDATE vulnerability_tracking SET status = ?, updated_at = ?".to_string();

    // Set resolved_at if transitioning to resolved
    if new_status == "resolved" {
        update_sql.push_str(", resolved_at = ?");
    }
    update_sql.push_str(" WHERE id = ?");

    if new_status == "resolved" {
        sqlx::query(&update_sql)
            .bind(&new_status)
            .bind(&now)
            .bind(&now) // resolved_at
            .bind(&vuln_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to update vulnerability status: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to update status")
            })?;
    } else {
        sqlx::query(&update_sql)
            .bind(&new_status)
            .bind(&now)
            .bind(&vuln_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to update vulnerability status: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to update status")
            })?;
    }

    // Create timeline event
    let timeline_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
        VALUES (?, ?, ?, 'portal_status_change', ?, ?, ?, ?)
        "#
    )
    .bind(&timeline_id)
    .bind(&vuln_id)
    .bind(format!("portal:{}", claims.sub))
    .bind(&current_status)
    .bind(&new_status)
    .bind(&body.comment)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .ok(); // Don't fail if timeline insert fails

    // If there's a comment, also add it as a separate comment
    if let Some(comment) = &body.comment {
        if !comment.trim().is_empty() {
            let comment_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO vulnerability_comments (id, vulnerability_tracking_id, user_id, comment, created_at)
                VALUES (?, ?, ?, ?, ?)
                "#
            )
            .bind(&comment_id)
            .bind(&vuln_id)
            .bind(format!("portal:{}", claims.sub))
            .bind(comment)
            .bind(&now)
            .execute(pool.get_ref())
            .await
            .ok();
        }
    }

    log::info!(
        "Portal user {} updated vulnerability {} status from '{}' to '{}'",
        claims.email, vuln_id, current_status, new_status
    );

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Status updated successfully",
        "status": new_status
    })))
}

/// Get comments for a vulnerability
pub async fn get_comments(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let vuln_id = path.into_inner();

    // Verify vulnerability belongs to customer
    let exists: Option<(i32,)> = sqlx::query_as(
        r#"
        SELECT 1 FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE vt.id = ? AND sr.customer_id = ?
        "#
    )
    .bind(&vuln_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Vulnerability not found"
        })));
    }

    // Get comments with user email
    let comments: Vec<VulnerabilityComment> = sqlx::query_as(
        r#"
        SELECT
            vc.id,
            vc.vulnerability_tracking_id as vulnerability_id,
            vc.user_id,
            COALESCE(
                CASE
                    WHEN vc.user_id LIKE 'portal:%' THEN
                        (SELECT email FROM portal_users WHERE id = REPLACE(vc.user_id, 'portal:', ''))
                    ELSE
                        (SELECT username FROM users WHERE id = vc.user_id)
                END,
                'Unknown'
            ) as user_email,
            vc.comment,
            vc.created_at
        FROM vulnerability_comments vc
        WHERE vc.vulnerability_tracking_id = ?
        ORDER BY vc.created_at ASC
        "#
    )
    .bind(&vuln_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "comments": comments
    })))
}

/// Add a comment to a vulnerability
pub async fn add_comment(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<AddCommentRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let vuln_id = path.into_inner();

    // Validate comment
    if body.comment.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Comment cannot be empty"
        })));
    }

    // Verify vulnerability belongs to customer
    let exists: Option<(i32,)> = sqlx::query_as(
        r#"
        SELECT 1 FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE vt.id = ? AND sr.customer_id = ?
        "#
    )
    .bind(&vuln_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    if exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Vulnerability not found"
        })));
    }

    let now = Utc::now().to_rfc3339();
    let comment_id = Uuid::new_v4().to_string();
    let portal_user_id = format!("portal:{}", claims.sub);

    // Insert comment
    sqlx::query(
        r#"
        INSERT INTO vulnerability_comments (id, vulnerability_tracking_id, user_id, comment, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#
    )
    .bind(&comment_id)
    .bind(&vuln_id)
    .bind(&portal_user_id)
    .bind(&body.comment)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to add comment: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add comment")
    })?;

    // Also create timeline event
    let timeline_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, comment, created_at)
        VALUES (?, ?, ?, 'portal_comment', ?, ?)
        "#
    )
    .bind(&timeline_id)
    .bind(&vuln_id)
    .bind(&portal_user_id)
    .bind(&body.comment)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .ok();

    log::info!(
        "Portal user {} added comment to vulnerability {}",
        claims.email, vuln_id
    );

    Ok(HttpResponse::Created().json(VulnerabilityComment {
        id: comment_id,
        vulnerability_id: vuln_id,
        user_id: portal_user_id,
        user_email: claims.email,
        comment: body.comment.clone(),
        created_at: now,
    }))
}
