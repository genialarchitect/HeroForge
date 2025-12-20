//! Portal Engagements
//!
//! Provides access to engagements for portal users with limited write capabilities.

use actix_web::{web, HttpRequest, HttpResponse, HttpMessage, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use super::auth::PortalClaims;

/// Engagement summary for portal
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PortalEngagement {
    pub id: String,
    pub name: String,
    pub engagement_type: String,
    pub status: String,
    pub scope: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub created_at: String,
}

/// Engagement detail with milestones
#[derive(Debug, Serialize)]
pub struct PortalEngagementDetail {
    pub engagement: PortalEngagement,
    pub milestones: Vec<PortalMilestone>,
    pub scan_count: i64,
    pub vulnerability_count: i64,
}

/// Milestone for portal
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PortalMilestone {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub due_date: Option<String>,
    pub completed_at: Option<String>,
    pub status: String,
}

/// List all engagements for the customer
pub async fn list_engagements(
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

    let engagements = sqlx::query_as::<_, PortalEngagement>(
        r#"
        SELECT id, name, engagement_type, status, scope, start_date, end_date, created_at
        FROM engagements
        WHERE customer_id = ?
        ORDER BY created_at DESC
        "#
    )
    .bind(&claims.customer_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch engagements: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch engagements")
    })?;

    Ok(HttpResponse::Ok().json(engagements))
}

/// Get a specific engagement with details
pub async fn get_engagement(
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

    let engagement_id = path.into_inner();

    // Get engagement (ensuring it belongs to the customer)
    let engagement = sqlx::query_as::<_, PortalEngagement>(
        r#"
        SELECT id, name, engagement_type, status, scope, start_date, end_date, created_at
        FROM engagements
        WHERE id = ? AND customer_id = ?
        "#
    )
    .bind(&engagement_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch engagement: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch engagement")
    })?;

    let engagement = match engagement {
        Some(e) => e,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Engagement not found"
            })));
        }
    };

    // Get milestones
    let milestones = sqlx::query_as::<_, PortalMilestone>(
        r#"
        SELECT id, name, description, due_date, completed_at, status
        FROM engagement_milestones
        WHERE engagement_id = ?
        ORDER BY due_date ASC
        "#
    )
    .bind(&engagement_id)
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    // Get scan count
    let (scan_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM scan_results WHERE engagement_id = ?"
    )
    .bind(&engagement_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    // Get vulnerability count
    let (vulnerability_count,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM vulnerability_tracking vt
        JOIN scan_results sr ON vt.scan_id = sr.id
        WHERE sr.engagement_id = ?
        "#
    )
    .bind(&engagement_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    Ok(HttpResponse::Ok().json(PortalEngagementDetail {
        engagement,
        milestones,
        scan_count,
        vulnerability_count,
    }))
}

/// Get milestones for a specific engagement
pub async fn get_milestones(
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

    let engagement_id = path.into_inner();

    // Verify engagement belongs to customer
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM engagements WHERE id = ? AND customer_id = ?"
    )
    .bind(&engagement_id)
    .bind(&claims.customer_id)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or((0,));

    if count == 0 {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Engagement not found"
        })));
    }

    let milestones = sqlx::query_as::<_, PortalMilestone>(
        r#"
        SELECT id, name, description, due_date, completed_at, status
        FROM engagement_milestones
        WHERE engagement_id = ?
        ORDER BY due_date ASC
        "#
    )
    .bind(&engagement_id)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch milestones: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch milestones")
    })?;

    Ok(HttpResponse::Ok().json(milestones))
}

// ============================================================================
// Write Endpoints
// ============================================================================

/// Update milestone request
#[derive(Debug, Deserialize)]
pub struct UpdateMilestoneRequest {
    pub status: Option<String>,
}

/// Portal-allowed milestone status values
const PORTAL_ALLOWED_MILESTONE_STATUSES: [&str; 3] = ["pending", "in_progress", "completed"];

/// Update a milestone status
pub async fn update_milestone(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
    body: web::Json<UpdateMilestoneRequest>,
) -> Result<HttpResponse> {
    let claims = match req.extensions().get::<PortalClaims>() {
        Some(c) => c.clone(),
        None => {
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            })));
        }
    };

    let (engagement_id, milestone_id) = path.into_inner();

    // Validate status if provided
    if let Some(status) = &body.status {
        let status_lower = status.to_lowercase();
        if !PORTAL_ALLOWED_MILESTONE_STATUSES.contains(&status_lower.as_str()) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid status. Allowed values: {:?}", PORTAL_ALLOWED_MILESTONE_STATUSES)
            })));
        }
    }

    // Verify engagement belongs to customer
    let engagement_exists: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM engagements WHERE id = ? AND customer_id = ?"
    )
    .bind(&engagement_id)
    .bind(&claims.customer_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    if engagement_exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Engagement not found"
        })));
    }

    // Verify milestone exists and belongs to engagement
    let milestone_exists: Option<(String,)> = sqlx::query_as(
        "SELECT status FROM engagement_milestones WHERE id = ? AND engagement_id = ?"
    )
    .bind(&milestone_id)
    .bind(&engagement_id)
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    if milestone_exists.is_none() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Milestone not found"
        })));
    }

    let now = Utc::now().to_rfc3339();

    // Build update query dynamically
    if let Some(status) = &body.status {
        let status_lower = status.to_lowercase();

        // If marking as completed, also set completed_at
        if status_lower == "completed" {
            sqlx::query(
                "UPDATE engagement_milestones SET status = ?, completed_at = ? WHERE id = ?"
            )
            .bind(&status_lower)
            .bind(&now)
            .bind(&milestone_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to update milestone: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to update milestone")
            })?;
        } else {
            // If changing away from completed, clear completed_at
            sqlx::query(
                "UPDATE engagement_milestones SET status = ?, completed_at = NULL WHERE id = ?"
            )
            .bind(&status_lower)
            .bind(&milestone_id)
            .execute(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to update milestone: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to update milestone")
            })?;
        }
    }

    // Get updated milestone
    let milestone = sqlx::query_as::<_, PortalMilestone>(
        "SELECT id, name, description, due_date, completed_at, status FROM engagement_milestones WHERE id = ?"
    )
    .bind(&milestone_id)
    .fetch_one(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch updated milestone: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch milestone")
    })?;

    log::info!(
        "Portal user {} updated milestone {} in engagement {}",
        claims.email, milestone_id, engagement_id
    );

    Ok(HttpResponse::Ok().json(milestone))
}
