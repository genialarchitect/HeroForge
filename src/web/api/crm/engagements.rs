//! Engagement API endpoints

use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::db::crm::{
    self, CreateEngagementRequest, UpdateEngagementRequest,
    CreateMilestoneRequest, UpdateMilestoneRequest,
};
use crate::web::auth::Claims;
use crate::web::error::{ApiErrorKind, bad_request, forbidden, not_found, internal_error, unauthorized};

#[derive(Debug, Deserialize)]
pub struct ListEngagementsQuery {
    pub status: Option<String>,
}

/// Extract claims from request or return Unauthorized error
fn get_claims(req: &HttpRequest) -> Result<Claims, ApiErrorKind> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| unauthorized("Unauthorized"))
}

/// Verify customer ownership
async fn verify_customer_ownership(
    pool: &SqlitePool,
    customer_id: &str,
    user_id: &str,
) -> Result<(), ApiErrorKind> {
    let customer = crm::get_customer_by_id(pool, customer_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Customer not found")
            } else {
                log::error!("Failed to verify customer: {}", e);
                internal_error("Failed to verify customer")
            }
        })?;

    if customer.user_id != user_id {
        return Err(forbidden("Access denied"));
    }

    Ok(())
}

/// Verify ownership via customer for an entity with a customer_id
async fn verify_ownership_via_customer(
    pool: &SqlitePool,
    customer_id: &str,
    user_id: &str,
) -> Result<(), ApiErrorKind> {
    crm::get_customer_by_id(pool, customer_id)
        .await
        .map_err(|_| forbidden("Access denied"))
        .and_then(|customer| {
            if customer.user_id != user_id {
                Err(forbidden("Access denied"))
            } else {
                Ok(())
            }
        })
}

/// List all engagements for the authenticated user
pub async fn list_engagements(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    query: web::Query<ListEngagementsQuery>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;

    let engagements = crm::get_all_engagements(pool.get_ref(), &claims.sub, query.status.as_deref())
        .await
        .map_err(|e| {
            log::error!("Failed to list engagements: {}", e);
            internal_error("Failed to list engagements")
        })?;

    Ok(HttpResponse::Ok().json(engagements))
}

/// List engagements for a specific customer
pub async fn list_customer_engagements(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    query: web::Query<ListEngagementsQuery>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    verify_customer_ownership(pool.get_ref(), &customer_id, &claims.sub).await?;

    let engagements = crm::get_customer_engagements(pool.get_ref(), &customer_id, query.status.as_deref())
        .await
        .map_err(|e| {
            log::error!("Failed to list engagements: {}", e);
            internal_error("Failed to list engagements")
        })?;

    Ok(HttpResponse::Ok().json(engagements))
}

/// Create an engagement for a customer
pub async fn create_engagement(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateEngagementRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let customer_id = path.into_inner();

    verify_customer_ownership(pool.get_ref(), &customer_id, &claims.sub).await?;

    if body.name.trim().is_empty() {
        return Err(bad_request("Engagement name is required"));
    }

    let engagement = crm::create_engagement(pool.get_ref(), &customer_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to create engagement: {}", e);
            internal_error("Failed to create engagement")
        })?;

    Ok(HttpResponse::Created().json(engagement))
}

/// Get a specific engagement
pub async fn get_engagement(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let engagement_id = path.into_inner();

    let engagement = crm::get_engagement_by_id(pool.get_ref(), &engagement_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Engagement not found")
            } else {
                log::error!("Failed to get engagement: {}", e);
                internal_error("Failed to get engagement")
            }
        })?;

    verify_ownership_via_customer(pool.get_ref(), &engagement.customer_id, &claims.sub).await?;

    Ok(HttpResponse::Ok().json(engagement))
}

/// Update an engagement
pub async fn update_engagement(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateEngagementRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let engagement_id = path.into_inner();

    // Get existing engagement to verify ownership
    let engagement = crm::get_engagement_by_id(pool.get_ref(), &engagement_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Engagement not found")
            } else {
                log::error!("Failed to get engagement: {}", e);
                internal_error("Failed to get engagement")
            }
        })?;

    verify_ownership_via_customer(pool.get_ref(), &engagement.customer_id, &claims.sub).await?;

    let updated_engagement = crm::update_engagement(pool.get_ref(), &engagement_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to update engagement: {}", e);
            internal_error("Failed to update engagement")
        })?;

    Ok(HttpResponse::Ok().json(updated_engagement))
}

/// Delete an engagement
pub async fn delete_engagement(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let engagement_id = path.into_inner();

    // Get existing engagement to verify ownership
    let engagement = crm::get_engagement_by_id(pool.get_ref(), &engagement_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Engagement not found")
            } else {
                log::error!("Failed to get engagement: {}", e);
                internal_error("Failed to get engagement")
            }
        })?;

    verify_ownership_via_customer(pool.get_ref(), &engagement.customer_id, &claims.sub).await?;

    crm::delete_engagement(pool.get_ref(), &engagement_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete engagement: {}", e);
            internal_error("Failed to delete engagement")
        })?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Milestone endpoints
// ============================================================================

/// Verify ownership via engagement -> customer chain
async fn verify_ownership_via_engagement(
    pool: &SqlitePool,
    engagement_id: &str,
    user_id: &str,
) -> Result<crm::Engagement, ApiErrorKind> {
    let engagement = crm::get_engagement_by_id(pool, engagement_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Engagement not found")
            } else {
                log::error!("Failed to get engagement: {}", e);
                internal_error("Failed to get engagement")
            }
        })?;

    verify_ownership_via_customer(pool, &engagement.customer_id, user_id).await?;

    Ok(engagement)
}

/// List milestones for an engagement
pub async fn list_milestones(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let engagement_id = path.into_inner();

    verify_ownership_via_engagement(pool.get_ref(), &engagement_id, &claims.sub).await?;

    let milestones = crm::get_engagement_milestones(pool.get_ref(), &engagement_id)
        .await
        .map_err(|e| {
            log::error!("Failed to list milestones: {}", e);
            internal_error("Failed to list milestones")
        })?;

    Ok(HttpResponse::Ok().json(milestones))
}

/// Create a milestone for an engagement
pub async fn create_milestone(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<CreateMilestoneRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let engagement_id = path.into_inner();

    verify_ownership_via_engagement(pool.get_ref(), &engagement_id, &claims.sub).await?;

    if body.name.trim().is_empty() {
        return Err(bad_request("Milestone name is required"));
    }

    let milestone = crm::create_milestone(pool.get_ref(), &engagement_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to create milestone: {}", e);
            internal_error("Failed to create milestone")
        })?;

    Ok(HttpResponse::Created().json(milestone))
}

/// Update a milestone
pub async fn update_milestone(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<UpdateMilestoneRequest>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let milestone_id = path.into_inner();

    // Get milestone to verify ownership
    let milestone = crm::get_milestone_by_id(pool.get_ref(), &milestone_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Milestone not found")
            } else {
                log::error!("Failed to get milestone: {}", e);
                internal_error("Failed to get milestone")
            }
        })?;

    // Verify ownership via engagement -> customer
    let engagement = crm::get_engagement_by_id(pool.get_ref(), &milestone.engagement_id)
        .await
        .map_err(|_| forbidden("Access denied"))?;

    verify_ownership_via_customer(pool.get_ref(), &engagement.customer_id, &claims.sub).await?;

    let updated_milestone = crm::update_milestone(pool.get_ref(), &milestone_id, body.into_inner())
        .await
        .map_err(|e| {
            log::error!("Failed to update milestone: {}", e);
            internal_error("Failed to update milestone")
        })?;

    Ok(HttpResponse::Ok().json(updated_milestone))
}

/// Delete a milestone
pub async fn delete_milestone(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiErrorKind> {
    let claims = get_claims(&req)?;
    let milestone_id = path.into_inner();

    // Get milestone to verify ownership
    let milestone = crm::get_milestone_by_id(pool.get_ref(), &milestone_id)
        .await
        .map_err(|e| {
            if e.to_string().contains("no rows") {
                not_found("Milestone not found")
            } else {
                log::error!("Failed to get milestone: {}", e);
                internal_error("Failed to get milestone")
            }
        })?;

    // Verify ownership via engagement -> customer
    let engagement = crm::get_engagement_by_id(pool.get_ref(), &milestone.engagement_id)
        .await
        .map_err(|_| forbidden("Access denied"))?;

    verify_ownership_via_customer(pool.get_ref(), &engagement.customer_id, &claims.sub).await?;

    crm::delete_milestone(pool.get_ref(), &milestone_id)
        .await
        .map_err(|e| {
            log::error!("Failed to delete milestone: {}", e);
            internal_error("Failed to delete milestone")
        })?;

    Ok(HttpResponse::NoContent().finish())
}
