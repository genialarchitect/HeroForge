//! Campaign API handlers
//!
//! Provides REST API endpoints for assessment campaign management including:
//! - List, get, create, update, delete campaigns
//! - Get campaign progress

use actix_web::{web, HttpResponse, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::compliance::manual_assessment::{AssessmentCampaign, CampaignProgress, CampaignStatus};
use crate::compliance::types::ComplianceFramework;
use crate::web::auth;

use super::types::{
    CampaignListQuery, CampaignListResponse, CampaignRow, CreateCampaignRequest,
    UpdateCampaignRequest,
};

/// GET /api/compliance/campaigns
/// List all campaigns
#[utoipa::path(
    get,
    path = "/api/compliance/campaigns",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("status" = Option<String>, Query, description = "Filter by status (draft, active, completed, archived)")
    ),
    responses(
        (status = 200, description = "List of campaigns"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_campaigns(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    query: web::Query<CampaignListQuery>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;

    let campaigns = match &query.status {
        Some(status) => {
            sqlx::query_as::<_, CampaignRow>(
                r#"
                SELECT id, user_id, name, description, frameworks, due_date,
                       status, created_at, updated_at
                FROM assessment_campaigns
                WHERE user_id = ?1 AND status = ?2
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .bind(status)
            .fetch_all(pool.get_ref())
            .await
        }
        None => {
            sqlx::query_as::<_, CampaignRow>(
                r#"
                SELECT id, user_id, name, description, frameworks, due_date,
                       status, created_at, updated_at
                FROM assessment_campaigns
                WHERE user_id = ?1
                ORDER BY created_at DESC
                "#,
            )
            .bind(user_id)
            .fetch_all(pool.get_ref())
            .await
        }
    }
    .map_err(|e| {
        log::error!("Failed to fetch campaigns: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaigns")
    })?;

    let campaigns: Vec<AssessmentCampaign> = campaigns.into_iter().map(|c| c.into()).collect();
    let total = campaigns.len();

    Ok(HttpResponse::Ok().json(CampaignListResponse { campaigns, total }))
}

/// GET /api/compliance/campaigns/{id}
/// Get a specific campaign by ID
#[utoipa::path(
    get,
    path = "/api/compliance/campaigns/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign details"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    let campaign = sqlx::query_as::<_, CampaignRow>(
        r#"
        SELECT id, user_id, name, description, frameworks, due_date,
               status, created_at, updated_at
        FROM assessment_campaigns
        WHERE id = ?1
        "#,
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
    })?;

    match campaign {
        Some(c) if c.user_id == *user_id => Ok(HttpResponse::Ok().json(AssessmentCampaign::from(c))),
        Some(_) => Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to view this campaign"
        }))),
        None => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Campaign not found"
        }))),
    }
}

/// POST /api/compliance/campaigns
/// Create a new campaign
#[utoipa::path(
    post,
    path = "/api/compliance/campaigns",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    request_body = CreateCampaignRequest,
    responses(
        (status = 201, description = "Campaign created"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn create_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<CreateCampaignRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let now = Utc::now();
    let campaign_id = Uuid::new_v4().to_string();

    // Validate frameworks
    for framework_id in &request.frameworks {
        if ComplianceFramework::from_id(framework_id).is_none() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid framework ID: {}", framework_id)
            })));
        }
    }

    let frameworks_json = serde_json::to_string(&request.frameworks)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid frameworks: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO assessment_campaigns (
            id, user_id, name, description, frameworks, due_date,
            status, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&campaign_id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&frameworks_json)
    .bind(request.due_date)
    .bind("draft")
    .bind(now)
    .bind(now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to create campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create campaign")
    })?;

    let campaign = AssessmentCampaign {
        id: campaign_id,
        user_id: user_id.clone(),
        name: request.name.clone(),
        description: request.description.clone(),
        frameworks: request.frameworks.clone(),
        due_date: request.due_date,
        status: CampaignStatus::Draft,
        created_at: now,
        updated_at: now,
    };

    Ok(HttpResponse::Created().json(campaign))
}

/// PUT /api/compliance/campaigns/{id}
/// Update a campaign
#[utoipa::path(
    put,
    path = "/api/compliance/campaigns/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    request_body = UpdateCampaignRequest,
    responses(
        (status = 200, description = "Campaign updated"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn update_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
    request: web::Json<UpdateCampaignRequest>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    // Fetch existing campaign
    let existing = sqlx::query_as::<_, CampaignRow>(
        r#"
        SELECT id, user_id, name, description, frameworks, due_date,
               status, created_at, updated_at
        FROM assessment_campaigns
        WHERE id = ?1
        "#,
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
    })?;

    let existing = match existing {
        Some(c) => c,
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Campaign not found"
            })));
        }
    };

    if existing.user_id != *user_id {
        return Ok(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Not authorized to modify this campaign"
        })));
    }

    let now = Utc::now();
    let mut campaign: AssessmentCampaign = existing.into();

    // Apply updates
    if let Some(name) = &request.name {
        campaign.name = name.clone();
    }
    if let Some(description) = &request.description {
        campaign.description = Some(description.clone());
    }
    if let Some(frameworks) = &request.frameworks {
        // Validate frameworks
        for framework_id in frameworks {
            if ComplianceFramework::from_id(framework_id).is_none() {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid framework ID: {}", framework_id)
                })));
            }
        }
        campaign.frameworks = frameworks.clone();
    }
    if let Some(due_date) = request.due_date {
        campaign.due_date = Some(due_date);
    }
    if let Some(status) = &request.status {
        campaign.status = status.clone();
    }
    campaign.updated_at = now;

    let frameworks_json = serde_json::to_string(&campaign.frameworks)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid frameworks: {}", e)))?;
    let status_str = serde_json::to_string(&campaign.status)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid status: {}", e)))?;

    sqlx::query(
        r#"
        UPDATE assessment_campaigns
        SET name = ?1, description = ?2, frameworks = ?3, due_date = ?4,
            status = ?5, updated_at = ?6
        WHERE id = ?7
        "#,
    )
    .bind(&campaign.name)
    .bind(&campaign.description)
    .bind(&frameworks_json)
    .bind(campaign.due_date)
    .bind(&status_str)
    .bind(now)
    .bind(&campaign_id)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to update campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to update campaign")
    })?;

    Ok(HttpResponse::Ok().json(campaign))
}

/// DELETE /api/compliance/campaigns/{id}
/// Delete a campaign
#[utoipa::path(
    delete,
    path = "/api/compliance/campaigns/{id}",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_campaign(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    // Check ownership
    let existing =
        sqlx::query_as::<_, (String,)>("SELECT user_id FROM assessment_campaigns WHERE id = ?1")
            .bind(&campaign_id)
            .fetch_optional(pool.get_ref())
            .await
            .map_err(|e| {
                log::error!("Failed to fetch campaign: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
            })?;

    match existing {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Campaign not found"
            })));
        }
        Some((owner_id,)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to delete this campaign"
            })));
        }
        _ => {}
    }

    sqlx::query("DELETE FROM assessment_campaigns WHERE id = ?1")
        .bind(&campaign_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete campaign: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete campaign")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Campaign deleted successfully"
    })))
}

/// GET /api/compliance/campaigns/{id}/progress
/// Get progress for a campaign
#[utoipa::path(
    get,
    path = "/api/compliance/campaigns/{id}/progress",
    tag = "Manual Compliance",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Campaign ID")
    ),
    responses(
        (status = 200, description = "Campaign progress"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Campaign not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_campaign_progress(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    campaign_id: web::Path<String>,
) -> Result<HttpResponse> {
    let user_id = &claims.sub;
    let campaign_id = campaign_id.into_inner();

    // Verify ownership and get frameworks
    let campaign = sqlx::query_as::<_, (String, String)>(
        "SELECT user_id, frameworks FROM assessment_campaigns WHERE id = ?1",
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch campaign: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to fetch campaign")
    })?;

    let (owner_id, frameworks_json) = match campaign {
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Campaign not found"
            })));
        }
        Some((owner_id, _)) if owner_id != *user_id => {
            return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "error": "Not authorized to view this campaign"
            })));
        }
        Some(c) => c,
    };

    let _ = owner_id; // Suppress unused variable warning

    // Parse frameworks
    let frameworks: Vec<String> = serde_json::from_str(&frameworks_json).unwrap_or_default();

    // Calculate total controls across all frameworks
    let mut total_controls = 0usize;
    for framework_id in &frameworks {
        if let Some(framework) = ComplianceFramework::from_id(framework_id) {
            total_controls += crate::compliance::frameworks::get_controls(framework).len();
        }
    }

    // Count assessments by status for this user and campaign frameworks
    let stats = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT review_status, COUNT(*) as count
        FROM manual_assessments
        WHERE user_id = ?1 AND framework_id IN (SELECT value FROM json_each(?2))
        GROUP BY review_status
        "#,
    )
    .bind(user_id)
    .bind(&frameworks_json)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to fetch assessment stats: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to calculate progress")
    })?;

    let mut assessed = 0usize;
    let mut pending_review = 0usize;
    let mut approved = 0usize;

    for (status, count) in stats {
        let count = count as usize;
        assessed += count;
        match status.as_str() {
            "pending_review" => pending_review = count,
            "approved" => approved = count,
            _ => {}
        }
    }

    let progress = CampaignProgress::new(total_controls, assessed, pending_review, approved);

    Ok(HttpResponse::Ok().json(progress))
}
