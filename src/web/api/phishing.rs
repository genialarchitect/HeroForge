//! Phishing Campaign API Endpoints
//!
//! REST API for managing phishing campaigns, email templates, landing pages,
//! and tracking.

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::phishing::{
    types::*, CampaignManager, EmailSender, Tracker, WebsiteCloner, TRACKING_PIXEL,
};
use crate::web::auth;
use crate::web::error::ApiError;

/// Configure phishing routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/phishing")
            // Campaign management
            .route("/campaigns", web::post().to(create_campaign))
            .route("/campaigns", web::get().to(list_campaigns))
            .route("/campaigns/{id}", web::get().to(get_campaign))
            .route("/campaigns/{id}", web::put().to(update_campaign))
            .route("/campaigns/{id}", web::delete().to(delete_campaign))
            .route("/campaigns/{id}/launch", web::post().to(launch_campaign))
            .route("/campaigns/{id}/pause", web::post().to(pause_campaign))
            .route("/campaigns/{id}/resume", web::post().to(resume_campaign))
            .route("/campaigns/{id}/complete", web::post().to(complete_campaign))
            .route("/campaigns/{id}/stats", web::get().to(get_campaign_stats))
            .route("/campaigns/{id}/targets", web::get().to(list_campaign_targets))
            .route("/campaigns/{id}/targets", web::post().to(add_campaign_targets))
            .route("/campaigns/{id}/credentials", web::get().to(list_captured_credentials))
            // Email templates
            .route("/templates", web::post().to(create_email_template))
            .route("/templates", web::get().to(list_email_templates))
            .route("/templates/{id}", web::get().to(get_email_template))
            .route("/templates/{id}", web::put().to(update_email_template))
            .route("/templates/{id}", web::delete().to(delete_email_template))
            // Landing pages
            .route("/landing-pages", web::post().to(create_landing_page))
            .route("/landing-pages", web::get().to(list_landing_pages))
            .route("/landing-pages/{id}", web::get().to(get_landing_page))
            .route("/landing-pages/{id}", web::put().to(update_landing_page))
            .route("/landing-pages/{id}", web::delete().to(delete_landing_page))
            .route("/landing-pages/clone", web::post().to(clone_website))
            // SMTP profiles
            .route("/smtp-profiles", web::post().to(create_smtp_profile))
            .route("/smtp-profiles", web::get().to(list_smtp_profiles))
            .route("/smtp-profiles/{id}", web::get().to(get_smtp_profile))
            .route("/smtp-profiles/{id}", web::put().to(update_smtp_profile))
            .route("/smtp-profiles/{id}", web::delete().to(delete_smtp_profile))
            .route("/smtp-profiles/{id}/test", web::post().to(test_smtp_profile))
            // Target groups
            .route("/target-groups", web::post().to(create_target_group))
            .route("/target-groups", web::get().to(list_target_groups))
            .route("/target-groups/{id}", web::get().to(get_target_group))
            .route("/target-groups/{id}", web::delete().to(delete_target_group)),
    );
}

/// Configure public tracking routes (no auth required)
/// These routes are prefixed with /t/ for phishing tracking endpoints
pub fn configure_tracking(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/t")
            // Tracking pixel (email opens)
            .route("/p/{tracking_id}.png", web::get().to(track_open))
            // Click tracking
            .route("/c/{tracking_id}", web::get().to(track_click))
            // Credential submission
            .route("/submit", web::post().to(submit_credentials))
            // Report phish
            .route("/r/{tracking_id}", web::get().to(report_phish)),
    );
}

// ============================================================================
// Campaign Endpoints
// ============================================================================

async fn create_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.create_campaign(&claims.sub, body.into_inner()).await?;

    Ok(HttpResponse::Created().json(campaign))
}

async fn list_campaigns(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let campaigns = sqlx::query_as::<_, (
        String, String, String, i64, i64, i64, i64, i64, i64,
        Option<String>, String,
    )>(
        r#"
        SELECT
            c.id, c.name, c.status,
            (SELECT COUNT(*) FROM phishing_targets WHERE campaign_id = c.id) as total_targets,
            (SELECT COUNT(*) FROM phishing_targets WHERE campaign_id = c.id AND email_sent_at IS NOT NULL) as emails_sent,
            (SELECT COUNT(*) FROM phishing_targets WHERE campaign_id = c.id AND email_opened_at IS NOT NULL) as emails_opened,
            (SELECT COUNT(*) FROM phishing_targets WHERE campaign_id = c.id AND link_clicked_at IS NOT NULL) as links_clicked,
            (SELECT COUNT(*) FROM phishing_targets WHERE campaign_id = c.id AND credentials_submitted_at IS NOT NULL) as credentials_captured,
            (SELECT COUNT(*) FROM phishing_targets WHERE campaign_id = c.id AND reported_at IS NOT NULL) as reported_phish,
            c.launch_date, c.created_at
        FROM phishing_campaigns c
        WHERE c.user_id = ?
        ORDER BY c.created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(&claims.sub)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await?;

    let summaries: Vec<CampaignSummary> = campaigns.into_iter().map(|r| {
        CampaignSummary {
            id: r.0,
            name: r.1,
            status: r.2.parse().unwrap_or(CampaignStatus::Draft),
            total_targets: r.3 as u32,
            emails_sent: r.4 as u32,
            emails_opened: r.5 as u32,
            links_clicked: r.6 as u32,
            credentials_captured: r.7 as u32,
            reported_phish: r.8 as u32,
            launch_date: r.9.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.10).unwrap().with_timezone(&Utc),
        }
    }).collect();

    Ok(HttpResponse::Ok().json(summaries))
}

async fn get_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(campaign))
}

async fn update_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<UpdateCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Check ownership
    let campaign = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let now = Utc::now();
    let req = body.into_inner();

    sqlx::query(
        r#"
        UPDATE phishing_campaigns SET
            name = COALESCE(?, name),
            description = COALESCE(?, description),
            email_template_id = COALESCE(?, email_template_id),
            landing_page_id = COALESCE(?, landing_page_id),
            smtp_profile_id = COALESCE(?, smtp_profile_id),
            tracking_domain = COALESCE(?, tracking_domain),
            awareness_training = COALESCE(?, awareness_training),
            training_url = COALESCE(?, training_url),
            launch_date = COALESCE(?, launch_date),
            end_date = COALESCE(?, end_date),
            updated_at = ?
        WHERE id = ?
        "#
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.email_template_id)
    .bind(&req.landing_page_id)
    .bind(&req.smtp_profile_id)
    .bind(&req.tracking_domain)
    .bind(req.awareness_training)
    .bind(&req.training_url)
    .bind(req.launch_date.map(|d| d.to_rfc3339()))
    .bind(req.end_date.map(|d| d.to_rfc3339()))
    .bind(now.to_rfc3339())
    .bind(&campaign_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

async fn delete_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Check ownership
    let campaign = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM phishing_campaigns WHERE id = ?")
        .bind(&campaign_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn launch_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.launch_campaign(&campaign_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "launched"})))
}

async fn pause_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.pause_campaign(&campaign_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "paused"})))
}

async fn resume_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.resume_campaign(&campaign_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "resumed"})))
}

async fn complete_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.complete_campaign(&campaign_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "completed"})))
}

async fn get_campaign_stats(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let stats = manager.get_statistics(&campaign_id).await?;

    Ok(HttpResponse::Ok().json(stats))
}

async fn list_campaign_targets(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Check ownership
    let campaign = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let targets = sqlx::query_as::<_, (
        String, String, String, Option<String>, Option<String>,
        Option<String>, Option<String>, String, String,
        Option<String>, Option<String>, Option<String>,
        Option<String>, Option<String>, String,
    )>(
        r#"
        SELECT id, campaign_id, email, first_name, last_name,
               position, department, tracking_id, status,
               email_sent_at, email_opened_at, link_clicked_at,
               credentials_submitted_at, reported_at, created_at
        FROM phishing_targets WHERE campaign_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(&campaign_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<PhishingTarget> = targets.into_iter().map(|r| PhishingTarget {
        id: r.0,
        campaign_id: r.1,
        email: r.2,
        first_name: r.3,
        last_name: r.4,
        position: r.5,
        department: r.6,
        tracking_id: r.7,
        status: r.8.parse().unwrap_or(TargetStatus::Pending),
        email_sent_at: r.9.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        email_opened_at: r.10.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        link_clicked_at: r.11.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        credentials_submitted_at: r.12.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        reported_at: r.13.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        created_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn add_campaign_targets(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<Vec<CreateTargetRequest>>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let mut targets = Vec::new();
    for target in body.into_inner() {
        let t = manager.add_target(&campaign_id, &target).await?;
        targets.push(t);
    }

    Ok(HttpResponse::Created().json(targets))
}

async fn list_captured_credentials(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Check ownership
    let campaign = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let credentials = sqlx::query_as::<_, (
        String, String, String, Option<String>, String, String, Option<String>, String,
    )>(
        r#"
        SELECT id, campaign_id, target_id, landing_page_id, fields,
               ip_address, user_agent, created_at
        FROM phishing_captured_credentials WHERE campaign_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&campaign_id)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<CapturedCredential> = credentials.into_iter().map(|r| {
        let fields: std::collections::HashMap<String, String> = serde_json::from_str(&r.4).unwrap_or_default();
        CapturedCredential {
            id: r.0,
            campaign_id: r.1,
            target_id: r.2,
            landing_page_id: r.3.unwrap_or_default(),
            fields,
            ip_address: r.5,
            user_agent: r.6,
            created_at: chrono::DateTime::parse_from_rfc3339(&r.7).unwrap().with_timezone(&Utc),
        }
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

// ============================================================================
// Email Template Endpoints
// ============================================================================

async fn create_email_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateEmailTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let req = body.into_inner();
    let attachments_json = serde_json::to_string(&req.attachments.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON serialization error: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO phishing_email_templates (
            id, user_id, name, subject, html_body, text_body,
            from_name, from_email, envelope_sender, attachments,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&req.subject)
    .bind(&req.html_body)
    .bind(&req.text_body)
    .bind(&req.from_name)
    .bind(&req.from_email)
    .bind(&req.envelope_sender)
    .bind(&attachments_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "created_at": now
    })))
}

async fn list_email_templates(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let templates = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        r#"
        SELECT id, name, subject, from_name, from_email, created_at
        FROM phishing_email_templates WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = templates.into_iter().map(|r| {
        serde_json::json!({
            "id": r.0,
            "name": r.1,
            "subject": r.2,
            "from_name": r.3,
            "from_email": r.4,
            "created_at": r.5
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn get_email_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let template = manager.get_email_template(&template_id).await?
        .ok_or_else(|| ApiError::not_found("Template not found".to_string()))?;

    if template.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(template))
}

async fn update_email_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<CreateEmailTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Check ownership
    let template = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_email_templates WHERE id = ?"
    )
    .bind(&template_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Template not found".to_string()))?;

    if template.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();
    let attachments_json = serde_json::to_string(&req.attachments.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON serialization error: {}", e)))?;

    sqlx::query(
        r#"
        UPDATE phishing_email_templates SET
            name = ?, subject = ?, html_body = ?, text_body = ?,
            from_name = ?, from_email = ?, envelope_sender = ?,
            attachments = ?, updated_at = ?
        WHERE id = ?
        "#
    )
    .bind(&req.name)
    .bind(&req.subject)
    .bind(&req.html_body)
    .bind(&req.text_body)
    .bind(&req.from_name)
    .bind(&req.from_email)
    .bind(&req.envelope_sender)
    .bind(&attachments_json)
    .bind(Utc::now().to_rfc3339())
    .bind(&template_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

async fn delete_email_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Check ownership
    let template = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_email_templates WHERE id = ?"
    )
    .bind(&template_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Template not found".to_string()))?;

    if template.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM phishing_email_templates WHERE id = ?")
        .bind(&template_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Landing Page Endpoints
// ============================================================================

async fn create_landing_page(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateLandingPageRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let req = body.into_inner();
    let capture_fields_json = serde_json::to_string(&req.capture_fields)
        .map_err(|e| ApiError::bad_request(format!("JSON serialization error: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO phishing_landing_pages (
            id, user_id, name, html_content, capture_credentials,
            capture_fields, redirect_url, redirect_delay,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&req.html_content)
    .bind(req.capture_credentials)
    .bind(&capture_fields_json)
    .bind(&req.redirect_url)
    .bind(req.redirect_delay.unwrap_or(0) as i64)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "created_at": now
    })))
}

async fn list_landing_pages(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let pages = sqlx::query_as::<_, (String, String, bool, Option<String>, String)>(
        r#"
        SELECT id, name, capture_credentials, cloned_from, created_at
        FROM phishing_landing_pages WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = pages.into_iter().map(|r| {
        serde_json::json!({
            "id": r.0,
            "name": r.1,
            "capture_credentials": r.2,
            "cloned_from": r.3,
            "created_at": r.4
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn get_landing_page(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let page_id = path.into_inner();

    let row = sqlx::query_as::<_, (
        String, String, String, String, bool, String,
        Option<String>, i64, Option<String>, String, String,
    )>(
        r#"
        SELECT id, user_id, name, html_content, capture_credentials,
               capture_fields, redirect_url, redirect_delay, cloned_from,
               created_at, updated_at
        FROM phishing_landing_pages WHERE id = ?
        "#,
    )
    .bind(&page_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Landing page not found".to_string()))?;

    if row.1 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let capture_fields: Vec<String> = serde_json::from_str(&row.5).unwrap_or_default();

    Ok(HttpResponse::Ok().json(LandingPage {
        id: row.0,
        user_id: row.1,
        name: row.2,
        html_content: row.3,
        capture_credentials: row.4,
        capture_fields,
        redirect_url: row.6,
        redirect_delay: row.7 as u32,
        cloned_from: row.8,
        created_at: chrono::DateTime::parse_from_rfc3339(&row.9).unwrap().with_timezone(&Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&row.10).unwrap().with_timezone(&Utc),
    }))
}

async fn update_landing_page(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<CreateLandingPageRequest>,
) -> Result<HttpResponse, ApiError> {
    let page_id = path.into_inner();

    // Check ownership
    let page = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_landing_pages WHERE id = ?"
    )
    .bind(&page_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Landing page not found".to_string()))?;

    if page.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();
    let capture_fields_json = serde_json::to_string(&req.capture_fields)
        .map_err(|e| ApiError::bad_request(format!("JSON serialization error: {}", e)))?;

    sqlx::query(
        r#"
        UPDATE phishing_landing_pages SET
            name = ?, html_content = ?, capture_credentials = ?,
            capture_fields = ?, redirect_url = ?, redirect_delay = ?,
            updated_at = ?
        WHERE id = ?
        "#
    )
    .bind(&req.name)
    .bind(&req.html_content)
    .bind(req.capture_credentials)
    .bind(&capture_fields_json)
    .bind(&req.redirect_url)
    .bind(req.redirect_delay.unwrap_or(0) as i64)
    .bind(Utc::now().to_rfc3339())
    .bind(&page_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

async fn delete_landing_page(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let page_id = path.into_inner();

    // Check ownership
    let page = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_landing_pages WHERE id = ?"
    )
    .bind(&page_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Landing page not found".to_string()))?;

    if page.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM phishing_landing_pages WHERE id = ?")
        .bind(&page_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn clone_website(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CloneRequest>,
) -> Result<HttpResponse, ApiError> {
    let cloner = WebsiteCloner::new();
    let req = body.into_inner();

    let cloned = cloner.clone_website(
        &req.url,
        req.capture_credentials,
        &req.capture_fields,
        req.redirect_url.as_deref(),
    ).await?;

    // Save as a landing page
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let capture_fields_json = serde_json::to_string(&cloned.capture_fields)
        .map_err(|e| ApiError::bad_request(format!("JSON serialization error: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO phishing_landing_pages (
            id, user_id, name, html_content, capture_credentials,
            capture_fields, redirect_url, redirect_delay, cloned_from,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&cloned.html)
    .bind(req.capture_credentials)
    .bind(&capture_fields_json)
    .bind(&req.redirect_url)
    .bind(0i64)
    .bind(&cloned.original_url)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "cloned_from": cloned.original_url,
        "created_at": now
    })))
}

// ============================================================================
// SMTP Profile Endpoints
// ============================================================================

async fn create_smtp_profile(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateSmtpProfileRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let req = body.into_inner();

    sqlx::query(
        r#"
        INSERT INTO phishing_smtp_profiles (
            id, user_id, name, host, port, username, password,
            use_tls, use_starttls, from_address, ignore_cert_errors,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&req.host)
    .bind(req.port as i64)
    .bind(&req.username)
    .bind(&req.password)
    .bind(req.use_tls.unwrap_or(false))
    .bind(req.use_starttls.unwrap_or(true))
    .bind(&req.from_address)
    .bind(req.ignore_cert_errors.unwrap_or(false))
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "created_at": now
    })))
}

async fn list_smtp_profiles(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let profiles = sqlx::query_as::<_, (String, String, String, i64, String, String)>(
        r#"
        SELECT id, name, host, port, from_address, created_at
        FROM phishing_smtp_profiles WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = profiles.into_iter().map(|r| {
        serde_json::json!({
            "id": r.0,
            "name": r.1,
            "host": r.2,
            "port": r.3,
            "from_address": r.4,
            "created_at": r.5
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn get_smtp_profile(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let profile_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender);

    let profile = manager.get_smtp_profile(&profile_id).await?
        .ok_or_else(|| ApiError::not_found("SMTP profile not found".to_string()))?;

    if profile.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    // Don't return the password
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": profile.id,
        "name": profile.name,
        "host": profile.host,
        "port": profile.port,
        "username": profile.username,
        "use_tls": profile.use_tls,
        "use_starttls": profile.use_starttls,
        "from_address": profile.from_address,
        "ignore_cert_errors": profile.ignore_cert_errors,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at
    })))
}

async fn update_smtp_profile(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<CreateSmtpProfileRequest>,
) -> Result<HttpResponse, ApiError> {
    let profile_id = path.into_inner();

    // Check ownership
    let profile = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_smtp_profiles WHERE id = ?"
    )
    .bind(&profile_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("SMTP profile not found".to_string()))?;

    if profile.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();

    sqlx::query(
        r#"
        UPDATE phishing_smtp_profiles SET
            name = ?, host = ?, port = ?, username = ?, password = COALESCE(?, password),
            use_tls = ?, use_starttls = ?, from_address = ?, ignore_cert_errors = ?,
            updated_at = ?
        WHERE id = ?
        "#
    )
    .bind(&req.name)
    .bind(&req.host)
    .bind(req.port as i64)
    .bind(&req.username)
    .bind(&req.password)
    .bind(req.use_tls.unwrap_or(false))
    .bind(req.use_starttls.unwrap_or(true))
    .bind(&req.from_address)
    .bind(req.ignore_cert_errors.unwrap_or(false))
    .bind(Utc::now().to_rfc3339())
    .bind(&profile_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

async fn delete_smtp_profile(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let profile_id = path.into_inner();

    // Check ownership
    let profile = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_smtp_profiles WHERE id = ?"
    )
    .bind(&profile_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("SMTP profile not found".to_string()))?;

    if profile.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM phishing_smtp_profiles WHERE id = ?")
        .bind(&profile_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn test_smtp_profile(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<TestSmtpRequest>,
) -> Result<HttpResponse, ApiError> {
    let profile_id = path.into_inner();
    let sender = EmailSender::new();
    let manager = CampaignManager::new(pool.get_ref().clone(), sender.clone());

    let profile = manager.get_smtp_profile(&profile_id).await?
        .ok_or_else(|| ApiError::not_found("SMTP profile not found".to_string()))?;

    if profile.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    match sender.send_test_email(&profile, &body.to_email).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Test email sent successfully"
        }))),
        Err(e) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "message": e.to_string()
        }))),
    }
}

// ============================================================================
// Target Group Endpoints
// ============================================================================

async fn create_target_group(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateTargetGroupRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let req = body.into_inner();
    let targets_json = serde_json::to_string(&req.targets)
        .map_err(|e| ApiError::bad_request(format!("JSON serialization error: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO phishing_target_groups (
            id, user_id, name, description, targets, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&targets_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": id,
        "name": req.name,
        "target_count": req.targets.len(),
        "created_at": now
    })))
}

async fn list_target_groups(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let groups = sqlx::query_as::<_, (String, String, Option<String>, String, String)>(
        r#"
        SELECT id, name, description, targets, created_at
        FROM phishing_target_groups WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = groups.into_iter().map(|r| {
        let targets: Vec<serde_json::Value> = serde_json::from_str(&r.3).unwrap_or_default();
        serde_json::json!({
            "id": r.0,
            "name": r.1,
            "description": r.2,
            "target_count": targets.len(),
            "created_at": r.4
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn get_target_group(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let group_id = path.into_inner();

    let row = sqlx::query_as::<_, (String, String, String, Option<String>, String, String, String)>(
        r#"
        SELECT id, user_id, name, description, targets, created_at, updated_at
        FROM phishing_target_groups WHERE id = ?
        "#,
    )
    .bind(&group_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Target group not found".to_string()))?;

    if row.1 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let targets: Vec<TargetImport> = serde_json::from_str(&row.4).unwrap_or_default();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": row.0,
        "name": row.2,
        "description": row.3,
        "targets": targets,
        "created_at": row.5,
        "updated_at": row.6
    })))
}

async fn delete_target_group(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let group_id = path.into_inner();

    // Check ownership
    let group = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM phishing_target_groups WHERE id = ?"
    )
    .bind(&group_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Target group not found".to_string()))?;

    if group.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM phishing_target_groups WHERE id = ?")
        .bind(&group_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Tracking Endpoints (Public)
// ============================================================================

async fn track_open(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let tracking_id = path.into_inner().trim_end_matches(".png").to_string();
    let tracker = Tracker::new(pool.get_ref().clone());

    let ip = req.connection_info().realip_remote_addr()
        .map(|s| s.to_string());
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    tracker.record_open(&tracking_id, ip.as_deref(), user_agent.as_deref()).await?;

    // Return 1x1 transparent PNG
    Ok(HttpResponse::Ok()
        .content_type("image/png")
        .insert_header(("Cache-Control", "no-cache, no-store, must-revalidate"))
        .body(TRACKING_PIXEL.to_vec()))
}

async fn track_click(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let tracking_id = path.into_inner();
    let tracker = Tracker::new(pool.get_ref().clone());

    let ip = req.connection_info().realip_remote_addr()
        .map(|s| s.to_string());
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Check for training mode
    if let Ok(Some(training_url)) = tracker.should_redirect_to_training(&tracking_id).await {
        return Ok(HttpResponse::Found()
            .insert_header(("Location", training_url))
            .finish());
    }

    // Record click and get landing page
    match tracker.record_click(&tracking_id, ip.as_deref(), user_agent.as_deref()).await? {
        Some((target, Some(landing_page))) => {
            // Render landing page with tracking ID
            let html = landing_page.html_content
                .replace("{{.TrackingID}}", &tracking_id)
                .replace("${TrackingID}", &tracking_id)
                .replace("{{.FirstName}}", target.first_name.as_deref().unwrap_or(""))
                .replace("${FirstName}", target.first_name.as_deref().unwrap_or(""))
                .replace("{{.LastName}}", target.last_name.as_deref().unwrap_or(""))
                .replace("${LastName}", target.last_name.as_deref().unwrap_or(""))
                .replace("{{.Email}}", &target.email)
                .replace("${Email}", &target.email);

            Ok(HttpResponse::Ok()
                .content_type("text/html")
                .body(html))
        }
        Some((_, None)) => {
            // No landing page configured, return simple message
            Ok(HttpResponse::Ok()
                .content_type("text/html")
                .body("<html><body><h1>Thank you</h1></body></html>"))
        }
        None => {
            // Unknown tracking ID
            Ok(HttpResponse::NotFound().finish())
        }
    }
}

async fn submit_credentials(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    form: web::Form<std::collections::HashMap<String, String>>,
) -> Result<HttpResponse, ApiError> {
    let mut fields = form.into_inner();
    let tracking_id = fields.remove("__tracking_id").unwrap_or_default();
    let redirect_url = fields.remove("__redirect_url");
    fields.remove("__timestamp"); // Remove internal fields

    if tracking_id.is_empty() {
        return Ok(HttpResponse::BadRequest().finish());
    }

    let tracker = Tracker::new(pool.get_ref().clone());

    let ip = req.connection_info().realip_remote_addr()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Check for training mode
    if let Ok(Some(training_url)) = tracker.should_redirect_to_training(&tracking_id).await {
        // Still record the submission for metrics
        tracker.record_credential_submission(
            &tracking_id,
            fields,
            &ip,
            user_agent.as_deref(),
        ).await?;

        return Ok(HttpResponse::Found()
            .insert_header(("Location", training_url))
            .finish());
    }

    // Record credentials
    tracker.record_credential_submission(
        &tracking_id,
        fields,
        &ip,
        user_agent.as_deref(),
    ).await?;

    // Redirect to configured URL or show thank you page
    if let Some(url) = redirect_url {
        Ok(HttpResponse::Found()
            .insert_header(("Location", url))
            .finish())
    } else {
        Ok(HttpResponse::Ok()
            .content_type("text/html")
            .body("<html><body><h1>Thank you</h1><p>Your information has been received.</p></body></html>"))
    }
}

async fn report_phish(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let tracking_id = path.into_inner();
    let tracker = Tracker::new(pool.get_ref().clone());

    let ip = req.connection_info().realip_remote_addr()
        .map(|s| s.to_string());
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    tracker.record_phish_report(&tracking_id, ip.as_deref(), user_agent.as_deref()).await?;

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body("<html><body><h1>Thank you for reporting!</h1><p>This was a simulated phishing test. Your vigilance helps keep our organization safe.</p></body></html>"))
}

// ============================================================================
// Helper Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCampaignRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub email_template_id: Option<String>,
    pub landing_page_id: Option<String>,
    pub smtp_profile_id: Option<String>,
    pub tracking_domain: Option<String>,
    pub awareness_training: Option<bool>,
    pub training_url: Option<String>,
    pub launch_date: Option<chrono::DateTime<Utc>>,
    pub end_date: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct TestSmtpRequest {
    pub to_email: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTargetGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub targets: Vec<TargetImport>,
}
