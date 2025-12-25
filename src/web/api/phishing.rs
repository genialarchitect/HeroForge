//! Phishing Campaign API Endpoints
//!
//! REST API for managing phishing campaigns, email templates, landing pages,
//! QR code phishing (quishing), and tracking.

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::Deserialize;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::phishing::{
    types::*, CampaignManager, EmailSender, Tracker, WebsiteCloner, TRACKING_PIXEL,
    qrcode::{
        QrCodeGenerator, CreateQrCampaignRequest, GenerateQrCodeRequest, UpdateQrCampaignRequest,
        QrCampaignStatus,
    },
    pretexts::{
        PretextCategory, PretextLibrary, PretextTemplate, CreatePretextRequest, PretextScript,
        PretextDifficulty,
    },
    vishing::{
        VishingManager, VishingCampaignStatus, CreateVishingCampaignRequest,
        CreateVishingTargetRequest, CreateVishingScriptRequest, LogCallRequest,
    },
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
            .route("/target-groups/{id}", web::delete().to(delete_target_group))
            // QR Code phishing (quishing)
            .route("/qr/generate", web::post().to(generate_qr_code))
            .route("/qr/campaigns", web::post().to(create_qr_campaign))
            .route("/qr/campaigns", web::get().to(list_qr_campaigns))
            .route("/qr/campaigns/{id}", web::get().to(get_qr_campaign))
            .route("/qr/campaigns/{id}", web::put().to(update_qr_campaign))
            .route("/qr/campaigns/{id}", web::delete().to(delete_qr_campaign))
            .route("/qr/campaigns/{id}/activate", web::post().to(activate_qr_campaign))
            .route("/qr/campaigns/{id}/pause", web::post().to(pause_qr_campaign))
            .route("/qr/campaigns/{id}/complete", web::post().to(complete_qr_campaign))
            .route("/qr/campaigns/{id}/assets", web::get().to(list_qr_assets))
            .route("/qr/campaigns/{id}/assets", web::post().to(create_qr_asset))
            .route("/qr/campaigns/{id}/stats", web::get().to(get_qr_campaign_stats))
            .route("/qr/assets/{id}", web::get().to(get_qr_asset))
            .route("/qr/assets/{id}/image", web::get().to(get_qr_asset_image))
            // Pretexting templates
            .route("/pretexts/templates", web::get().to(list_pretext_templates))
            .route("/pretexts/templates/{id}", web::get().to(get_pretext_template))
            .route("/pretexts/categories", web::get().to(list_pretext_categories))
            .route("/pretexts/custom", web::post().to(create_custom_pretext))
            .route("/pretexts/custom/{id}", web::put().to(update_custom_pretext))
            .route("/pretexts/custom/{id}", web::delete().to(delete_custom_pretext))
            // Vishing campaigns
            .route("/vishing/campaigns", web::post().to(create_vishing_campaign))
            .route("/vishing/campaigns", web::get().to(list_vishing_campaigns))
            .route("/vishing/campaigns/{id}", web::get().to(get_vishing_campaign))
            .route("/vishing/campaigns/{id}", web::put().to(update_vishing_campaign))
            .route("/vishing/campaigns/{id}", web::delete().to(delete_vishing_campaign))
            .route("/vishing/campaigns/{id}/activate", web::post().to(activate_vishing_campaign))
            .route("/vishing/campaigns/{id}/pause", web::post().to(pause_vishing_campaign))
            .route("/vishing/campaigns/{id}/complete", web::post().to(complete_vishing_campaign))
            .route("/vishing/campaigns/{id}/targets", web::get().to(list_vishing_targets))
            .route("/vishing/campaigns/{id}/targets", web::post().to(add_vishing_targets))
            .route("/vishing/campaigns/{id}/logs", web::get().to(list_vishing_call_logs))
            .route("/vishing/{id}/log", web::post().to(log_vishing_call))
            .route("/vishing/stats", web::get().to(get_vishing_stats))
            .route("/vishing/stats/{campaign_id}", web::get().to(get_vishing_campaign_stats))
            // Vishing scripts
            .route("/vishing/scripts", web::post().to(create_vishing_script))
            .route("/vishing/scripts", web::get().to(list_vishing_scripts))
            .route("/vishing/scripts/{id}", web::get().to(get_vishing_script))
            .route("/vishing/scripts/{id}", web::put().to(update_vishing_script))
            .route("/vishing/scripts/{id}", web::delete().to(delete_vishing_script)),
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
            .route("/r/{tracking_id}", web::get().to(report_phish))
            // QR code scan tracking
            .route("/q/{tracking_id}", web::get().to(track_qr_scan)),
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
// QR Code Phishing (Quishing) Endpoints
// ============================================================================

/// Generate a standalone QR code (without campaign)
async fn generate_qr_code(
    pool: web::Data<SqlitePool>,
    _claims: auth::Claims,
    body: web::Json<GenerateQrCodeRequest>,
) -> Result<HttpResponse, ApiError> {
    let generator = QrCodeGenerator::new(pool.get_ref().clone());
    let config = body.config.clone().unwrap_or_default();

    // Build content based on template type
    let content = match body.template_type.as_ref() {
        Some(crate::phishing::qrcode::QrCodeTemplateType::WiFi) => {
            let ssid = body.wifi_ssid.as_deref()
                .ok_or_else(|| ApiError::bad_request("WiFi SSID required for WiFi template".to_string()))?;
            QrCodeGenerator::build_wifi_content(
                ssid,
                body.wifi_password.as_deref(),
                body.wifi_security.as_deref(),
                body.wifi_hidden.unwrap_or(false),
            )
        }
        Some(crate::phishing::qrcode::QrCodeTemplateType::VCard) => {
            let name = body.vcard_name.as_deref()
                .ok_or_else(|| ApiError::bad_request("Name required for vCard template".to_string()))?;
            QrCodeGenerator::build_vcard_content(
                name,
                body.vcard_phone.as_deref(),
                body.vcard_email.as_deref(),
                body.vcard_org.as_deref(),
            )
        }
        _ => body.content.clone(),
    };

    let output = generator.generate_qr_code(&content, &config)
        .map_err(|e| ApiError::internal(format!("Failed to generate QR code: {}", e)))?;

    match config.format {
        crate::phishing::qrcode::QrCodeFormat::Svg => {
            Ok(HttpResponse::Ok()
                .content_type("image/svg+xml")
                .body(output.data))
        }
        crate::phishing::qrcode::QrCodeFormat::Png => {
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &output.data,
            ).map_err(|e| ApiError::internal(format!("Failed to decode PNG: {}", e)))?;
            Ok(HttpResponse::Ok()
                .content_type("image/png")
                .body(bytes))
        }
        _ => {
            // Base64 formats return as JSON
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "format": output.format.to_string(),
                "data": output.data,
            })))
        }
    }
}

/// Create a new QR code campaign
async fn create_qr_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateQrCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let generator = QrCodeGenerator::new(pool.get_ref().clone());
    let campaign = generator.create_campaign(&claims.sub, body.into_inner()).await?;
    Ok(HttpResponse::Created().json(campaign))
}

/// List QR code campaigns for the user
async fn list_qr_campaigns(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let generator = QrCodeGenerator::new(pool.get_ref().clone());
    let campaigns = generator.list_campaigns(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(campaigns))
}

/// Get a QR code campaign by ID
async fn get_qr_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(campaign))
}

/// Update a QR code campaign
async fn update_qr_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<UpdateQrCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    generator.update_campaign(&campaign_id, body.into_inner()).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

/// Delete a QR code campaign
async fn delete_qr_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    generator.delete_campaign(&campaign_id).await?;

    Ok(HttpResponse::NoContent().finish())
}

/// Activate a QR code campaign
async fn activate_qr_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    generator.update_campaign_status(&campaign_id, QrCampaignStatus::Active).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "active"})))
}

/// Pause a QR code campaign
async fn pause_qr_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    generator.update_campaign_status(&campaign_id, QrCampaignStatus::Paused).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "paused"})))
}

/// Complete a QR code campaign
async fn complete_qr_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    generator.update_campaign_status(&campaign_id, QrCampaignStatus::Completed).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "completed"})))
}

/// List QR code assets for a campaign
async fn list_qr_assets(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let assets = generator.list_assets(&campaign_id).await?;

    Ok(HttpResponse::Ok().json(assets))
}

/// Create a new QR code asset for a campaign
async fn create_qr_asset(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<GenerateQrCodeRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let asset = generator.generate_asset(&campaign_id, body.into_inner()).await?;

    Ok(HttpResponse::Created().json(asset))
}

/// Get QR code campaign statistics
async fn get_qr_campaign_stats(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let campaign = generator.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("QR campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let stats = generator.get_campaign_statistics(&campaign_id).await?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Get a QR code asset by ID
async fn get_qr_asset(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    let row = sqlx::query_as::<_, (
        String, String, String, String, String, String,
        Option<String>, Option<String>, Option<String>, Option<String>, String,
    )>(
        r#"
        SELECT a.id, a.campaign_id, a.tracking_id, a.tracking_url, a.content_data,
               a.format, a.image_data, a.target_email, a.target_name, a.metadata, a.created_at
        FROM qr_assets a
        JOIN qr_campaigns c ON a.campaign_id = c.id
        WHERE a.id = ? AND c.user_id = ?
        "#,
    )
    .bind(&asset_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("QR asset not found".to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": row.0,
        "campaign_id": row.1,
        "tracking_id": row.2,
        "tracking_url": row.3,
        "content_data": row.4,
        "format": row.5,
        "image_data": row.6,
        "target_email": row.7,
        "target_name": row.8,
        "metadata": row.9.and_then(|m| serde_json::from_str::<serde_json::Value>(&m).ok()),
        "created_at": row.10,
    })))
}

/// Get QR code image for an asset
async fn get_qr_asset_image(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let asset_id = path.into_inner();

    let row = sqlx::query_as::<_, (String, Option<String>)>(
        r#"
        SELECT a.format, a.image_data
        FROM qr_assets a
        JOIN qr_campaigns c ON a.campaign_id = c.id
        WHERE a.id = ? AND c.user_id = ?
        "#,
    )
    .bind(&asset_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("QR asset not found".to_string()))?;

    let image_data = row.1
        .ok_or_else(|| ApiError::not_found("QR image data not found".to_string()))?;

    let format: crate::phishing::qrcode::QrCodeFormat = row.0.parse().unwrap_or_default();

    match format {
        crate::phishing::qrcode::QrCodeFormat::Svg | crate::phishing::qrcode::QrCodeFormat::Base64Svg => {
            let svg = if format == crate::phishing::qrcode::QrCodeFormat::Base64Svg {
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &image_data,
                ).map_err(|e| ApiError::internal(format!("Failed to decode SVG: {}", e)))?;
                String::from_utf8(bytes)
                    .map_err(|e| ApiError::internal(format!("Invalid SVG: {}", e)))?
            } else {
                image_data
            };
            Ok(HttpResponse::Ok()
                .content_type("image/svg+xml")
                .body(svg))
        }
        _ => {
            // PNG format - decode base64
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &image_data,
            ).map_err(|e| ApiError::internal(format!("Failed to decode PNG: {}", e)))?;
            Ok(HttpResponse::Ok()
                .content_type("image/png")
                .body(bytes))
        }
    }
}

/// Track QR code scan (public endpoint)
async fn track_qr_scan(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let tracking_id = path.into_inner();
    let generator = QrCodeGenerator::new(pool.get_ref().clone());

    let ip = req.connection_info().realip_remote_addr()
        .map(|s| s.to_string());
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    match generator.record_scan(&tracking_id, ip.as_deref(), user_agent.as_deref()).await? {
        Some((_asset, Some(redirect_url))) => {
            // Redirect to landing page or training URL
            if redirect_url.starts_with('/') {
                // Relative URL - treat as click tracking
                Ok(HttpResponse::Found()
                    .insert_header(("Location", format!("/t{}", redirect_url)))
                    .finish())
            } else {
                Ok(HttpResponse::Found()
                    .insert_header(("Location", redirect_url))
                    .finish())
            }
        }
        Some((_asset, None)) => {
            // No redirect configured - show thank you page
            Ok(HttpResponse::Ok()
                .content_type("text/html")
                .body("<html><body><h1>Thank you</h1><p>QR code scanned successfully.</p></body></html>"))
        }
        None => {
            // Unknown tracking ID
            Ok(HttpResponse::NotFound()
                .content_type("text/html")
                .body("<html><body><h1>Not Found</h1></body></html>"))
        }
    }
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

#[derive(Debug, Deserialize)]
pub struct UpdateVishingCampaignRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub script_id: Option<String>,
    pub pretext_template_id: Option<String>,
    pub caller_id: Option<String>,
    pub start_date: Option<chrono::DateTime<Utc>>,
    pub end_date: Option<chrono::DateTime<Utc>>,
    pub target_organization: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateVishingScriptRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<PretextCategory>,
    pub difficulty: Option<PretextDifficulty>,
    pub persona: Option<String>,
    pub caller_id: Option<String>,
    pub script: Option<PretextScript>,
}

#[derive(Debug, Deserialize)]
pub struct PretextFilterQuery {
    pub category: Option<String>,
    pub difficulty: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Pretexting Template Endpoints
// ============================================================================

/// List all pretext templates (built-in + custom)
async fn list_pretext_templates(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<PretextFilterQuery>,
) -> Result<HttpResponse, ApiError> {
    // Get built-in templates
    let mut templates = PretextLibrary::get_all();

    // Filter by category if specified
    if let Some(ref cat) = query.category {
        if let Ok(category) = cat.parse::<PretextCategory>() {
            templates.retain(|t| t.category == category);
        }
    }

    // Filter by difficulty if specified
    if let Some(ref diff) = query.difficulty {
        if let Ok(difficulty) = diff.parse::<PretextDifficulty>() {
            templates.retain(|t| t.difficulty == difficulty);
        }
    }

    // Filter by search term if specified
    if let Some(ref search) = query.search {
        let search_lower = search.to_lowercase();
        templates.retain(|t| {
            t.name.to_lowercase().contains(&search_lower)
                || t.description.to_lowercase().contains(&search_lower)
                || t.scenario.to_lowercase().contains(&search_lower)
                || t.tags.iter().any(|tag| tag.to_lowercase().contains(&search_lower))
        });
    }

    // Get custom templates from database
    let custom_templates = sqlx::query(
        r#"
        SELECT id, user_id, name, description, category, difficulty, scenario,
               objectives, script, prerequisites, success_criteria, red_flags,
               tips, tags, is_builtin, created_at, updated_at
        FROM pretext_templates
        WHERE user_id = ? OR is_builtin = 1
        ORDER BY is_builtin DESC, created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    use sqlx::Row;
    for row in custom_templates {
        let template = PretextTemplate {
            id: row.get("id"),
            user_id: row.get("user_id"),
            name: row.get("name"),
            description: row.get("description"),
            category: row.get::<String, _>("category").parse().unwrap_or(PretextCategory::Custom),
            difficulty: row.get::<String, _>("difficulty").parse().unwrap_or(PretextDifficulty::Medium),
            scenario: row.get("scenario"),
            objectives: serde_json::from_str(&row.get::<String, _>("objectives")).unwrap_or_default(),
            script: serde_json::from_str(&row.get::<String, _>("script")).unwrap_or_else(|_| PretextScript {
                opening: String::new(),
                talking_points: Vec::new(),
                objection_handling: std::collections::HashMap::new(),
                information_to_gather: Vec::new(),
                closing: String::new(),
                follow_up: None,
            }),
            prerequisites: serde_json::from_str(&row.get::<String, _>("prerequisites")).unwrap_or_default(),
            success_criteria: serde_json::from_str(&row.get::<String, _>("success_criteria")).unwrap_or_default(),
            red_flags: serde_json::from_str(&row.get::<String, _>("red_flags")).unwrap_or_default(),
            tips: serde_json::from_str(&row.get::<String, _>("tips")).unwrap_or_default(),
            tags: serde_json::from_str(&row.get::<String, _>("tags")).unwrap_or_default(),
            is_builtin: row.get("is_builtin"),
            created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
                .unwrap()
                .with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
                .unwrap()
                .with_timezone(&Utc),
        };

        // Only add if not already in built-in list
        if !templates.iter().any(|t| t.id == template.id) {
            templates.push(template);
        }
    }

    // Apply pagination
    let offset = query.offset.unwrap_or(0) as usize;
    let limit = query.limit.unwrap_or(50) as usize;
    let total = templates.len();
    let templates: Vec<_> = templates.into_iter().skip(offset).take(limit).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "templates": templates,
        "total": total,
        "offset": offset,
        "limit": limit
    })))
}

/// Get a specific pretext template by ID
async fn get_pretext_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Check built-in templates first
    if let Some(template) = PretextLibrary::get_by_id(&template_id) {
        return Ok(HttpResponse::Ok().json(template));
    }

    // Check database for custom templates
    let row = sqlx::query(
        r#"
        SELECT id, user_id, name, description, category, difficulty, scenario,
               objectives, script, prerequisites, success_criteria, red_flags,
               tips, tags, is_builtin, created_at, updated_at
        FROM pretext_templates
        WHERE id = ? AND (user_id = ? OR is_builtin = 1)
        "#,
    )
    .bind(&template_id)
    .bind(&claims.sub)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Pretext template not found".to_string()))?;

    use sqlx::Row;
    let template = PretextTemplate {
        id: row.get("id"),
        user_id: row.get("user_id"),
        name: row.get("name"),
        description: row.get("description"),
        category: row.get::<String, _>("category").parse().unwrap_or(PretextCategory::Custom),
        difficulty: row.get::<String, _>("difficulty").parse().unwrap_or(PretextDifficulty::Medium),
        scenario: row.get("scenario"),
        objectives: serde_json::from_str(&row.get::<String, _>("objectives")).unwrap_or_default(),
        script: serde_json::from_str(&row.get::<String, _>("script")).unwrap_or_else(|_| PretextScript {
            opening: String::new(),
            talking_points: Vec::new(),
            objection_handling: std::collections::HashMap::new(),
            information_to_gather: Vec::new(),
            closing: String::new(),
            follow_up: None,
        }),
        prerequisites: serde_json::from_str(&row.get::<String, _>("prerequisites")).unwrap_or_default(),
        success_criteria: serde_json::from_str(&row.get::<String, _>("success_criteria")).unwrap_or_default(),
        red_flags: serde_json::from_str(&row.get::<String, _>("red_flags")).unwrap_or_default(),
        tips: serde_json::from_str(&row.get::<String, _>("tips")).unwrap_or_default(),
        tags: serde_json::from_str(&row.get::<String, _>("tags")).unwrap_or_default(),
        is_builtin: row.get("is_builtin"),
        created_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("created_at"))
            .unwrap()
            .with_timezone(&Utc),
        updated_at: chrono::DateTime::parse_from_rfc3339(&row.get::<String, _>("updated_at"))
            .unwrap()
            .with_timezone(&Utc),
    };

    Ok(HttpResponse::Ok().json(template))
}

/// List all available pretext categories
async fn list_pretext_categories(
    _claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let categories = vec![
        serde_json::json!({
            "id": "it_support",
            "name": "IT Support",
            "description": "IT help desk and technical support pretexts"
        }),
        serde_json::json!({
            "id": "human_resources",
            "name": "Human Resources",
            "description": "HR-related pretexts (benefits, policies, surveys)"
        }),
        serde_json::json!({
            "id": "executive",
            "name": "Executive",
            "description": "CEO/CFO fraud and executive impersonation"
        }),
        serde_json::json!({
            "id": "vendor",
            "name": "Vendor",
            "description": "Third-party vendor and supplier pretexts"
        }),
        serde_json::json!({
            "id": "tech_support",
            "name": "Tech Support",
            "description": "External tech support scam scenarios"
        }),
        serde_json::json!({
            "id": "financial",
            "name": "Financial",
            "description": "Banking, tax, and financial pretexts"
        }),
        serde_json::json!({
            "id": "delivery",
            "name": "Delivery",
            "description": "Package delivery and shipping pretexts"
        }),
        serde_json::json!({
            "id": "legal",
            "name": "Legal",
            "description": "Legal and compliance-related pretexts"
        }),
        serde_json::json!({
            "id": "custom",
            "name": "Custom",
            "description": "User-created custom pretexts"
        }),
    ];

    Ok(HttpResponse::Ok().json(categories))
}

/// Create a custom pretext template
async fn create_custom_pretext(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreatePretextRequest>,
) -> Result<HttpResponse, ApiError> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let req = body.into_inner();

    let objectives_json = serde_json::to_string(&req.objectives)
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let script_json = serde_json::to_string(&req.script)
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let prerequisites_json = serde_json::to_string(&req.prerequisites.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let success_json = serde_json::to_string(&req.success_criteria.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let red_flags_json = serde_json::to_string(&req.red_flags.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let tips_json = serde_json::to_string(&req.tips.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let tags_json = serde_json::to_string(&req.tags.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;

    sqlx::query(
        r#"
        INSERT INTO pretext_templates (
            id, user_id, name, description, category, difficulty, scenario,
            objectives, script, prerequisites, success_criteria, red_flags,
            tips, tags, is_builtin, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&claims.sub)
    .bind(&req.name)
    .bind(&req.description)
    .bind(req.category.to_string())
    .bind(req.difficulty.unwrap_or(PretextDifficulty::Medium).to_string())
    .bind(&req.scenario)
    .bind(&objectives_json)
    .bind(&script_json)
    .bind(&prerequisites_json)
    .bind(&success_json)
    .bind(&red_flags_json)
    .bind(&tips_json)
    .bind(&tags_json)
    .bind(false)
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

/// Update a custom pretext template
async fn update_custom_pretext(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<CreatePretextRequest>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Check ownership and that it's not a built-in
    let template = sqlx::query_as::<_, (String, bool)>(
        "SELECT user_id, is_builtin FROM pretext_templates WHERE id = ?"
    )
    .bind(&template_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Template not found".to_string()))?;

    if template.1 {
        return Err(ApiError::forbidden("Cannot modify built-in templates".to_string()));
    }

    if template.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();
    let now = Utc::now();

    let objectives_json = serde_json::to_string(&req.objectives)
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let script_json = serde_json::to_string(&req.script)
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let prerequisites_json = serde_json::to_string(&req.prerequisites.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let success_json = serde_json::to_string(&req.success_criteria.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let red_flags_json = serde_json::to_string(&req.red_flags.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let tips_json = serde_json::to_string(&req.tips.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;
    let tags_json = serde_json::to_string(&req.tags.unwrap_or_default())
        .map_err(|e| ApiError::bad_request(format!("JSON error: {}", e)))?;

    sqlx::query(
        r#"
        UPDATE pretext_templates SET
            name = ?, description = ?, category = ?, difficulty = ?, scenario = ?,
            objectives = ?, script = ?, prerequisites = ?, success_criteria = ?,
            red_flags = ?, tips = ?, tags = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(req.category.to_string())
    .bind(req.difficulty.unwrap_or(PretextDifficulty::Medium).to_string())
    .bind(&req.scenario)
    .bind(&objectives_json)
    .bind(&script_json)
    .bind(&prerequisites_json)
    .bind(&success_json)
    .bind(&red_flags_json)
    .bind(&tips_json)
    .bind(&tags_json)
    .bind(now.to_rfc3339())
    .bind(&template_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

/// Delete a custom pretext template
async fn delete_custom_pretext(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Check ownership and that it's not a built-in
    let template = sqlx::query_as::<_, (String, bool)>(
        "SELECT user_id, is_builtin FROM pretext_templates WHERE id = ?"
    )
    .bind(&template_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Template not found".to_string()))?;

    if template.1 {
        return Err(ApiError::forbidden("Cannot delete built-in templates".to_string()));
    }

    if template.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM pretext_templates WHERE id = ?")
        .bind(&template_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Vishing Campaign Endpoints
// ============================================================================

/// Create a new vishing campaign
async fn create_vishing_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateVishingCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = VishingManager::new(pool.get_ref().clone());
    let campaign = manager.create_campaign(&claims.sub, body.into_inner()).await?;
    Ok(HttpResponse::Created().json(campaign))
}

/// List vishing campaigns
async fn list_vishing_campaigns(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    query: web::Query<ListQuery>,
) -> Result<HttpResponse, ApiError> {
    let manager = VishingManager::new(pool.get_ref().clone());
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);
    let campaigns = manager.list_campaigns(&claims.sub, limit, offset).await?;
    Ok(HttpResponse::Ok().json(campaigns))
}

/// Get a specific vishing campaign
async fn get_vishing_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(campaign))
}

/// Update a vishing campaign
async fn update_vishing_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<UpdateVishingCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Check ownership
    let campaign = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM vishing_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE vishing_campaigns SET
            name = COALESCE(?, name),
            description = COALESCE(?, description),
            script_id = COALESCE(?, script_id),
            pretext_template_id = COALESCE(?, pretext_template_id),
            caller_id = COALESCE(?, caller_id),
            start_date = COALESCE(?, start_date),
            end_date = COALESCE(?, end_date),
            target_organization = COALESCE(?, target_organization),
            notes = COALESCE(?, notes),
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.script_id)
    .bind(&req.pretext_template_id)
    .bind(&req.caller_id)
    .bind(req.start_date.map(|d| d.to_rfc3339()))
    .bind(req.end_date.map(|d| d.to_rfc3339()))
    .bind(&req.target_organization)
    .bind(&req.notes)
    .bind(now.to_rfc3339())
    .bind(&campaign_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

/// Delete a vishing campaign
async fn delete_vishing_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.delete_campaign(&campaign_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// Activate a vishing campaign
async fn activate_vishing_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.update_campaign_status(&campaign_id, VishingCampaignStatus::Active).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "active"})))
}

/// Pause a vishing campaign
async fn pause_vishing_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.update_campaign_status(&campaign_id, VishingCampaignStatus::Paused).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "paused"})))
}

/// Complete a vishing campaign
async fn complete_vishing_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.update_campaign_status(&campaign_id, VishingCampaignStatus::Completed).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "completed"})))
}

/// List targets for a vishing campaign
async fn list_vishing_targets(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let targets = manager.get_targets(&campaign_id).await?;
    Ok(HttpResponse::Ok().json(targets))
}

/// Add targets to a vishing campaign
async fn add_vishing_targets(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<Vec<CreateVishingTargetRequest>>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

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

/// List call logs for a vishing campaign
async fn list_vishing_call_logs(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let logs = manager.get_call_logs(&campaign_id).await?;
    Ok(HttpResponse::Ok().json(logs))
}

/// Log a vishing call outcome
async fn log_vishing_call(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<LogCallRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let log = manager.log_call(&campaign_id, Some(&claims.sub), body.into_inner()).await?;
    Ok(HttpResponse::Created().json(log))
}

/// Get overall vishing statistics
async fn get_vishing_stats(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    // Get aggregate stats across all user's campaigns
    let stats = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM vishing_campaigns WHERE user_id = ?) as total_campaigns,
            (SELECT COUNT(*) FROM vishing_targets t
             INNER JOIN vishing_campaigns c ON t.campaign_id = c.id
             WHERE c.user_id = ?) as total_targets,
            (SELECT COUNT(*) FROM vishing_call_logs l
             INNER JOIN vishing_campaigns c ON l.campaign_id = c.id
             WHERE c.user_id = ?) as total_calls,
            (SELECT COUNT(*) FROM vishing_call_logs l
             INNER JOIN vishing_campaigns c ON l.campaign_id = c.id
             WHERE c.user_id = ? AND l.outcome IN ('partial_success', 'full_success')) as successful_calls,
            (SELECT COUNT(*) FROM vishing_call_logs l
             INNER JOIN vishing_campaigns c ON l.campaign_id = c.id
             WHERE c.user_id = ? AND l.outcome = 'reported') as reported_calls
        "#,
    )
    .bind(&claims.sub)
    .bind(&claims.sub)
    .bind(&claims.sub)
    .bind(&claims.sub)
    .bind(&claims.sub)
    .fetch_one(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "total_campaigns": stats.0,
        "total_targets": stats.1,
        "total_calls": stats.2,
        "successful_calls": stats.3,
        "reported_calls": stats.4,
        "success_rate": if stats.2 > 0 { stats.3 as f32 / stats.2 as f32 * 100.0 } else { 0.0 },
        "reporting_rate": if stats.2 > 0 { stats.4 as f32 / stats.2 as f32 * 100.0 } else { 0.0 }
    })))
}

/// Get statistics for a specific vishing campaign
async fn get_vishing_campaign_stats(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("Campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let stats = manager.get_campaign_stats(&campaign_id).await?;
    Ok(HttpResponse::Ok().json(stats))
}

// ============================================================================
// Vishing Script Endpoints
// ============================================================================

/// Create a new vishing script
async fn create_vishing_script(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateVishingScriptRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = VishingManager::new(pool.get_ref().clone());
    let script = manager.create_script(&claims.sub, body.into_inner()).await?;
    Ok(HttpResponse::Created().json(script))
}

/// List vishing scripts
async fn list_vishing_scripts(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let manager = VishingManager::new(pool.get_ref().clone());
    let scripts = manager.list_scripts(&claims.sub).await?;
    Ok(HttpResponse::Ok().json(scripts))
}

/// Get a specific vishing script
async fn get_vishing_script(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let script_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let script = manager.get_script(&script_id).await?
        .ok_or_else(|| ApiError::not_found("Script not found".to_string()))?;

    // Allow access to built-in scripts or user's own scripts
    if !script.is_builtin && script.user_id.as_deref() != Some(&claims.sub) {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(script))
}

/// Update a vishing script
async fn update_vishing_script(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<UpdateVishingScriptRequest>,
) -> Result<HttpResponse, ApiError> {
    let script_id = path.into_inner();

    // Check ownership and that it's not a built-in
    let script = sqlx::query_as::<_, (Option<String>, bool)>(
        "SELECT user_id, is_builtin FROM vishing_scripts WHERE id = ?"
    )
    .bind(&script_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Script not found".to_string()))?;

    if script.1 {
        return Err(ApiError::forbidden("Cannot modify built-in scripts".to_string()));
    }

    if script.0.as_deref() != Some(&claims.sub) {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();
    let now = Utc::now();

    // Build update query dynamically based on provided fields
    let script_json = req.script.as_ref().map(|s| serde_json::to_string(s).unwrap_or_default());

    sqlx::query(
        r#"
        UPDATE vishing_scripts SET
            name = COALESCE(?, name),
            description = COALESCE(?, description),
            category = COALESCE(?, category),
            difficulty = COALESCE(?, difficulty),
            persona = COALESCE(?, persona),
            caller_id = COALESCE(?, caller_id),
            script = COALESCE(?, script),
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(req.category.as_ref().map(|c| c.to_string()))
    .bind(req.difficulty.as_ref().map(|d| d.to_string()))
    .bind(&req.persona)
    .bind(&req.caller_id)
    .bind(&script_json)
    .bind(now.to_rfc3339())
    .bind(&script_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

/// Delete a vishing script
async fn delete_vishing_script(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let script_id = path.into_inner();
    let manager = VishingManager::new(pool.get_ref().clone());

    let script = manager.get_script(&script_id).await?
        .ok_or_else(|| ApiError::not_found("Script not found".to_string()))?;

    if script.is_builtin {
        return Err(ApiError::forbidden("Cannot delete built-in scripts".to_string()));
    }

    if script.user_id.as_deref() != Some(&claims.sub) {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    manager.delete_script(&script_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
