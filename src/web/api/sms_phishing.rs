//! SMS Phishing (Smishing) API Endpoints
//!
//! REST API for managing SMS phishing campaigns, templates, Twilio configurations,
//! and tracking.
//!
//! # Security Notice
//!
//! This module is intended for:
//! - Security awareness training programs
//! - Authorized penetration testing engagements
//! - Red team assessments with proper authorization
//!
//! Unauthorized SMS phishing (smishing) is illegal. Always obtain proper authorization.

#![allow(dead_code)]

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::phishing::sms::*;
use crate::phishing::types::CampaignStatus;
use crate::web::auth;
use crate::web::error::ApiError;

/// Configure SMS phishing routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/phishing/sms")
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
            // SMS templates
            .route("/templates", web::post().to(create_template))
            .route("/templates", web::get().to(list_templates))
            .route("/templates/{id}", web::get().to(get_template))
            .route("/templates/{id}", web::put().to(update_template))
            .route("/templates/{id}", web::delete().to(delete_template))
            // Twilio configurations
            .route("/twilio-configs", web::post().to(create_twilio_config))
            .route("/twilio-configs", web::get().to(list_twilio_configs))
            .route("/twilio-configs/{id}", web::get().to(get_twilio_config))
            .route("/twilio-configs/{id}", web::put().to(update_twilio_config))
            .route("/twilio-configs/{id}", web::delete().to(delete_twilio_config))
            .route("/twilio-configs/{id}/test", web::post().to(test_twilio_config))
            // Single SMS send
            .route("/send", web::post().to(send_single_sms)),
    );
}

/// Configure public SMS tracking routes (no auth required)
/// These routes are prefixed with /s/ for SMS tracking endpoints
pub fn configure_sms_tracking(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/s")
            // Click tracking for SMS links
            .route("/{tracking_id}", web::get().to(track_sms_click)),
    );
}

// ============================================================================
// Campaign Endpoints
// ============================================================================

async fn create_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateSmsCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = SmsCampaignManager::new(pool.get_ref().clone());
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
        String, String, String, i64, i64, i64, i64, i64,
        Option<String>, String,
    )>(
        r#"
        SELECT
            c.id, c.name, c.status,
            (SELECT COUNT(*) FROM sms_targets WHERE campaign_id = c.id) as total_targets,
            (SELECT COUNT(*) FROM sms_targets WHERE campaign_id = c.id AND sent_at IS NOT NULL) as messages_sent,
            (SELECT COUNT(*) FROM sms_targets WHERE campaign_id = c.id AND delivery_status = 'delivered') as messages_delivered,
            (SELECT COUNT(*) FROM sms_targets WHERE campaign_id = c.id AND status = 'failed') as messages_failed,
            (SELECT COUNT(*) FROM sms_targets WHERE campaign_id = c.id AND clicked_at IS NOT NULL) as links_clicked,
            c.launch_date, c.created_at
        FROM sms_campaigns c
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

    let summaries: Vec<SmsCampaignSummary> = campaigns.into_iter().map(|r| {
        SmsCampaignSummary {
            id: r.0,
            name: r.1,
            status: r.2.parse().unwrap_or(CampaignStatus::Draft),
            total_targets: r.3 as u32,
            messages_sent: r.4 as u32,
            messages_delivered: r.5 as u32,
            messages_failed: r.6 as u32,
            links_clicked: r.7 as u32,
            launch_date: r.8.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: chrono::DateTime::parse_from_rfc3339(&r.9).unwrap().with_timezone(&Utc),
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
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(campaign))
}

async fn update_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<UpdateSmsCampaignRequest>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();

    // Check ownership
    let campaign = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM sms_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

    if campaign.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let now = Utc::now();
    let req = body.into_inner();

    sqlx::query(
        r#"
        UPDATE sms_campaigns SET
            name = COALESCE(?, name),
            description = COALESCE(?, description),
            template_id = COALESCE(?, template_id),
            twilio_config_id = COALESCE(?, twilio_config_id),
            tracking_domain = COALESCE(?, tracking_domain),
            awareness_training = COALESCE(?, awareness_training),
            training_url = COALESCE(?, training_url),
            launch_date = COALESCE(?, launch_date),
            end_date = COALESCE(?, end_date),
            rate_limit_per_minute = COALESCE(?, rate_limit_per_minute),
            updated_at = ?
        WHERE id = ?
        "#
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.template_id)
    .bind(&req.twilio_config_id)
    .bind(&req.tracking_domain)
    .bind(req.awareness_training)
    .bind(&req.training_url)
    .bind(req.launch_date.map(|d| d.to_rfc3339()))
    .bind(req.end_date.map(|d| d.to_rfc3339()))
    .bind(req.rate_limit_per_minute.map(|r| r as i64))
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
        "SELECT user_id FROM sms_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

    if campaign.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM sms_campaigns WHERE id = ?")
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
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

    if campaign.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    // Launch in background task to not block the request
    let pool_clone = pool.get_ref().clone();
    let campaign_id_clone = campaign_id.clone();
    tokio::spawn(async move {
        let manager = SmsCampaignManager::new(pool_clone);
        if let Err(e) = manager.launch_campaign(&campaign_id_clone).await {
            log::error!("Failed to launch SMS campaign {}: {}", campaign_id_clone, e);
        }
    });

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "launching",
        "message": "Campaign launch initiated in background"
    })))
}

async fn pause_campaign(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

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
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

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
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

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
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

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
        "SELECT user_id FROM sms_campaigns WHERE id = ?"
    )
    .bind(&campaign_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

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
        SELECT id, campaign_id, phone_number, first_name, last_name,
               company, department, tracking_id, status,
               message_sid, delivery_status, sent_at,
               delivered_at, clicked_at, created_at
        FROM sms_targets WHERE campaign_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(&campaign_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<SmsTarget> = targets.into_iter().map(|r| SmsTarget {
        id: r.0,
        campaign_id: r.1,
        phone_number: r.2,
        first_name: r.3,
        last_name: r.4,
        company: r.5,
        department: r.6,
        tracking_id: r.7,
        status: r.8.parse().unwrap_or(crate::phishing::types::TargetStatus::Pending),
        message_sid: r.9,
        delivery_status: r.10.and_then(|s| s.parse().ok()),
        sent_at: r.11.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        delivered_at: r.12.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        clicked_at: r.13.and_then(|d| chrono::DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        created_at: chrono::DateTime::parse_from_rfc3339(&r.14).unwrap().with_timezone(&Utc),
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn add_campaign_targets(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<Vec<CreateSmsTargetRequest>>,
) -> Result<HttpResponse, ApiError> {
    let campaign_id = path.into_inner();
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let campaign = manager.get_campaign(&campaign_id).await?
        .ok_or_else(|| ApiError::not_found("SMS campaign not found".to_string()))?;

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

// ============================================================================
// Template Endpoints
// ============================================================================

async fn create_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateSmsTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = SmsCampaignManager::new(pool.get_ref().clone());
    let template = manager.create_template(&claims.sub, body.into_inner()).await?;
    Ok(HttpResponse::Created().json(template))
}

async fn list_templates(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let templates = sqlx::query_as::<_, (String, String, String, String)>(
        r#"
        SELECT id, name, content, created_at
        FROM sms_templates WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = templates.into_iter().map(|r| {
        let preview = if r.2.len() > 100 {
            format!("{}...", &r.2[..100])
        } else {
            r.2.clone()
        };
        serde_json::json!({
            "id": r.0,
            "name": r.1,
            "preview": preview,
            "created_at": r.3
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn get_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let template = manager.get_template(&template_id).await?
        .ok_or_else(|| ApiError::not_found("SMS template not found".to_string()))?;

    if template.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    Ok(HttpResponse::Ok().json(template))
}

async fn update_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<CreateSmsTemplateRequest>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Check ownership
    let template = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM sms_templates WHERE id = ?"
    )
    .bind(&template_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("SMS template not found".to_string()))?;

    if template.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();

    sqlx::query(
        "UPDATE sms_templates SET name = ?, content = ?, updated_at = ? WHERE id = ?"
    )
    .bind(&req.name)
    .bind(&req.content)
    .bind(Utc::now().to_rfc3339())
    .bind(&template_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

async fn delete_template(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let template_id = path.into_inner();

    // Check ownership
    let template = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM sms_templates WHERE id = ?"
    )
    .bind(&template_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("SMS template not found".to_string()))?;

    if template.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM sms_templates WHERE id = ?")
        .bind(&template_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

// ============================================================================
// Twilio Configuration Endpoints
// ============================================================================

async fn create_twilio_config(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<CreateTwilioConfigRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = SmsCampaignManager::new(pool.get_ref().clone());
    let config = manager.create_twilio_config(&claims.sub, body.into_inner()).await?;

    // Return config without sensitive data
    Ok(HttpResponse::Created().json(serde_json::json!({
        "id": config.id,
        "name": config.name,
        "account_sid": config.account_sid,
        "from_number": config.from_number,
        "messaging_service_sid": config.messaging_service_sid,
        "rate_limit_per_second": config.rate_limit_per_second,
        "created_at": config.created_at
    })))
}

async fn list_twilio_configs(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
) -> Result<HttpResponse, ApiError> {
    let configs = sqlx::query_as::<_, (String, String, String, String, Option<String>, i64, String)>(
        r#"
        SELECT id, name, account_sid, from_number, messaging_service_sid, rate_limit_per_second, created_at
        FROM sms_twilio_configs WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(&claims.sub)
    .fetch_all(pool.get_ref())
    .await?;

    let result: Vec<serde_json::Value> = configs.into_iter().map(|r| {
        serde_json::json!({
            "id": r.0,
            "name": r.1,
            "account_sid": r.2,
            "from_number": r.3,
            "messaging_service_sid": r.4,
            "rate_limit_per_second": r.5,
            "created_at": r.6
        })
    }).collect();

    Ok(HttpResponse::Ok().json(result))
}

async fn get_twilio_config(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let config = manager.get_twilio_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("Twilio configuration not found".to_string()))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    // Don't return the auth token
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "id": config.id,
        "name": config.name,
        "account_sid": config.account_sid,
        "from_number": config.from_number,
        "messaging_service_sid": config.messaging_service_sid,
        "rate_limit_per_second": config.rate_limit_per_second,
        "created_at": config.created_at,
        "updated_at": config.updated_at
    })))
}

async fn update_twilio_config(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
    body: web::Json<UpdateTwilioConfigRequest>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();

    // Check ownership
    let config = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM sms_twilio_configs WHERE id = ?"
    )
    .bind(&config_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Twilio configuration not found".to_string()))?;

    if config.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    let req = body.into_inner();

    sqlx::query(
        r#"
        UPDATE sms_twilio_configs SET
            name = COALESCE(?, name),
            account_sid = COALESCE(?, account_sid),
            auth_token = COALESCE(?, auth_token),
            from_number = COALESCE(?, from_number),
            messaging_service_sid = COALESCE(?, messaging_service_sid),
            rate_limit_per_second = COALESCE(?, rate_limit_per_second),
            updated_at = ?
        WHERE id = ?
        "#
    )
    .bind(&req.name)
    .bind(&req.account_sid)
    .bind(&req.auth_token)
    .bind(&req.from_number)
    .bind(&req.messaging_service_sid)
    .bind(req.rate_limit_per_second.map(|r| r as i64))
    .bind(Utc::now().to_rfc3339())
    .bind(&config_id)
    .execute(pool.get_ref())
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "updated"})))
}

async fn delete_twilio_config(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();

    // Check ownership
    let config = sqlx::query_as::<_, (String,)>(
        "SELECT user_id FROM sms_twilio_configs WHERE id = ?"
    )
    .bind(&config_id)
    .fetch_optional(pool.get_ref())
    .await?
    .ok_or_else(|| ApiError::not_found("Twilio configuration not found".to_string()))?;

    if config.0 != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    sqlx::query("DELETE FROM sms_twilio_configs WHERE id = ?")
        .bind(&config_id)
        .execute(pool.get_ref())
        .await?;

    Ok(HttpResponse::NoContent().finish())
}

async fn test_twilio_config(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let config_id = path.into_inner();
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let config = manager.get_twilio_config(&config_id).await?
        .ok_or_else(|| ApiError::not_found("Twilio configuration not found".to_string()))?;

    if config.user_id != claims.sub {
        return Err(ApiError::forbidden("Access denied".to_string()));
    }

    match manager.test_twilio_config(&config_id).await {
        Ok(true) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Twilio connection successful"
        }))),
        Ok(false) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "message": "Twilio connection failed - check credentials"
        }))),
        Err(e) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": false,
            "message": e.to_string()
        }))),
    }
}

// ============================================================================
// Single SMS Send
// ============================================================================

async fn send_single_sms(
    pool: web::Data<SqlitePool>,
    claims: auth::Claims,
    body: web::Json<SendSingleSmsRequest>,
) -> Result<HttpResponse, ApiError> {
    let manager = SmsCampaignManager::new(pool.get_ref().clone());
    let result = manager.send_single_sms(&claims.sub, body.into_inner()).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message_sid": result.message_sid,
        "status": result.status.to_string(),
        "error_code": result.error_code,
        "error_message": result.error_message
    })))
}

// ============================================================================
// SMS Click Tracking (Public)
// ============================================================================

async fn track_sms_click(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let tracking_id = path.into_inner();
    let manager = SmsCampaignManager::new(pool.get_ref().clone());

    let ip = req.connection_info().realip_remote_addr()
        .map(|s| s.to_string());
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let referrer = req.headers()
        .get("referer")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Record click and check for training mode
    match manager.record_click(
        &tracking_id,
        ip.as_deref(),
        user_agent.as_deref(),
        referrer.as_deref(),
    ).await? {
        Some((_target, Some(training_url))) => {
            // Awareness training mode - redirect to training page
            Ok(HttpResponse::Found()
                .insert_header(("Location", training_url))
                .finish())
        }
        Some((_target, None)) => {
            // No training mode - show generic page
            Ok(HttpResponse::Ok()
                .content_type("text/html")
                .body(format!(r#"
                    <html>
                    <head><title>Link Visited</title></head>
                    <body>
                        <h1>Thank you for visiting</h1>
                        <p>This was a test link for security awareness training.</p>
                    </body>
                    </html>
                "#)))
        }
        None => {
            // Unknown tracking ID
            Ok(HttpResponse::NotFound().finish())
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
pub struct UpdateSmsCampaignRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub template_id: Option<String>,
    pub twilio_config_id: Option<String>,
    pub tracking_domain: Option<String>,
    pub awareness_training: Option<bool>,
    pub training_url: Option<String>,
    pub launch_date: Option<chrono::DateTime<Utc>>,
    pub end_date: Option<chrono::DateTime<Utc>>,
    pub rate_limit_per_minute: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTwilioConfigRequest {
    pub name: Option<String>,
    pub account_sid: Option<String>,
    pub auth_token: Option<String>,
    pub from_number: Option<String>,
    pub messaging_service_sid: Option<String>,
    pub rate_limit_per_second: Option<u32>,
}
