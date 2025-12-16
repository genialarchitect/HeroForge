use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use sqlx::SqlitePool;

use crate::db::{self, models};
use crate::notifications::{NotificationEvent, Notifier, SlackNotifier, TeamsNotifier};
use crate::web::auth;

/// Get notification settings for the current user
pub async fn get_notification_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let settings = db::get_notification_settings(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch notification settings: {}", e);
            actix_web::error::ErrorInternalServerError("An internal error occurred. Please try again later.")
        })?;

    Ok(HttpResponse::Ok().json(settings))
}

/// Update notification settings for the current user
pub async fn update_notification_settings(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<models::UpdateNotificationSettingsRequest>,
) -> Result<HttpResponse> {
    let updated_settings = db::update_notification_settings(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update notification settings: {}", e);
            actix_web::error::ErrorInternalServerError("Update failed. Please try again.")
        })?;

    Ok(HttpResponse::Ok().json(updated_settings))
}

/// Test Slack webhook integration
pub async fn test_slack_webhook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let settings = db::get_notification_settings(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch notification settings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch settings")
        })?;

    let webhook_url = settings.slack_webhook_url.ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Slack webhook URL not configured")
    })?;

    let notifier = SlackNotifier::new(webhook_url);
    notifier
        .send_test_message()
        .await
        .map_err(|e| {
            log::error!("Failed to send Slack test message: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Failed to send test message: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "message": "Test message sent successfully to Slack"
    })))
}

/// Test Microsoft Teams webhook integration
pub async fn test_teams_webhook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let settings = db::get_notification_settings(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch notification settings: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch settings")
        })?;

    let webhook_url = settings.teams_webhook_url.ok_or_else(|| {
        actix_web::error::ErrorBadRequest("Teams webhook URL not configured")
    })?;

    let notifier = TeamsNotifier::new(webhook_url);
    notifier
        .send_test_message()
        .await
        .map_err(|e| {
            log::error!("Failed to send Teams test message: {}", e);
            actix_web::error::ErrorInternalServerError(format!("Failed to send test message: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(json!({
        "success": true,
        "message": "Test message sent successfully to Microsoft Teams"
    })))
}
