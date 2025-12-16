use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;

use crate::db::{self, models};
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
