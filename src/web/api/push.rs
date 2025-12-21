#![allow(dead_code)]
//! Push notification device registration API endpoints
//!
//! These endpoints allow mobile apps to register and manage push notification tokens.

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db::push_tokens::{
    self, Platform, PushDeviceTokenResponse, RegisterDeviceRequest,
};
use crate::notifications::push::send_test_notification;
use crate::web::auth::jwt::Claims;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response after registering a device
#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    pub success: bool,
    pub device: PushDeviceTokenResponse,
}

/// Request to unregister a device
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UnregisterDeviceRequest {
    /// Device token to unregister (optional if using path param)
    pub device_token: Option<String>,
}

/// List devices response
#[derive(Debug, Serialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<PushDeviceTokenResponse>,
    pub count: usize,
}

/// Test notification response
#[derive(Debug, Serialize)]
pub struct TestNotificationResponse {
    pub success: bool,
    pub message: String,
    pub ticket_id: Option<String>,
}

// ============================================================================
// API Endpoints
// ============================================================================

/// Register a push notification device token
///
/// POST /api/push/register
#[utoipa::path(
    post,
    path = "/api/push/register",
    tag = "Push Notifications",
    request_body(
        content = RegisterDeviceRequest,
        description = "Device token registration data"
    ),
    responses(
        (status = 200, description = "Device registered successfully"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn register_device(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: web::Json<RegisterDeviceRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    // Validate platform
    if Platform::from_str(&req.platform).is_none() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid platform. Must be 'ios' or 'android'"
        })));
    }

    // Validate device token format
    if req.device_token.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Device token is required"
        })));
    }

    // Expo push tokens have a specific format
    if !req.device_token.starts_with("ExponentPushToken[") && !req.device_token.starts_with("ExpoPushToken[") {
        log::warn!(
            "Device token doesn't match Expo format: {}",
            &req.device_token[..req.device_token.len().min(20)]
        );
        // Still allow registration for backward compatibility
    }

    match push_tokens::register_device_token(
        pool.get_ref(),
        &claims.sub,
        &req.device_token,
        &req.platform,
        req.device_name.as_deref(),
    )
    .await
    {
        Ok(token) => {
            log::info!(
                "Registered push device for user {} (platform: {})",
                claims.sub,
                req.platform
            );

            Ok(HttpResponse::Ok().json(RegisterDeviceResponse {
                success: true,
                device: token.into(),
            }))
        }
        Err(e) => {
            log::error!("Failed to register push device: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to register device"
            })))
        }
    }
}

/// Unregister a push notification device
///
/// DELETE /api/push/unregister
#[utoipa::path(
    delete,
    path = "/api/push/unregister",
    tag = "Push Notifications",
    request_body(
        content = UnregisterDeviceRequest,
        description = "Device to unregister"
    ),
    responses(
        (status = 200, description = "Device unregistered successfully"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Device not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn unregister_device(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    req: web::Json<UnregisterDeviceRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let device_token = match &req.device_token {
        Some(token) if !token.is_empty() => token,
        _ => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Device token is required"
            })));
        }
    };

    match push_tokens::unregister_device_by_token(pool.get_ref(), &claims.sub, device_token).await {
        Ok(true) => {
            log::info!("Unregistered push device for user {}", claims.sub);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Device unregistered successfully"
            })))
        }
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Device not found"
        }))),
        Err(e) => {
            log::error!("Failed to unregister push device: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to unregister device"
            })))
        }
    }
}

/// Unregister a device by ID
///
/// DELETE /api/push/devices/{id}
#[utoipa::path(
    delete,
    path = "/api/push/devices/{id}",
    tag = "Push Notifications",
    params(
        ("id" = String, Path, description = "Device token ID")
    ),
    responses(
        (status = 200, description = "Device unregistered successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Device not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn unregister_device_by_id(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, actix_web::Error> {
    let device_id = path.into_inner();

    match push_tokens::unregister_device_token(pool.get_ref(), &claims.sub, &device_id).await {
        Ok(true) => {
            log::info!(
                "Unregistered push device {} for user {}",
                device_id,
                claims.sub
            );
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Device unregistered successfully"
            })))
        }
        Ok(false) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Device not found"
        }))),
        Err(e) => {
            log::error!("Failed to unregister push device: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to unregister device"
            })))
        }
    }
}

/// List user's registered devices
///
/// GET /api/push/devices
#[utoipa::path(
    get,
    path = "/api/push/devices",
    tag = "Push Notifications",
    responses(
        (status = 200, description = "List of registered devices"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_devices(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, actix_web::Error> {
    match push_tokens::get_user_device_tokens(pool.get_ref(), &claims.sub).await {
        Ok(tokens) => {
            let devices: Vec<PushDeviceTokenResponse> = tokens.into_iter().map(Into::into).collect();
            let count = devices.len();

            Ok(HttpResponse::Ok().json(ListDevicesResponse { devices, count }))
        }
        Err(e) => {
            log::error!("Failed to list push devices: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list devices"
            })))
        }
    }
}

/// Send a test notification to a specific device
///
/// POST /api/push/devices/{id}/test
#[utoipa::path(
    post,
    path = "/api/push/devices/{id}/test",
    tag = "Push Notifications",
    params(
        ("id" = String, Path, description = "Device token ID")
    ),
    responses(
        (status = 200, description = "Test notification sent"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Device not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_device_notification(
    pool: web::Data<SqlitePool>,
    claims: Claims,
    path: web::Path<String>,
) -> Result<HttpResponse, actix_web::Error> {
    let device_id = path.into_inner();

    // Get the device token
    let token = match push_tokens::get_device_token_by_id(pool.get_ref(), &claims.sub, &device_id)
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Device not found"
            })));
        }
        Err(e) => {
            log::error!("Failed to get device token: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get device"
            })));
        }
    };

    // Send test notification
    match send_test_notification(pool.get_ref(), &token.device_token).await {
        Ok(result) => {
            if result.success {
                Ok(HttpResponse::Ok().json(TestNotificationResponse {
                    success: true,
                    message: "Test notification sent successfully".to_string(),
                    ticket_id: result.ticket_id,
                }))
            } else {
                Ok(HttpResponse::Ok().json(TestNotificationResponse {
                    success: false,
                    message: result.error.unwrap_or_else(|| "Unknown error".to_string()),
                    ticket_id: None,
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to send test notification: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to send test notification: {}", e)
            })))
        }
    }
}

/// Get push notification stats for the user
///
/// GET /api/push/stats
#[utoipa::path(
    get,
    path = "/api/push/stats",
    tag = "Push Notifications",
    responses(
        (status = 200, description = "Push notification stats"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_push_stats(
    pool: web::Data<SqlitePool>,
    claims: Claims,
) -> Result<HttpResponse, actix_web::Error> {
    match push_tokens::get_token_stats_for_user(pool.get_ref(), &claims.sub).await {
        Ok(stats) => {
            let total: i64 = stats.iter().map(|s| s.count).sum();

            Ok(HttpResponse::Ok().json(serde_json::json!({
                "total_devices": total,
                "by_platform": stats
            })))
        }
        Err(e) => {
            log::error!("Failed to get push stats: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get push stats"
            })))
        }
    }
}

/// Configure push notification routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/push")
            .route("/register", web::post().to(register_device))
            .route("/unregister", web::delete().to(unregister_device))
            .route("/devices", web::get().to(list_devices))
            .route("/devices/{id}", web::delete().to(unregister_device_by_id))
            .route("/devices/{id}/test", web::post().to(test_device_notification))
            .route("/stats", web::get().to(get_push_stats)),
    );
}
