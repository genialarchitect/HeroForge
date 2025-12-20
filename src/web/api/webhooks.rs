//! Webhook API endpoints
//!
//! This module provides REST API endpoints for managing outbound webhooks.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db;
use crate::web::auth;
use crate::webhooks::{send_test_webhook, WebhookEventType};

/// List all available webhook event types
#[derive(Debug, Serialize)]
pub struct EventTypesResponse {
    pub event_types: Vec<EventTypeInfo>,
}

#[derive(Debug, Serialize)]
pub struct EventTypeInfo {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// GET /api/webhooks/event-types - Get all available event types
pub async fn get_event_types() -> Result<HttpResponse> {
    let event_types = vec![
        EventTypeInfo {
            id: "scan.started".to_string(),
            name: "Scan Started".to_string(),
            description: "Triggered when a scan begins".to_string(),
        },
        EventTypeInfo {
            id: "scan.completed".to_string(),
            name: "Scan Completed".to_string(),
            description: "Triggered when a scan finishes successfully".to_string(),
        },
        EventTypeInfo {
            id: "scan.failed".to_string(),
            name: "Scan Failed".to_string(),
            description: "Triggered when a scan fails with an error".to_string(),
        },
        EventTypeInfo {
            id: "vulnerability.found".to_string(),
            name: "Vulnerability Found".to_string(),
            description: "Triggered when a new vulnerability is discovered".to_string(),
        },
        EventTypeInfo {
            id: "vulnerability.critical".to_string(),
            name: "Critical Vulnerability".to_string(),
            description: "Triggered when a critical severity vulnerability is found".to_string(),
        },
        EventTypeInfo {
            id: "vulnerability.resolved".to_string(),
            name: "Vulnerability Resolved".to_string(),
            description: "Triggered when a vulnerability is marked as resolved".to_string(),
        },
        EventTypeInfo {
            id: "asset.discovered".to_string(),
            name: "Asset Discovered".to_string(),
            description: "Triggered when a new asset is discovered".to_string(),
        },
        EventTypeInfo {
            id: "compliance.violation".to_string(),
            name: "Compliance Violation".to_string(),
            description: "Triggered when a compliance check fails".to_string(),
        },
    ];

    Ok(HttpResponse::Ok().json(EventTypesResponse { event_types }))
}

/// GET /api/webhooks - List all webhooks for the current user
pub async fn list_webhooks(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> Result<HttpResponse> {
    let webhooks = db::get_user_webhooks(&pool, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch webhooks: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch webhooks")
        })?;

    // Convert to response format (hide secret)
    let response: Vec<db::WebhookResponse> = webhooks.into_iter().map(Into::into).collect();

    Ok(HttpResponse::Ok().json(response))
}

/// GET /api/webhooks/{id} - Get a specific webhook
pub async fn get_webhook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    webhook_id: web::Path<String>,
) -> Result<HttpResponse> {
    let webhook = db::get_webhook_by_id(&pool, &webhook_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch webhook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch webhook")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Webhook not found"))?;

    let response: db::WebhookResponse = webhook.into();

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/webhooks - Create a new webhook
pub async fn create_webhook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    request: web::Json<db::CreateWebhookRequest>,
) -> Result<HttpResponse> {
    // Validate URL
    if !request.url.starts_with("http://") && !request.url.starts_with("https://") {
        return Err(actix_web::error::ErrorBadRequest(
            "URL must start with http:// or https://",
        ));
    }

    // Validate event types
    for event in &request.events {
        if WebhookEventType::from_str(event).is_none() && event != "*" {
            return Err(actix_web::error::ErrorBadRequest(format!(
                "Invalid event type: {}",
                event
            )));
        }
    }

    if request.events.is_empty() {
        return Err(actix_web::error::ErrorBadRequest(
            "At least one event type must be specified",
        ));
    }

    let webhook = db::create_webhook(&pool, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to create webhook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create webhook")
        })?;

    let response: db::WebhookResponse = webhook.into();

    Ok(HttpResponse::Created().json(response))
}

/// PUT /api/webhooks/{id} - Update a webhook
pub async fn update_webhook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    webhook_id: web::Path<String>,
    request: web::Json<db::UpdateWebhookRequest>,
) -> Result<HttpResponse> {
    // Validate URL if provided
    if let Some(ref url) = request.url {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(actix_web::error::ErrorBadRequest(
                "URL must start with http:// or https://",
            ));
        }
    }

    // Validate event types if provided
    if let Some(ref events) = request.events {
        for event in events {
            if WebhookEventType::from_str(event).is_none() && event != "*" {
                return Err(actix_web::error::ErrorBadRequest(format!(
                    "Invalid event type: {}",
                    event
                )));
            }
        }

        if events.is_empty() {
            return Err(actix_web::error::ErrorBadRequest(
                "At least one event type must be specified",
            ));
        }
    }

    let webhook = db::update_webhook(&pool, &webhook_id, &claims.sub, &request)
        .await
        .map_err(|e| {
            log::error!("Failed to update webhook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to update webhook")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Webhook not found"))?;

    let response: db::WebhookResponse = webhook.into();

    Ok(HttpResponse::Ok().json(response))
}

/// DELETE /api/webhooks/{id} - Delete a webhook
pub async fn delete_webhook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    webhook_id: web::Path<String>,
) -> Result<HttpResponse> {
    let deleted = db::delete_webhook(&pool, &webhook_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to delete webhook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete webhook")
        })?;

    if !deleted {
        return Err(actix_web::error::ErrorNotFound("Webhook not found"));
    }

    Ok(HttpResponse::NoContent().finish())
}

/// POST /api/webhooks/{id}/test - Send a test webhook
pub async fn test_webhook(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    webhook_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Verify webhook exists
    let _webhook = db::get_webhook_by_id(&pool, &webhook_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to fetch webhook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to fetch webhook")
        })?
        .ok_or_else(|| actix_web::error::ErrorNotFound("Webhook not found"))?;

    // Send test webhook
    let result = send_test_webhook(&pool, &webhook_id, &claims.sub)
        .await
        .map_err(|e| {
            log::error!("Failed to send test webhook: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to send test webhook")
        })?;

    #[derive(Serialize)]
    struct TestResponse {
        success: bool,
        status_code: Option<u16>,
        error: Option<String>,
        attempts: u32,
    }

    Ok(HttpResponse::Ok().json(TestResponse {
        success: result.success,
        status_code: result.status_code,
        error: result.error,
        attempts: result.attempts,
    }))
}

/// GET /api/webhooks/{id}/deliveries - Get delivery history for a webhook
pub async fn get_deliveries(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    webhook_id: web::Path<String>,
    query: web::Query<DeliveriesQuery>,
) -> Result<HttpResponse> {
    let limit = query.limit.unwrap_or(50).min(100);

    let deliveries = db::get_delivery_history(&pool, &webhook_id, &claims.sub, limit)
        .await
        .map_err(|e| {
            if e.to_string().contains("not found") {
                actix_web::error::ErrorNotFound("Webhook not found")
            } else {
                log::error!("Failed to fetch deliveries: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to fetch deliveries")
            }
        })?;

    Ok(HttpResponse::Ok().json(deliveries))
}

#[derive(Debug, Deserialize)]
pub struct DeliveriesQuery {
    pub limit: Option<i64>,
}

/// GET /api/webhooks/{id}/stats - Get statistics for a webhook
pub async fn get_stats(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    webhook_id: web::Path<String>,
) -> Result<HttpResponse> {
    let stats = db::get_webhook_stats(&pool, &webhook_id, &claims.sub)
        .await
        .map_err(|e| {
            if e.to_string().contains("not found") {
                actix_web::error::ErrorNotFound("Webhook not found")
            } else {
                log::error!("Failed to fetch stats: {}", e);
                actix_web::error::ErrorInternalServerError("Failed to fetch stats")
            }
        })?;

    Ok(HttpResponse::Ok().json(stats))
}

/// Generate a random webhook secret
#[derive(Debug, Serialize)]
pub struct GenerateSecretResponse {
    pub secret: String,
}

/// POST /api/webhooks/generate-secret - Generate a random secret key
pub async fn generate_secret() -> Result<HttpResponse> {
    use rand::Rng;

    let secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    Ok(HttpResponse::Ok().json(GenerateSecretResponse { secret }))
}
