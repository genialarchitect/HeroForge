//! Webhook database operations for outbound webhooks
//!
//! This module provides CRUD operations for webhooks and delivery logging.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

// ============================================================================
// Models
// ============================================================================

/// Webhook configuration stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Webhook {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub url: String,
    pub secret: Option<String>,
    pub events: String,  // JSON array of event types
    pub headers: Option<String>,  // JSON object of custom headers
    pub is_active: bool,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub last_status_code: Option<i32>,
    pub failure_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Webhook with parsed events for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub url: String,
    pub has_secret: bool,
    pub events: Vec<String>,
    pub headers: Option<serde_json::Value>,
    pub is_active: bool,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub last_status_code: Option<i32>,
    pub failure_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Webhook> for WebhookResponse {
    fn from(w: Webhook) -> Self {
        let events: Vec<String> = serde_json::from_str(&w.events).unwrap_or_default();
        let headers: Option<serde_json::Value> = w.headers
            .as_ref()
            .and_then(|h| serde_json::from_str(h).ok());

        Self {
            id: w.id,
            user_id: w.user_id,
            name: w.name,
            url: w.url,
            has_secret: w.secret.is_some(),
            events,
            headers,
            is_active: w.is_active,
            last_triggered_at: w.last_triggered_at,
            last_status_code: w.last_status_code,
            failure_count: w.failure_count,
            created_at: w.created_at,
            updated_at: w.updated_at,
        }
    }
}

/// Webhook delivery record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub payload: String,
    pub response_status: Option<i32>,
    pub response_body: Option<String>,
    pub error: Option<String>,
    pub delivered_at: DateTime<Utc>,
}

/// Request to create a new webhook
#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    pub secret: Option<String>,
    pub events: Vec<String>,
    pub headers: Option<serde_json::Value>,
    pub is_active: Option<bool>,
}

/// Request to update a webhook
#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub secret: Option<String>,
    pub events: Option<Vec<String>>,
    pub headers: Option<serde_json::Value>,
    pub is_active: Option<bool>,
}

// ============================================================================
// Webhook CRUD Operations
// ============================================================================

/// Create a new webhook
pub async fn create_webhook(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateWebhookRequest,
) -> Result<Webhook> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let events_json = serde_json::to_string(&request.events)?;
    let headers_json = request.headers.as_ref().map(|h| serde_json::to_string(h)).transpose()?;
    let is_active = request.is_active.unwrap_or(true);

    sqlx::query(
        r#"
        INSERT INTO webhooks (id, user_id, name, url, secret, events, headers, is_active, failure_count, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.url)
    .bind(&request.secret)
    .bind(&events_json)
    .bind(&headers_json)
    .bind(is_active)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    get_webhook_by_id(pool, &id, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch created webhook"))
}

/// Get all webhooks for a user
pub async fn get_user_webhooks(pool: &SqlitePool, user_id: &str) -> Result<Vec<Webhook>> {
    let webhooks = sqlx::query_as::<_, Webhook>(
        r#"
        SELECT id, user_id, name, url, secret, events, headers, is_active,
               last_triggered_at, last_status_code, failure_count, created_at, updated_at
        FROM webhooks
        WHERE user_id = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(webhooks)
}

/// Get a webhook by ID (with user ownership check)
pub async fn get_webhook_by_id(
    pool: &SqlitePool,
    webhook_id: &str,
    user_id: &str,
) -> Result<Option<Webhook>> {
    let webhook = sqlx::query_as::<_, Webhook>(
        r#"
        SELECT id, user_id, name, url, secret, events, headers, is_active,
               last_triggered_at, last_status_code, failure_count, created_at, updated_at
        FROM webhooks
        WHERE id = ?1 AND user_id = ?2
        "#,
    )
    .bind(webhook_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(webhook)
}

/// Get a webhook by ID (internal use, no user check)
pub async fn get_webhook_by_id_internal(
    pool: &SqlitePool,
    webhook_id: &str,
) -> Result<Option<Webhook>> {
    let webhook = sqlx::query_as::<_, Webhook>(
        r#"
        SELECT id, user_id, name, url, secret, events, headers, is_active,
               last_triggered_at, last_status_code, failure_count, created_at, updated_at
        FROM webhooks
        WHERE id = ?1
        "#,
    )
    .bind(webhook_id)
    .fetch_optional(pool)
    .await?;

    Ok(webhook)
}

/// Update a webhook
pub async fn update_webhook(
    pool: &SqlitePool,
    webhook_id: &str,
    user_id: &str,
    request: &UpdateWebhookRequest,
) -> Result<Option<Webhook>> {
    // First verify ownership
    let existing = get_webhook_by_id(pool, webhook_id, user_id).await?;
    if existing.is_none() {
        return Ok(None);
    }

    let now = Utc::now();

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?1".to_string()];
    let mut param_index = 2;

    if request.name.is_some() {
        updates.push(format!("name = ?{}", param_index));
        param_index += 1;
    }
    if request.url.is_some() {
        updates.push(format!("url = ?{}", param_index));
        param_index += 1;
    }
    if request.secret.is_some() {
        updates.push(format!("secret = ?{}", param_index));
        param_index += 1;
    }
    if request.events.is_some() {
        updates.push(format!("events = ?{}", param_index));
        param_index += 1;
    }
    if request.headers.is_some() {
        updates.push(format!("headers = ?{}", param_index));
        param_index += 1;
    }
    if request.is_active.is_some() {
        updates.push(format!("is_active = ?{}", param_index));
        param_index += 1;
    }

    let query = format!(
        "UPDATE webhooks SET {} WHERE id = ?{} AND user_id = ?{}",
        updates.join(", "),
        param_index,
        param_index + 1
    );

    let mut q = sqlx::query(&query).bind(now);

    if let Some(ref name) = request.name {
        q = q.bind(name);
    }
    if let Some(ref url) = request.url {
        q = q.bind(url);
    }
    if let Some(ref secret) = request.secret {
        q = q.bind(secret);
    }
    if let Some(ref events) = request.events {
        let events_json = serde_json::to_string(events)?;
        q = q.bind(events_json);
    }
    if let Some(ref headers) = request.headers {
        let headers_json = serde_json::to_string(headers)?;
        q = q.bind(headers_json);
    }
    if let Some(is_active) = request.is_active {
        q = q.bind(is_active);
    }

    q = q.bind(webhook_id).bind(user_id);
    q.execute(pool).await?;

    get_webhook_by_id(pool, webhook_id, user_id).await
}

/// Delete a webhook
pub async fn delete_webhook(pool: &SqlitePool, webhook_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM webhooks WHERE id = ?1 AND user_id = ?2")
        .bind(webhook_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get webhooks that subscribe to a specific event type for a user
pub async fn get_webhooks_for_event(
    pool: &SqlitePool,
    user_id: &str,
    event_type: &str,
) -> Result<Vec<Webhook>> {
    // Get all active webhooks for the user
    let webhooks = sqlx::query_as::<_, Webhook>(
        r#"
        SELECT id, user_id, name, url, secret, events, headers, is_active,
               last_triggered_at, last_status_code, failure_count, created_at, updated_at
        FROM webhooks
        WHERE user_id = ?1 AND is_active = 1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Filter webhooks that subscribe to this event type
    let matching: Vec<Webhook> = webhooks
        .into_iter()
        .filter(|w| {
            let events: Vec<String> = serde_json::from_str(&w.events).unwrap_or_default();
            events.contains(&event_type.to_string()) || events.contains(&"*".to_string())
        })
        .collect();

    Ok(matching)
}

/// Update webhook status after a delivery attempt
pub async fn update_webhook_status(
    pool: &SqlitePool,
    webhook_id: &str,
    status_code: Option<i32>,
    success: bool,
) -> Result<()> {
    let now = Utc::now();

    if success {
        // Reset failure count on success
        sqlx::query(
            r#"
            UPDATE webhooks
            SET last_triggered_at = ?1, last_status_code = ?2, failure_count = 0, updated_at = ?1
            WHERE id = ?3
            "#,
        )
        .bind(now)
        .bind(status_code)
        .bind(webhook_id)
        .execute(pool)
        .await?;
    } else {
        // Increment failure count
        sqlx::query(
            r#"
            UPDATE webhooks
            SET last_triggered_at = ?1, last_status_code = ?2, failure_count = failure_count + 1, updated_at = ?1
            WHERE id = ?3
            "#,
        )
        .bind(now)
        .bind(status_code)
        .bind(webhook_id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Disable a webhook (e.g., after too many failures)
pub async fn disable_webhook(pool: &SqlitePool, webhook_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE webhooks
        SET is_active = 0, updated_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(now)
    .bind(webhook_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Webhook Delivery Operations
// ============================================================================

/// Log a webhook delivery attempt
pub async fn log_delivery(
    pool: &SqlitePool,
    webhook_id: &str,
    event_type: &str,
    payload: &str,
    response_status: Option<i32>,
    response_body: Option<&str>,
    error: Option<&str>,
) -> Result<WebhookDelivery> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, response_status, response_body, error, delivered_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(webhook_id)
    .bind(event_type)
    .bind(payload)
    .bind(response_status)
    .bind(response_body)
    .bind(error)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(WebhookDelivery {
        id,
        webhook_id: webhook_id.to_string(),
        event_type: event_type.to_string(),
        payload: payload.to_string(),
        response_status,
        response_body: response_body.map(String::from),
        error: error.map(String::from),
        delivered_at: now,
    })
}

/// Get delivery history for a webhook
pub async fn get_delivery_history(
    pool: &SqlitePool,
    webhook_id: &str,
    user_id: &str,
    limit: i64,
) -> Result<Vec<WebhookDelivery>> {
    // First verify the webhook belongs to the user
    let webhook = get_webhook_by_id(pool, webhook_id, user_id).await?;
    if webhook.is_none() {
        return Err(anyhow::anyhow!("Webhook not found"));
    }

    let deliveries = sqlx::query_as::<_, WebhookDelivery>(
        r#"
        SELECT id, webhook_id, event_type, payload, response_status, response_body, error, delivered_at
        FROM webhook_deliveries
        WHERE webhook_id = ?1
        ORDER BY delivered_at DESC
        LIMIT ?2
        "#,
    )
    .bind(webhook_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(deliveries)
}

/// Clean up old delivery records (retention: 30 days)
pub async fn cleanup_old_deliveries(pool: &SqlitePool, days_to_keep: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(days_to_keep);

    let result = sqlx::query("DELETE FROM webhook_deliveries WHERE delivered_at < ?1")
        .bind(cutoff)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Get delivery statistics for a webhook
#[derive(Debug, Serialize)]
pub struct WebhookStats {
    pub total_deliveries: i64,
    pub successful_deliveries: i64,
    pub failed_deliveries: i64,
    pub last_7_days_deliveries: i64,
}

pub async fn get_webhook_stats(
    pool: &SqlitePool,
    webhook_id: &str,
    user_id: &str,
) -> Result<WebhookStats> {
    // Verify ownership
    let webhook = get_webhook_by_id(pool, webhook_id, user_id).await?;
    if webhook.is_none() {
        return Err(anyhow::anyhow!("Webhook not found"));
    }

    let seven_days_ago = Utc::now() - chrono::Duration::days(7);

    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = ?1",
    )
    .bind(webhook_id)
    .fetch_one(pool)
    .await?;

    let successful: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = ?1 AND response_status >= 200 AND response_status < 300",
    )
    .bind(webhook_id)
    .fetch_one(pool)
    .await?;

    let failed: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = ?1 AND (response_status IS NULL OR response_status < 200 OR response_status >= 300)",
    )
    .bind(webhook_id)
    .fetch_one(pool)
    .await?;

    let last_7_days: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = ?1 AND delivered_at >= ?2",
    )
    .bind(webhook_id)
    .bind(seven_days_ago)
    .fetch_one(pool)
    .await?;

    Ok(WebhookStats {
        total_deliveries: total.0,
        successful_deliveries: successful.0,
        failed_deliveries: failed.0,
        last_7_days_deliveries: last_7_days.0,
    })
}
