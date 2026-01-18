use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::integrations::{
    ConflictStrategy, IntegrationType, LinkedTicket, SyncAction, SyncActionType,
    SyncConfig, SyncEngine, SyncStats, TicketStatus, WebhookConfig, WebhookData,
    WebhookEvent, WebhookPayload, WebhookProcessResult, WebhookReceiver,
};
use crate::web::auth;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct LinkTicketRequest {
    pub vulnerability_id: String,
    pub integration_type: String,
    pub external_id: String,
    pub external_key: String,
    pub external_url: String,
}

#[derive(Debug, Serialize)]
pub struct LinkedTicketResponse {
    pub id: String,
    pub vulnerability_id: String,
    pub integration_type: String,
    pub external_id: String,
    pub external_key: String,
    pub external_url: String,
    pub status: String,
    pub last_synced_at: String,
    pub local_updated_at: String,
    pub remote_updated_at: Option<String>,
    pub sync_enabled: bool,
    pub created_at: String,
}

impl From<LinkedTicket> for LinkedTicketResponse {
    fn from(ticket: LinkedTicket) -> Self {
        Self {
            id: ticket.id,
            vulnerability_id: ticket.vulnerability_id,
            integration_type: format!("{:?}", ticket.integration_type),
            external_id: ticket.external_id,
            external_key: ticket.external_key,
            external_url: ticket.external_url,
            status: format!("{:?}", ticket.status),
            last_synced_at: ticket.last_synced_at.to_rfc3339(),
            local_updated_at: ticket.local_updated_at.to_rfc3339(),
            remote_updated_at: ticket.remote_updated_at.map(|dt| dt.to_rfc3339()),
            sync_enabled: ticket.sync_enabled,
            created_at: ticket.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SyncActionResponse {
    pub linked_ticket_id: String,
    pub action_type: String,
    pub details: String,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: String,
}

impl From<SyncAction> for SyncActionResponse {
    fn from(action: SyncAction) -> Self {
        Self {
            linked_ticket_id: action.linked_ticket_id,
            action_type: format!("{:?}", action.action_type),
            details: action.details,
            success: action.success,
            error: action.error,
            timestamp: action.timestamp.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SyncStatsResponse {
    pub total_synced: u64,
    pub status_updates: u64,
    pub comments_synced: u64,
    pub tickets_closed: u64,
    pub conflicts_resolved: u64,
    pub errors: u64,
    pub last_sync_at: Option<String>,
}

impl From<SyncStats> for SyncStatsResponse {
    fn from(stats: SyncStats) -> Self {
        Self {
            total_synced: stats.total_synced,
            status_updates: stats.status_updates,
            comments_synced: stats.comments_synced,
            tickets_closed: stats.tickets_closed,
            conflicts_resolved: stats.conflicts_resolved,
            errors: stats.errors,
            last_sync_at: stats.last_sync_at.map(|dt| dt.to_rfc3339()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateSyncConfigRequest {
    pub sync_enabled: Option<bool>,
    pub sync_interval_seconds: Option<u64>,
    pub sync_status: Option<bool>,
    pub sync_comments: Option<bool>,
    pub auto_close_on_verify: Option<bool>,
    pub conflict_strategy: Option<String>,
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SyncConfigResponse {
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub sync_comments: bool,
    pub auto_close_on_verify: bool,
    pub conflict_strategy: String,
}

impl From<SyncConfig> for SyncConfigResponse {
    fn from(config: SyncConfig) -> Self {
        let strategy = match config.conflict_strategy {
            ConflictStrategy::LocalWins => "local_wins",
            ConflictStrategy::RemoteWins => "remote_wins",
            ConflictStrategy::MostRecent => "most_recent",
            ConflictStrategy::Manual => "manual",
        };
        Self {
            enabled: config.enabled,
            poll_interval_secs: config.poll_interval_secs,
            sync_comments: config.sync_comments,
            auto_close_on_verify: config.auto_close_on_verify,
            conflict_strategy: strategy.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SyncTicketRequest {
    pub ticket_id: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyVulnerabilityRequest {
    pub vulnerability_id: String,
}

#[derive(Debug, Serialize)]
pub struct WebhookLogEntry {
    pub id: String,
    pub integration_type: String,
    pub event_type: String,
    pub signature_valid: Option<bool>,
    pub processed: bool,
    pub process_result: Option<String>,
    pub error_message: Option<String>,
    pub received_at: String,
    pub processed_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WebhookProcessResponse {
    pub success: bool,
    pub actions_taken: Vec<SyncActionResponse>,
    pub error_message: Option<String>,
}

// ============================================================================
// Endpoint Handlers
// ============================================================================

/// Link a vulnerability to an external ticket
pub async fn link_ticket(
    pool: web::Data<SqlitePool>,
    request: web::Json<LinkTicketRequest>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let req = request.into_inner();

    let integration_type = match req.integration_type.to_lowercase().as_str() {
        "jira" => IntegrationType::Jira,
        "servicenow" => IntegrationType::ServiceNow,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid integration type. Must be 'jira' or 'servicenow'"
            }));
        }
    };

    // Create sync engine
    let sync_engine = SyncEngine::new(Arc::new(pool.get_ref().clone()));

    // Link the ticket
    match sync_engine.link_ticket(
        &req.vulnerability_id,
        integration_type,
        &req.external_id,
        &req.external_key,
        &req.external_url,
        &claims.sub,
    ).await {
        Ok(ticket) => HttpResponse::Ok().json(LinkedTicketResponse::from(ticket)),
        Err(e) => {
            log::error!("Failed to link ticket: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to link ticket: {}", e)
            }))
        }
    }
}

/// Unlink a ticket from a vulnerability
pub async fn unlink_ticket(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let ticket_id = path.into_inner();

    match sqlx::query("DELETE FROM linked_tickets WHERE id = ?")
        .bind(&ticket_id)
        .execute(pool.get_ref())
        .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "Ticket unlinked successfully"
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "Linked ticket not found"
                }))
            }
        }
        Err(e) => {
            log::error!("Failed to unlink ticket: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to unlink ticket"
            }))
        }
    }
}

/// Get all linked tickets for a vulnerability
pub async fn get_linked_tickets(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let vulnerability_id = path.into_inner();

    match sqlx::query_as::<_, (String, String, String, String, Option<String>, String, Option<String>, Option<String>, bool, String, String)>(
        r#"
        SELECT id, vulnerability_id, integration_type, external_id, external_url,
               local_status, remote_status, last_synced_at, sync_enabled, created_at, updated_at
        FROM linked_tickets
        WHERE vulnerability_id = ?
        ORDER BY created_at DESC
        "#
    )
    .bind(&vulnerability_id)
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(rows) => {
            let tickets: Vec<serde_json::Value> = rows.iter().map(|row| {
                serde_json::json!({
                    "id": row.0,
                    "vulnerability_id": row.1,
                    "integration_type": row.2,
                    "external_id": row.3,
                    "external_url": row.4,
                    "local_status": row.5,
                    "remote_status": row.6,
                    "last_synced_at": row.7,
                    "sync_enabled": row.8,
                    "created_at": row.9,
                    "updated_at": row.10
                })
            }).collect();
            HttpResponse::Ok().json(tickets)
        }
        Err(e) => {
            log::error!("Failed to get linked tickets: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get linked tickets"
            }))
        }
    }
}

/// Sync a specific ticket
pub async fn sync_ticket(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let ticket_id = path.into_inner();

    // Create sync engine
    let sync_engine = SyncEngine::new(Arc::new(pool.get_ref().clone()));

    match sync_engine.sync_ticket(&ticket_id, &claims.sub).await {
        Ok(actions) => {
            let responses: Vec<SyncActionResponse> = actions.into_iter()
                .map(SyncActionResponse::from)
                .collect();
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Ticket synchronized successfully",
                "actions": responses
            }))
        }
        Err(e) => {
            log::error!("Failed to sync ticket: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to sync ticket: {}", e)
            }))
        }
    }
}

/// Sync all linked tickets
pub async fn sync_all(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Create sync engine
    let sync_engine = SyncEngine::new(Arc::new(pool.get_ref().clone()));

    match sync_engine.sync_all(&claims.sub).await {
        Ok(actions) => {
            let responses: Vec<SyncActionResponse> = actions.into_iter()
                .map(SyncActionResponse::from)
                .collect();
            HttpResponse::Ok().json(serde_json::json!({
                "message": "All tickets synchronized",
                "actions_count": responses.len(),
                "actions": responses
            }))
        }
        Err(e) => {
            log::error!("Failed to sync all tickets: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to sync: {}", e)
            }))
        }
    }
}

/// Handle vulnerability verification and auto-close linked tickets
pub async fn on_vulnerability_verified(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let vulnerability_id = path.into_inner();

    // Create sync engine
    let sync_engine = SyncEngine::new(Arc::new(pool.get_ref().clone()));

    match sync_engine.on_vulnerability_verified(&vulnerability_id, &claims.sub).await {
        Ok(actions) => {
            let responses: Vec<SyncActionResponse> = actions.into_iter()
                .map(SyncActionResponse::from)
                .collect();
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Vulnerability verification processed",
                "tickets_closed": responses.len(),
                "actions": responses
            }))
        }
        Err(e) => {
            log::error!("Failed to process vulnerability verification: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to process verification: {}", e)
            }))
        }
    }
}

/// Get sync statistics
pub async fn get_sync_stats(
    pool: web::Data<SqlitePool>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    // Create sync engine
    let sync_engine = SyncEngine::new(Arc::new(pool.get_ref().clone()));

    let stats = sync_engine.get_stats().await;
    HttpResponse::Ok().json(SyncStatsResponse::from(stats))
}

/// Get sync configuration
pub async fn get_sync_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let integration_type = path.into_inner();

    match sqlx::query_as::<_, (bool, i64, bool, bool, bool, String)>(
        r#"
        SELECT sync_enabled, sync_interval_seconds, sync_status, sync_comments,
               auto_close_on_verify, conflict_strategy
        FROM integration_sync_config
        WHERE integration_type = ?
        "#
    )
    .bind(&integration_type)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(Some(row)) => HttpResponse::Ok().json(serde_json::json!({
            "sync_enabled": row.0,
            "sync_interval_seconds": row.1,
            "sync_status": row.2,
            "sync_comments": row.3,
            "auto_close_on_verify": row.4,
            "conflict_strategy": row.5
        })),
        Ok(None) => {
            // Return default config
            HttpResponse::Ok().json(serde_json::json!({
                "sync_enabled": true,
                "sync_interval_seconds": 300,
                "sync_status": true,
                "sync_comments": true,
                "auto_close_on_verify": true,
                "conflict_strategy": "most_recent"
            }))
        }
        Err(e) => {
            log::error!("Failed to get sync config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get sync configuration"
            }))
        }
    }
}

/// Update sync configuration
pub async fn update_sync_config(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    request: web::Json<UpdateSyncConfigRequest>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let integration_type = path.into_inner();
    let req = request.into_inner();
    let now = chrono::Utc::now();

    // Check if config exists
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM integration_sync_config WHERE integration_type = ?"
    )
    .bind(&integration_type)
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0) > 0;

    if exists {
        // Build dynamic update query
        let mut updates = vec![];
        let mut params: Vec<String> = vec![];

        if let Some(enabled) = req.sync_enabled {
            updates.push("sync_enabled = ?");
            params.push(if enabled { "1".to_string() } else { "0".to_string() });
        }
        if let Some(interval) = req.sync_interval_seconds {
            updates.push("sync_interval_seconds = ?");
            params.push(interval.to_string());
        }
        if let Some(status) = req.sync_status {
            updates.push("sync_status = ?");
            params.push(if status { "1".to_string() } else { "0".to_string() });
        }
        if let Some(comments) = req.sync_comments {
            updates.push("sync_comments = ?");
            params.push(if comments { "1".to_string() } else { "0".to_string() });
        }
        if let Some(auto_close) = req.auto_close_on_verify {
            updates.push("auto_close_on_verify = ?");
            params.push(if auto_close { "1".to_string() } else { "0".to_string() });
        }
        if let Some(ref strategy) = req.conflict_strategy {
            updates.push("conflict_strategy = ?");
            params.push(strategy.clone());
        }
        if let Some(ref secret) = req.webhook_secret {
            updates.push("webhook_secret = ?");
            params.push(secret.clone());
        }

        if updates.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No fields to update"
            }));
        }

        updates.push("updated_at = ?");
        let query = format!(
            "UPDATE integration_sync_config SET {} WHERE integration_type = ?",
            updates.join(", ")
        );

        let mut q = sqlx::query(&query);
        for param in &params {
            q = q.bind(param);
        }
        q = q.bind(now.to_rfc3339()).bind(&integration_type);

        match q.execute(pool.get_ref()).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "message": "Sync configuration updated"
            })),
            Err(e) => {
                log::error!("Failed to update sync config: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to update sync configuration"
                }))
            }
        }
    } else {
        // Insert new config
        let id = uuid::Uuid::new_v4().to_string();
        match sqlx::query(
            r#"
            INSERT INTO integration_sync_config
            (id, integration_type, sync_enabled, sync_interval_seconds, sync_status,
             sync_comments, auto_close_on_verify, conflict_strategy, webhook_secret,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&id)
        .bind(&integration_type)
        .bind(req.sync_enabled.unwrap_or(true))
        .bind(req.sync_interval_seconds.unwrap_or(300) as i64)
        .bind(req.sync_status.unwrap_or(true))
        .bind(req.sync_comments.unwrap_or(true))
        .bind(req.auto_close_on_verify.unwrap_or(true))
        .bind(req.conflict_strategy.unwrap_or_else(|| "most_recent".to_string()))
        .bind(&req.webhook_secret)
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(pool.get_ref())
        .await
        {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "message": "Sync configuration created"
            })),
            Err(e) => {
                log::error!("Failed to create sync config: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to create sync configuration"
                }))
            }
        }
    }
}

/// Get sync action history
pub async fn get_sync_history(
    pool: web::Data<SqlitePool>,
    query: web::Query<std::collections::HashMap<String, String>>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let limit = query.get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(50);
    let offset = query.get("offset")
        .and_then(|o| o.parse::<i64>().ok())
        .unwrap_or(0);

    match sqlx::query_as::<_, (String, Option<String>, String, String, Option<String>, bool, Option<String>, String)>(
        r#"
        SELECT id, linked_ticket_id, action_type, direction, details,
               success, error_message, executed_at
        FROM sync_action_history
        ORDER BY executed_at DESC
        LIMIT ? OFFSET ?
        "#
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.get_ref())
    .await
    {
        Ok(rows) => {
            let history: Vec<serde_json::Value> = rows.iter().map(|row| {
                serde_json::json!({
                    "id": row.0,
                    "linked_ticket_id": row.1,
                    "action_type": row.2,
                    "direction": row.3,
                    "details": row.4,
                    "success": row.5,
                    "error_message": row.6,
                    "executed_at": row.7
                })
            }).collect();
            HttpResponse::Ok().json(history)
        }
        Err(e) => {
            log::error!("Failed to get sync history: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get sync history"
            }))
        }
    }
}

// ============================================================================
// Webhook Handlers
// ============================================================================

/// Receive JIRA webhook
pub async fn jira_webhook(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let body_str = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Invalid webhook body encoding: {}", e);
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid request body encoding"
            }));
        }
    };

    // Create webhook receiver
    let receiver = WebhookReceiver::new(Arc::new(pool.get_ref().clone()));

    // Verify signature if configured
    if let Some(signature) = req.headers()
        .get("X-Hub-Signature-256")
        .or_else(|| req.headers().get("X-Atlassian-Webhook-Identifier"))
        .and_then(|h| h.to_str().ok())
    {
        match receiver.verify_signature(&IntegrationType::Jira, body_str.as_bytes(), signature).await {
            Ok(true) => {},
            Ok(false) => {
                log::warn!("JIRA webhook signature verification failed");
                // Continue processing but log the failure
            }
            Err(e) => {
                log::error!("Signature verification error: {}", e);
            }
        }
    }

    // Parse the webhook payload
    let payload = match receiver.parse_jira_webhook(&body_str) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Failed to parse JIRA webhook: {}", e);
            // Log the webhook even if parsing fails
            let _ = log_webhook(&pool, "jira", "unknown", &body_str, false, None).await;
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Failed to parse webhook payload"
            }));
        }
    };

    // Process the webhook
    match receiver.process_webhook(payload.clone()).await {
        Ok(result) => {
            let _ = log_webhook(
                &pool,
                "jira",
                &format!("{:?}", payload.event_type),
                &body_str,
                true,
                Some(&result)
            ).await;
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "actions_taken": result.actions.len()
            }))
        }
        Err(e) => {
            log::error!("Failed to process JIRA webhook: {}", e);
            let _ = log_webhook(
                &pool,
                "jira",
                &format!("{:?}", payload.event_type),
                &body_str,
                false,
                None
            ).await;
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to process webhook: {}", e)
            }))
        }
    }
}

/// Receive ServiceNow webhook
pub async fn servicenow_webhook(
    pool: web::Data<SqlitePool>,
    req: HttpRequest,
    body: web::Bytes,
) -> HttpResponse {
    let body_str = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Invalid webhook body encoding: {}", e);
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid request body encoding"
            }));
        }
    };

    // Create webhook receiver
    let receiver = WebhookReceiver::new(Arc::new(pool.get_ref().clone()));

    // Verify signature if configured
    if let Some(signature) = req.headers()
        .get("X-ServiceNow-Signature")
        .and_then(|h| h.to_str().ok())
    {
        match receiver.verify_signature(&IntegrationType::ServiceNow, body_str.as_bytes(), signature).await {
            Ok(true) => {},
            Ok(false) => {
                log::warn!("ServiceNow webhook signature verification failed");
            }
            Err(e) => {
                log::error!("Signature verification error: {}", e);
            }
        }
    }

    // Parse the webhook payload
    let payload = match receiver.parse_servicenow_webhook(&body_str) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Failed to parse ServiceNow webhook: {}", e);
            let _ = log_webhook(&pool, "servicenow", "unknown", &body_str, false, None).await;
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Failed to parse webhook payload"
            }));
        }
    };

    // Process the webhook
    match receiver.process_webhook(payload.clone()).await {
        Ok(result) => {
            let _ = log_webhook(
                &pool,
                "servicenow",
                &format!("{:?}", payload.event_type),
                &body_str,
                true,
                Some(&result)
            ).await;
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "actions_taken": result.actions.len()
            }))
        }
        Err(e) => {
            log::error!("Failed to process ServiceNow webhook: {}", e);
            let _ = log_webhook(
                &pool,
                "servicenow",
                &format!("{:?}", payload.event_type),
                &body_str,
                false,
                None
            ).await;
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to process webhook: {}", e)
            }))
        }
    }
}

/// Get webhook logs
pub async fn get_webhook_logs(
    pool: web::Data<SqlitePool>,
    query: web::Query<std::collections::HashMap<String, String>>,
    _claims: web::ReqData<auth::Claims>,
) -> HttpResponse {
    let limit = query.get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(50);
    let integration = query.get("integration");

    let (query_str, bind_integration) = if let Some(int) = integration {
        (
            r#"
            SELECT id, integration_type, event_type, signature_valid, processed,
                   process_result, error_message, received_at, processed_at
            FROM webhook_logs
            WHERE integration_type = ?
            ORDER BY received_at DESC
            LIMIT ?
            "#,
            Some(int.clone())
        )
    } else {
        (
            r#"
            SELECT id, integration_type, event_type, signature_valid, processed,
                   process_result, error_message, received_at, processed_at
            FROM webhook_logs
            ORDER BY received_at DESC
            LIMIT ?
            "#,
            None
        )
    };

    let result = if let Some(int) = bind_integration {
        sqlx::query_as::<_, (String, String, String, Option<bool>, bool, Option<String>, Option<String>, String, Option<String>)>(query_str)
            .bind(&int)
            .bind(limit)
            .fetch_all(pool.get_ref())
            .await
    } else {
        sqlx::query_as::<_, (String, String, String, Option<bool>, bool, Option<String>, Option<String>, String, Option<String>)>(
            r#"
            SELECT id, integration_type, event_type, signature_valid, processed,
                   process_result, error_message, received_at, processed_at
            FROM webhook_logs
            ORDER BY received_at DESC
            LIMIT ?
            "#
        )
            .bind(limit)
            .fetch_all(pool.get_ref())
            .await
    };

    match result {
        Ok(rows) => {
            let logs: Vec<WebhookLogEntry> = rows.iter().map(|row| WebhookLogEntry {
                id: row.0.clone(),
                integration_type: row.1.clone(),
                event_type: row.2.clone(),
                signature_valid: row.3,
                processed: row.4,
                process_result: row.5.clone(),
                error_message: row.6.clone(),
                received_at: row.7.clone(),
                processed_at: row.8.clone(),
            }).collect();
            HttpResponse::Ok().json(logs)
        }
        Err(e) => {
            log::error!("Failed to get webhook logs: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get webhook logs"
            }))
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn log_webhook(
    pool: &SqlitePool,
    integration_type: &str,
    event_type: &str,
    payload: &str,
    processed: bool,
    result: Option<&WebhookProcessResult>,
) -> Result<(), sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let (process_result, error_message) = if let Some(r) = result {
        (
            Some(serde_json::to_string(&r.actions).unwrap_or_default()),
            if r.success { None } else { Some(r.message.clone()) }
        )
    } else {
        (None, None)
    };

    sqlx::query(
        r#"
        INSERT INTO webhook_logs (id, integration_type, event_type, payload, processed,
                                  process_result, error_message, received_at, processed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(&id)
    .bind(integration_type)
    .bind(event_type)
    .bind(payload)
    .bind(processed)
    .bind(&process_result)
    .bind(&error_message)
    .bind(now.to_rfc3339())
    .bind(if processed { Some(now.to_rfc3339()) } else { None })
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/integration-sync")
            // Ticket linking
            .route("/tickets", web::post().to(link_ticket))
            .route("/tickets/{id}", web::delete().to(unlink_ticket))
            .route("/vulnerabilities/{id}/tickets", web::get().to(get_linked_tickets))
            // Syncing
            .route("/tickets/{id}/sync", web::post().to(sync_ticket))
            .route("/sync", web::post().to(sync_all))
            .route("/stats", web::get().to(get_sync_stats))
            // Verification handling
            .route("/vulnerabilities/{id}/verified", web::post().to(on_vulnerability_verified))
            // Configuration
            .route("/config/{integration}", web::get().to(get_sync_config))
            .route("/config/{integration}", web::put().to(update_sync_config))
            // History
            .route("/history", web::get().to(get_sync_history))
            // Webhook logs
            .route("/webhooks/logs", web::get().to(get_webhook_logs))
    );

    // Webhook endpoints (no auth required - signature verified)
    cfg.service(
        web::scope("/webhooks")
            .route("/jira", web::post().to(jira_webhook))
            .route("/servicenow", web::post().to(servicenow_webhook))
    );
}
