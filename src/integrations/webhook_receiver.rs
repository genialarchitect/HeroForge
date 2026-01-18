//! Webhook Receiver for External Integration Events
//!
//! Receives and processes webhooks from external systems (JIRA, ServiceNow, etc.)
//! to enable real-time bidirectional sync.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::sync_engine::{CommentSource, IntegrationType, SyncAction, SyncActionType, TicketStatus};

/// Webhook configuration per integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub integration_type: IntegrationType,
    pub secret: String,
    pub enabled: bool,
    pub events: Vec<WebhookEvent>,
}

/// Types of webhook events we handle
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookEvent {
    IssueCreated,
    IssueUpdated,
    IssueDeleted,
    StatusChanged,
    CommentCreated,
    CommentUpdated,
    CommentDeleted,
    AssigneeChanged,
    PriorityChanged,
}

/// Parsed webhook payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub integration_type: IntegrationType,
    pub event_type: WebhookEvent,
    pub external_id: String,
    pub external_key: String,
    pub timestamp: DateTime<Utc>,
    pub data: WebhookData,
}

/// Webhook data variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebhookData {
    StatusChange {
        old_status: String,
        new_status: String,
        changed_by: String,
    },
    CommentAdded {
        comment_id: String,
        author: String,
        body: String,
    },
    CommentUpdated {
        comment_id: String,
        author: String,
        body: String,
    },
    CommentDeleted {
        comment_id: String,
    },
    AssigneeChanged {
        old_assignee: Option<String>,
        new_assignee: Option<String>,
    },
    PriorityChanged {
        old_priority: String,
        new_priority: String,
    },
    IssueUpdated {
        fields_changed: Vec<String>,
    },
    Generic {
        raw: serde_json::Value,
    },
}

/// Result of processing a webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookProcessResult {
    pub success: bool,
    pub actions: Vec<SyncAction>,
    pub message: String,
}

/// Webhook receiver
pub struct WebhookReceiver {
    pool: Arc<SqlitePool>,
    configs: Arc<RwLock<HashMap<IntegrationType, WebhookConfig>>>,
}

impl WebhookReceiver {
    /// Create a new webhook receiver
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self {
            pool,
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a webhook configuration
    pub async fn register_config(&self, config: WebhookConfig) {
        let mut configs = self.configs.write().await;
        configs.insert(config.integration_type.clone(), config);
    }

    /// Verify webhook signature (HMAC-SHA256)
    pub async fn verify_signature(
        &self,
        integration_type: &IntegrationType,
        payload: &[u8],
        signature: &str,
    ) -> Result<bool> {
        let configs = self.configs.read().await;
        let config = configs
            .get(integration_type)
            .ok_or_else(|| anyhow!("No webhook config for {:?}", integration_type))?;

        // Parse signature header (format depends on integration)
        let expected_sig = match integration_type {
            IntegrationType::Jira => {
                // JIRA uses X-Hub-Signature format: sha256=<hex>
                signature.strip_prefix("sha256=").unwrap_or(signature)
            }
            IntegrationType::ServiceNow => {
                // ServiceNow sends plain signature
                signature
            }
            _ => signature,
        };

        // Compute HMAC-SHA256
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(config.secret.as_bytes()).map_err(|e| anyhow!("{}", e))?;
        mac.update(payload);
        let result = mac.finalize();
        let computed = hex::encode(result.into_bytes());

        Ok(computed == expected_sig)
    }

    /// Parse a JIRA webhook payload
    pub fn parse_jira_webhook(&self, body: &str) -> Result<WebhookPayload> {
        let json: serde_json::Value = serde_json::from_str(body)?;

        let event_type = json
            .get("webhookEvent")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let issue = json.get("issue").ok_or_else(|| anyhow!("Missing issue in JIRA webhook"))?;
        let external_id = issue
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let external_key = issue
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let webhook_event = match event_type {
            "jira:issue_created" => WebhookEvent::IssueCreated,
            "jira:issue_updated" => {
                // Check if it's a status change
                if let Some(changelog) = json.get("changelog") {
                    if let Some(items) = changelog.get("items").and_then(|v| v.as_array()) {
                        for item in items {
                            if item.get("field").and_then(|v| v.as_str()) == Some("status") {
                                return Ok(WebhookPayload {
                                    integration_type: IntegrationType::Jira,
                                    event_type: WebhookEvent::StatusChanged,
                                    external_id,
                                    external_key,
                                    timestamp: Utc::now(),
                                    data: WebhookData::StatusChange {
                                        old_status: item
                                            .get("fromString")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string(),
                                        new_status: item
                                            .get("toString")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string(),
                                        changed_by: json
                                            .get("user")
                                            .and_then(|u| u.get("displayName"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string(),
                                    },
                                });
                            }
                        }
                    }
                }
                WebhookEvent::IssueUpdated
            }
            "jira:issue_deleted" => WebhookEvent::IssueDeleted,
            "comment_created" => WebhookEvent::CommentCreated,
            "comment_updated" => WebhookEvent::CommentUpdated,
            "comment_deleted" => WebhookEvent::CommentDeleted,
            _ => WebhookEvent::IssueUpdated,
        };

        let data = match webhook_event {
            WebhookEvent::CommentCreated | WebhookEvent::CommentUpdated => {
                if let Some(comment) = json.get("comment") {
                    WebhookData::CommentAdded {
                        comment_id: comment
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        author: comment
                            .get("author")
                            .and_then(|a| a.get("displayName"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        body: comment
                            .get("body")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    }
                } else {
                    WebhookData::Generic {
                        raw: json.clone(),
                    }
                }
            }
            WebhookEvent::CommentDeleted => {
                if let Some(comment) = json.get("comment") {
                    WebhookData::CommentDeleted {
                        comment_id: comment
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    }
                } else {
                    WebhookData::Generic {
                        raw: json.clone(),
                    }
                }
            }
            _ => WebhookData::Generic {
                raw: json.clone(),
            },
        };

        Ok(WebhookPayload {
            integration_type: IntegrationType::Jira,
            event_type: webhook_event,
            external_id,
            external_key,
            timestamp: Utc::now(),
            data,
        })
    }

    /// Parse a ServiceNow webhook payload
    pub fn parse_servicenow_webhook(&self, body: &str) -> Result<WebhookPayload> {
        let json: serde_json::Value = serde_json::from_str(body)?;

        let event_type = json
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("update");

        let external_id = json
            .get("sys_id")
            .or_else(|| json.get("number"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let external_key = json
            .get("number")
            .and_then(|v| v.as_str())
            .unwrap_or(&external_id)
            .to_string();

        let webhook_event = match event_type {
            "insert" => WebhookEvent::IssueCreated,
            "update" => {
                // Check if state changed
                if json.get("state").is_some() {
                    WebhookEvent::StatusChanged
                } else {
                    WebhookEvent::IssueUpdated
                }
            }
            "delete" => WebhookEvent::IssueDeleted,
            "work_note" | "comment" => WebhookEvent::CommentCreated,
            _ => WebhookEvent::IssueUpdated,
        };

        let data = match webhook_event {
            WebhookEvent::StatusChanged => WebhookData::StatusChange {
                old_status: json
                    .get("previous_state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                new_status: json
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                changed_by: json
                    .get("sys_updated_by")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
            },
            WebhookEvent::CommentCreated => WebhookData::CommentAdded {
                comment_id: json
                    .get("work_note_sys_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                author: json
                    .get("sys_updated_by")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                body: json
                    .get("work_notes")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            },
            _ => WebhookData::Generic {
                raw: json.clone(),
            },
        };

        Ok(WebhookPayload {
            integration_type: IntegrationType::ServiceNow,
            event_type: webhook_event,
            external_id,
            external_key,
            timestamp: Utc::now(),
            data,
        })
    }

    /// Process a webhook payload
    pub async fn process_webhook(&self, payload: WebhookPayload) -> Result<WebhookProcessResult> {
        info!(
            "Processing {} webhook for {}: {:?}",
            payload.integration_type, payload.external_key, payload.event_type
        );

        let mut actions = Vec::new();

        // Find the linked ticket
        let row: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT id, vulnerability_id
            FROM linked_tickets
            WHERE integration_type = ? AND (external_id = ? OR external_key = ?)
            AND sync_enabled = true
            "#,
        )
        .bind(payload.integration_type.to_string())
        .bind(&payload.external_id)
        .bind(&payload.external_key)
        .fetch_optional(&*self.pool)
        .await?;

        let (ticket_id, vulnerability_id) = match row {
            Some(r) => r,
            None => {
                debug!(
                    "No linked ticket found for {} {}",
                    payload.integration_type, payload.external_key
                );
                return Ok(WebhookProcessResult {
                    success: true,
                    actions: Vec::new(),
                    message: "No linked ticket found - ignoring webhook".to_string(),
                });
            }
        };

        // Process based on event type
        match payload.event_type {
            WebhookEvent::StatusChanged => {
                if let WebhookData::StatusChange {
                    old_status,
                    new_status,
                    changed_by,
                } = &payload.data
                {
                    let ticket_status = TicketStatus::from(new_status.as_str());

                    // Update local ticket status
                    sqlx::query(
                        "UPDATE linked_tickets SET status = ?, remote_updated_at = ? WHERE id = ?",
                    )
                    .bind(serde_json::to_string(&ticket_status)?)
                    .bind(Utc::now().to_rfc3339())
                    .bind(&ticket_id)
                    .execute(&*self.pool)
                    .await?;

                    // Update vulnerability status
                    let vuln_status = match &ticket_status {
                        TicketStatus::Open | TicketStatus::Reopened => "open",
                        TicketStatus::InProgress => "in_progress",
                        TicketStatus::Resolved => "resolved",
                        TicketStatus::Closed => "verified",
                        TicketStatus::Unknown(_) => "open",
                    };

                    sqlx::query(
                        "UPDATE vulnerability_tracking SET status = ?, updated_at = ? WHERE id = ?",
                    )
                    .bind(vuln_status)
                    .bind(Utc::now().to_rfc3339())
                    .bind(&vulnerability_id)
                    .execute(&*self.pool)
                    .await?;

                    actions.push(SyncAction {
                        action_type: SyncActionType::StatusPulled,
                        linked_ticket_id: ticket_id.clone(),
                        details: format!(
                            "Status changed from {} to {} by {}",
                            old_status, new_status, changed_by
                        ),
                        success: true,
                        error: None,
                        timestamp: Utc::now(),
                    });

                    info!(
                        "Updated vulnerability {} status to {} from webhook",
                        vulnerability_id, vuln_status
                    );
                }
            }
            WebhookEvent::CommentCreated | WebhookEvent::CommentUpdated => {
                if let WebhookData::CommentAdded {
                    comment_id,
                    author,
                    body,
                } = &payload.data
                {
                    // Check if this comment is already synced
                    let exists: Option<(String,)> = sqlx::query_as(
                        "SELECT id FROM synced_comments WHERE remote_comment_id = ?",
                    )
                    .bind(comment_id)
                    .fetch_optional(&*self.pool)
                    .await?;

                    if exists.is_none() {
                        // Check if this is a comment from HeroForge (to avoid duplication)
                        if !body.starts_with("[HeroForge") {
                            // Save as synced comment
                            sqlx::query(
                                r#"
                                INSERT INTO synced_comments (
                                    id, linked_ticket_id, remote_comment_id,
                                    author, content, source, synced_at, created_at
                                ) VALUES (?, ?, ?, ?, ?, 'remote', ?, ?)
                                "#,
                            )
                            .bind(uuid::Uuid::new_v4().to_string())
                            .bind(&ticket_id)
                            .bind(comment_id)
                            .bind(author)
                            .bind(body)
                            .bind(Utc::now().to_rfc3339())
                            .bind(Utc::now().to_rfc3339())
                            .execute(&*self.pool)
                            .await?;

                            actions.push(SyncAction {
                                action_type: SyncActionType::CommentPulled,
                                linked_ticket_id: ticket_id.clone(),
                                details: format!("Comment added by {}", author),
                                success: true,
                                error: None,
                                timestamp: Utc::now(),
                            });
                        }
                    }
                }
            }
            WebhookEvent::CommentDeleted => {
                if let WebhookData::CommentDeleted { comment_id } = &payload.data {
                    // Mark as deleted but don't actually delete
                    sqlx::query(
                        "UPDATE synced_comments SET content = '[DELETED]' WHERE remote_comment_id = ?",
                    )
                    .bind(comment_id)
                    .execute(&*self.pool)
                    .await?;

                    debug!("Marked comment {} as deleted", comment_id);
                }
            }
            _ => {
                debug!("Unhandled webhook event type: {:?}", payload.event_type);
            }
        }

        // Log webhook
        self.log_webhook(&payload, &actions).await?;

        Ok(WebhookProcessResult {
            success: true,
            actions,
            message: format!(
                "Processed {:?} event for {}",
                payload.event_type, payload.external_key
            ),
        })
    }

    /// Log webhook for audit trail
    async fn log_webhook(&self, payload: &WebhookPayload, actions: &[SyncAction]) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO webhook_logs (
                id, integration_type, event_type, external_key,
                payload_summary, actions_count, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(payload.integration_type.to_string())
        .bind(format!("{:?}", payload.event_type))
        .bind(&payload.external_key)
        .bind(format!("{:?}", payload.data))
        .bind(actions.len() as i32)
        .bind(Utc::now().to_rfc3339())
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Get recent webhook logs
    pub async fn get_webhook_logs(&self, limit: u32) -> Result<Vec<WebhookLogEntry>> {
        let rows: Vec<(String, String, String, String, String, i32, String)> = sqlx::query_as(
            r#"
            SELECT id, integration_type, event_type, external_key,
                   payload_summary, actions_count, received_at
            FROM webhook_logs
            ORDER BY received_at DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&*self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| WebhookLogEntry {
                id: row.0,
                integration_type: row.1,
                event_type: row.2,
                external_key: row.3,
                payload_summary: row.4,
                actions_count: row.5,
                received_at: DateTime::parse_from_rfc3339(&row.6)
                    .map(|t| t.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
            .collect())
    }
}

/// Webhook log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookLogEntry {
    pub id: String,
    pub integration_type: String,
    pub event_type: String,
    pub external_key: String,
    pub payload_summary: String,
    pub actions_count: i32,
    pub received_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jira_status_change() {
        let body = r#"{
            "webhookEvent": "jira:issue_updated",
            "issue": {
                "id": "12345",
                "key": "PROJ-123"
            },
            "changelog": {
                "items": [
                    {
                        "field": "status",
                        "fromString": "Open",
                        "toString": "In Progress"
                    }
                ]
            },
            "user": {
                "displayName": "John Doe"
            }
        }"#;

        let receiver = WebhookReceiver::new(Arc::new(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async { SqlitePool::connect(":memory:").await.unwrap() }),
        ));

        let payload = receiver.parse_jira_webhook(body).unwrap();
        assert_eq!(payload.event_type, WebhookEvent::StatusChanged);
        assert_eq!(payload.external_key, "PROJ-123");

        if let WebhookData::StatusChange {
            old_status,
            new_status,
            changed_by,
        } = payload.data
        {
            assert_eq!(old_status, "Open");
            assert_eq!(new_status, "In Progress");
            assert_eq!(changed_by, "John Doe");
        } else {
            panic!("Expected StatusChange data");
        }
    }
}
