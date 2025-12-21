#![allow(dead_code)]
//! Push notification sender using Expo Push API
//!
//! This module provides functionality to send push notifications to mobile devices
//! via the Expo Push Notification service, which supports both iOS (APNS) and
//! Android (FCM) platforms.
//!
//! Expo Push API: https://docs.expo.dev/push-notifications/sending-notifications/

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use super::NotificationEvent;
use crate::db::push_tokens;

/// Expo Push API endpoint
const EXPO_PUSH_API_URL: &str = "https://exp.host/--/api/v2/push/send";

/// Maximum number of notifications per batch (Expo API limit)
const MAX_BATCH_SIZE: usize = 100;

/// Priority levels for push notifications
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PushPriority {
    #[default]
    Default,
    Normal,
    High,
}

/// Sound options for push notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PushSound {
    Default(String),
    Custom { critical: bool, name: String, volume: f32 },
}

impl Default for PushSound {
    fn default() -> Self {
        PushSound::Default("default".to_string())
    }
}

/// A single push notification message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMessage {
    /// Expo push token (e.g., "ExponentPushToken[xxxx]")
    pub to: String,

    /// Title shown in notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Body text of notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    /// Additional data payload (delivered to app)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,

    /// Notification sound
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sound: Option<PushSound>,

    /// Time-to-live in seconds (0 = immediate delivery only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,

    /// Expiration time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<u64>,

    /// Delivery priority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<PushPriority>,

    /// Badge count (iOS only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub badge: Option<u32>,

    /// Channel ID (Android only)
    #[serde(rename = "channelId", skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Category ID for interactive notifications
    #[serde(rename = "categoryId", skip_serializing_if = "Option::is_none")]
    pub category_id: Option<String>,

    /// Whether the notification can be muted (iOS 15+)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutable_content: Option<bool>,
}

impl PushMessage {
    /// Create a new push message with required fields
    pub fn new(to: String, title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            to,
            title: Some(title.into()),
            body: Some(body.into()),
            data: None,
            sound: Some(PushSound::default()),
            ttl: None,
            expiration: None,
            priority: Some(PushPriority::Default),
            badge: None,
            channel_id: None,
            category_id: None,
            mutable_content: None,
        }
    }

    /// Create a silent/data-only notification
    pub fn silent(to: String, data: serde_json::Value) -> Self {
        Self {
            to,
            title: None,
            body: None,
            data: Some(data),
            sound: None,
            ttl: None,
            expiration: None,
            priority: Some(PushPriority::Normal),
            badge: None,
            channel_id: None,
            category_id: None,
            mutable_content: None,
        }
    }

    /// Set additional data payload
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Set high priority (for urgent notifications)
    pub fn with_high_priority(mut self) -> Self {
        self.priority = Some(PushPriority::High);
        self
    }

    /// Set badge count (iOS)
    pub fn with_badge(mut self, badge: u32) -> Self {
        self.badge = Some(badge);
        self
    }

    /// Set Android notification channel
    pub fn with_channel(mut self, channel_id: impl Into<String>) -> Self {
        self.channel_id = Some(channel_id.into());
        self
    }

    /// Set time-to-live in seconds
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// Response from Expo Push API for a single notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushTicket {
    /// "ok" on success, "error" on failure
    pub status: String,

    /// Ticket ID for checking receipt (only on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Error message (only on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Error details (only on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Response from Expo Push API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    pub data: Vec<PushTicket>,
}

/// Result of sending a push notification
#[derive(Debug, Clone)]
pub struct PushResult {
    /// The device token this result corresponds to
    pub device_token: String,
    /// Whether the send was successful
    pub success: bool,
    /// Ticket ID if successful
    pub ticket_id: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// Whether the token should be invalidated
    pub should_invalidate: bool,
}

/// Push notification sender
pub struct PushNotifier {
    client: reqwest::Client,
    pool: SqlitePool,
}

impl PushNotifier {
    /// Create a new push notifier
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            client: reqwest::Client::new(),
            pool,
        }
    }

    /// Create a new push notifier with custom HTTP client
    pub fn with_client(client: reqwest::Client, pool: SqlitePool) -> Self {
        Self { client, pool }
    }

    /// Send a single push notification
    pub async fn send(&self, message: PushMessage) -> Result<PushResult> {
        let results = self.send_batch(vec![message]).await?;
        results.into_iter().next().ok_or_else(|| anyhow::anyhow!("No response from push API"))
    }

    /// Send multiple push notifications in batch
    pub async fn send_batch(&self, messages: Vec<PushMessage>) -> Result<Vec<PushResult>> {
        if messages.is_empty() {
            return Ok(vec![]);
        }

        let mut all_results = Vec::with_capacity(messages.len());
        let mut tokens_to_invalidate = Vec::new();

        // Process in batches of MAX_BATCH_SIZE
        for chunk in messages.chunks(MAX_BATCH_SIZE) {
            let device_tokens: Vec<String> = chunk.iter().map(|m| m.to.clone()).collect();

            let response = self
                .client
                .post(EXPO_PUSH_API_URL)
                .header("Accept", "application/json")
                .header("Accept-Encoding", "gzip, deflate")
                .header("Content-Type", "application/json")
                .json(chunk)
                .send()
                .await
                .context("Failed to send push notification request")?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                log::error!("Expo Push API error: {} - {}", status, body);

                // Return error results for all messages in this batch
                for token in device_tokens {
                    all_results.push(PushResult {
                        device_token: token,
                        success: false,
                        ticket_id: None,
                        error: Some(format!("API error: {}", status)),
                        should_invalidate: false,
                    });
                }
                continue;
            }

            let push_response: PushResponse = response
                .json()
                .await
                .context("Failed to parse push response")?;

            // Process each ticket
            for (i, ticket) in push_response.data.into_iter().enumerate() {
                let device_token = device_tokens.get(i).cloned().unwrap_or_default();

                let (success, should_invalidate) = if ticket.status == "ok" {
                    (true, false)
                } else {
                    // Check if this is a token-related error
                    let should_invalidate = ticket.details.as_ref()
                        .and_then(|d| d.get("error"))
                        .and_then(|e| e.as_str())
                        .map(|e| e == "DeviceNotRegistered" || e == "InvalidCredentials")
                        .unwrap_or(false);

                    if should_invalidate {
                        tokens_to_invalidate.push(device_token.clone());
                    }

                    (false, should_invalidate)
                };

                all_results.push(PushResult {
                    device_token,
                    success,
                    ticket_id: ticket.id,
                    error: ticket.message,
                    should_invalidate,
                });
            }
        }

        // Invalidate tokens that are no longer valid
        if !tokens_to_invalidate.is_empty() {
            if let Err(e) = push_tokens::deactivate_device_tokens(&self.pool, &tokens_to_invalidate).await {
                log::error!("Failed to deactivate invalid push tokens: {}", e);
            }
        }

        Ok(all_results)
    }

    /// Send notification to all devices for a user
    pub async fn send_to_user(
        &self,
        user_id: &str,
        title: impl Into<String>,
        body: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Result<Vec<PushResult>> {
        let tokens = push_tokens::get_user_device_tokens(&self.pool, user_id).await?;

        if tokens.is_empty() {
            log::debug!("No push tokens found for user {}", user_id);
            return Ok(vec![]);
        }

        let title = title.into();
        let body = body.into();

        let messages: Vec<PushMessage> = tokens
            .into_iter()
            .map(|token| {
                let mut msg = PushMessage::new(token.device_token.clone(), title.clone(), body.clone());
                if let Some(ref d) = data {
                    msg = msg.with_data(d.clone());
                }
                msg
            })
            .collect();

        self.send_batch(messages).await
    }

    /// Send notification to multiple users
    pub async fn send_to_users(
        &self,
        user_ids: &[String],
        title: impl Into<String>,
        body: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Result<Vec<PushResult>> {
        let tokens = push_tokens::get_tokens_for_users(&self.pool, user_ids).await?;

        if tokens.is_empty() {
            log::debug!("No push tokens found for {} users", user_ids.len());
            return Ok(vec![]);
        }

        let title = title.into();
        let body = body.into();

        let messages: Vec<PushMessage> = tokens
            .into_iter()
            .map(|token| {
                let mut msg = PushMessage::new(token.device_token.clone(), title.clone(), body.clone());
                if let Some(ref d) = data {
                    msg = msg.with_data(d.clone());
                }
                msg
            })
            .collect();

        self.send_batch(messages).await
    }

    /// Send a HeroForge notification event to a user
    pub async fn send_notification_event(
        &self,
        user_id: &str,
        event: &NotificationEvent,
    ) -> Result<Vec<PushResult>> {
        let (title, body, data) = match event {
            NotificationEvent::ScanCompleted {
                scan_name,
                hosts_discovered,
                vulnerabilities_found,
                critical_vulns,
                high_vulns,
                ..
            } => {
                let title = format!("Scan Complete: {}", scan_name);
                let body = if *critical_vulns > 0 {
                    format!(
                        "{} hosts, {} vulns ({} critical!)",
                        hosts_discovered, vulnerabilities_found, critical_vulns
                    )
                } else if *high_vulns > 0 {
                    format!(
                        "{} hosts, {} vulns ({} high)",
                        hosts_discovered, vulnerabilities_found, high_vulns
                    )
                } else {
                    format!("{} hosts, {} vulns", hosts_discovered, vulnerabilities_found)
                };

                let data = serde_json::json!({
                    "type": "scan_completed",
                    "scan_name": scan_name,
                    "hosts_discovered": hosts_discovered,
                    "vulnerabilities_found": vulnerabilities_found,
                    "critical_vulns": critical_vulns,
                    "high_vulns": high_vulns
                });

                (title, body, data)
            }

            NotificationEvent::CriticalVulnerability {
                scan_name,
                host,
                severity,
                title: vuln_title,
                ..
            } => {
                let title = format!("{} Vulnerability Found!", severity.to_uppercase());
                let body = format!("{} on {} ({})", vuln_title, host, scan_name);

                let data = serde_json::json!({
                    "type": "critical_vulnerability",
                    "scan_name": scan_name,
                    "host": host,
                    "severity": severity,
                    "title": vuln_title
                });

                (title, body, data)
            }

            NotificationEvent::ScheduledScanStarted { scan_name, targets } => {
                let title = format!("Scan Started: {}", scan_name);
                let body = format!("Scanning {}", targets);

                let data = serde_json::json!({
                    "type": "scheduled_scan_started",
                    "scan_name": scan_name,
                    "targets": targets
                });

                (title, body, data)
            }

            NotificationEvent::ScheduledScanCompleted {
                scan_name,
                status,
                duration_secs,
            } => {
                let title = if status == "completed" {
                    format!("Scan Complete: {}", scan_name)
                } else {
                    format!("Scan Failed: {}", scan_name)
                };

                let minutes = duration_secs / 60;
                let seconds = duration_secs % 60;
                let body = format!("Status: {} ({}m {}s)", status, minutes, seconds);

                let data = serde_json::json!({
                    "type": "scheduled_scan_completed",
                    "scan_name": scan_name,
                    "status": status,
                    "duration_secs": duration_secs
                });

                (title, body, data)
            }
        };

        self.send_to_user(user_id, title, body, Some(data)).await
    }
}

/// Send a test notification to a device
pub async fn send_test_notification(pool: &SqlitePool, device_token: &str) -> Result<PushResult> {
    let notifier = PushNotifier::new(pool.clone());

    let message = PushMessage::new(
        device_token.to_string(),
        "HeroForge Test",
        "Push notifications are working! You'll receive security alerts here.",
    )
    .with_data(serde_json::json!({
        "type": "test",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }));

    notifier.send(message).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_message_creation() {
        let msg = PushMessage::new(
            "ExponentPushToken[xxx]".to_string(),
            "Test Title",
            "Test Body",
        );

        assert_eq!(msg.to, "ExponentPushToken[xxx]");
        assert_eq!(msg.title, Some("Test Title".to_string()));
        assert_eq!(msg.body, Some("Test Body".to_string()));
        assert!(msg.sound.is_some());
    }

    #[test]
    fn test_push_message_with_data() {
        let msg = PushMessage::new(
            "ExponentPushToken[xxx]".to_string(),
            "Test",
            "Body",
        )
        .with_data(serde_json::json!({"key": "value"}));

        assert!(msg.data.is_some());
        assert_eq!(msg.data.unwrap()["key"], "value");
    }

    #[test]
    fn test_push_message_silent() {
        let msg = PushMessage::silent(
            "ExponentPushToken[xxx]".to_string(),
            serde_json::json!({"type": "sync"}),
        );

        assert!(msg.title.is_none());
        assert!(msg.body.is_none());
        assert!(msg.sound.is_none());
        assert!(msg.data.is_some());
    }

    #[test]
    fn test_push_message_high_priority() {
        let msg = PushMessage::new("token".to_string(), "Urgent", "Alert")
            .with_high_priority();

        assert!(matches!(msg.priority, Some(PushPriority::High)));
    }

    #[test]
    fn test_push_message_serialization() {
        let msg = PushMessage::new(
            "ExponentPushToken[abc123]".to_string(),
            "Title",
            "Body",
        )
        .with_badge(5)
        .with_channel("alerts");

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ExponentPushToken[abc123]"));
        assert!(json.contains("Title"));
        assert!(json.contains("\"badge\":5"));
        assert!(json.contains("\"channelId\":\"alerts\""));
    }
}
