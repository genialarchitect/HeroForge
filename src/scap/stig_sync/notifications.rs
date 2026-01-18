//! STIG Update Notifications
//!
//! This module provides notification functionality for STIG updates,
//! integrating with the HeroForge webhook system to send alerts when
//! STIGs are updated or new versions become available.
//!
//! # Features
//!
//! - **Update Notifications**: Alert when new STIG versions are available
//! - **Download Notifications**: Notify when STIGs are downloaded/updated
//! - **Sync Status**: Notify on sync completion or failure
//! - **Change Summaries**: Include rule change counts in notifications
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scap::stig_sync::notifications::StigNotifier;
//!
//! let notifier = StigNotifier::new(pool.clone());
//!
//! // Notify about available update
//! notifier.notify_update_available(&tracked_stig, &available_entry).await?;
//!
//! // Notify about completed download
//! notifier.notify_stig_updated(&tracked_stig, diff_summary).await?;
//! ```

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use serde_json::json;

use crate::webhooks::dispatcher::dispatch_event;
use crate::webhooks::types::{
    WebhookEventType,
    StigUpdateAvailableData,
    StigUpdatedData,
    StigSyncCompletedData,
    StigSyncFailedData,
    StigUpdateInfo,
    StigChangeSummary,
};
use super::types::{TrackedStig, StigEntry};
use super::diff::DiffSummary;

/// STIG notification service
pub struct StigNotifier {
    pool: SqlitePool,
}

impl StigNotifier {
    /// Create a new STIG notifier
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Notify about a STIG update being available
    pub async fn notify_update_available(
        &self,
        tracked: &TrackedStig,
        available: &StigEntry,
    ) -> Result<()> {
        let data = StigUpdateAvailableData {
            stig_id: tracked.stig_id.clone(),
            stig_name: tracked.stig_name.clone(),
            current_version: tracked.current_version,
            current_release: tracked.current_release,
            available_version: available.version,
            available_release: available.release,
            release_date: available.release_date.map(|d| d.to_string()),
            download_url: Some(available.download_url.clone()),
            detected_at: Utc::now(),
        };

        log::info!(
            "Sending STIG update notification: {} v{}r{} -> v{}r{}",
            tracked.stig_id,
            tracked.current_version,
            tracked.current_release,
            available.version,
            available.release
        );

        // Dispatch to all users (broadcast notification)
        self.dispatch_to_all_users(
            WebhookEventType::StigUpdateAvailable,
            serde_json::to_value(&data)?,
        ).await
    }

    /// Notify about a STIG being updated/downloaded
    pub async fn notify_stig_updated(
        &self,
        tracked: &TrackedStig,
        new_version: i32,
        new_release: i32,
        local_path: Option<String>,
        diff_summary: Option<&DiffSummary>,
    ) -> Result<()> {
        let change_summary = diff_summary.map(|s| StigChangeSummary {
            rules_added: s.rules_added,
            rules_removed: s.rules_removed,
            rules_modified: s.rules_modified,
            severity_upgrades: s.severity_upgrades,
            severity_downgrades: s.severity_downgrades,
        });

        let data = StigUpdatedData {
            stig_id: tracked.stig_id.clone(),
            stig_name: tracked.stig_name.clone(),
            old_version: Some(tracked.current_version),
            old_release: Some(tracked.current_release),
            new_version,
            new_release,
            local_path,
            updated_at: Utc::now(),
            change_summary,
        };

        log::info!(
            "Sending STIG updated notification: {} v{}r{} -> v{}r{}",
            tracked.stig_id,
            tracked.current_version,
            tracked.current_release,
            new_version,
            new_release
        );

        self.dispatch_to_all_users(
            WebhookEventType::StigUpdated,
            serde_json::to_value(&data)?,
        ).await
    }

    /// Notify about sync completion
    pub async fn notify_sync_completed(
        &self,
        total_checked: usize,
        updates_available: usize,
        auto_updated: usize,
        pending_downloads: Vec<(TrackedStig, StigEntry)>,
        duration_seconds: u64,
    ) -> Result<()> {
        let pending_info: Vec<StigUpdateInfo> = pending_downloads
            .into_iter()
            .map(|(tracked, available)| StigUpdateInfo {
                stig_id: tracked.stig_id,
                stig_name: tracked.stig_name,
                current_version: tracked.current_version,
                current_release: tracked.current_release,
                available_version: available.version,
                available_release: available.release,
            })
            .collect();

        let data = StigSyncCompletedData {
            total_checked,
            updates_available,
            auto_updated,
            pending_downloads: pending_info,
            completed_at: Utc::now(),
            duration_seconds,
        };

        log::info!(
            "Sending STIG sync completed notification: checked={}, updates={}, auto_updated={}",
            total_checked,
            updates_available,
            auto_updated
        );

        self.dispatch_to_all_users(
            WebhookEventType::StigSyncCompleted,
            serde_json::to_value(&data)?,
        ).await
    }

    /// Notify about sync failure
    pub async fn notify_sync_failed(
        &self,
        error: &str,
        operation: &str,
        stig_id: Option<String>,
    ) -> Result<()> {
        let data = StigSyncFailedData {
            error: error.to_string(),
            operation: operation.to_string(),
            stig_id,
            failed_at: Utc::now(),
        };

        log::warn!("Sending STIG sync failed notification: {} - {}", operation, error);

        self.dispatch_to_all_users(
            WebhookEventType::StigSyncFailed,
            serde_json::to_value(&data)?,
        ).await
    }

    /// Dispatch an event to all users with STIG webhooks
    ///
    /// This broadcasts the notification to all users who have webhooks
    /// subscribed to STIG events.
    async fn dispatch_to_all_users(
        &self,
        event_type: WebhookEventType,
        data: serde_json::Value,
    ) -> Result<()> {
        // Get all unique user IDs that have STIG webhooks
        let event_str = event_type.as_str();

        // Query all users with active webhooks for this event type
        let user_ids: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT user_id
            FROM webhooks
            WHERE active = 1
            AND events LIKE ?
            "#
        )
        .bind(format!("%{}%", event_str))
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        if user_ids.is_empty() {
            log::debug!("No users subscribed to STIG event: {}", event_str);
            return Ok(());
        }

        log::debug!(
            "Dispatching STIG event '{}' to {} users",
            event_str,
            user_ids.len()
        );

        // Dispatch to each user
        for user_id in user_ids {
            if let Err(e) = dispatch_event(&self.pool, &user_id, event_type, data.clone()).await {
                log::error!(
                    "Failed to dispatch STIG event to user {}: {}",
                    user_id,
                    e
                );
            }
        }

        Ok(())
    }

    /// Send a test notification to verify webhook configuration
    pub async fn send_test_notification(&self, user_id: &str) -> Result<()> {
        let data = json!({
            "message": "This is a test STIG notification from HeroForge",
            "timestamp": Utc::now().to_rfc3339(),
            "test": true,
            "sample_stig": {
                "stig_id": "windows_server_2022_stig",
                "name": "Windows Server 2022 STIG",
                "current_version": 1,
                "current_release": 1,
                "available_version": 1,
                "available_release": 2,
            }
        });

        dispatch_event(
            &self.pool,
            user_id,
            WebhookEventType::StigUpdateAvailable,
            data,
        ).await?;

        Ok(())
    }
}

/// Configuration for STIG notification settings
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StigNotificationConfig {
    /// Notify when any tracked STIG has an update available
    pub notify_updates_available: bool,
    /// Notify when STIGs are downloaded/updated
    pub notify_stig_updated: bool,
    /// Notify on sync completion
    pub notify_sync_completed: bool,
    /// Notify on sync failure
    pub notify_sync_failed: bool,
    /// Only notify for STIGs with severity changes
    pub only_severity_changes: bool,
    /// Minimum severity level for notifications (if any)
    pub min_severity: Option<String>,
    /// Specific STIGs to notify about (empty = all tracked)
    pub stig_filter: Vec<String>,
}

impl Default for StigNotificationConfig {
    fn default() -> Self {
        Self {
            notify_updates_available: true,
            notify_stig_updated: true,
            notify_sync_completed: true,
            notify_sync_failed: true,
            only_severity_changes: false,
            min_severity: None,
            stig_filter: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_config_default() {
        let config = StigNotificationConfig::default();
        assert!(config.notify_updates_available);
        assert!(config.notify_stig_updated);
        assert!(config.notify_sync_completed);
        assert!(config.notify_sync_failed);
        assert!(!config.only_severity_changes);
    }

    #[test]
    fn test_change_summary() {
        let summary = StigChangeSummary {
            rules_added: 5,
            rules_removed: 2,
            rules_modified: 10,
            severity_upgrades: 3,
            severity_downgrades: 1,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"rules_added\":5"));
        assert!(json.contains("\"severity_upgrades\":3"));
    }
}
