//! DISA STIG Repository Auto-Sync
//!
//! This module provides automatic synchronization with the DISA STIG repository,
//! enabling HeroForge to automatically download and update STIGs.
//!
//! # Features
//!
//! - **Automatic Discovery**: Fetches the list of available STIGs from DISA
//! - **Update Detection**: Compares local versions with available versions
//! - **Automatic Downloads**: Downloads new and updated STIGs
//! - **Background Scheduling**: Periodic sync checks in the background
//! - **Manual Sync**: On-demand sync and download capabilities
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scap::stig_sync::{StigSyncScheduler, StigSyncConfig};
//!
//! // Create and start the scheduler
//! let config = StigSyncConfig::default();
//! let scheduler = StigSyncScheduler::new(pool, config);
//! scheduler.start().await?;
//!
//! // Manually trigger a sync
//! scheduler.trigger_sync().await?;
//!
//! // Download and import a specific STIG
//! scheduler.download_and_import("windows_server_2022_stig").await?;
//!
//! // Get current sync status
//! let status = scheduler.get_status().await;
//! println!("Tracked STIGs: {}", status.total_tracked);
//! println!("Updates available: {}", status.updates_available);
//! ```

pub mod types;
pub mod downloader;
pub mod parser;
pub mod scheduler;
pub mod diff;
pub mod notifications;

pub use types::{
    StigEntry,
    StigCategory,
    TrackedStig,
    StigSyncStatus,
    SyncResult,
    StigSyncHistoryEntry,
    SyncType,
    SyncEntryStatus,
    StigSyncConfig,
    ParsedStig,
};

pub use downloader::StigDownloader;
pub use parser::{StigParser, BundleValidation};
pub use scheduler::StigSyncScheduler;
pub use diff::{StigDiff, DiffSummary, RuleDiff, RuleChange, ChangeType, compare_stig_bundles};
pub use notifications::{StigNotifier, StigNotificationConfig};

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize the STIG sync subsystem
///
/// This should be called during application startup to initialize
/// the STIG repository tables and start the background sync scheduler.
pub async fn init_stig_sync(pool: &SqlitePool, config: StigSyncConfig) -> Result<StigSyncScheduler> {
    // Initialize database tables
    init_stig_tables(pool).await?;

    // Create and start scheduler
    let scheduler = StigSyncScheduler::new(pool.clone(), config);
    scheduler.start().await?;

    Ok(scheduler)
}

/// Initialize STIG sync database tables
pub async fn init_stig_tables(pool: &SqlitePool) -> Result<()> {
    // STIG repository table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS stig_repository (
            id TEXT PRIMARY KEY,
            stig_id TEXT NOT NULL UNIQUE,
            stig_name TEXT NOT NULL,
            current_version INTEGER NOT NULL,
            current_release INTEGER NOT NULL,
            available_version INTEGER,
            available_release INTEGER,
            release_date TEXT,
            bundle_id TEXT,
            local_path TEXT,
            download_url TEXT,
            last_checked_at TEXT,
            last_updated_at TEXT,
            auto_update INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (bundle_id) REFERENCES scap_content_bundles(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // STIG sync history table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS stig_sync_history (
            id TEXT PRIMARY KEY,
            stig_id TEXT NOT NULL,
            old_version INTEGER,
            new_version INTEGER NOT NULL,
            old_release INTEGER,
            new_release INTEGER NOT NULL,
            sync_type TEXT NOT NULL,
            status TEXT NOT NULL,
            error_message TEXT,
            synced_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_stig_repo_stig ON stig_repository(stig_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_stig_history_stig ON stig_sync_history(stig_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_stig_history_date ON stig_sync_history(synced_at)")
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stig_category_display() {
        assert_eq!(StigCategory::OperatingSystem.to_string(), "Operating System");
        assert_eq!(StigCategory::NetworkDevice.to_string(), "Network Device");
    }

    #[test]
    fn test_sync_type_display() {
        assert_eq!(SyncType::Initial.to_string(), "initial");
        assert_eq!(SyncType::AutoUpdate.to_string(), "auto_update");
    }

    #[test]
    fn test_config_default() {
        let config = StigSyncConfig::default();
        assert_eq!(config.check_interval_hours, 24);
        assert!(!config.auto_download);
        assert_eq!(config.max_concurrent_downloads, 3);
    }
}
