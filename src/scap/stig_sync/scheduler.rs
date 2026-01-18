//! STIG Sync Scheduler
//!
//! Background task scheduler for automatic STIG updates.

use anyhow::Result;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::time;

use super::downloader::StigDownloader;
use super::parser::StigParser;
use super::types::{StigSyncConfig, StigSyncStatus, SyncResult, TrackedStig};
use crate::db::scap as db_scap;

/// STIG sync scheduler
pub struct StigSyncScheduler {
    pool: SqlitePool,
    config: Arc<RwLock<StigSyncConfig>>,
    status: Arc<RwLock<StigSyncStatus>>,
    shutdown_tx: broadcast::Sender<()>,
    is_running: Arc<RwLock<bool>>,
}

impl StigSyncScheduler {
    /// Create a new STIG sync scheduler
    pub fn new(pool: SqlitePool, config: StigSyncConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            pool,
            config: Arc::new(RwLock::new(config)),
            status: Arc::new(RwLock::new(StigSyncStatus {
                in_progress: false,
                current_operation: None,
                last_sync_at: None,
                last_sync_result: None,
                next_sync_at: None,
                total_tracked: 0,
                updates_available: 0,
                last_errors: Vec::new(),
            })),
            shutdown_tx,
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the background sync scheduler
    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            log::warn!("STIG sync scheduler is already running");
            return Ok(());
        }
        *is_running = true;
        drop(is_running);

        let pool = self.pool.clone();
        let config = self.config.clone();
        let status = self.status.clone();
        let is_running = self.is_running.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            log::info!("STIG sync scheduler started");

            loop {
                // Calculate next sync time
                let check_interval = {
                    let cfg = config.read().await;
                    Duration::hours(cfg.check_interval_hours as i64)
                };

                let next_sync = Utc::now() + check_interval;
                {
                    let mut s = status.write().await;
                    s.next_sync_at = Some(next_sync);
                }

                // Wait until next sync time or shutdown
                let sleep_duration = time::Duration::from_secs(
                    check_interval.num_seconds().max(60) as u64
                );

                tokio::select! {
                    _ = time::sleep(sleep_duration) => {
                        // Run sync check
                        if let Err(e) = Self::run_sync_check(&pool, &config, &status).await {
                            log::error!("STIG sync check failed: {}", e);
                            let mut s = status.write().await;
                            s.last_errors.push(e.to_string());
                            s.last_sync_result = Some(SyncResult::Failed);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        log::info!("STIG sync scheduler shutting down");
                        break;
                    }
                }
            }

            let mut running = is_running.write().await;
            *running = false;
        });

        Ok(())
    }

    /// Stop the scheduler
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Run a sync check
    async fn run_sync_check(
        pool: &SqlitePool,
        config: &Arc<RwLock<StigSyncConfig>>,
        status: &Arc<RwLock<StigSyncStatus>>,
    ) -> Result<()> {
        log::info!("Running STIG sync check");

        {
            let mut s = status.write().await;
            s.in_progress = true;
            s.current_operation = Some("Checking for updates".to_string());
            s.last_errors.clear();
        }

        let cfg = config.read().await.clone();
        let downloader = StigDownloader::new(cfg.clone())?;

        // Get tracked STIGs from database
        let tracked_stigs = db_scap::list_tracked_stigs(pool).await?;

        let mut updates_found = 0;
        let mut errors = Vec::new();

        for tracked in &tracked_stigs {
            {
                let mut s = status.write().await;
                s.current_operation = Some(format!("Checking: {}", tracked.stig_name));
            }

            match downloader.check_for_update(tracked).await {
                Ok(Some(update)) => {
                    log::info!("Update available for {}: V{}R{}", tracked.stig_name, update.version, update.release);
                    updates_found += 1;

                    // Update the available version in the database
                    if let Err(e) = db_scap::update_tracked_stig_available_version(
                        pool,
                        &tracked.id,
                        update.version,
                        update.release,
                    ).await {
                        errors.push(format!("Failed to update available version for {}: {}", tracked.stig_name, e));
                    }

                    // Auto-download if enabled
                    if cfg.auto_download && tracked.auto_update {
                        {
                            let mut s = status.write().await;
                            s.current_operation = Some(format!("Downloading: {}", tracked.stig_name));
                        }

                        match downloader.download_stig(&update, &cfg.download_dir).await {
                            Ok(path) => {
                                log::info!("Downloaded update to: {}", path);
                                // Parse and import would happen here
                            }
                            Err(e) => {
                                errors.push(format!("Failed to download {}: {}", tracked.stig_name, e));
                            }
                        }
                    }
                }
                Ok(None) => {
                    log::debug!("No update available for {}", tracked.stig_name);
                }
                Err(e) => {
                    errors.push(format!("Failed to check {}: {}", tracked.stig_name, e));
                }
            }
        }

        // Update status
        {
            let mut s = status.write().await;
            s.in_progress = false;
            s.current_operation = None;
            s.last_sync_at = Some(Utc::now());
            s.total_tracked = tracked_stigs.len();
            s.updates_available = updates_found;
            s.last_errors = errors.clone();
            s.last_sync_result = if errors.is_empty() {
                Some(SyncResult::Success)
            } else if updates_found > 0 {
                Some(SyncResult::PartialSuccess)
            } else {
                Some(SyncResult::Failed)
            };
        }

        // Update last_checked_at for all tracked STIGs
        for tracked in &tracked_stigs {
            let _ = db_scap::update_tracked_stig_last_checked(pool, &tracked.id).await;
        }

        log::info!("STIG sync check complete: {} tracked, {} updates available", tracked_stigs.len(), updates_found);
        Ok(())
    }

    /// Manually trigger a sync check
    pub async fn trigger_sync(&self) -> Result<()> {
        Self::run_sync_check(&self.pool, &self.config, &self.status).await
    }

    /// Get current sync status
    pub async fn get_status(&self) -> StigSyncStatus {
        self.status.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, config: StigSyncConfig) {
        let mut cfg = self.config.write().await;
        *cfg = config;
    }

    /// Download and import a specific STIG
    pub async fn download_and_import(&self, stig_id: &str) -> Result<()> {
        log::info!("Downloading and importing STIG: {}", stig_id);

        {
            let mut s = self.status.write().await;
            s.in_progress = true;
            s.current_operation = Some(format!("Downloading STIG: {}", stig_id));
        }

        let cfg = self.config.read().await.clone();
        let downloader = StigDownloader::new(cfg.clone())?;

        // Find the STIG in available list
        let available = downloader.fetch_available_stigs().await?;
        let stig = available
            .iter()
            .find(|s| s.stig_id == stig_id)
            .ok_or_else(|| anyhow::anyhow!("STIG {} not found in available list", stig_id))?;

        // Download
        {
            let mut s = self.status.write().await;
            s.current_operation = Some(format!("Downloading: {}", stig.name));
        }

        let path = downloader.download_stig(stig, &cfg.download_dir).await?;

        // Parse
        {
            let mut s = self.status.write().await;
            s.current_operation = Some(format!("Parsing: {}", stig.name));
        }

        let parser = StigParser::new();
        let parsed = parser.parse_bundle(&path, stig).await?;

        // Import using existing content loader
        {
            let mut s = self.status.write().await;
            s.current_operation = Some(format!("Importing: {}", stig.name));
        }

        let content_loader = crate::scap::content::ContentLoader::new();
        let bundle = content_loader.load_from_file(&path, crate::scap::ScapContentSource::Disa).await?;

        // Add to tracked STIGs
        let tracked = TrackedStig {
            id: String::new(), // Will be generated
            stig_id: stig.stig_id.clone(),
            stig_name: stig.name.clone(),
            current_version: stig.version,
            current_release: stig.release,
            available_version: None,
            available_release: None,
            release_date: stig.release_date,
            bundle_id: Some(bundle.id.clone()),
            local_path: Some(path),
            download_url: Some(stig.download_url.clone()),
            last_checked_at: Some(Utc::now()),
            last_updated_at: Some(Utc::now()),
            auto_update: true,
            created_at: Utc::now(),
        };

        db_scap::create_tracked_stig(&self.pool, &tracked).await?;

        // Record sync history
        let history = super::types::StigSyncHistoryEntry {
            id: String::new(),
            stig_id: stig.stig_id.clone(),
            old_version: None,
            new_version: stig.version,
            old_release: None,
            new_release: stig.release,
            sync_type: super::types::SyncType::Initial,
            status: super::types::SyncEntryStatus::Completed,
            error_message: None,
            synced_at: Utc::now(),
        };

        db_scap::create_stig_sync_history(&self.pool, &history).await?;

        {
            let mut s = self.status.write().await;
            s.in_progress = false;
            s.current_operation = None;
            s.total_tracked += 1;
        }

        log::info!("Successfully imported STIG: {} (V{}R{})", stig.name, stig.version, stig.release);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = StigSyncConfig::default();
        assert_eq!(config.check_interval_hours, 24);
        assert!(!config.auto_download);
    }
}
