//! ASM Monitor execution engine

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::types::*;
use super::baseline::BaselineManager;
use super::comparison::ChangeDetector;
use super::risk_scoring::RiskScorer;
use crate::db;

/// ASM Monitor execution engine
pub struct AsmMonitorEngine {
    pool: SqlitePool,
}

impl AsmMonitorEngine {
    /// Create a new ASM monitor engine
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Run a monitor scan
    pub async fn run_monitor(&self, monitor_id: &str) -> anyhow::Result<MonitorRunResult> {
        let started_at = Utc::now();

        // Get the monitor
        let monitor = db::asm::get_monitor(&self.pool, monitor_id).await?;

        log::info!("Running ASM monitor: {} ({})", monitor.name, monitor_id);

        // Run asset discovery for each domain
        let mut all_assets = Vec::new();
        for domain in &monitor.domains {
            match self.discover_assets(domain, &monitor.discovery_config).await {
                Ok(assets) => all_assets.extend(assets),
                Err(e) => {
                    log::warn!("Failed to discover assets for {}: {}", domain, e);
                }
            }
        }

        // Get or create baseline
        let baseline = match db::asm::get_active_baseline(&self.pool, monitor_id).await {
            Ok(baseline) => baseline,
            Err(_) => {
                // Create initial baseline
                let baseline = BaselineManager::create_baseline(monitor_id, &[]);
                db::asm::create_baseline(&self.pool, &baseline).await?;
                baseline
            }
        };

        // Detect changes
        let authorized = db::asm::get_authorized_assets(&self.pool, &monitor.user_id).await
            .unwrap_or_default();

        let changes = ChangeDetector::detect_changes(
            monitor_id,
            &baseline,
            &all_assets,
            &authorized,
        );

        let changes_count = changes.len();

        // Store changes
        for change in &changes {
            if let Err(e) = db::asm::create_change(&self.pool, change).await {
                log::error!("Failed to store change: {}", e);
            }

            // Check if we should alert
            if Self::should_alert(&monitor.alert_config, change) {
                if let Err(e) = self.send_alert(&monitor, change).await {
                    log::error!("Failed to send alert: {}", e);
                }
            }
        }

        // Update baseline with new assets
        let mut updated_baseline = baseline.clone();
        BaselineManager::merge_assets(&mut updated_baseline, &Self::hosts_to_baseline(&all_assets));
        db::asm::update_baseline(&self.pool, &updated_baseline).await?;

        // Calculate risk scores for assets
        for asset in &all_assets {
            let is_authorized = ChangeDetector::detect_changes(
                monitor_id,
                &AsmBaseline {
                    id: String::new(),
                    monitor_id: monitor_id.to_string(),
                    assets: vec![asset.clone()],
                    summary: BaselineSummary {
                        total_assets: 1,
                        total_ports: 0,
                        total_services: 0,
                        assets_with_ssl: 0,
                        unique_technologies: 0,
                    },
                    is_active: false,
                    created_at: Utc::now(),
                },
                &[asset.clone()],
                &authorized,
            ).iter().all(|c| !matches!(c.change_type, ChangeType::ShadowItDetected));

            let risk_score = RiskScorer::calculate_score(asset, is_authorized);
            if let Err(e) = db::asm::save_risk_score(&self.pool, &risk_score).await {
                log::error!("Failed to save risk score: {}", e);
            }
        }

        // Update monitor last run time
        db::asm::update_monitor_run_time(&self.pool, monitor_id, Utc::now()).await?;

        let completed_at = Utc::now();

        Ok(MonitorRunResult {
            monitor_id: monitor_id.to_string(),
            baseline_id: baseline.id,
            assets_discovered: all_assets.len(),
            changes_detected: changes_count,
            duration_secs: (completed_at - started_at).num_seconds() as u64,
            started_at,
            completed_at,
            error: None,
        })
    }

    /// Discover assets for a domain
    async fn discover_assets(
        &self,
        domain: &str,
        config: &AssetDiscoveryConfig,
    ) -> anyhow::Result<Vec<BaselineAsset>> {
        let mut assets = Vec::new();

        // Basic DNS lookup
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| anyhow::anyhow!("Failed to create resolver: {}", e))?;

        // Resolve main domain
        if let Ok(response) = resolver.lookup_ip(domain).await {
            let ips: Vec<String> = response.iter()
                .map(|ip| ip.to_string())
                .collect();

            if !ips.is_empty() {
                assets.push(BaselineAsset {
                    hostname: domain.to_string(),
                    ip_addresses: ips,
                    ports: vec![],
                    technologies: vec![],
                    ssl_info: None,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                });
            }
        }

        // Subdomain enumeration if enabled
        if config.enable_subdomain_enum {
            let common_prefixes = vec![
                "www", "mail", "ftp", "admin", "api", "app", "dev", "staging",
                "test", "beta", "portal", "vpn", "remote", "cdn", "static",
                "assets", "images", "files", "download", "shop", "store",
            ];

            for prefix in common_prefixes {
                let subdomain = format!("{}.{}", prefix, domain);
                if let Ok(response) = resolver.lookup_ip(&subdomain).await {
                    let ips: Vec<String> = response.iter()
                        .map(|ip| ip.to_string())
                        .collect();

                    if !ips.is_empty() {
                        assets.push(BaselineAsset {
                            hostname: subdomain,
                            ip_addresses: ips,
                            ports: vec![],
                            technologies: vec![],
                            ssl_info: None,
                            first_seen: Utc::now(),
                            last_seen: Utc::now(),
                        });
                    }
                }
            }
        }

        // Port scanning would be integrated here via the scanner module
        // For now, we return just the discovered hosts

        Ok(assets)
    }

    /// Check if an alert should be sent for a change
    fn should_alert(config: &AlertConfig, change: &AsmChange) -> bool {
        // Check severity threshold
        let severity_order = |s: &AlertSeverity| match s {
            AlertSeverity::Info => 0,
            AlertSeverity::Low => 1,
            AlertSeverity::Medium => 2,
            AlertSeverity::High => 3,
            AlertSeverity::Critical => 4,
        };

        if severity_order(&change.severity) < severity_order(&config.min_severity) {
            return false;
        }

        // Check change type config
        match change.change_type {
            ChangeType::NewSubdomain => config.alert_on_new_subdomain,
            ChangeType::NewPort => config.alert_on_new_port,
            ChangeType::PortClosed => false, // Usually not critical
            ChangeType::CertificateChange => config.alert_on_cert_change,
            ChangeType::CertificateExpiring => config.alert_on_cert_change,
            ChangeType::TechnologyChange => config.alert_on_tech_change,
            ChangeType::IpAddressChange => config.alert_on_ip_change,
            ChangeType::AssetRemoved => config.alert_on_asset_removed,
            ChangeType::ServiceChange => config.alert_on_tech_change,
            ChangeType::ShadowItDetected => config.alert_on_shadow_it,
        }
    }

    /// Send alert for a detected change
    async fn send_alert(&self, monitor: &AsmMonitor, change: &AsmChange) -> anyhow::Result<()> {
        // Get notification settings and send via configured channels
        // This would integrate with the notifications module
        log::info!(
            "ASM Alert: {} - {} on {} ({})",
            change.severity,
            change.change_type,
            change.hostname,
            change.details.description
        );

        // For now, just log. In production, this would:
        // 1. Look up notification channels from monitor.alert_config.notification_channels
        // 2. Send notifications via email, Slack, webhook, etc.

        Ok(())
    }

    /// Convert host info to baseline assets (placeholder for scanner integration)
    fn hosts_to_baseline(assets: &[BaselineAsset]) -> Vec<crate::types::HostInfo> {
        // This would convert in the other direction normally
        // For now, return empty as we work with BaselineAssets directly
        vec![]
    }

    /// Get dashboard statistics
    pub async fn get_dashboard(&self, user_id: &str) -> anyhow::Result<AsmDashboard> {
        let monitors = db::asm::get_user_monitors(&self.pool, user_id).await?;

        let active_monitors = monitors.iter().filter(|m| m.enabled).count();
        let mut total_assets = 0;
        let mut next_scan_at = None;
        let mut last_scan_at = None;

        for monitor in &monitors {
            if let Ok(baseline) = db::asm::get_active_baseline(&self.pool, &monitor.id).await {
                total_assets += baseline.summary.total_assets;
            }

            if let Some(next) = &monitor.next_run_at {
                if next_scan_at.is_none() || next < next_scan_at.as_ref().unwrap() {
                    next_scan_at = Some(*next);
                }
            }

            if let Some(last) = &monitor.last_run_at {
                if last_scan_at.is_none() || last > last_scan_at.as_ref().unwrap() {
                    last_scan_at = Some(*last);
                }
            }
        }

        let changes_24h = db::asm::count_changes_since(
            &self.pool,
            user_id,
            Utc::now() - chrono::Duration::hours(24),
        ).await.unwrap_or(0);

        let changes_7d = db::asm::count_changes_since(
            &self.pool,
            user_id,
            Utc::now() - chrono::Duration::days(7),
        ).await.unwrap_or(0);

        let critical_changes = db::asm::count_changes_by_severity(
            &self.pool,
            user_id,
            AlertSeverity::Critical,
        ).await.unwrap_or(0);

        let unacknowledged = db::asm::count_unacknowledged_changes(&self.pool, user_id)
            .await.unwrap_or(0);

        let risk_scores = db::asm::get_risk_scores(&self.pool, user_id).await?;
        let average_risk = if risk_scores.is_empty() {
            0.0
        } else {
            RiskScorer::calculate_aggregate_score(&risk_scores)
        };

        let high_risk = risk_scores.iter().filter(|s| s.overall_score >= 60).count();
        let shadow_it = db::asm::count_shadow_it(&self.pool, user_id).await.unwrap_or(0);

        Ok(AsmDashboard {
            total_monitors: monitors.len(),
            active_monitors,
            total_assets,
            total_changes_24h: changes_24h as usize,
            total_changes_7d: changes_7d as usize,
            critical_changes: critical_changes as usize,
            unacknowledged_changes: unacknowledged as usize,
            average_risk_score: average_risk,
            high_risk_assets: high_risk,
            shadow_it_count: shadow_it as usize,
            next_scan_at,
            last_scan_at,
        })
    }
}
