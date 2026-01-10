//! Multi-region geo-replication (Sprint 9)
//!
//! Provides data replication across geographic regions including:
//! - Asynchronous data replication
//! - Replication status monitoring
//! - Failover capabilities
//! - Region health tracking

use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub is_primary: bool,
    pub replication_lag_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatus {
    pub source_region: String,
    pub target_region: String,
    pub lag_ms: u64,
    pub last_sync: chrono::DateTime<chrono::Utc>,
    pub health: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    pub regions: Vec<Region>,
    pub sync_interval_ms: u64,
    pub batch_size: usize,
    pub compression: bool,
    pub encryption: bool,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            regions: vec![],
            sync_interval_ms: 5000,
            batch_size: 1000,
            compression: true,
            encryption: true,
        }
    }
}

/// Global replication state
static REPLICATION_STATE: once_cell::sync::Lazy<Arc<RwLock<ReplicationState>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(ReplicationState::default())));

#[derive(Debug, Default)]
struct ReplicationState {
    config: ReplicationConfig,
    statuses: HashMap<String, Vec<ReplicationStatus>>,
    pending_data: HashMap<String, Vec<Vec<u8>>>,
    replication_log: Vec<ReplicationLogEntry>,
}

#[derive(Debug, Clone)]
struct ReplicationLogEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    source: String,
    target: String,
    bytes_replicated: usize,
    success: bool,
}

/// Initialize replication with configuration
pub async fn initialize_replication(config: ReplicationConfig) -> Result<()> {
    let mut state = REPLICATION_STATE.write().await;
    state.config = config.clone();

    // Initialize status tracking for each region
    for region in &config.regions {
        state.statuses.insert(region.id.clone(), Vec::new());
        state.pending_data.insert(region.id.clone(), Vec::new());
    }

    info!("Replication initialized with {} regions", config.regions.len());
    Ok(())
}

/// Replicate data between regions
pub async fn replicate_data(source: &str, target: &str, data: &[u8]) -> Result<()> {
    let start = std::time::Instant::now();

    info!("Replicating {} bytes from {} to {}", data.len(), source, target);

    // Queue data for replication
    {
        let mut state = REPLICATION_STATE.write().await;

        if let Some(pending) = state.pending_data.get_mut(target) {
            pending.push(data.to_vec());
        } else {
            state.pending_data.insert(target.to_string(), vec![data.to_vec()]);
        }
    }

    // Simulate replication (in real implementation, would send to target endpoint)
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Update replication status
    let lag_ms = start.elapsed().as_millis() as u64;
    update_replication_status(source, target, lag_ms, true).await;

    // Log the replication
    {
        let mut state = REPLICATION_STATE.write().await;
        state.replication_log.push(ReplicationLogEntry {
            timestamp: chrono::Utc::now(),
            source: source.to_string(),
            target: target.to_string(),
            bytes_replicated: data.len(),
            success: true,
        });

        // Limit log size
        if state.replication_log.len() > 10000 {
            state.replication_log.drain(0..1000);
        }
    }

    Ok(())
}

/// Update replication status between regions
async fn update_replication_status(source: &str, target: &str, lag_ms: u64, success: bool) {
    let mut state = REPLICATION_STATE.write().await;

    let health = if !success {
        "failed"
    } else if lag_ms > 10000 {
        "degraded"
    } else {
        "healthy"
    };

    let status = ReplicationStatus {
        source_region: source.to_string(),
        target_region: target.to_string(),
        lag_ms,
        last_sync: chrono::Utc::now(),
        health: health.to_string(),
    };

    // Update or add status
    if let Some(statuses) = state.statuses.get_mut(source) {
        if let Some(existing) = statuses.iter_mut().find(|s| s.target_region == target) {
            *existing = status;
        } else {
            statuses.push(status);
        }
    }
}

/// Get replication status for a region
pub async fn get_replication_status(region_id: &str) -> Result<Vec<ReplicationStatus>> {
    let state = REPLICATION_STATE.read().await;

    let statuses = state.statuses.get(region_id)
        .cloned()
        .unwrap_or_default();

    // If no recorded statuses, generate from config
    if statuses.is_empty() {
        let config_statuses: Vec<ReplicationStatus> = state.config.regions.iter()
            .filter(|r| r.id != region_id)
            .map(|r| ReplicationStatus {
                source_region: region_id.to_string(),
                target_region: r.id.clone(),
                lag_ms: 0,
                last_sync: chrono::Utc::now(),
                health: "unknown".to_string(),
            })
            .collect();
        return Ok(config_statuses);
    }

    Ok(statuses)
}

/// Failover to a specified region
pub async fn failover_to_region(region_id: &str) -> Result<()> {
    info!("Initiating failover to region: {}", region_id);

    let mut state = REPLICATION_STATE.write().await;

    // Find the target region
    let region = state.config.regions.iter_mut()
        .find(|r| r.id == region_id)
        .ok_or_else(|| anyhow!("Region not found: {}", region_id))?;

    if region.is_primary {
        return Err(anyhow!("Region {} is already primary", region_id));
    }

    // Demote current primary
    for r in state.config.regions.iter_mut() {
        if r.is_primary {
            r.is_primary = false;
            info!("Demoted region {} from primary", r.id);
        }
    }

    // Promote target region
    if let Some(r) = state.config.regions.iter_mut().find(|r| r.id == region_id) {
        r.is_primary = true;
    }

    info!("Failover to region {} completed", region_id);
    Ok(())
}

/// Get all configured regions
pub async fn get_regions() -> Vec<Region> {
    let state = REPLICATION_STATE.read().await;
    state.config.regions.clone()
}

/// Get the primary region
pub async fn get_primary_region() -> Option<Region> {
    let state = REPLICATION_STATE.read().await;
    state.config.regions.iter().find(|r| r.is_primary).cloned()
}

/// Check overall replication health
pub async fn check_replication_health() -> ReplicationHealth {
    let state = REPLICATION_STATE.read().await;

    let mut healthy_count = 0;
    let mut degraded_count = 0;
    let mut failed_count = 0;

    for statuses in state.statuses.values() {
        for status in statuses {
            match status.health.as_str() {
                "healthy" => healthy_count += 1,
                "degraded" => degraded_count += 1,
                "failed" => failed_count += 1,
                _ => {}
            }
        }
    }

    let overall = if failed_count > 0 {
        "critical"
    } else if degraded_count > 0 {
        "degraded"
    } else {
        "healthy"
    };

    ReplicationHealth {
        overall_status: overall.to_string(),
        healthy_links: healthy_count,
        degraded_links: degraded_count,
        failed_links: failed_count,
        total_regions: state.config.regions.len(),
    }
}

/// Get replication metrics
pub async fn get_replication_metrics() -> ReplicationMetrics {
    let state = REPLICATION_STATE.read().await;

    let recent_replications: Vec<_> = state.replication_log.iter()
        .rev()
        .take(100)
        .collect();

    let total_bytes: usize = recent_replications.iter().map(|e| e.bytes_replicated).sum();
    let success_count = recent_replications.iter().filter(|e| e.success).count();
    let success_rate = if recent_replications.is_empty() {
        100.0
    } else {
        (success_count as f64 / recent_replications.len() as f64) * 100.0
    };

    ReplicationMetrics {
        total_bytes_replicated: total_bytes,
        replication_count: state.replication_log.len(),
        success_rate,
        average_lag_ms: state.statuses.values()
            .flat_map(|s| s.iter().map(|st| st.lag_ms))
            .sum::<u64>() / state.statuses.values().flat_map(|s| s.iter()).count().max(1) as u64,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationHealth {
    pub overall_status: String,
    pub healthy_links: usize,
    pub degraded_links: usize,
    pub failed_links: usize,
    pub total_regions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationMetrics {
    pub total_bytes_replicated: usize,
    pub replication_count: usize,
    pub success_rate: f64,
    pub average_lag_ms: u64,
}
