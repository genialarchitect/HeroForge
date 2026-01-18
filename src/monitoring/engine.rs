//! Continuous Monitoring Engine
//!
//! Orchestrates lightweight and full scans to maintain near real-time
//! attack surface visibility.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use log::{debug, error, info, warn};
use tokio::sync::{broadcast, RwLock, Mutex};
use tokio::time::{interval, sleep};
use sqlx::SqlitePool;

use super::change_detector::{ChangeDetector, summarize_changes};
use super::types::{
    MonitoringConfig, TargetState, DetectedChange, Baseline, MonitoringStatus,
    MonitoringAlert, AlertTriggers, MonitoringPortInfo,
};

/// Top 100 common ports for lightweight scanning
const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389,
    5432, 5900, 5901, 6379, 8000, 8080, 8443, 8888, 9000, 9090,
    27017, 27018, 27019, 28017, 6666, 6667, 6668, 6669, 7001, 7002,
    8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 9001,
    9002, 9003, 9200, 9300, 10000, 11211, 15672, 25565, 27015, 32768,
    49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 5060,
    5061, 5357, 5666, 5672, 5938, 5984, 6000, 6001, 6002, 6003,
    7000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8010, 8100, 8200, 8300, 8400, 8500, 8600, 8700, 8800, 8900,
];

/// Message types for the monitoring engine broadcast
#[derive(Debug, Clone)]
pub enum MonitoringMessage {
    Started,
    Stopped,
    LightScanCompleted { target: String },
    FullScanCompleted { target: String },
    ChangesDetected { changes: Vec<DetectedChange> },
    AlertSent { alert_id: String },
    Error { message: String },
}

/// The continuous monitoring engine
pub struct MonitoringEngine {
    /// Engine configuration
    config: Arc<RwLock<MonitoringConfig>>,
    /// Current state of all monitored targets
    states: Arc<RwLock<HashMap<String, TargetState>>>,
    /// Active baseline for comparison (optional)
    baseline: Arc<RwLock<Option<Baseline>>>,
    /// Database pool for persistence
    pool: Arc<SqlitePool>,
    /// Broadcast channel for events
    tx: broadcast::Sender<MonitoringMessage>,
    /// Whether the engine is running
    running: Arc<RwLock<bool>>,
    /// Engine start time
    start_time: Arc<RwLock<Option<Instant>>>,
    /// Changes detected since last reset
    changes_today: Arc<RwLock<Vec<DetectedChange>>>,
    /// Alerts sent since last reset
    alerts_sent_today: Arc<RwLock<usize>>,
}

impl MonitoringEngine {
    /// Create a new monitoring engine
    pub fn new(pool: Arc<SqlitePool>, config: MonitoringConfig) -> Self {
        let (tx, _) = broadcast::channel(1000);

        Self {
            config: Arc::new(RwLock::new(config)),
            states: Arc::new(RwLock::new(HashMap::new())),
            baseline: Arc::new(RwLock::new(None)),
            pool,
            tx,
            running: Arc::new(RwLock::new(false)),
            start_time: Arc::new(RwLock::new(None)),
            changes_today: Arc::new(RwLock::new(Vec::new())),
            alerts_sent_today: Arc::new(RwLock::new(0)),
        }
    }

    /// Subscribe to monitoring events
    pub fn subscribe(&self) -> broadcast::Receiver<MonitoringMessage> {
        self.tx.subscribe()
    }

    /// Update the configuration
    pub async fn update_config(&self, config: MonitoringConfig) {
        let mut current = self.config.write().await;
        *current = config;
    }

    /// Get current configuration
    pub async fn get_config(&self) -> MonitoringConfig {
        self.config.read().await.clone()
    }

    /// Set a baseline for comparison
    pub async fn set_baseline(&self, baseline: Baseline) {
        let mut current = self.baseline.write().await;
        *current = Some(baseline);
        info!("Baseline set with {} targets", current.as_ref().map(|b| b.targets.len()).unwrap_or(0));
    }

    /// Create a baseline from current state
    pub async fn create_baseline(&self, name: String, description: Option<String>) -> Baseline {
        let states = self.states.read().await;
        let targets: Vec<TargetState> = states.values().cloned().collect();

        Baseline {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            created_at: Utc::now(),
            targets,
            description,
        }
    }

    /// Get current status
    pub async fn get_status(&self) -> MonitoringStatus {
        let running = *self.running.read().await;
        let states = self.states.read().await;
        let changes_today = self.changes_today.read().await;
        let alerts_sent_today = *self.alerts_sent_today.read().await;
        let start_time = *self.start_time.read().await;

        let last_light_scan = states.values()
            .filter_map(|s| s.last_light_scan)
            .max();

        let last_full_scan = states.values()
            .filter_map(|s| s.last_full_scan)
            .max();

        let uptime_seconds = start_time
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);

        MonitoringStatus {
            is_running: running,
            targets_count: states.len(),
            last_light_scan,
            last_full_scan,
            changes_detected_today: changes_today.len(),
            alerts_sent_today,
            uptime_seconds,
        }
    }

    /// Get all current target states
    pub async fn get_states(&self) -> Vec<TargetState> {
        self.states.read().await.values().cloned().collect()
    }

    /// Get recent changes
    pub async fn get_recent_changes(&self, limit: usize) -> Vec<DetectedChange> {
        let changes = self.changes_today.read().await;
        changes.iter().rev().take(limit).cloned().collect()
    }

    /// Acknowledge a change
    pub async fn acknowledge_change(&self, change_id: &str, user_id: &str) -> bool {
        let mut changes = self.changes_today.write().await;
        for change in changes.iter_mut() {
            if change.id == change_id {
                change.acknowledged = true;
                change.acknowledged_by = Some(user_id.to_string());
                change.acknowledged_at = Some(Utc::now());
                return true;
            }
        }
        false
    }

    /// Start the monitoring engine
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(()); // Already running
        }
        *running = true;
        drop(running);

        {
            let mut start_time = self.start_time.write().await;
            *start_time = Some(Instant::now());
        }

        let _ = self.tx.send(MonitoringMessage::Started);
        info!("Monitoring engine started");

        // Clone references for async tasks
        let config = Arc::clone(&self.config);
        let states = Arc::clone(&self.states);
        let baseline = Arc::clone(&self.baseline);
        let tx = self.tx.clone();
        let running = Arc::clone(&self.running);
        let changes_today = Arc::clone(&self.changes_today);

        // Spawn lightweight scan task
        let light_config = Arc::clone(&config);
        let light_states = Arc::clone(&states);
        let light_baseline = Arc::clone(&baseline);
        let light_tx = tx.clone();
        let light_running = Arc::clone(&running);
        let light_changes = Arc::clone(&changes_today);

        tokio::spawn(async move {
            loop {
                // Check if still running
                if !*light_running.read().await {
                    break;
                }

                let cfg = light_config.read().await;
                let interval_secs = cfg.light_scan_interval_secs;
                let targets = cfg.targets.clone();
                let triggers = cfg.alert_on.clone();
                drop(cfg);

                // Run lightweight scans
                for target in &targets {
                    if !*light_running.read().await {
                        break;
                    }

                    match run_light_scan(target, TOP_PORTS).await {
                        Ok(ports) => {
                            let (previous, current) = {
                                let mut states_lock = light_states.write().await;
                                let state = states_lock
                                    .entry(target.clone())
                                    .or_insert_with(|| TargetState::new(target.clone()));

                                let previous = state.clone();

                                // Update state
                                ChangeDetector::update_target_state(state, &ports, !ports.is_empty());
                                state.last_light_scan = Some(Utc::now());

                                let current = state.clone();
                                (previous, current)
                            };

                            // Detect changes
                            let detector = ChangeDetector::new(triggers.clone());
                            let changes = detector.detect_changes(&previous, &current);

                            if !changes.is_empty() {
                                let mut changes_lock = light_changes.write().await;
                                changes_lock.extend(changes.clone());
                                drop(changes_lock);

                                let _ = light_tx.send(MonitoringMessage::ChangesDetected { changes });
                            }

                            let _ = light_tx.send(MonitoringMessage::LightScanCompleted {
                                target: target.clone(),
                            });
                        }
                        Err(e) => {
                            debug!("Light scan failed for {}: {}", target, e);
                        }
                    }
                }

                // Wait for next interval
                sleep(Duration::from_secs(interval_secs)).await;
            }
        });

        // Spawn full scan task
        let full_config = Arc::clone(&config);
        let full_states = Arc::clone(&states);
        let full_baseline = Arc::clone(&baseline);
        let full_tx = tx.clone();
        let full_running = Arc::clone(&running);
        let full_changes = Arc::clone(&changes_today);

        tokio::spawn(async move {
            loop {
                // Check if still running
                if !*full_running.read().await {
                    break;
                }

                let cfg = full_config.read().await;
                let interval_secs = cfg.full_scan_interval_secs;
                let targets = cfg.targets.clone();
                let triggers = cfg.alert_on.clone();
                drop(cfg);

                // Run full scans
                for target in &targets {
                    if !*full_running.read().await {
                        break;
                    }

                    match run_full_scan(target).await {
                        Ok(ports) => {
                            let (previous, current) = {
                                let mut states_lock = full_states.write().await;
                                let state = states_lock
                                    .entry(target.clone())
                                    .or_insert_with(|| TargetState::new(target.clone()));

                                let previous = state.clone();

                                // Update state
                                ChangeDetector::update_target_state(state, &ports, !ports.is_empty());
                                state.last_full_scan = Some(Utc::now());

                                let current = state.clone();
                                (previous, current)
                            };

                            // Detect changes
                            let detector = ChangeDetector::new(triggers.clone());
                            let changes = detector.detect_changes(&previous, &current);

                            if !changes.is_empty() {
                                let mut changes_lock = full_changes.write().await;
                                changes_lock.extend(changes.clone());
                                drop(changes_lock);

                                let _ = full_tx.send(MonitoringMessage::ChangesDetected { changes });
                            }

                            let _ = full_tx.send(MonitoringMessage::FullScanCompleted {
                                target: target.clone(),
                            });
                        }
                        Err(e) => {
                            warn!("Full scan failed for {}: {}", target, e);
                        }
                    }
                }

                // Wait for next interval
                sleep(Duration::from_secs(interval_secs)).await;
            }
        });

        Ok(())
    }

    /// Stop the monitoring engine
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        if !*running {
            return;
        }
        *running = false;
        let _ = self.tx.send(MonitoringMessage::Stopped);
        info!("Monitoring engine stopped");
    }

    /// Add a target to monitoring
    pub async fn add_target(&self, target: String) {
        let mut config = self.config.write().await;
        if !config.targets.contains(&target) {
            config.targets.push(target.clone());
            info!("Added target {} to monitoring", target);
        }
    }

    /// Remove a target from monitoring
    pub async fn remove_target(&self, target: &str) {
        let mut config = self.config.write().await;
        config.targets.retain(|t| t != target);

        let mut states = self.states.write().await;
        states.remove(target);

        info!("Removed target {} from monitoring", target);
    }
}

/// Run a lightweight scan (top ports only)
async fn run_light_scan(target: &str, ports: &[u16]) -> Result<Vec<MonitoringPortInfo>> {
    // Use TCP connect scan for speed
    let mut open_ports = Vec::new();

    for &port in ports {
        let addr = format!("{}:{}", target, port);
        match tokio::time::timeout(
            Duration::from_millis(100),
            tokio::net::TcpStream::connect(&addr),
        ).await {
            Ok(Ok(_stream)) => {
                open_ports.push(MonitoringPortInfo {
                    port,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service: None,
                    version: None,
                    banner: None,
                });
            }
            _ => {}
        }
    }

    Ok(open_ports)
}

/// Run a full port scan
async fn run_full_scan(target: &str) -> Result<Vec<MonitoringPortInfo>> {
    // Full scan of common ports (1-10000)
    let mut open_ports = Vec::new();

    // Use concurrent scanning for speed
    let mut handles = Vec::new();

    for port in 1..=10000u16 {
        let target = target.to_string();
        handles.push(tokio::spawn(async move {
            let addr = format!("{}:{}", target, port);
            match tokio::time::timeout(
                Duration::from_millis(500),
                tokio::net::TcpStream::connect(&addr),
            ).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        }));
    }

    // Process in batches to avoid too many concurrent connections
    for chunk in handles.chunks_mut(500) {
        let results: Vec<_> = futures::future::join_all(chunk.iter_mut().map(|h| async {
            match h.await {
                Ok(Some(port)) => Some(port),
                _ => None,
            }
        })).await;

        for result in results {
            if let Some(port) = result {
                open_ports.push(MonitoringPortInfo {
                    port,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service: get_common_service(port),
                    version: None,
                    banner: None,
                });
            }
        }
    }

    Ok(open_ports)
}

/// Get common service name for a port
fn get_common_service(port: u16) -> Option<String> {
    match port {
        21 => Some("ftp".to_string()),
        22 => Some("ssh".to_string()),
        23 => Some("telnet".to_string()),
        25 => Some("smtp".to_string()),
        53 => Some("dns".to_string()),
        80 => Some("http".to_string()),
        110 => Some("pop3".to_string()),
        143 => Some("imap".to_string()),
        443 => Some("https".to_string()),
        445 => Some("smb".to_string()),
        993 => Some("imaps".to_string()),
        995 => Some("pop3s".to_string()),
        1433 => Some("mssql".to_string()),
        1521 => Some("oracle".to_string()),
        3306 => Some("mysql".to_string()),
        3389 => Some("rdp".to_string()),
        5432 => Some("postgresql".to_string()),
        5900 => Some("vnc".to_string()),
        6379 => Some("redis".to_string()),
        8080 => Some("http-proxy".to_string()),
        8443 => Some("https-alt".to_string()),
        27017 => Some("mongodb".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_common_service() {
        assert_eq!(get_common_service(22), Some("ssh".to_string()));
        assert_eq!(get_common_service(80), Some("http".to_string()));
        assert_eq!(get_common_service(443), Some("https".to_string()));
        assert_eq!(get_common_service(12345), None);
    }

    #[test]
    fn test_top_ports_count() {
        assert_eq!(TOP_PORTS.len(), 100);
    }
}
