//! Real-time File System Monitor for YARA Scanning
//!
//! Monitors directories for file changes and automatically scans with YARA rules:
//! - Create events: New files are scanned immediately
//! - Modify events: Modified files are rescanned
//! - Configurable scan depth and file filters
//! - Alert generation for matches
//! - Performance-optimized with debouncing

use super::{YaraScanner, YaraMatch, YaraRule};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use md5::{Md5, Digest};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::fs;

// ============================================================================
// Types
// ============================================================================

/// File system event type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileEventType {
    /// New file created
    Created,
    /// File modified
    Modified,
    /// File deleted
    Deleted,
    /// File renamed
    Renamed,
    /// File accessed
    Accessed,
    /// Unknown event
    Unknown,
}

impl std::fmt::Display for FileEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileEventType::Created => write!(f, "created"),
            FileEventType::Modified => write!(f, "modified"),
            FileEventType::Deleted => write!(f, "deleted"),
            FileEventType::Renamed => write!(f, "renamed"),
            FileEventType::Accessed => write!(f, "accessed"),
            FileEventType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Severity of an alert
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "info"),
            AlertSeverity::Low => write!(f, "low"),
            AlertSeverity::Medium => write!(f, "medium"),
            AlertSeverity::High => write!(f, "high"),
            AlertSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// A file monitor alert generated when YARA rules match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorAlert {
    /// Unique alert ID
    pub id: String,
    /// Path to the file that triggered the alert
    pub file_path: String,
    /// Event type that triggered the scan
    pub event_type: FileEventType,
    /// Matched YARA rules
    pub matches: Vec<YaraMatch>,
    /// Highest severity among matched rules
    pub severity: AlertSeverity,
    /// File hash (SHA256)
    pub file_hash: Option<String>,
    /// File size in bytes
    pub file_size: u64,
    /// Monitor ID that generated this alert
    pub monitor_id: String,
    /// When the alert was generated
    pub created_at: DateTime<Utc>,
    /// Whether the alert has been acknowledged
    pub acknowledged: bool,
    /// Notes added by user
    pub notes: Option<String>,
}

/// Configuration for a file monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorConfig {
    /// Unique monitor ID
    pub id: String,
    /// Monitor name for display
    pub name: String,
    /// Directory paths to monitor
    pub paths: Vec<String>,
    /// Whether to monitor subdirectories
    pub recursive: bool,
    /// File extensions to include (empty = all)
    pub include_extensions: Vec<String>,
    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,
    /// Paths to exclude (glob patterns)
    pub exclude_paths: Vec<String>,
    /// Maximum file size to scan (bytes)
    pub max_file_size: u64,
    /// YARA rule IDs to use for scanning
    pub rule_ids: Vec<String>,
    /// Debounce duration for rapid events (ms)
    pub debounce_ms: u64,
    /// Whether the monitor is active
    pub enabled: bool,
    /// Alert on create events
    pub alert_on_create: bool,
    /// Alert on modify events
    pub alert_on_modify: bool,
    /// Alert on access events (can be noisy)
    pub alert_on_access: bool,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Default for FileMonitorConfig {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Default Monitor".to_string(),
            paths: Vec::new(),
            recursive: true,
            include_extensions: Vec::new(),
            exclude_extensions: vec![
                "tmp".to_string(),
                "swp".to_string(),
                "log".to_string(),
            ],
            exclude_paths: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                "__pycache__".to_string(),
            ],
            max_file_size: 50 * 1024 * 1024, // 50 MB
            rule_ids: Vec::new(),
            debounce_ms: 500,
            enabled: true,
            alert_on_create: true,
            alert_on_modify: true,
            alert_on_access: false,
            metadata: HashMap::new(),
        }
    }
}

/// Statistics for a file monitor
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileMonitorStats {
    /// Total events received
    pub events_received: u64,
    /// Events that triggered scans
    pub events_scanned: u64,
    /// Events skipped (filtered out)
    pub events_skipped: u64,
    /// Total alerts generated
    pub alerts_generated: u64,
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Total scan time (ms)
    pub total_scan_time_ms: u64,
    /// Last event timestamp
    pub last_event_at: Option<DateTime<Utc>>,
    /// Last alert timestamp
    pub last_alert_at: Option<DateTime<Utc>>,
    /// Errors encountered
    pub errors: u64,
}

/// Status of a file monitor
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    /// Monitor is running
    Running,
    /// Monitor is stopped
    Stopped,
    /// Monitor is paused
    Paused,
    /// Monitor encountered an error
    Error,
}

impl std::fmt::Display for MonitorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitorStatus::Running => write!(f, "running"),
            MonitorStatus::Stopped => write!(f, "stopped"),
            MonitorStatus::Paused => write!(f, "paused"),
            MonitorStatus::Error => write!(f, "error"),
        }
    }
}

/// A file event that was detected
#[derive(Debug, Clone)]
struct FileEvent {
    path: PathBuf,
    event_type: FileEventType,
    timestamp: Instant,
}

// ============================================================================
// File Monitor
// ============================================================================

/// Real-time file system monitor with YARA scanning
pub struct FileMonitor {
    config: FileMonitorConfig,
    scanner: Arc<RwLock<YaraScanner>>,
    status: Arc<RwLock<MonitorStatus>>,
    stats: Arc<RwLock<FileMonitorStats>>,
    alert_tx: broadcast::Sender<FileMonitorAlert>,
    stop_tx: Option<mpsc::Sender<()>>,
}

impl FileMonitor {
    /// Create a new file monitor
    pub fn new(config: FileMonitorConfig, rules: Vec<YaraRule>) -> Result<Self> {
        let mut scanner = YaraScanner::new();
        scanner.add_rules(rules);
        scanner.compile()?;

        let (alert_tx, _) = broadcast::channel(1000);

        Ok(Self {
            config,
            scanner: Arc::new(RwLock::new(scanner)),
            status: Arc::new(RwLock::new(MonitorStatus::Stopped)),
            stats: Arc::new(RwLock::new(FileMonitorStats::default())),
            alert_tx,
            stop_tx: None,
        })
    }

    /// Get the monitor configuration
    pub fn config(&self) -> &FileMonitorConfig {
        &self.config
    }

    /// Get current status
    pub async fn status(&self) -> MonitorStatus {
        *self.status.read().await
    }

    /// Get current statistics
    pub async fn stats(&self) -> FileMonitorStats {
        self.stats.read().await.clone()
    }

    /// Subscribe to alerts
    pub fn subscribe_alerts(&self) -> broadcast::Receiver<FileMonitorAlert> {
        self.alert_tx.subscribe()
    }

    /// Start the file monitor
    pub async fn start(&mut self) -> Result<()> {
        if !self.config.enabled {
            return Err(anyhow!("Monitor is disabled"));
        }

        if self.config.paths.is_empty() {
            return Err(anyhow!("No paths configured to monitor"));
        }

        // Check if already running
        {
            let status = self.status.read().await;
            if *status == MonitorStatus::Running {
                return Err(anyhow!("Monitor is already running"));
            }
        }

        *self.status.write().await = MonitorStatus::Running;

        // Create stop channel
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);
        self.stop_tx = Some(stop_tx);

        // Clone Arcs for the monitoring task
        let config = self.config.clone();
        let scanner = Arc::clone(&self.scanner);
        let status = Arc::clone(&self.status);
        let stats = Arc::clone(&self.stats);
        let alert_tx = self.alert_tx.clone();

        // Spawn the monitoring task
        tokio::spawn(async move {
            if let Err(e) = run_monitor(config, scanner, status.clone(), stats, alert_tx, stop_rx).await {
                log::error!("File monitor error: {}", e);
                *status.write().await = MonitorStatus::Error;
            }
        });

        Ok(())
    }

    /// Stop the file monitor
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(()).await;
        }
        *self.status.write().await = MonitorStatus::Stopped;
        Ok(())
    }

    /// Pause the file monitor (keeps watcher running but doesn't scan)
    pub async fn pause(&mut self) -> Result<()> {
        let mut status = self.status.write().await;
        if *status == MonitorStatus::Running {
            *status = MonitorStatus::Paused;
        }
        Ok(())
    }

    /// Resume a paused monitor
    pub async fn resume(&mut self) -> Result<()> {
        let mut status = self.status.write().await;
        if *status == MonitorStatus::Paused {
            *status = MonitorStatus::Running;
        }
        Ok(())
    }

    /// Update YARA rules
    pub async fn update_rules(&self, rules: Vec<YaraRule>) -> Result<()> {
        let mut scanner = self.scanner.write().await;
        *scanner = YaraScanner::new();
        scanner.add_rules(rules);
        scanner.compile()?;
        Ok(())
    }

    /// Manually scan a file
    pub async fn scan_file(&self, path: &str) -> Result<Vec<YaraMatch>> {
        let mut scanner = self.scanner.write().await;
        scanner.scan_file(path).await
    }
}

/// Run the file monitor in a background task
async fn run_monitor(
    config: FileMonitorConfig,
    scanner: Arc<RwLock<YaraScanner>>,
    status: Arc<RwLock<MonitorStatus>>,
    stats: Arc<RwLock<FileMonitorStats>>,
    alert_tx: broadcast::Sender<FileMonitorAlert>,
    mut stop_rx: mpsc::Receiver<()>,
) -> Result<()> {
    // Create notify watcher
    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(1000);

    let tx_clone = tx.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx_clone.blocking_send(res);
        },
        Config::default().with_poll_interval(Duration::from_millis(config.debounce_ms)),
    )?;

    // Add paths to watch
    let mode = if config.recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };

    for path in &config.paths {
        let path = Path::new(path);
        if path.exists() {
            watcher.watch(path, mode)?;
            log::info!("Watching path: {}", path.display());
        } else {
            log::warn!("Path does not exist, skipping: {}", path.display());
        }
    }

    // Debounce state
    let debounce_duration = Duration::from_millis(config.debounce_ms);
    let mut pending_events: HashMap<PathBuf, FileEvent> = HashMap::new();
    let mut last_process = Instant::now();

    loop {
        tokio::select! {
            // Check for stop signal
            _ = stop_rx.recv() => {
                log::info!("File monitor received stop signal");
                break;
            }

            // Process file system events
            Some(event_result) = rx.recv() => {
                match event_result {
                    Ok(event) => {
                        // Update stats
                        {
                            let mut s = stats.write().await;
                            s.events_received += 1;
                            s.last_event_at = Some(Utc::now());
                        }

                        // Check if paused
                        if *status.read().await == MonitorStatus::Paused {
                            continue;
                        }

                        // Convert event type
                        let event_type = match event.kind {
                            EventKind::Create(_) => FileEventType::Created,
                            EventKind::Modify(_) => FileEventType::Modified,
                            EventKind::Remove(_) => FileEventType::Deleted,
                            EventKind::Access(_) => FileEventType::Accessed,
                            _ => FileEventType::Unknown,
                        };

                        // Filter by event type
                        let should_process = match event_type {
                            FileEventType::Created => config.alert_on_create,
                            FileEventType::Modified => config.alert_on_modify,
                            FileEventType::Accessed => config.alert_on_access,
                            FileEventType::Deleted => false, // Can't scan deleted files
                            _ => false,
                        };

                        if !should_process {
                            let mut s = stats.write().await;
                            s.events_skipped += 1;
                            continue;
                        }

                        // Add to pending events (for debouncing)
                        for path in event.paths {
                            if should_scan_file(&path, &config) {
                                pending_events.insert(path.clone(), FileEvent {
                                    path,
                                    event_type,
                                    timestamp: Instant::now(),
                                });
                            } else {
                                let mut s = stats.write().await;
                                s.events_skipped += 1;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("File watcher error: {}", e);
                        let mut s = stats.write().await;
                        s.errors += 1;
                    }
                }
            }
        }

        // Process debounced events
        if last_process.elapsed() >= debounce_duration && !pending_events.is_empty() {
            let events_to_process: Vec<_> = pending_events
                .drain()
                .filter(|(_, e)| e.timestamp.elapsed() >= debounce_duration)
                .collect();

            for (path, event) in events_to_process {
                match scan_and_alert(&path, event.event_type, &config, &scanner, &stats, &alert_tx).await {
                    Ok(Some(alert)) => {
                        log::info!("Alert generated for {}: {} matches", path.display(), alert.matches.len());
                    }
                    Ok(None) => {
                        // No matches, normal
                    }
                    Err(e) => {
                        log::error!("Error scanning {}: {}", path.display(), e);
                        let mut s = stats.write().await;
                        s.errors += 1;
                    }
                }
            }
            last_process = Instant::now();
        }
    }

    Ok(())
}

/// Check if a file should be scanned based on config
fn should_scan_file(path: &Path, config: &FileMonitorConfig) -> bool {
    // Check if it's a file
    if !path.is_file() {
        return false;
    }

    // Check exclude paths
    let path_str = path.to_string_lossy();
    for exclude in &config.exclude_paths {
        if path_str.contains(exclude) {
            return false;
        }
    }

    // Check file extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_lowercase();

        // Check exclude extensions
        if config.exclude_extensions.iter().any(|e| e.to_lowercase() == ext_lower) {
            return false;
        }

        // Check include extensions (if specified)
        if !config.include_extensions.is_empty() {
            if !config.include_extensions.iter().any(|e| e.to_lowercase() == ext_lower) {
                return false;
            }
        }
    }

    true
}

/// Scan a file and generate alert if matches found
async fn scan_and_alert(
    path: &Path,
    event_type: FileEventType,
    config: &FileMonitorConfig,
    scanner: &Arc<RwLock<YaraScanner>>,
    stats: &Arc<RwLock<FileMonitorStats>>,
    alert_tx: &broadcast::Sender<FileMonitorAlert>,
) -> Result<Option<FileMonitorAlert>> {
    // Check file size
    let metadata = fs::metadata(path).await?;
    let file_size = metadata.len();

    if file_size > config.max_file_size {
        let mut s = stats.write().await;
        s.events_skipped += 1;
        return Ok(None);
    }

    // Calculate file hash
    let data = fs::read(path).await?;
    let mut hasher = Md5::new();
    hasher.update(&data);
    let file_hash = Some(format!("{:x}", hasher.finalize()));

    // Scan the file
    let start_time = Instant::now();
    let matches = {
        let mut scanner = scanner.write().await;
        scanner.scan_bytes(&data).await?
    };
    let scan_time = start_time.elapsed();

    // Update stats
    {
        let mut s = stats.write().await;
        s.events_scanned += 1;
        s.bytes_scanned += file_size;
        s.total_scan_time_ms += scan_time.as_millis() as u64;
    }

    // Generate alert if matches found
    if !matches.is_empty() {
        // Determine severity based on matches
        let severity = matches
            .iter()
            .filter_map(|m| m.metadata.severity.as_ref())
            .filter_map(|s| match s.to_lowercase().as_str() {
                "critical" => Some(AlertSeverity::Critical),
                "high" => Some(AlertSeverity::High),
                "medium" => Some(AlertSeverity::Medium),
                "low" => Some(AlertSeverity::Low),
                "info" => Some(AlertSeverity::Info),
                _ => None,
            })
            .max()
            .unwrap_or(AlertSeverity::Medium);

        let alert = FileMonitorAlert {
            id: uuid::Uuid::new_v4().to_string(),
            file_path: path.to_string_lossy().to_string(),
            event_type,
            matches: matches.clone(),
            severity,
            file_hash,
            file_size,
            monitor_id: config.id.clone(),
            created_at: Utc::now(),
            acknowledged: false,
            notes: None,
        };

        // Update stats
        {
            let mut s = stats.write().await;
            s.alerts_generated += 1;
            s.last_alert_at = Some(Utc::now());
        }

        // Send alert
        let _ = alert_tx.send(alert.clone());

        Ok(Some(alert))
    } else {
        Ok(None)
    }
}

// ============================================================================
// Monitor Manager
// ============================================================================

/// Manages multiple file monitors
pub struct MonitorManager {
    monitors: Arc<RwLock<HashMap<String, FileMonitor>>>,
    rules: Arc<RwLock<Vec<YaraRule>>>,
}

impl MonitorManager {
    /// Create a new monitor manager
    pub fn new() -> Self {
        Self {
            monitors: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Set the YARA rules to use for all monitors
    pub async fn set_rules(&self, rules: Vec<YaraRule>) {
        *self.rules.write().await = rules;
    }

    /// Add a new monitor
    pub async fn add_monitor(&self, config: FileMonitorConfig) -> Result<String> {
        let id = config.id.clone();
        let rules = self.rules.read().await.clone();
        let monitor = FileMonitor::new(config, rules)?;

        self.monitors.write().await.insert(id.clone(), monitor);
        Ok(id)
    }

    /// Remove a monitor
    pub async fn remove_monitor(&self, id: &str) -> Result<()> {
        let mut monitors = self.monitors.write().await;
        if let Some(mut monitor) = monitors.remove(id) {
            monitor.stop().await?;
        }
        Ok(())
    }

    /// Start a monitor
    pub async fn start_monitor(&self, id: &str) -> Result<()> {
        let mut monitors = self.monitors.write().await;
        if let Some(monitor) = monitors.get_mut(id) {
            monitor.start().await?;
        } else {
            return Err(anyhow!("Monitor not found: {}", id));
        }
        Ok(())
    }

    /// Stop a monitor
    pub async fn stop_monitor(&self, id: &str) -> Result<()> {
        let mut monitors = self.monitors.write().await;
        if let Some(monitor) = monitors.get_mut(id) {
            monitor.stop().await?;
        }
        Ok(())
    }

    /// Get all monitor statuses
    pub async fn list_monitors(&self) -> Vec<(String, FileMonitorConfig, MonitorStatus, FileMonitorStats)> {
        let monitors = self.monitors.read().await;
        let mut result = Vec::new();

        for (id, monitor) in monitors.iter() {
            let status = monitor.status().await;
            let stats = monitor.stats().await;
            result.push((id.clone(), monitor.config().clone(), status, stats));
        }

        result
    }

    /// Get a specific monitor
    pub async fn get_monitor(&self, id: &str) -> Option<(FileMonitorConfig, MonitorStatus, FileMonitorStats)> {
        let monitors = self.monitors.read().await;
        if let Some(monitor) = monitors.get(id) {
            Some((monitor.config().clone(), monitor.status().await, monitor.stats().await))
        } else {
            None
        }
    }

    /// Subscribe to alerts from a specific monitor
    pub async fn subscribe_alerts(&self, id: &str) -> Option<broadcast::Receiver<FileMonitorAlert>> {
        let monitors = self.monitors.read().await;
        monitors.get(id).map(|m| m.subscribe_alerts())
    }

    /// Stop all monitors
    pub async fn stop_all(&self) -> Result<()> {
        let mut monitors = self.monitors.write().await;
        for (_, monitor) in monitors.iter_mut() {
            let _ = monitor.stop().await;
        }
        Ok(())
    }
}

impl Default for MonitorManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_file_monitor_config_default() {
        let config = FileMonitorConfig::default();
        assert!(config.enabled);
        assert!(config.recursive);
        assert!(config.alert_on_create);
        assert!(config.alert_on_modify);
        assert!(!config.alert_on_access);
    }

    #[test]
    fn test_should_scan_file() {
        let config = FileMonitorConfig {
            exclude_extensions: vec!["log".to_string(), "tmp".to_string()],
            exclude_paths: vec![".git".to_string()],
            include_extensions: Vec::new(),
            ..Default::default()
        };

        // Create temp files for testing
        let dir = tempdir().unwrap();

        let test_file = dir.path().join("test.exe");
        std::fs::File::create(&test_file).unwrap();
        assert!(should_scan_file(&test_file, &config));

        let log_file = dir.path().join("test.log");
        std::fs::File::create(&log_file).unwrap();
        assert!(!should_scan_file(&log_file, &config));

        let git_file = dir.path().join(".git/config");
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::File::create(&git_file).unwrap();
        assert!(!should_scan_file(&git_file, &config));
    }

    #[tokio::test]
    async fn test_monitor_manager() {
        let manager = MonitorManager::new();

        let config = FileMonitorConfig {
            name: "Test Monitor".to_string(),
            paths: vec!["/tmp".to_string()],
            ..Default::default()
        };

        let id = manager.add_monitor(config).await.unwrap();

        let monitors = manager.list_monitors().await;
        assert_eq!(monitors.len(), 1);
        assert_eq!(monitors[0].0, id);

        manager.remove_monitor(&id).await.unwrap();
        let monitors = manager.list_monitors().await;
        assert!(monitors.is_empty());
    }
}
