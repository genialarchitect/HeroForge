//! DISA STIG Repository Sync Types
//!
//! Type definitions for STIG repository synchronization.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Entry representing a STIG available in the repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigEntry {
    /// Unique identifier for the STIG
    pub stig_id: String,
    /// Human-readable name (e.g., "Windows Server 2022 STIG")
    pub name: String,
    /// Short name/acronym (e.g., "WinServer2022")
    pub short_name: String,
    /// STIG version number (e.g., 1)
    pub version: i32,
    /// STIG release number (e.g., 1)
    pub release: i32,
    /// Release date
    pub release_date: Option<NaiveDate>,
    /// Target operating system or application
    pub target_product: String,
    /// Category (OS, Application, Network, etc.)
    pub category: StigCategory,
    /// Download URL for the ZIP bundle
    pub download_url: String,
    /// File size in bytes (if known)
    pub file_size: Option<u64>,
    /// SHA-256 hash of the file (if known)
    pub file_hash: Option<String>,
    /// Whether this is a benchmark STIG
    pub is_benchmark: bool,
}

/// Category of STIG
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StigCategory {
    /// Operating System STIGs
    OperatingSystem,
    /// Application STIGs
    Application,
    /// Network Device STIGs
    NetworkDevice,
    /// Database STIGs
    Database,
    /// Web Server STIGs
    WebServer,
    /// Virtualization STIGs
    Virtualization,
    /// Mobile Device STIGs
    MobileDevice,
    /// Container/Cloud STIGs
    Container,
    /// Uncategorized
    Other,
}

impl std::fmt::Display for StigCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperatingSystem => write!(f, "Operating System"),
            Self::Application => write!(f, "Application"),
            Self::NetworkDevice => write!(f, "Network Device"),
            Self::Database => write!(f, "Database"),
            Self::WebServer => write!(f, "Web Server"),
            Self::Virtualization => write!(f, "Virtualization"),
            Self::MobileDevice => write!(f, "Mobile Device"),
            Self::Container => write!(f, "Container/Cloud"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Status of a tracked STIG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedStig {
    /// Local database ID
    pub id: String,
    /// STIG identifier
    pub stig_id: String,
    /// STIG name
    pub stig_name: String,
    /// Current version installed locally
    pub current_version: i32,
    /// Current release installed locally
    pub current_release: i32,
    /// Available version from DISA (if newer)
    pub available_version: Option<i32>,
    /// Available release from DISA (if newer)
    pub available_release: Option<i32>,
    /// Release date of local version
    pub release_date: Option<NaiveDate>,
    /// Local bundle ID in scap_content_bundles
    pub bundle_id: Option<String>,
    /// Local file path to the STIG bundle
    pub local_path: Option<String>,
    /// Download URL
    pub download_url: Option<String>,
    /// Last time we checked for updates
    pub last_checked_at: Option<DateTime<Utc>>,
    /// Last time the STIG was updated locally
    pub last_updated_at: Option<DateTime<Utc>>,
    /// Whether auto-update is enabled
    pub auto_update: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Status of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigSyncStatus {
    /// Whether a sync is currently in progress
    pub in_progress: bool,
    /// Current operation (if in progress)
    pub current_operation: Option<String>,
    /// Last successful sync time
    pub last_sync_at: Option<DateTime<Utc>>,
    /// Last sync result
    pub last_sync_result: Option<SyncResult>,
    /// Next scheduled sync time
    pub next_sync_at: Option<DateTime<Utc>>,
    /// Total STIGs tracked
    pub total_tracked: usize,
    /// STIGs with updates available
    pub updates_available: usize,
    /// Errors from last sync (if any)
    pub last_errors: Vec<String>,
}

/// Result of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResult {
    Success,
    PartialSuccess,
    Failed,
}

/// Record of a sync history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigSyncHistoryEntry {
    /// Unique ID
    pub id: String,
    /// STIG ID that was synced
    pub stig_id: String,
    /// Old version before sync
    pub old_version: Option<i32>,
    /// New version after sync
    pub new_version: i32,
    /// Old release before sync
    pub old_release: Option<i32>,
    /// New release after sync
    pub new_release: i32,
    /// Type of sync operation
    pub sync_type: SyncType,
    /// Status of the sync
    pub status: SyncEntryStatus,
    /// Error message if failed
    pub error_message: Option<String>,
    /// When the sync occurred
    pub synced_at: DateTime<Utc>,
}

/// Type of sync operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncType {
    /// Initial download/import
    Initial,
    /// Automatic update check
    AutoUpdate,
    /// Manual update
    Manual,
    /// Re-download due to corruption
    Repair,
}

impl std::fmt::Display for SyncType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initial => write!(f, "initial"),
            Self::AutoUpdate => write!(f, "auto_update"),
            Self::Manual => write!(f, "manual"),
            Self::Repair => write!(f, "repair"),
        }
    }
}

/// Status of a sync history entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncEntryStatus {
    Started,
    Downloading,
    Parsing,
    Importing,
    Completed,
    Failed,
}

impl std::fmt::Display for SyncEntryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Started => write!(f, "started"),
            Self::Downloading => write!(f, "downloading"),
            Self::Parsing => write!(f, "parsing"),
            Self::Importing => write!(f, "importing"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Configuration for STIG sync
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigSyncConfig {
    /// Base URL for DISA STIG downloads
    pub disa_base_url: String,
    /// Directory to store downloaded STIG bundles
    pub download_dir: String,
    /// How often to check for updates (in hours)
    pub check_interval_hours: u32,
    /// Whether to auto-download updates
    pub auto_download: bool,
    /// Maximum concurrent downloads
    pub max_concurrent_downloads: usize,
    /// HTTP timeout in seconds
    pub http_timeout_seconds: u64,
    /// Retry count for failed downloads
    pub retry_count: u32,
}

impl Default for StigSyncConfig {
    fn default() -> Self {
        Self {
            disa_base_url: "https://public.cyber.mil/stigs/downloads/".to_string(),
            download_dir: "./stig_downloads".to_string(),
            check_interval_hours: 24,
            auto_download: false,
            max_concurrent_downloads: 3,
            http_timeout_seconds: 300,
            retry_count: 3,
        }
    }
}

/// Parsed STIG from a downloaded bundle
#[derive(Debug, Clone)]
pub struct ParsedStig {
    /// Entry information
    pub entry: StigEntry,
    /// Path to the downloaded bundle
    pub bundle_path: String,
    /// XCCDF benchmark IDs found
    pub benchmark_ids: Vec<String>,
    /// OVAL definition count
    pub oval_definition_count: usize,
    /// Total rule count
    pub rule_count: usize,
}
