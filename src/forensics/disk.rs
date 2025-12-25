//! Disk Analysis module for Digital Forensics
//!
//! Provides capabilities for analyzing disk images:
//! - Disk image metadata parsing
//! - File system timeline (MFT-style timestamps)
//! - Deleted file recovery indicators
//! - Registry hive parsing (Windows)
//! - Browser artifact extraction
//! - Prefetch/recent files analysis

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::forensics::types::{AnalysisStatus, TimelineEventType};

// =============================================================================
// Disk Image Types
// =============================================================================

/// Disk image metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskImage {
    pub id: String,
    pub case_id: String,
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub image_type: DiskImageType,
    pub collected_at: DateTime<Utc>,
    pub analysis_status: AnalysisStatus,
    pub findings_json: Option<serde_json::Value>,
}

/// Type of disk image
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DiskImageType {
    Raw,
    Ewf,      // E01/EWF format
    Vhd,
    Vhdx,
    Vmdk,
    Qcow2,
    Dd,
    Aff,      // Advanced Forensic Format
    Other,
}

impl DiskImageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiskImageType::Raw => "raw",
            DiskImageType::Ewf => "ewf",
            DiskImageType::Vhd => "vhd",
            DiskImageType::Vhdx => "vhdx",
            DiskImageType::Vmdk => "vmdk",
            DiskImageType::Qcow2 => "qcow2",
            DiskImageType::Dd => "dd",
            DiskImageType::Aff => "aff",
            DiskImageType::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "raw" => DiskImageType::Raw,
            "ewf" | "e01" => DiskImageType::Ewf,
            "vhd" => DiskImageType::Vhd,
            "vhdx" => DiskImageType::Vhdx,
            "vmdk" => DiskImageType::Vmdk,
            "qcow2" => DiskImageType::Qcow2,
            "dd" => DiskImageType::Dd,
            "aff" => DiskImageType::Aff,
            _ => DiskImageType::Other,
        }
    }

    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "raw" | "img" | "bin" => DiskImageType::Raw,
            "e01" | "ex01" | "ewf" => DiskImageType::Ewf,
            "vhd" => DiskImageType::Vhd,
            "vhdx" => DiskImageType::Vhdx,
            "vmdk" => DiskImageType::Vmdk,
            "qcow2" => DiskImageType::Qcow2,
            "dd" => DiskImageType::Dd,
            "aff" | "afd" => DiskImageType::Aff,
            _ => DiskImageType::Other,
        }
    }
}

// =============================================================================
// File System Timeline
// =============================================================================

/// MFT-style file entry with timestamps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub name: String,
    pub size: i64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub changed: Option<DateTime<Utc>>, // MFT entry change time
    pub is_directory: bool,
    pub is_deleted: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub extension: Option<String>,
    pub mft_entry_number: Option<u64>,
    pub parent_mft_entry: Option<u64>,
    pub attributes: Vec<String>,
}

/// Timeline entry for file system events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub path: String,
    pub name: String,
    pub size: i64,
    pub is_deleted: bool,
    pub mft_entry: Option<u64>,
    pub details: Option<String>,
}

/// File system timeline result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineResult {
    pub entries: Vec<FileTimelineEntry>,
    pub total_count: u32,
    pub deleted_count: u32,
    pub by_event_type: HashMap<String, u32>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Deleted File Recovery
// =============================================================================

/// Deleted file indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFile {
    pub path: String,
    pub name: String,
    pub size: i64,
    pub deleted_time: Option<DateTime<Utc>>,
    pub original_location: Option<String>,
    pub recovery_status: RecoveryStatus,
    pub cluster_range: Option<String>,
    pub mft_entry: Option<u64>,
    pub file_signature: Option<String>,
}

/// Recovery status for deleted files
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    FullyRecoverable,
    PartiallyRecoverable,
    Overwritten,
    Unknown,
}

impl RecoveryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecoveryStatus::FullyRecoverable => "fully_recoverable",
            RecoveryStatus::PartiallyRecoverable => "partially_recoverable",
            RecoveryStatus::Overwritten => "overwritten",
            RecoveryStatus::Unknown => "unknown",
        }
    }
}

/// Deleted files analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFilesResult {
    pub files: Vec<DeletedFile>,
    pub total_count: u32,
    pub recoverable_count: u32,
    pub by_extension: HashMap<String, u32>,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Registry Analysis (Windows)
// =============================================================================

/// Registry hive type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RegistryHive {
    Sam,
    Security,
    Software,
    System,
    NtUser,
    UsrClass,
    AmCache,
    Default,
}

impl RegistryHive {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistryHive::Sam => "SAM",
            RegistryHive::Security => "SECURITY",
            RegistryHive::Software => "SOFTWARE",
            RegistryHive::System => "SYSTEM",
            RegistryHive::NtUser => "NTUSER.DAT",
            RegistryHive::UsrClass => "UsrClass.dat",
            RegistryHive::AmCache => "Amcache.hve",
            RegistryHive::Default => "DEFAULT",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "SAM" => Some(RegistryHive::Sam),
            "SECURITY" => Some(RegistryHive::Security),
            "SOFTWARE" => Some(RegistryHive::Software),
            "SYSTEM" => Some(RegistryHive::System),
            "NTUSER.DAT" | "NTUSER" => Some(RegistryHive::NtUser),
            "USRCLASS.DAT" | "USRCLASS" => Some(RegistryHive::UsrClass),
            "AMCACHE.HVE" | "AMCACHE" => Some(RegistryHive::AmCache),
            "DEFAULT" => Some(RegistryHive::Default),
            _ => None,
        }
    }
}

/// Registry key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    pub path: String,
    pub name: String,
    pub last_modified: Option<DateTime<Utc>>,
    pub values: Vec<RegistryValue>,
    pub subkey_count: u32,
    pub value_count: u32,
}

/// Registry value entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: RegistryValueType,
    pub data: String,
    pub raw_data: Option<Vec<u8>>,
}

/// Registry value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RegistryValueType {
    RegSz,
    RegExpandSz,
    RegBinary,
    RegDword,
    RegDwordBigEndian,
    RegLink,
    RegMultiSz,
    RegQword,
    RegNone,
    Unknown,
}

/// Registry analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAnalysisResult {
    pub hive: RegistryHive,
    pub keys: Vec<RegistryKey>,
    pub key_count: u32,
    pub value_count: u32,
    pub interesting_keys: Vec<InterestingRegistryKey>,
    pub analysis_notes: Vec<String>,
}

/// Interesting registry key with forensic context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterestingRegistryKey {
    pub path: String,
    pub category: String,
    pub description: String,
    pub values: Vec<RegistryValue>,
    pub forensic_relevance: String,
}

// =============================================================================
// Browser Artifacts
// =============================================================================

/// Browser type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Safari,
    InternetExplorer,
    Opera,
    Brave,
    Other,
}

impl BrowserType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BrowserType::Chrome => "chrome",
            BrowserType::Firefox => "firefox",
            BrowserType::Edge => "edge",
            BrowserType::Safari => "safari",
            BrowserType::InternetExplorer => "ie",
            BrowserType::Opera => "opera",
            BrowserType::Brave => "brave",
            BrowserType::Other => "other",
        }
    }
}

/// Browser history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHistoryEntry {
    pub browser: BrowserType,
    pub url: String,
    pub title: Option<String>,
    pub visit_time: DateTime<Utc>,
    pub visit_count: u32,
    pub from_visit: Option<String>,
    pub transition_type: Option<String>,
}

/// Browser download entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownload {
    pub browser: BrowserType,
    pub url: String,
    pub target_path: String,
    pub filename: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub received_bytes: i64,
    pub total_bytes: i64,
    pub danger_type: Option<String>,
    pub mime_type: Option<String>,
}

/// Browser cookie entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCookie {
    pub browser: BrowserType,
    pub host: String,
    pub name: String,
    pub path: String,
    pub value: Option<String>,
    pub creation_time: DateTime<Utc>,
    pub last_access_time: DateTime<Utc>,
    pub expiry_time: Option<DateTime<Utc>>,
    pub is_secure: bool,
    pub is_http_only: bool,
}

/// Browser artifacts result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserArtifactsResult {
    pub history: Vec<BrowserHistoryEntry>,
    pub downloads: Vec<BrowserDownload>,
    pub cookies: Vec<BrowserCookie>,
    pub history_count: u32,
    pub download_count: u32,
    pub cookie_count: u32,
    pub by_browser: HashMap<String, BrowserStats>,
    pub analysis_notes: Vec<String>,
}

/// Browser statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserStats {
    pub history_count: u32,
    pub download_count: u32,
    pub cookie_count: u32,
}

// =============================================================================
// Prefetch Analysis (Windows)
// =============================================================================

/// Prefetch file entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchEntry {
    pub filename: String,
    pub executable_name: String,
    pub hash: String,
    pub run_count: u32,
    pub last_run_time: DateTime<Utc>,
    pub previous_run_times: Vec<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub file_references: Vec<String>,
    pub volume_info: Vec<PrefetchVolume>,
}

/// Prefetch volume information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchVolume {
    pub device_path: String,
    pub serial_number: String,
    pub creation_time: DateTime<Utc>,
}

/// Prefetch analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchResult {
    pub entries: Vec<PrefetchEntry>,
    pub total_count: u32,
    pub suspicious_entries: Vec<PrefetchEntry>,
    pub by_date: HashMap<String, u32>,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Recent Files Analysis
// =============================================================================

/// Recent file link (LNK) entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentFileEntry {
    pub link_path: String,
    pub target_path: String,
    pub target_name: String,
    pub target_size: i64,
    pub target_created: Option<DateTime<Utc>>,
    pub target_modified: Option<DateTime<Utc>>,
    pub target_accessed: Option<DateTime<Utc>>,
    pub link_created: DateTime<Utc>,
    pub link_modified: DateTime<Utc>,
    pub link_accessed: DateTime<Utc>,
    pub volume_serial: Option<String>,
    pub machine_id: Option<String>,
    pub mac_address: Option<String>,
}

/// Recent files analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentFilesResult {
    pub entries: Vec<RecentFileEntry>,
    pub total_count: u32,
    pub by_extension: HashMap<String, u32>,
    pub unique_targets: u32,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Disk Analyzer
// =============================================================================

/// Disk analyzer with configurable options
pub struct DiskAnalyzer {
    suspicious_extensions: Vec<String>,
    suspicious_paths: Vec<String>,
    interesting_registry_paths: Vec<(String, String)>,
}

impl Default for DiskAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DiskAnalyzer {
    pub fn new() -> Self {
        Self {
            suspicious_extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "scr".to_string(),
                "pif".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "ps1".to_string(),
                "vbs".to_string(),
                "js".to_string(),
                "hta".to_string(),
            ],
            suspicious_paths: vec![
                "\\temp\\".to_string(),
                "\\tmp\\".to_string(),
                "\\users\\public\\".to_string(),
                "\\programdata\\".to_string(),
                "\\appdata\\local\\temp\\".to_string(),
            ],
            interesting_registry_paths: vec![
                ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(), "Startup programs".to_string()),
                ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(), "One-time startup".to_string()),
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(), "User startup programs".to_string()),
                ("HKLM\\SYSTEM\\CurrentControlSet\\Services".to_string(), "Windows services".to_string()),
                ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks".to_string(), "Scheduled tasks".to_string()),
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs".to_string(), "Recent documents".to_string()),
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU".to_string(), "Run dialog history".to_string()),
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths".to_string(), "Explorer typed paths".to_string()),
            ],
        }
    }

    /// Build timeline from file entries
    pub fn build_timeline(
        &self,
        files: Vec<FileEntry>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> TimelineResult {
        let mut entries = Vec::new();
        let mut by_event_type: HashMap<String, u32> = HashMap::new();
        let mut deleted_count = 0;

        for file in files {
            // Add created event
            if let Some(created) = file.created {
                if self.in_time_range(&created, &start_time, &end_time) {
                    entries.push(FileTimelineEntry {
                        timestamp: created,
                        event_type: TimelineEventType::FileCreated,
                        path: file.path.clone(),
                        name: file.name.clone(),
                        size: file.size,
                        is_deleted: file.is_deleted,
                        mft_entry: file.mft_entry_number,
                        details: None,
                    });
                    *by_event_type.entry("file_created".to_string()).or_insert(0) += 1;
                }
            }

            // Add modified event
            if let Some(modified) = file.modified {
                if self.in_time_range(&modified, &start_time, &end_time) {
                    entries.push(FileTimelineEntry {
                        timestamp: modified,
                        event_type: TimelineEventType::FileModified,
                        path: file.path.clone(),
                        name: file.name.clone(),
                        size: file.size,
                        is_deleted: file.is_deleted,
                        mft_entry: file.mft_entry_number,
                        details: None,
                    });
                    *by_event_type.entry("file_modified".to_string()).or_insert(0) += 1;
                }
            }

            // Add accessed event
            if let Some(accessed) = file.accessed {
                if self.in_time_range(&accessed, &start_time, &end_time) {
                    entries.push(FileTimelineEntry {
                        timestamp: accessed,
                        event_type: TimelineEventType::FileAccessed,
                        path: file.path.clone(),
                        name: file.name.clone(),
                        size: file.size,
                        is_deleted: file.is_deleted,
                        mft_entry: file.mft_entry_number,
                        details: None,
                    });
                    *by_event_type.entry("file_accessed".to_string()).or_insert(0) += 1;
                }
            }

            if file.is_deleted {
                deleted_count += 1;
            }
        }

        // Sort by timestamp
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let actual_start = entries.first().map(|e| e.timestamp);
        let actual_end = entries.last().map(|e| e.timestamp);

        let mut result = TimelineResult {
            total_count: entries.len() as u32,
            deleted_count,
            entries,
            by_event_type,
            start_time: actual_start,
            end_time: actual_end,
            analysis_notes: Vec::new(),
        };

        result.analysis_notes.push(format!(
            "Generated timeline with {} events",
            result.total_count
        ));

        if deleted_count > 0 {
            result.analysis_notes.push(format!(
                "Timeline includes {} events from deleted files",
                deleted_count
            ));
        }

        result
    }

    /// Analyze deleted files
    pub fn analyze_deleted_files(&self, files: Vec<DeletedFile>) -> DeletedFilesResult {
        let mut by_extension: HashMap<String, u32> = HashMap::new();
        let mut recoverable_count = 0;

        for file in &files {
            // Count by extension
            let ext = file.name.split('.').last().unwrap_or("unknown").to_lowercase();
            *by_extension.entry(ext).or_insert(0) += 1;

            // Count recoverable
            if file.recovery_status == RecoveryStatus::FullyRecoverable
                || file.recovery_status == RecoveryStatus::PartiallyRecoverable
            {
                recoverable_count += 1;
            }
        }

        let mut result = DeletedFilesResult {
            total_count: files.len() as u32,
            recoverable_count,
            files,
            by_extension,
            analysis_notes: Vec::new(),
        };

        result.analysis_notes.push(format!(
            "Found {} deleted files, {} potentially recoverable",
            result.total_count, recoverable_count
        ));

        result
    }

    /// Get interesting registry keys for forensic analysis
    pub fn get_interesting_registry_paths(&self) -> Vec<(String, String)> {
        self.interesting_registry_paths.clone()
    }

    /// Analyze browser artifacts
    pub fn analyze_browser_artifacts(
        &self,
        history: Vec<BrowserHistoryEntry>,
        downloads: Vec<BrowserDownload>,
        cookies: Vec<BrowserCookie>,
    ) -> BrowserArtifactsResult {
        let mut by_browser: HashMap<String, BrowserStats> = HashMap::new();

        // Count by browser for history
        for entry in &history {
            let stats = by_browser
                .entry(entry.browser.as_str().to_string())
                .or_insert(BrowserStats {
                    history_count: 0,
                    download_count: 0,
                    cookie_count: 0,
                });
            stats.history_count += 1;
        }

        // Count by browser for downloads
        for entry in &downloads {
            let stats = by_browser
                .entry(entry.browser.as_str().to_string())
                .or_insert(BrowserStats {
                    history_count: 0,
                    download_count: 0,
                    cookie_count: 0,
                });
            stats.download_count += 1;
        }

        // Count by browser for cookies
        for entry in &cookies {
            let stats = by_browser
                .entry(entry.browser.as_str().to_string())
                .or_insert(BrowserStats {
                    history_count: 0,
                    download_count: 0,
                    cookie_count: 0,
                });
            stats.cookie_count += 1;
        }

        let mut result = BrowserArtifactsResult {
            history_count: history.len() as u32,
            download_count: downloads.len() as u32,
            cookie_count: cookies.len() as u32,
            history,
            downloads,
            cookies,
            by_browser,
            analysis_notes: Vec::new(),
        };

        result.analysis_notes.push(format!(
            "Analyzed {} history entries, {} downloads, {} cookies",
            result.history_count, result.download_count, result.cookie_count
        ));

        result
    }

    /// Analyze prefetch files
    pub fn analyze_prefetch(&self, entries: Vec<PrefetchEntry>) -> PrefetchResult {
        let mut suspicious = Vec::new();
        let mut by_date: HashMap<String, u32> = HashMap::new();

        for entry in &entries {
            // Group by date
            let date = entry.last_run_time.format("%Y-%m-%d").to_string();
            *by_date.entry(date).or_insert(0) += 1;

            // Check for suspicious characteristics
            let name_lower = entry.executable_name.to_lowercase();
            let is_suspicious = self.suspicious_extensions.iter().any(|ext| {
                name_lower.ends_with(ext)
            }) && entry.file_references.iter().any(|ref_path| {
                let path_lower = ref_path.to_lowercase();
                self.suspicious_paths.iter().any(|sp| path_lower.contains(sp))
            });

            if is_suspicious {
                suspicious.push(entry.clone());
            }
        }

        let mut result = PrefetchResult {
            total_count: entries.len() as u32,
            entries,
            suspicious_entries: suspicious,
            by_date,
            analysis_notes: Vec::new(),
        };

        if !result.suspicious_entries.is_empty() {
            result.analysis_notes.push(format!(
                "Found {} suspicious prefetch entries",
                result.suspicious_entries.len()
            ));
        }

        result
    }

    // Helper: Check if timestamp is in range
    fn in_time_range(
        &self,
        timestamp: &DateTime<Utc>,
        start: &Option<DateTime<Utc>>,
        end: &Option<DateTime<Utc>>,
    ) -> bool {
        if let Some(s) = start {
            if timestamp < s {
                return false;
            }
        }
        if let Some(e) = end {
            if timestamp > e {
                return false;
            }
        }
        true
    }
}

/// Get browser artifact paths for different browsers on Windows
pub fn get_browser_artifact_paths_windows() -> HashMap<BrowserType, BrowserPaths> {
    let mut paths = HashMap::new();

    paths.insert(
        BrowserType::Chrome,
        BrowserPaths {
            history: vec![
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History".to_string(),
            ],
            downloads: vec![
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History".to_string(),
            ],
            cookies: vec![
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies".to_string(),
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies".to_string(),
            ],
            cache: vec![
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache".to_string(),
            ],
        },
    );

    paths.insert(
        BrowserType::Firefox,
        BrowserPaths {
            history: vec![
                "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite".to_string(),
            ],
            downloads: vec![
                "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite".to_string(),
            ],
            cookies: vec![
                "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite".to_string(),
            ],
            cache: vec![
                "%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cache2".to_string(),
            ],
        },
    );

    paths.insert(
        BrowserType::Edge,
        BrowserPaths {
            history: vec![
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History".to_string(),
            ],
            downloads: vec![
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History".to_string(),
            ],
            cookies: vec![
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cookies".to_string(),
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies".to_string(),
            ],
            cache: vec![
                "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache".to_string(),
            ],
        },
    );

    paths
}

/// Browser artifact paths structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserPaths {
    pub history: Vec<String>,
    pub downloads: Vec<String>,
    pub cookies: Vec<String>,
    pub cache: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disk_image_type_from_extension() {
        assert_eq!(DiskImageType::from_extension("e01"), DiskImageType::Ewf);
        assert_eq!(DiskImageType::from_extension("vmdk"), DiskImageType::Vmdk);
        assert_eq!(DiskImageType::from_extension("raw"), DiskImageType::Raw);
        assert_eq!(DiskImageType::from_extension("unknown"), DiskImageType::Other);
    }

    #[test]
    fn test_disk_analyzer_new() {
        let analyzer = DiskAnalyzer::new();
        assert!(!analyzer.suspicious_extensions.is_empty());
        assert!(!analyzer.interesting_registry_paths.is_empty());
    }

    #[test]
    fn test_browser_type() {
        assert_eq!(BrowserType::Chrome.as_str(), "chrome");
        assert_eq!(BrowserType::Firefox.as_str(), "firefox");
    }

    #[test]
    fn test_recovery_status() {
        assert_eq!(RecoveryStatus::FullyRecoverable.as_str(), "fully_recoverable");
        assert_eq!(RecoveryStatus::Overwritten.as_str(), "overwritten");
    }
}
