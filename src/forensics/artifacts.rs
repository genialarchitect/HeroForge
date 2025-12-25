//! Artifact Collection module for Digital Forensics
//!
//! Provides capabilities for collecting and analyzing forensic artifacts:
//! - Artifact categories: Windows, Linux, Web artifacts
//! - Collection templates per OS
//! - Artifact storage with hashing
//! - Analysis notes per artifact

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Artifact Types
// =============================================================================

/// Operating system type for artifact collection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOs,
    Other,
}

impl OperatingSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatingSystem::Windows => "windows",
            OperatingSystem::Linux => "linux",
            OperatingSystem::MacOs => "macos",
            OperatingSystem::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "windows" | "win" => OperatingSystem::Windows,
            "linux" | "unix" => OperatingSystem::Linux,
            "macos" | "darwin" | "osx" => OperatingSystem::MacOs,
            _ => OperatingSystem::Other,
        }
    }
}

/// Artifact category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    // Windows
    Registry,
    EventLog,
    Prefetch,
    Lnk,
    JumpList,
    Amcache,
    Shimcache,
    Srum,
    Shellbag,
    Ntfs,
    Usb,
    UserAssist,
    RecycleBin,
    Wmi,
    Task,
    Service,

    // Linux
    AuthLog,
    SysLog,
    BashHistory,
    Cron,
    Passwd,
    Shadow,
    Wtmp,
    Lastlog,
    Apt,
    Dpkg,
    Yum,
    SystemD,

    // Web/Browser
    BrowserHistory,
    BrowserCache,
    BrowserCookies,
    BrowserDownloads,
    BrowserBookmarks,
    BrowserPasswords,
    BrowserSession,

    // Cross-platform
    Network,
    Process,
    Memory,
    FileSystem,
    Application,
    Other,
}

impl ArtifactCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactCategory::Registry => "registry",
            ArtifactCategory::EventLog => "event_log",
            ArtifactCategory::Prefetch => "prefetch",
            ArtifactCategory::Lnk => "lnk",
            ArtifactCategory::JumpList => "jump_list",
            ArtifactCategory::Amcache => "amcache",
            ArtifactCategory::Shimcache => "shimcache",
            ArtifactCategory::Srum => "srum",
            ArtifactCategory::Shellbag => "shellbag",
            ArtifactCategory::Ntfs => "ntfs",
            ArtifactCategory::Usb => "usb",
            ArtifactCategory::UserAssist => "user_assist",
            ArtifactCategory::RecycleBin => "recycle_bin",
            ArtifactCategory::Wmi => "wmi",
            ArtifactCategory::Task => "task",
            ArtifactCategory::Service => "service",
            ArtifactCategory::AuthLog => "auth_log",
            ArtifactCategory::SysLog => "syslog",
            ArtifactCategory::BashHistory => "bash_history",
            ArtifactCategory::Cron => "cron",
            ArtifactCategory::Passwd => "passwd",
            ArtifactCategory::Shadow => "shadow",
            ArtifactCategory::Wtmp => "wtmp",
            ArtifactCategory::Lastlog => "lastlog",
            ArtifactCategory::Apt => "apt",
            ArtifactCategory::Dpkg => "dpkg",
            ArtifactCategory::Yum => "yum",
            ArtifactCategory::SystemD => "systemd",
            ArtifactCategory::BrowserHistory => "browser_history",
            ArtifactCategory::BrowserCache => "browser_cache",
            ArtifactCategory::BrowserCookies => "browser_cookies",
            ArtifactCategory::BrowserDownloads => "browser_downloads",
            ArtifactCategory::BrowserBookmarks => "browser_bookmarks",
            ArtifactCategory::BrowserPasswords => "browser_passwords",
            ArtifactCategory::BrowserSession => "browser_session",
            ArtifactCategory::Network => "network",
            ArtifactCategory::Process => "process",
            ArtifactCategory::Memory => "memory",
            ArtifactCategory::FileSystem => "file_system",
            ArtifactCategory::Application => "application",
            ArtifactCategory::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "registry" => ArtifactCategory::Registry,
            "event_log" | "eventlog" => ArtifactCategory::EventLog,
            "prefetch" => ArtifactCategory::Prefetch,
            "lnk" | "shortcut" => ArtifactCategory::Lnk,
            "jump_list" | "jumplist" => ArtifactCategory::JumpList,
            "amcache" => ArtifactCategory::Amcache,
            "shimcache" => ArtifactCategory::Shimcache,
            "srum" => ArtifactCategory::Srum,
            "shellbag" => ArtifactCategory::Shellbag,
            "ntfs" | "mft" => ArtifactCategory::Ntfs,
            "usb" => ArtifactCategory::Usb,
            "user_assist" | "userassist" => ArtifactCategory::UserAssist,
            "recycle_bin" | "recyclebin" => ArtifactCategory::RecycleBin,
            "wmi" => ArtifactCategory::Wmi,
            "task" | "scheduled_task" => ArtifactCategory::Task,
            "service" => ArtifactCategory::Service,
            "auth_log" | "authlog" | "auth.log" => ArtifactCategory::AuthLog,
            "syslog" => ArtifactCategory::SysLog,
            "bash_history" | "bashhistory" | ".bash_history" => ArtifactCategory::BashHistory,
            "cron" | "crontab" => ArtifactCategory::Cron,
            "passwd" | "/etc/passwd" => ArtifactCategory::Passwd,
            "shadow" | "/etc/shadow" => ArtifactCategory::Shadow,
            "wtmp" => ArtifactCategory::Wtmp,
            "lastlog" => ArtifactCategory::Lastlog,
            "apt" => ArtifactCategory::Apt,
            "dpkg" => ArtifactCategory::Dpkg,
            "yum" => ArtifactCategory::Yum,
            "systemd" | "systemctl" => ArtifactCategory::SystemD,
            "browser_history" => ArtifactCategory::BrowserHistory,
            "browser_cache" => ArtifactCategory::BrowserCache,
            "browser_cookies" | "cookies" => ArtifactCategory::BrowserCookies,
            "browser_downloads" | "downloads" => ArtifactCategory::BrowserDownloads,
            "browser_bookmarks" | "bookmarks" => ArtifactCategory::BrowserBookmarks,
            "browser_passwords" => ArtifactCategory::BrowserPasswords,
            "browser_session" | "session" => ArtifactCategory::BrowserSession,
            "network" => ArtifactCategory::Network,
            "process" => ArtifactCategory::Process,
            "memory" => ArtifactCategory::Memory,
            "file_system" | "filesystem" => ArtifactCategory::FileSystem,
            "application" | "app" => ArtifactCategory::Application,
            _ => ArtifactCategory::Other,
        }
    }

    /// Get the operating system this artifact category belongs to
    pub fn operating_system(&self) -> Option<OperatingSystem> {
        match self {
            // Windows-specific
            ArtifactCategory::Registry
            | ArtifactCategory::EventLog
            | ArtifactCategory::Prefetch
            | ArtifactCategory::Lnk
            | ArtifactCategory::JumpList
            | ArtifactCategory::Amcache
            | ArtifactCategory::Shimcache
            | ArtifactCategory::Srum
            | ArtifactCategory::Shellbag
            | ArtifactCategory::Ntfs
            | ArtifactCategory::UserAssist
            | ArtifactCategory::RecycleBin
            | ArtifactCategory::Wmi => Some(OperatingSystem::Windows),

            // Linux-specific
            ArtifactCategory::AuthLog
            | ArtifactCategory::SysLog
            | ArtifactCategory::BashHistory
            | ArtifactCategory::Cron
            | ArtifactCategory::Passwd
            | ArtifactCategory::Shadow
            | ArtifactCategory::Wtmp
            | ArtifactCategory::Lastlog
            | ArtifactCategory::Apt
            | ArtifactCategory::Dpkg
            | ArtifactCategory::Yum
            | ArtifactCategory::SystemD => Some(OperatingSystem::Linux),

            // Cross-platform or unspecified
            _ => None,
        }
    }
}

// =============================================================================
// Forensic Artifact
// =============================================================================

/// Forensic artifact entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicArtifact {
    pub id: String,
    pub case_id: String,
    pub artifact_type: ArtifactCategory,
    pub source_path: String,
    pub content_hash: String,
    pub collected_at: DateTime<Utc>,
    pub analysis_notes: Option<String>,
    pub tags: Vec<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Artifact collection request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactCollectionRequest {
    pub categories: Vec<ArtifactCategory>,
    pub operating_system: OperatingSystem,
    pub custom_paths: Option<Vec<String>>,
    pub include_metadata: bool,
    pub compute_hashes: bool,
}

// =============================================================================
// Collection Templates
// =============================================================================

/// Artifact path template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPath {
    pub category: ArtifactCategory,
    pub path: String,
    pub description: String,
    pub is_directory: bool,
    pub recursive: bool,
    pub file_pattern: Option<String>,
    pub forensic_value: String,
}

/// Collection template for an OS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionTemplate {
    pub operating_system: OperatingSystem,
    pub name: String,
    pub description: String,
    pub artifacts: Vec<ArtifactPath>,
}

/// Get Windows artifact collection template
pub fn get_windows_collection_template() -> CollectionTemplate {
    CollectionTemplate {
        operating_system: OperatingSystem::Windows,
        name: "Windows Full Collection".to_string(),
        description: "Comprehensive Windows forensic artifact collection".to_string(),
        artifacts: vec![
            // Registry Hives
            ArtifactPath {
                category: ArtifactCategory::Registry,
                path: "%SYSTEMROOT%\\System32\\config\\SAM".to_string(),
                description: "SAM registry hive - user accounts".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "User account information, password hashes".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Registry,
                path: "%SYSTEMROOT%\\System32\\config\\SYSTEM".to_string(),
                description: "SYSTEM registry hive".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "System configuration, services, drivers".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Registry,
                path: "%SYSTEMROOT%\\System32\\config\\SOFTWARE".to_string(),
                description: "SOFTWARE registry hive".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Installed software, autorun entries".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Registry,
                path: "%SYSTEMROOT%\\System32\\config\\SECURITY".to_string(),
                description: "SECURITY registry hive".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Security policies, LSA secrets".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Registry,
                path: "%USERPROFILE%\\NTUSER.DAT".to_string(),
                description: "User registry hive".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "User-specific settings, MRU lists, typed URLs".to_string(),
            },
            // Event Logs
            ArtifactPath {
                category: ArtifactCategory::EventLog,
                path: "%SYSTEMROOT%\\System32\\winevt\\Logs".to_string(),
                description: "Windows Event Logs".to_string(),
                is_directory: true,
                recursive: false,
                file_pattern: Some("*.evtx".to_string()),
                forensic_value: "Security events, logons, process execution".to_string(),
            },
            // Prefetch
            ArtifactPath {
                category: ArtifactCategory::Prefetch,
                path: "%SYSTEMROOT%\\Prefetch".to_string(),
                description: "Prefetch files".to_string(),
                is_directory: true,
                recursive: false,
                file_pattern: Some("*.pf".to_string()),
                forensic_value: "Program execution history, run counts".to_string(),
            },
            // Amcache
            ArtifactPath {
                category: ArtifactCategory::Amcache,
                path: "%SYSTEMROOT%\\AppCompat\\Programs\\Amcache.hve".to_string(),
                description: "Amcache hive".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Application execution, file metadata, SHA1 hashes".to_string(),
            },
            // SRUM
            ArtifactPath {
                category: ArtifactCategory::Srum,
                path: "%SYSTEMROOT%\\System32\\sru\\SRUDB.dat".to_string(),
                description: "System Resource Usage Monitor".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Application usage, network data, energy usage".to_string(),
            },
            // Recent Files
            ArtifactPath {
                category: ArtifactCategory::Lnk,
                path: "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent".to_string(),
                description: "Recent files shortcuts".to_string(),
                is_directory: true,
                recursive: true,
                file_pattern: Some("*.lnk".to_string()),
                forensic_value: "Recently accessed files, target paths".to_string(),
            },
            // Jump Lists
            ArtifactPath {
                category: ArtifactCategory::JumpList,
                path: "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations".to_string(),
                description: "Automatic Jump Lists".to_string(),
                is_directory: true,
                recursive: false,
                file_pattern: Some("*.automaticDestinations-ms".to_string()),
                forensic_value: "Application-specific recent files".to_string(),
            },
            // Browser - Chrome
            ArtifactPath {
                category: ArtifactCategory::BrowserHistory,
                path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History".to_string(),
                description: "Chrome browsing history".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "URLs visited, download history".to_string(),
            },
            // Scheduled Tasks
            ArtifactPath {
                category: ArtifactCategory::Task,
                path: "%SYSTEMROOT%\\System32\\Tasks".to_string(),
                description: "Scheduled Tasks".to_string(),
                is_directory: true,
                recursive: true,
                file_pattern: None,
                forensic_value: "Persistence mechanisms, automated execution".to_string(),
            },
            // USB History
            ArtifactPath {
                category: ArtifactCategory::Usb,
                path: "%SYSTEMROOT%\\inf\\setupapi.dev.log".to_string(),
                description: "USB device installation log".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "USB device connection history".to_string(),
            },
        ],
    }
}

/// Get Linux artifact collection template
pub fn get_linux_collection_template() -> CollectionTemplate {
    CollectionTemplate {
        operating_system: OperatingSystem::Linux,
        name: "Linux Full Collection".to_string(),
        description: "Comprehensive Linux forensic artifact collection".to_string(),
        artifacts: vec![
            // Auth logs
            ArtifactPath {
                category: ArtifactCategory::AuthLog,
                path: "/var/log/auth.log".to_string(),
                description: "Authentication log (Debian/Ubuntu)".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Login attempts, sudo usage, SSH connections".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::AuthLog,
                path: "/var/log/secure".to_string(),
                description: "Secure log (RHEL/CentOS)".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Login attempts, sudo usage, SSH connections".to_string(),
            },
            // Syslog
            ArtifactPath {
                category: ArtifactCategory::SysLog,
                path: "/var/log/syslog".to_string(),
                description: "System log (Debian/Ubuntu)".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "System events, kernel messages".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::SysLog,
                path: "/var/log/messages".to_string(),
                description: "System messages (RHEL/CentOS)".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "System events, kernel messages".to_string(),
            },
            // Bash history
            ArtifactPath {
                category: ArtifactCategory::BashHistory,
                path: "/home/*/.bash_history".to_string(),
                description: "User bash history".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: Some(".bash_history".to_string()),
                forensic_value: "Command line history".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::BashHistory,
                path: "/root/.bash_history".to_string(),
                description: "Root bash history".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Root command line history".to_string(),
            },
            // Cron
            ArtifactPath {
                category: ArtifactCategory::Cron,
                path: "/etc/crontab".to_string(),
                description: "System crontab".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Scheduled tasks, persistence".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Cron,
                path: "/var/spool/cron".to_string(),
                description: "User crontabs".to_string(),
                is_directory: true,
                recursive: true,
                file_pattern: None,
                forensic_value: "User scheduled tasks".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Cron,
                path: "/etc/cron.d".to_string(),
                description: "Cron.d directory".to_string(),
                is_directory: true,
                recursive: false,
                file_pattern: None,
                forensic_value: "System cron jobs".to_string(),
            },
            // User accounts
            ArtifactPath {
                category: ArtifactCategory::Passwd,
                path: "/etc/passwd".to_string(),
                description: "User accounts".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "User account information".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Shadow,
                path: "/etc/shadow".to_string(),
                description: "Password hashes".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Password hashes, account expiration".to_string(),
            },
            // Login records
            ArtifactPath {
                category: ArtifactCategory::Wtmp,
                path: "/var/log/wtmp".to_string(),
                description: "Login records".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "User login/logout history".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Lastlog,
                path: "/var/log/lastlog".to_string(),
                description: "Last login records".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Last login times per user".to_string(),
            },
            // Package management
            ArtifactPath {
                category: ArtifactCategory::Apt,
                path: "/var/log/apt/history.log".to_string(),
                description: "APT history".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Package installation history".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::Dpkg,
                path: "/var/log/dpkg.log".to_string(),
                description: "DPKG log".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Package manager activity".to_string(),
            },
            // Systemd
            ArtifactPath {
                category: ArtifactCategory::SystemD,
                path: "/etc/systemd/system".to_string(),
                description: "Systemd unit files".to_string(),
                is_directory: true,
                recursive: true,
                file_pattern: Some("*.service".to_string()),
                forensic_value: "Service configurations, persistence".to_string(),
            },
            // SSH
            ArtifactPath {
                category: ArtifactCategory::Network,
                path: "/home/*/.ssh".to_string(),
                description: "User SSH directories".to_string(),
                is_directory: true,
                recursive: false,
                file_pattern: None,
                forensic_value: "SSH keys, known hosts, authorized keys".to_string(),
            },
            // Browser - Firefox
            ArtifactPath {
                category: ArtifactCategory::BrowserHistory,
                path: "/home/*/.mozilla/firefox/*/places.sqlite".to_string(),
                description: "Firefox browsing history".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "URLs visited, bookmarks".to_string(),
            },
        ],
    }
}

/// Get web browser artifact collection template
pub fn get_browser_collection_template() -> CollectionTemplate {
    CollectionTemplate {
        operating_system: OperatingSystem::Other,
        name: "Browser Artifact Collection".to_string(),
        description: "Web browser forensic artifact collection".to_string(),
        artifacts: vec![
            // Chrome (Windows)
            ArtifactPath {
                category: ArtifactCategory::BrowserHistory,
                path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History".to_string(),
                description: "Chrome History".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Browsing history, downloads".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::BrowserCookies,
                path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies".to_string(),
                description: "Chrome Cookies".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Session cookies, tracking".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::BrowserCache,
                path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache".to_string(),
                description: "Chrome Cache".to_string(),
                is_directory: true,
                recursive: true,
                file_pattern: None,
                forensic_value: "Cached web content".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::BrowserPasswords,
                path: "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data".to_string(),
                description: "Chrome Login Data".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Saved passwords (encrypted)".to_string(),
            },
            // Firefox (Windows)
            ArtifactPath {
                category: ArtifactCategory::BrowserHistory,
                path: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite".to_string(),
                description: "Firefox Places".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Browsing history, bookmarks".to_string(),
            },
            ArtifactPath {
                category: ArtifactCategory::BrowserCookies,
                path: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite".to_string(),
                description: "Firefox Cookies".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Session cookies".to_string(),
            },
            // Edge (Windows)
            ArtifactPath {
                category: ArtifactCategory::BrowserHistory,
                path: "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History".to_string(),
                description: "Edge History".to_string(),
                is_directory: false,
                recursive: false,
                file_pattern: None,
                forensic_value: "Browsing history".to_string(),
            },
        ],
    }
}

// =============================================================================
// Artifact Storage
// =============================================================================

/// Artifact with computed hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedArtifact {
    pub artifact: ForensicArtifact,
    pub md5_hash: String,
    pub sha1_hash: String,
    pub sha256_hash: String,
    pub file_size: i64,
}

/// Hash computation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResult {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Compute hashes for data (simulated - real implementation would use crypto crate)
pub fn compute_hashes(data: &[u8]) -> HashResult {
    // In a real implementation, use:
    // - md5 crate for MD5
    // - sha1 crate for SHA1
    // - sha2 crate for SHA256

    // For now, return placeholder hashes
    HashResult {
        md5: format!("{:032x}", data.len()),
        sha1: format!("{:040x}", data.len()),
        sha256: format!("{:064x}", data.len()),
    }
}

// =============================================================================
// Artifact Analysis
// =============================================================================

/// Artifact analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactAnalysisResult {
    pub artifact_id: String,
    pub category: ArtifactCategory,
    pub findings: Vec<ArtifactFinding>,
    pub timeline_entries: Vec<ArtifactTimelineEntry>,
    pub iocs: Vec<String>,
    pub analysis_notes: Vec<String>,
}

/// Individual finding from artifact analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactFinding {
    pub finding_type: String,
    pub description: String,
    pub severity: String,
    pub evidence: String,
    pub timestamp: Option<DateTime<Utc>>,
}

/// Timeline entry extracted from artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactTimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub source: String,
    pub description: String,
    pub details: HashMap<String, String>,
}

/// Artifact collector with analysis capabilities
pub struct ArtifactCollector {
    windows_template: CollectionTemplate,
    linux_template: CollectionTemplate,
    browser_template: CollectionTemplate,
}

impl Default for ArtifactCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactCollector {
    pub fn new() -> Self {
        Self {
            windows_template: get_windows_collection_template(),
            linux_template: get_linux_collection_template(),
            browser_template: get_browser_collection_template(),
        }
    }

    /// Get collection template for operating system
    pub fn get_template(&self, os: &OperatingSystem) -> &CollectionTemplate {
        match os {
            OperatingSystem::Windows => &self.windows_template,
            OperatingSystem::Linux => &self.linux_template,
            _ => &self.browser_template,
        }
    }

    /// Get artifact paths for specific categories
    pub fn get_paths_for_categories(
        &self,
        os: &OperatingSystem,
        categories: &[ArtifactCategory],
    ) -> Vec<&ArtifactPath> {
        let template = self.get_template(os);
        template
            .artifacts
            .iter()
            .filter(|a| categories.is_empty() || categories.contains(&a.category))
            .collect()
    }

    /// Get all Windows artifacts
    pub fn get_windows_artifacts(&self) -> &[ArtifactPath] {
        &self.windows_template.artifacts
    }

    /// Get all Linux artifacts
    pub fn get_linux_artifacts(&self) -> &[ArtifactPath] {
        &self.linux_template.artifacts
    }

    /// Get all browser artifacts
    pub fn get_browser_artifacts(&self) -> &[ArtifactPath] {
        &self.browser_template.artifacts
    }

    /// Get artifacts by category
    pub fn get_artifacts_by_category(&self, category: &ArtifactCategory) -> Vec<&ArtifactPath> {
        let mut results = Vec::new();

        for artifact in &self.windows_template.artifacts {
            if artifact.category == *category {
                results.push(artifact);
            }
        }

        for artifact in &self.linux_template.artifacts {
            if artifact.category == *category {
                results.push(artifact);
            }
        }

        for artifact in &self.browser_template.artifacts {
            if artifact.category == *category {
                results.push(artifact);
            }
        }

        results
    }

    /// Describe artifact forensic value
    pub fn describe_artifact(&self, category: &ArtifactCategory) -> String {
        match category {
            ArtifactCategory::Registry => {
                "Windows Registry hives contain system configuration, installed software, \
                user accounts, autorun entries, network settings, and more. Key hives include \
                SAM (user accounts), SYSTEM (hardware, services), SOFTWARE (installed apps), \
                and NTUSER.DAT (user preferences).".to_string()
            }
            ArtifactCategory::EventLog => {
                "Windows Event Logs record system events including security events (logons, \
                privilege use), application errors, and system events. Key logs: Security.evtx, \
                System.evtx, Application.evtx, Microsoft-Windows-PowerShell/Operational.evtx".to_string()
            }
            ArtifactCategory::Prefetch => {
                "Windows Prefetch files (.pf) record program execution metadata including \
                run count, last run time, and file references. Created when applications run \
                (requires SSD or spinning disk configuration).".to_string()
            }
            ArtifactCategory::AuthLog => {
                "Linux authentication logs record login attempts, sudo commands, SSH sessions, \
                and PAM authentication events. Located at /var/log/auth.log (Debian) or \
                /var/log/secure (RHEL).".to_string()
            }
            ArtifactCategory::BashHistory => {
                "Bash command history files (.bash_history) record commands executed by users. \
                Located in user home directories. May contain credentials, malicious commands, \
                or evidence of lateral movement.".to_string()
            }
            ArtifactCategory::BrowserHistory => {
                "Browser history databases contain visited URLs, page titles, visit times, \
                and transition types. Chrome/Edge use SQLite History files, Firefox uses \
                places.sqlite.".to_string()
            }
            _ => format!("Forensic artifact category: {:?}", category),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_category_parsing() {
        assert_eq!(ArtifactCategory::from_str("registry"), ArtifactCategory::Registry);
        assert_eq!(ArtifactCategory::from_str("bash_history"), ArtifactCategory::BashHistory);
        assert_eq!(ArtifactCategory::from_str("unknown"), ArtifactCategory::Other);
    }

    #[test]
    fn test_operating_system_parsing() {
        assert_eq!(OperatingSystem::from_str("windows"), OperatingSystem::Windows);
        assert_eq!(OperatingSystem::from_str("linux"), OperatingSystem::Linux);
    }

    #[test]
    fn test_artifact_collector() {
        let collector = ArtifactCollector::new();

        let windows = collector.get_windows_artifacts();
        assert!(!windows.is_empty());

        let linux = collector.get_linux_artifacts();
        assert!(!linux.is_empty());
    }

    #[test]
    fn test_category_os_mapping() {
        assert_eq!(
            ArtifactCategory::Registry.operating_system(),
            Some(OperatingSystem::Windows)
        );
        assert_eq!(
            ArtifactCategory::AuthLog.operating_system(),
            Some(OperatingSystem::Linux)
        );
        assert_eq!(
            ArtifactCategory::BrowserHistory.operating_system(),
            None
        );
    }

    #[test]
    fn test_collection_templates() {
        let windows = get_windows_collection_template();
        assert_eq!(windows.operating_system, OperatingSystem::Windows);
        assert!(!windows.artifacts.is_empty());

        let linux = get_linux_collection_template();
        assert_eq!(linux.operating_system, OperatingSystem::Linux);
        assert!(!linux.artifacts.is_empty());
    }
}
