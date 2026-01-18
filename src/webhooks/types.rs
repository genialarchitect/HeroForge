#![allow(dead_code)]
//! Webhook event types and payload structures
//!
//! This module defines the event types that can trigger webhooks and the
//! payload format for each event type.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Supported webhook event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    /// Scan has started
    #[serde(rename = "scan.started")]
    ScanStarted,
    /// Scan completed successfully
    #[serde(rename = "scan.completed")]
    ScanCompleted,
    /// Scan failed with an error
    #[serde(rename = "scan.failed")]
    ScanFailed,
    /// New vulnerability discovered
    #[serde(rename = "vulnerability.found")]
    VulnerabilityFound,
    /// Critical severity vulnerability found
    #[serde(rename = "vulnerability.critical")]
    VulnerabilityCritical,
    /// Vulnerability marked as resolved
    #[serde(rename = "vulnerability.resolved")]
    VulnerabilityResolved,
    /// New asset discovered
    #[serde(rename = "asset.discovered")]
    AssetDiscovered,
    /// Compliance check failed
    #[serde(rename = "compliance.violation")]
    ComplianceViolation,
    /// STIG update available
    #[serde(rename = "stig.update_available")]
    StigUpdateAvailable,
    /// STIG downloaded/updated
    #[serde(rename = "stig.updated")]
    StigUpdated,
    /// STIG sync completed
    #[serde(rename = "stig.sync_completed")]
    StigSyncCompleted,
    /// STIG sync failed
    #[serde(rename = "stig.sync_failed")]
    StigSyncFailed,
}

impl WebhookEventType {
    /// Get the string representation of the event type
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ScanStarted => "scan.started",
            Self::ScanCompleted => "scan.completed",
            Self::ScanFailed => "scan.failed",
            Self::VulnerabilityFound => "vulnerability.found",
            Self::VulnerabilityCritical => "vulnerability.critical",
            Self::VulnerabilityResolved => "vulnerability.resolved",
            Self::AssetDiscovered => "asset.discovered",
            Self::ComplianceViolation => "compliance.violation",
            Self::StigUpdateAvailable => "stig.update_available",
            Self::StigUpdated => "stig.updated",
            Self::StigSyncCompleted => "stig.sync_completed",
            Self::StigSyncFailed => "stig.sync_failed",
        }
    }

    /// Parse an event type from a string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "scan.started" => Some(Self::ScanStarted),
            "scan.completed" => Some(Self::ScanCompleted),
            "scan.failed" => Some(Self::ScanFailed),
            "vulnerability.found" => Some(Self::VulnerabilityFound),
            "vulnerability.critical" => Some(Self::VulnerabilityCritical),
            "vulnerability.resolved" => Some(Self::VulnerabilityResolved),
            "asset.discovered" => Some(Self::AssetDiscovered),
            "compliance.violation" => Some(Self::ComplianceViolation),
            "stig.update_available" => Some(Self::StigUpdateAvailable),
            "stig.updated" => Some(Self::StigUpdated),
            "stig.sync_completed" => Some(Self::StigSyncCompleted),
            "stig.sync_failed" => Some(Self::StigSyncFailed),
            _ => None,
        }
    }

    /// Get all available event types
    pub fn all() -> Vec<Self> {
        vec![
            Self::ScanStarted,
            Self::ScanCompleted,
            Self::ScanFailed,
            Self::VulnerabilityFound,
            Self::VulnerabilityCritical,
            Self::VulnerabilityResolved,
            Self::AssetDiscovered,
            Self::ComplianceViolation,
            Self::StigUpdateAvailable,
            Self::StigUpdated,
            Self::StigSyncCompleted,
            Self::StigSyncFailed,
        ]
    }
}

impl std::fmt::Display for WebhookEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The standard webhook payload format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// The event type
    pub event: String,
    /// ISO 8601 timestamp
    pub timestamp: DateTime<Utc>,
    /// Event-specific data
    pub data: serde_json::Value,
}

impl WebhookPayload {
    /// Create a new webhook payload
    pub fn new(event: WebhookEventType, data: serde_json::Value) -> Self {
        Self {
            event: event.to_string(),
            timestamp: Utc::now(),
            data,
        }
    }
}

/// Scan started event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStartedData {
    pub scan_id: String,
    pub name: String,
    pub targets: Vec<String>,
    pub started_at: DateTime<Utc>,
}

/// Scan completed event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCompletedData {
    pub scan_id: String,
    pub name: String,
    pub targets: Vec<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: DateTime<Utc>,
    pub hosts_discovered: usize,
    pub open_ports: usize,
    pub vulnerabilities_found: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

/// Scan failed event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFailedData {
    pub scan_id: String,
    pub name: String,
    pub error: String,
    pub failed_at: DateTime<Utc>,
}

/// Vulnerability found event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFoundData {
    pub scan_id: String,
    pub vulnerability_id: String,
    pub host_ip: String,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub severity: String,
    pub title: String,
    pub description: Option<String>,
    pub cve_ids: Vec<String>,
    pub cvss_score: Option<f32>,
}

/// Vulnerability resolved event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResolvedData {
    pub vulnerability_id: String,
    pub scan_id: String,
    pub host_ip: String,
    pub severity: String,
    pub title: String,
    pub resolved_by: Option<String>,
    pub resolved_at: DateTime<Utc>,
}

/// Asset discovered event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetDiscoveredData {
    pub asset_id: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub open_ports: Vec<u16>,
    pub discovered_at: DateTime<Utc>,
}

/// Compliance violation event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolationData {
    pub scan_id: String,
    pub framework: String,
    pub control_id: String,
    pub control_name: String,
    pub severity: String,
    pub description: String,
    pub affected_hosts: Vec<String>,
}

/// Test payload for webhook testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestWebhookData {
    pub message: String,
    pub webhook_id: String,
    pub webhook_name: String,
    pub timestamp: DateTime<Utc>,
}

/// STIG update available event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigUpdateAvailableData {
    /// The STIG identifier
    pub stig_id: String,
    /// STIG name
    pub stig_name: String,
    /// Current local version
    pub current_version: i32,
    /// Current local release
    pub current_release: i32,
    /// Available version
    pub available_version: i32,
    /// Available release
    pub available_release: i32,
    /// Release date of the new version
    pub release_date: Option<String>,
    /// Download URL
    pub download_url: Option<String>,
    /// When the update was detected
    pub detected_at: DateTime<Utc>,
}

/// STIG updated event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigUpdatedData {
    /// The STIG identifier
    pub stig_id: String,
    /// STIG name
    pub stig_name: String,
    /// Previous version
    pub old_version: Option<i32>,
    /// Previous release
    pub old_release: Option<i32>,
    /// New version
    pub new_version: i32,
    /// New release
    pub new_release: i32,
    /// Path to the downloaded file
    pub local_path: Option<String>,
    /// When the update was applied
    pub updated_at: DateTime<Utc>,
    /// Change summary (if diff available)
    pub change_summary: Option<StigChangeSummary>,
}

/// Summary of changes in a STIG update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigChangeSummary {
    pub rules_added: usize,
    pub rules_removed: usize,
    pub rules_modified: usize,
    pub severity_upgrades: usize,
    pub severity_downgrades: usize,
}

/// STIG sync completed event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigSyncCompletedData {
    /// Total STIGs checked
    pub total_checked: usize,
    /// Number with updates available
    pub updates_available: usize,
    /// Number automatically updated
    pub auto_updated: usize,
    /// STIGs with updates pending download
    pub pending_downloads: Vec<StigUpdateInfo>,
    /// When the sync completed
    pub completed_at: DateTime<Utc>,
    /// Duration of the sync in seconds
    pub duration_seconds: u64,
}

/// Brief info about a STIG update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigUpdateInfo {
    pub stig_id: String,
    pub stig_name: String,
    pub current_version: i32,
    pub current_release: i32,
    pub available_version: i32,
    pub available_release: i32,
}

/// STIG sync failed event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigSyncFailedData {
    /// Error message
    pub error: String,
    /// Which operation failed
    pub operation: String,
    /// STIG ID if specific to one STIG
    pub stig_id: Option<String>,
    /// When the failure occurred
    pub failed_at: DateTime<Utc>,
}
