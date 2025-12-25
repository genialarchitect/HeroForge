//! Common types for scanner import functionality

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::Severity;

/// Import source type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ImportSource {
    Nessus,
    Qualys,
    Nexpose,
    OpenVAS,
}

impl std::fmt::Display for ImportSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportSource::Nessus => write!(f, "nessus"),
            ImportSource::Qualys => write!(f, "qualys"),
            ImportSource::Nexpose => write!(f, "nexpose"),
            ImportSource::OpenVAS => write!(f, "openvas"),
        }
    }
}

/// Imported vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedFinding {
    pub plugin_id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub cve_ids: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub host: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub solution: Option<String>,
    pub see_also: Vec<String>,
    pub plugin_output: Option<String>,
    pub first_discovered: Option<DateTime<Utc>>,
    pub last_observed: Option<DateTime<Utc>>,
    pub exploit_available: bool,
    pub exploitability_ease: Option<String>,
    pub patch_published: Option<DateTime<Utc>>,
}

impl Default for ImportedFinding {
    fn default() -> Self {
        ImportedFinding {
            plugin_id: None,
            title: String::new(),
            description: String::new(),
            severity: Severity::Low,
            cvss_score: None,
            cvss_vector: None,
            cve_ids: Vec::new(),
            cwe_ids: Vec::new(),
            host: String::new(),
            port: None,
            protocol: None,
            service: None,
            solution: None,
            see_also: Vec::new(),
            plugin_output: None,
            first_discovered: None,
            last_observed: None,
            exploit_available: false,
            exploitability_ease: None,
            patch_published: None,
        }
    }
}

/// Imported host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub mac_address: Option<String>,
    pub os: Option<String>,
    pub os_confidence: Option<u8>,
    pub netbios_name: Option<String>,
    pub findings: Vec<ImportedFinding>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl Default for ImportedHost {
    fn default() -> Self {
        ImportedHost {
            ip: String::new(),
            hostname: None,
            fqdn: None,
            mac_address: None,
            os: None,
            os_confidence: None,
            netbios_name: None,
            findings: Vec::new(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
        }
    }
}

/// Imported scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedScan {
    pub source: ImportSource,
    pub scanner_name: String,
    pub scanner_version: Option<String>,
    pub policy_name: Option<String>,
    pub scan_name: Option<String>,
    pub scan_start: Option<DateTime<Utc>>,
    pub scan_end: Option<DateTime<Utc>>,
    pub hosts: Vec<ImportedHost>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

impl Default for ImportedScan {
    fn default() -> Self {
        ImportedScan {
            source: ImportSource::Nessus,
            scanner_name: String::new(),
            scanner_version: None,
            policy_name: None,
            scan_name: None,
            scan_start: None,
            scan_end: None,
            hosts: Vec::new(),
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
        }
    }
}

/// Import result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub success: bool,
    pub source: ImportSource,
    pub hosts_imported: usize,
    pub findings_imported: usize,
    pub scan_id: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Import record for database tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    pub id: String,
    pub user_id: String,
    pub source: String,
    pub original_filename: String,
    pub scan_name: Option<String>,
    pub scan_date: Option<DateTime<Utc>>,
    pub host_count: i32,
    pub vulnerability_count: i32,
    pub imported_at: DateTime<Utc>,
    pub scan_id: Option<String>,
}
