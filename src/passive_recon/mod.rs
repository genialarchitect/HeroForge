//! Passive Reconnaissance Automation
//!
//! This module provides passive reconnaissance capabilities using external APIs
//! and services to gather intelligence without direct interaction with targets.
//!
//! Data Sources:
//! - Certificate Transparency (crt.sh)
//! - SecurityTrails API
//! - Wayback Machine (archive.org)
//! - GitHub Code Search
//! - VirusTotal (if API key provided)

pub mod crtsh;
pub mod wayback;
pub mod github_search;
pub mod securitytrails;
pub mod aggregator;

pub use crtsh::CrtshClient;
pub use wayback::WaybackClient;
pub use github_search::GitHubCodeSearch;
pub use securitytrails::SecurityTrailsClient;
pub use aggregator::{PassiveReconAggregator, PassiveReconResult, ReconSource};

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Common subdomain discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub additional_info: Option<serde_json::Value>,
}

/// Historical URL result from Wayback Machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalUrl {
    pub url: String,
    pub timestamp: DateTime<Utc>,
    pub mime_type: Option<String>,
    pub status_code: Option<u16>,
}

/// Code search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSearchResult {
    pub repository: String,
    pub file_path: String,
    pub match_line: String,
    pub line_number: Option<u32>,
    pub url: String,
}

/// DNS record from passive sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveDnsRecord {
    pub record_type: String,
    pub value: String,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub source: String,
}
