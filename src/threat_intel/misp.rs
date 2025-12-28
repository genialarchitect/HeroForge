//! MISP (Malware Information Sharing Platform) Integration
//!
//! Integration with MISP threat intelligence platform:
//! - Event retrieval and correlation
//! - IOC import and export
//! - Attribute search
//! - Feed synchronization

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MISP client for API integration
pub struct MispClient {
    client: Client,
    base_url: String,
    api_key: String,
}

/// MISP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispConfig {
    pub base_url: String,
    pub api_key: String,
    pub verify_ssl: bool,
    pub org_id: Option<String>,
}

/// MISP event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEvent {
    pub id: String,
    pub uuid: String,
    pub info: String,
    pub threat_level_id: String,
    pub analysis: String,
    pub date: String,
    pub timestamp: String,
    pub published: bool,
    pub org_id: String,
    pub orgc_id: String,
    pub distribution: String,
    #[serde(default)]
    pub attribute_count: u32,
    #[serde(default)]
    pub attributes: Vec<MispAttribute>,
    #[serde(default)]
    pub tags: Vec<MispTag>,
    #[serde(default)]
    pub galaxies: Vec<MispGalaxy>,
    #[serde(default)]
    pub objects: Vec<MispObject>,
}

/// MISP attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispAttribute {
    pub id: String,
    pub uuid: String,
    pub event_id: String,
    #[serde(rename = "type")]
    pub attr_type: String,
    pub category: String,
    pub value: String,
    pub comment: Option<String>,
    pub to_ids: bool,
    pub timestamp: String,
    #[serde(default)]
    pub tags: Vec<MispTag>,
    pub distribution: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

/// MISP tag
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispTag {
    pub id: String,
    pub name: String,
    pub colour: Option<String>,
    pub exportable: bool,
}

/// MISP galaxy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxy {
    pub id: String,
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub galaxy_type: String,
    #[serde(default)]
    pub galaxy_cluster: Vec<MispGalaxyCluster>,
}

/// MISP galaxy cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispGalaxyCluster {
    pub id: String,
    pub uuid: String,
    pub collection_uuid: Option<String>,
    #[serde(rename = "type")]
    pub cluster_type: String,
    pub value: String,
    pub tag_name: String,
    pub description: Option<String>,
    pub source: Option<String>,
    #[serde(default)]
    pub meta: HashMap<String, serde_json::Value>,
}

/// MISP object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispObject {
    pub id: String,
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub template_uuid: String,
    pub template_version: String,
    pub event_id: String,
    #[serde(default)]
    pub attributes: Vec<MispAttribute>,
    pub timestamp: String,
    pub distribution: String,
    pub comment: Option<String>,
}

/// MISP search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispSearchResult {
    pub response: Vec<MispEventWrapper>,
}

/// Wrapper for MISP event in API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispEventWrapper {
    #[serde(rename = "Event")]
    pub event: MispEvent,
}

/// MISP attribute type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MispAttributeType {
    Ip,
    #[serde(rename = "ip-src")]
    IpSrc,
    #[serde(rename = "ip-dst")]
    IpDst,
    Domain,
    Hostname,
    Url,
    #[serde(rename = "user-agent")]
    UserAgent,
    #[serde(rename = "http-method")]
    HttpMethod,
    Email,
    #[serde(rename = "email-src")]
    EmailSrc,
    #[serde(rename = "email-dst")]
    EmailDst,
    #[serde(rename = "email-subject")]
    EmailSubject,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Ssdeep,
    Imphash,
    Filename,
    #[serde(rename = "filename|md5")]
    FilenameMd5,
    #[serde(rename = "filename|sha256")]
    FilenameSha256,
    Regkey,
    #[serde(rename = "regkey|value")]
    RegkeyValue,
    Mutex,
    Vulnerability,
    CveId,
    Yara,
    Sigma,
    #[serde(rename = "mitre-attack-pattern")]
    MitreAttackPattern,
    Ja3Fingerprint,
    #[serde(rename = "ja3-fingerprint-md5")]
    Ja3FingerprintMd5,
    Comment,
    Text,
    Other,
}

impl MispClient {
    /// Create a new MISP client
    pub fn new(config: MispConfig) -> Result<Self, String> {
        let client = if config.verify_ssl {
            Client::new()
        } else {
            Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| e.to_string())?
        };

        Ok(Self {
            client,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            api_key: config.api_key,
        })
    }

    /// Get an event by ID
    pub async fn get_event(&self, event_id: &str) -> Result<MispEvent, String> {
        let url = format!("{}/events/view/{}", self.base_url, event_id);

        let response = self.client
            .get(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP API error: {}", response.status()));
        }

        let wrapper: MispEventWrapper = response.json().await.map_err(|e| e.to_string())?;
        Ok(wrapper.event)
    }

    /// Search events
    pub async fn search_events(&self, query: &MispSearchQuery) -> Result<Vec<MispEvent>, String> {
        let url = format!("{}/events/restSearch", self.base_url);

        let response = self.client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP API error: {}", response.status()));
        }

        let result: MispSearchResult = response.json().await.map_err(|e| e.to_string())?;
        Ok(result.response.into_iter().map(|w| w.event).collect())
    }

    /// Search attributes
    pub async fn search_attributes(&self, value: &str, attr_type: Option<&str>) -> Result<Vec<MispAttribute>, String> {
        let url = format!("{}/attributes/restSearch", self.base_url);

        let mut query = HashMap::new();
        query.insert("value", value);
        if let Some(t) = attr_type {
            query.insert("type", t);
        }

        let response = self.client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP API error: {}", response.status()));
        }

        #[derive(Deserialize)]
        struct AttrResponse {
            #[serde(rename = "Attribute")]
            attributes: Vec<MispAttribute>,
        }

        let result: AttrResponse = response.json().await.map_err(|e| e.to_string())?;
        Ok(result.attributes)
    }

    /// Create an event
    pub async fn create_event(&self, event: &CreateMispEvent) -> Result<MispEvent, String> {
        let url = format!("{}/events/add", self.base_url);

        let response = self.client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&event)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP API error: {}", response.status()));
        }

        let wrapper: MispEventWrapper = response.json().await.map_err(|e| e.to_string())?;
        Ok(wrapper.event)
    }

    /// Add attribute to event
    pub async fn add_attribute(&self, event_id: &str, attr: &CreateMispAttribute) -> Result<MispAttribute, String> {
        let url = format!("{}/attributes/add/{}", self.base_url, event_id);

        let response = self.client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&attr)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP API error: {}", response.status()));
        }

        #[derive(Deserialize)]
        struct AttrWrapper {
            #[serde(rename = "Attribute")]
            attribute: MispAttribute,
        }

        let wrapper: AttrWrapper = response.json().await.map_err(|e| e.to_string())?;
        Ok(wrapper.attribute)
    }

    /// Get MISP statistics
    pub async fn get_statistics(&self) -> Result<MispStatistics, String> {
        let url = format!("{}/users/statistics", self.base_url);

        let response = self.client
            .get(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP API error: {}", response.status()));
        }

        response.json().await.map_err(|e| e.to_string())
    }

    /// Get recent IOCs for a specific type
    pub async fn get_recent_iocs(&self, attr_type: &str, days: u32) -> Result<Vec<MispAttribute>, String> {
        let url = format!("{}/attributes/restSearch", self.base_url);

        let query = serde_json::json!({
            "type": attr_type,
            "last": format!("{}d", days),
            "to_ids": true
        });

        let response = self.client
            .post(&url)
            .header("Authorization", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP API error: {}", response.status()));
        }

        #[derive(Deserialize)]
        struct AttrResponse {
            #[serde(rename = "Attribute")]
            attributes: Vec<MispAttribute>,
        }

        let result: AttrResponse = response.json().await.map_err(|e| e.to_string())?;
        Ok(result.attributes)
    }

    /// Export IOCs in a specific format
    pub async fn export_iocs(&self, format: MispExportFormat) -> Result<String, String> {
        let path = match format {
            MispExportFormat::Csv => "attributes/csv/download/all",
            MispExportFormat::Stix1 => "events/stix/download",
            MispExportFormat::Stix2 => "events/stix2/collection.json",
            MispExportFormat::Snort => "events/nids/snort/download",
            MispExportFormat::Suricata => "events/nids/suricata/download",
            MispExportFormat::Yara => "events/yara/download",
            MispExportFormat::Sigma => "events/sigma/download",
            MispExportFormat::OpenIoc => "events/openioc/download",
        };

        let url = format!("{}/{}", self.base_url, path);

        let response = self.client
            .get(&url)
            .header("Authorization", &self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("MISP export error: {}", response.status()));
        }

        response.text().await.map_err(|e| e.to_string())
    }
}

/// MISP search query
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MispSearchQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub attr_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforceWarninglist: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ids: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
}

/// Create MISP event request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMispEvent {
    pub info: String,
    pub threat_level_id: String,
    pub analysis: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Create MISP attribute request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMispAttribute {
    #[serde(rename = "type")]
    pub attr_type: String,
    pub value: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_ids: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<String>,
}

/// MISP statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispStatistics {
    pub event_count: u64,
    pub attribute_count: u64,
    pub correlation_count: u64,
    pub proposal_count: u64,
    pub user_count: u64,
    pub org_count: u64,
    #[serde(default)]
    pub attribute_count_per_type: HashMap<String, u64>,
}

/// MISP export format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MispExportFormat {
    Csv,
    Stix1,
    Stix2,
    Snort,
    Suricata,
    Yara,
    Sigma,
    OpenIoc,
}

/// Convert MISP event to internal threat intel format
pub fn misp_event_to_threat_intel(event: &MispEvent) -> Vec<super::types::Ioc> {
    let mut iocs = Vec::new();

    for attr in &event.attributes {
        let ioc_type = match attr.attr_type.as_str() {
            "ip-src" | "ip-dst" | "ip" => super::types::IocType::Ip,
            "domain" | "hostname" => super::types::IocType::Domain,
            "url" => super::types::IocType::Url,
            "md5" => super::types::IocType::Md5,
            "sha1" => super::types::IocType::Sha1,
            "sha256" => super::types::IocType::Sha256,
            "email" | "email-src" | "email-dst" => super::types::IocType::Email,
            "filename" => super::types::IocType::Filename,
            "regkey" | "regkey|value" => super::types::IocType::Registry,
            _ => continue,
        };

        iocs.push(super::types::Ioc {
            id: attr.uuid.clone(),
            ioc_type,
            value: attr.value.clone(),
            source: format!("MISP Event {}", event.id),
            confidence: if attr.to_ids { 0.9 } else { 0.5 },
            severity: match event.threat_level_id.as_str() {
                "1" => super::types::ThreatSeverity::Critical,
                "2" => super::types::ThreatSeverity::High,
                "3" => super::types::ThreatSeverity::Medium,
                _ => super::types::ThreatSeverity::Low,
            },
            first_seen: attr.first_seen.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            last_seen: attr.last_seen.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc)),
            tags: attr.tags.iter().map(|t| t.name.clone()).collect(),
            context: Some(format!("Event: {} - {}", event.uuid, event.info)),
            created_at: Utc::now(),
        });
    }

    iocs
}
