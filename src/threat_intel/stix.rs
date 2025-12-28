//! STIX 2.1 Integration
//!
//! Implementation of STIX 2.1 (Structured Threat Information Expression):
//! - Object parsing and serialization
//! - Bundle handling
//! - TAXII client for server communication
//! - Conversion to/from internal formats

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// STIX Bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub bundle_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    pub objects: Vec<StixObject>,
}

impl Default for StixBundle {
    fn default() -> Self {
        Self {
            bundle_type: "bundle".to_string(),
            id: format!("bundle--{}", uuid::Uuid::new_v4()),
            spec_version: Some("2.1".to_string()),
            objects: Vec::new(),
        }
    }
}

/// STIX Domain Object (SDO)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StixObject {
    #[serde(rename = "attack-pattern")]
    AttackPattern(AttackPattern),
    #[serde(rename = "campaign")]
    Campaign(Campaign),
    #[serde(rename = "course-of-action")]
    CourseOfAction(CourseOfAction),
    #[serde(rename = "identity")]
    Identity(Identity),
    #[serde(rename = "indicator")]
    Indicator(Indicator),
    #[serde(rename = "intrusion-set")]
    IntrusionSet(IntrusionSet),
    #[serde(rename = "malware")]
    Malware(Malware),
    #[serde(rename = "threat-actor")]
    ThreatActor(ThreatActor),
    #[serde(rename = "tool")]
    Tool(Tool),
    #[serde(rename = "vulnerability")]
    Vulnerability(StixVulnerability),
    #[serde(rename = "relationship")]
    Relationship(Relationship),
    #[serde(rename = "sighting")]
    Sighting(Sighting),
    #[serde(rename = "observed-data")]
    ObservedData(ObservedData),
    #[serde(rename = "report")]
    Report(Report),
    #[serde(rename = "note")]
    Note(Note),
    #[serde(rename = "opinion")]
    Opinion(Opinion),
    #[serde(rename = "location")]
    Location(Location),
    #[serde(rename = "infrastructure")]
    Infrastructure(Infrastructure),
    #[serde(rename = "malware-analysis")]
    MalwareAnalysis(MalwareAnalysis),
}

/// Common STIX properties
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StixCommonProperties {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub external_references: Vec<ExternalReference>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub object_marking_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub granular_markings: Vec<GranularMarking>,
}

/// External reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    pub source_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// Granular marking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GranularMarking {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marking_ref: Option<String>,
    pub selectors: Vec<String>,
}

/// Kill chain phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub kill_chain_name: String,
    pub phase_name: String,
}

/// Attack Pattern SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
}

/// Campaign SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objective: Option<String>,
}

/// Course of Action SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourseOfAction {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_execution_envs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_reference: Option<ExternalReference>,
}

/// Identity SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_class: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sectors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_information: Option<String>,
}

/// Indicator SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub indicator_types: Vec<String>,
    pub pattern: String,
    pub pattern_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_version: Option<String>,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
}

/// Intrusion Set SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrusionSet {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub goals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_motivation: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub secondary_motivations: Vec<String>,
}

/// Malware SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Malware {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub malware_types: Vec<String>,
    pub is_family: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub operating_system_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub architecture_execution_envs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub implementation_languages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sample_refs: Vec<String>,
}

/// Threat Actor SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub threat_actor_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub goals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sophistication: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_motivation: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub secondary_motivations: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub personal_motivations: Vec<String>,
}

/// Tool SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tool_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
}

/// Vulnerability SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixVulnerability {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Relationship SRO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub relationship_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source_ref: String,
    pub target_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_time: Option<DateTime<Utc>>,
}

/// Sighting SRO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sighting {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    pub sighting_of_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub observed_data_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub where_sighted_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<bool>,
}

/// Observed Data SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedData {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub first_observed: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,
    pub number_observed: u32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub object_refs: Vec<String>,
}

/// Report SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub report_types: Vec<String>,
    pub published: DateTime<Utc>,
    pub object_refs: Vec<String>,
}

/// Note SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abstract_: Option<String>,
    pub content: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authors: Vec<String>,
    pub object_refs: Vec<String>,
}

/// Opinion SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opinion {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authors: Vec<String>,
    pub opinion: String, // strongly-disagree, disagree, neutral, agree, strongly-agree
    pub object_refs: Vec<String>,
}

/// Location SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precision: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub administrative_area: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
}

/// Infrastructure SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Infrastructure {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub infrastructure_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub kill_chain_phases: Vec<KillChainPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
}

/// Malware Analysis SDO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareAnalysis {
    #[serde(flatten)]
    pub common: StixCommonProperties,
    pub product: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_vm_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_software_refs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub modules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_definition_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitted: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_started: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_ended: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>, // malicious, suspicious, benign, unknown
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub analysis_sco_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_ref: Option<String>,
}

impl StixBundle {
    /// Create a new STIX bundle
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an object to the bundle
    pub fn add_object(&mut self, object: StixObject) {
        self.objects.push(object);
    }

    /// Parse a STIX bundle from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get all indicators from the bundle
    pub fn get_indicators(&self) -> Vec<&Indicator> {
        self.objects.iter()
            .filter_map(|obj| {
                if let StixObject::Indicator(ind) = obj {
                    Some(ind)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all threat actors from the bundle
    pub fn get_threat_actors(&self) -> Vec<&ThreatActor> {
        self.objects.iter()
            .filter_map(|obj| {
                if let StixObject::ThreatActor(ta) = obj {
                    Some(ta)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all malware from the bundle
    pub fn get_malware(&self) -> Vec<&Malware> {
        self.objects.iter()
            .filter_map(|obj| {
                if let StixObject::Malware(m) = obj {
                    Some(m)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get relationships for a specific object
    pub fn get_relationships_for(&self, object_id: &str) -> Vec<&Relationship> {
        self.objects.iter()
            .filter_map(|obj| {
                if let StixObject::Relationship(rel) = obj {
                    if rel.source_ref == object_id || rel.target_ref == object_id {
                        Some(rel)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Create a STIX Indicator from an IOC
pub fn ioc_to_stix_indicator(ioc: &super::types::Ioc) -> Indicator {
    let pattern = match ioc.ioc_type {
        super::types::IocType::Ip => format!("[ipv4-addr:value = '{}']", ioc.value),
        super::types::IocType::Domain => format!("[domain-name:value = '{}']", ioc.value),
        super::types::IocType::Url => format!("[url:value = '{}']", ioc.value),
        super::types::IocType::Md5 => format!("[file:hashes.MD5 = '{}']", ioc.value),
        super::types::IocType::Sha1 => format!("[file:hashes.'SHA-1' = '{}']", ioc.value),
        super::types::IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{}']", ioc.value),
        super::types::IocType::Email => format!("[email-addr:value = '{}']", ioc.value),
        super::types::IocType::Filename => format!("[file:name = '{}']", ioc.value),
        _ => format!("[x-heroforge-ioc:value = '{}']", ioc.value),
    };

    let now = Utc::now();

    Indicator {
        common: StixCommonProperties {
            id: format!("indicator--{}", uuid::Uuid::new_v4()),
            spec_version: Some("2.1".to_string()),
            created: now,
            modified: now,
            labels: ioc.tags.clone(),
            confidence: Some((ioc.confidence * 100.0) as u8),
            ..Default::default()
        },
        name: Some(format!("{:?}: {}", ioc.ioc_type, ioc.value)),
        description: ioc.context.clone(),
        indicator_types: vec!["malicious-activity".to_string()],
        pattern,
        pattern_type: "stix".to_string(),
        pattern_version: Some("2.1".to_string()),
        valid_from: ioc.first_seen.unwrap_or(now),
        valid_until: None,
        kill_chain_phases: Vec::new(),
    }
}

/// TAXII 2.1 Client for server communication
pub struct TaxiiClient {
    client: reqwest::Client,
    base_url: String,
    username: Option<String>,
    password: Option<String>,
}

impl TaxiiClient {
    /// Create a new TAXII client
    pub fn new(base_url: &str, username: Option<String>, password: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            username,
            password,
        }
    }

    /// Discover available API roots
    pub async fn discover(&self) -> Result<TaxiiDiscovery, String> {
        let url = format!("{}/taxii2/", self.base_url);
        let mut request = self.client.get(&url)
            .header("Accept", "application/taxii+json;version=2.1");

        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request.send().await.map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("TAXII error: {}", response.status()));
        }

        response.json().await.map_err(|e| e.to_string())
    }

    /// Get API root information
    pub async fn get_api_root(&self, api_root: &str) -> Result<TaxiiApiRoot, String> {
        let url = format!("{}/{}/", self.base_url, api_root);
        let mut request = self.client.get(&url)
            .header("Accept", "application/taxii+json;version=2.1");

        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request.send().await.map_err(|e| e.to_string())?;
        response.json().await.map_err(|e| e.to_string())
    }

    /// List collections
    pub async fn list_collections(&self, api_root: &str) -> Result<Vec<TaxiiCollection>, String> {
        let url = format!("{}/{}/collections/", self.base_url, api_root);
        let mut request = self.client.get(&url)
            .header("Accept", "application/taxii+json;version=2.1");

        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request.send().await.map_err(|e| e.to_string())?;

        #[derive(Deserialize)]
        struct CollectionsResponse {
            collections: Vec<TaxiiCollection>,
        }

        let result: CollectionsResponse = response.json().await.map_err(|e| e.to_string())?;
        Ok(result.collections)
    }

    /// Get objects from a collection
    pub async fn get_objects(&self, api_root: &str, collection_id: &str) -> Result<StixBundle, String> {
        let url = format!("{}/{}/collections/{}/objects/", self.base_url, api_root, collection_id);
        let mut request = self.client.get(&url)
            .header("Accept", "application/stix+json;version=2.1");

        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request.send().await.map_err(|e| e.to_string())?;
        response.json().await.map_err(|e| e.to_string())
    }
}

/// TAXII discovery response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiDiscovery {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub api_roots: Vec<String>,
}

/// TAXII API root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiApiRoot {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub versions: Vec<String>,
    pub max_content_length: u64,
}

/// TAXII collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiCollection {
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_types: Option<Vec<String>>,
}
