//! Threat intelligence sharing platforms

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for threat intel sharing platforms
#[derive(Debug, Clone, Default)]
pub struct SharingConfig {
    pub misp: Option<MispSharingConfig>,
    pub taxii: Option<TaxiiSharingConfig>,
}

#[derive(Debug, Clone)]
pub struct MispSharingConfig {
    pub base_url: String,
    pub api_key: String,
    pub verify_ssl: bool,
    pub default_distribution: u8,
    pub default_threat_level: u8,
}

#[derive(Debug, Clone)]
pub struct TaxiiSharingConfig {
    pub api_root: String,
    pub collection_id: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub struct ThreatIntelSharing {
    client: Client,
    config: SharingConfig,
}

#[derive(Debug, Serialize)]
struct MispEventCreate {
    #[serde(rename = "Event")]
    event: MispEventData,
}

#[derive(Debug, Serialize)]
struct MispEventData {
    info: String,
    distribution: String,
    threat_level_id: String,
    analysis: String,
    #[serde(rename = "Attribute")]
    attributes: Vec<MispAttributeData>,
}

#[derive(Debug, Serialize)]
struct MispAttributeData {
    #[serde(rename = "type")]
    attr_type: String,
    category: String,
    value: String,
    to_ids: bool,
    comment: String,
}

#[derive(Debug, Deserialize)]
struct MispEventResponse {
    #[serde(rename = "Event")]
    event: Option<MispEventResult>,
    errors: Option<Vec<String>>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MispEventResult {
    id: String,
    uuid: String,
}

#[derive(Debug, Serialize)]
struct StixBundle {
    #[serde(rename = "type")]
    bundle_type: String,
    id: String,
    objects: Vec<serde_json::Value>,
}

impl ThreatIntelSharing {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            config: SharingConfig::default(),
        }
    }

    pub fn with_config(config: SharingConfig) -> Self {
        let client = if let Some(misp) = &config.misp {
            if !misp.verify_ssl {
                Client::builder()
                    .timeout(Duration::from_secs(30))
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap_or_default()
            } else {
                Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap_or_default()
            }
        } else {
            Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default()
        };

        Self { client, config }
    }

    /// Configure MISP sharing
    pub fn with_misp(mut self, config: MispSharingConfig) -> Self {
        self.config.misp = Some(config);
        self
    }

    /// Configure TAXII sharing
    pub fn with_taxii(mut self, config: TaxiiSharingConfig) -> Self {
        self.config.taxii = Some(config);
        self
    }

    pub async fn share_indicator(&self, ioc: &str, context: &str) -> Result<()> {
        let mut results = Vec::new();

        // Share to MISP if configured
        if self.config.misp.is_some() {
            results.push(("MISP", self.share_to_misp(ioc, context).await));
        }

        // Share to TAXII if configured
        if self.config.taxii.is_some() {
            results.push(("TAXII", self.share_to_taxii(ioc, context).await));
        }

        // Check results
        let successes: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
        let failures: Vec<_> = results
            .iter()
            .filter_map(|(name, r)| r.as_ref().err().map(|e| format!("{}: {}", name, e)))
            .collect();

        if successes.is_empty() {
            if results.is_empty() {
                Err(anyhow!("No sharing platforms configured"))
            } else {
                Err(anyhow!("All sharing platforms failed: {}", failures.join("; ")))
            }
        } else {
            if !failures.is_empty() {
                log::warn!("Some platforms failed: {}", failures.join("; "));
            }
            log::info!("Successfully shared indicator {} to {} platform(s)", ioc, successes.len());
            Ok(())
        }
    }

    /// Share indicator to MISP
    async fn share_to_misp(&self, ioc: &str, context: &str) -> Result<()> {
        let misp_config = self.config.misp.as_ref()
            .ok_or_else(|| anyhow!("MISP not configured"))?;

        let ioc_type = detect_ioc_type(ioc);
        let (attr_type, category) = misp_type_mapping(&ioc_type);

        let event = MispEventCreate {
            event: MispEventData {
                info: format!("HeroForge IOC: {}", context),
                distribution: misp_config.default_distribution.to_string(),
                threat_level_id: misp_config.default_threat_level.to_string(),
                analysis: "1".to_string(), // Ongoing analysis
                attributes: vec![MispAttributeData {
                    attr_type: attr_type.to_string(),
                    category: category.to_string(),
                    value: ioc.to_string(),
                    to_ids: true,
                    comment: context.to_string(),
                }],
            },
        };

        let url = format!("{}/events/add", misp_config.base_url.trim_end_matches('/'));

        let response = self
            .client
            .post(&url)
            .header("Authorization", &misp_config.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&event)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            let result: MispEventResponse = response.json().await?;
            if let Some(event) = result.event {
                log::info!("MISP event created: {} (UUID: {})", event.id, event.uuid);
                Ok(())
            } else if let Some(errors) = result.errors {
                Err(anyhow!("MISP error: {}", errors.join(", ")))
            } else {
                Err(anyhow!("MISP error: {}", result.message.unwrap_or_else(|| "Unknown error".to_string())))
            }
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("MISP API error ({}): {}", status, error_text))
        }
    }

    /// Share indicator to TAXII server
    async fn share_to_taxii(&self, ioc: &str, context: &str) -> Result<()> {
        let taxii_config = self.config.taxii.as_ref()
            .ok_or_else(|| anyhow!("TAXII not configured"))?;

        let ioc_type = detect_ioc_type(ioc);

        // Create STIX 2.1 indicator object
        let indicator_id = format!("indicator--{}", uuid::Uuid::new_v4());
        let pattern = create_stix_pattern(ioc, &ioc_type);

        let indicator = serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": chrono::Utc::now().to_rfc3339(),
            "modified": chrono::Utc::now().to_rfc3339(),
            "name": format!("HeroForge IOC: {}", &ioc[..ioc.len().min(50)]),
            "description": context,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": chrono::Utc::now().to_rfc3339(),
            "indicator_types": [detect_indicator_type(&ioc_type)],
            "labels": ["heroforge", "automated"]
        });

        let bundle = StixBundle {
            bundle_type: "bundle".to_string(),
            id: format!("bundle--{}", uuid::Uuid::new_v4()),
            objects: vec![indicator],
        };

        let url = format!(
            "{}/collections/{}/objects/",
            taxii_config.api_root.trim_end_matches('/'),
            taxii_config.collection_id
        );

        let mut request = self
            .client
            .post(&url)
            .header("Accept", "application/taxii+json;version=2.1")
            .header("Content-Type", "application/taxii+json;version=2.1")
            .json(&bundle);

        if let (Some(user), Some(pass)) = (&taxii_config.username, &taxii_config.password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request.send().await?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 202 {
            log::info!("TAXII indicator shared: {}", indicator_id);
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("TAXII API error ({}): {}", status, error_text))
        }
    }

    /// Share multiple indicators at once
    pub async fn share_indicators(&self, indicators: &[(String, String)]) -> Result<ShareResult> {
        let mut result = ShareResult {
            total: indicators.len(),
            successful: 0,
            failed: 0,
            errors: vec![],
        };

        for (ioc, context) in indicators {
            match self.share_indicator(ioc, context).await {
                Ok(_) => result.successful += 1,
                Err(e) => {
                    result.failed += 1;
                    result.errors.push(format!("{}: {}", ioc, e));
                }
            }
        }

        Ok(result)
    }

    /// Add an attribute to an existing MISP event
    pub async fn add_to_misp_event(&self, event_id: &str, ioc: &str, context: &str) -> Result<()> {
        let misp_config = self.config.misp.as_ref()
            .ok_or_else(|| anyhow!("MISP not configured"))?;

        let ioc_type = detect_ioc_type(ioc);
        let (attr_type, category) = misp_type_mapping(&ioc_type);

        let attribute = serde_json::json!({
            "type": attr_type,
            "category": category,
            "value": ioc,
            "to_ids": true,
            "comment": context
        });

        let url = format!(
            "{}/attributes/add/{}",
            misp_config.base_url.trim_end_matches('/'),
            event_id
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", &misp_config.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&attribute)
            .send()
            .await?;

        if response.status().is_success() {
            log::info!("Added attribute to MISP event {}", event_id);
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(anyhow!("MISP API error: {}", error_text))
        }
    }
}

impl Default for ThreatIntelSharing {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResult {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Detect IOC type from value
fn detect_ioc_type(ioc: &str) -> String {
    use std::net::IpAddr;

    if ioc.parse::<IpAddr>().is_ok() {
        return "ip".to_string();
    }

    let ioc_lower = ioc.to_lowercase();
    if (ioc_lower.len() == 32 || ioc_lower.len() == 40 || ioc_lower.len() == 64)
        && ioc_lower.chars().all(|c| c.is_ascii_hexdigit())
    {
        return "hash".to_string();
    }

    if ioc.starts_with("http://") || ioc.starts_with("https://") {
        return "url".to_string();
    }

    if ioc.contains('@') && ioc.contains('.') {
        return "email".to_string();
    }

    "domain".to_string()
}

/// Map IOC type to MISP attribute type and category
fn misp_type_mapping(ioc_type: &str) -> (&'static str, &'static str) {
    match ioc_type {
        "ip" => ("ip-dst", "Network activity"),
        "domain" => ("domain", "Network activity"),
        "url" => ("url", "Network activity"),
        "hash" => ("sha256", "Payload delivery"),
        "email" => ("email-src", "Payload delivery"),
        _ => ("text", "Other"),
    }
}

/// Create STIX 2.1 pattern from IOC
fn create_stix_pattern(ioc: &str, ioc_type: &str) -> String {
    match ioc_type {
        "ip" => format!("[ipv4-addr:value = '{}']", ioc),
        "domain" => format!("[domain-name:value = '{}']", ioc),
        "url" => format!("[url:value = '{}']", ioc.replace('\'', "\\'")),
        "hash" => {
            let len = ioc.len();
            let hash_type = match len {
                32 => "MD5",
                40 => "SHA-1",
                64 => "SHA-256",
                _ => "SHA-256",
            };
            format!("[file:hashes.'{}' = '{}']", hash_type, ioc)
        }
        "email" => format!("[email-addr:value = '{}']", ioc),
        _ => format!("[x-heroforge:value = '{}']", ioc),
    }
}

/// Detect STIX indicator type from IOC type
fn detect_indicator_type(ioc_type: &str) -> &'static str {
    match ioc_type {
        "ip" | "domain" | "url" => "malicious-activity",
        "hash" => "malicious-activity",
        "email" => "attribution",
        _ => "unknown",
    }
}
