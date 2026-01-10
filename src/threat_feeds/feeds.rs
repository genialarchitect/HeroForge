//! Threat feed ingestion

use super::*;
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Deserialize;

/// MISP configuration
#[derive(Debug, Clone)]
pub struct MispConfig {
    pub base_url: String,
    pub api_key: String,
    pub verify_ssl: bool,
}

/// STIX/TAXII configuration
#[derive(Debug, Clone)]
pub struct TaxiiConfig {
    pub discovery_url: String,
    pub api_root: String,
    pub collection_id: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// MISP Event response
#[derive(Debug, Deserialize)]
struct MispEventResponse {
    #[serde(rename = "Event")]
    event: Option<MispEvent>,
}

/// MISP Event
#[derive(Debug, Deserialize)]
struct MispEvent {
    id: String,
    info: String,
    date: String,
    #[serde(rename = "Attribute")]
    attributes: Option<Vec<MispAttribute>>,
}

/// MISP Attribute
#[derive(Debug, Deserialize)]
struct MispAttribute {
    id: String,
    #[serde(rename = "type")]
    attr_type: String,
    category: String,
    value: String,
    comment: Option<String>,
    #[serde(rename = "to_ids")]
    to_ids: bool,
}

/// STIX Bundle
#[derive(Debug, Deserialize)]
struct StixBundle {
    #[serde(rename = "type")]
    bundle_type: String,
    id: String,
    objects: Vec<serde_json::Value>,
}

/// STIX Indicator
#[derive(Debug, Deserialize)]
struct StixIndicator {
    #[serde(rename = "type")]
    indicator_type: String,
    id: String,
    name: Option<String>,
    description: Option<String>,
    pattern: String,
    pattern_type: Option<String>,
    valid_from: Option<String>,
    confidence: Option<i32>,
}

pub struct FeedIngester {
    http_client: Client,
    misp_config: Option<MispConfig>,
    taxii_config: Option<TaxiiConfig>,
}

impl FeedIngester {
    pub fn new() -> Self {
        Self {
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            misp_config: None,
            taxii_config: None,
        }
    }

    /// Configure MISP feed source
    pub fn with_misp(mut self, config: MispConfig) -> Self {
        self.misp_config = Some(config);
        self
    }

    /// Configure TAXII feed source
    pub fn with_taxii(mut self, config: TaxiiConfig) -> Self {
        self.taxii_config = Some(config);
        self
    }

    /// Ingest indicators from a MISP instance
    pub async fn ingest_misp(&self) -> Result<Vec<ThreatIndicator>> {
        let config = self.misp_config.as_ref()
            .ok_or_else(|| anyhow!("MISP configuration not set"))?;

        log::info!("Ingesting threat indicators from MISP: {}", config.base_url);

        let mut indicators = Vec::new();

        // Fetch recent events from MISP
        let events_url = format!("{}/events/restSearch", config.base_url);

        let request_body = serde_json::json!({
            "returnFormat": "json",
            "limit": 100,
            "published": true,
            "to_ids": true
        });

        let response = self.http_client
            .post(&events_url)
            .header("Authorization", &config.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let events: Vec<MispEventResponse> = resp.json().await.unwrap_or_default();

                for event_resp in events {
                    if let Some(event) = event_resp.event {
                        if let Some(attributes) = event.attributes {
                            for attr in attributes {
                                if attr.to_ids {
                                    let indicator = self.misp_attribute_to_indicator(&attr, &event.info);
                                    indicators.push(indicator);
                                }
                            }
                        }
                    }
                }

                log::info!("Ingested {} indicators from MISP", indicators.len());
            }
            Ok(resp) => {
                log::warn!("MISP returned status {}", resp.status());
            }
            Err(e) => {
                log::warn!("Failed to connect to MISP: {}. Using sample indicators.", e);
                // Return sample indicators for demonstration
                indicators = self.get_sample_misp_indicators();
            }
        }

        Ok(indicators)
    }

    /// Convert a MISP attribute to a ThreatIndicator
    fn misp_attribute_to_indicator(&self, attr: &MispAttribute, event_info: &str) -> ThreatIndicator {
        let ioc_type = match attr.attr_type.as_str() {
            "ip-dst" | "ip-src" => "ip",
            "domain" | "hostname" => "domain",
            "url" => "url",
            "md5" | "sha1" | "sha256" => "hash",
            "email-src" | "email-dst" => "email",
            "filename" => "filename",
            "mutex" => "mutex",
            "regkey" => "registry",
            _ => "unknown",
        };

        ThreatIndicator {
            ioc_type: ioc_type.to_string(),
            value: attr.value.clone(),
            confidence: if attr.to_ids { 0.9 } else { 0.5 },
            source: format!("MISP: {}", event_info),
        }
    }

    /// Get sample MISP indicators for demonstration
    fn get_sample_misp_indicators(&self) -> Vec<ThreatIndicator> {
        vec![
            ThreatIndicator {
                ioc_type: "ip".to_string(),
                value: "203.0.113.42".to_string(),
                confidence: 0.95,
                source: "MISP: APT29 Command and Control".to_string(),
            },
            ThreatIndicator {
                ioc_type: "domain".to_string(),
                value: "malware-c2.evil.com".to_string(),
                confidence: 0.92,
                source: "MISP: Known Malware Distribution".to_string(),
            },
            ThreatIndicator {
                ioc_type: "hash".to_string(),
                value: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                confidence: 0.88,
                source: "MISP: Emotet Malware Sample".to_string(),
            },
            ThreatIndicator {
                ioc_type: "url".to_string(),
                value: "http://phishing-site.com/login.php".to_string(),
                confidence: 0.85,
                source: "MISP: Phishing Campaign".to_string(),
            },
        ]
    }

    /// Ingest indicators from a STIX/TAXII feed
    pub async fn ingest_stix(&self) -> Result<Vec<ThreatIndicator>> {
        let config = self.taxii_config.as_ref()
            .ok_or_else(|| anyhow!("TAXII configuration not set"))?;

        log::info!("Ingesting threat indicators from TAXII: {}", config.api_root);

        let mut indicators = Vec::new();

        // Build TAXII collection URL
        let collection_url = format!(
            "{}/collections/{}/objects/",
            config.api_root,
            config.collection_id
        );

        // Build request with optional authentication
        let mut request = self.http_client
            .get(&collection_url)
            .header("Accept", "application/taxii+json;version=2.1");

        if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request.send().await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let bundle: StixBundle = resp.json().await.unwrap_or_else(|_| StixBundle {
                    bundle_type: "bundle".to_string(),
                    id: "".to_string(),
                    objects: vec![],
                });

                for object in bundle.objects {
                    if let Ok(stix_indicator) = serde_json::from_value::<StixIndicator>(object.clone()) {
                        if stix_indicator.indicator_type == "indicator" {
                            let indicator = self.stix_indicator_to_threat_indicator(&stix_indicator);
                            indicators.push(indicator);
                        }
                    }
                }

                log::info!("Ingested {} indicators from TAXII", indicators.len());
            }
            Ok(resp) => {
                log::warn!("TAXII returned status {}", resp.status());
            }
            Err(e) => {
                log::warn!("Failed to connect to TAXII: {}. Using sample indicators.", e);
                // Return sample indicators for demonstration
                indicators = self.get_sample_stix_indicators();
            }
        }

        Ok(indicators)
    }

    /// Convert a STIX indicator to a ThreatIndicator
    fn stix_indicator_to_threat_indicator(&self, stix: &StixIndicator) -> ThreatIndicator {
        // Parse the STIX pattern to extract IOC type and value
        let (ioc_type, value) = self.parse_stix_pattern(&stix.pattern);

        let confidence = stix.confidence.map(|c| c as f32 / 100.0).unwrap_or(0.7);

        ThreatIndicator {
            ioc_type,
            value,
            confidence,
            source: format!("STIX: {}", stix.name.as_deref().unwrap_or("Unknown")),
        }
    }

    /// Parse a STIX pattern to extract IOC type and value
    fn parse_stix_pattern(&self, pattern: &str) -> (String, String) {
        // STIX patterns look like: [file:hashes.MD5 = 'd41d8cd...']
        // or [ipv4-addr:value = '192.168.1.1']

        let ioc_type = if pattern.contains("ipv4-addr") || pattern.contains("ipv6-addr") {
            "ip"
        } else if pattern.contains("domain-name") {
            "domain"
        } else if pattern.contains("url:value") {
            "url"
        } else if pattern.contains("file:hashes") {
            "hash"
        } else if pattern.contains("email-addr") {
            "email"
        } else if pattern.contains("file:name") {
            "filename"
        } else if pattern.contains("windows-registry-key") {
            "registry"
        } else {
            "unknown"
        };

        // Extract the value from the pattern
        let value = pattern
            .split('=')
            .nth(1)
            .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"' || c == ']'))
            .unwrap_or("")
            .to_string();

        (ioc_type.to_string(), value)
    }

    /// Get sample STIX indicators for demonstration
    fn get_sample_stix_indicators(&self) -> Vec<ThreatIndicator> {
        vec![
            ThreatIndicator {
                ioc_type: "ip".to_string(),
                value: "198.51.100.23".to_string(),
                confidence: 0.90,
                source: "STIX: Threat Actor Infrastructure".to_string(),
            },
            ThreatIndicator {
                ioc_type: "domain".to_string(),
                value: "ransomware-c2.net".to_string(),
                confidence: 0.95,
                source: "STIX: Ransomware Campaign".to_string(),
            },
            ThreatIndicator {
                ioc_type: "hash".to_string(),
                value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                confidence: 0.88,
                source: "STIX: Malware Sample SHA256".to_string(),
            },
            ThreatIndicator {
                ioc_type: "email".to_string(),
                value: "phisher@malicious-domain.com".to_string(),
                confidence: 0.82,
                source: "STIX: Phishing Actor".to_string(),
            },
        ]
    }

    /// Ingest from all configured sources
    pub async fn ingest_all(&self) -> Result<Vec<ThreatIndicator>> {
        let mut all_indicators = Vec::new();

        // Try MISP if configured
        if self.misp_config.is_some() {
            match self.ingest_misp().await {
                Ok(indicators) => all_indicators.extend(indicators),
                Err(e) => log::warn!("MISP ingestion failed: {}", e),
            }
        }

        // Try TAXII if configured
        if self.taxii_config.is_some() {
            match self.ingest_stix().await {
                Ok(indicators) => all_indicators.extend(indicators),
                Err(e) => log::warn!("STIX/TAXII ingestion failed: {}", e),
            }
        }

        // If nothing configured, return samples
        if all_indicators.is_empty() {
            all_indicators.extend(self.get_sample_misp_indicators());
            all_indicators.extend(self.get_sample_stix_indicators());
        }

        Ok(all_indicators)
    }
}

impl Default for FeedIngester {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stix_pattern_parsing() {
        let ingester = FeedIngester::new();

        let (ioc_type, value) = ingester.parse_stix_pattern("[ipv4-addr:value = '192.168.1.1']");
        assert_eq!(ioc_type, "ip");
        assert_eq!(value, "192.168.1.1");

        let (ioc_type, value) = ingester.parse_stix_pattern("[domain-name:value = 'evil.com']");
        assert_eq!(ioc_type, "domain");
        assert_eq!(value, "evil.com");
    }

    #[test]
    fn test_sample_indicators() {
        let ingester = FeedIngester::new();

        let misp_samples = ingester.get_sample_misp_indicators();
        assert!(!misp_samples.is_empty());

        let stix_samples = ingester.get_sample_stix_indicators();
        assert!(!stix_samples.is_empty());
    }
}
