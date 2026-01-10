//! IOC enrichment and contextualization

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Configuration for IOC enrichment sources
#[derive(Debug, Clone, Default)]
pub struct EnricherConfig {
    pub virustotal_api_key: Option<String>,
    pub abuseipdb_api_key: Option<String>,
    pub otx_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
}

pub struct IocEnricher {
    client: Client,
    config: EnricherConfig,
}

#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    data: Option<VirusTotalData>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalData {
    attributes: Option<VirusTotalAttributes>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalAttributes {
    last_analysis_stats: Option<VirusTotalStats>,
    reputation: Option<i32>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalStats {
    malicious: Option<i32>,
    suspicious: Option<i32>,
    harmless: Option<i32>,
    undetected: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct AbuseIPDBResponse {
    data: Option<AbuseIPDBData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseIPDBData {
    abuse_confidence_score: Option<i32>,
    is_tor: Option<bool>,
    is_public: Option<bool>,
    total_reports: Option<i32>,
    last_reported_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OtxResponse {
    pulse_info: Option<OtxPulseInfo>,
    reputation: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct OtxPulseInfo {
    count: Option<i32>,
    pulses: Option<Vec<OtxPulse>>,
}

#[derive(Debug, Deserialize)]
struct OtxPulse {
    name: Option<String>,
    tags: Option<Vec<String>>,
    created: Option<String>,
}

impl IocEnricher {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            config: EnricherConfig::default(),
        }
    }

    pub fn with_config(config: EnricherConfig) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            config,
        }
    }

    pub async fn enrich(&self, ioc: &str) -> Result<EnrichedIoc> {
        let ioc_type = detect_ioc_type(ioc);

        let mut enriched = EnrichedIoc {
            ioc: ioc.to_string(),
            ioc_type: ioc_type.clone(),
            reputation_score: 0.0,
            first_seen: None,
            last_seen: None,
            threat_types: vec![],
            sources: vec![],
            related_indicators: vec![],
            geo_location: None,
            asn_info: None,
        };

        // Query multiple sources in parallel
        let (vt_result, abuse_result, otx_result) = tokio::join!(
            self.query_virustotal(ioc, &ioc_type),
            self.query_abuseipdb(ioc, &ioc_type),
            self.query_otx(ioc, &ioc_type),
        );

        let mut scores = Vec::new();
        let mut threat_types = Vec::new();

        // Process VirusTotal results
        if let Ok(Some(vt)) = vt_result {
            if let Some(stats) = vt.last_analysis_stats {
                let malicious = stats.malicious.unwrap_or(0);
                let suspicious = stats.suspicious.unwrap_or(0);
                let total = malicious + suspicious + stats.harmless.unwrap_or(0) + stats.undetected.unwrap_or(0);
                if total > 0 {
                    let vt_score = ((malicious + suspicious) as f32 / total as f32) * 100.0;
                    scores.push(vt_score);
                }
            }
            if let Some(tags) = vt.tags {
                threat_types.extend(tags);
            }
            enriched.sources.push(EnrichmentSource {
                name: "VirusTotal".to_string(),
                url: format!("https://www.virustotal.com/gui/search/{}", ioc),
                confidence: 0.9,
            });
        }

        // Process AbuseIPDB results
        if let Ok(Some(abuse)) = abuse_result {
            if let Some(score) = abuse.abuse_confidence_score {
                scores.push(score as f32);
            }
            if abuse.is_tor.unwrap_or(false) {
                threat_types.push("tor_exit_node".to_string());
            }
            if let Some(last_reported) = abuse.last_reported_at {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&last_reported) {
                    enriched.last_seen = Some(dt.with_timezone(&chrono::Utc));
                }
            }
            enriched.sources.push(EnrichmentSource {
                name: "AbuseIPDB".to_string(),
                url: format!("https://www.abuseipdb.com/check/{}", ioc),
                confidence: 0.85,
            });
        }

        // Process OTX results
        if let Ok(Some(otx)) = otx_result {
            if let Some(pulse_info) = otx.pulse_info {
                let pulse_count = pulse_info.count.unwrap_or(0);
                if pulse_count > 0 {
                    // Higher pulse count = higher threat score
                    let otx_score = (pulse_count as f32 * 10.0).min(100.0);
                    scores.push(otx_score);
                }
                if let Some(pulses) = pulse_info.pulses {
                    for pulse in pulses.iter().take(5) {
                        if let Some(tags) = &pulse.tags {
                            threat_types.extend(tags.iter().cloned());
                        }
                        if let Some(created) = &pulse.created {
                            if enriched.first_seen.is_none() {
                                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created) {
                                    enriched.first_seen = Some(dt.with_timezone(&chrono::Utc));
                                }
                            }
                        }
                    }
                }
            }
            enriched.sources.push(EnrichmentSource {
                name: "AlienVault OTX".to_string(),
                url: format!("https://otx.alienvault.com/indicator/ip/{}", ioc),
                confidence: 0.8,
            });
        }

        // Calculate weighted average reputation score
        if !scores.is_empty() {
            enriched.reputation_score = scores.iter().sum::<f32>() / scores.len() as f32;
        }

        // Deduplicate threat types
        threat_types.sort();
        threat_types.dedup();
        enriched.threat_types = threat_types;

        // If no data from external sources, return with minimal enrichment
        if enriched.sources.is_empty() {
            log::info!("No external enrichment data available for IOC: {}", ioc);
            // Still set the last_seen to now if this is a new sighting
            enriched.last_seen = Some(chrono::Utc::now());
        }

        Ok(enriched)
    }

    async fn query_virustotal(&self, ioc: &str, ioc_type: &str) -> Result<Option<VirusTotalAttributes>> {
        let api_key = match &self.config.virustotal_api_key {
            Some(key) if !key.is_empty() => key,
            _ => return Ok(None),
        };

        let endpoint = match ioc_type {
            "ip" => format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ioc),
            "domain" => format!("https://www.virustotal.com/api/v3/domains/{}", ioc),
            "hash" => format!("https://www.virustotal.com/api/v3/files/{}", ioc),
            "url" => {
                let url_id = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    ioc,
                );
                format!("https://www.virustotal.com/api/v3/urls/{}", url_id)
            }
            _ => return Ok(None),
        };

        let response = self
            .client
            .get(&endpoint)
            .header("x-apikey", api_key)
            .send()
            .await?;

        if response.status().is_success() {
            let vt_response: VirusTotalResponse = response.json().await?;
            Ok(vt_response.data.and_then(|d| d.attributes))
        } else {
            log::debug!("VirusTotal query failed with status: {}", response.status());
            Ok(None)
        }
    }

    async fn query_abuseipdb(&self, ioc: &str, ioc_type: &str) -> Result<Option<AbuseIPDBData>> {
        // AbuseIPDB only works with IP addresses
        if ioc_type != "ip" {
            return Ok(None);
        }

        let api_key = match &self.config.abuseipdb_api_key {
            Some(key) if !key.is_empty() => key,
            _ => return Ok(None),
        };

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ioc
        );

        let response = self
            .client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await?;

        if response.status().is_success() {
            let abuse_response: AbuseIPDBResponse = response.json().await?;
            Ok(abuse_response.data)
        } else {
            log::debug!("AbuseIPDB query failed with status: {}", response.status());
            Ok(None)
        }
    }

    async fn query_otx(&self, ioc: &str, ioc_type: &str) -> Result<Option<OtxResponse>> {
        let api_key = match &self.config.otx_api_key {
            Some(key) if !key.is_empty() => key,
            _ => return Ok(None),
        };

        let endpoint = match ioc_type {
            "ip" => format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general", ioc),
            "domain" => format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/general", ioc),
            "hash" => format!("https://otx.alienvault.com/api/v1/indicators/file/{}/general", ioc),
            "url" => format!("https://otx.alienvault.com/api/v1/indicators/url/{}/general", urlencoding::encode(ioc)),
            _ => return Ok(None),
        };

        let response = self
            .client
            .get(&endpoint)
            .header("X-OTX-API-KEY", api_key)
            .send()
            .await?;

        if response.status().is_success() {
            let otx_response: OtxResponse = response.json().await?;
            Ok(Some(otx_response))
        } else {
            log::debug!("OTX query failed with status: {}", response.status());
            Ok(None)
        }
    }
}

impl Default for IocEnricher {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect the type of IOC based on its format
fn detect_ioc_type(ioc: &str) -> String {
    // Check if it's an IP address
    if ioc.parse::<IpAddr>().is_ok() {
        return "ip".to_string();
    }

    // Check if it's a hash (MD5, SHA1, SHA256)
    let ioc_lower = ioc.to_lowercase();
    if ioc_lower.len() == 32 && ioc_lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return "hash".to_string(); // MD5
    }
    if ioc_lower.len() == 40 && ioc_lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return "hash".to_string(); // SHA1
    }
    if ioc_lower.len() == 64 && ioc_lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return "hash".to_string(); // SHA256
    }

    // Check if it's a URL
    if ioc.starts_with("http://") || ioc.starts_with("https://") {
        return "url".to_string();
    }

    // Check if it's an email
    if ioc.contains('@') && ioc.contains('.') {
        return "email".to_string();
    }

    // Default to domain
    "domain".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedIoc {
    pub ioc: String,
    pub ioc_type: String,
    pub reputation_score: f32,
    pub first_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
    pub threat_types: Vec<String>,
    pub sources: Vec<EnrichmentSource>,
    pub related_indicators: Vec<String>,
    pub geo_location: Option<GeoLocation>,
    pub asn_info: Option<AsnInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentSource {
    pub name: String,
    pub url: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: String,
    pub organization: String,
    pub isp: Option<String>,
}
