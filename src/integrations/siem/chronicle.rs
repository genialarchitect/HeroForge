//! Google Chronicle SIEM Integration
//!
//! Provides integration with Google Chronicle (SecOps):
//! - UDM (Unified Data Model) log ingestion
//! - Detection Engine rules
//! - IOC matching
//! - Reference list management
//! - Search and hunting

use super::{SiemEvent, SiemExporter};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};

const CHRONICLE_API_BASE: &str = "https://backstory.googleapis.com";
const CHRONICLE_INGESTION_API: &str = "https://malachiteingestion-pa.googleapis.com";

/// Google Chronicle exporter
pub struct ChronicleExporter {
    client: Client,
    config: ChronicleConfig,
}

/// Chronicle configuration
#[derive(Debug, Clone)]
pub struct ChronicleConfig {
    /// Google Cloud project ID
    pub project_id: String,
    /// Customer ID (UUID format)
    pub customer_id: String,
    /// API Key for authentication (simpler than OAuth2)
    pub api_key: String,
    /// Region (us, europe, asia-southeast1)
    pub region: String,
    /// Log type for ingestion
    pub log_type: String,
}

impl ChronicleConfig {
    pub fn new(project_id: String, customer_id: String, api_key: String) -> Self {
        Self {
            project_id,
            customer_id,
            api_key,
            region: "us".to_string(),
            log_type: "HEROFORGE".to_string(),
        }
    }

    pub fn with_region(mut self, region: String) -> Self {
        self.region = region;
        self
    }

    pub fn with_log_type(mut self, log_type: String) -> Self {
        self.log_type = log_type;
        self
    }
}

impl ChronicleExporter {
    /// Create new Chronicle exporter
    pub fn new(config: ChronicleConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            config,
        })
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self> {
        let project_id = std::env::var("GOOGLE_CLOUD_PROJECT")
            .map_err(|_| anyhow!("GOOGLE_CLOUD_PROJECT not set"))?;
        let customer_id = std::env::var("CHRONICLE_CUSTOMER_ID")
            .map_err(|_| anyhow!("CHRONICLE_CUSTOMER_ID not set"))?;
        let api_key = std::env::var("CHRONICLE_API_KEY")
            .map_err(|_| anyhow!("CHRONICLE_API_KEY not set"))?;

        let mut config = ChronicleConfig::new(project_id, customer_id, api_key);

        if let Ok(region) = std::env::var("CHRONICLE_REGION") {
            config = config.with_region(region);
        }

        if let Ok(log_type) = std::env::var("CHRONICLE_LOG_TYPE") {
            config = config.with_log_type(log_type);
        }

        Self::new(config)
    }

    /// Get API key for authentication
    fn get_api_key(&self) -> &str {
        &self.config.api_key
    }

    /// Get ingestion API URL
    fn ingestion_url(&self) -> String {
        let base = match self.config.region.as_str() {
            "europe" => "https://europe-malachiteingestion-pa.googleapis.com",
            "asia-southeast1" => "https://asia-southeast1-malachiteingestion-pa.googleapis.com",
            _ => CHRONICLE_INGESTION_API,
        };
        format!("{}/v2/unstructuredlogentries:batchCreate", base)
    }

    /// Get backstory API URL
    fn backstory_url(&self) -> String {
        let base = match self.config.region.as_str() {
            "europe" => "https://europe-backstory.googleapis.com",
            "asia-southeast1" => "https://asia-southeast1-backstory.googleapis.com",
            _ => CHRONICLE_API_BASE,
        };
        base.to_string()
    }

    /// Ingest logs using Chronicle Ingestion API
    async fn ingest_logs(&self, entries: &[ChronicleLogEntry]) -> Result<()> {
        let request = ChronicleIngestionRequest {
            customer_id: self.config.customer_id.clone(),
            log_type: self.config.log_type.clone(),
            entries: entries.to_vec(),
        };

        // Use API key in URL query parameter
        let url = format!("{}?key={}", self.ingestion_url(), self.get_api_key());

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Chronicle ingestion failed: {} - {}", status, body));
        }

        info!("Ingested {} events to Chronicle", entries.len());
        Ok(())
    }

    /// Convert SiemEvent to Chronicle UDM format
    fn convert_to_udm(&self, event: &SiemEvent) -> ChronicleLogEntry {
        // Create UDM JSON
        let udm = serde_json::json!({
            "metadata": {
                "event_timestamp": event.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
                "event_type": map_event_type(&event.event_type),
                "product_name": "HeroForge",
                "vendor_name": "HeroForge",
                "description": event.message,
            },
            "principal": {
                "ip": event.source_ip,
                "user": {
                    "userid": event.user_id,
                }
            },
            "target": {
                "ip": event.destination_ip,
                "port": event.port,
            },
            "network": {
                "ip_protocol": event.protocol.as_deref().unwrap_or("TCP"),
            },
            "security_result": [{
                "severity": map_severity(&event.severity),
                "category": event.event_type,
                "summary": event.message,
                "detection_fields": event.cve_ids.iter().map(|cve| {
                    serde_json::json!({
                        "key": "cve_id",
                        "value": cve
                    })
                }).collect::<Vec<_>>(),
            }],
            "extensions": {
                "vulns": {
                    "vulnerabilities": event.cve_ids.iter().map(|cve| {
                        serde_json::json!({
                            "cve_id": cve,
                            "cvss_score": event.cvss_score,
                        })
                    }).collect::<Vec<_>>(),
                }
            }
        });

        ChronicleLogEntry {
            log_text: serde_json::to_string(&udm).unwrap_or_default(),
            ts_epoch_microseconds: event.timestamp.timestamp_micros(),
        }
    }

    /// Search for events using Chronicle Search API
    pub async fn search(&self, query: &str, start_time: DateTime<Utc>, end_time: DateTime<Utc>) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "{}/v2/detect/rules:runRetrohunt?key={}",
            self.backstory_url(),
            self.get_api_key()
        );

        let request = serde_json::json!({
            "rule_text": query,
            "start_time": start_time.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            "end_time": end_time.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
        });

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Chronicle search failed: {} - {}", status, body));
        }

        let result: serde_json::Value = response.json().await?;
        let events = result.get("detections")
            .and_then(|d| d.as_array())
            .map(|a| a.to_vec())
            .unwrap_or_default();

        Ok(events)
    }

    /// Check IOC against Chronicle
    pub async fn check_ioc(&self, indicator: &str, indicator_type: &str) -> Result<ChronicleIocMatch> {
        let url = format!(
            "{}/v2/ioc:isReputationAvailable?key={}",
            self.backstory_url(),
            self.get_api_key()
        );

        let request = serde_json::json!({
            "indicator": {
                "indicator_type": indicator_type,
                "indicator_value": indicator,
            }
        });

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("IOC check failed: {} - {}", status, body));
        }

        let result: serde_json::Value = response.json().await?;

        Ok(ChronicleIocMatch {
            indicator: indicator.to_string(),
            indicator_type: indicator_type.to_string(),
            is_available: result.get("isAvailable").and_then(|v| v.as_bool()).unwrap_or(false),
            sources: result.get("sources")
                .and_then(|s| s.as_array())
                .map(|a| a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect())
                .unwrap_or_default(),
        })
    }

    /// List detection rules
    pub async fn list_rules(&self) -> Result<Vec<ChronicleRule>> {
        let url = format!("{}/v2/detect/rules?key={}", self.backstory_url(), self.get_api_key());

        let response = self.client
            .get(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("List rules failed: {} - {}", status, body));
        }

        let result: ChronicleRulesResponse = response.json().await?;
        Ok(result.rules)
    }
}

#[async_trait]
impl SiemExporter for ChronicleExporter {
    async fn export_event(&self, event: &SiemEvent) -> Result<()> {
        let entry = self.convert_to_udm(event);
        self.ingest_logs(&[entry]).await
    }

    async fn export_events(&self, events: &[SiemEvent]) -> Result<()> {
        let entries: Vec<ChronicleLogEntry> = events.iter()
            .map(|e| self.convert_to_udm(e))
            .collect();
        self.ingest_logs(&entries).await
    }

    async fn test_connection(&self) -> Result<()> {
        // Verify API key is configured
        if self.config.api_key.is_empty() {
            return Err(anyhow!("Chronicle API key not configured"));
        }
        // Try to list rules as a connection test
        let _ = self.list_rules().await?;
        Ok(())
    }
}

// =============================================================================
// Chronicle API Types
// =============================================================================

#[derive(Debug, Clone, Serialize)]
struct ChronicleIngestionRequest {
    customer_id: String,
    log_type: String,
    entries: Vec<ChronicleLogEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct ChronicleLogEntry {
    log_text: String,
    ts_epoch_microseconds: i64,
}

/// IOC match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleIocMatch {
    pub indicator: String,
    pub indicator_type: String,
    pub is_available: bool,
    pub sources: Vec<String>,
}

/// Detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChronicleRule {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleName")]
    pub rule_name: String,
    #[serde(rename = "ruleText")]
    pub rule_text: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ChronicleRulesResponse {
    #[serde(default)]
    rules: Vec<ChronicleRule>,
}

// =============================================================================
// Helper Functions
// =============================================================================

fn map_event_type(event_type: &str) -> &'static str {
    match event_type {
        "scan_complete" => "SCAN_UNCATEGORIZED",
        "vulnerability_found" => "SCAN_VULN_HOST",
        "host_discovered" => "SCAN_HOST",
        "port_found" => "SCAN_NETWORK",
        _ => "GENERIC_EVENT",
    }
}

fn map_severity(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" => "HIGH",
        "medium" => "MEDIUM",
        "low" => "LOW",
        "informational" | "info" => "INFORMATIONAL",
        _ => "UNKNOWN_SEVERITY",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = ChronicleConfig::new(
            "project123".to_string(),
            "customer-uuid".to_string(),
            "{}".to_string(),
        );
        assert_eq!(config.project_id, "project123");
        assert_eq!(config.region, "us");
        assert_eq!(config.log_type, "HEROFORGE");
    }

    #[test]
    fn test_config_with_options() {
        let config = ChronicleConfig::new("p".to_string(), "c".to_string(), "{}".to_string())
            .with_region("europe".to_string())
            .with_log_type("CUSTOM_LOG".to_string());

        assert_eq!(config.region, "europe");
        assert_eq!(config.log_type, "CUSTOM_LOG");
    }

    #[test]
    fn test_map_severity() {
        assert_eq!(map_severity("critical"), "CRITICAL");
        assert_eq!(map_severity("HIGH"), "HIGH");
        assert_eq!(map_severity("Info"), "INFORMATIONAL");
        assert_eq!(map_severity("unknown"), "UNKNOWN_SEVERITY");
    }
}
