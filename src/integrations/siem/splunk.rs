use super::{SiemEvent, SiemExporter};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

pub struct SplunkExporter {
    client: Client,
    endpoint_url: String,
    api_key: String,
}

impl SplunkExporter {
    pub fn new(endpoint_url: &str, api_key: &str) -> Result<Self> {
        // Ensure endpoint ends with /services/collector/event
        let endpoint_url = if endpoint_url.ends_with("/services/collector/event") {
            endpoint_url.to_string()
        } else if endpoint_url.ends_with('/') {
            format!("{}services/collector/event", endpoint_url)
        } else {
            format!("{}/services/collector/event", endpoint_url)
        };

        Ok(Self {
            client: Client::builder()
                .danger_accept_invalid_certs(false)
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            endpoint_url,
            api_key: api_key.to_string(),
        })
    }

    fn format_hec_event(&self, event: &SiemEvent) -> serde_json::Value {
        // Splunk HTTP Event Collector format
        json!({
            "time": event.timestamp.timestamp(),
            "host": "heroforge",
            "source": "heroforge-scanner",
            "sourcetype": "heroforge:security",
            "event": {
                "event_type": event.event_type,
                "severity": event.severity,
                "message": event.message,
                "scan_id": event.scan_id,
                "user_id": event.user_id,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "port": event.port,
                "protocol": event.protocol,
                "cve_ids": event.cve_ids,
                "cvss_score": event.cvss_score,
                "details": event.details,
            }
        })
    }
}

#[async_trait]
impl SiemExporter for SplunkExporter {
    async fn export_event(&self, event: &SiemEvent) -> Result<()> {
        let payload = self.format_hec_event(event);

        let response = self
            .client
            .post(&self.endpoint_url)
            .header("Authorization", format!("Splunk {}", self.api_key))
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Splunk HEC request failed with status {}: {}",
                status,
                error_text
            );
        }

        Ok(())
    }

    async fn export_events(&self, events: &[SiemEvent]) -> Result<()> {
        // Splunk HEC supports batch ingestion - send all events in one request
        if events.is_empty() {
            return Ok(());
        }

        let batch: Vec<_> = events.iter().map(|e| self.format_hec_event(e)).collect();

        // Send as newline-delimited JSON
        let payload: String = batch
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");

        let response = self
            .client
            .post(&self.endpoint_url)
            .header("Authorization", format!("Splunk {}", self.api_key))
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Splunk HEC batch request failed with status {}: {}",
                status,
                error_text
            );
        }

        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        let test_event = SiemEvent {
            timestamp: chrono::Utc::now(),
            severity: "info".to_string(),
            event_type: "test_connection".to_string(),
            source_ip: None,
            destination_ip: None,
            port: None,
            protocol: None,
            message: "HeroForge SIEM integration test".to_string(),
            details: serde_json::json!({"test": true}),
            cve_ids: vec![],
            cvss_score: None,
            scan_id: "test".to_string(),
            user_id: "test".to_string(),
        };

        self.export_event(&test_event).await
    }
}
