use super::{SiemEvent, SiemExporter};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

pub struct ElasticsearchExporter {
    client: Client,
    endpoint_url: String,
    api_key: Option<String>,
    index_name: String,
}

impl ElasticsearchExporter {
    pub fn new(endpoint_url: &str, api_key: Option<&str>) -> Result<Self> {
        // Ensure endpoint URL doesn't have trailing slash
        let endpoint_url = endpoint_url.trim_end_matches('/').to_string();

        let mut client_builder = Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(30));

        // Set up authentication if API key is provided
        if let Some(key) = api_key {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "Authorization",
                format!("ApiKey {}", key).parse().unwrap(),
            );
            client_builder = client_builder.default_headers(headers);
        }

        Ok(Self {
            client: client_builder.build()?,
            endpoint_url,
            api_key: api_key.map(|s| s.to_string()),
            index_name: "heroforge-security".to_string(),
        })
    }

    fn format_elasticsearch_document(&self, event: &SiemEvent) -> serde_json::Value {
        json!({
            "@timestamp": event.timestamp,
            "event": {
                "type": event.event_type,
                "severity": event.severity,
                "message": event.message,
            },
            "source": {
                "ip": event.source_ip,
            },
            "destination": {
                "ip": event.destination_ip,
                "port": event.port,
            },
            "network": {
                "protocol": event.protocol,
            },
            "vulnerability": {
                "cve_ids": event.cve_ids,
                "cvss_score": event.cvss_score,
            },
            "heroforge": {
                "scan_id": event.scan_id,
                "user_id": event.user_id,
            },
            "details": event.details,
        })
    }
}

#[async_trait]
impl SiemExporter for ElasticsearchExporter {
    async fn export_event(&self, event: &SiemEvent) -> Result<()> {
        let document = self.format_elasticsearch_document(event);

        // Use current date for index name (e.g., heroforge-security-2024-01-15)
        let index_date = event.timestamp.format("%Y-%m-%d");
        let index_url = format!(
            "{}/{}-{}/_doc",
            self.endpoint_url, self.index_name, index_date
        );

        let response = self.client.post(&index_url).json(&document).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Elasticsearch index request failed with status {}: {}",
                status,
                error_text
            );
        }

        Ok(())
    }

    async fn export_events(&self, events: &[SiemEvent]) -> Result<()> {
        // Use Elasticsearch Bulk API for batch ingestion
        if events.is_empty() {
            return Ok(());
        }

        // Group events by date to ensure they go to correct daily indices
        let mut bulk_body = String::new();

        for event in events {
            let index_date = event.timestamp.format("%Y-%m-%d");
            let index_name = format!("{}-{}", self.index_name, index_date);

            // Action line
            let action = json!({
                "index": {
                    "_index": index_name
                }
            });
            bulk_body.push_str(&serde_json::to_string(&action)?);
            bulk_body.push('\n');

            // Document line
            let document = self.format_elasticsearch_document(event);
            bulk_body.push_str(&serde_json::to_string(&document)?);
            bulk_body.push('\n');
        }

        let bulk_url = format!("{}/_bulk", self.endpoint_url);

        let response = self
            .client
            .post(&bulk_url)
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Elasticsearch bulk request failed with status {}: {}",
                status,
                error_text
            );
        }

        // Check for partial errors in bulk response
        let bulk_response: serde_json::Value = response.json().await?;
        if let Some(true) = bulk_response["errors"].as_bool() {
            log::warn!("Some documents failed to index in bulk operation");
            // Log but don't fail - partial success is still success
        }

        Ok(())
    }

    async fn test_connection(&self) -> Result<()> {
        // Test connection by checking cluster health
        let health_url = format!("{}/_cluster/health", self.endpoint_url);

        let response = self.client.get(&health_url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Elasticsearch health check failed with status {}: {}",
                status,
                error_text
            );
        }

        // Also send a test event
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
