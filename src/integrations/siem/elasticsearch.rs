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

        Self::with_client(endpoint_url, api_key, client_builder.build()?)
    }

    /// Create a new exporter with a custom HTTP client (useful for testing)
    pub fn with_client(endpoint_url: &str, api_key: Option<&str>, client: Client) -> Result<Self> {
        // Ensure endpoint URL doesn't have trailing slash
        let endpoint_url = endpoint_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_event() -> SiemEvent {
        SiemEvent {
            timestamp: Utc::now(),
            severity: "critical".to_string(),
            event_type: "vulnerability_found".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            port: Some(22),
            protocol: Some("tcp".to_string()),
            message: "SSH vulnerability detected".to_string(),
            details: serde_json::json!({"cve": "CVE-2024-5678", "cvss": 9.1}),
            cve_ids: vec!["CVE-2024-5678".to_string()],
            cvss_score: Some(9.1),
            scan_id: "scan-456".to_string(),
            user_id: "user-789".to_string(),
        }
    }

    #[test]
    fn test_endpoint_url_normalization() {
        let client = Client::new();

        // Test URL with trailing slash is trimmed
        let exporter =
            ElasticsearchExporter::with_client("https://elastic.example.com:9200/", None, client.clone())
                .unwrap();
        assert!(!exporter.endpoint_url.ends_with('/'));

        // Test URL without trailing slash stays the same
        let exporter =
            ElasticsearchExporter::with_client("https://elastic.example.com:9200", None, client)
                .unwrap();
        assert_eq!(exporter.endpoint_url, "https://elastic.example.com:9200");
    }

    #[test]
    fn test_format_elasticsearch_document() {
        let client = Client::new();
        let exporter =
            ElasticsearchExporter::with_client("https://elastic.example.com:9200", None, client)
                .unwrap();

        let event = create_test_event();
        let doc = exporter.format_elasticsearch_document(&event);

        // Verify ECS-like structure
        assert!(doc["@timestamp"].is_string());
        assert_eq!(doc["event"]["type"], "vulnerability_found");
        assert_eq!(doc["event"]["severity"], "critical");
        assert_eq!(doc["source"]["ip"], "192.168.1.100");
        assert_eq!(doc["destination"]["ip"], "10.0.0.1");
        assert_eq!(doc["destination"]["port"], 22);
        assert_eq!(doc["network"]["protocol"], "tcp");
        assert_eq!(doc["heroforge"]["scan_id"], "scan-456");
        assert_eq!(doc["vulnerability"]["cve_ids"][0], "CVE-2024-5678");
    }

    #[tokio::test]
    async fn test_export_event_success() {
        let mut server = mockito::Server::new_async().await;
        let today = Utc::now().format("%Y-%m-%d");

        let mock = server
            .mock("POST", format!("/heroforge-security-{}/_doc", today).as_str())
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"_index": "heroforge-security", "_id": "abc123", "result": "created"}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let event = create_test_event();
        let result = exporter.export_event(&event).await;

        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_event_unauthorized() {
        let mut server = mockito::Server::new_async().await;
        let today = Utc::now().format("%Y-%m-%d");

        let mock = server
            .mock("POST", format!("/heroforge-security-{}/_doc", today).as_str())
            .with_status(401)
            .with_body(r#"{"error": {"type": "security_exception", "reason": "missing authentication credentials"}}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let event = create_test_event();
        let result = exporter.export_event(&event).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("401"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_event_server_error() {
        let mut server = mockito::Server::new_async().await;
        let today = Utc::now().format("%Y-%m-%d");

        let mock = server
            .mock("POST", format!("/heroforge-security-{}/_doc", today).as_str())
            .with_status(500)
            .with_body(r#"{"error": {"type": "internal_server_error", "reason": "unknown error"}}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let event = create_test_event();
        let result = exporter.export_event(&event).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_events_bulk_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/_bulk")
            .match_header("Content-Type", "application/x-ndjson")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"took": 30, "errors": false, "items": [{"index": {"result": "created"}}]}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let events = vec![create_test_event(), create_test_event()];
        let result = exporter.export_events(&events).await;

        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_events_empty_batch() {
        // Empty batch should return Ok without making any request
        let exporter =
            ElasticsearchExporter::with_client("https://elastic.example.com:9200", None, Client::new())
                .unwrap();

        let events: Vec<SiemEvent> = vec![];
        let result = exporter.export_events(&events).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_events_partial_errors() {
        let mut server = mockito::Server::new_async().await;

        // Elasticsearch returns success status but with errors in body
        let mock = server
            .mock("POST", "/_bulk")
            .with_status(200)
            .with_body(r#"{"took": 30, "errors": true, "items": [{"index": {"result": "created"}}, {"index": {"error": {"type": "mapper_parsing_exception"}}}]}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let events = vec![create_test_event()];
        let result = exporter.export_events(&events).await;

        // Partial errors are logged but don't fail the operation
        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_events_bulk_failure() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/_bulk")
            .with_status(503)
            .with_body(r#"{"error": {"type": "cluster_block_exception", "reason": "index read-only"}}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let events = vec![create_test_event()];
        let result = exporter.export_events(&events).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("503"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_connection_health_check_success() {
        let mut server = mockito::Server::new_async().await;
        let today = Utc::now().format("%Y-%m-%d");

        let health_mock = server
            .mock("GET", "/_cluster/health")
            .with_status(200)
            .with_body(r#"{"cluster_name": "test", "status": "green", "number_of_nodes": 3}"#)
            .create_async()
            .await;

        let doc_mock = server
            .mock("POST", format!("/heroforge-security-{}/_doc", today).as_str())
            .with_status(201)
            .with_body(r#"{"_id": "test", "result": "created"}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let result = exporter.test_connection().await;
        assert!(result.is_ok());

        health_mock.assert_async().await;
        doc_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_connection_health_check_failure() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/_cluster/health")
            .with_status(503)
            .with_body(r#"{"error": "Service unavailable"}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let result = exporter.test_connection().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("503"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_daily_index_naming() {
        let mut server = mockito::Server::new_async().await;

        // Create event with specific date
        let event = create_test_event();
        let expected_date = event.timestamp.format("%Y-%m-%d");
        let expected_path = format!("/heroforge-security-{}/_doc", expected_date);

        let mock = server
            .mock("POST", expected_path.as_str())
            .with_status(201)
            .with_body(r#"{"_id": "test", "result": "created"}"#)
            .create_async()
            .await;

        let exporter =
            ElasticsearchExporter::with_client(&server.url(), None, Client::new()).unwrap();

        let result = exporter.export_event(&event).await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }
}
