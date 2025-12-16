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
        Self::with_client(
            endpoint_url,
            api_key,
            Client::builder()
                .danger_accept_invalid_certs(false)
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        )
    }

    /// Create a new exporter with a custom HTTP client (useful for testing)
    pub fn with_client(endpoint_url: &str, api_key: &str, client: Client) -> Result<Self> {
        // Ensure endpoint ends with /services/collector/event
        let endpoint_url = if endpoint_url.ends_with("/services/collector/event") {
            endpoint_url.to_string()
        } else if endpoint_url.ends_with('/') {
            format!("{}services/collector/event", endpoint_url)
        } else {
            format!("{}/services/collector/event", endpoint_url)
        };

        Ok(Self {
            client,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_event() -> SiemEvent {
        SiemEvent {
            timestamp: Utc::now(),
            severity: "high".to_string(),
            event_type: "vulnerability_found".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            port: Some(443),
            protocol: Some("tcp".to_string()),
            message: "SQL Injection vulnerability detected".to_string(),
            details: serde_json::json!({"cve": "CVE-2024-1234", "cvss": 9.8}),
            cve_ids: vec!["CVE-2024-1234".to_string()],
            cvss_score: Some(9.8),
            scan_id: "scan-123".to_string(),
            user_id: "user-456".to_string(),
        }
    }

    #[test]
    fn test_endpoint_url_normalization() {
        let client = Client::new();

        // Test URL without suffix
        let exporter = SplunkExporter::with_client(
            "https://splunk.example.com:8088",
            "test-token",
            client.clone(),
        )
        .unwrap();
        assert!(exporter
            .endpoint_url
            .ends_with("/services/collector/event"));

        // Test URL with trailing slash
        let exporter = SplunkExporter::with_client(
            "https://splunk.example.com:8088/",
            "test-token",
            client.clone(),
        )
        .unwrap();
        assert!(exporter
            .endpoint_url
            .ends_with("/services/collector/event"));

        // Test URL already with suffix
        let exporter = SplunkExporter::with_client(
            "https://splunk.example.com:8088/services/collector/event",
            "test-token",
            client,
        )
        .unwrap();
        assert_eq!(
            exporter.endpoint_url,
            "https://splunk.example.com:8088/services/collector/event"
        );
    }

    #[test]
    fn test_format_hec_event() {
        let client = Client::new();
        let exporter =
            SplunkExporter::with_client("https://splunk.example.com:8088", "test-token", client)
                .unwrap();

        let event = create_test_event();
        let formatted = exporter.format_hec_event(&event);

        // Verify HEC format structure
        assert_eq!(formatted["host"], "heroforge");
        assert_eq!(formatted["source"], "heroforge-scanner");
        assert_eq!(formatted["sourcetype"], "heroforge:security");
        assert!(formatted["time"].is_number());

        // Verify event data
        let event_data = &formatted["event"];
        assert_eq!(event_data["event_type"], "vulnerability_found");
        assert_eq!(event_data["severity"], "high");
        assert_eq!(event_data["scan_id"], "scan-123");
        assert_eq!(event_data["source_ip"], "192.168.1.100");
        assert_eq!(event_data["destination_ip"], "10.0.0.1");
        assert_eq!(event_data["port"], 443);
    }

    #[tokio::test]
    async fn test_export_event_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/services/collector/event")
            .match_header("Authorization", "Splunk test-hec-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"text": "Success", "code": 0}"#)
            .create_async()
            .await;

        let exporter =
            SplunkExporter::with_client(&server.url(), "test-hec-token", Client::new()).unwrap();

        let event = create_test_event();
        let result = exporter.export_event(&event).await;

        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_event_unauthorized() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/services/collector/event")
            .with_status(401)
            .with_body(r#"{"text": "Invalid token", "code": 4}"#)
            .create_async()
            .await;

        let exporter =
            SplunkExporter::with_client(&server.url(), "invalid-token", Client::new()).unwrap();

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

        let mock = server
            .mock("POST", "/services/collector/event")
            .with_status(500)
            .with_body(r#"{"text": "Internal error", "code": 6}"#)
            .create_async()
            .await;

        let exporter =
            SplunkExporter::with_client(&server.url(), "test-token", Client::new()).unwrap();

        let event = create_test_event();
        let result = exporter.export_event(&event).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_events_batch_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/services/collector/event")
            .match_header("Authorization", "Splunk test-hec-token")
            .match_header("Content-Type", "application/json")
            .with_status(200)
            .with_body(r#"{"text": "Success", "code": 0}"#)
            .create_async()
            .await;

        let exporter =
            SplunkExporter::with_client(&server.url(), "test-hec-token", Client::new()).unwrap();

        let events = vec![create_test_event(), create_test_event()];
        let result = exporter.export_events(&events).await;

        assert!(result.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_export_events_empty_batch() {
        // Empty batch should return Ok without making any request
        let exporter =
            SplunkExporter::with_client("https://splunk.example.com:8088", "test-token", Client::new())
                .unwrap();

        let events: Vec<SiemEvent> = vec![];
        let result = exporter.export_events(&events).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_export_events_batch_failure() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/services/collector/event")
            .with_status(503)
            .with_body(r#"{"text": "Service temporarily unavailable", "code": 9}"#)
            .create_async()
            .await;

        let exporter =
            SplunkExporter::with_client(&server.url(), "test-token", Client::new()).unwrap();

        let events = vec![create_test_event()];
        let result = exporter.export_events(&events).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("503"));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_connection_success() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/services/collector/event")
            .with_status(200)
            .with_body(r#"{"text": "Success", "code": 0}"#)
            .create_async()
            .await;

        let exporter =
            SplunkExporter::with_client(&server.url(), "test-token", Client::new()).unwrap();

        let result = exporter.test_connection().await;
        assert!(result.is_ok());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_authorization_header_format() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("POST", "/services/collector/event")
            .match_header("Authorization", "Splunk my-secret-hec-token")
            .with_status(200)
            .with_body(r#"{"text": "Success", "code": 0}"#)
            .create_async()
            .await;

        let exporter =
            SplunkExporter::with_client(&server.url(), "my-secret-hec-token", Client::new())
                .unwrap();

        let event = create_test_event();
        let _ = exporter.export_event(&event).await;

        mock.assert_async().await;
    }
}
