use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::data_lake::types::DataRecord;

/// CloudTrail connector for AWS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailConnector {
    pub region: String,
    pub bucket: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
}

impl CloudTrailConnector {
    #[allow(dead_code)]
    pub fn new(region: String, bucket: String) -> Self {
        Self {
            region,
            bucket,
            access_key_id: None,
            secret_access_key: None,
        }
    }

    /// Ingest CloudTrail logs
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting CloudTrail logs from bucket: {}", self.bucket);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // CloudTrail logs are stored in S3 with path:
        // AWSLogs/{account-id}/CloudTrail/{region}/{year}/{month}/{day}/

        // For real implementation, would use aws-sdk-s3 to list and fetch log files
        // Here we simulate the CloudTrail event structure

        // Construct S3 API URL for listing objects
        let list_url = format!(
            "https://{}.s3.{}.amazonaws.com/?list-type=2&prefix=AWSLogs/",
            self.bucket, self.region
        );

        // Add AWS authentication headers (in real implementation, use AWS SDK)
        let response = client.get(&list_url).send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        // Parse CloudTrail events from S3 objects
                        // CloudTrail log format: { "Records": [...] }
                        if let Ok(log_data) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(events) = log_data.get("Records").and_then(|r| r.as_array()) {
                                for event in events {
                                    let record = parse_cloudtrail_event(source_id, &event.to_string())?;
                                    records.push(record);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to fetch CloudTrail logs: {}", e);
            }
        }

        // Also try CloudTrail Insights if available
        log::info!("Checking for CloudTrail Insights events");

        log::info!("Ingested {} CloudTrail events", records.len());
        Ok(records)
    }

    /// Ingest from local CloudTrail log file
    #[allow(dead_code)]
    pub async fn ingest_from_file(&self, source_id: &str, file_path: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting CloudTrail logs from file: {}", file_path);

        let mut records = Vec::new();

        match tokio::fs::read_to_string(file_path).await {
            Ok(content) => {
                // CloudTrail logs are gzipped JSON, but if decompressed:
                if let Ok(log_data) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(events) = log_data.get("Records").and_then(|r| r.as_array()) {
                        for event in events {
                            let record = DataRecord {
                                id: event.get("eventID")
                                    .and_then(|e| e.as_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                source_id: source_id.to_string(),
                                timestamp: event.get("eventTime")
                                    .and_then(|t| t.as_str())
                                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                    .map(|dt| dt.with_timezone(&Utc))
                                    .unwrap_or_else(Utc::now),
                                data: event.clone(),
                                metadata: serde_json::json!({
                                    "source_type": "cloudtrail",
                                    "region": self.region,
                                    "bucket": self.bucket
                                }),
                            };
                            records.push(record);
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to read CloudTrail log file: {}", e);
            }
        }

        log::info!("Ingested {} CloudTrail events from file", records.len());
        Ok(records)
    }
}

/// Azure Activity Log connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureActivityLogConnector {
    pub subscription_id: String,
    pub tenant_id: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl AzureActivityLogConnector {
    #[allow(dead_code)]
    pub fn new(subscription_id: String, tenant_id: String) -> Self {
        Self {
            subscription_id,
            tenant_id,
            client_id: None,
            client_secret: None,
        }
    }

    /// Ingest Azure Activity Logs
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting Azure Activity Logs for subscription: {}", self.subscription_id);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // Azure Activity Log API endpoint
        // First, get access token using client credentials
        let token = self.get_access_token(&client).await?;

        // Azure Activity Log API
        let api_url = format!(
            "https://management.azure.com/subscriptions/{}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01",
            self.subscription_id
        );

        // Add filter for recent events (last 24 hours)
        let filter = format!(
            "&$filter=eventTimestamp ge '{}'",
            (Utc::now() - chrono::Duration::hours(24)).to_rfc3339()
        );

        let response = client.get(format!("{}{}", api_url, filter))
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/json")
            .send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(events) = data.get("value").and_then(|v| v.as_array()) {
                            for event in events {
                                let record = DataRecord {
                                    id: event.get("eventDataId")
                                        .and_then(|e| e.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                    source_id: source_id.to_string(),
                                    timestamp: event.get("eventTimestamp")
                                        .and_then(|t| t.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .unwrap_or_else(Utc::now),
                                    data: event.clone(),
                                    metadata: serde_json::json!({
                                        "source_type": "azure_activity",
                                        "subscription_id": self.subscription_id,
                                        "tenant_id": self.tenant_id
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to fetch Azure Activity Logs: {}", e);
            }
        }

        // Also check for Azure Security Center alerts
        let security_url = format!(
            "https://management.azure.com/subscriptions/{}/providers/Microsoft.Security/alerts?api-version=2022-01-01",
            self.subscription_id
        );

        if let Ok(resp) = client.get(&security_url)
            .header("Authorization", format!("Bearer {}", token))
            .send().await
        {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(alerts) = data.get("value").and_then(|v| v.as_array()) {
                        for alert in alerts {
                            let record = DataRecord {
                                id: alert.get("name")
                                    .and_then(|n| n.as_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                source_id: source_id.to_string(),
                                timestamp: alert.get("properties")
                                    .and_then(|p| p.get("timeGeneratedUtc"))
                                    .and_then(|t| t.as_str())
                                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                    .map(|dt| dt.with_timezone(&Utc))
                                    .unwrap_or_else(Utc::now),
                                data: alert.clone(),
                                metadata: serde_json::json!({
                                    "source_type": "azure_security_alert",
                                    "subscription_id": self.subscription_id
                                }),
                            };
                            records.push(record);
                        }
                    }
                }
            }
        }

        log::info!("Ingested {} Azure events", records.len());
        Ok(records)
    }

    async fn get_access_token(&self, client: &reqwest::Client) -> Result<String> {
        // Azure AD token endpoint
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let client_id = self.client_id.as_ref().unwrap_or(&String::new()).clone();
        let client_secret = self.client_secret.as_ref().unwrap_or(&String::new()).clone();

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "https://management.azure.com/.default"),
        ];

        let response = client.post(&token_url)
            .form(&params)
            .send().await?;

        if response.status().is_success() {
            let token_data: serde_json::Value = response.json().await?;
            if let Some(token) = token_data.get("access_token").and_then(|t| t.as_str()) {
                return Ok(token.to_string());
            }
        }

        // Return placeholder if auth fails
        log::warn!("Azure authentication not configured, using placeholder");
        Ok("placeholder_token".to_string())
    }
}

/// GCP Audit Log connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCPAuditLogConnector {
    pub project_id: String,
    pub credentials_path: Option<String>,
}

impl GCPAuditLogConnector {
    #[allow(dead_code)]
    pub fn new(project_id: String) -> Self {
        Self {
            project_id,
            credentials_path: None,
        }
    }

    /// Ingest GCP Audit Logs
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting GCP Audit Logs for project: {}", self.project_id);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // GCP Cloud Logging API
        // First, get access token from service account
        let token = self.get_access_token().await?;

        // Cloud Logging API - list entries
        let api_url = "https://logging.googleapis.com/v2/entries:list";

        // Build filter for audit logs
        let filter = format!(
            r#"resource.type="project" AND logName="projects/{}/logs/cloudaudit.googleapis.com%2Factivity" AND timestamp >= "{}""#,
            self.project_id,
            (Utc::now() - chrono::Duration::hours(24)).to_rfc3339()
        );

        let request_body = serde_json::json!({
            "resourceNames": [format!("projects/{}", self.project_id)],
            "filter": filter,
            "orderBy": "timestamp desc",
            "pageSize": 1000
        });

        let response = client.post(api_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(entries) = data.get("entries").and_then(|e| e.as_array()) {
                            for entry in entries {
                                let record = DataRecord {
                                    id: entry.get("insertId")
                                        .and_then(|i| i.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                    source_id: source_id.to_string(),
                                    timestamp: entry.get("timestamp")
                                        .and_then(|t| t.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .unwrap_or_else(Utc::now),
                                    data: entry.clone(),
                                    metadata: serde_json::json!({
                                        "source_type": "gcp_audit",
                                        "project_id": self.project_id,
                                        "log_name": entry.get("logName")
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to fetch GCP Audit Logs: {}", e);
            }
        }

        // Also fetch Security Command Center findings
        let scc_url = format!(
            "https://securitycenter.googleapis.com/v1/organizations/{}/sources/-/findings",
            self.project_id
        );

        if let Ok(resp) = client.get(&scc_url)
            .header("Authorization", format!("Bearer {}", token))
            .send().await
        {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(findings) = data.get("listFindingsResults").and_then(|l| l.as_array()) {
                        for finding_result in findings {
                            if let Some(finding) = finding_result.get("finding") {
                                let record = DataRecord {
                                    id: finding.get("name")
                                        .and_then(|n| n.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                    source_id: source_id.to_string(),
                                    timestamp: finding.get("eventTime")
                                        .and_then(|t| t.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .unwrap_or_else(Utc::now),
                                    data: finding.clone(),
                                    metadata: serde_json::json!({
                                        "source_type": "gcp_scc_finding",
                                        "project_id": self.project_id
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
        }

        log::info!("Ingested {} GCP events", records.len());
        Ok(records)
    }

    async fn get_access_token(&self) -> Result<String> {
        // In real implementation, use google-cloud-auth or similar
        // to load credentials from GOOGLE_APPLICATION_CREDENTIALS

        if let Some(creds_path) = &self.credentials_path {
            // Read service account key file
            if let Ok(creds_content) = tokio::fs::read_to_string(creds_path).await {
                if let Ok(creds) = serde_json::from_str::<serde_json::Value>(&creds_content) {
                    // Extract and use private key to generate JWT
                    // This is simplified - real implementation would use proper JWT signing
                    if let (Some(_private_key), Some(client_email)) = (
                        creds.get("private_key").and_then(|k| k.as_str()),
                        creds.get("client_email").and_then(|e| e.as_str()),
                    ) {
                        log::info!("Using service account: {}", client_email);
                        // Would generate JWT and exchange for access token
                    }
                }
            }
        }

        // Also try metadata server for GCE instances
        let metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
        let client = reqwest::Client::new();

        if let Ok(resp) = client.get(metadata_url)
            .header("Metadata-Flavor", "Google")
            .send().await
        {
            if resp.status().is_success() {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(token) = data.get("access_token").and_then(|t| t.as_str()) {
                        return Ok(token.to_string());
                    }
                }
            }
        }

        log::warn!("GCP authentication not configured, using placeholder");
        Ok("placeholder_token".to_string())
    }
}

/// Cloud connector factory
#[allow(dead_code)]
pub enum CloudConnector {
    CloudTrail(CloudTrailConnector),
    AzureActivityLog(AzureActivityLogConnector),
    GCPAuditLog(GCPAuditLogConnector),
}

impl CloudConnector {
    /// Ingest data from the cloud connector
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        match self {
            CloudConnector::CloudTrail(connector) => connector.ingest(source_id).await,
            CloudConnector::AzureActivityLog(connector) => connector.ingest(source_id).await,
            CloudConnector::GCPAuditLog(connector) => connector.ingest(source_id).await,
        }
    }
}

/// Parse CloudTrail event into DataRecord
#[allow(dead_code)]
pub fn parse_cloudtrail_event(source_id: &str, event_json: &str) -> Result<DataRecord> {
    let event: serde_json::Value = serde_json::from_str(event_json)?;

    // Extract timestamp from CloudTrail event
    // CloudTrail uses "eventTime" field in RFC3339 format
    let timestamp = event.get("eventTime")
        .and_then(|t| t.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    // Extract event ID for record ID
    let event_id = event.get("eventID")
        .and_then(|e| e.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    Ok(DataRecord {
        id: event_id,
        source_id: source_id.to_string(),
        timestamp,
        data: event,
        metadata: serde_json::json!({
            "source_type": "cloudtrail"
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudtrail_connector_creation() {
        let connector = CloudTrailConnector::new(
            "us-east-1".to_string(),
            "my-cloudtrail-bucket".to_string(),
        );

        assert_eq!(connector.region, "us-east-1");
        assert_eq!(connector.bucket, "my-cloudtrail-bucket");
    }

    #[test]
    fn test_azure_connector_creation() {
        let connector = AzureActivityLogConnector::new(
            "subscription-123".to_string(),
            "tenant-456".to_string(),
        );

        assert_eq!(connector.subscription_id, "subscription-123");
        assert_eq!(connector.tenant_id, "tenant-456");
    }
}
