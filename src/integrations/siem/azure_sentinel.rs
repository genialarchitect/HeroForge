//! Azure Sentinel (Microsoft Sentinel) Integration
//!
//! Provides integration with Microsoft Sentinel SIEM:
//! - Log Analytics Data Collector API
//! - Custom log ingestion
//! - Incident management
//! - Hunting queries (KQL)

use super::{SiemEvent, SiemExporter};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Azure Sentinel exporter
pub struct AzureSentinelExporter {
    client: Client,
    config: SentinelConfig,
    token: Arc<RwLock<Option<TokenInfo>>>,
}

/// Sentinel configuration
#[derive(Debug, Clone)]
pub struct SentinelConfig {
    /// Log Analytics Workspace ID
    pub workspace_id: String,
    /// Log Analytics Primary Key (for Data Collector API)
    pub shared_key: String,
    /// Custom log table name
    pub log_type: String,
    /// Azure AD credentials for Sentinel API (optional)
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl SentinelConfig {
    pub fn new(workspace_id: String, shared_key: String) -> Self {
        Self {
            workspace_id,
            shared_key,
            log_type: "HeroForge".to_string(),
            tenant_id: None,
            client_id: None,
            client_secret: None,
        }
    }

    pub fn with_log_type(mut self, log_type: String) -> Self {
        self.log_type = log_type;
        self
    }

    pub fn with_aad_credentials(mut self, tenant_id: String, client_id: String, client_secret: String) -> Self {
        self.tenant_id = Some(tenant_id);
        self.client_id = Some(client_id);
        self.client_secret = Some(client_secret);
        self
    }
}

/// Azure AD token info
#[derive(Debug, Clone)]
struct TokenInfo {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl AzureSentinelExporter {
    /// Create new Sentinel exporter
    pub fn new(config: SentinelConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            config,
            token: Arc::new(RwLock::new(None)),
        })
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self> {
        let workspace_id = std::env::var("SENTINEL_WORKSPACE_ID")
            .map_err(|_| anyhow!("SENTINEL_WORKSPACE_ID not set"))?;
        let shared_key = std::env::var("SENTINEL_SHARED_KEY")
            .map_err(|_| anyhow!("SENTINEL_SHARED_KEY not set"))?;

        let mut config = SentinelConfig::new(workspace_id, shared_key);

        if let Ok(log_type) = std::env::var("SENTINEL_LOG_TYPE") {
            config = config.with_log_type(log_type);
        }

        if let (Ok(tenant_id), Ok(client_id), Ok(client_secret)) = (
            std::env::var("AZURE_TENANT_ID"),
            std::env::var("AZURE_CLIENT_ID"),
            std::env::var("AZURE_CLIENT_SECRET"),
        ) {
            config = config.with_aad_credentials(tenant_id, client_id, client_secret);
        }

        Self::new(config)
    }

    /// Build the authorization signature for Data Collector API
    fn build_signature(&self, date: &str, content_length: usize) -> Result<String> {
        let string_to_hash = format!(
            "POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs",
            content_length, date
        );

        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&self.config.shared_key)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)?;
        mac.update(string_to_hash.as_bytes());
        let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        Ok(format!("SharedKey {}:{}", self.config.workspace_id, signature))
    }

    /// Send logs using Data Collector API
    async fn send_logs(&self, events: &[SentinelLog]) -> Result<()> {
        let url = format!(
            "https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            self.config.workspace_id
        );

        let body = serde_json::to_string(events)?;
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let authorization = self.build_signature(&date, body.len())?;

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Log-Type", &self.config.log_type)
            .header("x-ms-date", &date)
            .header("Authorization", authorization)
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Sentinel API error: {} - {}", status, body));
        }

        info!("Sent {} events to Azure Sentinel", events.len());
        Ok(())
    }

    /// Convert SiemEvent to Sentinel log format
    fn convert_event(&self, event: &SiemEvent) -> SentinelLog {
        SentinelLog {
            timestamp: event.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            severity: event.severity.clone(),
            event_type: event.event_type.clone(),
            source_ip: event.source_ip.clone(),
            destination_ip: event.destination_ip.clone(),
            port: event.port,
            protocol: event.protocol.clone(),
            message: event.message.clone(),
            cve_ids: event.cve_ids.join(","),
            cvss_score: event.cvss_score,
            scan_id: event.scan_id.clone(),
            user_id: event.user_id.clone(),
            details: event.details.to_string(),
        }
    }

    /// Get AAD token for Sentinel API (for incidents, hunting, etc.)
    async fn get_token(&self) -> Result<String> {
        let tenant_id = self.config.tenant_id.as_ref()
            .ok_or_else(|| anyhow!("Azure AD credentials not configured"))?;
        let client_id = self.config.client_id.as_ref()
            .ok_or_else(|| anyhow!("Azure AD credentials not configured"))?;
        let client_secret = self.config.client_secret.as_ref()
            .ok_or_else(|| anyhow!("Azure AD credentials not configured"))?;

        {
            let token = self.token.read().await;
            if let Some(ref t) = *token {
                if t.expires_at > Utc::now() + Duration::seconds(300) {
                    return Ok(t.access_token.clone());
                }
            }
        }

        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );

        let params = [
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("scope", "https://management.azure.com/.default"),
            ("grant_type", "client_credentials"),
        ];

        let response = self.client
            .post(&url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("AAD token request failed: {} - {}", status, body));
        }

        let token_response: AadTokenResponse = response.json().await?;

        let token_info = TokenInfo {
            access_token: token_response.access_token.clone(),
            expires_at: Utc::now() + Duration::seconds(token_response.expires_in as i64),
        };

        {
            let mut token = self.token.write().await;
            *token = Some(token_info);
        }

        Ok(token_response.access_token)
    }

    /// Create an incident in Sentinel
    pub async fn create_incident(&self, incident: &SentinelIncident) -> Result<String> {
        let subscription_id = std::env::var("AZURE_SUBSCRIPTION_ID")
            .map_err(|_| anyhow!("AZURE_SUBSCRIPTION_ID not set"))?;
        let resource_group = std::env::var("SENTINEL_RESOURCE_GROUP")
            .map_err(|_| anyhow!("SENTINEL_RESOURCE_GROUP not set"))?;
        let workspace_name = std::env::var("SENTINEL_WORKSPACE_NAME")
            .map_err(|_| anyhow!("SENTINEL_WORKSPACE_NAME not set"))?;

        let incident_id = uuid::Uuid::new_v4().to_string();
        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights/incidents/{}?api-version=2023-02-01",
            subscription_id, resource_group, workspace_name, incident_id
        );

        let token = self.get_token().await?;

        let response = self.client
            .put(&url)
            .bearer_auth(&token)
            .json(incident)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to create incident: {} - {}", status, body));
        }

        info!("Created Sentinel incident: {}", incident_id);
        Ok(incident_id)
    }

    /// Run a hunting query
    pub async fn run_hunting_query(&self, query: &str) -> Result<Vec<serde_json::Value>> {
        let token = self.get_token().await?;

        let url = format!(
            "https://api.loganalytics.io/v1/workspaces/{}/query",
            self.config.workspace_id
        );

        let body = serde_json::json!({ "query": query });

        let response = self.client
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Query failed: {} - {}", status, body));
        }

        let result: serde_json::Value = response.json().await?;

        // Parse result tables
        let tables = result.get("tables")
            .and_then(|t| t.as_array())
            .ok_or_else(|| anyhow!("Invalid query response"))?;

        let mut results = Vec::new();
        for table in tables {
            let columns = table.get("columns")
                .and_then(|c| c.as_array())
                .ok_or_else(|| anyhow!("Invalid table format"))?;
            let rows = table.get("rows")
                .and_then(|r| r.as_array())
                .ok_or_else(|| anyhow!("Invalid table format"))?;

            let column_names: Vec<String> = columns.iter()
                .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect();

            for row in rows {
                if let Some(row_array) = row.as_array() {
                    let mut row_obj = serde_json::Map::new();
                    for (i, value) in row_array.iter().enumerate() {
                        if i < column_names.len() {
                            row_obj.insert(column_names[i].clone(), value.clone());
                        }
                    }
                    results.push(serde_json::Value::Object(row_obj));
                }
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl SiemExporter for AzureSentinelExporter {
    async fn export_event(&self, event: &SiemEvent) -> Result<()> {
        let log = self.convert_event(event);
        self.send_logs(&[log]).await
    }

    async fn export_events(&self, events: &[SiemEvent]) -> Result<()> {
        let logs: Vec<SentinelLog> = events.iter()
            .map(|e| self.convert_event(e))
            .collect();
        self.send_logs(&logs).await
    }

    async fn test_connection(&self) -> Result<()> {
        // Send a test event
        let test_event = SentinelLog {
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            severity: "Informational".to_string(),
            event_type: "test".to_string(),
            source_ip: None,
            destination_ip: None,
            port: None,
            protocol: None,
            message: "HeroForge connection test".to_string(),
            cve_ids: String::new(),
            cvss_score: None,
            scan_id: "test".to_string(),
            user_id: "system".to_string(),
            details: "{}".to_string(),
        };
        self.send_logs(&[test_event]).await
    }
}

// =============================================================================
// Sentinel API Types
// =============================================================================

#[derive(Debug, Serialize)]
struct SentinelLog {
    #[serde(rename = "TimeGenerated")]
    timestamp: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "EventType")]
    event_type: String,
    #[serde(rename = "SourceIP")]
    source_ip: Option<String>,
    #[serde(rename = "DestinationIP")]
    destination_ip: Option<String>,
    #[serde(rename = "Port")]
    port: Option<u16>,
    #[serde(rename = "Protocol")]
    protocol: Option<String>,
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "CVEIDs")]
    cve_ids: String,
    #[serde(rename = "CVSSScore")]
    cvss_score: Option<f32>,
    #[serde(rename = "ScanID")]
    scan_id: String,
    #[serde(rename = "UserID")]
    user_id: String,
    #[serde(rename = "Details")]
    details: String,
}

#[derive(Debug, Deserialize)]
struct AadTokenResponse {
    access_token: String,
    expires_in: u32,
    token_type: String,
}

/// Sentinel incident for creation
#[derive(Debug, Serialize)]
pub struct SentinelIncident {
    pub properties: SentinelIncidentProperties,
}

#[derive(Debug, Serialize)]
pub struct SentinelIncidentProperties {
    pub title: String,
    pub description: String,
    pub severity: String, // High, Medium, Low, Informational
    pub status: String,   // New, Active, Closed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<SentinelOwner>,
}

#[derive(Debug, Serialize)]
pub struct SentinelOwner {
    #[serde(rename = "objectId")]
    pub object_id: String,
    #[serde(rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = SentinelConfig::new(
            "workspace123".to_string(),
            "key456".to_string(),
        );
        assert_eq!(config.workspace_id, "workspace123");
        assert_eq!(config.log_type, "HeroForge");
    }

    #[test]
    fn test_config_with_options() {
        let config = SentinelConfig::new("ws".to_string(), "key".to_string())
            .with_log_type("CustomLog".to_string())
            .with_aad_credentials(
                "tenant".to_string(),
                "client".to_string(),
                "secret".to_string(),
            );

        assert_eq!(config.log_type, "CustomLog");
        assert_eq!(config.tenant_id, Some("tenant".to_string()));
    }
}
