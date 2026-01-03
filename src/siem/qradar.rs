//! IBM QRadar SIEM integration
//!
//! This module provides integration with IBM QRadar SIEM, enabling:
//! - Event forwarding to QRadar via REST API
//! - Offense creation and management
//! - Bidirectional alert synchronization
//!
//! # Configuration
//!
//! QRadar integration requires:
//! - QRadar Console URL (e.g., https://qradar.example.com)
//! - SEC Token for API authentication
//! - Optional: Custom event mapping for field normalization
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use heroforge::siem::qradar::{QRadarIntegration, QRadarConfig};
//!
//! let config = QRadarConfig {
//!     base_url: "https://qradar.example.com".to_string(),
//!     sec_token: "your-sec-token".to_string(),
//!     ..Default::default()
//! };
//!
//! let qradar = QRadarIntegration::new(config)?;
//! qradar.send_event(&event).await?;
//! ```

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// QRadar integration configuration
#[derive(Debug, Clone)]
pub struct QRadarConfig {
    /// QRadar Console base URL
    pub base_url: String,
    /// SEC Token for API authentication
    pub sec_token: String,
    /// API version (default: 15.1)
    pub api_version: String,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Whether to verify SSL certificates
    pub verify_ssl: bool,
    /// Log source identifier for events
    pub log_source_id: Option<i64>,
    /// Custom field mappings
    pub field_mappings: HashMap<String, String>,
    /// Rate limit (requests per minute)
    pub rate_limit_rpm: u32,
    /// Batch size for bulk operations
    pub batch_size: usize,
}

impl Default for QRadarConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            sec_token: String::new(),
            api_version: "15.1".to_string(),
            timeout_secs: 30,
            verify_ssl: true,
            log_source_id: None,
            field_mappings: HashMap::new(),
            rate_limit_rpm: 60,
            batch_size: 100,
        }
    }
}

/// QRadar offense status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OffenseStatus {
    Open,
    Hidden,
    Closed,
}

impl OffenseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Hidden => "HIDDEN",
            Self::Closed => "CLOSED",
        }
    }
}

/// QRadar offense closing reason
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClosingReason {
    FalsePositive,
    NonIssue,
    PolicyViolation,
}

impl ClosingReason {
    pub fn id(&self) -> i32 {
        match self {
            Self::FalsePositive => 1,
            Self::NonIssue => 2,
            Self::PolicyViolation => 3,
        }
    }
}

/// QRadar offense details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QRadarOffense {
    pub id: i64,
    pub description: String,
    pub assigned_to: Option<String>,
    pub categories: Vec<String>,
    pub category_count: i32,
    pub close_time: Option<i64>,
    pub closing_reason_id: Option<i32>,
    pub closing_user: Option<String>,
    pub credibility: i32,
    pub destination_networks: Vec<String>,
    pub device_count: i32,
    pub domain_id: i32,
    pub event_count: i64,
    pub flow_count: i64,
    pub follow_up: bool,
    pub inactive: bool,
    pub last_updated_time: i64,
    pub local_destination_count: i32,
    pub magnitude: i32,
    pub offense_source: String,
    pub offense_type: i32,
    pub policy_category_count: i32,
    pub protected: bool,
    pub relevance: i32,
    pub remote_destination_count: i32,
    pub rules: Vec<QRadarRule>,
    pub security_category_count: i32,
    pub severity: i32,
    pub source_address_ids: Vec<i64>,
    pub source_count: i32,
    pub source_network: String,
    pub start_time: i64,
    pub status: String,
    pub username_count: i32,
}

/// QRadar rule reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QRadarRule {
    pub id: i64,
    pub r#type: String,
}

/// QRadar event for sending
#[derive(Debug, Clone, Serialize)]
pub struct QRadarEvent {
    /// Event timestamp in milliseconds since epoch
    pub timestamp: i64,
    /// Source IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Destination IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    /// Source port
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    /// Destination port
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    /// Protocol
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Event category
    pub category: String,
    /// Event severity (1-10)
    pub severity: i32,
    /// Event description/message
    pub message: String,
    /// Log source type identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_source_type_id: Option<i64>,
    /// Custom properties
    #[serde(flatten)]
    pub custom_properties: HashMap<String, serde_json::Value>,
}

impl QRadarEvent {
    /// Create a new QRadar event from a log entry
    pub fn from_log_entry(entry: &serde_json::Value) -> Self {
        let timestamp = entry.get("timestamp")
            .and_then(|t| t.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp_millis())
            .unwrap_or_else(|| Utc::now().timestamp_millis());

        Self {
            timestamp,
            source_ip: entry.get("source_ip").and_then(|v| v.as_str()).map(String::from),
            destination_ip: entry.get("destination_ip").and_then(|v| v.as_str()).map(String::from),
            source_port: entry.get("source_port").and_then(|v| v.as_u64()).map(|p| p as u16),
            destination_port: entry.get("destination_port").and_then(|v| v.as_u64()).map(|p| p as u16),
            protocol: entry.get("protocol").and_then(|v| v.as_str()).map(String::from),
            username: entry.get("user").and_then(|v| v.as_str()).map(String::from),
            category: entry.get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            severity: entry.get("severity")
                .and_then(|v| v.as_i64())
                .unwrap_or(5) as i32,
            message: entry.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            log_source_type_id: None,
            custom_properties: HashMap::new(),
        }
    }
}

/// Response from creating an offense
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOffenseResponse {
    pub id: i64,
    pub description: String,
    pub status: String,
    pub severity: i32,
    pub start_time: i64,
}

/// Syslog event for QRadar ingestion (alternative to REST API)
#[derive(Debug)]
pub struct SyslogEvent {
    pub facility: u8,
    pub severity: u8,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub application: String,
    pub message: String,
}

impl SyslogEvent {
    /// Format as RFC 5424 syslog message
    pub fn to_rfc5424(&self) -> String {
        let pri = (self.facility * 8) + self.severity;
        format!(
            "<{}>1 {} {} {} - - - {}",
            pri,
            self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            self.hostname,
            self.application,
            self.message
        )
    }

    /// Format as LEEF (Log Event Extended Format) for QRadar
    pub fn to_leef(&self) -> String {
        format!(
            "LEEF:2.0|HeroForge|SecurityScanner|1.0|{}|cat={}\tdevTime={}\tsrc={}\tmsg={}",
            self.application,
            self.application,
            self.timestamp.format("%Y-%m-%d %H:%M:%S"),
            self.hostname,
            self.message
        )
    }
}

/// QRadar API client
pub struct QRadarIntegration {
    config: QRadarConfig,
    client: Client,
}

impl QRadarIntegration {
    /// Create a new QRadar integration with default configuration (unconfigured)
    pub fn new() -> Self {
        Self {
            config: QRadarConfig::default(),
            client: Client::new(),
        }
    }

    /// Create a new QRadar integration with configuration
    pub fn with_config(config: QRadarConfig) -> Result<Self> {
        if config.base_url.is_empty() {
            return Err(anyhow!("QRadar base URL is required"));
        }
        if config.sec_token.is_empty() {
            return Err(anyhow!("QRadar SEC token is required"));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!config.verify_ssl)
            .build()?;

        Ok(Self { config, client })
    }

    /// Check if QRadar is configured
    pub fn is_configured(&self) -> bool {
        !self.config.base_url.is_empty() && !self.config.sec_token.is_empty()
    }

    /// Build the API URL for a given endpoint
    fn api_url(&self, endpoint: &str) -> String {
        format!("{}/api/{}", self.config.base_url.trim_end_matches('/'), endpoint)
    }

    /// Send an event to QRadar via REST API
    ///
    /// This uses QRadar's REST API to ingest events. Events are normalized
    /// to QRadar's expected format and sent as JSON.
    ///
    /// # Arguments
    /// * `event` - The event data as a JSON value
    ///
    /// # Returns
    /// * `Ok(())` if the event was successfully sent
    /// * `Err` if the integration is not configured or the request failed
    pub async fn send_event(&self, event: &serde_json::Value) -> Result<()> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured. Set base_url and sec_token."));
        }

        // Convert to QRadar event format
        let qradar_event = QRadarEvent::from_log_entry(event);

        // QRadar events are typically sent via syslog or the /data_classification/dsm_events endpoint
        // Using the ariel/events endpoint for custom events
        let url = self.api_url("ariel/events");

        // For bulk ingestion, QRadar prefers syslog. For REST API, we can use the reference data API
        // or custom log source. Here we'll use the reference data collection approach.
        let response = self.client
            .post(&url)
            .header("SEC", &self.config.sec_token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .json(&qradar_event)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED => {
                log::debug!("Event sent to QRadar successfully");
                Ok(())
            }
            StatusCode::UNAUTHORIZED => {
                Err(anyhow!("QRadar authentication failed: Invalid SEC token"))
            }
            StatusCode::FORBIDDEN => {
                Err(anyhow!("QRadar authorization failed: Insufficient permissions"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar API error ({}): {}", status, error_body))
            }
        }
    }

    /// Send multiple events to QRadar in batch
    ///
    /// Batches events for more efficient transmission.
    pub async fn send_events(&self, events: &[serde_json::Value]) -> Result<usize> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let mut sent = 0;

        for chunk in events.chunks(self.config.batch_size) {
            for event in chunk {
                if self.send_event(event).await.is_ok() {
                    sent += 1;
                }
            }
        }

        Ok(sent)
    }

    /// Create a QRadar offense
    ///
    /// Creates a new offense in QRadar with the specified details.
    /// Offenses are QRadar's equivalent of alerts/incidents.
    ///
    /// # Arguments
    /// * `title` - The offense description/title
    /// * `severity` - Severity level (1-10, where 10 is most severe)
    ///
    /// # Returns
    /// * `Ok(offense_id)` if the offense was created successfully
    /// * `Err` if creation failed
    pub async fn create_offense(&self, title: &str, severity: u32) -> Result<String> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured. Set base_url and sec_token."));
        }

        // QRadar doesn't have a direct "create offense" API - offenses are created by rules
        // However, we can use the custom actions or reference data to trigger offense creation
        // through a correlation rule. Here we'll use the offense closing/update API pattern
        // combined with a custom reference set that triggers an offense.

        // For a practical implementation, we'll create an entry in a reference set
        // that a QRadar rule is configured to watch and create offenses from.
        let reference_set_name = "HeroForge_Offenses";
        let url = self.api_url(&format!("reference_data/sets/{}", reference_set_name));

        // Create the offense data entry
        let offense_data = serde_json::json!({
            "value": format!("{}|{}|{}", title, severity, Utc::now().timestamp()),
        });

        let response = self.client
            .post(&url)
            .header("SEC", &self.config.sec_token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .json(&offense_data)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                // Generate a tracking ID for the offense trigger
                let offense_id = uuid::Uuid::new_v4().to_string();
                log::info!("Offense trigger sent to QRadar: {} (tracking: {})", title, offense_id);
                Ok(offense_id)
            }
            StatusCode::NOT_FOUND => {
                // Reference set doesn't exist - create it first
                self.ensure_reference_set(reference_set_name).await?;
                // Retry the offense creation
                Box::pin(self.create_offense(title, severity)).await
            }
            StatusCode::UNAUTHORIZED => {
                Err(anyhow!("QRadar authentication failed: Invalid SEC token"))
            }
            StatusCode::FORBIDDEN => {
                Err(anyhow!("QRadar authorization failed: Insufficient permissions"))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar API error ({}): {}", status, error_body))
            }
        }
    }

    /// Ensure a reference set exists for offense triggers
    async fn ensure_reference_set(&self, name: &str) -> Result<()> {
        let url = self.api_url("reference_data/sets");

        let set_data = serde_json::json!({
            "name": name,
            "element_type": "ALN", // Alphanumeric
            "time_to_live": "1 day",
            "timeout_type": "LAST_SEEN"
        });

        let response = self.client
            .post(&url)
            .header("SEC", &self.config.sec_token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .json(&set_data)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK | StatusCode::CREATED | StatusCode::CONFLICT => {
                // Created or already exists
                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("Failed to create QRadar reference set ({}): {}", status, error_body))
            }
        }
    }

    /// Get offense details by ID
    pub async fn get_offense(&self, offense_id: i64) -> Result<QRadarOffense> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let url = self.api_url(&format!("siem/offenses/{}", offense_id));

        let response = self.client
            .get(&url)
            .header("SEC", &self.config.sec_token)
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let offense = response.json::<QRadarOffense>().await?;
                Ok(offense)
            }
            StatusCode::NOT_FOUND => {
                Err(anyhow!("Offense {} not found", offense_id))
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar API error ({}): {}", status, error_body))
            }
        }
    }

    /// List offenses with optional filters
    pub async fn list_offenses(
        &self,
        status: Option<OffenseStatus>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<QRadarOffense>> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let mut url = self.api_url("siem/offenses");
        let mut params = Vec::new();

        if let Some(s) = status {
            params.push(format!("filter=status%3D{}", s.as_str()));
        }

        if let Some(l) = limit {
            params.push(format!("Range=items%3D{}-{}", offset.unwrap_or(0), offset.unwrap_or(0) + l - 1));
        }

        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let response = self.client
            .get(&url)
            .header("SEC", &self.config.sec_token)
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let offenses = response.json::<Vec<QRadarOffense>>().await?;
                Ok(offenses)
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar API error ({}): {}", status, error_body))
            }
        }
    }

    /// Update offense status
    pub async fn update_offense_status(
        &self,
        offense_id: i64,
        status: OffenseStatus,
        closing_reason: Option<ClosingReason>,
    ) -> Result<()> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let url = self.api_url(&format!("siem/offenses/{}", offense_id));

        let mut update_data = serde_json::Map::new();
        update_data.insert("status".to_string(), serde_json::Value::String(status.as_str().to_string()));

        if let Some(reason) = closing_reason {
            update_data.insert("closing_reason_id".to_string(), serde_json::Value::Number(reason.id().into()));
        }

        let response = self.client
            .post(&url)
            .header("SEC", &self.config.sec_token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .json(&serde_json::Value::Object(update_data))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                log::info!("Offense {} status updated to {}", offense_id, status.as_str());
                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar API error ({}): {}", status, error_body))
            }
        }
    }

    /// Close an offense
    pub async fn close_offense(
        &self,
        offense_id: i64,
        closing_reason: ClosingReason,
    ) -> Result<()> {
        self.update_offense_status(offense_id, OffenseStatus::Closed, Some(closing_reason)).await
    }

    /// Assign offense to a user
    pub async fn assign_offense(&self, offense_id: i64, username: &str) -> Result<()> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let url = self.api_url(&format!("siem/offenses/{}", offense_id));

        let update_data = serde_json::json!({
            "assigned_to": username
        });

        let response = self.client
            .post(&url)
            .header("SEC", &self.config.sec_token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .json(&update_data)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                log::info!("Offense {} assigned to {}", offense_id, username);
                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar API error ({}): {}", status, error_body))
            }
        }
    }

    /// Add a note to an offense
    pub async fn add_offense_note(&self, offense_id: i64, note: &str) -> Result<()> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let url = self.api_url(&format!("siem/offenses/{}/notes", offense_id));

        let note_data = serde_json::json!({
            "note_text": note
        });

        let response = self.client
            .post(&url)
            .header("SEC", &self.config.sec_token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .json(&note_data)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                log::debug!("Note added to offense {}", offense_id);
                Ok(())
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar API error ({}): {}", status, error_body))
            }
        }
    }

    /// Run an AQL search query
    pub async fn search_aql(&self, query: &str) -> Result<serde_json::Value> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let url = self.api_url("ariel/searches");

        let search_data = serde_json::json!({
            "query_expression": query
        });

        let response = self.client
            .post(&url)
            .header("SEC", &self.config.sec_token)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .json(&search_data)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK | StatusCode::CREATED => {
                let result = response.json::<serde_json::Value>().await?;
                Ok(result)
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar AQL search failed ({}): {}", status, error_body))
            }
        }
    }

    /// Get the QRadar system health status
    pub async fn get_health(&self) -> Result<serde_json::Value> {
        if !self.is_configured() {
            return Err(anyhow!("QRadar integration is not configured"));
        }

        let url = self.api_url("system/about");

        let response = self.client
            .get(&url)
            .header("SEC", &self.config.sec_token)
            .header("Accept", "application/json")
            .header("Version", &self.config.api_version)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let info = response.json::<serde_json::Value>().await?;
                Ok(info)
            }
            status => {
                let error_body = response.text().await.unwrap_or_default();
                Err(anyhow!("QRadar health check failed ({}): {}", status, error_body))
            }
        }
    }
}

impl Default for QRadarIntegration {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qradar_config_default() {
        let config = QRadarConfig::default();
        assert!(config.base_url.is_empty());
        assert!(config.sec_token.is_empty());
        assert_eq!(config.api_version, "15.1");
        assert_eq!(config.timeout_secs, 30);
        assert!(config.verify_ssl);
    }

    #[test]
    fn test_qradar_integration_unconfigured() {
        let qradar = QRadarIntegration::new();
        assert!(!qradar.is_configured());
    }

    #[test]
    fn test_qradar_event_from_log_entry() {
        let entry = serde_json::json!({
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "tcp",
            "user": "admin",
            "category": "authentication",
            "severity": 7,
            "message": "Failed login attempt"
        });

        let event = QRadarEvent::from_log_entry(&entry);
        assert_eq!(event.source_ip, Some("192.168.1.100".to_string()));
        assert_eq!(event.destination_port, Some(443));
        assert_eq!(event.username, Some("admin".to_string()));
        assert_eq!(event.category, "authentication");
        assert_eq!(event.severity, 7);
        assert_eq!(event.message, "Failed login attempt");
    }

    #[test]
    fn test_syslog_event_rfc5424() {
        let event = SyslogEvent {
            facility: 1,
            severity: 4,
            timestamp: Utc::now(),
            hostname: "testhost".to_string(),
            application: "heroforge".to_string(),
            message: "Test message".to_string(),
        };

        let formatted = event.to_rfc5424();
        assert!(formatted.starts_with("<12>")); // pri = 1*8 + 4 = 12
        assert!(formatted.contains("testhost"));
        assert!(formatted.contains("heroforge"));
        assert!(formatted.contains("Test message"));
    }

    #[test]
    fn test_syslog_event_leef() {
        let event = SyslogEvent {
            facility: 1,
            severity: 4,
            timestamp: Utc::now(),
            hostname: "testhost".to_string(),
            application: "heroforge".to_string(),
            message: "Test message".to_string(),
        };

        let formatted = event.to_leef();
        assert!(formatted.starts_with("LEEF:2.0|HeroForge|SecurityScanner|"));
        assert!(formatted.contains("src=testhost"));
        assert!(formatted.contains("msg=Test message"));
    }

    #[test]
    fn test_offense_status_as_str() {
        assert_eq!(OffenseStatus::Open.as_str(), "OPEN");
        assert_eq!(OffenseStatus::Hidden.as_str(), "HIDDEN");
        assert_eq!(OffenseStatus::Closed.as_str(), "CLOSED");
    }

    #[test]
    fn test_closing_reason_id() {
        assert_eq!(ClosingReason::FalsePositive.id(), 1);
        assert_eq!(ClosingReason::NonIssue.id(), 2);
        assert_eq!(ClosingReason::PolicyViolation.id(), 3);
    }
}
