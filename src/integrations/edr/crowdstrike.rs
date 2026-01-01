//! CrowdStrike Falcon EDR Integration
//!
//! Provides integration with CrowdStrike Falcon platform:
//! - OAuth2 authentication with automatic token refresh
//! - Detection and alert management
//! - Real-Time Response (RTR) commands
//! - IOC management
//! - Threat graph queries
//! - Host management

use super::{
    ActionResult, AlertSeverity, AlertStatus, EdrAlert, EdrConnector, EdrEndpoint, EdrIoc,
    EdrPlatform, EndpointStatus, HuntingQuery, HuntingResult, IocType, ResponseAction, TimeRange,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use log::{debug, error, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

const DEFAULT_API_BASE: &str = "https://api.crowdstrike.com";
const TOKEN_REFRESH_MARGIN_SECS: i64 = 300; // Refresh 5 minutes before expiry

/// CrowdStrike Falcon client
pub struct CrowdStrikeClient {
    client: Client,
    config: CrowdStrikeConfig,
    token: Arc<RwLock<Option<TokenInfo>>>,
}

/// CrowdStrike configuration
#[derive(Debug, Clone)]
pub struct CrowdStrikeConfig {
    pub client_id: String,
    pub client_secret: String,
    pub api_base: String,
    pub member_cid: Option<String>, // For MSSP multi-tenant
}

impl CrowdStrikeConfig {
    pub fn new(client_id: String, client_secret: String) -> Self {
        Self {
            client_id,
            client_secret,
            api_base: DEFAULT_API_BASE.to_string(),
            member_cid: None,
        }
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.api_base = base_url;
        self
    }

    pub fn with_member_cid(mut self, cid: String) -> Self {
        self.member_cid = Some(cid);
        self
    }
}

/// OAuth2 token information
#[derive(Debug, Clone)]
struct TokenInfo {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl CrowdStrikeClient {
    /// Create a new CrowdStrike client
    pub fn new(config: CrowdStrikeConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("HeroForge/0.2.0")
            .build()?;

        Ok(Self {
            client,
            config,
            token: Arc::new(RwLock::new(None)),
        })
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self> {
        let client_id = std::env::var("CROWDSTRIKE_CLIENT_ID")
            .map_err(|_| anyhow!("CROWDSTRIKE_CLIENT_ID not set"))?;
        let client_secret = std::env::var("CROWDSTRIKE_CLIENT_SECRET")
            .map_err(|_| anyhow!("CROWDSTRIKE_CLIENT_SECRET not set"))?;

        let mut config = CrowdStrikeConfig::new(client_id, client_secret);

        if let Ok(base_url) = std::env::var("CROWDSTRIKE_API_BASE") {
            config = config.with_base_url(base_url);
        }

        if let Ok(member_cid) = std::env::var("CROWDSTRIKE_MEMBER_CID") {
            config = config.with_member_cid(member_cid);
        }

        Self::new(config)
    }

    /// Get a valid access token, refreshing if necessary
    async fn get_token(&self) -> Result<String> {
        // Check if current token is still valid
        {
            let token = self.token.read().await;
            if let Some(ref t) = *token {
                if t.expires_at > Utc::now() + Duration::seconds(TOKEN_REFRESH_MARGIN_SECS) {
                    return Ok(t.access_token.clone());
                }
            }
        }

        // Need to refresh token
        self.refresh_token().await
    }

    /// Refresh the OAuth2 token
    async fn refresh_token(&self) -> Result<String> {
        let url = format!("{}/oauth2/token", self.config.api_base);

        let mut params = vec![
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];

        if let Some(ref member_cid) = self.config.member_cid {
            params.push(("member_cid", member_cid.as_str()));
        }

        let response = self.client
            .post(&url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("OAuth2 token request failed: {} - {}", status, body));
        }

        let token_response: TokenResponse = response.json().await?;

        let token_info = TokenInfo {
            access_token: token_response.access_token.clone(),
            expires_at: Utc::now() + Duration::seconds(token_response.expires_in as i64),
        };

        {
            let mut token = self.token.write().await;
            *token = Some(token_info);
        }

        info!("CrowdStrike OAuth2 token refreshed");
        Ok(token_response.access_token)
    }

    /// Make an authenticated GET request
    async fn get<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<T> {
        let token = self.get_token().await?;
        let url = format!("{}{}", self.config.api_base, endpoint);

        let response = self.client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("CrowdStrike API error: {} - {}", status, body));
        }

        Ok(response.json().await?)
    }

    /// Make an authenticated POST request
    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(&self, endpoint: &str, body: &B) -> Result<T> {
        let token = self.get_token().await?;
        let url = format!("{}{}", self.config.api_base, endpoint);

        let response = self.client
            .post(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("CrowdStrike API error: {} - {}", status, body));
        }

        Ok(response.json().await?)
    }

    /// Convert CrowdStrike detection to common EdrAlert
    fn convert_detection(&self, detection: &CsDetection) -> EdrAlert {
        EdrAlert {
            id: detection.detection_id.clone(),
            platform: EdrPlatform::CrowdStrike,
            severity: AlertSeverity::from_crowdstrike(&detection.max_severity_displayname),
            title: detection.behaviors.first()
                .map(|b| b.scenario.clone())
                .unwrap_or_else(|| "Unknown".to_string()),
            description: detection.behaviors.first()
                .map(|b| b.description.clone().unwrap_or_default())
                .unwrap_or_default(),
            hostname: detection.device.hostname.clone().unwrap_or_default(),
            username: detection.behaviors.first()
                .and_then(|b| b.user_name.clone()),
            ip_address: detection.device.local_ip.clone(),
            process_name: detection.behaviors.first()
                .and_then(|b| b.filename.clone()),
            process_path: detection.behaviors.first()
                .and_then(|b| b.filepath.clone()),
            command_line: detection.behaviors.first()
                .and_then(|b| b.cmdline.clone()),
            parent_process: detection.behaviors.first()
                .and_then(|b| b.parent_details.as_ref())
                .and_then(|p| p.parent_cmdline.clone()),
            file_hash: detection.behaviors.first()
                .and_then(|b| b.sha256.clone()),
            mitre_tactics: detection.behaviors.iter()
                .filter_map(|b| b.tactic.clone())
                .collect(),
            mitre_techniques: detection.behaviors.iter()
                .filter_map(|b| b.technique.clone())
                .collect(),
            status: self.convert_status(&detection.status),
            created_at: DateTime::parse_from_rfc3339(&detection.first_behavior)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&detection.last_behavior)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            raw_data: serde_json::to_value(detection).unwrap_or_default(),
        }
    }

    fn convert_status(&self, status: &str) -> AlertStatus {
        match status.to_lowercase().as_str() {
            "new" => AlertStatus::New,
            "in_progress" => AlertStatus::InProgress,
            "true_positive" | "closed" => AlertStatus::Resolved,
            "false_positive" => AlertStatus::FalsePositive,
            "ignored" => AlertStatus::Ignored,
            _ => AlertStatus::New,
        }
    }

    /// Convert CrowdStrike device to common EdrEndpoint
    fn convert_device(&self, device: &CsDevice) -> EdrEndpoint {
        EdrEndpoint {
            id: device.device_id.clone(),
            platform: EdrPlatform::CrowdStrike,
            hostname: device.hostname.clone().unwrap_or_default(),
            ip_addresses: vec![
                device.local_ip.clone(),
                device.external_ip.clone(),
            ].into_iter().flatten().collect(),
            mac_addresses: device.mac_address.clone().map(|m| vec![m]).unwrap_or_default(),
            os_name: device.platform_name.clone().unwrap_or_default(),
            os_version: device.os_version.clone().unwrap_or_default(),
            agent_version: device.agent_version.clone().unwrap_or_default(),
            last_seen: DateTime::parse_from_rfc3339(&device.last_seen.clone().unwrap_or_default())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            status: self.convert_device_status(&device.status.clone().unwrap_or_default()),
            groups: device.groups.clone().unwrap_or_default(),
            tags: device.tags.clone().unwrap_or_default(),
            is_online: device.status.as_deref() == Some("normal"),
        }
    }

    fn convert_device_status(&self, status: &str) -> EndpointStatus {
        match status.to_lowercase().as_str() {
            "normal" => EndpointStatus::Online,
            "contained" => EndpointStatus::Isolated,
            "containment_pending" => EndpointStatus::Isolated,
            "lift_containment_pending" => EndpointStatus::Degraded,
            _ => EndpointStatus::Offline,
        }
    }
}

#[async_trait]
impl EdrConnector for CrowdStrikeClient {
    fn platform(&self) -> EdrPlatform {
        EdrPlatform::CrowdStrike
    }

    async fn test_connection(&self) -> Result<bool> {
        // Try to get a token to verify credentials
        self.get_token().await?;
        Ok(true)
    }

    async fn get_alerts(&self, since: DateTime<Utc>, limit: u32) -> Result<Vec<EdrAlert>> {
        let filter = format!("first_behavior:>='{}'", since.format("%Y-%m-%dT%H:%M:%SZ"));
        let endpoint = format!("/detects/queries/detects/v1?filter={}&limit={}",
            urlencoding::encode(&filter), limit);

        let ids_response: CsIdsResponse = self.get(&endpoint).await?;

        if ids_response.resources.is_empty() {
            return Ok(Vec::new());
        }

        // Get detection details
        let details_endpoint = "/detects/entities/summaries/GET/v1";
        let details_request = CsIdsRequest { ids: ids_response.resources };
        let details_response: CsDetectionsResponse = self.post(details_endpoint, &details_request).await?;

        Ok(details_response.resources.iter()
            .map(|d| self.convert_detection(d))
            .collect())
    }

    async fn get_alert(&self, alert_id: &str) -> Result<EdrAlert> {
        let endpoint = "/detects/entities/summaries/GET/v1";
        let request = CsIdsRequest { ids: vec![alert_id.to_string()] };
        let response: CsDetectionsResponse = self.post(endpoint, &request).await?;

        response.resources.first()
            .map(|d| self.convert_detection(d))
            .ok_or_else(|| anyhow!("Detection not found"))
    }

    async fn update_alert_status(&self, alert_id: &str, status: AlertStatus) -> Result<()> {
        let cs_status = match status {
            AlertStatus::New => "new",
            AlertStatus::InProgress => "in_progress",
            AlertStatus::Resolved => "true_positive",
            AlertStatus::FalsePositive => "false_positive",
            AlertStatus::Ignored => "ignored",
        };

        let endpoint = "/detects/entities/detects/v2";
        let request = CsUpdateRequest {
            ids: vec![alert_id.to_string()],
            status: Some(cs_status.to_string()),
            comment: None,
            assigned_to_uuid: None,
        };

        let _: serde_json::Value = self.post(endpoint, &request).await?;
        Ok(())
    }

    async fn get_endpoints(&self, limit: u32, offset: u32) -> Result<Vec<EdrEndpoint>> {
        let endpoint = format!("/devices/queries/devices/v1?limit={}&offset={}", limit, offset);
        let ids_response: CsIdsResponse = self.get(&endpoint).await?;

        if ids_response.resources.is_empty() {
            return Ok(Vec::new());
        }

        let details_endpoint = "/devices/entities/devices/v2";
        let details_request = CsIdsRequest { ids: ids_response.resources };
        let details_response: CsDevicesResponse = self.post(details_endpoint, &details_request).await?;

        Ok(details_response.resources.iter()
            .map(|d| self.convert_device(d))
            .collect())
    }

    async fn get_endpoint(&self, endpoint_id: &str) -> Result<EdrEndpoint> {
        let endpoint = "/devices/entities/devices/v2";
        let request = CsIdsRequest { ids: vec![endpoint_id.to_string()] };
        let response: CsDevicesResponse = self.post(endpoint, &request).await?;

        response.resources.first()
            .map(|d| self.convert_device(d))
            .ok_or_else(|| anyhow!("Device not found"))
    }

    async fn search_endpoints(&self, query: &str) -> Result<Vec<EdrEndpoint>> {
        let filter = format!("hostname:*'{}*'", query);
        let endpoint = format!("/devices/queries/devices/v1?filter={}&limit=100",
            urlencoding::encode(&filter));

        let ids_response: CsIdsResponse = self.get(&endpoint).await?;

        if ids_response.resources.is_empty() {
            return Ok(Vec::new());
        }

        let details_endpoint = "/devices/entities/devices/v2";
        let details_request = CsIdsRequest { ids: ids_response.resources };
        let details_response: CsDevicesResponse = self.post(details_endpoint, &details_request).await?;

        Ok(details_response.resources.iter()
            .map(|d| self.convert_device(d))
            .collect())
    }

    async fn push_iocs(&self, iocs: &[EdrIoc]) -> Result<u32> {
        let cs_iocs: Vec<CsIocCreate> = iocs.iter()
            .map(|ioc| CsIocCreate {
                ioc_type: match ioc.ioc_type {
                    IocType::Sha256 => "sha256",
                    IocType::Md5 => "md5",
                    IocType::Domain => "domain",
                    IocType::IpAddress => "ipv4",
                    _ => "sha256",
                }.to_string(),
                value: ioc.value.clone(),
                action: "detect".to_string(),
                platforms: vec!["windows".to_string(), "mac".to_string(), "linux".to_string()],
                severity: match ioc.severity {
                    AlertSeverity::Critical => "critical",
                    AlertSeverity::High => "high",
                    AlertSeverity::Medium => "medium",
                    AlertSeverity::Low => "low",
                    AlertSeverity::Informational => "informational",
                }.to_string(),
                description: ioc.description.clone(),
                tags: Some(ioc.tags.clone()),
                expiration: ioc.expiration.map(|e| e.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                source: Some(ioc.source.clone()),
                applied_globally: Some(true),
            })
            .collect();

        let endpoint = "/iocs/entities/indicators/v1";
        let request = CsIocCreateRequest { indicators: cs_iocs };
        let _: serde_json::Value = self.post(endpoint, &request).await?;

        Ok(iocs.len() as u32)
    }

    async fn execute_action(&self, endpoint_id: &str, action: ResponseAction) -> Result<ActionResult> {
        let (endpoint, body): (&str, serde_json::Value) = match action {
            ResponseAction::Isolate => (
                "/devices/entities/devices-actions/v2?action_name=contain",
                serde_json::json!({ "ids": [endpoint_id] }),
            ),
            ResponseAction::Unisolate => (
                "/devices/entities/devices-actions/v2?action_name=lift_containment",
                serde_json::json!({ "ids": [endpoint_id] }),
            ),
            _ => return Err(anyhow!("Action {:?} not supported for CrowdStrike", action)),
        };

        let token = self.get_token().await?;
        let url = format!("{}{}", self.config.api_base, endpoint);

        let response = self.client
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        let success = response.status().is_success();
        let message = if success {
            format!("Action {:?} executed successfully", action)
        } else {
            response.text().await.unwrap_or_else(|_| "Unknown error".to_string())
        };

        Ok(ActionResult {
            action,
            target: endpoint_id.to_string(),
            success,
            message,
            timestamp: Utc::now(),
        })
    }

    async fn hunt(&self, query: &HuntingQuery) -> Result<HuntingResult> {
        let start = std::time::Instant::now();

        // Use Event Search API
        let endpoint = "/threatgraph/combined/ran-on/v1";
        let filter = format!(
            "timestamp:>='{}'+timestamp:<='{}'+{}",
            query.time_range.start.format("%Y-%m-%dT%H:%M:%SZ"),
            query.time_range.end.format("%Y-%m-%dT%H:%M:%SZ"),
            query.query
        );

        let search_endpoint = format!("{}?filter={}&limit=1000", endpoint, urlencoding::encode(&filter));

        let response: serde_json::Value = self.get(&search_endpoint).await?;

        let results = response.get("resources")
            .and_then(|r| r.as_array())
            .map(|a| a.to_vec())
            .unwrap_or_default();

        Ok(HuntingResult {
            query_name: query.name.clone(),
            platform: EdrPlatform::CrowdStrike,
            total_results: results.len() as u64,
            results,
            execution_time_ms: start.elapsed().as_millis() as u64,
            executed_at: Utc::now(),
        })
    }
}

// =============================================================================
// CrowdStrike API Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u32,
    token_type: String,
}

#[derive(Debug, Serialize)]
struct CsIdsRequest {
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CsIdsResponse {
    resources: Vec<String>,
    #[allow(dead_code)]
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct CsDetectionsResponse {
    resources: Vec<CsDetection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsDetection {
    detection_id: String,
    status: String,
    max_severity: u32,
    max_severity_displayname: String,
    first_behavior: String,
    last_behavior: String,
    device: CsDetectionDevice,
    behaviors: Vec<CsBehavior>,
    #[serde(default)]
    quarantined_files: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsDetectionDevice {
    device_id: String,
    hostname: Option<String>,
    local_ip: Option<String>,
    external_ip: Option<String>,
    machine_domain: Option<String>,
    platform_name: Option<String>,
    os_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsBehavior {
    behavior_id: String,
    scenario: String,
    severity: u32,
    confidence: u32,
    description: Option<String>,
    filename: Option<String>,
    filepath: Option<String>,
    cmdline: Option<String>,
    sha256: Option<String>,
    user_name: Option<String>,
    tactic: Option<String>,
    technique: Option<String>,
    parent_details: Option<CsParentDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsParentDetails {
    parent_sha256: Option<String>,
    parent_cmdline: Option<String>,
    parent_process_graph_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CsUpdateRequest {
    ids: Vec<String>,
    status: Option<String>,
    comment: Option<String>,
    assigned_to_uuid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CsDevicesResponse {
    resources: Vec<CsDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CsDevice {
    device_id: String,
    hostname: Option<String>,
    local_ip: Option<String>,
    external_ip: Option<String>,
    mac_address: Option<String>,
    platform_name: Option<String>,
    os_version: Option<String>,
    agent_version: Option<String>,
    last_seen: Option<String>,
    first_seen: Option<String>,
    status: Option<String>,
    groups: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    machine_domain: Option<String>,
}

#[derive(Debug, Serialize)]
struct CsIocCreateRequest {
    indicators: Vec<CsIocCreate>,
}

#[derive(Debug, Serialize)]
struct CsIocCreate {
    #[serde(rename = "type")]
    ioc_type: String,
    value: String,
    action: String,
    platforms: Vec<String>,
    severity: String,
    description: Option<String>,
    tags: Option<Vec<String>>,
    expiration: Option<String>,
    source: Option<String>,
    applied_globally: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = CrowdStrikeConfig::new(
            "test_id".to_string(),
            "test_secret".to_string(),
        );
        assert_eq!(config.api_base, DEFAULT_API_BASE);
        assert!(config.member_cid.is_none());
    }

    #[test]
    fn test_config_with_options() {
        let config = CrowdStrikeConfig::new("id".to_string(), "secret".to_string())
            .with_base_url("https://custom.api.com".to_string())
            .with_member_cid("member123".to_string());

        assert_eq!(config.api_base, "https://custom.api.com");
        assert_eq!(config.member_cid, Some("member123".to_string()));
    }
}
