//! SentinelOne EDR Integration
//!
//! Provides integration with SentinelOne platform:
//! - API token authentication
//! - Threat and alert management
//! - Endpoint management
//! - IOC management via Threat Intelligence
//! - Deep Visibility queries
//! - Response actions (isolate, scan, remediate)

use super::{
    ActionResult, AlertSeverity, AlertStatus, EdrAlert, EdrConnector, EdrEndpoint, EdrIoc,
    EdrPlatform, EndpointStatus, HuntingQuery, HuntingResult, IocType, ResponseAction,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// SentinelOne client
pub struct SentinelOneClient {
    client: Client,
    config: SentinelOneConfig,
}

/// SentinelOne configuration
#[derive(Debug, Clone)]
pub struct SentinelOneConfig {
    pub api_token: String,
    pub management_url: String,
    pub account_id: Option<String>,
    pub site_id: Option<String>,
}

impl SentinelOneConfig {
    pub fn new(api_token: String, management_url: String) -> Self {
        Self {
            api_token,
            management_url: management_url.trim_end_matches('/').to_string(),
            account_id: None,
            site_id: None,
        }
    }

    pub fn with_account_id(mut self, account_id: String) -> Self {
        self.account_id = Some(account_id);
        self
    }

    pub fn with_site_id(mut self, site_id: String) -> Self {
        self.site_id = Some(site_id);
        self
    }
}

impl SentinelOneClient {
    /// Create a new SentinelOne client
    pub fn new(config: SentinelOneConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("HeroForge/0.2.0")
            .build()?;

        Ok(Self { client, config })
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self> {
        let api_token = std::env::var("SENTINELONE_API_TOKEN")
            .map_err(|_| anyhow!("SENTINELONE_API_TOKEN not set"))?;
        let management_url = std::env::var("SENTINELONE_MANAGEMENT_URL")
            .map_err(|_| anyhow!("SENTINELONE_MANAGEMENT_URL not set"))?;

        let mut config = SentinelOneConfig::new(api_token, management_url);

        if let Ok(account_id) = std::env::var("SENTINELONE_ACCOUNT_ID") {
            config = config.with_account_id(account_id);
        }

        if let Ok(site_id) = std::env::var("SENTINELONE_SITE_ID") {
            config = config.with_site_id(site_id);
        }

        Self::new(config)
    }

    /// Make an authenticated GET request
    async fn get<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<T> {
        let url = format!("{}/web/api/v2.1{}", self.config.management_url, endpoint);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("ApiToken {}", self.config.api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("SentinelOne API error: {} - {}", status, body));
        }

        Ok(response.json().await?)
    }

    /// Make an authenticated POST request
    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(&self, endpoint: &str, body: &B) -> Result<T> {
        let url = format!("{}/web/api/v2.1{}", self.config.management_url, endpoint);

        let response = self.client
            .post(&url)
            .header("Authorization", format!("ApiToken {}", self.config.api_token))
            .json(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("SentinelOne API error: {} - {}", status, body));
        }

        Ok(response.json().await?)
    }

    /// Convert SentinelOne threat to common EdrAlert
    fn convert_threat(&self, threat: &S1Threat) -> EdrAlert {
        let agent_info = &threat.agent_realtime_info;
        let threat_info = &threat.threat_info;

        EdrAlert {
            id: threat.id.clone(),
            platform: EdrPlatform::SentinelOne,
            severity: AlertSeverity::from_sentinelone(threat_info.confidence_level.unwrap_or(50)),
            title: threat_info.threat_name.clone().unwrap_or_else(|| "Unknown Threat".to_string()),
            description: threat_info.classification.clone().unwrap_or_default(),
            hostname: agent_info.agent_computer_name.clone().unwrap_or_default(),
            username: threat_info.origin_user_name.clone(),
            ip_address: agent_info.agent_network_info.as_ref()
                .and_then(|n| n.inet.as_ref())
                .and_then(|i| i.first().cloned()),
            process_name: threat_info.origin_file_name.clone(),
            process_path: threat_info.file_path.clone(),
            command_line: threat_info.process_cmdline.clone(),
            parent_process: None,
            file_hash: threat_info.sha256.clone(),
            mitre_tactics: threat_info.mitre_info.as_ref()
                .map(|m| m.tactics.clone())
                .unwrap_or_default(),
            mitre_techniques: threat_info.mitre_info.as_ref()
                .map(|m| m.techniques.clone())
                .unwrap_or_default(),
            status: self.convert_status(&threat_info.analyst_verdict.clone().unwrap_or_default()),
            created_at: DateTime::parse_from_rfc3339(&threat_info.created_at.clone().unwrap_or_default())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&threat_info.updated_at.clone().unwrap_or_default())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            raw_data: serde_json::to_value(threat).unwrap_or_default(),
        }
    }

    fn convert_status(&self, verdict: &str) -> AlertStatus {
        match verdict.to_lowercase().as_str() {
            "undefined" => AlertStatus::New,
            "suspicious" => AlertStatus::InProgress,
            "true_positive" => AlertStatus::Resolved,
            "false_positive" => AlertStatus::FalsePositive,
            _ => AlertStatus::New,
        }
    }

    /// Convert SentinelOne agent to common EdrEndpoint
    fn convert_agent(&self, agent: &S1Agent) -> EdrEndpoint {
        EdrEndpoint {
            id: agent.id.clone(),
            platform: EdrPlatform::SentinelOne,
            hostname: agent.computer_name.clone().unwrap_or_default(),
            ip_addresses: agent.network_interfaces.as_ref()
                .map(|interfaces| interfaces.iter()
                    .filter_map(|i| i.inet.as_ref())
                    .flat_map(|inet| inet.iter().cloned())
                    .collect())
                .unwrap_or_default(),
            mac_addresses: agent.network_interfaces.as_ref()
                .map(|interfaces| interfaces.iter()
                    .filter_map(|i| i.physical.clone())
                    .collect())
                .unwrap_or_default(),
            os_name: agent.os_name.clone().unwrap_or_default(),
            os_version: agent.os_revision.clone().unwrap_or_default(),
            agent_version: agent.agent_version.clone().unwrap_or_default(),
            last_seen: DateTime::parse_from_rfc3339(&agent.last_active_date.clone().unwrap_or_default())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            status: self.convert_agent_status(&agent.network_status.clone().unwrap_or_default()),
            groups: agent.group_name.clone().map(|g| vec![g]).unwrap_or_default(),
            tags: agent.tags.as_ref()
                .map(|t| t.names.clone())
                .unwrap_or_default(),
            is_online: agent.is_active.unwrap_or(false),
        }
    }

    fn convert_agent_status(&self, status: &str) -> EndpointStatus {
        match status.to_lowercase().as_str() {
            "connected" => EndpointStatus::Online,
            "disconnected" => EndpointStatus::Offline,
            "connecting" => EndpointStatus::Degraded,
            "disconnecting" => EndpointStatus::Degraded,
            _ => EndpointStatus::Offline,
        }
    }
}

#[async_trait]
impl EdrConnector for SentinelOneClient {
    fn platform(&self) -> EdrPlatform {
        EdrPlatform::SentinelOne
    }

    async fn test_connection(&self) -> Result<bool> {
        let endpoint = "/system/status";
        let _: serde_json::Value = self.get(endpoint).await?;
        Ok(true)
    }

    async fn get_alerts(&self, since: DateTime<Utc>, limit: u32) -> Result<Vec<EdrAlert>> {
        let mut endpoint = format!(
            "/threats?createdAt__gte={}&limit={}",
            since.format("%Y-%m-%dT%H:%M:%S.000Z"),
            limit
        );

        if let Some(ref account_id) = self.config.account_id {
            endpoint.push_str(&format!("&accountIds={}", account_id));
        }
        if let Some(ref site_id) = self.config.site_id {
            endpoint.push_str(&format!("&siteIds={}", site_id));
        }

        let response: S1ThreatsResponse = self.get(&endpoint).await?;

        Ok(response.data.iter()
            .map(|t| self.convert_threat(t))
            .collect())
    }

    async fn get_alert(&self, alert_id: &str) -> Result<EdrAlert> {
        let endpoint = format!("/threats?ids={}", alert_id);
        let response: S1ThreatsResponse = self.get(&endpoint).await?;

        response.data.first()
            .map(|t| self.convert_threat(t))
            .ok_or_else(|| anyhow!("Threat not found"))
    }

    async fn update_alert_status(&self, alert_id: &str, status: AlertStatus) -> Result<()> {
        let verdict = match status {
            AlertStatus::Resolved => "true_positive",
            AlertStatus::FalsePositive => "false_positive",
            AlertStatus::Ignored => "false_positive",
            AlertStatus::InProgress => "suspicious",
            AlertStatus::New => "undefined",
        };

        let endpoint = "/threats/analyst-verdict";
        let request = S1VerdictRequest {
            filter: S1Filter {
                ids: Some(vec![alert_id.to_string()]),
            },
            data: S1VerdictData {
                analyst_verdict: verdict.to_string(),
            },
        };

        let _: serde_json::Value = self.post(endpoint, &request).await?;
        Ok(())
    }

    async fn get_endpoints(&self, limit: u32, offset: u32) -> Result<Vec<EdrEndpoint>> {
        let mut endpoint = format!("/agents?limit={}&skip={}", limit, offset);

        if let Some(ref account_id) = self.config.account_id {
            endpoint.push_str(&format!("&accountIds={}", account_id));
        }
        if let Some(ref site_id) = self.config.site_id {
            endpoint.push_str(&format!("&siteIds={}", site_id));
        }

        let response: S1AgentsResponse = self.get(&endpoint).await?;

        Ok(response.data.iter()
            .map(|a| self.convert_agent(a))
            .collect())
    }

    async fn get_endpoint(&self, endpoint_id: &str) -> Result<EdrEndpoint> {
        let endpoint = format!("/agents?ids={}", endpoint_id);
        let response: S1AgentsResponse = self.get(&endpoint).await?;

        response.data.first()
            .map(|a| self.convert_agent(a))
            .ok_or_else(|| anyhow!("Agent not found"))
    }

    async fn search_endpoints(&self, query: &str) -> Result<Vec<EdrEndpoint>> {
        let endpoint = format!("/agents?computerName__contains={}&limit=100", urlencoding::encode(query));
        let response: S1AgentsResponse = self.get(&endpoint).await?;

        Ok(response.data.iter()
            .map(|a| self.convert_agent(a))
            .collect())
    }

    async fn push_iocs(&self, iocs: &[EdrIoc]) -> Result<u32> {
        // SentinelOne uses Threat Intelligence for IOCs
        let s1_iocs: Vec<S1IocCreate> = iocs.iter()
            .map(|ioc| S1IocCreate {
                value: ioc.value.clone(),
                ioc_type: match ioc.ioc_type {
                    IocType::Sha256 => "SHA256",
                    IocType::Sha1 => "SHA1",
                    IocType::Md5 => "MD5",
                    IocType::Domain => "DNS",
                    IocType::IpAddress => "IPV4",
                    IocType::Url => "URL",
                    _ => "SHA256",
                }.to_string(),
                method: "EQUALS".to_string(),
                source: Some(ioc.source.clone()),
                description: ioc.description.clone(),
                external_id: None,
                valid_until: ioc.expiration.map(|e| e.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()),
            })
            .collect();

        let endpoint = "/threat-intelligence/iocs";
        let request = S1IocCreateRequest { data: s1_iocs };

        let _: serde_json::Value = self.post(endpoint, &request).await?;
        Ok(iocs.len() as u32)
    }

    async fn execute_action(&self, endpoint_id: &str, action: ResponseAction) -> Result<ActionResult> {
        let (endpoint_path, action_name) = match action {
            ResponseAction::Isolate => ("/agents/actions/disconnect", "disconnect"),
            ResponseAction::Unisolate => ("/agents/actions/connect", "connect"),
            ResponseAction::Scan => ("/agents/actions/initiate-scan", "initiate-scan"),
            ResponseAction::Kill => ("/agents/actions/abort-scan", "abort-scan"),
            _ => return Err(anyhow!("Action {:?} not supported for SentinelOne", action)),
        };

        let request = S1ActionRequest {
            filter: S1Filter {
                ids: Some(vec![endpoint_id.to_string()]),
            },
            data: serde_json::json!({}),
        };

        let response: S1ActionResponse = self.post(endpoint_path, &request).await?;

        Ok(ActionResult {
            action,
            target: endpoint_id.to_string(),
            success: response.data.affected > 0,
            message: format!("{} agents affected", response.data.affected),
            timestamp: Utc::now(),
        })
    }

    async fn hunt(&self, query: &HuntingQuery) -> Result<HuntingResult> {
        let start = std::time::Instant::now();

        // Use Deep Visibility API
        let endpoint = "/dv/query-history";
        let request = S1DvQueryRequest {
            query: query.query.clone(),
            from_date: query.time_range.start.format("%Y-%m-%dT%H:%M:%S.000Z").to_string(),
            to_date: query.time_range.end.format("%Y-%m-%dT%H:%M:%S.000Z").to_string(),
            query_type: vec!["events".to_string()],
            limit: Some(10000),
        };

        // Create query
        let create_response: S1DvQueryCreateResponse = self.post("/dv/init-query", &request).await?;

        // Poll for results
        let query_id = create_response.data.query_id;
        let mut results = Vec::new();

        for _ in 0..60 {
            let status_endpoint = format!("/dv/query-status?queryId={}", query_id);
            let status: S1DvQueryStatus = self.get(&status_endpoint).await?;

            if status.data.status == "FINISHED" {
                let results_endpoint = format!("/dv/events?queryId={}&limit=10000", query_id);
                let events_response: S1DvEventsResponse = self.get(&results_endpoint).await?;
                results = events_response.data.into_iter()
                    .map(|e| serde_json::to_value(e).unwrap_or_default())
                    .collect();
                break;
            } else if status.data.status == "FAILED" {
                return Err(anyhow!("Deep Visibility query failed"));
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        Ok(HuntingResult {
            query_name: query.name.clone(),
            platform: EdrPlatform::SentinelOne,
            total_results: results.len() as u64,
            results,
            execution_time_ms: start.elapsed().as_millis() as u64,
            executed_at: Utc::now(),
        })
    }
}

// =============================================================================
// SentinelOne API Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct S1ThreatsResponse {
    data: Vec<S1Threat>,
    pagination: Option<S1Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1Threat {
    id: String,
    #[serde(rename = "agentRealtimeInfo")]
    agent_realtime_info: S1AgentRealtimeInfo,
    #[serde(rename = "threatInfo")]
    threat_info: S1ThreatInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1AgentRealtimeInfo {
    #[serde(rename = "agentComputerName")]
    agent_computer_name: Option<String>,
    #[serde(rename = "agentId")]
    agent_id: Option<String>,
    #[serde(rename = "agentNetworkInfo")]
    agent_network_info: Option<S1NetworkInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1NetworkInfo {
    inet: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1ThreatInfo {
    #[serde(rename = "threatName")]
    threat_name: Option<String>,
    classification: Option<String>,
    #[serde(rename = "confidenceLevel")]
    confidence_level: Option<i32>,
    #[serde(rename = "analystVerdict")]
    analyst_verdict: Option<String>,
    #[serde(rename = "originFileName")]
    origin_file_name: Option<String>,
    #[serde(rename = "originUserName")]
    origin_user_name: Option<String>,
    #[serde(rename = "filePath")]
    file_path: Option<String>,
    #[serde(rename = "processCmdline")]
    process_cmdline: Option<String>,
    sha256: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
    #[serde(rename = "updatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "mitreTactics")]
    mitre_info: Option<S1MitreInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1MitreInfo {
    #[serde(default)]
    tactics: Vec<String>,
    #[serde(default)]
    techniques: Vec<String>,
}

#[derive(Debug, Serialize)]
struct S1VerdictRequest {
    filter: S1Filter,
    data: S1VerdictData,
}

#[derive(Debug, Serialize)]
struct S1Filter {
    ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct S1VerdictData {
    #[serde(rename = "analystVerdict")]
    analyst_verdict: String,
}

#[derive(Debug, Deserialize)]
struct S1AgentsResponse {
    data: Vec<S1Agent>,
    pagination: Option<S1Pagination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1Agent {
    id: String,
    #[serde(rename = "computerName")]
    computer_name: Option<String>,
    #[serde(rename = "osName")]
    os_name: Option<String>,
    #[serde(rename = "osRevision")]
    os_revision: Option<String>,
    #[serde(rename = "agentVersion")]
    agent_version: Option<String>,
    #[serde(rename = "lastActiveDate")]
    last_active_date: Option<String>,
    #[serde(rename = "networkStatus")]
    network_status: Option<String>,
    #[serde(rename = "isActive")]
    is_active: Option<bool>,
    #[serde(rename = "groupName")]
    group_name: Option<String>,
    tags: Option<S1Tags>,
    #[serde(rename = "networkInterfaces")]
    network_interfaces: Option<Vec<S1NetworkInterface>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1Tags {
    #[serde(default)]
    names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S1NetworkInterface {
    inet: Option<Vec<String>>,
    physical: Option<String>,
}

#[derive(Debug, Deserialize)]
struct S1Pagination {
    #[serde(rename = "totalItems")]
    total_items: Option<i64>,
    #[serde(rename = "nextCursor")]
    next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct S1IocCreateRequest {
    data: Vec<S1IocCreate>,
}

#[derive(Debug, Serialize)]
struct S1IocCreate {
    value: String,
    #[serde(rename = "type")]
    ioc_type: String,
    method: String,
    source: Option<String>,
    description: Option<String>,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    #[serde(rename = "validUntil")]
    valid_until: Option<String>,
}

#[derive(Debug, Serialize)]
struct S1ActionRequest {
    filter: S1Filter,
    data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct S1ActionResponse {
    data: S1ActionData,
}

#[derive(Debug, Deserialize)]
struct S1ActionData {
    affected: i32,
}

#[derive(Debug, Serialize)]
struct S1DvQueryRequest {
    query: String,
    #[serde(rename = "fromDate")]
    from_date: String,
    #[serde(rename = "toDate")]
    to_date: String,
    #[serde(rename = "queryType")]
    query_type: Vec<String>,
    limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct S1DvQueryCreateResponse {
    data: S1DvQueryData,
}

#[derive(Debug, Deserialize)]
struct S1DvQueryData {
    #[serde(rename = "queryId")]
    query_id: String,
}

#[derive(Debug, Deserialize)]
struct S1DvQueryStatus {
    data: S1DvStatusData,
}

#[derive(Debug, Deserialize)]
struct S1DvStatusData {
    status: String,
}

#[derive(Debug, Deserialize)]
struct S1DvEventsResponse {
    data: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = SentinelOneConfig::new(
            "test_token".to_string(),
            "https://test.sentinelone.net".to_string(),
        );
        assert_eq!(config.management_url, "https://test.sentinelone.net");
        assert!(config.account_id.is_none());
    }

    #[test]
    fn test_config_with_options() {
        let config = SentinelOneConfig::new("token".to_string(), "https://s1.net".to_string())
            .with_account_id("account123".to_string())
            .with_site_id("site456".to_string());

        assert_eq!(config.account_id, Some("account123".to_string()));
        assert_eq!(config.site_id, Some("site456".to_string()));
    }

    #[test]
    fn test_severity_from_confidence() {
        assert_eq!(AlertSeverity::from_sentinelone(100), AlertSeverity::Critical);
        assert_eq!(AlertSeverity::from_sentinelone(75), AlertSeverity::High);
        assert_eq!(AlertSeverity::from_sentinelone(50), AlertSeverity::Medium);
        assert_eq!(AlertSeverity::from_sentinelone(30), AlertSeverity::Low);
        assert_eq!(AlertSeverity::from_sentinelone(10), AlertSeverity::Informational);
    }
}
