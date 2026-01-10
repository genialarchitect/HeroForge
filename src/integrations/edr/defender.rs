//! Microsoft Defender for Endpoint Integration
//!
//! Provides integration with Microsoft Defender for Endpoint:
//! - Azure AD OAuth2 authentication
//! - Alert and incident management
//! - Machine management
//! - Indicator (IOC) management
//! - Advanced hunting (KQL queries)
//! - Live response actions

use super::{
    ActionResult, AlertSeverity, AlertStatus, EdrAlert, EdrConnector, EdrEndpoint, EdrIoc,
    EdrPlatform, EndpointStatus, HuntingQuery, HuntingResult, IocType, ResponseAction,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use log::{info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

const GRAPH_API_BASE: &str = "https://graph.microsoft.com/v1.0";
const SECURITY_API_BASE: &str = "https://api.securitycenter.microsoft.com/api";
const AAD_TOKEN_URL: &str = "https://login.microsoftonline.com";
const TOKEN_REFRESH_MARGIN_SECS: i64 = 300;

/// Microsoft Defender for Endpoint client
pub struct DefenderClient {
    client: Client,
    config: DefenderConfig,
    token: Arc<RwLock<Option<TokenInfo>>>,
}

/// Defender configuration
#[derive(Debug, Clone)]
pub struct DefenderConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub use_graph_api: bool, // Use Graph API vs Security Center API
}

impl DefenderConfig {
    pub fn new(tenant_id: String, client_id: String, client_secret: String) -> Self {
        Self {
            tenant_id,
            client_id,
            client_secret,
            use_graph_api: false,
        }
    }

    pub fn with_graph_api(mut self, use_graph: bool) -> Self {
        self.use_graph_api = use_graph;
        self
    }
}

/// OAuth2 token information
#[derive(Debug, Clone)]
struct TokenInfo {
    access_token: String,
    expires_at: DateTime<Utc>,
}

impl DefenderClient {
    /// Create a new Defender client
    pub fn new(config: DefenderConfig) -> Result<Self> {
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
        let tenant_id = std::env::var("AZURE_TENANT_ID")
            .map_err(|_| anyhow!("AZURE_TENANT_ID not set"))?;
        let client_id = std::env::var("AZURE_CLIENT_ID")
            .or_else(|_| std::env::var("DEFENDER_CLIENT_ID"))
            .map_err(|_| anyhow!("AZURE_CLIENT_ID or DEFENDER_CLIENT_ID not set"))?;
        let client_secret = std::env::var("AZURE_CLIENT_SECRET")
            .or_else(|_| std::env::var("DEFENDER_CLIENT_SECRET"))
            .map_err(|_| anyhow!("AZURE_CLIENT_SECRET or DEFENDER_CLIENT_SECRET not set"))?;

        let config = DefenderConfig::new(tenant_id, client_id, client_secret);
        Self::new(config)
    }

    /// Get API base URL
    fn api_base(&self) -> &str {
        if self.config.use_graph_api {
            GRAPH_API_BASE
        } else {
            SECURITY_API_BASE
        }
    }

    /// Get a valid access token
    async fn get_token(&self) -> Result<String> {
        {
            let token = self.token.read().await;
            if let Some(ref t) = *token {
                if t.expires_at > Utc::now() + Duration::seconds(TOKEN_REFRESH_MARGIN_SECS) {
                    return Ok(t.access_token.clone());
                }
            }
        }
        self.refresh_token().await
    }

    /// Refresh the OAuth2 token
    async fn refresh_token(&self) -> Result<String> {
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            AAD_TOKEN_URL, self.config.tenant_id
        );

        let scope = if self.config.use_graph_api {
            "https://graph.microsoft.com/.default"
        } else {
            "https://api.securitycenter.microsoft.com/.default"
        };

        let params = [
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("scope", scope),
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
            return Err(anyhow!("Azure AD token request failed: {} - {}", status, body));
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

        info!("Azure AD token refreshed for Defender");
        Ok(token_response.access_token)
    }

    /// Make an authenticated GET request
    async fn get<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<T> {
        let token = self.get_token().await?;
        let url = format!("{}{}", self.api_base(), endpoint);

        let response = self.client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Defender API error: {} - {}", status, body));
        }

        Ok(response.json().await?)
    }

    /// Make an authenticated POST request
    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(&self, endpoint: &str, body: &B) -> Result<T> {
        let token = self.get_token().await?;
        let url = format!("{}{}", self.api_base(), endpoint);

        let response = self.client
            .post(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Defender API error: {} - {}", status, body));
        }

        Ok(response.json().await?)
    }

    /// Make an authenticated PATCH request
    async fn patch<B: Serialize>(&self, endpoint: &str, body: &B) -> Result<()> {
        let token = self.get_token().await?;
        let url = format!("{}{}", self.api_base(), endpoint);

        let response = self.client
            .patch(&url)
            .bearer_auth(&token)
            .json(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Defender API error: {} - {}", status, body));
        }

        Ok(())
    }

    /// Convert Defender alert to common EdrAlert
    fn convert_alert(&self, alert: &DefenderAlert) -> EdrAlert {
        EdrAlert {
            id: alert.id.clone(),
            platform: EdrPlatform::Defender,
            severity: AlertSeverity::from_defender(&alert.severity),
            title: alert.title.clone(),
            description: alert.description.clone().unwrap_or_default(),
            hostname: alert.machine_id.clone().unwrap_or_default(),
            username: alert.domain_name.as_ref()
                .map(|d| format!("{}\\{}", d, alert.user_name.as_deref().unwrap_or("unknown"))),
            ip_address: alert.related_user.as_ref()
                .and_then(|u| u.domain_name.clone()),
            process_name: alert.evidence.as_ref()
                .and_then(|e| e.first())
                .and_then(|ev| ev.file_name.clone()),
            process_path: alert.evidence.as_ref()
                .and_then(|e| e.first())
                .and_then(|ev| ev.file_path.clone()),
            command_line: alert.evidence.as_ref()
                .and_then(|e| e.first())
                .and_then(|ev| ev.process_command_line.clone()),
            parent_process: alert.evidence.as_ref()
                .and_then(|e| e.first())
                .and_then(|ev| ev.parent_process_file_name.clone()),
            file_hash: alert.evidence.as_ref()
                .and_then(|e| e.first())
                .and_then(|ev| ev.sha256.clone()),
            mitre_tactics: alert.mitre_techniques.as_ref()
                .map(|t| t.iter()
                    .filter_map(|m| m.tactic.clone())
                    .collect())
                .unwrap_or_default(),
            mitre_techniques: alert.mitre_techniques.as_ref()
                .map(|t| t.iter()
                    .filter_map(|m| m.technique.clone())
                    .collect())
                .unwrap_or_default(),
            status: self.convert_status(&alert.status),
            created_at: DateTime::parse_from_rfc3339(&alert.alert_creation_time)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&alert.last_update_time.clone().unwrap_or_default())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            raw_data: serde_json::to_value(alert).unwrap_or_default(),
        }
    }

    fn convert_status(&self, status: &str) -> AlertStatus {
        match status.to_lowercase().as_str() {
            "new" => AlertStatus::New,
            "inprogress" => AlertStatus::InProgress,
            "resolved" => AlertStatus::Resolved,
            _ => AlertStatus::New,
        }
    }

    /// Convert Defender machine to common EdrEndpoint
    fn convert_machine(&self, machine: &DefenderMachine) -> EdrEndpoint {
        EdrEndpoint {
            id: machine.id.clone(),
            platform: EdrPlatform::Defender,
            hostname: machine.computer_dns_name.clone().unwrap_or_default(),
            ip_addresses: machine.ip_addresses.as_ref()
                .map(|ips| ips.iter()
                    .filter_map(|ip| ip.ip_address.clone())
                    .collect())
                .unwrap_or_default(),
            mac_addresses: machine.ip_addresses.as_ref()
                .map(|ips| ips.iter()
                    .filter_map(|ip| ip.mac_address.clone())
                    .collect())
                .unwrap_or_default(),
            os_name: machine.os_platform.clone().unwrap_or_default(),
            os_version: machine.os_version.clone().unwrap_or_default(),
            agent_version: machine.agent_version.clone().unwrap_or_default(),
            last_seen: DateTime::parse_from_rfc3339(&machine.last_seen.clone().unwrap_or_default())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            status: self.convert_health_status(&machine.health_status.clone().unwrap_or_default()),
            groups: machine.machine_tags.clone().unwrap_or_default(),
            tags: machine.machine_tags.clone().unwrap_or_default(),
            is_online: machine.health_status.as_deref() == Some("Active"),
        }
    }

    fn convert_health_status(&self, status: &str) -> EndpointStatus {
        match status.to_lowercase().as_str() {
            "active" => EndpointStatus::Online,
            "inactive" => EndpointStatus::Offline,
            "impairedcommunication" => EndpointStatus::Degraded,
            "nosenosorcommunicationperformed" => EndpointStatus::Unmanaged,
            _ => EndpointStatus::Offline,
        }
    }
}

#[async_trait]
impl EdrConnector for DefenderClient {
    fn platform(&self) -> EdrPlatform {
        EdrPlatform::Defender
    }

    async fn test_connection(&self) -> Result<bool> {
        self.get_token().await?;
        Ok(true)
    }

    async fn get_alerts(&self, since: DateTime<Utc>, limit: u32) -> Result<Vec<EdrAlert>> {
        let filter = format!(
            "alertCreationTime ge {}",
            since.format("%Y-%m-%dT%H:%M:%SZ")
        );
        let endpoint = format!(
            "/alerts?$filter={}&$top={}",
            urlencoding::encode(&filter),
            limit
        );

        let response: DefenderAlertsResponse = self.get(&endpoint).await?;

        Ok(response.value.iter()
            .map(|a| self.convert_alert(a))
            .collect())
    }

    async fn get_alert(&self, alert_id: &str) -> Result<EdrAlert> {
        let endpoint = format!("/alerts/{}", alert_id);
        let alert: DefenderAlert = self.get(&endpoint).await?;
        Ok(self.convert_alert(&alert))
    }

    async fn update_alert_status(&self, alert_id: &str, status: AlertStatus) -> Result<()> {
        let defender_status = match status {
            AlertStatus::New => "New",
            AlertStatus::InProgress => "InProgress",
            AlertStatus::Resolved => "Resolved",
            AlertStatus::FalsePositive => "Resolved",
            AlertStatus::Ignored => "Resolved",
        };

        let endpoint = format!("/alerts/{}", alert_id);
        let body = DefenderAlertUpdate {
            status: defender_status.to_string(),
            classification: if status == AlertStatus::FalsePositive {
                Some("FalsePositive".to_string())
            } else {
                None
            },
            determination: None,
            assigned_to: None,
        };

        self.patch(&endpoint, &body).await
    }

    async fn get_endpoints(&self, limit: u32, offset: u32) -> Result<Vec<EdrEndpoint>> {
        let endpoint = format!("/machines?$top={}&$skip={}", limit, offset);
        let response: DefenderMachinesResponse = self.get(&endpoint).await?;

        Ok(response.value.iter()
            .map(|m| self.convert_machine(m))
            .collect())
    }

    async fn get_endpoint(&self, endpoint_id: &str) -> Result<EdrEndpoint> {
        let endpoint = format!("/machines/{}", endpoint_id);
        let machine: DefenderMachine = self.get(&endpoint).await?;
        Ok(self.convert_machine(&machine))
    }

    async fn search_endpoints(&self, query: &str) -> Result<Vec<EdrEndpoint>> {
        let filter = format!("contains(computerDnsName, '{}')", query);
        let endpoint = format!("/machines?$filter={}", urlencoding::encode(&filter));
        let response: DefenderMachinesResponse = self.get(&endpoint).await?;

        Ok(response.value.iter()
            .map(|m| self.convert_machine(m))
            .collect())
    }

    async fn push_iocs(&self, iocs: &[EdrIoc]) -> Result<u32> {
        let indicators: Vec<DefenderIndicator> = iocs.iter()
            .map(|ioc| DefenderIndicator {
                indicator_value: ioc.value.clone(),
                indicator_type: match ioc.ioc_type {
                    IocType::Sha256 => "FileSha256",
                    IocType::Sha1 => "FileSha1",
                    IocType::Md5 => "FileMd5",
                    IocType::Domain => "DomainName",
                    IocType::IpAddress => "IpAddress",
                    IocType::Url => "Url",
                    _ => "FileSha256",
                }.to_string(),
                action: "AlertAndBlock".to_string(),
                title: ioc.description.clone().unwrap_or_else(|| "HeroForge IOC".to_string()),
                description: ioc.description.clone(),
                severity: match ioc.severity {
                    AlertSeverity::Critical => "High",
                    AlertSeverity::High => "High",
                    AlertSeverity::Medium => "Medium",
                    AlertSeverity::Low => "Low",
                    AlertSeverity::Informational => "Informational",
                }.to_string(),
                recommended_actions: None,
                expiration_time: ioc.expiration.map(|e| e.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                generate_alert: Some(true),
            })
            .collect();

        let mut success_count = 0;
        for indicator in &indicators {
            match self.post::<serde_json::Value, _>("/indicators", indicator).await {
                Ok(_) => success_count += 1,
                Err(e) => warn!("Failed to push IOC {}: {}", indicator.indicator_value, e),
            }
        }

        Ok(success_count)
    }

    async fn execute_action(&self, endpoint_id: &str, action: ResponseAction) -> Result<ActionResult> {
        let (endpoint_path, request_body): (&str, serde_json::Value) = match action {
            ResponseAction::Isolate => (
                &format!("/machines/{}/isolate", endpoint_id),
                serde_json::json!({
                    "Comment": "Isolated by HeroForge",
                    "IsolationType": "Full"
                }),
            ),
            ResponseAction::Unisolate => (
                &format!("/machines/{}/unisolate", endpoint_id),
                serde_json::json!({ "Comment": "Released by HeroForge" }),
            ),
            ResponseAction::Scan => (
                &format!("/machines/{}/runAntiVirusScan", endpoint_id),
                serde_json::json!({
                    "Comment": "Scan initiated by HeroForge",
                    "ScanType": "Full"
                }),
            ),
            ResponseAction::Collect => (
                &format!("/machines/{}/collectInvestigationPackage", endpoint_id),
                serde_json::json!({ "Comment": "Collection by HeroForge" }),
            ),
            _ => return Err(anyhow!("Action {:?} not supported for Defender", action)),
        };

        let token = self.get_token().await?;
        let url = format!("{}{}", self.api_base(), endpoint_path);

        let response = self.client
            .post(&url)
            .bearer_auth(&token)
            .json(&request_body)
            .send()
            .await?;

        let success = response.status().is_success();
        let message = if success {
            format!("Action {:?} initiated successfully", action)
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

        // Use Advanced Hunting API
        let request = DefenderHuntingRequest {
            query: query.query.clone(),
        };

        let response: DefenderHuntingResponse = self.post("/advancedqueries/run", &request).await?;

        let results: Vec<serde_json::Value> = response.results.into_iter()
            .map(|r| serde_json::to_value(r).unwrap_or_default())
            .collect();

        Ok(HuntingResult {
            query_name: query.name.clone(),
            platform: EdrPlatform::Defender,
            total_results: results.len() as u64,
            results,
            execution_time_ms: start.elapsed().as_millis() as u64,
            executed_at: Utc::now(),
        })
    }
}

// =============================================================================
// Microsoft Defender API Types
// =============================================================================

#[derive(Debug, Deserialize)]
struct AadTokenResponse {
    access_token: String,
    expires_in: u32,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct DefenderAlertsResponse {
    value: Vec<DefenderAlert>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenderAlert {
    id: String,
    #[serde(rename = "incidentId")]
    incident_id: Option<i64>,
    title: String,
    description: Option<String>,
    severity: String,
    status: String,
    classification: Option<String>,
    determination: Option<String>,
    #[serde(rename = "alertCreationTime")]
    alert_creation_time: String,
    #[serde(rename = "lastUpdateTime")]
    last_update_time: Option<String>,
    #[serde(rename = "machineId")]
    machine_id: Option<String>,
    #[serde(rename = "computerDnsName")]
    computer_dns_name: Option<String>,
    #[serde(rename = "domainName")]
    domain_name: Option<String>,
    #[serde(rename = "userName")]
    user_name: Option<String>,
    #[serde(rename = "relatedUser")]
    related_user: Option<DefenderRelatedUser>,
    evidence: Option<Vec<DefenderEvidence>>,
    #[serde(rename = "mitreTechniques")]
    mitre_techniques: Option<Vec<DefenderMitreTechnique>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenderRelatedUser {
    #[serde(rename = "userName")]
    user_name: Option<String>,
    #[serde(rename = "domainName")]
    domain_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenderEvidence {
    #[serde(rename = "entityType")]
    entity_type: Option<String>,
    #[serde(rename = "fileName")]
    file_name: Option<String>,
    #[serde(rename = "filePath")]
    file_path: Option<String>,
    sha256: Option<String>,
    sha1: Option<String>,
    #[serde(rename = "processId")]
    process_id: Option<i64>,
    #[serde(rename = "processCommandLine")]
    process_command_line: Option<String>,
    #[serde(rename = "parentProcessFileName")]
    parent_process_file_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenderMitreTechnique {
    tactic: Option<String>,
    technique: Option<String>,
}

#[derive(Debug, Serialize)]
struct DefenderAlertUpdate {
    status: String,
    classification: Option<String>,
    determination: Option<String>,
    #[serde(rename = "assignedTo")]
    assigned_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DefenderMachinesResponse {
    value: Vec<DefenderMachine>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenderMachine {
    id: String,
    #[serde(rename = "computerDnsName")]
    computer_dns_name: Option<String>,
    #[serde(rename = "osPlatform")]
    os_platform: Option<String>,
    #[serde(rename = "osVersion")]
    os_version: Option<String>,
    #[serde(rename = "agentVersion")]
    agent_version: Option<String>,
    #[serde(rename = "lastSeen")]
    last_seen: Option<String>,
    #[serde(rename = "healthStatus")]
    health_status: Option<String>,
    #[serde(rename = "riskScore")]
    risk_score: Option<String>,
    #[serde(rename = "exposureLevel")]
    exposure_level: Option<String>,
    #[serde(rename = "machineTags")]
    machine_tags: Option<Vec<String>>,
    #[serde(rename = "ipAddresses")]
    ip_addresses: Option<Vec<DefenderIpAddress>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefenderIpAddress {
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(rename = "macAddress")]
    mac_address: Option<String>,
    #[serde(rename = "type")]
    ip_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct DefenderIndicator {
    #[serde(rename = "indicatorValue")]
    indicator_value: String,
    #[serde(rename = "indicatorType")]
    indicator_type: String,
    action: String,
    title: String,
    description: Option<String>,
    severity: String,
    #[serde(rename = "recommendedActions")]
    recommended_actions: Option<String>,
    #[serde(rename = "expirationTime")]
    expiration_time: Option<String>,
    #[serde(rename = "generateAlert")]
    generate_alert: Option<bool>,
}

#[derive(Debug, Serialize)]
struct DefenderHuntingRequest {
    #[serde(rename = "Query")]
    query: String,
}

#[derive(Debug, Deserialize)]
struct DefenderHuntingResponse {
    #[serde(rename = "Results")]
    results: Vec<std::collections::HashMap<String, serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = DefenderConfig::new(
            "tenant123".to_string(),
            "client456".to_string(),
            "secret789".to_string(),
        );
        assert_eq!(config.tenant_id, "tenant123");
        assert!(!config.use_graph_api);
    }

    #[test]
    fn test_config_with_graph_api() {
        let config = DefenderConfig::new("t".to_string(), "c".to_string(), "s".to_string())
            .with_graph_api(true);
        assert!(config.use_graph_api);
    }

    #[test]
    fn test_severity_from_defender() {
        assert_eq!(AlertSeverity::from_defender("high"), AlertSeverity::High);
        assert_eq!(AlertSeverity::from_defender("Medium"), AlertSeverity::Medium);
        assert_eq!(AlertSeverity::from_defender("LOW"), AlertSeverity::Low);
        assert_eq!(AlertSeverity::from_defender("unknown"), AlertSeverity::Medium);
    }
}
