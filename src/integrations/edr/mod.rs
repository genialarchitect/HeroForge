//! EDR (Endpoint Detection and Response) Connectors
//!
//! This module provides integration with major EDR platforms:
//! - **CrowdStrike Falcon**: Leading cloud-native EDR platform
//! - **SentinelOne**: AI-powered endpoint protection
//! - **Microsoft Defender for Endpoint**: Enterprise-grade EDR
//!
//! Features:
//! - Alert ingestion and correlation
//! - Threat hunting query execution
//! - IOC push/pull synchronization
//! - Automated response actions
//! - Real-time telemetry streaming

pub mod crowdstrike;
pub mod defender;
pub mod sentinelone;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use crowdstrike::CrowdStrikeClient;
pub use defender::DefenderClient;
pub use sentinelone::SentinelOneClient;

// =============================================================================
// Common Types
// =============================================================================

/// EDR platform type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdrPlatform {
    CrowdStrike,
    SentinelOne,
    Defender,
}

impl std::fmt::Display for EdrPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrowdStrike => write!(f, "CrowdStrike Falcon"),
            Self::SentinelOne => write!(f, "SentinelOne"),
            Self::Defender => write!(f, "Microsoft Defender for Endpoint"),
        }
    }
}

/// Common EDR alert representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrAlert {
    pub id: String,
    pub platform: EdrPlatform,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub hostname: String,
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_process: Option<String>,
    pub file_hash: Option<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub status: AlertStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub raw_data: serde_json::Value,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn from_crowdstrike(severity: &str) -> Self {
        match severity.to_lowercase().as_str() {
            "informational" => Self::Informational,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Medium,
        }
    }

    pub fn from_sentinelone(confidence: i32) -> Self {
        match confidence {
            0..=20 => Self::Informational,
            21..=40 => Self::Low,
            41..=60 => Self::Medium,
            61..=80 => Self::High,
            _ => Self::Critical,
        }
    }

    pub fn from_defender(severity: &str) -> Self {
        match severity.to_lowercase().as_str() {
            "informational" => Self::Informational,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            _ => Self::Medium,
        }
    }
}

/// Alert status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    New,
    InProgress,
    Resolved,
    FalsePositive,
    Ignored,
}

/// Common endpoint representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEndpoint {
    pub id: String,
    pub platform: EdrPlatform,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub mac_addresses: Vec<String>,
    pub os_name: String,
    pub os_version: String,
    pub agent_version: String,
    pub last_seen: DateTime<Utc>,
    pub status: EndpointStatus,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
    pub is_online: bool,
}

/// Endpoint status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStatus {
    Online,
    Offline,
    Degraded,
    Isolated,
    Unmanaged,
}

/// IOC (Indicator of Compromise) for push/pull
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrIoc {
    pub ioc_type: IocType,
    pub value: String,
    pub description: Option<String>,
    pub severity: AlertSeverity,
    pub expiration: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub source: String,
}

/// IOC types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Sha256,
    Sha1,
    Md5,
    Domain,
    IpAddress,
    Url,
    FilePath,
    RegistryKey,
    Email,
    ProcessName,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha1 => write!(f, "sha1"),
            Self::Md5 => write!(f, "md5"),
            Self::Domain => write!(f, "domain"),
            Self::IpAddress => write!(f, "ip_address"),
            Self::Url => write!(f, "url"),
            Self::FilePath => write!(f, "file_path"),
            Self::RegistryKey => write!(f, "registry_key"),
            Self::Email => write!(f, "email"),
            Self::ProcessName => write!(f, "process_name"),
        }
    }
}

/// Response action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    Isolate,
    Unisolate,
    Kill,
    Quarantine,
    Unquarantine,
    Scan,
    Collect,
    Remediate,
}

/// Response action result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: ResponseAction,
    pub target: String,
    pub success: bool,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// Threat hunting query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingQuery {
    pub name: String,
    pub description: Option<String>,
    pub query: String,
    pub platform: EdrPlatform,
    pub time_range: TimeRange,
}

/// Time range for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Hunting query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingResult {
    pub query_name: String,
    pub platform: EdrPlatform,
    pub total_results: u64,
    pub results: Vec<serde_json::Value>,
    pub execution_time_ms: u64,
    pub executed_at: DateTime<Utc>,
}

// =============================================================================
// EDR Connector Trait
// =============================================================================

/// Common interface for all EDR connectors
#[async_trait]
pub trait EdrConnector: Send + Sync {
    /// Get the platform type
    fn platform(&self) -> EdrPlatform;

    /// Test connection to the EDR platform
    async fn test_connection(&self) -> Result<bool>;

    /// Get alerts from the EDR platform
    async fn get_alerts(&self, since: DateTime<Utc>, limit: u32) -> Result<Vec<EdrAlert>>;

    /// Get a specific alert by ID
    async fn get_alert(&self, alert_id: &str) -> Result<EdrAlert>;

    /// Update alert status
    async fn update_alert_status(&self, alert_id: &str, status: AlertStatus) -> Result<()>;

    /// Get endpoints from the EDR platform
    async fn get_endpoints(&self, limit: u32, offset: u32) -> Result<Vec<EdrEndpoint>>;

    /// Get a specific endpoint by ID
    async fn get_endpoint(&self, endpoint_id: &str) -> Result<EdrEndpoint>;

    /// Search for endpoints
    async fn search_endpoints(&self, query: &str) -> Result<Vec<EdrEndpoint>>;

    /// Push IOCs to the EDR platform
    async fn push_iocs(&self, iocs: &[EdrIoc]) -> Result<u32>;

    /// Execute a response action
    async fn execute_action(&self, endpoint_id: &str, action: ResponseAction) -> Result<ActionResult>;

    /// Execute a hunting query
    async fn hunt(&self, query: &HuntingQuery) -> Result<HuntingResult>;
}

// =============================================================================
// Unified EDR Manager
// =============================================================================

/// Unified EDR manager for multi-platform operations
pub struct EdrManager {
    connectors: HashMap<EdrPlatform, Box<dyn EdrConnector>>,
}

impl EdrManager {
    /// Create a new EDR manager
    pub fn new() -> Self {
        Self {
            connectors: HashMap::new(),
        }
    }

    /// Add a connector
    pub fn add_connector(&mut self, connector: Box<dyn EdrConnector>) {
        self.connectors.insert(connector.platform(), connector);
    }

    /// Get all configured platforms
    pub fn platforms(&self) -> Vec<EdrPlatform> {
        self.connectors.keys().copied().collect()
    }

    /// Test all connections
    pub async fn test_all_connections(&self) -> HashMap<EdrPlatform, bool> {
        let mut results = HashMap::new();
        for (platform, connector) in &self.connectors {
            let result = connector.test_connection().await.unwrap_or(false);
            results.insert(*platform, result);
        }
        results
    }

    /// Get alerts from all platforms
    pub async fn get_all_alerts(&self, since: DateTime<Utc>, limit_per_platform: u32) -> Vec<EdrAlert> {
        let mut all_alerts = Vec::new();
        for connector in self.connectors.values() {
            if let Ok(alerts) = connector.get_alerts(since, limit_per_platform).await {
                all_alerts.extend(alerts);
            }
        }
        // Sort by severity and time
        all_alerts.sort_by(|a, b| {
            b.severity.cmp(&a.severity)
                .then_with(|| b.created_at.cmp(&a.created_at))
        });
        all_alerts
    }

    /// Get endpoints from all platforms
    pub async fn get_all_endpoints(&self, limit_per_platform: u32) -> Vec<EdrEndpoint> {
        let mut all_endpoints = Vec::new();
        for connector in self.connectors.values() {
            if let Ok(endpoints) = connector.get_endpoints(limit_per_platform, 0).await {
                all_endpoints.extend(endpoints);
            }
        }
        all_endpoints
    }

    /// Push IOCs to all platforms
    pub async fn push_iocs_to_all(&self, iocs: &[EdrIoc]) -> HashMap<EdrPlatform, Result<u32, String>> {
        let mut results = HashMap::new();
        for (platform, connector) in &self.connectors {
            match connector.push_iocs(iocs).await {
                Ok(count) => {
                    results.insert(*platform, Ok(count));
                }
                Err(e) => {
                    results.insert(*platform, Err(e.to_string()));
                }
            }
        }
        results
    }

    /// Execute action on a specific platform
    pub async fn execute_action(
        &self,
        platform: EdrPlatform,
        endpoint_id: &str,
        action: ResponseAction,
    ) -> Result<ActionResult> {
        let connector = self.connectors.get(&platform)
            .ok_or_else(|| anyhow::anyhow!("Platform {} not configured", platform))?;
        connector.execute_action(endpoint_id, action).await
    }

    /// Run hunting query on a specific platform
    pub async fn hunt(&self, query: &HuntingQuery) -> Result<HuntingResult> {
        let connector = self.connectors.get(&query.platform)
            .ok_or_else(|| anyhow::anyhow!("Platform {} not configured", query.platform))?;
        connector.hunt(query).await
    }

    /// Cross-platform threat correlation
    pub async fn correlate_threats(&self, since: DateTime<Utc>) -> CorrelatedThreatReport {
        let alerts = self.get_all_alerts(since, 1000).await;

        // Group by MITRE technique
        let mut by_technique: HashMap<String, Vec<&EdrAlert>> = HashMap::new();
        for alert in &alerts {
            for technique in &alert.mitre_techniques {
                by_technique.entry(technique.clone()).or_default().push(alert);
            }
        }

        // Group by hostname
        let mut by_host: HashMap<String, Vec<&EdrAlert>> = HashMap::new();
        for alert in &alerts {
            by_host.entry(alert.hostname.clone()).or_default().push(alert);
        }

        // Identify potential attack chains
        let attack_chains = self.identify_attack_chains(&alerts);

        CorrelatedThreatReport {
            total_alerts: alerts.len(),
            alerts_by_platform: self.count_by_platform(&alerts),
            alerts_by_severity: self.count_by_severity(&alerts),
            top_techniques: self.top_n(&by_technique, 10),
            top_hosts: self.top_n(&by_host, 10),
            potential_attack_chains: attack_chains,
            generated_at: Utc::now(),
        }
    }

    fn count_by_platform(&self, alerts: &[EdrAlert]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for alert in alerts {
            *counts.entry(alert.platform.to_string()).or_insert(0) += 1;
        }
        counts
    }

    fn count_by_severity(&self, alerts: &[EdrAlert]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for alert in alerts {
            *counts.entry(format!("{:?}", alert.severity)).or_insert(0) += 1;
        }
        counts
    }

    fn top_n<T>(&self, map: &HashMap<String, Vec<T>>, n: usize) -> Vec<(String, usize)> {
        let mut items: Vec<_> = map.iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();
        items.sort_by(|a, b| b.1.cmp(&a.1));
        items.truncate(n);
        items
    }

    fn identify_attack_chains(&self, alerts: &[EdrAlert]) -> Vec<AttackChainCandidate> {
        let mut chains = Vec::new();

        // Group alerts by host
        let mut by_host: HashMap<String, Vec<&EdrAlert>> = HashMap::new();
        for alert in alerts {
            by_host.entry(alert.hostname.clone()).or_default().push(alert);
        }

        // Look for hosts with multiple high-severity alerts following attack patterns
        for (hostname, host_alerts) in &by_host {
            if host_alerts.len() >= 3 {
                let high_severity: Vec<_> = host_alerts.iter()
                    .filter(|a| a.severity >= AlertSeverity::High)
                    .collect();

                if high_severity.len() >= 2 {
                    // Check for lateral movement indicators
                    let tactics: std::collections::HashSet<_> = high_severity.iter()
                        .flat_map(|a| a.mitre_tactics.iter())
                        .collect();

                    if tactics.len() >= 3 {
                        chains.push(AttackChainCandidate {
                            hostname: hostname.clone(),
                            alert_count: host_alerts.len(),
                            high_severity_count: high_severity.len(),
                            tactics: tactics.into_iter().cloned().collect(),
                            confidence: calculate_chain_confidence(&high_severity),
                        });
                    }
                }
            }
        }

        chains.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        chains.truncate(10);
        chains
    }
}

impl Default for EdrManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Correlated threat report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedThreatReport {
    pub total_alerts: usize,
    pub alerts_by_platform: HashMap<String, usize>,
    pub alerts_by_severity: HashMap<String, usize>,
    pub top_techniques: Vec<(String, usize)>,
    pub top_hosts: Vec<(String, usize)>,
    pub potential_attack_chains: Vec<AttackChainCandidate>,
    pub generated_at: DateTime<Utc>,
}

/// Potential attack chain candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChainCandidate {
    pub hostname: String,
    pub alert_count: usize,
    pub high_severity_count: usize,
    pub tactics: Vec<String>,
    pub confidence: f64,
}

fn calculate_chain_confidence(alerts: &[&&EdrAlert]) -> f64 {
    let mut score = 0.0;

    // More alerts = higher confidence
    score += (alerts.len() as f64 * 0.1).min(0.3);

    // More unique techniques = higher confidence
    let techniques: std::collections::HashSet<_> = alerts.iter()
        .flat_map(|a| a.mitre_techniques.iter())
        .collect();
    score += (techniques.len() as f64 * 0.1).min(0.3);

    // Higher severity = higher confidence
    let critical_count = alerts.iter()
        .filter(|a| a.severity == AlertSeverity::Critical)
        .count();
    score += (critical_count as f64 * 0.2).min(0.4);

    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Informational);
    }

    #[test]
    fn test_severity_from_crowdstrike() {
        assert_eq!(AlertSeverity::from_crowdstrike("critical"), AlertSeverity::Critical);
        assert_eq!(AlertSeverity::from_crowdstrike("HIGH"), AlertSeverity::High);
        assert_eq!(AlertSeverity::from_crowdstrike("unknown"), AlertSeverity::Medium);
    }

    #[test]
    fn test_severity_from_sentinelone() {
        assert_eq!(AlertSeverity::from_sentinelone(100), AlertSeverity::Critical);
        assert_eq!(AlertSeverity::from_sentinelone(70), AlertSeverity::High);
        assert_eq!(AlertSeverity::from_sentinelone(50), AlertSeverity::Medium);
        assert_eq!(AlertSeverity::from_sentinelone(10), AlertSeverity::Informational);
    }

    #[test]
    fn test_edr_manager_creation() {
        let manager = EdrManager::new();
        assert!(manager.platforms().is_empty());
    }
}
