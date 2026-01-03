use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::data_lake::types::DataRecord;

/// EDR (Endpoint Detection and Response) connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EDRConnector {
    pub api_url: String,
    pub api_key: String,
    pub vendor: EDRVendor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EDRVendor {
    CrowdStrike,
    SentinelOne,
    CarbonBlack,
    MicrosoftDefender,
    Other(String),
}

impl EDRConnector {
    #[allow(dead_code)]
    pub fn new(api_url: String, api_key: String, vendor: EDRVendor) -> Self {
        Self {
            api_url,
            api_key,
            vendor,
        }
    }

    /// Ingest EDR events
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting EDR events from {:?}", self.vendor);

        match &self.vendor {
            EDRVendor::CrowdStrike => self.ingest_crowdstrike(source_id).await,
            EDRVendor::SentinelOne => self.ingest_sentinelone(source_id).await,
            EDRVendor::CarbonBlack => self.ingest_carbonblack(source_id).await,
            EDRVendor::MicrosoftDefender => self.ingest_defender(source_id).await,
            EDRVendor::Other(name) => self.ingest_generic_edr(source_id, name).await,
        }
    }

    async fn ingest_crowdstrike(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // CrowdStrike Falcon API - Event Stream
        let events_url = format!("{}/sensors/entities/datafeed/v2", self.api_url);

        let response = client.get(&events_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Accept", "application/json")
            .send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(resources) = data.get("resources").and_then(|r| r.as_array()) {
                            for event in resources {
                                let record = DataRecord {
                                    id: event.get("event_id")
                                        .and_then(|e| e.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                    source_id: source_id.to_string(),
                                    timestamp: event.get("timestamp")
                                        .and_then(|t| t.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .unwrap_or_else(Utc::now),
                                    data: event.clone(),
                                    metadata: serde_json::json!({
                                        "vendor": "crowdstrike",
                                        "source_type": "edr"
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("CrowdStrike API error: {}", e),
        }

        log::info!("Ingested {} CrowdStrike events", records.len());
        Ok(records)
    }

    async fn ingest_sentinelone(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // SentinelOne API - Threats endpoint
        let threats_url = format!("{}/web/api/v2.1/threats", self.api_url);

        let response = client.get(&threats_url)
            .header("Authorization", format!("APIToken {}", self.api_key))
            .header("Accept", "application/json")
            .send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(threats) = data.get("data").and_then(|d| d.as_array()) {
                            for threat in threats {
                                let record = DataRecord {
                                    id: threat.get("id")
                                        .and_then(|e| e.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                    source_id: source_id.to_string(),
                                    timestamp: threat.get("createdAt")
                                        .and_then(|t| t.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .unwrap_or_else(Utc::now),
                                    data: threat.clone(),
                                    metadata: serde_json::json!({
                                        "vendor": "sentinelone",
                                        "source_type": "edr"
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("SentinelOne API error: {}", e),
        }

        log::info!("Ingested {} SentinelOne threats", records.len());
        Ok(records)
    }

    async fn ingest_carbonblack(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // Carbon Black Cloud API - Alerts
        let alerts_url = format!("{}/api/alerts/v7/orgs/{}/alerts/_search",
            self.api_url, "default");

        let search_body = serde_json::json!({
            "time_range": {
                "start": (Utc::now() - chrono::Duration::hours(24)).to_rfc3339(),
                "end": Utc::now().to_rfc3339()
            },
            "rows": 1000
        });

        let response = client.post(&alerts_url)
            .header("X-Auth-Token", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&search_body)
            .send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
                            for alert in results {
                                let record = DataRecord {
                                    id: alert.get("id")
                                        .and_then(|e| e.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                    source_id: source_id.to_string(),
                                    timestamp: alert.get("backend_timestamp")
                                        .and_then(|t| t.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .unwrap_or_else(Utc::now),
                                    data: alert.clone(),
                                    metadata: serde_json::json!({
                                        "vendor": "carbonblack",
                                        "source_type": "edr"
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("Carbon Black API error: {}", e),
        }

        log::info!("Ingested {} Carbon Black alerts", records.len());
        Ok(records)
    }

    async fn ingest_defender(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // Microsoft Defender for Endpoint API - Alerts
        let alerts_url = format!("{}/api/alerts", self.api_url);

        let response = client.get(&alerts_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Accept", "application/json")
            .send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(alerts) = data.get("value").and_then(|v| v.as_array()) {
                            for alert in alerts {
                                let record = DataRecord {
                                    id: alert.get("id")
                                        .and_then(|e| e.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                    source_id: source_id.to_string(),
                                    timestamp: alert.get("alertCreationTime")
                                        .and_then(|t| t.as_str())
                                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                        .map(|dt| dt.with_timezone(&Utc))
                                        .unwrap_or_else(Utc::now),
                                    data: alert.clone(),
                                    metadata: serde_json::json!({
                                        "vendor": "microsoft_defender",
                                        "source_type": "edr"
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("Microsoft Defender API error: {}", e),
        }

        log::info!("Ingested {} Microsoft Defender alerts", records.len());
        Ok(records)
    }

    async fn ingest_generic_edr(&self, source_id: &str, vendor_name: &str) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // Generic EDR API - assume JSON REST endpoint
        let response = client.get(&self.api_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Accept", "application/json")
            .send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        // Try to extract events from common response structures
                        let events = data.get("events")
                            .or_else(|| data.get("data"))
                            .or_else(|| data.get("results"))
                            .or_else(|| data.get("items"))
                            .and_then(|e| e.as_array());

                        if let Some(event_list) = events {
                            for event in event_list {
                                let record = DataRecord {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    source_id: source_id.to_string(),
                                    timestamp: Utc::now(),
                                    data: event.clone(),
                                    metadata: serde_json::json!({
                                        "vendor": vendor_name,
                                        "source_type": "edr"
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("Generic EDR API error: {}", e),
        }

        log::info!("Ingested {} events from {}", records.len(), vendor_name);
        Ok(records)
    }
}

/// Sysmon connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonConnector {
    pub event_log_path: String,
    pub forward_to: Option<String>,
}

impl SysmonConnector {
    #[allow(dead_code)]
    pub fn new(event_log_path: String) -> Self {
        Self {
            event_log_path,
            forward_to: None,
        }
    }

    /// Ingest Sysmon events
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting Sysmon events from: {}", self.event_log_path);

        let mut records = Vec::new();

        // Read events from file or Windows Event Log
        match tokio::fs::read_to_string(&self.event_log_path).await {
            Ok(content) => {
                // Parse as EVTX XML export or JSON lines
                if content.trim().starts_with('<') {
                    // XML format - parse Sysmon events
                    let mut pos = 0;
                    while let Some(event_start) = content[pos..].find("<Event") {
                        let abs_start = pos + event_start;
                        if let Some(event_end) = content[abs_start..].find("</Event>") {
                            let event_xml = &content[abs_start..abs_start + event_end + 8];
                            if let Ok(record) = self.parse_event(source_id, event_xml) {
                                records.push(record);
                            }
                            pos = abs_start + event_end + 8;
                        } else {
                            break;
                        }
                    }
                } else {
                    // JSON lines format (from Winlogbeat or similar)
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
                            let record = DataRecord {
                                id: event.get("record_id")
                                    .and_then(|r| r.as_u64())
                                    .map(|r| r.to_string())
                                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                source_id: source_id.to_string(),
                                timestamp: event.get("@timestamp")
                                    .or_else(|| event.get("timestamp"))
                                    .and_then(|t| t.as_str())
                                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                    .map(|dt| dt.with_timezone(&Utc))
                                    .unwrap_or_else(Utc::now),
                                data: event,
                                metadata: serde_json::json!({
                                    "source_type": "sysmon",
                                    "format": "json"
                                }),
                            };
                            records.push(record);
                        }
                    }
                }
            }
            Err(e) => log::warn!("Failed to read Sysmon log file: {}", e),
        }

        log::info!("Ingested {} Sysmon events", records.len());
        Ok(records)
    }

    /// Parse Sysmon event XML
    #[allow(dead_code)]
    pub fn parse_event(&self, source_id: &str, event_xml: &str) -> Result<DataRecord> {
        let mut data = serde_json::Map::new();
        data.insert("raw_xml".to_string(), serde_json::Value::String(event_xml.to_string()));

        let mut timestamp = Utc::now();

        // Extract System elements
        if let Some(system_content) = extract_xml_tag(event_xml, "System") {
            // Event ID
            if let Some(event_id) = extract_xml_tag(&system_content, "EventID") {
                data.insert("event_id".to_string(), serde_json::Value::String(event_id));
            }

            // Time Created
            if let Some(time_created) = extract_xml_attr(&system_content, "TimeCreated", "SystemTime") {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&time_created) {
                    timestamp = dt.with_timezone(&Utc);
                }
                data.insert("timestamp_str".to_string(), serde_json::Value::String(time_created));
            }

            // Computer
            if let Some(computer) = extract_xml_tag(&system_content, "Computer") {
                data.insert("computer".to_string(), serde_json::Value::String(computer));
            }

            // Provider
            if let Some(provider) = extract_xml_attr(&system_content, "Provider", "Name") {
                data.insert("provider".to_string(), serde_json::Value::String(provider));
            }
        }

        // Extract EventData elements
        if let Some(event_data) = extract_xml_tag(event_xml, "EventData") {
            let mut event_fields = serde_json::Map::new();

            // Parse Data elements with Name attribute
            let mut pos = 0;
            while let Some(data_start) = event_data[pos..].find("<Data Name=\"") {
                let abs_start = pos + data_start + 12;
                if let Some(name_end) = event_data[abs_start..].find('"') {
                    let name = &event_data[abs_start..abs_start + name_end];

                    // Find the value
                    let value_start = abs_start + name_end + 2;
                    if let Some(data_end) = event_data[value_start..].find("</Data>") {
                        let value = &event_data[value_start..value_start + data_end];
                        event_fields.insert(name.to_string(), serde_json::Value::String(value.to_string()));
                        pos = value_start + data_end;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            data.insert("event_data".to_string(), serde_json::Value::Object(event_fields));
        }

        // Determine Sysmon event type
        if let Some(event_id) = data.get("event_id").and_then(|e| e.as_str()) {
            let event_type = match event_id {
                "1" => "ProcessCreate",
                "2" => "FileCreateTime",
                "3" => "NetworkConnect",
                "4" => "SysmonServiceStateChange",
                "5" => "ProcessTerminate",
                "6" => "DriverLoad",
                "7" => "ImageLoad",
                "8" => "CreateRemoteThread",
                "9" => "RawAccessRead",
                "10" => "ProcessAccess",
                "11" => "FileCreate",
                "12" => "RegistryAddOrDelete",
                "13" => "RegistryValueSet",
                "14" => "RegistryRename",
                "15" => "FileCreateStreamHash",
                "16" => "SysmonConfigChange",
                "17" => "PipeCreated",
                "18" => "PipeConnected",
                "19" => "WmiEventFilter",
                "20" => "WmiEventConsumer",
                "21" => "WmiEventConsumerToFilter",
                "22" => "DNSQuery",
                "23" => "FileDelete",
                "24" => "ClipboardChange",
                "25" => "ProcessTampering",
                "26" => "FileDeleteDetected",
                "27" => "FileBlockExecutable",
                "28" => "FileBlockShredding",
                "29" => "FileExecutableDetected",
                _ => "Unknown",
            };
            data.insert("event_type".to_string(), serde_json::Value::String(event_type.to_string()));
        }

        Ok(DataRecord {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: source_id.to_string(),
            timestamp,
            data: serde_json::Value::Object(data),
            metadata: serde_json::json!({
                "source_type": "sysmon"
            }),
        })
    }
}

/// Extract content of an XML tag
fn extract_xml_tag(xml: &str, tag_name: &str) -> Option<String> {
    let open_tag = format!("<{}", tag_name);
    let close_tag = format!("</{}>", tag_name);

    if let Some(open_start) = xml.find(&open_tag) {
        if let Some(content_start) = xml[open_start..].find('>') {
            let abs_content_start = open_start + content_start + 1;
            if let Some(close_start) = xml[abs_content_start..].find(&close_tag) {
                return Some(xml[abs_content_start..abs_content_start + close_start].to_string());
            }
        }
    }
    None
}

/// Extract XML attribute value from a specific element
fn extract_xml_attr(xml: &str, element: &str, attr: &str) -> Option<String> {
    let open_tag = format!("<{}", element);
    if let Some(elem_start) = xml.find(&open_tag) {
        let attr_pattern = format!("{}=\"", attr);
        if let Some(attr_start) = xml[elem_start..].find(&attr_pattern) {
            let value_start = elem_start + attr_start + attr_pattern.len();
            if let Some(value_end) = xml[value_start..].find('"') {
                return Some(xml[value_start..value_start + value_end].to_string());
            }
        }
    }
    None
}

/// osquery connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryConnector {
    pub tls_hostname: String,
    pub enroll_secret: String,
}

impl OsqueryConnector {
    #[allow(dead_code)]
    pub fn new(tls_hostname: String, enroll_secret: String) -> Self {
        Self {
            tls_hostname,
            enroll_secret,
        }
    }

    /// Start osquery TLS server
    #[allow(dead_code)]
    pub async fn start(&self) -> Result<()> {
        log::info!("Starting osquery TLS server at: {}", self.tls_hostname);

        // osquery TLS server endpoints:
        // POST /enroll - Node enrollment
        // POST /config - Configuration retrieval
        // POST /log - Log submission
        // POST /distributed/read - Distributed query retrieval
        // POST /distributed/write - Distributed query results

        // The actual server would be implemented as an Actix-web service
        // Here we provide the configuration and endpoint structure

        log::info!("osquery TLS server configured with endpoints:");
        log::info!("  POST /enroll - Node enrollment");
        log::info!("  POST /config - Configuration retrieval");
        log::info!("  POST /log - Log submission");
        log::info!("  POST /distributed/read - Query retrieval");
        log::info!("  POST /distributed/write - Query results");

        Ok(())
    }

    /// Handle osquery enrollment
    #[allow(dead_code)]
    pub async fn handle_enrollment(&self, enroll_secret: &str, host_identifier: &str) -> Result<String> {
        log::info!("Processing osquery enrollment for host: {}", host_identifier);

        // Validate enrollment secret
        if enroll_secret != self.enroll_secret {
            anyhow::bail!("Invalid enrollment secret");
        }

        // Generate node key
        let node_key = uuid::Uuid::new_v4().to_string();

        log::info!("Enrolled node {} with key {}", host_identifier, &node_key[..8]);
        Ok(node_key)
    }

    /// Handle osquery log submission
    #[allow(dead_code)]
    pub async fn handle_log(&self, source_id: &str, log_data: &str) -> Result<Vec<DataRecord>> {
        let mut records = Vec::new();

        // Parse osquery JSON log format
        // osquery logs come in batches with format:
        // { "node_key": "...", "log_type": "result|status", "data": [...] }

        if let Ok(log_batch) = serde_json::from_str::<serde_json::Value>(log_data) {
            let log_type = log_batch.get("log_type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            if let Some(data_array) = log_batch.get("data").and_then(|d| d.as_array()) {
                for entry in data_array {
                    let record = self.parse_osquery_entry(source_id, entry, log_type);
                    records.push(record);
                }
            }
        } else {
            // Try parsing as newline-delimited JSON
            for line in log_data.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                    let log_type = entry.get("log_type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("result");
                    let record = self.parse_osquery_entry(source_id, &entry, log_type);
                    records.push(record);
                }
            }
        }

        log::info!("Processed {} osquery log entries", records.len());
        Ok(records)
    }

    fn parse_osquery_entry(&self, source_id: &str, entry: &serde_json::Value, log_type: &str) -> DataRecord {
        // Extract common osquery fields
        let name = entry.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown_query");

        let hostname = entry.get("hostIdentifier")
            .or_else(|| entry.get("host_identifier"))
            .and_then(|h| h.as_str())
            .unwrap_or("unknown");

        let unix_time = entry.get("unixTime")
            .or_else(|| entry.get("unix_time"))
            .and_then(|t| t.as_i64())
            .unwrap_or(0);

        let timestamp = if unix_time > 0 {
            chrono::DateTime::from_timestamp(unix_time, 0).unwrap_or_else(Utc::now)
        } else {
            Utc::now()
        };

        // Build enriched data
        let mut data = serde_json::Map::new();
        data.insert("query_name".to_string(), serde_json::Value::String(name.to_string()));
        data.insert("hostname".to_string(), serde_json::Value::String(hostname.to_string()));
        data.insert("log_type".to_string(), serde_json::Value::String(log_type.to_string()));

        // Add columns (query results)
        if let Some(columns) = entry.get("columns") {
            data.insert("columns".to_string(), columns.clone());
        }

        // Add action (added, removed, snapshot)
        if let Some(action) = entry.get("action") {
            data.insert("action".to_string(), action.clone());
        }

        // Add decorations
        if let Some(decorations) = entry.get("decorations") {
            data.insert("decorations".to_string(), decorations.clone());
        }

        // Add original entry for complete data
        data.insert("raw".to_string(), entry.clone());

        DataRecord {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: source_id.to_string(),
            timestamp,
            data: serde_json::Value::Object(data),
            metadata: serde_json::json!({
                "source_type": "osquery",
                "query_name": name,
                "log_type": log_type
            }),
        }
    }
}

/// Endpoint connector factory
#[allow(dead_code)]
pub enum EndpointConnector {
    EDR(EDRConnector),
    Sysmon(SysmonConnector),
    Osquery(OsqueryConnector),
}

impl EndpointConnector {
    /// Ingest data from the endpoint connector
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        match self {
            EndpointConnector::EDR(connector) => connector.ingest(source_id).await,
            EndpointConnector::Sysmon(connector) => connector.ingest(source_id).await,
            EndpointConnector::Osquery(_) => {
                // osquery is push-based, not pull-based
                Ok(Vec::new())
            }
        }
    }
}

/// Parse process execution event
#[allow(dead_code)]
pub fn parse_process_event(
    source_id: &str,
    process_name: &str,
    command_line: &str,
    pid: u32,
    parent_pid: u32,
    user: &str,
) -> DataRecord {
    DataRecord {
        id: uuid::Uuid::new_v4().to_string(),
        source_id: source_id.to_string(),
        timestamp: Utc::now(),
        data: serde_json::json!({
            "process_name": process_name,
            "command_line": command_line,
            "pid": pid,
            "parent_pid": parent_pid,
            "user": user
        }),
        metadata: serde_json::json!({
            "source_type": "process_execution"
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edr_connector_creation() {
        let connector = EDRConnector::new(
            "https://api.crowdstrike.com".to_string(),
            "test-key".to_string(),
            EDRVendor::CrowdStrike,
        );

        assert_eq!(connector.vendor, EDRVendor::CrowdStrike);
    }

    #[test]
    fn test_parse_process_event() {
        let record = parse_process_event(
            "source1",
            "cmd.exe",
            "cmd.exe /c whoami",
            1234,
            5678,
            "SYSTEM",
        );

        assert_eq!(record.data["process_name"], "cmd.exe");
        assert_eq!(record.data["pid"], 1234);
    }
}
