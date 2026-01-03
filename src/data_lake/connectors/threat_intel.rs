use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::data_lake::types::DataRecord;

/// Threat intelligence feed connector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConnector {
    pub feed_type: ThreatIntelFeedType,
    pub config: ThreatIntelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatIntelFeedType {
    STIX,
    TAXII,
    OpenIOC,
    MISP,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub url: String,
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub poll_interval_seconds: u64,
}

impl ThreatIntelConnector {
    #[allow(dead_code)]
    pub fn new(feed_type: ThreatIntelFeedType, config: ThreatIntelConfig) -> Self {
        Self { feed_type, config }
    }

    /// Ingest threat intelligence data
    #[allow(dead_code)]
    pub async fn ingest(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        match self.feed_type {
            ThreatIntelFeedType::STIX => self.ingest_stix(source_id).await,
            ThreatIntelFeedType::TAXII => self.ingest_taxii(source_id).await,
            ThreatIntelFeedType::OpenIOC => self.ingest_openioc(source_id).await,
            ThreatIntelFeedType::MISP => self.ingest_misp(source_id).await,
            ThreatIntelFeedType::Custom => self.ingest_custom(source_id).await,
        }
    }

    async fn ingest_stix(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting STIX threat intel from: {}", self.config.url);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        let mut request = client.get(&self.config.url)
            .header("Accept", "application/stix+json;version=2.1")
            .header("Content-Type", "application/stix+json;version=2.1");

        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        if let Ok(stix_bundle) = serde_json::from_str::<serde_json::Value>(&text) {
                            // Parse STIX 2.1 bundle format
                            if let Some(objects) = stix_bundle.get("objects").and_then(|o| o.as_array()) {
                                for obj in objects {
                                    let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");

                                    // Extract indicators, attack patterns, malware, etc.
                                    let record = DataRecord {
                                        id: obj.get("id").and_then(|i| i.as_str())
                                            .map(|s| s.to_string())
                                            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                        source_id: source_id.to_string(),
                                        timestamp: obj.get("created").and_then(|c| c.as_str())
                                            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                            .map(|dt| dt.with_timezone(&Utc))
                                            .unwrap_or_else(Utc::now),
                                        data: obj.clone(),
                                        metadata: serde_json::json!({
                                            "format": "stix",
                                            "version": "2.1",
                                            "object_type": obj_type,
                                            "feed_url": self.config.url
                                        }),
                                    };
                                    records.push(record);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("Failed to fetch STIX feed: {}", e),
        }

        log::info!("Ingested {} STIX objects from feed", records.len());
        Ok(records)
    }

    async fn ingest_taxii(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting TAXII threat intel from: {}", self.config.url);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // TAXII 2.1 discovery endpoint
        let discovery_url = format!("{}/taxii2/", self.config.url.trim_end_matches('/'));

        let mut request = client.get(&discovery_url)
            .header("Accept", "application/taxii+json;version=2.1");

        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        } else if let (Some(user), Some(pass)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(user, Some(pass));
        }

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(discovery) = response.json::<serde_json::Value>().await {
                        // Get API roots
                        if let Some(api_roots) = discovery.get("api_roots").and_then(|r| r.as_array()) {
                            for api_root in api_roots {
                                if let Some(root_url) = api_root.as_str() {
                                    // Fetch collections from each API root
                                    let collections_url = format!("{}/collections/", root_url.trim_end_matches('/'));
                                    if let Ok(coll_response) = client.get(&collections_url)
                                        .header("Accept", "application/taxii+json;version=2.1")
                                        .send().await
                                    {
                                        if let Ok(collections) = coll_response.json::<serde_json::Value>().await {
                                            if let Some(colls) = collections.get("collections").and_then(|c| c.as_array()) {
                                                for coll in colls {
                                                    if let Some(coll_id) = coll.get("id").and_then(|i| i.as_str()) {
                                                        // Fetch objects from collection
                                                        let objects_url = format!("{}/collections/{}/objects/",
                                                            root_url.trim_end_matches('/'), coll_id);

                                                        if let Ok(obj_response) = client.get(&objects_url)
                                                            .header("Accept", "application/stix+json;version=2.1")
                                                            .send().await
                                                        {
                                                            if let Ok(envelope) = obj_response.json::<serde_json::Value>().await {
                                                                if let Some(objects) = envelope.get("objects").and_then(|o| o.as_array()) {
                                                                    for obj in objects {
                                                                        let record = DataRecord {
                                                                            id: uuid::Uuid::new_v4().to_string(),
                                                                            source_id: source_id.to_string(),
                                                                            timestamp: Utc::now(),
                                                                            data: obj.clone(),
                                                                            metadata: serde_json::json!({
                                                                                "format": "taxii",
                                                                                "version": "2.1",
                                                                                "collection_id": coll_id,
                                                                                "api_root": root_url
                                                                            }),
                                                                        };
                                                                        records.push(record);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("Failed to connect to TAXII server: {}", e),
        }

        log::info!("Ingested {} TAXII objects", records.len());
        Ok(records)
    }

    async fn ingest_openioc(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting OpenIOC threat intel from: {}", self.config.url);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        let mut request = client.get(&self.config.url);
        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        // Parse OpenIOC XML format
                        // OpenIOC structure: <ioc> -> <definition> -> <Indicator> with IndicatorItems
                        let iocs = parse_openioc_xml(&text);

                        for ioc in iocs {
                            let record = DataRecord {
                                id: ioc.id.clone(),
                                source_id: source_id.to_string(),
                                timestamp: ioc.last_modified.unwrap_or_else(Utc::now),
                                data: serde_json::json!({
                                    "id": ioc.id,
                                    "name": ioc.name,
                                    "author": ioc.author,
                                    "description": ioc.description,
                                    "indicators": ioc.indicators,
                                    "keywords": ioc.keywords
                                }),
                                metadata: serde_json::json!({
                                    "format": "openioc",
                                    "feed_url": self.config.url
                                }),
                            };
                            records.push(record);
                        }
                    }
                }
            }
            Err(e) => log::warn!("Failed to fetch OpenIOC feed: {}", e),
        }

        log::info!("Ingested {} OpenIOC indicators", records.len());
        Ok(records)
    }

    async fn ingest_misp(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting MISP threat intel from: {}", self.config.url);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        // MISP API requires Authorization header with API key
        let api_key = self.config.api_key.clone().unwrap_or_default();

        // Fetch recent events
        let events_url = format!("{}/events/index", self.config.url.trim_end_matches('/'));

        let request = client.get(&events_url)
            .header("Authorization", api_key.clone())
            .header("Accept", "application/json")
            .header("Content-Type", "application/json");

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(events) = response.json::<serde_json::Value>().await {
                        if let Some(event_list) = events.as_array() {
                            for event_summary in event_list.iter().take(100) {
                                // Get full event details
                                if let Some(event_id) = event_summary.get("Event")
                                    .and_then(|e| e.get("id"))
                                    .and_then(|i| i.as_str())
                                {
                                    let event_url = format!("{}/events/view/{}",
                                        self.config.url.trim_end_matches('/'), event_id);

                                    if let Ok(event_response) = client.get(&event_url)
                                        .header("Authorization", api_key.clone())
                                        .header("Accept", "application/json")
                                        .send().await
                                    {
                                        if let Ok(event_data) = event_response.json::<serde_json::Value>().await {
                                            if let Some(event) = event_data.get("Event") {
                                                // Extract attributes (IOCs)
                                                if let Some(attributes) = event.get("Attribute").and_then(|a| a.as_array()) {
                                                    for attr in attributes {
                                                        let attr_type = attr.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                                        let attr_value = attr.get("value").and_then(|v| v.as_str()).unwrap_or("");

                                                        let record = DataRecord {
                                                            id: attr.get("uuid").and_then(|u| u.as_str())
                                                                .map(|s| s.to_string())
                                                                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                                                            source_id: source_id.to_string(),
                                                            timestamp: attr.get("timestamp").and_then(|t| t.as_str())
                                                                .and_then(|s| s.parse::<i64>().ok())
                                                                .map(|ts| chrono::DateTime::from_timestamp(ts, 0)
                                                                    .unwrap_or_else(Utc::now))
                                                                .unwrap_or_else(Utc::now),
                                                            data: serde_json::json!({
                                                                "type": attr_type,
                                                                "value": attr_value,
                                                                "category": attr.get("category"),
                                                                "to_ids": attr.get("to_ids"),
                                                                "comment": attr.get("comment"),
                                                                "event_id": event_id,
                                                                "event_info": event.get("info")
                                                            }),
                                                            metadata: serde_json::json!({
                                                                "format": "misp",
                                                                "feed_url": self.config.url
                                                            }),
                                                        };
                                                        records.push(record);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("Failed to connect to MISP: {}", e),
        }

        log::info!("Ingested {} MISP attributes", records.len());
        Ok(records)
    }

    async fn ingest_custom(&self, source_id: &str) -> Result<Vec<DataRecord>> {
        log::info!("Ingesting custom threat intel from: {}", self.config.url);

        let mut records = Vec::new();
        let client = reqwest::Client::new();

        let mut request = client.get(&self.config.url);

        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        } else if let (Some(user), Some(pass)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(user, Some(pass));
        }

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        // Try to parse as JSON
                        if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&text) {
                            // Handle array of indicators
                            if let Some(arr) = json_data.as_array() {
                                for item in arr {
                                    let record = DataRecord {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        source_id: source_id.to_string(),
                                        timestamp: Utc::now(),
                                        data: item.clone(),
                                        metadata: serde_json::json!({
                                            "format": "custom_json",
                                            "feed_url": self.config.url
                                        }),
                                    };
                                    records.push(record);
                                }
                            } else {
                                // Single object
                                let record = DataRecord {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    source_id: source_id.to_string(),
                                    timestamp: Utc::now(),
                                    data: json_data,
                                    metadata: serde_json::json!({
                                        "format": "custom_json",
                                        "feed_url": self.config.url
                                    }),
                                };
                                records.push(record);
                            }
                        } else {
                            // Parse as plain text (one IOC per line)
                            for line in text.lines() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') {
                                    continue;
                                }

                                // Detect IOC type
                                let ioc_type = detect_ioc_type(line);

                                let record = DataRecord {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    source_id: source_id.to_string(),
                                    timestamp: Utc::now(),
                                    data: serde_json::json!({
                                        "type": ioc_type,
                                        "value": line
                                    }),
                                    metadata: serde_json::json!({
                                        "format": "custom_text",
                                        "feed_url": self.config.url
                                    }),
                                };
                                records.push(record);
                            }
                        }
                    }
                }
            }
            Err(e) => log::warn!("Failed to fetch custom feed: {}", e),
        }

        log::info!("Ingested {} custom indicators", records.len());
        Ok(records)
    }

    /// Parse STIX indicator
    #[allow(dead_code)]
    pub fn parse_stix_indicator(&self, source_id: &str, stix_json: &str) -> Result<DataRecord> {
        let stix_data: serde_json::Value = serde_json::from_str(stix_json)?;

        Ok(DataRecord {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: source_id.to_string(),
            timestamp: Utc::now(),
            data: stix_data,
            metadata: serde_json::json!({
                "format": "stix",
                "feed_type": "threat_intel"
            }),
        })
    }
}

/// Parsed OpenIOC structure
#[derive(Debug, Clone)]
struct ParsedOpenIOC {
    id: String,
    name: String,
    author: String,
    description: String,
    indicators: Vec<serde_json::Value>,
    keywords: Vec<String>,
    last_modified: Option<chrono::DateTime<Utc>>,
}

/// Parse OpenIOC XML format
fn parse_openioc_xml(xml: &str) -> Vec<ParsedOpenIOC> {
    let mut iocs = Vec::new();

    // Simple XML parsing without external dependency
    // Extract IOC elements from the XML
    let mut current_pos = 0;
    while let Some(ioc_start) = xml[current_pos..].find("<ioc ") {
        let abs_start = current_pos + ioc_start;
        if let Some(ioc_end) = xml[abs_start..].find("</ioc>") {
            let ioc_xml = &xml[abs_start..abs_start + ioc_end + 6];

            // Extract attributes
            let id = extract_xml_attr(ioc_xml, "id").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let last_modified = extract_xml_attr(ioc_xml, "last-modified")
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            // Extract child elements
            let name = extract_xml_element(ioc_xml, "short_description").unwrap_or_default();
            let author = extract_xml_element(ioc_xml, "authored_by").unwrap_or_default();
            let description = extract_xml_element(ioc_xml, "description").unwrap_or_default();

            // Extract keywords
            let mut keywords = Vec::new();
            let mut kw_pos = 0;
            while let Some(kw_start) = ioc_xml[kw_pos..].find("<keyword>") {
                if let Some(kw_end) = ioc_xml[kw_pos + kw_start..].find("</keyword>") {
                    let keyword = &ioc_xml[kw_pos + kw_start + 9..kw_pos + kw_start + kw_end];
                    keywords.push(keyword.to_string());
                    kw_pos = kw_pos + kw_start + kw_end;
                } else {
                    break;
                }
            }

            // Extract indicator items
            let mut indicators = Vec::new();
            let mut ind_pos = 0;
            while let Some(ind_start) = ioc_xml[ind_pos..].find("<IndicatorItem ") {
                if let Some(ind_end) = ioc_xml[ind_pos + ind_start..].find("</IndicatorItem>") {
                    let ind_xml = &ioc_xml[ind_pos + ind_start..ind_pos + ind_start + ind_end + 16];

                    let condition = extract_xml_attr(ind_xml, "condition").unwrap_or_default();
                    let context = extract_xml_element(ind_xml, "Context")
                        .and_then(|c| extract_xml_attr(&c, "search"))
                        .unwrap_or_default();
                    let content = extract_xml_element(ind_xml, "Content").unwrap_or_default();
                    let content_type = extract_xml_element(ind_xml, "Content")
                        .and_then(|c| extract_xml_attr(&c, "type"))
                        .unwrap_or_default();

                    indicators.push(serde_json::json!({
                        "condition": condition,
                        "context": context,
                        "content": content,
                        "content_type": content_type
                    }));

                    ind_pos = ind_pos + ind_start + ind_end;
                } else {
                    break;
                }
            }

            iocs.push(ParsedOpenIOC {
                id,
                name,
                author,
                description,
                indicators,
                keywords,
                last_modified,
            });

            current_pos = abs_start + ioc_end + 6;
        } else {
            break;
        }
    }

    iocs
}

/// Extract XML attribute value
fn extract_xml_attr(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name);
    if let Some(start) = xml.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = xml[value_start..].find('"') {
            return Some(xml[value_start..value_start + end].to_string());
        }
    }
    None
}

/// Extract XML element content
fn extract_xml_element(xml: &str, element_name: &str) -> Option<String> {
    let open_tag = format!("<{}", element_name);
    let close_tag = format!("</{}>", element_name);

    if let Some(open_start) = xml.find(&open_tag) {
        if let Some(content_start) = xml[open_start..].find('>') {
            let abs_content_start = open_start + content_start + 1;
            if let Some(close_start) = xml[abs_content_start..].find(&close_tag) {
                return Some(xml[abs_content_start..abs_content_start + close_start].trim().to_string());
            }
        }
    }
    None
}

/// Detect IOC type from value
fn detect_ioc_type(value: &str) -> &'static str {
    // IPv4 address
    if value.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return "ipv4";
        }
    }

    // IPv6 address
    if value.contains(':') && value.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        return "ipv6";
    }

    // Domain name
    if value.contains('.') && !value.contains('/') && !value.contains('@') {
        let domain_chars = value.chars().all(|c|
            c.is_alphanumeric() || c == '.' || c == '-'
        );
        if domain_chars {
            return "domain";
        }
    }

    // URL
    if value.starts_with("http://") || value.starts_with("https://") {
        return "url";
    }

    // Email
    if value.contains('@') && value.contains('.') {
        return "email";
    }

    // MD5 hash (32 hex chars)
    if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "md5";
    }

    // SHA1 hash (40 hex chars)
    if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha1";
    }

    // SHA256 hash (64 hex chars)
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha256";
    }

    // SHA512 hash (128 hex chars)
    if value.len() == 128 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha512";
    }

    // CVE ID
    if value.starts_with("CVE-") {
        return "cve";
    }

    // File path
    if value.starts_with('/') || value.starts_with("C:\\") || value.contains("\\") {
        return "filepath";
    }

    "unknown"
}

/// IOC (Indicator of Compromise) from threat intel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelIOC {
    pub ioc_type: String,
    pub value: String,
    pub confidence: f64,
    pub severity: String,
    pub tags: Vec<String>,
    pub first_seen: chrono::DateTime<Utc>,
    pub last_seen: chrono::DateTime<Utc>,
    pub source: String,
}

/// Convert threat intel data to IOC
///
/// Parses various threat intelligence formats and extracts IOCs:
/// - STIX 2.x indicators
/// - MISP attributes
/// - OpenIOC indicators
/// - Generic JSON with indicators array
/// - Plain text IOC values
#[allow(dead_code)]
pub fn extract_iocs_from_feed(record: &DataRecord) -> Vec<ThreatIntelIOC> {
    let mut iocs = Vec::new();
    let now = Utc::now();

    // Check metadata for format hint
    let format = record.metadata.get("format")
        .and_then(|f| f.as_str())
        .unwrap_or("unknown");

    match format {
        "stix" => {
            // STIX 2.x format - extract from indicator objects
            extract_stix_iocs(&record.data, &record.source_id, &mut iocs);
        }
        "misp" => {
            // MISP format - attributes are the IOCs
            extract_misp_iocs(&record.data, &record.source_id, &mut iocs);
        }
        "openioc" => {
            // OpenIOC format - parse indicator items
            extract_openioc_iocs(&record.data, &record.source_id, &mut iocs);
        }
        "taxii" => {
            // TAXII delivers STIX objects
            extract_stix_iocs(&record.data, &record.source_id, &mut iocs);
        }
        _ => {
            // Generic format - try to find IOCs in common structures
            extract_generic_iocs(&record.data, &record.source_id, &mut iocs);
        }
    }

    // Also scan the raw data for any IOC patterns we might have missed
    if iocs.is_empty() {
        let data_str = serde_json::to_string(&record.data).unwrap_or_default();
        extract_iocs_from_text(&data_str, &record.source_id, &mut iocs);
    }

    // Set timestamps for any IOCs that don't have them
    for ioc in &mut iocs {
        if ioc.first_seen == chrono::DateTime::<Utc>::MIN_UTC {
            ioc.first_seen = record.timestamp;
        }
        if ioc.last_seen == chrono::DateTime::<Utc>::MIN_UTC {
            ioc.last_seen = now;
        }
    }

    iocs
}

/// Extract IOCs from STIX 2.x format
fn extract_stix_iocs(data: &serde_json::Value, source_id: &str, iocs: &mut Vec<ThreatIntelIOC>) {
    // STIX indicator pattern format: [type:field = 'value']
    if let Some(pattern) = data.get("pattern").and_then(|p| p.as_str()) {
        if let Some(ioc) = parse_stix_pattern(pattern, source_id) {
            iocs.push(ioc);
        }
    }

    // Check for indicator objects in a bundle
    if let Some(objects) = data.get("objects").and_then(|o| o.as_array()) {
        for obj in objects {
            if obj.get("type").and_then(|t| t.as_str()) == Some("indicator") {
                if let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) {
                    if let Some(mut ioc) = parse_stix_pattern(pattern, source_id) {
                        // Enrich with STIX metadata
                        if let Some(labels) = obj.get("labels").and_then(|l| l.as_array()) {
                            ioc.tags = labels.iter()
                                .filter_map(|l| l.as_str().map(|s| s.to_string()))
                                .collect();
                        }
                        if let Some(confidence) = obj.get("confidence").and_then(|c| c.as_u64()) {
                            ioc.confidence = (confidence as f64) / 100.0;
                        }
                        if let Some(created) = obj.get("created").and_then(|c| c.as_str()) {
                            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created) {
                                ioc.first_seen = dt.with_timezone(&Utc);
                            }
                        }
                        iocs.push(ioc);
                    }
                }
            }
        }
    }

    // Check for observables
    if let Some(obs) = data.get("observable").or(data.get("observed_data")) {
        if let Some(objects) = obs.get("objects").and_then(|o| o.as_object()) {
            for (_key, obj) in objects {
                if let Some(ioc) = extract_observable_ioc(obj, source_id) {
                    iocs.push(ioc);
                }
            }
        }
    }
}

/// Parse a STIX pattern string into an IOC
fn parse_stix_pattern(pattern: &str, source_id: &str) -> Option<ThreatIntelIOC> {
    // Pattern format examples:
    // [ipv4-addr:value = '192.168.1.1']
    // [domain-name:value = 'malware.com']
    // [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']
    // [url:value = 'http://malware.com/payload']

    let pattern = pattern.trim();
    if !pattern.starts_with('[') || !pattern.ends_with(']') {
        return None;
    }

    let inner = &pattern[1..pattern.len()-1];

    // Split on comparison operators
    for op in &["=", "LIKE", "MATCHES"] {
        if let Some(pos) = inner.find(op) {
            let type_field = inner[..pos].trim();
            let value_part = inner[pos + op.len()..].trim();

            // Extract the value (remove quotes)
            let value = value_part.trim_matches(|c| c == '\'' || c == '"').to_string();
            if value.is_empty() {
                continue;
            }

            // Determine IOC type from STIX type
            let ioc_type = if type_field.starts_with("ipv4-addr") {
                "ipv4"
            } else if type_field.starts_with("ipv6-addr") {
                "ipv6"
            } else if type_field.starts_with("domain-name") {
                "domain"
            } else if type_field.starts_with("url") {
                "url"
            } else if type_field.starts_with("email") {
                "email"
            } else if type_field.contains("hashes.MD5") || type_field.contains("hashes.'MD5'") {
                "md5"
            } else if type_field.contains("hashes.SHA-1") || type_field.contains("hashes.'SHA-1'") {
                "sha1"
            } else if type_field.contains("hashes.SHA-256") || type_field.contains("hashes.'SHA-256'") {
                "sha256"
            } else if type_field.starts_with("file") {
                "file"
            } else {
                "unknown"
            };

            return Some(ThreatIntelIOC {
                ioc_type: ioc_type.to_string(),
                value,
                confidence: 0.8,
                severity: "medium".to_string(),
                tags: vec!["stix".to_string()],
                first_seen: chrono::DateTime::<Utc>::MIN_UTC,
                last_seen: chrono::DateTime::<Utc>::MIN_UTC,
                source: source_id.to_string(),
            });
        }
    }

    None
}

/// Extract IOC from STIX observable object
fn extract_observable_ioc(obj: &serde_json::Value, source_id: &str) -> Option<ThreatIntelIOC> {
    let obj_type = obj.get("type").and_then(|t| t.as_str())?;
    let value = obj.get("value").and_then(|v| v.as_str())?;

    let ioc_type = match obj_type {
        "ipv4-addr" => "ipv4",
        "ipv6-addr" => "ipv6",
        "domain-name" => "domain",
        "url" => "url",
        "email-addr" => "email",
        _ => return None,
    };

    Some(ThreatIntelIOC {
        ioc_type: ioc_type.to_string(),
        value: value.to_string(),
        confidence: 0.7,
        severity: "medium".to_string(),
        tags: vec!["stix-observable".to_string()],
        first_seen: chrono::DateTime::<Utc>::MIN_UTC,
        last_seen: chrono::DateTime::<Utc>::MIN_UTC,
        source: source_id.to_string(),
    })
}

/// Extract IOCs from MISP format
fn extract_misp_iocs(data: &serde_json::Value, source_id: &str, iocs: &mut Vec<ThreatIntelIOC>) {
    // MISP attribute types map to IOC types
    let misp_type_map: std::collections::HashMap<&str, &str> = [
        ("ip-src", "ipv4"), ("ip-dst", "ipv4"),
        ("ip-src|port", "ipv4"), ("ip-dst|port", "ipv4"),
        ("domain", "domain"), ("hostname", "domain"),
        ("url", "url"), ("link", "url"),
        ("email-src", "email"), ("email-dst", "email"),
        ("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256"),
        ("filename", "filename"), ("filename|md5", "filename"),
    ].iter().cloned().collect();

    // Parse MISP data directly if it's an attribute
    if let (Some(attr_type), Some(value)) = (
        data.get("type").and_then(|t| t.as_str()),
        data.get("value").and_then(|v| v.as_str()),
    ) {
        let ioc_type = misp_type_map.get(attr_type).unwrap_or(&"unknown");

        // Parse composite types (e.g., "ip-src|port" -> extract IP)
        let clean_value = if value.contains('|') {
            value.split('|').next().unwrap_or(value)
        } else {
            value
        };

        let mut tags = vec!["misp".to_string()];
        if let Some(category) = data.get("category").and_then(|c| c.as_str()) {
            tags.push(category.to_string());
        }

        let confidence = if data.get("to_ids").and_then(|t| t.as_bool()).unwrap_or(false) {
            0.9
        } else {
            0.6
        };

        iocs.push(ThreatIntelIOC {
            ioc_type: ioc_type.to_string(),
            value: clean_value.to_string(),
            confidence,
            severity: "medium".to_string(),
            tags,
            first_seen: data.get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(|s| s.parse::<i64>().ok())
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                .unwrap_or_else(|| chrono::DateTime::<Utc>::MIN_UTC),
            last_seen: chrono::DateTime::<Utc>::MIN_UTC,
            source: source_id.to_string(),
        });
    }
}

/// Extract IOCs from OpenIOC format
fn extract_openioc_iocs(data: &serde_json::Value, source_id: &str, iocs: &mut Vec<ThreatIntelIOC>) {
    // OpenIOC stores indicators in an array
    if let Some(indicators) = data.get("indicators").and_then(|i| i.as_array()) {
        for indicator in indicators {
            let context = indicator.get("context").and_then(|c| c.as_str()).unwrap_or("");
            let content = indicator.get("content").and_then(|c| c.as_str()).unwrap_or("");

            if content.is_empty() {
                continue;
            }

            // Map OpenIOC context to IOC type
            let ioc_type = if context.contains("Network/DNS") {
                "domain"
            } else if context.contains("Network/URI") {
                "url"
            } else if context.contains("PortItem/remoteIP") || context.contains("Network/IP") {
                "ipv4"
            } else if context.contains("FileItem/Md5sum") {
                "md5"
            } else if context.contains("FileItem/Sha1sum") {
                "sha1"
            } else if context.contains("FileItem/Sha256sum") {
                "sha256"
            } else if context.contains("FileItem/FileName") {
                "filename"
            } else if context.contains("Email") {
                "email"
            } else {
                detect_ioc_type(content)
            };

            iocs.push(ThreatIntelIOC {
                ioc_type: ioc_type.to_string(),
                value: content.to_string(),
                confidence: 0.7,
                severity: "medium".to_string(),
                tags: vec!["openioc".to_string()],
                first_seen: chrono::DateTime::<Utc>::MIN_UTC,
                last_seen: chrono::DateTime::<Utc>::MIN_UTC,
                source: source_id.to_string(),
            });
        }
    }
}

/// Extract IOCs from generic JSON format
fn extract_generic_iocs(data: &serde_json::Value, source_id: &str, iocs: &mut Vec<ThreatIntelIOC>) {
    // Try common array field names
    for field in &["indicators", "iocs", "observables", "data", "results", "items"] {
        if let Some(arr) = data.get(*field).and_then(|v| v.as_array()) {
            for item in arr {
                if let (Some(ioc_type), Some(value)) = (
                    item.get("type").or(item.get("ioc_type")).and_then(|v| v.as_str()),
                    item.get("value").or(item.get("indicator")).and_then(|v| v.as_str()),
                ) {
                    iocs.push(ThreatIntelIOC {
                        ioc_type: ioc_type.to_string(),
                        value: value.to_string(),
                        confidence: item.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.5),
                        severity: item.get("severity").and_then(|v| v.as_str()).unwrap_or("medium").to_string(),
                        tags: item.get("tags")
                            .and_then(|t| t.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                        first_seen: chrono::DateTime::<Utc>::MIN_UTC,
                        last_seen: chrono::DateTime::<Utc>::MIN_UTC,
                        source: source_id.to_string(),
                    });
                }
            }
            return; // Found data, stop looking
        }
    }

    // Try flat structure
    if let (Some(ioc_type), Some(value)) = (
        data.get("type").and_then(|v| v.as_str()),
        data.get("value").and_then(|v| v.as_str()),
    ) {
        iocs.push(ThreatIntelIOC {
            ioc_type: ioc_type.to_string(),
            value: value.to_string(),
            confidence: data.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.5),
            severity: data.get("severity").and_then(|v| v.as_str()).unwrap_or("medium").to_string(),
            tags: Vec::new(),
            first_seen: chrono::DateTime::<Utc>::MIN_UTC,
            last_seen: chrono::DateTime::<Utc>::MIN_UTC,
            source: source_id.to_string(),
        });
    }
}

/// Extract IOCs from plain text using pattern matching
fn extract_iocs_from_text(text: &str, source_id: &str, iocs: &mut Vec<ThreatIntelIOC>) {
    // IPv4 addresses
    let ipv4_regex = regex::Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").ok();
    if let Some(re) = ipv4_regex {
        for cap in re.find_iter(text) {
            let ip = cap.as_str();
            // Skip common non-malicious IPs
            if !ip.starts_with("127.") && !ip.starts_with("0.") && ip != "255.255.255.255" {
                if !iocs.iter().any(|i| i.value == ip) {
                    iocs.push(ThreatIntelIOC {
                        ioc_type: "ipv4".to_string(),
                        value: ip.to_string(),
                        confidence: 0.5,
                        severity: "low".to_string(),
                        tags: vec!["extracted".to_string()],
                        first_seen: chrono::DateTime::<Utc>::MIN_UTC,
                        last_seen: chrono::DateTime::<Utc>::MIN_UTC,
                        source: source_id.to_string(),
                    });
                }
            }
        }
    }

    // MD5 hashes (32 hex chars)
    let md5_regex = regex::Regex::new(r"\b[a-fA-F0-9]{32}\b").ok();
    if let Some(re) = md5_regex {
        for cap in re.find_iter(text) {
            let hash = cap.as_str().to_lowercase();
            if !iocs.iter().any(|i| i.value == hash) {
                iocs.push(ThreatIntelIOC {
                    ioc_type: "md5".to_string(),
                    value: hash,
                    confidence: 0.6,
                    severity: "low".to_string(),
                    tags: vec!["extracted".to_string()],
                    first_seen: chrono::DateTime::<Utc>::MIN_UTC,
                    last_seen: chrono::DateTime::<Utc>::MIN_UTC,
                    source: source_id.to_string(),
                });
            }
        }
    }

    // SHA256 hashes (64 hex chars)
    let sha256_regex = regex::Regex::new(r"\b[a-fA-F0-9]{64}\b").ok();
    if let Some(re) = sha256_regex {
        for cap in re.find_iter(text) {
            let hash = cap.as_str().to_lowercase();
            if !iocs.iter().any(|i| i.value == hash) {
                iocs.push(ThreatIntelIOC {
                    ioc_type: "sha256".to_string(),
                    value: hash,
                    confidence: 0.6,
                    severity: "low".to_string(),
                    tags: vec!["extracted".to_string()],
                    first_seen: chrono::DateTime::<Utc>::MIN_UTC,
                    last_seen: chrono::DateTime::<Utc>::MIN_UTC,
                    source: source_id.to_string(),
                });
            }
        }
    }

    // URLs
    let url_regex = regex::Regex::new(r#"https?://[^\s"'<>\]\)]+"#).ok();
    if let Some(re) = url_regex {
        for cap in re.find_iter(text) {
            let url = cap.as_str().trim_end_matches(|c| c == ',' || c == '.');
            if !iocs.iter().any(|i| i.value == url) {
                iocs.push(ThreatIntelIOC {
                    ioc_type: "url".to_string(),
                    value: url.to_string(),
                    confidence: 0.5,
                    severity: "low".to_string(),
                    tags: vec!["extracted".to_string()],
                    first_seen: chrono::DateTime::<Utc>::MIN_UTC,
                    last_seen: chrono::DateTime::<Utc>::MIN_UTC,
                    source: source_id.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_intel_connector_creation() {
        let config = ThreatIntelConfig {
            url: "https://threat-feed.example.com".to_string(),
            api_key: Some("test-key".to_string()),
            username: None,
            password: None,
            poll_interval_seconds: 3600,
        };

        let connector = ThreatIntelConnector::new(ThreatIntelFeedType::STIX, config);

        assert_eq!(connector.feed_type, ThreatIntelFeedType::STIX);
        assert_eq!(connector.config.poll_interval_seconds, 3600);
    }

    #[test]
    fn test_extract_iocs() {
        let record = DataRecord {
            id: "test1".to_string(),
            source_id: "threat_feed".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "indicators": [
                    {
                        "type": "ip",
                        "value": "192.0.2.1",
                        "confidence": 0.9,
                        "severity": "high"
                    }
                ]
            }),
            metadata: serde_json::json!({}),
        };

        let iocs = extract_iocs_from_feed(&record);
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].ioc_type, "ip");
        assert_eq!(iocs[0].value, "192.0.2.1");
    }
}
