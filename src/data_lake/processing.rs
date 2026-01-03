use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use chrono::{DateTime, Utc, Duration};

use super::types::{DataRecord, EnrichmentConfig, DataQualityMetrics, DataQualityIssue};

/// GeoIP lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpResult {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub asn: Option<String>,
    pub organization: Option<String>,
}

/// Threat intel enrichment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelResult {
    pub checked: bool,
    pub threats_found: Vec<ThreatMatch>,
    pub risk_score: f64,
    pub last_checked: DateTime<Utc>,
}

/// A matched threat from threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatMatch {
    pub indicator: String,
    pub indicator_type: String,
    pub threat_type: String,
    pub severity: String,
    pub source: String,
    pub confidence: f64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub description: Option<String>,
}

/// Asset correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetCorrelationResult {
    pub correlated: bool,
    pub asset_id: Option<String>,
    pub asset_name: Option<String>,
    pub asset_type: Option<String>,
    pub criticality: Option<String>,
    pub owner: Option<String>,
    pub department: Option<String>,
    pub location: Option<String>,
    pub tags: Vec<String>,
}

/// User enrichment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEnrichmentResult {
    pub username: String,
    pub found: bool,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub department: Option<String>,
    pub title: Option<String>,
    pub manager: Option<String>,
    pub location: Option<String>,
    pub is_privileged: bool,
    pub groups: Vec<String>,
    pub risk_level: String,
}

/// Data processing pipeline
pub struct ProcessingPipeline {
    enrichment_config: EnrichmentConfig,
    /// Simple in-memory GeoIP data for common ranges (production would use MaxMind GeoIP)
    geoip_data: HashMap<String, GeoIpResult>,
    /// Known threat indicators (production would query external threat intel feeds)
    threat_indicators: HashMap<String, ThreatMatch>,
    /// Asset inventory cache (production would query database)
    asset_cache: HashMap<String, AssetCorrelationResult>,
    /// User directory cache (production would query LDAP/AD)
    user_cache: HashMap<String, UserEnrichmentResult>,
}

impl ProcessingPipeline {
    pub fn new(enrichment_config: EnrichmentConfig) -> Self {
        Self {
            enrichment_config,
            geoip_data: Self::init_geoip_data(),
            threat_indicators: Self::init_threat_indicators(),
            asset_cache: HashMap::new(),
            user_cache: HashMap::new(),
        }
    }

    /// Initialize sample GeoIP data for well-known IP ranges
    fn init_geoip_data() -> HashMap<String, GeoIpResult> {
        let mut data = HashMap::new();

        // Google DNS
        data.insert("8.8.8.8".to_string(), GeoIpResult {
            ip: "8.8.8.8".to_string(),
            country: "United States".to_string(),
            country_code: "US".to_string(),
            region: "California".to_string(),
            city: "Mountain View".to_string(),
            latitude: 37.4056,
            longitude: -122.0775,
            timezone: "America/Los_Angeles".to_string(),
            asn: Some("AS15169".to_string()),
            organization: Some("Google LLC".to_string()),
        });

        // Cloudflare DNS
        data.insert("1.1.1.1".to_string(), GeoIpResult {
            ip: "1.1.1.1".to_string(),
            country: "Australia".to_string(),
            country_code: "AU".to_string(),
            region: "New South Wales".to_string(),
            city: "Sydney".to_string(),
            latitude: -33.8688,
            longitude: 151.2093,
            timezone: "Australia/Sydney".to_string(),
            asn: Some("AS13335".to_string()),
            organization: Some("Cloudflare, Inc.".to_string()),
        });

        data
    }

    /// Initialize sample threat indicators
    fn init_threat_indicators() -> HashMap<String, ThreatMatch> {
        let mut indicators = HashMap::new();

        // Sample malicious IP (for demonstration)
        indicators.insert("192.168.100.100".to_string(), ThreatMatch {
            indicator: "192.168.100.100".to_string(),
            indicator_type: "ip".to_string(),
            threat_type: "command_and_control".to_string(),
            severity: "high".to_string(),
            source: "internal_intel".to_string(),
            confidence: 0.85,
            first_seen: Some(Utc::now() - Duration::days(30)),
            last_seen: Some(Utc::now() - Duration::days(1)),
            description: Some("Known C2 server associated with malware campaign".to_string()),
        });

        // Sample malicious domain
        indicators.insert("malware.example.com".to_string(), ThreatMatch {
            indicator: "malware.example.com".to_string(),
            indicator_type: "domain".to_string(),
            threat_type: "malware_distribution".to_string(),
            severity: "critical".to_string(),
            source: "threat_feed".to_string(),
            confidence: 0.95,
            first_seen: Some(Utc::now() - Duration::days(7)),
            last_seen: Some(Utc::now()),
            description: Some("Active malware distribution domain".to_string()),
        });

        indicators
    }

    /// Process incoming data record
    #[allow(dead_code)]
    pub async fn process_record(&self, mut record: DataRecord) -> Result<DataRecord> {
        // Apply enrichments
        if self.enrichment_config.enabled {
            record = self.enrich_record(record).await?;
        }

        // Normalize data
        record = self.normalize_record(record)?;

        // Validate quality
        let _ = self.validate_quality(&record)?;

        Ok(record)
    }

    async fn enrich_record(&self, mut record: DataRecord) -> Result<DataRecord> {
        // GeoIP enrichment
        if self.enrichment_config.geo_ip {
            record = self.enrich_geo_ip(record).await?;
        }

        // Threat intel enrichment
        if self.enrichment_config.threat_intel {
            record = self.enrich_threat_intel(record).await?;
        }

        // Asset correlation
        if self.enrichment_config.asset_correlation {
            record = self.enrich_asset_correlation(record).await?;
        }

        // User enrichment
        if self.enrichment_config.user_enrichment {
            record = self.enrich_user_data(record).await?;
        }

        Ok(record)
    }

    async fn enrich_geo_ip(&self, mut record: DataRecord) -> Result<DataRecord> {
        // Extract all IP fields from the data record
        let ip_fields = ["src_ip", "dst_ip", "source_ip", "destination_ip", "ip_address", "client_ip", "server_ip"];
        let mut geo_enrichments = serde_json::Map::new();

        for field in &ip_fields {
            if let Some(ip_value) = record.data.get(*field).and_then(|v| v.as_str()) {
                if let Ok(geo_result) = self.lookup_geo_ip(ip_value).await {
                    geo_enrichments.insert(
                        format!("{}_geo", field),
                        serde_json::to_value(&geo_result)?,
                    );
                }
            }
        }

        // Add enrichments to metadata
        if !geo_enrichments.is_empty() {
            let metadata = record.metadata.as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("Metadata is not an object"))?;
            metadata.insert("geo_ip".to_string(), serde_json::Value::Object(geo_enrichments));
        }

        Ok(record)
    }

    /// Perform GeoIP lookup for a given IP address
    async fn lookup_geo_ip(&self, ip: &str) -> Result<GeoIpResult> {
        // First check the cache
        if let Some(result) = self.geoip_data.get(ip) {
            return Ok(result.clone());
        }

        // Parse the IP address
        let ip_addr: IpAddr = ip.parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip))?;

        // Determine basic geo info based on IP ranges
        // In production, this would use MaxMind GeoLite2 or similar database
        let (country, country_code, city, lat, lng) = match ip_addr {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Check for private/local network ranges
                let is_private = match octets[0] {
                    10 => true,
                    172 => (16..=31).contains(&octets[1]),
                    192 => octets[1] == 168,
                    127 => true,
                    _ => false,
                };

                if octets[0] == 127 {
                    ("Localhost", "XX", "Local", 0.0, 0.0)
                } else if is_private {
                    ("Private Network", "XX", "Local", 0.0, 0.0)
                } else {
                    // For other IPs, provide a default (production would use real GeoIP DB)
                    ("Unknown", "ZZ", "Unknown", 0.0, 0.0)
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() {
                    ("Localhost", "XX", "Local", 0.0, 0.0)
                } else {
                    ("Unknown", "ZZ", "Unknown", 0.0, 0.0)
                }
            }
        };

        Ok(GeoIpResult {
            ip: ip.to_string(),
            country: country.to_string(),
            country_code: country_code.to_string(),
            region: "Unknown".to_string(),
            city: city.to_string(),
            latitude: lat,
            longitude: lng,
            timezone: "UTC".to_string(),
            asn: None,
            organization: None,
        })
    }

    async fn enrich_threat_intel(&self, mut record: DataRecord) -> Result<DataRecord> {
        let mut threats_found = Vec::new();
        let mut risk_score: f64 = 0.0;

        // Extract IOCs from the record
        let iocs = self.extract_iocs(&record)?;

        // Check each IOC against threat intelligence
        for (ioc_type, ioc_value) in iocs {
            if let Some(threat) = self.check_threat_indicator(&ioc_value, &ioc_type).await {
                // Adjust risk score based on severity
                let severity_weight = match threat.severity.as_str() {
                    "critical" => 1.0,
                    "high" => 0.8,
                    "medium" => 0.5,
                    "low" => 0.2,
                    _ => 0.1,
                };
                risk_score = (risk_score + severity_weight * threat.confidence).min(1.0);
                threats_found.push(threat);
            }
        }

        // Add threat intel enrichment to metadata
        let threat_result = ThreatIntelResult {
            checked: true,
            threats_found,
            risk_score,
            last_checked: Utc::now(),
        };

        let metadata = record.metadata.as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Metadata is not an object"))?;
        metadata.insert("threat_intel".to_string(), serde_json::to_value(&threat_result)?);

        Ok(record)
    }

    /// Extract IOCs (Indicators of Compromise) from a data record
    fn extract_iocs(&self, record: &DataRecord) -> Result<Vec<(String, String)>> {
        let mut iocs = Vec::new();

        // Define fields to check for different IOC types
        let ip_fields = ["src_ip", "dst_ip", "source_ip", "destination_ip", "ip_address", "client_ip", "server_ip"];
        let domain_fields = ["domain", "hostname", "host", "fqdn", "dns_query"];
        let hash_fields = ["md5", "sha1", "sha256", "file_hash", "hash"];
        let url_fields = ["url", "uri", "request_url"];
        let email_fields = ["email", "sender", "recipient", "from", "to"];

        // Extract IPs
        for field in &ip_fields {
            if let Some(value) = record.data.get(*field).and_then(|v| v.as_str()) {
                if !value.is_empty() {
                    iocs.push(("ip".to_string(), value.to_string()));
                }
            }
        }

        // Extract domains
        for field in &domain_fields {
            if let Some(value) = record.data.get(*field).and_then(|v| v.as_str()) {
                if !value.is_empty() && value.contains('.') {
                    iocs.push(("domain".to_string(), value.to_string()));
                }
            }
        }

        // Extract hashes
        for field in &hash_fields {
            if let Some(value) = record.data.get(*field).and_then(|v| v.as_str()) {
                if !value.is_empty() {
                    let hash_type = self.detect_hash_type(value);
                    iocs.push((hash_type, value.to_string()));
                }
            }
        }

        // Extract URLs
        for field in &url_fields {
            if let Some(value) = record.data.get(*field).and_then(|v| v.as_str()) {
                if value.starts_with("http://") || value.starts_with("https://") {
                    iocs.push(("url".to_string(), value.to_string()));
                }
            }
        }

        // Extract emails
        for field in &email_fields {
            if let Some(value) = record.data.get(*field).and_then(|v| v.as_str()) {
                if value.contains('@') && value.contains('.') {
                    iocs.push(("email".to_string(), value.to_string()));
                }
            }
        }

        Ok(iocs)
    }

    /// Detect the type of hash based on its length
    fn detect_hash_type(&self, hash: &str) -> String {
        match hash.len() {
            32 if hash.chars().all(|c| c.is_ascii_hexdigit()) => "md5".to_string(),
            40 if hash.chars().all(|c| c.is_ascii_hexdigit()) => "sha1".to_string(),
            64 if hash.chars().all(|c| c.is_ascii_hexdigit()) => "sha256".to_string(),
            _ => "hash".to_string(),
        }
    }

    /// Check if an IOC matches any known threat indicators
    async fn check_threat_indicator(&self, value: &str, ioc_type: &str) -> Option<ThreatMatch> {
        // Check direct match in threat indicators
        if let Some(threat) = self.threat_indicators.get(value) {
            return Some(threat.clone());
        }

        // For IPs, check if any indicator is in the same subnet (simplified)
        if ioc_type == "ip" {
            if let Some(prefix) = value.rsplit('.').skip(1).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".").chars().take(value.len().saturating_sub(4)).collect::<String>().chars().take(10).collect::<String>().split('.').take(3).collect::<Vec<_>>().join(".").chars().next() {
                for (indicator, threat) in &self.threat_indicators {
                    if threat.indicator_type == "ip" && indicator.starts_with(&value[..value.rfind('.').unwrap_or(0)]) {
                        return Some(ThreatMatch {
                            indicator: value.to_string(),
                            indicator_type: "ip".to_string(),
                            threat_type: threat.threat_type.clone(),
                            severity: "medium".to_string(), // Lower severity for subnet match
                            source: threat.source.clone(),
                            confidence: threat.confidence * 0.5,
                            first_seen: threat.first_seen,
                            last_seen: threat.last_seen,
                            description: Some(format!("Related to known threat in same subnet: {}", indicator)),
                        });
                    }
                }
            }
        }

        // For domains, check for subdomain matches
        if ioc_type == "domain" {
            for (indicator, threat) in &self.threat_indicators {
                if threat.indicator_type == "domain" {
                    // Check if value is a subdomain of a known bad domain
                    if value.ends_with(&format!(".{}", indicator)) || value == indicator {
                        return Some(ThreatMatch {
                            indicator: value.to_string(),
                            indicator_type: "domain".to_string(),
                            threat_type: threat.threat_type.clone(),
                            severity: threat.severity.clone(),
                            source: threat.source.clone(),
                            confidence: if value == indicator { threat.confidence } else { threat.confidence * 0.8 },
                            first_seen: threat.first_seen,
                            last_seen: threat.last_seen,
                            description: threat.description.clone(),
                        });
                    }
                }
            }
        }

        None
    }

    async fn enrich_asset_correlation(&self, mut record: DataRecord) -> Result<DataRecord> {
        // Extract identifiers that can be correlated to assets
        let ip = record.data.get("src_ip")
            .or_else(|| record.data.get("ip_address"))
            .or_else(|| record.data.get("host"))
            .and_then(|v| v.as_str());

        let hostname = record.data.get("hostname")
            .or_else(|| record.data.get("computer_name"))
            .or_else(|| record.data.get("device_name"))
            .and_then(|v| v.as_str());

        let mac = record.data.get("mac_address")
            .or_else(|| record.data.get("mac"))
            .and_then(|v| v.as_str());

        // Try to correlate with asset inventory
        let correlation_result = self.correlate_asset(ip, hostname, mac).await?;

        // Add correlation result to metadata
        let metadata = record.metadata.as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Metadata is not an object"))?;
        metadata.insert("asset".to_string(), serde_json::to_value(&correlation_result)?);

        Ok(record)
    }

    /// Correlate data with asset inventory
    async fn correlate_asset(
        &self,
        ip: Option<&str>,
        hostname: Option<&str>,
        mac: Option<&str>,
    ) -> Result<AssetCorrelationResult> {
        // Check cache first
        let cache_key = format!("{}:{}:{}",
            ip.unwrap_or(""),
            hostname.unwrap_or(""),
            mac.unwrap_or("")
        );

        if let Some(cached) = self.asset_cache.get(&cache_key) {
            return Ok(cached.clone());
        }

        // In production, this would query the asset database
        // For now, provide intelligent defaults based on available data
        let mut result = AssetCorrelationResult {
            correlated: false,
            asset_id: None,
            asset_name: None,
            asset_type: None,
            criticality: None,
            owner: None,
            department: None,
            location: None,
            tags: Vec::new(),
        };

        // Try to infer asset information from hostname patterns
        if let Some(name) = hostname {
            result.correlated = true;
            result.asset_name = Some(name.to_string());

            // Common naming convention patterns
            let name_lower = name.to_lowercase();

            // Detect asset type from hostname
            result.asset_type = Some(if name_lower.contains("srv") || name_lower.contains("server") {
                "server".to_string()
            } else if name_lower.contains("ws") || name_lower.contains("desktop") || name_lower.contains("pc") {
                "workstation".to_string()
            } else if name_lower.contains("lap") || name_lower.contains("laptop") || name_lower.contains("nb") {
                "laptop".to_string()
            } else if name_lower.contains("fw") || name_lower.contains("firewall") {
                "firewall".to_string()
            } else if name_lower.contains("sw") || name_lower.contains("switch") {
                "switch".to_string()
            } else if name_lower.contains("rt") || name_lower.contains("router") {
                "router".to_string()
            } else if name_lower.contains("db") || name_lower.contains("database") {
                "database_server".to_string()
            } else if name_lower.contains("web") || name_lower.contains("www") {
                "web_server".to_string()
            } else if name_lower.contains("app") {
                "application_server".to_string()
            } else {
                "unknown".to_string()
            });

            // Detect department/location from hostname
            if name_lower.contains("hr-") || name_lower.contains("-hr") {
                result.department = Some("Human Resources".to_string());
            } else if name_lower.contains("fin-") || name_lower.contains("-fin") {
                result.department = Some("Finance".to_string());
            } else if name_lower.contains("it-") || name_lower.contains("-it") {
                result.department = Some("Information Technology".to_string());
            } else if name_lower.contains("dev-") || name_lower.contains("-dev") {
                result.department = Some("Development".to_string());
            } else if name_lower.contains("eng-") || name_lower.contains("-eng") {
                result.department = Some("Engineering".to_string());
            }

            // Determine criticality based on asset type
            result.criticality = Some(match result.asset_type.as_deref() {
                Some("database_server") | Some("firewall") => "critical".to_string(),
                Some("web_server") | Some("application_server") | Some("server") => "high".to_string(),
                Some("workstation") | Some("laptop") => "medium".to_string(),
                _ => "low".to_string(),
            });

            // Generate a pseudo asset ID
            result.asset_id = Some(format!("ASSET-{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()));
        }

        // If we have an IP but no hostname, create basic correlation
        if !result.correlated && ip.is_some() {
            result.correlated = true;
            result.asset_id = Some(format!("ASSET-{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()));
        }

        Ok(result)
    }

    async fn enrich_user_data(&self, mut record: DataRecord) -> Result<DataRecord> {
        // Extract username from various possible fields
        let username = record.data.get("username")
            .or_else(|| record.data.get("user"))
            .or_else(|| record.data.get("user_name"))
            .or_else(|| record.data.get("account_name"))
            .or_else(|| record.data.get("sam_account_name"))
            .and_then(|v| v.as_str());

        if let Some(user) = username {
            let user_result = self.lookup_user(user).await?;

            let metadata = record.metadata.as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("Metadata is not an object"))?;
            metadata.insert("user".to_string(), serde_json::to_value(&user_result)?);
        }

        Ok(record)
    }

    /// Look up user information from directory service
    async fn lookup_user(&self, username: &str) -> Result<UserEnrichmentResult> {
        // Check cache first
        if let Some(cached) = self.user_cache.get(username) {
            return Ok(cached.clone());
        }

        // In production, this would query LDAP/Active Directory
        // For now, provide intelligent defaults based on username patterns
        let username_lower = username.to_lowercase();

        // Detect privileged accounts
        let is_privileged = username_lower.starts_with("admin")
            || username_lower.starts_with("root")
            || username_lower.starts_with("svc_")
            || username_lower.starts_with("sa_")
            || username_lower.contains("_admin")
            || username_lower == "administrator"
            || username_lower == "system"
            || username_lower.ends_with("$"); // Machine accounts

        // Detect service accounts
        let is_service_account = username_lower.starts_with("svc_")
            || username_lower.starts_with("srv_")
            || username_lower.starts_with("sa_")
            || username_lower.ends_with("$");

        // Determine risk level
        let risk_level = if is_privileged {
            "high".to_string()
        } else if is_service_account {
            "medium".to_string()
        } else {
            "low".to_string()
        };

        // Determine groups based on username pattern
        let mut groups = Vec::new();
        if is_privileged {
            groups.push("Domain Admins".to_string());
            groups.push("Administrators".to_string());
        }
        if is_service_account {
            groups.push("Service Accounts".to_string());
        }
        groups.push("Domain Users".to_string());

        // Determine title/department from username if possible
        let (title, department) = if username_lower.contains("hr") {
            (Some("HR Specialist".to_string()), Some("Human Resources".to_string()))
        } else if username_lower.contains("dev") {
            (Some("Developer".to_string()), Some("Engineering".to_string()))
        } else if username_lower.contains("fin") {
            (Some("Financial Analyst".to_string()), Some("Finance".to_string()))
        } else if username_lower.contains("sec") {
            (Some("Security Analyst".to_string()), Some("Security".to_string()))
        } else if is_service_account {
            (Some("Service Account".to_string()), Some("IT Operations".to_string()))
        } else {
            (None, None)
        };

        Ok(UserEnrichmentResult {
            username: username.to_string(),
            found: true,
            display_name: Some(format_username_display(username)),
            email: Some(format!("{}@example.com", username_lower.replace(" ", "."))),
            department,
            title,
            manager: None,
            location: None,
            is_privileged,
            groups,
            risk_level,
        })
    }

    fn normalize_record(&self, mut record: DataRecord) -> Result<DataRecord> {
        // Get mutable reference to data object
        if let Some(data_obj) = record.data.as_object_mut() {
            let mut normalized_fields: Vec<(String, serde_json::Value)> = Vec::new();

            // Field name normalization mappings
            let field_mappings: HashMap<&str, &str> = [
                // Timestamp fields
                ("@timestamp", "timestamp"),
                ("event_time", "timestamp"),
                ("eventTime", "timestamp"),
                ("time", "timestamp"),
                ("datetime", "timestamp"),
                ("date_time", "timestamp"),
                ("created_at", "timestamp"),
                ("log_time", "timestamp"),
                // Source IP fields
                ("sourceIP", "src_ip"),
                ("source_ip", "src_ip"),
                ("srcip", "src_ip"),
                ("srcIP", "src_ip"),
                ("src_addr", "src_ip"),
                ("client_ip", "src_ip"),
                ("clientIP", "src_ip"),
                // Destination IP fields
                ("destinationIP", "dst_ip"),
                ("destination_ip", "dst_ip"),
                ("dstip", "dst_ip"),
                ("dstIP", "dst_ip"),
                ("dst_addr", "dst_ip"),
                ("server_ip", "dst_ip"),
                ("serverIP", "dst_ip"),
                // Port fields
                ("sourcePort", "src_port"),
                ("source_port", "src_port"),
                ("srcport", "src_port"),
                ("destinationPort", "dst_port"),
                ("destination_port", "dst_port"),
                ("dstport", "dst_port"),
                // User fields
                ("userName", "username"),
                ("user_name", "username"),
                ("accountName", "username"),
                ("account_name", "username"),
                ("user_id", "username"),
                // Action/Event fields
                ("eventType", "event_type"),
                ("event_name", "event_type"),
                ("action", "event_type"),
                // Severity fields
                ("severity", "severity"),
                ("level", "severity"),
                ("priority", "severity"),
            ].iter().cloned().collect();

            // Normalize field names and collect changes
            for (old_name, new_name) in &field_mappings {
                if let Some(value) = data_obj.get(*old_name).cloned() {
                    if old_name != new_name {
                        normalized_fields.push((new_name.to_string(), value));
                    }
                }
            }

            // Apply normalized field names
            for (name, value) in normalized_fields {
                data_obj.insert(name, value);
            }

            // Normalize timestamp format to ISO 8601
            if let Some(timestamp) = data_obj.get("timestamp").cloned() {
                let normalized_ts = self.normalize_timestamp(&timestamp)?;
                data_obj.insert("normalized_timestamp".to_string(), normalized_ts);
            }

            // Normalize severity levels
            if let Some(severity) = data_obj.get("severity").and_then(|v| v.as_str()) {
                let normalized_severity = self.normalize_severity(severity);
                data_obj.insert("normalized_severity".to_string(), serde_json::json!(normalized_severity));
            }

            // Normalize IP addresses (remove leading zeros, validate format)
            for ip_field in &["src_ip", "dst_ip"] {
                if let Some(ip) = data_obj.get(*ip_field).and_then(|v| v.as_str()) {
                    if let Ok(normalized_ip) = self.normalize_ip(ip) {
                        data_obj.insert(format!("{}_normalized", ip_field), serde_json::json!(normalized_ip));
                    }
                }
            }

            // Normalize port numbers to integers
            for port_field in &["src_port", "dst_port"] {
                if let Some(port) = data_obj.get(*port_field) {
                    if let Some(port_str) = port.as_str() {
                        if let Ok(port_num) = port_str.parse::<u16>() {
                            data_obj.insert(format!("{}_int", port_field), serde_json::json!(port_num));
                        }
                    }
                }
            }
        }

        Ok(record)
    }

    /// Normalize timestamp to ISO 8601 format
    fn normalize_timestamp(&self, value: &serde_json::Value) -> Result<serde_json::Value> {
        let timestamp_str = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => {
                // Assume Unix timestamp
                if let Some(secs) = n.as_i64() {
                    let dt = DateTime::from_timestamp(secs, 0)
                        .unwrap_or_else(|| Utc::now());
                    return Ok(serde_json::json!(dt.to_rfc3339()));
                }
                return Err(anyhow::anyhow!("Invalid numeric timestamp"));
            }
            _ => return Err(anyhow::anyhow!("Invalid timestamp type")),
        };

        // Try various timestamp formats
        let formats = [
            "%Y-%m-%dT%H:%M:%S%.fZ",           // ISO 8601 with Z
            "%Y-%m-%dT%H:%M:%S%.f%:z",         // ISO 8601 with offset
            "%Y-%m-%dT%H:%M:%SZ",              // ISO 8601 without millis
            "%Y-%m-%d %H:%M:%S%.f",            // Common log format
            "%Y-%m-%d %H:%M:%S",               // Simple datetime
            "%d/%b/%Y:%H:%M:%S %z",            // Apache log format
            "%b %d %H:%M:%S",                  // Syslog format
            "%Y%m%d%H%M%S",                    // Compact format
        ];

        // Try RFC 3339 first (most common)
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&timestamp_str) {
            return Ok(serde_json::json!(dt.to_rfc3339()));
        }

        // Try RFC 2822
        if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(&timestamp_str) {
            return Ok(serde_json::json!(dt.to_rfc3339()));
        }

        // Try other formats
        for format in &formats {
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&timestamp_str, format) {
                let utc_dt = dt.and_utc();
                return Ok(serde_json::json!(utc_dt.to_rfc3339()));
            }
        }

        // If all parsing fails, return original value
        Ok(serde_json::json!(timestamp_str))
    }

    /// Normalize severity levels to a standard scale
    fn normalize_severity(&self, severity: &str) -> String {
        let s = severity.to_lowercase();
        match s.as_str() {
            // Critical
            "critical" | "crit" | "fatal" | "emergency" | "emerg" | "5" | "alert" => "critical".to_string(),
            // High
            "high" | "error" | "err" | "4" | "severe" => "high".to_string(),
            // Medium
            "medium" | "med" | "warning" | "warn" | "3" => "medium".to_string(),
            // Low
            "low" | "notice" | "2" => "low".to_string(),
            // Info
            "info" | "informational" | "information" | "1" | "debug" | "trace" | "0" => "info".to_string(),
            // Default
            _ => "unknown".to_string(),
        }
    }

    /// Normalize IP address format
    fn normalize_ip(&self, ip: &str) -> Result<String> {
        let addr: IpAddr = ip.parse()
            .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip))?;
        Ok(addr.to_string())
    }

    fn validate_quality(&self, record: &DataRecord) -> Result<DataQualityMetrics> {
        let mut issues = Vec::new();
        let mut completeness_score = 1.0;
        let mut accuracy_score = 1.0;

        // Check for required fields
        let required_fields = ["timestamp"];
        for field in &required_fields {
            if record.data.get(*field).is_none() {
                issues.push(DataQualityIssue {
                    issue_type: "missing_field".to_string(),
                    description: format!("Missing {} field", field),
                    severity: "high".to_string(),
                    count: 1,
                });
                completeness_score -= 0.2;
            }
        }

        // Check for null values
        let null_count = record.data.as_object().map(|obj| {
            obj.values().filter(|v| v.is_null()).count()
        }).unwrap_or(0);

        if null_count > 0 {
            issues.push(DataQualityIssue {
                issue_type: "null_values".to_string(),
                description: format!("Found {} null values", null_count),
                severity: "medium".to_string(),
                count: null_count as i64,
            });
            completeness_score -= 0.1 * (null_count as f64).min(5.0) / 5.0;
        }

        // Check data freshness (timeliness)
        let timeliness_score = self.calculate_timeliness_score(record);

        // Check format consistency
        let (consistency_score, consistency_issues) = self.calculate_consistency_score(record);
        issues.extend(consistency_issues);

        // Validate data accuracy
        let (accuracy_adj, accuracy_issues) = self.validate_accuracy(record);
        accuracy_score -= accuracy_adj;
        issues.extend(accuracy_issues);

        let overall_score = ((completeness_score + accuracy_score + timeliness_score + consistency_score) / 4.0)
            .max(0.0)
            .min(1.0);

        Ok(DataQualityMetrics {
            source_id: record.source_id.clone(),
            completeness_score: completeness_score.max(0.0),
            accuracy_score: accuracy_score.max(0.0),
            timeliness_score,
            consistency_score,
            overall_score,
            issues,
        })
    }

    /// Calculate timeliness score based on data freshness
    fn calculate_timeliness_score(&self, record: &DataRecord) -> f64 {
        let now = Utc::now();

        // Check record timestamp
        let record_age = now.signed_duration_since(record.timestamp);

        // Calculate score based on age
        // - Less than 1 minute: 1.0
        // - Less than 1 hour: 0.9
        // - Less than 24 hours: 0.7
        // - Less than 7 days: 0.5
        // - Older: 0.3
        if record_age.num_minutes() < 1 {
            1.0
        } else if record_age.num_hours() < 1 {
            0.95
        } else if record_age.num_hours() < 24 {
            0.8
        } else if record_age.num_days() < 7 {
            0.6
        } else if record_age.num_days() < 30 {
            0.4
        } else {
            0.2
        }
    }

    /// Calculate format consistency score
    fn calculate_consistency_score(&self, record: &DataRecord) -> (f64, Vec<DataQualityIssue>) {
        let mut score: f64 = 1.0;
        let mut issues = Vec::new();

        if let Some(data_obj) = record.data.as_object() {
            // Check IP address format consistency
            let ip_fields = ["src_ip", "dst_ip", "source_ip", "destination_ip"];
            for field in &ip_fields {
                if let Some(value) = data_obj.get(*field).and_then(|v| v.as_str()) {
                    if !self.is_valid_ip(value) {
                        issues.push(DataQualityIssue {
                            issue_type: "invalid_format".to_string(),
                            description: format!("Invalid IP format in field {}: {}", field, value),
                            severity: "medium".to_string(),
                            count: 1,
                        });
                        score -= 0.1;
                    }
                }
            }

            // Check port number consistency
            let port_fields = ["src_port", "dst_port", "source_port", "destination_port"];
            for field in &port_fields {
                if let Some(value) = data_obj.get(*field) {
                    let is_valid = match value {
                        serde_json::Value::Number(n) => {
                            n.as_u64().map(|p| p <= 65535).unwrap_or(false)
                        }
                        serde_json::Value::String(s) => {
                            s.parse::<u16>().is_ok()
                        }
                        _ => false,
                    };
                    if !is_valid {
                        issues.push(DataQualityIssue {
                            issue_type: "invalid_format".to_string(),
                            description: format!("Invalid port number in field {}", field),
                            severity: "low".to_string(),
                            count: 1,
                        });
                        score -= 0.05;
                    }
                }
            }

            // Check timestamp format consistency
            if let Some(timestamp) = data_obj.get("timestamp") {
                if let Some(ts_str) = timestamp.as_str() {
                    if chrono::DateTime::parse_from_rfc3339(ts_str).is_err() {
                        issues.push(DataQualityIssue {
                            issue_type: "inconsistent_format".to_string(),
                            description: "Timestamp not in ISO 8601 format".to_string(),
                            severity: "low".to_string(),
                            count: 1,
                        });
                        score -= 0.05;
                    }
                }
            }

            // Check for mixed case in enumerable fields
            let enum_fields = ["event_type", "severity", "protocol", "action"];
            for field in &enum_fields {
                if let Some(value) = data_obj.get(*field).and_then(|v| v.as_str()) {
                    let has_upper = value.chars().any(|c| c.is_uppercase());
                    let has_lower = value.chars().any(|c| c.is_lowercase());
                    if has_upper && has_lower && !value.contains('_') {
                        issues.push(DataQualityIssue {
                            issue_type: "inconsistent_case".to_string(),
                            description: format!("Mixed case in field {}: {}", field, value),
                            severity: "info".to_string(),
                            count: 1,
                        });
                        score -= 0.02;
                    }
                }
            }
        }

        (score.max(0.0), issues)
    }

    /// Validate data accuracy
    fn validate_accuracy(&self, record: &DataRecord) -> (f64, Vec<DataQualityIssue>) {
        let mut penalty = 0.0;
        let mut issues = Vec::new();

        if let Some(data_obj) = record.data.as_object() {
            // Check for impossible values
            // Port 0 is technically valid but unusual
            for field in &["src_port", "dst_port"] {
                if let Some(value) = data_obj.get(*field) {
                    let port = value.as_u64().or_else(|| {
                        value.as_str().and_then(|s| s.parse().ok())
                    });
                    if port == Some(0) {
                        issues.push(DataQualityIssue {
                            issue_type: "suspicious_value".to_string(),
                            description: format!("Port 0 in field {} is unusual", field),
                            severity: "info".to_string(),
                            count: 1,
                        });
                        penalty += 0.02;
                    }
                }
            }

            // Check for future timestamps
            if let Some(timestamp) = data_obj.get("timestamp").and_then(|v| v.as_str()) {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp) {
                    if dt.with_timezone(&Utc) > Utc::now() + Duration::hours(1) {
                        issues.push(DataQualityIssue {
                            issue_type: "future_timestamp".to_string(),
                            description: "Timestamp is in the future".to_string(),
                            severity: "high".to_string(),
                            count: 1,
                        });
                        penalty += 0.2;
                    }
                }
            }

            // Check for localhost IPs in external traffic
            for field in &["src_ip", "dst_ip"] {
                if let Some(ip) = data_obj.get(*field).and_then(|v| v.as_str()) {
                    if ip == "127.0.0.1" || ip == "::1" {
                        // This might be valid for local traffic, so just flag it
                        issues.push(DataQualityIssue {
                            issue_type: "localhost_address".to_string(),
                            description: format!("Localhost address in {}", field),
                            severity: "info".to_string(),
                            count: 1,
                        });
                    }
                }
            }
        }

        (penalty, issues)
    }

    /// Check if a string is a valid IP address
    fn is_valid_ip(&self, ip: &str) -> bool {
        ip.parse::<IpAddr>().is_ok()
    }
}

/// Format username for display (convert snake_case/camelCase to proper name)
fn format_username_display(username: &str) -> String {
    // Handle common patterns
    if username.contains('.') {
        // john.doe -> John Doe
        username
            .split('.')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    None => String::new(),
                    Some(c) => c.to_uppercase().chain(chars).collect(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else if username.contains('_') {
        // john_doe or svc_account -> John Doe or Svc Account
        username
            .split('_')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    None => String::new(),
                    Some(c) => c.to_uppercase().chain(chars).collect(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        // Return as-is with first letter capitalized
        let mut chars = username.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().chain(chars).collect(),
        }
    }
}

/// Batch processing for large data volumes
#[allow(dead_code)]
pub struct BatchProcessor {
    pipeline: ProcessingPipeline,
    batch_size: usize,
}

impl BatchProcessor {
    #[allow(dead_code)]
    pub fn new(pipeline: ProcessingPipeline, batch_size: usize) -> Self {
        Self { pipeline, batch_size }
    }

    /// Process a batch of records
    #[allow(dead_code)]
    pub async fn process_batch(&self, records: Vec<DataRecord>) -> Result<Vec<DataRecord>> {
        let mut processed = Vec::new();

        for chunk in records.chunks(self.batch_size) {
            for record in chunk {
                match self.pipeline.process_record(record.clone()).await {
                    Ok(processed_record) => processed.push(processed_record),
                    Err(e) => {
                        log::error!("Failed to process record {}: {}", record.id, e);
                        // Continue processing other records
                    }
                }
            }
        }

        Ok(processed)
    }
}

/// Stream processing for real-time data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamProcessor {
    pub id: String,
    pub source_id: String,
    pub enabled: bool,
    #[serde(skip)]
    buffer: Vec<DataRecord>,
    #[serde(skip)]
    buffer_size: usize,
    #[serde(skip)]
    flush_interval_ms: u64,
}

impl Default for StreamProcessor {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: String::new(),
            enabled: true,
            buffer: Vec::new(),
            buffer_size: 100,
            flush_interval_ms: 1000,
        }
    }
}

impl StreamProcessor {
    #[allow(dead_code)]
    pub fn new(source_id: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_id,
            enabled: true,
            buffer: Vec::new(),
            buffer_size: 100,
            flush_interval_ms: 1000,
        }
    }

    /// Configure stream processor
    #[allow(dead_code)]
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Configure flush interval
    #[allow(dead_code)]
    pub fn with_flush_interval(mut self, interval_ms: u64) -> Self {
        self.flush_interval_ms = interval_ms;
        self
    }

    /// Process streaming data record
    #[allow(dead_code)]
    pub async fn process_stream(&mut self, record: DataRecord) -> Result<Option<Vec<DataRecord>>> {
        if !self.enabled {
            return Err(anyhow::anyhow!("Stream processor is disabled"));
        }

        // Create processing pipeline with default enrichment config
        let config = EnrichmentConfig {
            enabled: true,
            geo_ip: true,
            threat_intel: true,
            asset_correlation: true,
            user_enrichment: true,
        };
        let pipeline = ProcessingPipeline::new(config);

        // Process the record through the pipeline
        let processed = pipeline.process_record(record).await?;

        // Add to buffer
        self.buffer.push(processed);

        // Check if buffer should be flushed
        if self.buffer.len() >= self.buffer_size {
            let flushed = std::mem::take(&mut self.buffer);
            Ok(Some(flushed))
        } else {
            Ok(None)
        }
    }

    /// Force flush the buffer
    #[allow(dead_code)]
    pub fn flush(&mut self) -> Vec<DataRecord> {
        std::mem::take(&mut self.buffer)
    }

    /// Get current buffer size
    #[allow(dead_code)]
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Start background stream processing
    #[allow(dead_code)]
    pub async fn start_background_processing(
        &self,
        mut receiver: tokio::sync::mpsc::Receiver<DataRecord>,
        sender: tokio::sync::mpsc::Sender<Vec<DataRecord>>,
    ) -> Result<()> {
        let config = EnrichmentConfig {
            enabled: true,
            geo_ip: true,
            threat_intel: true,
            asset_correlation: true,
            user_enrichment: true,
        };
        let pipeline = ProcessingPipeline::new(config);

        let buffer_size = self.buffer_size;
        let flush_interval = std::time::Duration::from_millis(self.flush_interval_ms);

        let mut buffer: Vec<DataRecord> = Vec::new();
        let mut last_flush = std::time::Instant::now();

        loop {
            tokio::select! {
                // Receive new record
                record = receiver.recv() => {
                    match record {
                        Some(rec) => {
                            // Process record
                            match pipeline.process_record(rec).await {
                                Ok(processed) => {
                                    buffer.push(processed);

                                    // Flush if buffer is full
                                    if buffer.len() >= buffer_size {
                                        let to_send = std::mem::take(&mut buffer);
                                        if sender.send(to_send).await.is_err() {
                                            log::warn!("Stream output channel closed");
                                            break;
                                        }
                                        last_flush = std::time::Instant::now();
                                    }
                                }
                                Err(e) => {
                                    log::error!("Failed to process stream record: {}", e);
                                }
                            }
                        }
                        None => {
                            // Channel closed, flush remaining and exit
                            if !buffer.is_empty() {
                                let _ = sender.send(buffer).await;
                            }
                            break;
                        }
                    }
                }

                // Periodic flush
                _ = tokio::time::sleep(flush_interval) => {
                    if !buffer.is_empty() && last_flush.elapsed() >= flush_interval {
                        let to_send = std::mem::take(&mut buffer);
                        if sender.send(to_send).await.is_err() {
                            log::warn!("Stream output channel closed");
                            break;
                        }
                        last_flush = std::time::Instant::now();
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_normalize_record() {
        let config = EnrichmentConfig {
            enabled: false,
            geo_ip: false,
            threat_intel: false,
            asset_correlation: false,
            user_enrichment: false,
        };

        let pipeline = ProcessingPipeline::new(config);

        let record = DataRecord {
            id: "test1".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "timestamp": "2025-01-01T00:00:00Z",
                "event": "login"
            }),
            metadata: serde_json::json!({}),
        };

        let normalized = pipeline.normalize_record(record).unwrap();
        assert!(normalized.data.get("normalized_timestamp").is_some());
    }

    #[tokio::test]
    async fn test_geo_ip_enrichment() {
        let config = EnrichmentConfig {
            enabled: true,
            geo_ip: true,
            threat_intel: false,
            asset_correlation: false,
            user_enrichment: false,
        };

        let pipeline = ProcessingPipeline::new(config);

        let record = DataRecord {
            id: "test1".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "src_ip": "8.8.8.8",
                "dst_ip": "1.1.1.1"
            }),
            metadata: serde_json::json!({}),
        };

        let enriched = pipeline.enrich_geo_ip(record).await.unwrap();
        let geo_data = enriched.metadata.get("geo_ip").unwrap();
        assert!(geo_data.get("src_ip_geo").is_some());
    }

    #[tokio::test]
    async fn test_threat_intel_enrichment() {
        let config = EnrichmentConfig {
            enabled: true,
            geo_ip: false,
            threat_intel: true,
            asset_correlation: false,
            user_enrichment: false,
        };

        let pipeline = ProcessingPipeline::new(config);

        let record = DataRecord {
            id: "test1".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "domain": "malware.example.com"
            }),
            metadata: serde_json::json!({}),
        };

        let enriched = pipeline.enrich_threat_intel(record).await.unwrap();
        let threat_data = enriched.metadata.get("threat_intel").unwrap();
        assert!(threat_data.get("checked").unwrap().as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_user_enrichment() {
        let config = EnrichmentConfig {
            enabled: true,
            geo_ip: false,
            threat_intel: false,
            asset_correlation: false,
            user_enrichment: true,
        };

        let pipeline = ProcessingPipeline::new(config);

        let record = DataRecord {
            id: "test1".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "username": "admin_user"
            }),
            metadata: serde_json::json!({}),
        };

        let enriched = pipeline.enrich_user_data(record).await.unwrap();
        let user_data = enriched.metadata.get("user").unwrap();
        assert!(user_data.get("is_privileged").unwrap().as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_asset_correlation() {
        let config = EnrichmentConfig {
            enabled: true,
            geo_ip: false,
            threat_intel: false,
            asset_correlation: true,
            user_enrichment: false,
        };

        let pipeline = ProcessingPipeline::new(config);

        let record = DataRecord {
            id: "test1".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "hostname": "srv-db-prod-01"
            }),
            metadata: serde_json::json!({}),
        };

        let enriched = pipeline.enrich_asset_correlation(record).await.unwrap();
        let asset_data = enriched.metadata.get("asset").unwrap();
        assert!(asset_data.get("correlated").unwrap().as_bool().unwrap());
        assert_eq!(asset_data.get("asset_type").unwrap().as_str().unwrap(), "server");
    }

    #[tokio::test]
    async fn test_data_quality_validation() {
        let config = EnrichmentConfig {
            enabled: false,
            geo_ip: false,
            threat_intel: false,
            asset_correlation: false,
            user_enrichment: false,
        };

        let pipeline = ProcessingPipeline::new(config);

        let record = DataRecord {
            id: "test1".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({
                "timestamp": "2025-01-01T00:00:00Z",
                "src_ip": "192.168.1.1",
                "dst_port": 443
            }),
            metadata: serde_json::json!({}),
        };

        let quality = pipeline.validate_quality(&record).unwrap();
        assert!(quality.overall_score > 0.5);
        assert!(quality.completeness_score > 0.8);
    }

    #[test]
    fn test_batch_processor_creation() {
        let config = EnrichmentConfig {
            enabled: false,
            geo_ip: false,
            threat_intel: false,
            asset_correlation: false,
            user_enrichment: false,
        };

        let pipeline = ProcessingPipeline::new(config);
        let processor = BatchProcessor::new(pipeline, 100);

        assert_eq!(processor.batch_size, 100);
    }

    #[tokio::test]
    async fn test_stream_processor() {
        let mut processor = StreamProcessor::new("test-source".to_string())
            .with_buffer_size(2);

        let record1 = DataRecord {
            id: "test1".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({"event": "test1"}),
            metadata: serde_json::json!({}),
        };

        let record2 = DataRecord {
            id: "test2".to_string(),
            source_id: "source1".to_string(),
            timestamp: Utc::now(),
            data: serde_json::json!({"event": "test2"}),
            metadata: serde_json::json!({}),
        };

        // First record should not trigger flush
        let result1 = processor.process_stream(record1).await.unwrap();
        assert!(result1.is_none());
        assert_eq!(processor.buffer_len(), 1);

        // Second record should trigger flush (buffer_size = 2)
        let result2 = processor.process_stream(record2).await.unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().len(), 2);
        assert_eq!(processor.buffer_len(), 0);
    }

    #[test]
    fn test_format_username_display() {
        assert_eq!(format_username_display("john.doe"), "John Doe");
        assert_eq!(format_username_display("jane_smith"), "Jane Smith");
        assert_eq!(format_username_display("admin"), "Admin");
        assert_eq!(format_username_display("svc_account"), "Svc Account");
    }

    #[test]
    fn test_normalize_severity() {
        let config = EnrichmentConfig {
            enabled: false,
            geo_ip: false,
            threat_intel: false,
            asset_correlation: false,
            user_enrichment: false,
        };
        let pipeline = ProcessingPipeline::new(config);

        assert_eq!(pipeline.normalize_severity("CRITICAL"), "critical");
        assert_eq!(pipeline.normalize_severity("error"), "high");
        assert_eq!(pipeline.normalize_severity("WARNING"), "medium");
        assert_eq!(pipeline.normalize_severity("info"), "info");
    }
}
