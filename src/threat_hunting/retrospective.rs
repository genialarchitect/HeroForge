//! Retrospective Search for Threat Hunting
//!
//! Provides capabilities to:
//! - Search historical logs for IOCs
//! - Perform time-bounded searches
//! - Aggregate and visualize results in timeline view
//! - Export findings for further analysis

use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};

use super::ioc::{Ioc, IocType, IocMatcher};

/// Status of a retrospective search
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl SearchStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(SearchStatus::Pending),
            "running" | "in_progress" => Some(SearchStatus::Running),
            "completed" | "done" => Some(SearchStatus::Completed),
            "failed" | "error" => Some(SearchStatus::Failed),
            "cancelled" | "canceled" => Some(SearchStatus::Cancelled),
            _ => None,
        }
    }
}

impl std::fmt::Display for SearchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SearchStatus::Pending => "pending",
            SearchStatus::Running => "running",
            SearchStatus::Completed => "completed",
            SearchStatus::Failed => "failed",
            SearchStatus::Cancelled => "cancelled",
        };
        write!(f, "{}", s)
    }
}

/// Source type for retrospective search
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchSourceType {
    /// Search scan results
    ScanResults,
    /// Search SIEM logs
    SiemLogs,
    /// Search firewall logs
    FirewallLogs,
    /// Search DNS logs
    DnsLogs,
    /// Search authentication logs
    AuthLogs,
    /// Search network flow data
    NetworkFlows,
    /// Search endpoint logs
    EndpointLogs,
    /// Search cloud audit logs
    CloudLogs,
    /// Custom log source
    Custom(String),
}

impl SearchSourceType {
    pub fn all() -> Vec<SearchSourceType> {
        vec![
            SearchSourceType::ScanResults,
            SearchSourceType::SiemLogs,
            SearchSourceType::FirewallLogs,
            SearchSourceType::DnsLogs,
            SearchSourceType::AuthLogs,
            SearchSourceType::NetworkFlows,
            SearchSourceType::EndpointLogs,
            SearchSourceType::CloudLogs,
        ]
    }
}

impl std::fmt::Display for SearchSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SearchSourceType::ScanResults => "scan_results",
            SearchSourceType::SiemLogs => "siem_logs",
            SearchSourceType::FirewallLogs => "firewall_logs",
            SearchSourceType::DnsLogs => "dns_logs",
            SearchSourceType::AuthLogs => "auth_logs",
            SearchSourceType::NetworkFlows => "network_flows",
            SearchSourceType::EndpointLogs => "endpoint_logs",
            SearchSourceType::CloudLogs => "cloud_logs",
            SearchSourceType::Custom(name) => return write!(f, "custom:{}", name),
        };
        write!(f, "{}", s)
    }
}

/// Retrospective search request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrospectiveSearch {
    pub id: String,
    /// Search name/description
    pub name: String,
    /// Search query (free-text or structured)
    pub query: Option<String>,
    /// IOC IDs to search for
    pub ioc_ids: Vec<String>,
    /// Inline IOC values (for ad-hoc searches)
    pub ioc_values: Vec<InlineIoc>,
    /// Time range start
    pub time_start: DateTime<Utc>,
    /// Time range end
    pub time_end: DateTime<Utc>,
    /// Data sources to search
    pub sources: Vec<SearchSourceType>,
    /// Search status
    pub status: SearchStatus,
    /// Number of results found
    pub results_count: u32,
    /// User who initiated the search
    pub user_id: String,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Started at
    pub started_at: Option<DateTime<Utc>>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Progress percentage (0-100)
    pub progress: u8,
}

/// Inline IOC for ad-hoc searches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineIoc {
    pub ioc_type: IocType,
    pub value: String,
    pub description: Option<String>,
}

/// Result of a retrospective search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    /// Parent search ID
    pub search_id: String,
    /// Matched IOC ID or value
    pub matched_ioc: String,
    /// IOC type
    pub ioc_type: IocType,
    /// Source type where found
    pub source_type: SearchSourceType,
    /// Source record ID
    pub source_id: String,
    /// Timestamp of the match
    pub match_timestamp: DateTime<Utc>,
    /// Context around the match
    pub context: MatchContext,
    /// Severity based on IOC
    pub severity: String,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Context around a match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchContext {
    /// Source IP (if applicable)
    pub source_ip: Option<String>,
    /// Destination IP (if applicable)
    pub dest_ip: Option<String>,
    /// Hostname (if applicable)
    pub hostname: Option<String>,
    /// User (if applicable)
    pub user: Option<String>,
    /// Process (if applicable)
    pub process: Option<String>,
    /// Full log line or record
    pub raw_data: Option<String>,
    /// Related scan ID (if applicable)
    pub scan_id: Option<String>,
    /// Related vulnerability (if applicable)
    pub vulnerability_id: Option<String>,
    /// Additional fields
    pub additional_fields: Option<serde_json::Value>,
}

/// Timeline entry for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub ioc_value: String,
    pub ioc_type: IocType,
    pub source_type: String,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hosts_affected: Vec<String>,
}

/// Aggregated search summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchSummary {
    pub search_id: String,
    /// Total matches
    pub total_matches: u32,
    /// Unique IOCs matched
    pub unique_iocs_matched: u32,
    /// Matches by IOC type
    pub matches_by_type: Vec<TypeMatchCount>,
    /// Matches by source
    pub matches_by_source: Vec<SourceMatchCount>,
    /// Matches by severity
    pub matches_by_severity: Vec<SeverityMatchCount>,
    /// Timeline data
    pub timeline: Vec<TimelineEntry>,
    /// Affected hosts
    pub affected_hosts: Vec<AffectedHost>,
    /// Time range summary
    pub time_range: TimeRangeSummary,
}

/// Match count by IOC type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeMatchCount {
    pub ioc_type: IocType,
    pub count: u32,
    pub unique_iocs: u32,
}

/// Match count by source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMatchCount {
    pub source_type: String,
    pub count: u32,
}

/// Match count by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityMatchCount {
    pub severity: String,
    pub count: u32,
}

/// Affected host summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedHost {
    pub host: String,
    pub ip: Option<String>,
    pub match_count: u32,
    pub iocs_matched: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Time range summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRangeSummary {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_hours: i64,
    pub first_match: Option<DateTime<Utc>>,
    pub last_match: Option<DateTime<Utc>>,
    pub peak_hour: Option<DateTime<Utc>>,
    pub peak_hour_count: u32,
}

/// Request to create a retrospective search
#[derive(Debug, Clone, Deserialize)]
pub struct CreateSearchRequest {
    pub name: String,
    pub query: Option<String>,
    pub ioc_ids: Option<Vec<String>>,
    pub ioc_values: Option<Vec<InlineIoc>>,
    pub time_start: DateTime<Utc>,
    pub time_end: DateTime<Utc>,
    pub sources: Option<Vec<String>>,
}

/// Request to create a quick search
#[derive(Debug, Clone, Deserialize)]
pub struct QuickSearchRequest {
    /// Single IOC value to search
    pub ioc_value: String,
    /// Time range preset (e.g., "24h", "7d", "30d")
    pub time_range: Option<String>,
    /// Custom time start
    pub time_start: Option<DateTime<Utc>>,
    /// Custom time end
    pub time_end: Option<DateTime<Utc>>,
}

/// Export format for search results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Csv,
    Json,
    Stix,
    Pdf,
}

/// Retrospective search engine
pub struct RetrospectiveSearchEngine {
    /// Active IOC matcher
    ioc_matcher: Option<IocMatcher>,
}

impl RetrospectiveSearchEngine {
    /// Create a new search engine
    pub fn new() -> Self {
        Self {
            ioc_matcher: None,
        }
    }

    /// Initialize matcher with IOCs
    pub fn initialize_matcher(&mut self, iocs: &[Ioc]) {
        self.ioc_matcher = Some(IocMatcher::new(iocs));
    }

    /// Parse time range preset to duration
    pub fn parse_time_range(preset: &str) -> Option<Duration> {
        let preset = preset.trim().to_lowercase();

        if let Some(hours) = preset.strip_suffix('h') {
            hours.parse::<i64>().ok().map(Duration::hours)
        } else if let Some(days) = preset.strip_suffix('d') {
            days.parse::<i64>().ok().map(Duration::days)
        } else if let Some(weeks) = preset.strip_suffix('w') {
            weeks.parse::<i64>().ok().map(|w| Duration::weeks(w))
        } else if let Some(months) = preset.strip_suffix('m') {
            months.parse::<i64>().ok().map(|m| Duration::days(m * 30))
        } else {
            // Default to days if no suffix
            preset.parse::<i64>().ok().map(Duration::days)
        }
    }

    /// Calculate time range from preset
    pub fn calculate_time_range(preset: &str) -> (DateTime<Utc>, DateTime<Utc>) {
        let end = Utc::now();
        let duration = Self::parse_time_range(preset).unwrap_or(Duration::days(7));
        let start = end - duration;
        (start, end)
    }

    /// Match text against IOCs
    pub fn match_text(&self, text: &str) -> Vec<(String, IocType, String)> {
        if let Some(ref matcher) = self.ioc_matcher {
            matcher.match_text(text)
        } else {
            Vec::new()
        }
    }

    /// Match structured data against IOCs
    pub fn match_data(&self, data: &serde_json::Value) -> Vec<(String, IocType, String, String)> {
        if let Some(ref matcher) = self.ioc_matcher {
            matcher.match_data(data)
        } else {
            Vec::new()
        }
    }

    /// Generate timeline from results
    pub fn generate_timeline(results: &[SearchResult], bucket_hours: i64) -> Vec<TimelineEntry> {
        use std::collections::HashMap;

        let bucket_duration = Duration::hours(bucket_hours);
        let mut buckets: HashMap<i64, HashMap<(String, IocType), Vec<&SearchResult>>> = HashMap::new();

        for result in results {
            let bucket_key = (result.match_timestamp.timestamp() / bucket_duration.num_seconds()) * bucket_duration.num_seconds();
            let ioc_key = (result.matched_ioc.clone(), result.ioc_type);

            buckets
                .entry(bucket_key)
                .or_default()
                .entry(ioc_key)
                .or_default()
                .push(result);
        }

        let mut timeline = Vec::new();

        for (bucket_ts, ioc_matches) in buckets {
            for ((ioc_value, ioc_type), matches) in ioc_matches {
                let bucket_time = DateTime::from_timestamp(bucket_ts, 0)
                    .unwrap_or(Utc::now());

                let first_seen = matches.iter().map(|r| r.match_timestamp).min().unwrap_or(bucket_time);
                let last_seen = matches.iter().map(|r| r.match_timestamp).max().unwrap_or(bucket_time);

                let hosts: Vec<String> = matches
                    .iter()
                    .filter_map(|r| r.context.hostname.clone().or(r.context.source_ip.clone()))
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                timeline.push(TimelineEntry {
                    timestamp: bucket_time,
                    ioc_value,
                    ioc_type,
                    source_type: matches.first().map(|r| r.source_type.to_string()).unwrap_or_default(),
                    count: matches.len() as u32,
                    first_seen,
                    last_seen,
                    hosts_affected: hosts,
                });
            }
        }

        timeline.sort_by_key(|e| e.timestamp);
        timeline
    }

    /// Generate summary from results
    pub fn generate_summary(search: &RetrospectiveSearch, results: &[SearchResult]) -> SearchSummary {
        use std::collections::HashMap;

        // Count by type
        let mut type_counts: HashMap<IocType, (u32, std::collections::HashSet<String>)> = HashMap::new();
        for result in results {
            let entry = type_counts.entry(result.ioc_type).or_insert((0, std::collections::HashSet::new()));
            entry.0 += 1;
            entry.1.insert(result.matched_ioc.clone());
        }
        let matches_by_type: Vec<TypeMatchCount> = type_counts
            .into_iter()
            .map(|(ioc_type, (count, iocs))| TypeMatchCount {
                ioc_type,
                count,
                unique_iocs: iocs.len() as u32,
            })
            .collect();

        // Count by source
        let mut source_counts: HashMap<String, u32> = HashMap::new();
        for result in results {
            *source_counts.entry(result.source_type.to_string()).or_insert(0) += 1;
        }
        let matches_by_source: Vec<SourceMatchCount> = source_counts
            .into_iter()
            .map(|(source_type, count)| SourceMatchCount { source_type, count })
            .collect();

        // Count by severity
        let mut severity_counts: HashMap<String, u32> = HashMap::new();
        for result in results {
            *severity_counts.entry(result.severity.clone()).or_insert(0) += 1;
        }
        let matches_by_severity: Vec<SeverityMatchCount> = severity_counts
            .into_iter()
            .map(|(severity, count)| SeverityMatchCount { severity, count })
            .collect();

        // Affected hosts
        let mut host_data: HashMap<String, (Option<String>, u32, std::collections::HashSet<String>, DateTime<Utc>, DateTime<Utc>)> = HashMap::new();
        for result in results {
            let host = result.context.hostname.clone()
                .or(result.context.source_ip.clone())
                .unwrap_or_else(|| "unknown".to_string());

            let entry = host_data.entry(host.clone()).or_insert((
                result.context.source_ip.clone(),
                0,
                std::collections::HashSet::new(),
                result.match_timestamp,
                result.match_timestamp,
            ));
            entry.1 += 1;
            entry.2.insert(result.matched_ioc.clone());
            if result.match_timestamp < entry.3 {
                entry.3 = result.match_timestamp;
            }
            if result.match_timestamp > entry.4 {
                entry.4 = result.match_timestamp;
            }
        }
        let affected_hosts: Vec<AffectedHost> = host_data
            .into_iter()
            .map(|(host, (ip, count, iocs, first, last))| AffectedHost {
                host,
                ip,
                match_count: count,
                iocs_matched: iocs.into_iter().collect(),
                first_seen: first,
                last_seen: last,
            })
            .collect();

        // Time range summary
        let first_match = results.iter().map(|r| r.match_timestamp).min();
        let last_match = results.iter().map(|r| r.match_timestamp).max();

        // Find peak hour
        let mut hour_counts: HashMap<i64, u32> = HashMap::new();
        for result in results {
            let hour_key = result.match_timestamp.timestamp() / 3600 * 3600;
            *hour_counts.entry(hour_key).or_insert(0) += 1;
        }
        let (peak_hour, peak_count) = hour_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .unwrap_or((0, 0));
        let peak_hour = if peak_count > 0 {
            DateTime::from_timestamp(peak_hour, 0)
        } else {
            None
        };

        let time_range = TimeRangeSummary {
            start: search.time_start,
            end: search.time_end,
            duration_hours: (search.time_end - search.time_start).num_hours(),
            first_match,
            last_match,
            peak_hour,
            peak_hour_count: peak_count,
        };

        // Unique IOCs matched
        let unique_iocs: std::collections::HashSet<&String> = results.iter().map(|r| &r.matched_ioc).collect();

        // Generate timeline (hourly buckets)
        let timeline = Self::generate_timeline(results, 1);

        SearchSummary {
            search_id: search.id.clone(),
            total_matches: results.len() as u32,
            unique_iocs_matched: unique_iocs.len() as u32,
            matches_by_type,
            matches_by_source,
            matches_by_severity,
            timeline,
            affected_hosts,
            time_range,
        }
    }

    /// Export results to CSV
    pub fn export_to_csv(results: &[SearchResult]) -> String {
        let mut csv = String::new();

        // Header
        csv.push_str("match_id,ioc_value,ioc_type,source_type,match_timestamp,source_ip,dest_ip,hostname,user,severity\n");

        for result in results {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                result.id,
                result.matched_ioc,
                result.ioc_type,
                result.source_type,
                result.match_timestamp.to_rfc3339(),
                result.context.source_ip.as_deref().unwrap_or(""),
                result.context.dest_ip.as_deref().unwrap_or(""),
                result.context.hostname.as_deref().unwrap_or(""),
                result.context.user.as_deref().unwrap_or(""),
                result.severity
            ));
        }

        csv
    }

    /// Export results to JSON
    pub fn export_to_json(results: &[SearchResult]) -> serde_json::Value {
        serde_json::json!({
            "export_timestamp": Utc::now().to_rfc3339(),
            "total_results": results.len(),
            "results": results
        })
    }

    /// Export results to STIX format
    pub fn export_to_stix(search: &RetrospectiveSearch, results: &[SearchResult], iocs: &[Ioc]) -> serde_json::Value {
        let mut objects = Vec::new();

        // Create sighting objects for each match
        for result in results {
            let ioc = iocs.iter().find(|i| i.id == result.matched_ioc || i.value == result.matched_ioc);

            let sighting = serde_json::json!({
                "type": "sighting",
                "spec_version": "2.1",
                "id": format!("sighting--{}", result.id),
                "created": Utc::now().to_rfc3339(),
                "modified": Utc::now().to_rfc3339(),
                "first_seen": result.match_timestamp.to_rfc3339(),
                "last_seen": result.match_timestamp.to_rfc3339(),
                "count": 1,
                "sighting_of_ref": ioc.map(|i| format!("indicator--{}", i.id)),
                "where_sighted_refs": result.context.hostname.as_ref().map(|h| vec![format!("identity--{}", h)]),
                "x_heroforge_source_type": result.source_type.to_string(),
                "x_heroforge_search_id": search.id.clone(),
            });

            objects.push(sighting);
        }

        // Add indicator objects for matched IOCs
        let matched_ioc_ids: std::collections::HashSet<&String> = results.iter().map(|r| &r.matched_ioc).collect();
        for ioc in iocs {
            if matched_ioc_ids.contains(&ioc.id) || matched_ioc_ids.contains(&ioc.value) {
                let pattern = match ioc.ioc_type {
                    IocType::Ip => format!("[ipv4-addr:value = '{}']", ioc.value),
                    IocType::Domain => format!("[domain-name:value = '{}']", ioc.value),
                    IocType::Md5 => format!("[file:hashes.MD5 = '{}']", ioc.value),
                    IocType::Sha1 => format!("[file:hashes.'SHA-1' = '{}']", ioc.value),
                    IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{}']", ioc.value),
                    IocType::Url => format!("[url:value = '{}']", ioc.value),
                    IocType::Email => format!("[email-addr:value = '{}']", ioc.value),
                    IocType::Filename => format!("[file:name = '{}']", ioc.value),
                    IocType::RegistryKey => format!("[windows-registry-key:key = '{}']", ioc.value),
                };

                let indicator = serde_json::json!({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": format!("indicator--{}", ioc.id),
                    "created": ioc.created_at.to_rfc3339(),
                    "modified": ioc.updated_at.to_rfc3339(),
                    "name": ioc.description.as_deref().unwrap_or(&ioc.value),
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": ioc.first_seen.to_rfc3339(),
                });

                objects.push(indicator);
            }
        }

        serde_json::json!({
            "type": "bundle",
            "id": format!("bundle--{}", uuid::Uuid::new_v4()),
            "spec_version": "2.1",
            "objects": objects
        })
    }
}

impl Default for RetrospectiveSearchEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_range_parsing() {
        assert_eq!(RetrospectiveSearchEngine::parse_time_range("24h"), Some(Duration::hours(24)));
        assert_eq!(RetrospectiveSearchEngine::parse_time_range("7d"), Some(Duration::days(7)));
        assert_eq!(RetrospectiveSearchEngine::parse_time_range("4w"), Some(Duration::weeks(4)));
    }

    #[test]
    fn test_search_status() {
        assert_eq!(SearchStatus::from_str("pending"), Some(SearchStatus::Pending));
        assert_eq!(SearchStatus::from_str("running"), Some(SearchStatus::Running));
        assert_eq!(SearchStatus::from_str("completed"), Some(SearchStatus::Completed));
    }

    #[test]
    fn test_export_csv() {
        let results = vec![
            SearchResult {
                id: "1".to_string(),
                search_id: "search1".to_string(),
                matched_ioc: "192.168.1.1".to_string(),
                ioc_type: IocType::Ip,
                source_type: SearchSourceType::FirewallLogs,
                source_id: "log1".to_string(),
                match_timestamp: Utc::now(),
                context: MatchContext {
                    source_ip: Some("192.168.1.100".to_string()),
                    dest_ip: Some("192.168.1.1".to_string()),
                    hostname: Some("workstation1".to_string()),
                    user: Some("user1".to_string()),
                    process: None,
                    raw_data: None,
                    scan_id: None,
                    vulnerability_id: None,
                    additional_fields: None,
                },
                severity: "high".to_string(),
                metadata: None,
            },
        ];

        let csv = RetrospectiveSearchEngine::export_to_csv(&results);
        assert!(csv.contains("192.168.1.1"));
        assert!(csv.contains("ip"));
        assert!(csv.contains("high"));
    }
}
