//! Network Analysis module for Digital Forensics
//!
//! Provides capabilities for analyzing network captures:
//! - PCAP file parsing (packet metadata)
//! - Protocol statistics (TCP, UDP, HTTP, DNS counts)
//! - Connection summary (src/dst IP, ports, bytes)
//! - DNS query extraction
//! - HTTP request/response extraction
//! - Suspicious traffic indicators

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::forensics::types::AnalysisStatus;

// =============================================================================
// PCAP File Types
// =============================================================================

/// PCAP file metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapFile {
    pub id: String,
    pub case_id: String,
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub capture_start: Option<DateTime<Utc>>,
    pub capture_end: Option<DateTime<Utc>>,
    pub packet_count: i64,
    pub analysis_status: AnalysisStatus,
    pub findings_json: Option<serde_json::Value>,
}

/// PCAP format type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PcapFormat {
    Pcap,
    PcapNg,
    Erf,
    Other,
}

impl PcapFormat {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "pcap" | "cap" => PcapFormat::Pcap,
            "pcapng" => PcapFormat::PcapNg,
            "erf" => PcapFormat::Erf,
            _ => PcapFormat::Other,
        }
    }
}

// =============================================================================
// Protocol Statistics
// =============================================================================

/// Protocol statistics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStats {
    // Layer 2
    pub ethernet_count: u64,
    pub arp_count: u64,

    // Layer 3
    pub ipv4_count: u64,
    pub ipv6_count: u64,
    pub icmp_count: u64,
    pub icmpv6_count: u64,

    // Layer 4
    pub tcp_count: u64,
    pub udp_count: u64,
    pub sctp_count: u64,

    // Application Layer
    pub http_count: u64,
    pub https_count: u64,
    pub dns_count: u64,
    pub ftp_count: u64,
    pub ssh_count: u64,
    pub smtp_count: u64,
    pub pop3_count: u64,
    pub imap_count: u64,
    pub smb_count: u64,
    pub rdp_count: u64,
    pub other_count: u64,

    // Statistics
    pub total_packets: u64,
    pub total_bytes: u64,
    pub average_packet_size: f64,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_seconds: f64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
}

impl Default for ProtocolStats {
    fn default() -> Self {
        Self {
            ethernet_count: 0,
            arp_count: 0,
            ipv4_count: 0,
            ipv6_count: 0,
            icmp_count: 0,
            icmpv6_count: 0,
            tcp_count: 0,
            udp_count: 0,
            sctp_count: 0,
            http_count: 0,
            https_count: 0,
            dns_count: 0,
            ftp_count: 0,
            ssh_count: 0,
            smtp_count: 0,
            pop3_count: 0,
            imap_count: 0,
            smb_count: 0,
            rdp_count: 0,
            other_count: 0,
            total_packets: 0,
            total_bytes: 0,
            average_packet_size: 0.0,
            start_time: None,
            end_time: None,
            duration_seconds: 0.0,
            packets_per_second: 0.0,
            bytes_per_second: 0.0,
        }
    }
}

// =============================================================================
// Connection Summary
// =============================================================================

/// Network connection summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSummary {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub packet_count: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub duration_seconds: f64,
    pub tcp_flags: Option<TcpFlagsSummary>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// TCP flags summary for a connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlagsSummary {
    pub syn_count: u32,
    pub ack_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub psh_count: u32,
    pub urg_count: u32,
    pub connection_complete: bool,
}

/// Connection analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAnalysisResult {
    pub connections: Vec<ConnectionSummary>,
    pub total_connections: u32,
    pub suspicious_count: u32,
    pub unique_src_ips: Vec<String>,
    pub unique_dst_ips: Vec<String>,
    pub top_talkers: Vec<IpStats>,
    pub top_destinations: Vec<IpStats>,
    pub top_ports: Vec<PortStats>,
    pub analysis_notes: Vec<String>,
}

/// IP statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpStats {
    pub ip: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub connection_count: u32,
}

/// Port statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStats {
    pub port: u16,
    pub protocol: String,
    pub packet_count: u64,
    pub connection_count: u32,
    pub service_name: Option<String>,
}

// =============================================================================
// DNS Analysis
// =============================================================================

/// DNS query type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Txt,
    Soa,
    Srv,
    Any,
    Other,
}

impl DnsQueryType {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "A" => DnsQueryType::A,
            "AAAA" => DnsQueryType::Aaaa,
            "CNAME" => DnsQueryType::Cname,
            "MX" => DnsQueryType::Mx,
            "NS" => DnsQueryType::Ns,
            "PTR" => DnsQueryType::Ptr,
            "TXT" => DnsQueryType::Txt,
            "SOA" => DnsQueryType::Soa,
            "SRV" => DnsQueryType::Srv,
            "ANY" | "*" => DnsQueryType::Any,
            _ => DnsQueryType::Other,
        }
    }
}

/// DNS query entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transaction_id: u16,
    pub is_response: bool,
    pub response_code: Option<String>,
    pub answers: Vec<DnsAnswer>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// DNS answer entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: DnsQueryType,
    pub ttl: u32,
    pub data: String,
}

/// DNS analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnalysisResult {
    pub queries: Vec<DnsQuery>,
    pub total_queries: u32,
    pub unique_domains: Vec<String>,
    pub by_query_type: HashMap<String, u32>,
    pub by_response_code: HashMap<String, u32>,
    pub suspicious_count: u32,
    pub top_queried_domains: Vec<DomainStats>,
    pub analysis_notes: Vec<String>,
}

/// Domain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStats {
    pub domain: String,
    pub query_count: u32,
    pub unique_clients: u32,
    pub resolved_ips: Vec<String>,
}

// =============================================================================
// HTTP Analysis
// =============================================================================

/// HTTP method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
    Other,
}

impl HttpMethod {
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "PATCH" => HttpMethod::Patch,
            "CONNECT" => HttpMethod::Connect,
            "TRACE" => HttpMethod::Trace,
            _ => HttpMethod::Other,
        }
    }
}

/// HTTP request entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub method: HttpMethod,
    pub uri: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub headers: HashMap<String, String>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

/// HTTP response entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub status_code: u16,
    pub status_text: String,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub headers: HashMap<String, String>,
}

/// HTTP conversation (request + response pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConversation {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub duration_ms: Option<u64>,
}

/// HTTP analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAnalysisResult {
    pub conversations: Vec<HttpConversation>,
    pub total_requests: u32,
    pub by_method: HashMap<String, u32>,
    pub by_status_code: HashMap<u16, u32>,
    pub unique_hosts: Vec<String>,
    pub unique_user_agents: Vec<String>,
    pub suspicious_count: u32,
    pub file_downloads: Vec<FileDownload>,
    pub analysis_notes: Vec<String>,
}

/// File download detected in HTTP traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDownload {
    pub timestamp: DateTime<Utc>,
    pub url: String,
    pub filename: Option<String>,
    pub content_type: String,
    pub size: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

// =============================================================================
// Suspicious Traffic Indicators
// =============================================================================

/// Suspicious traffic indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousIndicator {
    pub timestamp: DateTime<Utc>,
    pub indicator_type: SuspiciousIndicatorType,
    pub severity: String,
    pub description: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub details: HashMap<String, String>,
}

/// Types of suspicious indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SuspiciousIndicatorType {
    PortScan,
    DnsExfiltration,
    BeaconingBehavior,
    UnusualPort,
    ClearTextCredentials,
    MaliciousDomain,
    C2Communication,
    DataExfiltration,
    LateralMovement,
    BruteForce,
    Tunneling,
    Other,
}

impl SuspiciousIndicatorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SuspiciousIndicatorType::PortScan => "port_scan",
            SuspiciousIndicatorType::DnsExfiltration => "dns_exfiltration",
            SuspiciousIndicatorType::BeaconingBehavior => "beaconing_behavior",
            SuspiciousIndicatorType::UnusualPort => "unusual_port",
            SuspiciousIndicatorType::ClearTextCredentials => "cleartext_credentials",
            SuspiciousIndicatorType::MaliciousDomain => "malicious_domain",
            SuspiciousIndicatorType::C2Communication => "c2_communication",
            SuspiciousIndicatorType::DataExfiltration => "data_exfiltration",
            SuspiciousIndicatorType::LateralMovement => "lateral_movement",
            SuspiciousIndicatorType::BruteForce => "brute_force",
            SuspiciousIndicatorType::Tunneling => "tunneling",
            SuspiciousIndicatorType::Other => "other",
        }
    }
}

/// Suspicious traffic analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousTrafficResult {
    pub indicators: Vec<SuspiciousIndicator>,
    pub total_count: u32,
    pub by_type: HashMap<String, u32>,
    pub by_severity: HashMap<String, u32>,
    pub high_severity_ips: Vec<String>,
    pub analysis_notes: Vec<String>,
}

// =============================================================================
// Network Analyzer
// =============================================================================

/// Network traffic analyzer
pub struct NetworkAnalyzer {
    suspicious_ports: Vec<u16>,
    suspicious_domains: Vec<String>,
    c2_indicators: Vec<String>,
    beacon_threshold_seconds: u64,
}

impl Default for NetworkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkAnalyzer {
    pub fn new() -> Self {
        Self {
            suspicious_ports: vec![
                4444, 5555, 6666, 7777, 8888, 9999,  // Common RAT ports
                1337, 31337,                          // Leet ports
                4545, 6667, 6668, 6669,              // IRC/Botnet
                8080, 8443, 9001, 9030,              // Tor/Proxy
                20, 21, 23,                           // Telnet/FTP
            ],
            suspicious_domains: vec![
                ".onion".to_string(),
                ".tor".to_string(),
                "pastebin.com".to_string(),
                "ngrok.io".to_string(),
            ],
            c2_indicators: vec![
                "beacon".to_string(),
                "shell".to_string(),
                "cmd".to_string(),
                "exec".to_string(),
                "payload".to_string(),
            ],
            beacon_threshold_seconds: 60, // Regular intervals under 60s
        }
    }

    /// Analyze connections for suspicious activity
    pub fn analyze_connections(&self, connections: Vec<ConnectionSummary>) -> ConnectionAnalysisResult {
        let mut result = ConnectionAnalysisResult {
            connections: Vec::new(),
            total_connections: connections.len() as u32,
            suspicious_count: 0,
            unique_src_ips: Vec::new(),
            unique_dst_ips: Vec::new(),
            top_talkers: Vec::new(),
            top_destinations: Vec::new(),
            top_ports: Vec::new(),
            analysis_notes: Vec::new(),
        };

        let mut src_ip_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut dst_ip_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut src_stats: HashMap<String, IpStats> = HashMap::new();
        let mut dst_stats: HashMap<String, IpStats> = HashMap::new();
        let mut port_stats: HashMap<u16, PortStats> = HashMap::new();

        for mut conn in connections {
            // Track unique IPs
            src_ip_set.insert(conn.src_ip.clone());
            dst_ip_set.insert(conn.dst_ip.clone());

            // Update source stats
            let src = src_stats.entry(conn.src_ip.clone()).or_insert(IpStats {
                ip: conn.src_ip.clone(),
                packet_count: 0,
                byte_count: 0,
                connection_count: 0,
            });
            src.packet_count += conn.packet_count;
            src.byte_count += conn.bytes_sent + conn.bytes_received;
            src.connection_count += 1;

            // Update destination stats
            let dst = dst_stats.entry(conn.dst_ip.clone()).or_insert(IpStats {
                ip: conn.dst_ip.clone(),
                packet_count: 0,
                byte_count: 0,
                connection_count: 0,
            });
            dst.packet_count += conn.packet_count;
            dst.byte_count += conn.bytes_sent + conn.bytes_received;
            dst.connection_count += 1;

            // Update port stats
            let port = port_stats.entry(conn.dst_port).or_insert(PortStats {
                port: conn.dst_port,
                protocol: conn.protocol.clone(),
                packet_count: 0,
                connection_count: 0,
                service_name: self.get_service_name(conn.dst_port),
            });
            port.packet_count += conn.packet_count;
            port.connection_count += 1;

            // Check for suspicious activity
            let mut suspicion_reasons = Vec::new();

            if self.suspicious_ports.contains(&conn.dst_port) {
                suspicion_reasons.push(format!("Suspicious destination port: {}", conn.dst_port));
            }
            if self.suspicious_ports.contains(&conn.src_port) {
                suspicion_reasons.push(format!("Suspicious source port: {}", conn.src_port));
            }

            conn.is_suspicious = !suspicion_reasons.is_empty();
            conn.suspicion_reasons = suspicion_reasons;

            if conn.is_suspicious {
                result.suspicious_count += 1;
            }

            result.connections.push(conn);
        }

        result.unique_src_ips = src_ip_set.into_iter().collect();
        result.unique_dst_ips = dst_ip_set.into_iter().collect();

        // Sort and get top talkers
        let mut talkers: Vec<IpStats> = src_stats.into_values().collect();
        talkers.sort_by(|a, b| b.byte_count.cmp(&a.byte_count));
        result.top_talkers = talkers.into_iter().take(10).collect();

        // Sort and get top destinations
        let mut destinations: Vec<IpStats> = dst_stats.into_values().collect();
        destinations.sort_by(|a, b| b.byte_count.cmp(&a.byte_count));
        result.top_destinations = destinations.into_iter().take(10).collect();

        // Sort and get top ports
        let mut ports: Vec<PortStats> = port_stats.into_values().collect();
        ports.sort_by(|a, b| b.connection_count.cmp(&a.connection_count));
        result.top_ports = ports.into_iter().take(10).collect();

        result.analysis_notes.push(format!(
            "Analyzed {} connections between {} source and {} destination IPs",
            result.total_connections,
            result.unique_src_ips.len(),
            result.unique_dst_ips.len()
        ));

        if result.suspicious_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} suspicious connections",
                result.suspicious_count
            ));
        }

        result
    }

    /// Analyze DNS queries
    pub fn analyze_dns(&self, queries: Vec<DnsQuery>) -> DnsAnalysisResult {
        let mut result = DnsAnalysisResult {
            queries: Vec::new(),
            total_queries: queries.len() as u32,
            unique_domains: Vec::new(),
            by_query_type: HashMap::new(),
            by_response_code: HashMap::new(),
            suspicious_count: 0,
            top_queried_domains: Vec::new(),
            analysis_notes: Vec::new(),
        };

        let mut domain_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut domain_stats: HashMap<String, DomainStats> = HashMap::new();

        for mut query in queries {
            // Track unique domains
            domain_set.insert(query.query_name.clone());

            // Update query type counts
            let type_str = format!("{:?}", query.query_type);
            *result.by_query_type.entry(type_str).or_insert(0) += 1;

            // Update response code counts
            if let Some(ref code) = query.response_code {
                *result.by_response_code.entry(code.clone()).or_insert(0) += 1;
            }

            // Update domain stats
            let stats = domain_stats.entry(query.query_name.clone()).or_insert(DomainStats {
                domain: query.query_name.clone(),
                query_count: 0,
                unique_clients: 0,
                resolved_ips: Vec::new(),
            });
            stats.query_count += 1;

            // Add resolved IPs from answers
            for answer in &query.answers {
                if !stats.resolved_ips.contains(&answer.data) {
                    stats.resolved_ips.push(answer.data.clone());
                }
            }

            // Check for suspicious DNS activity
            let mut suspicion_reasons = Vec::new();

            // Check for suspicious TLDs
            for suspicious in &self.suspicious_domains {
                if query.query_name.ends_with(suspicious) {
                    suspicion_reasons.push(format!("Suspicious domain: {}", query.query_name));
                    break;
                }
            }

            // Check for DNS tunneling indicators (long subdomains)
            let subdomain_len: usize = query.query_name.split('.').take(1).map(|s| s.len()).sum();
            if subdomain_len > 50 {
                suspicion_reasons.push("Possible DNS tunneling (long subdomain)".to_string());
            }

            // Check for high entropy domain names
            if self.is_high_entropy(&query.query_name) {
                suspicion_reasons.push("High entropy domain name (possible DGA)".to_string());
            }

            query.is_suspicious = !suspicion_reasons.is_empty();
            query.suspicion_reasons = suspicion_reasons;

            if query.is_suspicious {
                result.suspicious_count += 1;
            }

            result.queries.push(query);
        }

        result.unique_domains = domain_set.into_iter().collect();

        // Sort and get top queried domains
        let mut domains: Vec<DomainStats> = domain_stats.into_values().collect();
        domains.sort_by(|a, b| b.query_count.cmp(&a.query_count));
        result.top_queried_domains = domains.into_iter().take(20).collect();

        result.analysis_notes.push(format!(
            "Analyzed {} DNS queries for {} unique domains",
            result.total_queries,
            result.unique_domains.len()
        ));

        if result.suspicious_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} suspicious DNS queries",
                result.suspicious_count
            ));
        }

        result
    }

    /// Analyze HTTP traffic
    pub fn analyze_http(&self, conversations: Vec<HttpConversation>) -> HttpAnalysisResult {
        let mut result = HttpAnalysisResult {
            conversations: Vec::new(),
            total_requests: conversations.len() as u32,
            by_method: HashMap::new(),
            by_status_code: HashMap::new(),
            unique_hosts: Vec::new(),
            unique_user_agents: Vec::new(),
            suspicious_count: 0,
            file_downloads: Vec::new(),
            analysis_notes: Vec::new(),
        };

        let mut host_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut ua_set: std::collections::HashSet<String> = std::collections::HashSet::new();

        for mut conv in conversations {
            // Update method counts
            let method_str = format!("{:?}", conv.request.method);
            *result.by_method.entry(method_str).or_insert(0) += 1;

            // Update status code counts
            if let Some(ref response) = conv.response {
                *result.by_status_code.entry(response.status_code).or_insert(0) += 1;
            }

            // Track unique hosts
            if let Some(ref host) = conv.request.host {
                host_set.insert(host.clone());
            }

            // Track unique user agents
            if let Some(ref ua) = conv.request.user_agent {
                ua_set.insert(ua.clone());
            }

            // Check for suspicious HTTP activity
            let mut suspicion_reasons = Vec::new();

            // Check for suspicious user agents
            if let Some(ref ua) = conv.request.user_agent {
                let ua_lower = ua.to_lowercase();
                if ua_lower.contains("curl") || ua_lower.contains("wget")
                    || ua_lower.contains("python") || ua_lower.contains("powershell") {
                    suspicion_reasons.push(format!("Suspicious user agent: {}", ua));
                }
            }

            // Check for executable downloads
            if let Some(ref response) = conv.response {
                if let Some(ref ct) = response.content_type {
                    let suspicious_types = [
                        "application/x-executable",
                        "application/x-msdos-program",
                        "application/x-msdownload",
                        "application/octet-stream",
                    ];
                    for stype in &suspicious_types {
                        if ct.contains(stype) {
                            suspicion_reasons.push(format!("Suspicious content type: {}", ct));

                            // Track as file download
                            result.file_downloads.push(FileDownload {
                                timestamp: conv.request.timestamp,
                                url: format!("{}{}", conv.request.host.as_deref().unwrap_or(""), conv.request.uri),
                                filename: None,
                                content_type: ct.clone(),
                                size: response.content_length.unwrap_or(0),
                                src_ip: conv.request.src_ip.clone(),
                                dst_ip: conv.request.dst_ip.clone(),
                                is_suspicious: true,
                                suspicion_reasons: vec!["Executable download".to_string()],
                            });
                            break;
                        }
                    }
                }
            }

            // Check for POST to unusual ports
            if conv.request.method == HttpMethod::Post && conv.request.dst_port != 80 && conv.request.dst_port != 443 {
                suspicion_reasons.push(format!("POST to non-standard port: {}", conv.request.dst_port));
            }

            conv.request.is_suspicious = !suspicion_reasons.is_empty();
            conv.request.suspicion_reasons = suspicion_reasons;

            if conv.request.is_suspicious {
                result.suspicious_count += 1;
            }

            result.conversations.push(conv);
        }

        result.unique_hosts = host_set.into_iter().collect();
        result.unique_user_agents = ua_set.into_iter().collect();

        result.analysis_notes.push(format!(
            "Analyzed {} HTTP requests to {} unique hosts",
            result.total_requests,
            result.unique_hosts.len()
        ));

        if result.suspicious_count > 0 {
            result.analysis_notes.push(format!(
                "Found {} suspicious HTTP requests",
                result.suspicious_count
            ));
        }

        if !result.file_downloads.is_empty() {
            result.analysis_notes.push(format!(
                "Detected {} file downloads",
                result.file_downloads.len()
            ));
        }

        result
    }

    /// Detect suspicious traffic patterns
    pub fn detect_suspicious_traffic(
        &self,
        connections: &[ConnectionSummary],
        dns_queries: &[DnsQuery],
        http_convs: &[HttpConversation],
    ) -> SuspiciousTrafficResult {
        let mut result = SuspiciousTrafficResult {
            indicators: Vec::new(),
            total_count: 0,
            by_type: HashMap::new(),
            by_severity: HashMap::new(),
            high_severity_ips: Vec::new(),
            analysis_notes: Vec::new(),
        };

        let mut high_sev_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Detect port scanning
        self.detect_port_scans(connections, &mut result, &mut high_sev_ips);

        // Detect beaconing behavior
        self.detect_beaconing(connections, &mut result, &mut high_sev_ips);

        // Detect DNS exfiltration
        self.detect_dns_exfiltration(dns_queries, &mut result, &mut high_sev_ips);

        // Detect suspicious HTTP patterns
        self.detect_http_suspicious(http_convs, &mut result, &mut high_sev_ips);

        result.total_count = result.indicators.len() as u32;
        result.high_severity_ips = high_sev_ips.into_iter().collect();

        // Count by type and severity
        for indicator in &result.indicators {
            *result.by_type.entry(indicator.indicator_type.as_str().to_string()).or_insert(0) += 1;
            *result.by_severity.entry(indicator.severity.clone()).or_insert(0) += 1;
        }

        result.analysis_notes.push(format!(
            "Detected {} suspicious traffic indicators",
            result.total_count
        ));

        result
    }

    // Helper: Get service name for port
    fn get_service_name(&self, port: u16) -> Option<String> {
        match port {
            21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            143 => Some("IMAP".to_string()),
            443 => Some("HTTPS".to_string()),
            445 => Some("SMB".to_string()),
            3306 => Some("MySQL".to_string()),
            3389 => Some("RDP".to_string()),
            5432 => Some("PostgreSQL".to_string()),
            8080 => Some("HTTP-Proxy".to_string()),
            _ => None,
        }
    }

    // Helper: Check for high entropy strings
    fn is_high_entropy(&self, s: &str) -> bool {
        // Simplified entropy check - real implementation would use Shannon entropy
        let unique_chars: std::collections::HashSet<char> = s.chars().collect();
        let ratio = unique_chars.len() as f64 / s.len() as f64;
        ratio > 0.8 && s.len() > 15
    }

    // Helper: Detect port scans
    fn detect_port_scans(
        &self,
        connections: &[ConnectionSummary],
        result: &mut SuspiciousTrafficResult,
        high_sev_ips: &mut std::collections::HashSet<String>,
    ) {
        let mut src_dst_ports: HashMap<(String, String), Vec<u16>> = HashMap::new();

        for conn in connections {
            let key = (conn.src_ip.clone(), conn.dst_ip.clone());
            src_dst_ports.entry(key).or_default().push(conn.dst_port);
        }

        for ((src, dst), ports) in src_dst_ports {
            let unique_ports: std::collections::HashSet<u16> = ports.into_iter().collect();
            if unique_ports.len() > 20 {
                result.indicators.push(SuspiciousIndicator {
                    timestamp: Utc::now(),
                    indicator_type: SuspiciousIndicatorType::PortScan,
                    severity: "high".to_string(),
                    description: format!("Port scan detected: {} scanned {} ports on {}", src, unique_ports.len(), dst),
                    source_ip: Some(src.clone()),
                    destination_ip: Some(dst),
                    details: HashMap::new(),
                });
                high_sev_ips.insert(src);
            }
        }
    }

    // Helper: Detect beaconing behavior
    fn detect_beaconing(
        &self,
        connections: &[ConnectionSummary],
        result: &mut SuspiciousTrafficResult,
        high_sev_ips: &mut std::collections::HashSet<String>,
    ) {
        // Group connections by src/dst pair
        let mut conn_times: HashMap<(String, String), Vec<DateTime<Utc>>> = HashMap::new();

        for conn in connections {
            let key = (conn.src_ip.clone(), conn.dst_ip.clone());
            conn_times.entry(key).or_default().push(conn.first_seen);
        }

        for ((src, dst), times) in conn_times {
            if times.len() < 5 {
                continue;
            }

            // Check for regular intervals
            let mut intervals: Vec<i64> = Vec::new();
            let mut sorted_times = times.clone();
            sorted_times.sort();

            for i in 1..sorted_times.len() {
                let diff = (sorted_times[i] - sorted_times[i-1]).num_seconds();
                intervals.push(diff);
            }

            if intervals.len() >= 4 {
                let avg: f64 = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
                let variance: f64 = intervals.iter()
                    .map(|&x| (x as f64 - avg).powi(2))
                    .sum::<f64>() / intervals.len() as f64;
                let std_dev = variance.sqrt();

                // Low variance indicates regular intervals (beaconing)
                if std_dev < avg * 0.1 && avg < self.beacon_threshold_seconds as f64 {
                    result.indicators.push(SuspiciousIndicator {
                        timestamp: Utc::now(),
                        indicator_type: SuspiciousIndicatorType::BeaconingBehavior,
                        severity: "high".to_string(),
                        description: format!(
                            "Beaconing behavior detected: {} -> {} with ~{}s interval",
                            src, dst, avg as u64
                        ),
                        source_ip: Some(src.clone()),
                        destination_ip: Some(dst),
                        details: HashMap::new(),
                    });
                    high_sev_ips.insert(src);
                }
            }
        }
    }

    // Helper: Detect DNS exfiltration
    fn detect_dns_exfiltration(
        &self,
        queries: &[DnsQuery],
        result: &mut SuspiciousTrafficResult,
        high_sev_ips: &mut std::collections::HashSet<String>,
    ) {
        let mut domain_query_sizes: HashMap<String, Vec<usize>> = HashMap::new();

        for query in queries {
            let parts: Vec<&str> = query.query_name.split('.').collect();
            if parts.len() >= 2 {
                let base_domain = parts[parts.len()-2..].join(".");
                let subdomain_len: usize = if parts.len() > 2 {
                    parts[..parts.len()-2].iter().map(|s| s.len()).sum()
                } else {
                    0
                };
                domain_query_sizes.entry(base_domain).or_default().push(subdomain_len);
            }
        }

        for (domain, sizes) in domain_query_sizes {
            let total_size: usize = sizes.iter().sum();
            let avg_size = total_size as f64 / sizes.len() as f64;

            if sizes.len() > 50 && avg_size > 30.0 {
                result.indicators.push(SuspiciousIndicator {
                    timestamp: Utc::now(),
                    indicator_type: SuspiciousIndicatorType::DnsExfiltration,
                    severity: "critical".to_string(),
                    description: format!(
                        "Possible DNS exfiltration: {} queries to {} with avg subdomain length {}",
                        sizes.len(), domain, avg_size as u32
                    ),
                    source_ip: None,
                    destination_ip: None,
                    details: HashMap::new(),
                });
            }
        }
    }

    // Helper: Detect suspicious HTTP patterns
    fn detect_http_suspicious(
        &self,
        conversations: &[HttpConversation],
        result: &mut SuspiciousTrafficResult,
        high_sev_ips: &mut std::collections::HashSet<String>,
    ) {
        for conv in conversations {
            if conv.request.is_suspicious {
                for reason in &conv.request.suspicion_reasons {
                    result.indicators.push(SuspiciousIndicator {
                        timestamp: conv.request.timestamp,
                        indicator_type: SuspiciousIndicatorType::Other,
                        severity: "medium".to_string(),
                        description: reason.clone(),
                        source_ip: Some(conv.request.src_ip.clone()),
                        destination_ip: Some(conv.request.dst_ip.clone()),
                        details: HashMap::new(),
                    });
                    high_sev_ips.insert(conv.request.src_ip.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_analyzer_new() {
        let analyzer = NetworkAnalyzer::new();
        assert!(!analyzer.suspicious_ports.is_empty());
        assert!(!analyzer.suspicious_domains.is_empty());
    }

    #[test]
    fn test_dns_query_type_parsing() {
        assert_eq!(DnsQueryType::from_str("A"), DnsQueryType::A);
        assert_eq!(DnsQueryType::from_str("AAAA"), DnsQueryType::Aaaa);
        assert_eq!(DnsQueryType::from_str("MX"), DnsQueryType::Mx);
    }

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_str("GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from_str("POST"), HttpMethod::Post);
        assert_eq!(HttpMethod::from_str("DELETE"), HttpMethod::Delete);
    }

    #[test]
    fn test_pcap_format_from_extension() {
        assert_eq!(PcapFormat::from_extension("pcap"), PcapFormat::Pcap);
        assert_eq!(PcapFormat::from_extension("pcapng"), PcapFormat::PcapNg);
    }

    #[test]
    fn test_protocol_stats_default() {
        let stats = ProtocolStats::default();
        assert_eq!(stats.total_packets, 0);
        assert_eq!(stats.tcp_count, 0);
    }
}
