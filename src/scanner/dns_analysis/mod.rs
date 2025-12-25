//! DNS Query Analysis Module for Blue Team Threat Detection
//!
//! This module provides comprehensive DNS analysis capabilities for detecting:
//! - Domain Generation Algorithm (DGA) domains
//! - DNS tunneling attempts
//! - Fast-flux networks
//! - Malicious domain patterns
//! - Phishing and typosquatting
//!
//! Designed for integration with SIEM and blue team security operations.

#![allow(dead_code)]

pub mod dga;
pub mod tunneling;
pub mod reputation;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub use dga::{DgaDetector, DgaResult};
pub use tunneling::{TunnelingDetector, TunnelingIndicator};
pub use reputation::{DomainReputation, ReputationCategory};

// =============================================================================
// Core Types
// =============================================================================

/// DNS query log entry for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryLog {
    /// Timestamp of the query
    pub timestamp: DateTime<Utc>,
    /// The domain name being queried
    pub query_name: String,
    /// DNS query type (A, AAAA, TXT, MX, NS, CNAME, etc.)
    pub query_type: DnsQueryType,
    /// Response data (IP addresses, text records, etc.)
    pub response: Option<DnsResponse>,
    /// Client IP address that made the query
    pub client_ip: IpAddr,
    /// Optional DNS server that processed the query
    pub dns_server: Option<IpAddr>,
    /// Response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)
    pub response_code: DnsResponseCode,
    /// Query ID for correlation
    pub query_id: Option<u16>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
}

/// DNS query types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    SRV,
    TXT,
    CAA,
    DNSKEY,
    DS,
    NSEC,
    NSEC3,
    RRSIG,
    ANY,
    NULL,
    HINFO,
    AXFR,
    IXFR,
    Other(u16),
}

impl DnsQueryType {
    /// Check if this is a type commonly abused for tunneling
    pub fn is_tunneling_candidate(&self) -> bool {
        matches!(self, DnsQueryType::TXT | DnsQueryType::NULL | DnsQueryType::CNAME)
    }
}

impl std::fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsQueryType::Other(n) => write!(f, "TYPE{}", n),
            _ => write!(f, "{:?}", self),
        }
    }
}

/// DNS response codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    YxRrSet,
    NxRrSet,
    NotAuth,
    NotZone,
    Other(u8),
}

/// DNS response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResponse {
    /// List of DNS records in the response
    pub records: Vec<DnsRecord>,
    /// TTL from the response
    pub ttl: Option<u32>,
    /// Whether the response was truncated
    pub truncated: bool,
    /// Whether recursion was available
    pub recursion_available: bool,
}

/// Individual DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Record name
    pub name: String,
    /// Record type
    pub record_type: DnsQueryType,
    /// Record data (IP address, hostname, text, etc.)
    pub data: String,
    /// TTL for this record
    pub ttl: u32,
}

// =============================================================================
// Threat Detection Types
// =============================================================================

/// Types of DNS-based threats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    /// Domain Generation Algorithm detected
    DGA,
    /// DNS tunneling detected
    Tunneling,
    /// Fast-flux network detected
    FastFlux,
    /// Known malware domain
    Malware,
    /// Phishing domain
    Phishing,
    /// Command and Control domain
    C2,
    /// Typosquatting domain
    Typosquatting,
    /// Homograph attack (IDN abuse)
    Homograph,
    /// Newly registered domain (suspicious)
    NewlyRegistered,
    /// Domain with excessive subdomains
    ExcessiveSubdomains,
    /// High entropy domain
    HighEntropy,
    /// Known blocklisted domain
    Blocklisted,
    /// Data exfiltration via DNS
    DataExfiltration,
    /// DNS amplification attempt
    Amplification,
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::DGA => write!(f, "Domain Generation Algorithm"),
            ThreatType::Tunneling => write!(f, "DNS Tunneling"),
            ThreatType::FastFlux => write!(f, "Fast-Flux Network"),
            ThreatType::Malware => write!(f, "Known Malware Domain"),
            ThreatType::Phishing => write!(f, "Phishing Domain"),
            ThreatType::C2 => write!(f, "Command & Control"),
            ThreatType::Typosquatting => write!(f, "Typosquatting"),
            ThreatType::Homograph => write!(f, "Homograph Attack"),
            ThreatType::NewlyRegistered => write!(f, "Newly Registered Domain"),
            ThreatType::ExcessiveSubdomains => write!(f, "Excessive Subdomains"),
            ThreatType::HighEntropy => write!(f, "High Entropy Domain"),
            ThreatType::Blocklisted => write!(f, "Blocklisted Domain"),
            ThreatType::DataExfiltration => write!(f, "Data Exfiltration"),
            ThreatType::Amplification => write!(f, "DNS Amplification"),
        }
    }
}

/// Severity level for threats
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Info => write!(f, "info"),
            ThreatSeverity::Low => write!(f, "low"),
            ThreatSeverity::Medium => write!(f, "medium"),
            ThreatSeverity::High => write!(f, "high"),
            ThreatSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// A detected DNS threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsThreat {
    /// Unique identifier for this threat
    pub id: String,
    /// Type of threat detected
    pub threat_type: ThreatType,
    /// Severity level
    pub severity: ThreatSeverity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// The domain associated with this threat
    pub domain: String,
    /// Description of the threat
    pub description: String,
    /// Evidence supporting this detection
    pub evidence: Vec<String>,
    /// MITRE ATT&CK tactics (if applicable)
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques (if applicable)
    pub mitre_techniques: Vec<String>,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Number of occurrences
    pub occurrence_count: u64,
    /// Associated client IPs
    pub client_ips: Vec<IpAddr>,
    /// Raw scores from detection algorithms
    pub raw_scores: HashMap<String, f64>,
}

impl DnsThreat {
    /// Create a new DnsThreat
    pub fn new(
        threat_type: ThreatType,
        severity: ThreatSeverity,
        confidence: f64,
        domain: String,
        description: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            threat_type,
            severity,
            confidence,
            domain,
            description,
            evidence: Vec::new(),
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            recommendations: Vec::new(),
            first_seen: now,
            last_seen: now,
            occurrence_count: 1,
            client_ips: Vec::new(),
            raw_scores: HashMap::new(),
        }
    }

    /// Add evidence to the threat
    pub fn add_evidence(&mut self, evidence: String) {
        self.evidence.push(evidence);
    }

    /// Add MITRE ATT&CK mapping
    pub fn add_mitre(&mut self, tactic: &str, technique: &str) {
        if !self.mitre_tactics.contains(&tactic.to_string()) {
            self.mitre_tactics.push(tactic.to_string());
        }
        if !self.mitre_techniques.contains(&technique.to_string()) {
            self.mitre_techniques.push(technique.to_string());
        }
    }
}

/// DNS anomaly detected during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnomaly {
    /// Type of anomaly
    pub anomaly_type: String,
    /// Description
    pub description: String,
    /// Severity
    pub severity: ThreatSeverity,
    /// Affected domains
    pub affected_domains: Vec<String>,
    /// Detection timestamp
    pub detected_at: DateTime<Utc>,
    /// Statistics related to this anomaly
    pub stats: HashMap<String, serde_json::Value>,
}

/// Statistics from DNS analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsAnalysisStats {
    /// Total queries analyzed
    pub total_queries: u64,
    /// Unique domains seen
    pub unique_domains: u64,
    /// Unique clients
    pub unique_clients: u64,
    /// Queries by type
    pub queries_by_type: HashMap<String, u64>,
    /// Queries by response code
    pub queries_by_response_code: HashMap<String, u64>,
    /// Average response time (ms)
    pub avg_response_time_ms: f64,
    /// NXDOMAIN rate
    pub nxdomain_rate: f64,
    /// High entropy domain count
    pub high_entropy_count: u64,
    /// Potentially malicious domain count
    pub suspicious_domain_count: u64,
    /// TXT record query count (tunneling indicator)
    pub txt_query_count: u64,
}

/// Result of DNS analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnalysisResult {
    /// Unique ID for this analysis
    pub id: String,
    /// Threats detected
    pub threats: Vec<DnsThreat>,
    /// Anomalies detected
    pub anomalies: Vec<DnsAnomaly>,
    /// Analysis statistics
    pub stats: DnsAnalysisStats,
    /// Analysis start time
    pub started_at: DateTime<Utc>,
    /// Analysis completion time
    pub completed_at: DateTime<Utc>,
    /// Number of queries analyzed
    pub queries_analyzed: u64,
    /// Analysis duration in milliseconds
    pub duration_ms: u64,
    /// Overall risk score (0-100)
    pub risk_score: u8,
    /// Summary of findings
    pub summary: String,
}

// =============================================================================
// DNS Analysis Engine
// =============================================================================

/// Main DNS analysis engine
pub struct DnsAnalyzer {
    /// DGA detector
    dga_detector: DgaDetector,
    /// Tunneling detector
    tunneling_detector: TunnelingDetector,
    /// Domain reputation checker
    reputation_checker: DomainReputation,
    /// Configuration options
    config: DnsAnalyzerConfig,
}

/// Configuration for the DNS analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnalyzerConfig {
    /// Minimum confidence for DGA detection (0.0-1.0)
    pub dga_confidence_threshold: f64,
    /// Minimum confidence for tunneling detection (0.0-1.0)
    pub tunneling_confidence_threshold: f64,
    /// Enable fast-flux detection
    pub enable_fast_flux_detection: bool,
    /// Enable reputation checking
    pub enable_reputation_check: bool,
    /// Maximum domains to analyze in one batch
    pub max_batch_size: usize,
    /// Enable entropy analysis
    pub enable_entropy_analysis: bool,
    /// Entropy threshold for flagging domains
    pub entropy_threshold: f64,
}

impl Default for DnsAnalyzerConfig {
    fn default() -> Self {
        Self {
            dga_confidence_threshold: 0.7,
            tunneling_confidence_threshold: 0.6,
            enable_fast_flux_detection: true,
            enable_reputation_check: true,
            max_batch_size: 10000,
            enable_entropy_analysis: true,
            entropy_threshold: 3.5,
        }
    }
}

impl DnsAnalyzer {
    /// Create a new DNS analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(DnsAnalyzerConfig::default())
    }

    /// Create a new DNS analyzer with custom configuration
    pub fn with_config(config: DnsAnalyzerConfig) -> Self {
        Self {
            dga_detector: DgaDetector::new(),
            tunneling_detector: TunnelingDetector::new(),
            reputation_checker: DomainReputation::new(),
            config,
        }
    }

    /// Analyze a single DNS query
    pub fn analyze_query(&self, query: &DnsQueryLog) -> Result<Vec<DnsThreat>> {
        let mut threats = Vec::new();

        // Extract base domain for analysis
        let domain = extract_base_domain(&query.query_name);

        // Check for DGA patterns
        let dga_result = self.dga_detector.detect(&domain);
        if dga_result.is_dga && dga_result.confidence >= self.config.dga_confidence_threshold {
            let mut threat = DnsThreat::new(
                ThreatType::DGA,
                severity_from_confidence(dga_result.confidence),
                dga_result.confidence,
                domain.clone(),
                format!(
                    "Domain '{}' exhibits DGA characteristics: {}",
                    domain, dga_result.reason
                ),
            );
            threat.add_evidence(format!("Entropy score: {:.2}", dga_result.entropy));
            threat.add_evidence(format!("N-gram score: {:.2}", dga_result.ngram_score));
            threat.add_evidence(format!("Dictionary ratio: {:.2}", dga_result.dictionary_ratio));
            threat.add_mitre("Command and Control", "T1568.002");
            threat.recommendations.push("Block domain and investigate affected hosts".to_string());
            threat.recommendations.push("Check for malware infection on querying host".to_string());
            threat.client_ips.push(query.client_ip);
            threats.push(threat);
        }

        // Check for high entropy (potential encoded data)
        if self.config.enable_entropy_analysis {
            let entropy = dga::calculate_entropy(&query.query_name);
            if entropy > self.config.entropy_threshold && query.query_type.is_tunneling_candidate() {
                let mut threat = DnsThreat::new(
                    ThreatType::HighEntropy,
                    ThreatSeverity::Medium,
                    (entropy / 6.0).min(1.0),
                    query.query_name.clone(),
                    format!(
                        "High entropy query detected ({:.2} bits/char) using {} records",
                        entropy, query.query_type
                    ),
                );
                threat.add_evidence(format!("Query type: {}", query.query_type));
                threat.add_evidence(format!("Entropy: {:.2}", entropy));
                threat.add_mitre("Exfiltration", "T1048.003");
                threat.client_ips.push(query.client_ip);
                threats.push(threat);
            }
        }

        // Check domain reputation
        if self.config.enable_reputation_check {
            let rep_result = self.reputation_checker.check(&domain);
            if !rep_result.is_clean {
                for category in &rep_result.categories {
                    let (threat_type, severity) = match category {
                        ReputationCategory::Malware => (ThreatType::Malware, ThreatSeverity::Critical),
                        ReputationCategory::Phishing => (ThreatType::Phishing, ThreatSeverity::High),
                        ReputationCategory::C2 => (ThreatType::C2, ThreatSeverity::Critical),
                        ReputationCategory::Spam => (ThreatType::Blocklisted, ThreatSeverity::Low),
                        ReputationCategory::Suspicious => (ThreatType::Blocklisted, ThreatSeverity::Medium),
                    };

                    let mut threat = DnsThreat::new(
                        threat_type,
                        severity,
                        rep_result.confidence,
                        domain.clone(),
                        format!("Domain '{}' flagged as {:?}", domain, category),
                    );
                    threat.add_evidence(format!("Category: {:?}", category));
                    threat.add_evidence(format!("Source: {}", rep_result.source));
                    threat.client_ips.push(query.client_ip);
                    threats.push(threat);
                }
            }
        }

        Ok(threats)
    }

    /// Analyze multiple DNS queries for patterns
    pub fn analyze_queries(&self, queries: &[DnsQueryLog]) -> Result<DnsAnalysisResult> {
        let started_at = Utc::now();
        let mut all_threats = Vec::new();
        let mut anomalies = Vec::new();
        let mut stats = DnsAnalysisStats::default();

        // Collect statistics
        let mut domain_set = std::collections::HashSet::new();
        let mut client_set = std::collections::HashSet::new();
        let mut total_response_time = 0u64;
        let mut response_time_count = 0u64;
        let mut nxdomain_count = 0u64;

        for query in queries {
            stats.total_queries += 1;
            domain_set.insert(query.query_name.clone());
            client_set.insert(query.client_ip);

            // Count by type
            let type_key = query.query_type.to_string();
            *stats.queries_by_type.entry(type_key).or_insert(0) += 1;

            // Count TXT queries (tunneling indicator)
            if matches!(query.query_type, DnsQueryType::TXT | DnsQueryType::NULL) {
                stats.txt_query_count += 1;
            }

            // Count by response code
            let code_key = format!("{:?}", query.response_code);
            *stats.queries_by_response_code.entry(code_key).or_insert(0) += 1;

            if matches!(query.response_code, DnsResponseCode::NxDomain) {
                nxdomain_count += 1;
            }

            // Track response times
            if let Some(rt) = query.response_time_ms {
                total_response_time += rt;
                response_time_count += 1;
            }

            // Analyze individual query
            match self.analyze_query(query) {
                Ok(threats) => {
                    all_threats.extend(threats);
                }
                Err(e) => {
                    log::warn!("Failed to analyze query {}: {}", query.query_name, e);
                }
            }
        }

        stats.unique_domains = domain_set.len() as u64;
        stats.unique_clients = client_set.len() as u64;
        if response_time_count > 0 {
            stats.avg_response_time_ms = total_response_time as f64 / response_time_count as f64;
        }
        if stats.total_queries > 0 {
            stats.nxdomain_rate = nxdomain_count as f64 / stats.total_queries as f64;
        }

        // Detect tunneling patterns across queries
        let tunneling_result = self.tunneling_detector.detect(queries);
        if tunneling_result.is_tunneling
            && tunneling_result.confidence >= self.config.tunneling_confidence_threshold
        {
            for indicator in tunneling_result.indicators {
                let mut threat = DnsThreat::new(
                    ThreatType::Tunneling,
                    severity_from_confidence(indicator.confidence),
                    indicator.confidence,
                    indicator.domain.clone(),
                    format!("DNS tunneling detected: {}", indicator.description),
                );
                threat.add_evidence(format!("Indicator: {}", indicator.indicator_type));
                for evidence in indicator.evidence {
                    threat.add_evidence(evidence);
                }
                threat.add_mitre("Command and Control", "T1071.004");
                threat.add_mitre("Exfiltration", "T1048.003");
                threat.recommendations.push("Block suspicious domain".to_string());
                threat.recommendations.push("Investigate affected endpoints".to_string());
                all_threats.push(threat);
            }
        }

        // Detect anomalies
        // High NXDOMAIN rate
        if stats.nxdomain_rate > 0.5 && stats.total_queries > 100 {
            anomalies.push(DnsAnomaly {
                anomaly_type: "high_nxdomain_rate".to_string(),
                description: format!(
                    "NXDOMAIN rate of {:.1}% is unusually high (threshold: 50%)",
                    stats.nxdomain_rate * 100.0
                ),
                severity: ThreatSeverity::Medium,
                affected_domains: Vec::new(),
                detected_at: Utc::now(),
                stats: {
                    let mut m = HashMap::new();
                    m.insert("nxdomain_rate".to_string(), serde_json::json!(stats.nxdomain_rate));
                    m.insert("total_queries".to_string(), serde_json::json!(stats.total_queries));
                    m
                },
            });
        }

        // High TXT query rate
        let txt_rate = if stats.total_queries > 0 {
            stats.txt_query_count as f64 / stats.total_queries as f64
        } else {
            0.0
        };
        if txt_rate > 0.1 && stats.txt_query_count > 50 {
            anomalies.push(DnsAnomaly {
                anomaly_type: "high_txt_query_rate".to_string(),
                description: format!(
                    "TXT query rate of {:.1}% is unusually high, potential tunneling",
                    txt_rate * 100.0
                ),
                severity: ThreatSeverity::Medium,
                affected_domains: Vec::new(),
                detected_at: Utc::now(),
                stats: {
                    let mut m = HashMap::new();
                    m.insert("txt_rate".to_string(), serde_json::json!(txt_rate));
                    m.insert("txt_count".to_string(), serde_json::json!(stats.txt_query_count));
                    m
                },
            });
        }

        // Deduplicate threats by domain and type
        all_threats = deduplicate_threats(all_threats);

        // Count suspicious domains
        stats.suspicious_domain_count = all_threats.len() as u64;
        stats.high_entropy_count = all_threats
            .iter()
            .filter(|t| t.threat_type == ThreatType::HighEntropy)
            .count() as u64;

        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds() as u64;

        // Calculate risk score
        let risk_score = calculate_risk_score(&all_threats, &anomalies, &stats);

        // Generate summary
        let summary = generate_summary(&all_threats, &anomalies, &stats);

        Ok(DnsAnalysisResult {
            id: uuid::Uuid::new_v4().to_string(),
            threats: all_threats,
            anomalies,
            stats,
            started_at,
            completed_at,
            queries_analyzed: queries.len() as u64,
            duration_ms,
            risk_score,
            summary,
        })
    }

    /// Check if a domain exhibits DGA characteristics
    pub fn detect_dga(&self, domain: &str) -> DgaResult {
        self.dga_detector.detect(domain)
    }

    /// Detect tunneling patterns in a set of queries
    pub fn detect_tunneling(&self, queries: &[DnsQueryLog]) -> Vec<TunnelingIndicator> {
        let result = self.tunneling_detector.detect(queries);
        result.indicators
    }

    /// Check if a domain shows fast-flux behavior
    pub fn detect_fast_flux(&self, domain: &str, records: &[DnsRecord]) -> bool {
        detect_fast_flux_internal(domain, records)
    }
}

impl Default for DnsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extract the base domain from a fully qualified domain name
fn extract_base_domain(fqdn: &str) -> String {
    let parts: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
    if parts.len() <= 2 {
        return fqdn.to_lowercase();
    }

    // Handle common TLDs like co.uk, com.au, etc.
    let common_second_level = ["co", "com", "org", "net", "gov", "edu", "ac"];
    if parts.len() >= 3
        && common_second_level.contains(&parts[parts.len() - 2])
        && parts[parts.len() - 1].len() == 2
    {
        // It's a second-level TLD
        parts[parts.len() - 3..].join(".").to_lowercase()
    } else {
        parts[parts.len() - 2..].join(".").to_lowercase()
    }
}

/// Convert confidence score to severity
fn severity_from_confidence(confidence: f64) -> ThreatSeverity {
    if confidence >= 0.9 {
        ThreatSeverity::Critical
    } else if confidence >= 0.75 {
        ThreatSeverity::High
    } else if confidence >= 0.5 {
        ThreatSeverity::Medium
    } else if confidence >= 0.3 {
        ThreatSeverity::Low
    } else {
        ThreatSeverity::Info
    }
}

/// Deduplicate threats by domain and type
fn deduplicate_threats(threats: Vec<DnsThreat>) -> Vec<DnsThreat> {
    let mut seen = std::collections::HashMap::new();
    let mut result = Vec::new();

    for threat in threats {
        let key = (threat.domain.clone(), threat.threat_type);
        if let Some(existing) = seen.get_mut(&key) {
            // Merge into existing threat
            let existing_threat: &mut DnsThreat = existing;
            existing_threat.occurrence_count += 1;
            existing_threat.last_seen = threat.last_seen;
            for ip in threat.client_ips {
                if !existing_threat.client_ips.contains(&ip) {
                    existing_threat.client_ips.push(ip);
                }
            }
            for evidence in threat.evidence {
                if !existing_threat.evidence.contains(&evidence) {
                    existing_threat.evidence.push(evidence);
                }
            }
            // Keep higher confidence
            if threat.confidence > existing_threat.confidence {
                existing_threat.confidence = threat.confidence;
                existing_threat.severity = threat.severity;
            }
        } else {
            seen.insert(key, threat.clone());
            result.push(threat);
        }
    }

    result
}

/// Calculate overall risk score (0-100)
fn calculate_risk_score(
    threats: &[DnsThreat],
    anomalies: &[DnsAnomaly],
    stats: &DnsAnalysisStats,
) -> u8 {
    let mut score: f64 = 0.0;

    // Score based on threats
    for threat in threats {
        let threat_score = match threat.severity {
            ThreatSeverity::Critical => 25.0,
            ThreatSeverity::High => 15.0,
            ThreatSeverity::Medium => 8.0,
            ThreatSeverity::Low => 3.0,
            ThreatSeverity::Info => 1.0,
        } * threat.confidence;
        score += threat_score;
    }

    // Score based on anomalies
    for anomaly in anomalies {
        let anomaly_score = match anomaly.severity {
            ThreatSeverity::Critical => 15.0,
            ThreatSeverity::High => 10.0,
            ThreatSeverity::Medium => 5.0,
            ThreatSeverity::Low => 2.0,
            ThreatSeverity::Info => 0.5,
        };
        score += anomaly_score;
    }

    // Factor in statistics
    if stats.nxdomain_rate > 0.5 {
        score += 10.0;
    }
    if stats.txt_query_count > 100 {
        score += 5.0;
    }

    // Cap at 100
    (score.min(100.0)) as u8
}

/// Generate a summary of the analysis
fn generate_summary(
    threats: &[DnsThreat],
    anomalies: &[DnsAnomaly],
    stats: &DnsAnalysisStats,
) -> String {
    let critical_count = threats
        .iter()
        .filter(|t| t.severity == ThreatSeverity::Critical)
        .count();
    let high_count = threats
        .iter()
        .filter(|t| t.severity == ThreatSeverity::High)
        .count();

    if critical_count > 0 {
        format!(
            "CRITICAL: {} critical and {} high severity threats detected across {} unique domains. {} anomalies found.",
            critical_count, high_count, stats.unique_domains, anomalies.len()
        )
    } else if high_count > 0 {
        format!(
            "HIGH: {} high severity threats detected across {} unique domains. {} anomalies found.",
            high_count, stats.unique_domains, anomalies.len()
        )
    } else if !threats.is_empty() {
        format!(
            "MODERATE: {} threats detected across {} unique domains. {} anomalies found.",
            threats.len(),
            stats.unique_domains,
            anomalies.len()
        )
    } else if !anomalies.is_empty() {
        format!(
            "LOW: No threats detected, but {} anomalies found across {} unique domains.",
            anomalies.len(),
            stats.unique_domains
        )
    } else {
        format!(
            "CLEAN: No threats or anomalies detected across {} queries from {} unique domains.",
            stats.total_queries, stats.unique_domains
        )
    }
}

/// Detect fast-flux behavior in DNS records
fn detect_fast_flux_internal(domain: &str, records: &[DnsRecord]) -> bool {
    // Fast-flux typically shows:
    // 1. Many A records pointing to different IPs
    // 2. Very low TTLs (< 300 seconds)
    // 3. IPs changing rapidly between queries

    let a_records: Vec<_> = records
        .iter()
        .filter(|r| matches!(r.record_type, DnsQueryType::A | DnsQueryType::AAAA))
        .collect();

    if a_records.is_empty() {
        return false;
    }

    // Check for multiple IPs (fast-flux domains often have 3+ A records)
    let unique_ips: std::collections::HashSet<_> = a_records.iter().map(|r| &r.data).collect();
    let has_multiple_ips = unique_ips.len() >= 3;

    // Check for low TTLs
    let has_low_ttl = a_records.iter().any(|r| r.ttl < 300);

    // Heuristic: if both conditions are met, likely fast-flux
    if has_multiple_ips && has_low_ttl {
        log::debug!(
            "Fast-flux detected for {}: {} unique IPs, low TTL",
            domain,
            unique_ips.len()
        );
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_query(domain: &str, query_type: DnsQueryType) -> DnsQueryLog {
        DnsQueryLog {
            timestamp: Utc::now(),
            query_name: domain.to_string(),
            query_type,
            response: None,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dns_server: None,
            response_code: DnsResponseCode::NoError,
            query_id: Some(12345),
            response_time_ms: Some(5),
        }
    }

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("www.example.com"), "example.com");
        assert_eq!(extract_base_domain("sub.domain.example.co.uk"), "example.co.uk");
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(extract_base_domain("a.b.c.example.com"), "example.com");
    }

    #[test]
    fn test_severity_from_confidence() {
        assert_eq!(severity_from_confidence(0.95), ThreatSeverity::Critical);
        assert_eq!(severity_from_confidence(0.8), ThreatSeverity::High);
        assert_eq!(severity_from_confidence(0.6), ThreatSeverity::Medium);
        assert_eq!(severity_from_confidence(0.4), ThreatSeverity::Low);
        assert_eq!(severity_from_confidence(0.1), ThreatSeverity::Info);
    }

    #[test]
    fn test_query_type_tunneling_candidate() {
        assert!(DnsQueryType::TXT.is_tunneling_candidate());
        assert!(DnsQueryType::NULL.is_tunneling_candidate());
        assert!(!DnsQueryType::A.is_tunneling_candidate());
        assert!(!DnsQueryType::MX.is_tunneling_candidate());
    }

    #[test]
    fn test_dns_analyzer_creation() {
        let analyzer = DnsAnalyzer::new();
        assert!(analyzer.config.dga_confidence_threshold > 0.0);
    }

    #[test]
    fn test_analyze_normal_query() {
        let analyzer = DnsAnalyzer::new();
        let query = create_test_query("www.google.com", DnsQueryType::A);
        let threats = analyzer.analyze_query(&query).unwrap();
        assert!(threats.is_empty(), "Normal domain should not trigger threats");
    }

    #[test]
    fn test_threat_type_display() {
        assert_eq!(ThreatType::DGA.to_string(), "Domain Generation Algorithm");
        assert_eq!(ThreatType::Tunneling.to_string(), "DNS Tunneling");
        assert_eq!(ThreatType::FastFlux.to_string(), "Fast-Flux Network");
    }
}
