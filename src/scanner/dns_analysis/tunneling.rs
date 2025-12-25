//! DNS Tunneling Detection
//!
//! This module provides detection capabilities for DNS tunneling attempts using:
//! - Query length analysis (unusually long queries)
//! - Query frequency analysis (high query rate to single domain)
//! - TXT/NULL record abuse detection
//! - Subdomain entropy analysis
//! - Response size analysis
//! - Encoding detection (base64, hex in subdomains)

#![allow(dead_code)]

use crate::scanner::dns_analysis::{DnsQueryLog, DnsQueryType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};

// =============================================================================
// Types
// =============================================================================

/// Result of DNS tunneling detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelingResult {
    /// Whether tunneling was detected
    pub is_tunneling: bool,
    /// Overall confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Individual tunneling indicators
    pub indicators: Vec<TunnelingIndicator>,
    /// Domains suspected of tunneling
    pub suspicious_domains: Vec<String>,
    /// Total data volume estimate (bytes)
    pub estimated_data_volume: u64,
    /// Summary of detection
    pub summary: String,
}

/// Individual tunneling indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelingIndicator {
    /// Type of indicator
    pub indicator_type: IndicatorType,
    /// The domain associated with this indicator
    pub domain: String,
    /// Confidence for this indicator
    pub confidence: f64,
    /// Description of the indicator
    pub description: String,
    /// Supporting evidence
    pub evidence: Vec<String>,
    /// Timestamp when detected
    pub detected_at: DateTime<Utc>,
    /// Number of related queries
    pub query_count: u64,
}

/// Types of tunneling indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IndicatorType {
    /// Unusually long subdomain labels
    LongSubdomain,
    /// High query frequency to a single domain
    HighFrequency,
    /// Excessive use of TXT records
    TxtRecordAbuse,
    /// Excessive use of NULL records
    NullRecordAbuse,
    /// High entropy in subdomains (encoded data)
    SubdomainEntropy,
    /// Large response sizes
    LargeResponses,
    /// Base64-encoded subdomain labels
    Base64Encoding,
    /// Hex-encoded subdomain labels
    HexEncoding,
    /// Many unique subdomains for a single domain
    UniqueSubdomains,
    /// Requests during unusual hours
    UnusualTiming,
    /// Low TTL responses
    LowTtl,
    /// Unusual record types
    UnusualRecordType,
}

impl std::fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndicatorType::LongSubdomain => write!(f, "Long Subdomain"),
            IndicatorType::HighFrequency => write!(f, "High Query Frequency"),
            IndicatorType::TxtRecordAbuse => write!(f, "TXT Record Abuse"),
            IndicatorType::NullRecordAbuse => write!(f, "NULL Record Abuse"),
            IndicatorType::SubdomainEntropy => write!(f, "High Subdomain Entropy"),
            IndicatorType::LargeResponses => write!(f, "Large Responses"),
            IndicatorType::Base64Encoding => write!(f, "Base64 Encoding"),
            IndicatorType::HexEncoding => write!(f, "Hex Encoding"),
            IndicatorType::UniqueSubdomains => write!(f, "Unique Subdomains"),
            IndicatorType::UnusualTiming => write!(f, "Unusual Timing"),
            IndicatorType::LowTtl => write!(f, "Low TTL"),
            IndicatorType::UnusualRecordType => write!(f, "Unusual Record Type"),
        }
    }
}

// =============================================================================
// Tunneling Detector
// =============================================================================

/// DNS tunneling detection engine
pub struct TunnelingDetector {
    /// Configuration
    config: TunnelingDetectorConfig,
}

/// Configuration for tunneling detector
#[derive(Debug, Clone)]
pub struct TunnelingDetectorConfig {
    /// Maximum normal subdomain length (default: 30)
    pub max_subdomain_length: usize,
    /// Maximum normal query frequency per minute (default: 10)
    pub max_queries_per_minute: u32,
    /// Entropy threshold for subdomains (default: 3.5)
    pub entropy_threshold: f64,
    /// Minimum TXT queries for abuse detection (default: 20)
    pub txt_abuse_threshold: u32,
    /// Minimum unique subdomains for detection (default: 50)
    pub unique_subdomain_threshold: u32,
    /// Time window for frequency analysis (seconds)
    pub frequency_window_seconds: u64,
}

impl Default for TunnelingDetectorConfig {
    fn default() -> Self {
        Self {
            max_subdomain_length: 30,
            max_queries_per_minute: 10,
            entropy_threshold: 3.5,
            txt_abuse_threshold: 20,
            unique_subdomain_threshold: 50,
            frequency_window_seconds: 60,
        }
    }
}

impl TunnelingDetector {
    /// Create a new tunneling detector with default configuration
    pub fn new() -> Self {
        Self::with_config(TunnelingDetectorConfig::default())
    }

    /// Create a new tunneling detector with custom configuration
    pub fn with_config(config: TunnelingDetectorConfig) -> Self {
        Self { config }
    }

    /// Analyze DNS queries for tunneling patterns
    pub fn detect(&self, queries: &[DnsQueryLog]) -> TunnelingResult {
        if queries.is_empty() {
            return TunnelingResult {
                is_tunneling: false,
                confidence: 0.0,
                indicators: Vec::new(),
                suspicious_domains: Vec::new(),
                estimated_data_volume: 0,
                summary: "No queries to analyze".to_string(),
            };
        }

        let mut all_indicators = Vec::new();
        let mut suspicious_domains = std::collections::HashSet::new();
        let mut estimated_data_volume = 0u64;

        // Group queries by base domain
        let grouped = group_queries_by_domain(queries);

        for (domain, domain_queries) in &grouped {
            // 1. Check for long subdomains
            let long_subdomain_indicators = self.check_long_subdomains(domain, domain_queries);
            for indicator in &long_subdomain_indicators {
                if indicator.confidence > 0.5 {
                    suspicious_domains.insert(domain.clone());
                }
            }
            all_indicators.extend(long_subdomain_indicators);

            // 2. Check query frequency
            if let Some(indicator) = self.check_query_frequency(domain, domain_queries) {
                if indicator.confidence > 0.5 {
                    suspicious_domains.insert(domain.clone());
                }
                all_indicators.push(indicator);
            }

            // 3. Check TXT/NULL record abuse
            let record_indicators = self.check_record_type_abuse(domain, domain_queries);
            for indicator in &record_indicators {
                if indicator.confidence > 0.5 {
                    suspicious_domains.insert(domain.clone());
                }
            }
            all_indicators.extend(record_indicators);

            // 4. Check subdomain entropy
            if let Some(indicator) = self.check_subdomain_entropy(domain, domain_queries) {
                if indicator.confidence > 0.5 {
                    suspicious_domains.insert(domain.clone());
                }
                all_indicators.push(indicator);
            }

            // 5. Check for encoding patterns
            let encoding_indicators = self.check_encoding_patterns(domain, domain_queries);
            for indicator in &encoding_indicators {
                if indicator.confidence > 0.5 {
                    suspicious_domains.insert(domain.clone());
                }
            }
            all_indicators.extend(encoding_indicators);

            // 6. Check unique subdomain count
            if let Some(indicator) = self.check_unique_subdomains(domain, domain_queries) {
                if indicator.confidence > 0.5 {
                    suspicious_domains.insert(domain.clone());
                }
                all_indicators.push(indicator);
            }

            // 7. Estimate data volume
            estimated_data_volume += estimate_data_volume(domain_queries);
        }

        // 8. Check for low TTL responses across all queries
        let ttl_indicators = self.check_low_ttl(queries);
        all_indicators.extend(ttl_indicators);

        // Calculate overall confidence
        let overall_confidence = calculate_overall_confidence(&all_indicators);
        let is_tunneling = overall_confidence > 0.6 && !suspicious_domains.is_empty();

        let summary = generate_tunneling_summary(
            is_tunneling,
            &all_indicators,
            &suspicious_domains,
            estimated_data_volume,
        );

        TunnelingResult {
            is_tunneling,
            confidence: overall_confidence,
            indicators: all_indicators,
            suspicious_domains: suspicious_domains.into_iter().collect(),
            estimated_data_volume,
            summary,
        }
    }

    /// Check for unusually long subdomains
    fn check_long_subdomains(
        &self,
        base_domain: &str,
        queries: &[&DnsQueryLog],
    ) -> Vec<TunnelingIndicator> {
        let mut indicators = Vec::new();
        let mut long_count = 0;
        let mut max_length = 0;
        let mut examples = Vec::new();

        for query in queries {
            let subdomain = extract_subdomain(&query.query_name, base_domain);
            if subdomain.len() > self.config.max_subdomain_length {
                long_count += 1;
                if subdomain.len() > max_length {
                    max_length = subdomain.len();
                }
                if examples.len() < 5 {
                    examples.push(truncate_domain(&query.query_name, 50));
                }
            }
        }

        if long_count > 0 {
            let ratio = long_count as f64 / queries.len() as f64;
            let confidence = (ratio * 0.5 + (max_length as f64 / 253.0) * 0.5).min(1.0);

            if confidence > 0.3 {
                indicators.push(TunnelingIndicator {
                    indicator_type: IndicatorType::LongSubdomain,
                    domain: base_domain.to_string(),
                    confidence,
                    description: format!(
                        "{} queries with subdomains longer than {} chars (max: {})",
                        long_count, self.config.max_subdomain_length, max_length
                    ),
                    evidence: examples,
                    detected_at: Utc::now(),
                    query_count: long_count,
                });
            }
        }

        indicators
    }

    /// Check query frequency
    fn check_query_frequency(
        &self,
        base_domain: &str,
        queries: &[&DnsQueryLog],
    ) -> Option<TunnelingIndicator> {
        if queries.len() < 2 {
            return None;
        }

        // Calculate queries per minute using time windows
        let window = Duration::seconds(self.config.frequency_window_seconds as i64);
        let mut max_count = 0u32;

        // Sort by timestamp
        let mut sorted_queries: Vec<_> = queries.iter().map(|q| q.timestamp).collect();
        sorted_queries.sort();

        // Sliding window
        for i in 0..sorted_queries.len() {
            let window_start = sorted_queries[i];
            let window_end = window_start + window;
            let count = sorted_queries
                .iter()
                .filter(|&&t| t >= window_start && t < window_end)
                .count() as u32;
            if count > max_count {
                max_count = count;
            }
        }

        let per_minute = max_count as f64 * 60.0 / self.config.frequency_window_seconds as f64;

        if per_minute > self.config.max_queries_per_minute as f64 {
            let confidence = ((per_minute / (self.config.max_queries_per_minute as f64 * 10.0))
                .min(1.0))
            .max(0.3);

            return Some(TunnelingIndicator {
                indicator_type: IndicatorType::HighFrequency,
                domain: base_domain.to_string(),
                confidence,
                description: format!(
                    "High query rate: {:.1} queries/min (threshold: {})",
                    per_minute, self.config.max_queries_per_minute
                ),
                evidence: vec![
                    format!("Total queries: {}", queries.len()),
                    format!("Max burst: {} queries in {}s", max_count, self.config.frequency_window_seconds),
                ],
                detected_at: Utc::now(),
                query_count: queries.len() as u64,
            });
        }

        None
    }

    /// Check for TXT/NULL record abuse
    fn check_record_type_abuse(
        &self,
        base_domain: &str,
        queries: &[&DnsQueryLog],
    ) -> Vec<TunnelingIndicator> {
        let mut indicators = Vec::new();

        let txt_count = queries
            .iter()
            .filter(|q| matches!(q.query_type, DnsQueryType::TXT))
            .count();

        let null_count = queries
            .iter()
            .filter(|q| matches!(q.query_type, DnsQueryType::NULL))
            .count();

        if txt_count >= self.config.txt_abuse_threshold as usize {
            let ratio = txt_count as f64 / queries.len() as f64;
            let confidence = (ratio * 0.8 + (txt_count as f64 / 100.0).min(0.2)).min(1.0);

            indicators.push(TunnelingIndicator {
                indicator_type: IndicatorType::TxtRecordAbuse,
                domain: base_domain.to_string(),
                confidence,
                description: format!(
                    "{} TXT record queries ({:.1}% of total)",
                    txt_count,
                    ratio * 100.0
                ),
                evidence: vec![
                    format!("Total queries: {}", queries.len()),
                    "TXT records commonly used for DNS tunneling".to_string(),
                ],
                detected_at: Utc::now(),
                query_count: txt_count as u64,
            });
        }

        if null_count > 5 {
            let confidence = (null_count as f64 / 20.0).min(1.0).max(0.5);

            indicators.push(TunnelingIndicator {
                indicator_type: IndicatorType::NullRecordAbuse,
                domain: base_domain.to_string(),
                confidence,
                description: format!("{} NULL record queries (rarely used legitimately)", null_count),
                evidence: vec![
                    "NULL records are almost exclusively used for tunneling".to_string(),
                ],
                detected_at: Utc::now(),
                query_count: null_count as u64,
            });
        }

        indicators
    }

    /// Check subdomain entropy
    fn check_subdomain_entropy(
        &self,
        base_domain: &str,
        queries: &[&DnsQueryLog],
    ) -> Option<TunnelingIndicator> {
        let mut high_entropy_count = 0;
        let mut total_entropy = 0.0;
        let mut examples = Vec::new();

        for query in queries {
            let subdomain = extract_subdomain(&query.query_name, base_domain);
            if subdomain.len() >= 8 {
                let entropy = crate::scanner::dns_analysis::dga::calculate_entropy(&subdomain);
                total_entropy += entropy;
                if entropy > self.config.entropy_threshold {
                    high_entropy_count += 1;
                    if examples.len() < 3 {
                        examples.push(format!("{} (entropy: {:.2})", truncate_domain(&query.query_name, 40), entropy));
                    }
                }
            }
        }

        if high_entropy_count > 10 {
            let ratio = high_entropy_count as f64 / queries.len() as f64;
            let avg_entropy = if !queries.is_empty() {
                total_entropy / queries.len() as f64
            } else {
                0.0
            };
            let confidence = (ratio * 0.6 + (avg_entropy / 5.0).min(0.4)).min(1.0);

            return Some(TunnelingIndicator {
                indicator_type: IndicatorType::SubdomainEntropy,
                domain: base_domain.to_string(),
                confidence,
                description: format!(
                    "{} queries with high entropy subdomains (avg: {:.2})",
                    high_entropy_count, avg_entropy
                ),
                evidence: examples,
                detected_at: Utc::now(),
                query_count: high_entropy_count as u64,
            });
        }

        None
    }

    /// Check for encoding patterns (base64, hex)
    fn check_encoding_patterns(
        &self,
        base_domain: &str,
        queries: &[&DnsQueryLog],
    ) -> Vec<TunnelingIndicator> {
        let mut indicators = Vec::new();
        let mut base64_count = 0;
        let mut hex_count = 0;
        let mut base64_examples = Vec::new();
        let mut hex_examples = Vec::new();

        for query in queries {
            let subdomain = extract_subdomain(&query.query_name, base_domain);

            // Check for base64 encoding
            if looks_like_base64(&subdomain) {
                base64_count += 1;
                if base64_examples.len() < 3 {
                    base64_examples.push(truncate_domain(&query.query_name, 50));
                }
            }

            // Check for hex encoding
            if looks_like_hex(&subdomain) {
                hex_count += 1;
                if hex_examples.len() < 3 {
                    hex_examples.push(truncate_domain(&query.query_name, 50));
                }
            }
        }

        if base64_count > 10 {
            let ratio = base64_count as f64 / queries.len() as f64;
            let confidence = (ratio * 0.7 + 0.3).min(1.0);

            indicators.push(TunnelingIndicator {
                indicator_type: IndicatorType::Base64Encoding,
                domain: base_domain.to_string(),
                confidence,
                description: format!(
                    "{} subdomains appear base64-encoded ({:.1}%)",
                    base64_count,
                    ratio * 100.0
                ),
                evidence: base64_examples,
                detected_at: Utc::now(),
                query_count: base64_count as u64,
            });
        }

        if hex_count > 10 {
            let ratio = hex_count as f64 / queries.len() as f64;
            let confidence = (ratio * 0.6 + 0.3).min(1.0);

            indicators.push(TunnelingIndicator {
                indicator_type: IndicatorType::HexEncoding,
                domain: base_domain.to_string(),
                confidence,
                description: format!(
                    "{} subdomains appear hex-encoded ({:.1}%)",
                    hex_count,
                    ratio * 100.0
                ),
                evidence: hex_examples,
                detected_at: Utc::now(),
                query_count: hex_count as u64,
            });
        }

        indicators
    }

    /// Check for excessive unique subdomains
    fn check_unique_subdomains(
        &self,
        base_domain: &str,
        queries: &[&DnsQueryLog],
    ) -> Option<TunnelingIndicator> {
        let unique_subdomains: std::collections::HashSet<_> = queries
            .iter()
            .map(|q| extract_subdomain(&q.query_name, base_domain))
            .collect();

        let unique_count = unique_subdomains.len();

        if unique_count >= self.config.unique_subdomain_threshold as usize {
            let ratio = unique_count as f64 / queries.len() as f64;
            let confidence = (ratio * 0.5 + (unique_count as f64 / 200.0).min(0.5)).min(1.0);

            return Some(TunnelingIndicator {
                indicator_type: IndicatorType::UniqueSubdomains,
                domain: base_domain.to_string(),
                confidence,
                description: format!(
                    "{} unique subdomains out of {} queries ({:.1}% unique)",
                    unique_count,
                    queries.len(),
                    ratio * 100.0
                ),
                evidence: vec![
                    "High unique subdomain count suggests data encoding".to_string(),
                    "Each subdomain may carry encoded payload".to_string(),
                ],
                detected_at: Utc::now(),
                query_count: unique_count as u64,
            });
        }

        None
    }

    /// Check for low TTL responses
    fn check_low_ttl(&self, queries: &[DnsQueryLog]) -> Vec<TunnelingIndicator> {
        let mut indicators = Vec::new();
        let mut low_ttl_domains: HashMap<String, (u32, u32)> = HashMap::new();

        for query in queries {
            if let Some(response) = &query.response {
                for record in &response.records {
                    if record.ttl < 60 {
                        let domain = extract_base_domain(&query.query_name);
                        let entry = low_ttl_domains.entry(domain).or_insert((0, 0));
                        entry.0 += 1;
                        if record.ttl < entry.1 || entry.1 == 0 {
                            entry.1 = record.ttl;
                        }
                    }
                }
            }
        }

        for (domain, (count, min_ttl)) in low_ttl_domains {
            if count >= 10 {
                let confidence = ((count as f64 / 50.0).min(0.5) + (1.0 - min_ttl as f64 / 60.0) * 0.5).min(0.8);

                indicators.push(TunnelingIndicator {
                    indicator_type: IndicatorType::LowTtl,
                    domain: domain.clone(),
                    confidence,
                    description: format!(
                        "{} responses with TTL < 60s (min: {}s)",
                        count, min_ttl
                    ),
                    evidence: vec![
                        "Low TTLs prevent caching and enable rapid C2 communication".to_string(),
                    ],
                    detected_at: Utc::now(),
                    query_count: count as u64,
                });
            }
        }

        indicators
    }
}

impl Default for TunnelingDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Group queries by base domain
fn group_queries_by_domain(queries: &[DnsQueryLog]) -> HashMap<String, Vec<&DnsQueryLog>> {
    let mut groups: HashMap<String, Vec<&DnsQueryLog>> = HashMap::new();

    for query in queries {
        let base = extract_base_domain(&query.query_name);
        groups.entry(base).or_default().push(query);
    }

    groups
}

/// Extract base domain from FQDN
fn extract_base_domain(fqdn: &str) -> String {
    let parts: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();

    if parts.len() <= 2 {
        return fqdn.to_lowercase();
    }

    // Handle common second-level TLDs
    let common_second_level = ["co", "com", "org", "net", "gov", "edu", "ac"];
    if parts.len() >= 3
        && common_second_level.contains(&parts[parts.len() - 2])
        && parts[parts.len() - 1].len() == 2
    {
        parts[parts.len() - 3..].join(".").to_lowercase()
    } else {
        parts[parts.len() - 2..].join(".").to_lowercase()
    }
}

/// Extract subdomain from FQDN given base domain
fn extract_subdomain(fqdn: &str, base_domain: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.').to_lowercase();
    let base = base_domain.to_lowercase();

    if fqdn.ends_with(&base) && fqdn.len() > base.len() {
        let subdomain = &fqdn[..fqdn.len() - base.len()];
        subdomain.trim_end_matches('.').to_string()
    } else {
        fqdn
    }
}

/// Check if a string looks like base64 encoding
fn looks_like_base64(s: &str) -> bool {
    if s.len() < 10 {
        return false;
    }

    // Base64 uses A-Z, a-z, 0-9, +, /, =
    // But in DNS, + and / are replaced with - and _
    let valid_chars = s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
    });

    if !valid_chars {
        return false;
    }

    // Check for typical base64 patterns (groups of 4, may end with padding)
    // High ratio of uppercase letters is common in base64
    let uppercase_count = s.chars().filter(|c| c.is_ascii_uppercase()).count();
    let uppercase_ratio = uppercase_count as f64 / s.len() as f64;

    // Base64 typically has 25-50% uppercase
    uppercase_ratio > 0.2 && uppercase_ratio < 0.6
}

/// Check if a string looks like hex encoding
fn looks_like_hex(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }

    // Must be all hex characters
    if !s.chars().all(|c| c.is_ascii_hexdigit() || c == '.') {
        return false;
    }

    // Count non-dot characters
    let hex_chars: String = s.chars().filter(|c| *c != '.').collect();

    // Hex encoded data is typically even length
    hex_chars.len() >= 16 && hex_chars.len() % 2 == 0
}

/// Truncate domain for display
fn truncate_domain(domain: &str, max_len: usize) -> String {
    if domain.len() <= max_len {
        domain.to_string()
    } else {
        format!("{}...", &domain[..max_len - 3])
    }
}

/// Estimate data volume from queries
fn estimate_data_volume(queries: &[&DnsQueryLog]) -> u64 {
    let mut volume = 0u64;

    for query in queries {
        // Subdomain can carry ~63 bytes per label, ~253 total
        // TXT responses can carry ~255 bytes per string, up to ~64KB total
        let query_data = query.query_name.len() as u64;
        volume += query_data;

        if let Some(response) = &query.response {
            for record in &response.records {
                if matches!(record.record_type, DnsQueryType::TXT) {
                    volume += record.data.len() as u64;
                }
            }
        }
    }

    volume
}

/// Calculate overall confidence from indicators
fn calculate_overall_confidence(indicators: &[TunnelingIndicator]) -> f64 {
    if indicators.is_empty() {
        return 0.0;
    }

    // Weight different indicator types
    let mut weighted_sum = 0.0;
    let mut weight_total = 0.0;

    for indicator in indicators {
        let weight = match indicator.indicator_type {
            IndicatorType::NullRecordAbuse => 1.5,
            IndicatorType::Base64Encoding => 1.3,
            IndicatorType::HexEncoding => 1.2,
            IndicatorType::TxtRecordAbuse => 1.2,
            IndicatorType::HighFrequency => 1.0,
            IndicatorType::SubdomainEntropy => 1.0,
            IndicatorType::LongSubdomain => 0.9,
            IndicatorType::UniqueSubdomains => 0.8,
            IndicatorType::LowTtl => 0.7,
            _ => 0.5,
        };

        weighted_sum += indicator.confidence * weight;
        weight_total += weight;
    }

    let avg_confidence = weighted_sum / weight_total;

    // Boost confidence if multiple indicator types are present
    let unique_types: std::collections::HashSet<_> =
        indicators.iter().map(|i| i.indicator_type).collect();

    let type_boost = match unique_types.len() {
        1 => 0.0,
        2 => 0.1,
        3 => 0.2,
        _ => 0.3,
    };

    (avg_confidence + type_boost).min(1.0)
}

/// Generate summary for tunneling detection
fn generate_tunneling_summary(
    is_tunneling: bool,
    indicators: &[TunnelingIndicator],
    suspicious_domains: &std::collections::HashSet<String>,
    data_volume: u64,
) -> String {
    if !is_tunneling {
        if indicators.is_empty() {
            return "No tunneling indicators detected".to_string();
        } else {
            return format!(
                "Low confidence: {} indicators found but below detection threshold",
                indicators.len()
            );
        }
    }

    let volume_str = if data_volume > 1_000_000 {
        format!("{:.1} MB", data_volume as f64 / 1_000_000.0)
    } else if data_volume > 1000 {
        format!("{:.1} KB", data_volume as f64 / 1000.0)
    } else {
        format!("{} bytes", data_volume)
    };

    format!(
        "DNS TUNNELING DETECTED: {} suspicious domain(s), {} indicator(s), ~{} estimated data volume",
        suspicious_domains.len(),
        indicators.len(),
        volume_str
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::scanner::dns_analysis::DnsResponseCode;

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
        assert_eq!(extract_base_domain("sub.domain.example.com"), "example.com");
        assert_eq!(extract_base_domain("example.com"), "example.com");
    }

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(
            extract_subdomain("aaa.bbb.example.com", "example.com"),
            "aaa.bbb"
        );
        assert_eq!(
            extract_subdomain("www.example.com", "example.com"),
            "www"
        );
    }

    #[test]
    fn test_looks_like_base64() {
        assert!(looks_like_base64("SGVsbG9Xb3JsZDEyMzQ1Njc4"));
        assert!(!looks_like_base64("hello"));
        assert!(!looks_like_base64("www"));
    }

    #[test]
    fn test_looks_like_hex() {
        assert!(looks_like_hex("48656c6c6f576f726c64"));
        assert!(!looks_like_hex("hello"));
        assert!(!looks_like_hex("abcdefgh")); // Contains non-hex
    }

    #[test]
    fn test_detector_normal_traffic() {
        let detector = TunnelingDetector::new();
        let queries: Vec<DnsQueryLog> = vec![
            create_test_query("www.google.com", DnsQueryType::A),
            create_test_query("mail.google.com", DnsQueryType::MX),
        ];

        let result = detector.detect(&queries);
        assert!(!result.is_tunneling);
    }

    #[test]
    fn test_truncate_domain() {
        assert_eq!(truncate_domain("short.com", 20), "short.com");
        assert_eq!(
            truncate_domain("this.is.a.very.long.domain.name.example.com", 20),
            "this.is.a.very.lo..."
        );
    }
}
