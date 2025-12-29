//! DNS Tunneling Detection
//!
//! Detects DNS tunneling by analyzing:
//! - Query length and subdomain structure
//! - Query frequency patterns
//! - TXT/NULL record usage
//! - Encoding patterns (base64, hex)
//! - Entropy analysis

use std::collections::HashMap;
use std::net::IpAddr;
use chrono::{DateTime, Utc, Duration};
use super::types::{DnsAnomaly, DnsAnomalyType, DnsAnomalySeverity, DnsAnomalyStatus, TunnelIndicators, DnsQuery};
use super::dga_detection::DgaDetector;

/// DNS tunnel detector configuration
#[derive(Debug, Clone)]
pub struct TunnelDetectorConfig {
    /// Maximum average query length before flagging
    pub max_avg_query_length: f64,
    /// Maximum subdomain count before flagging
    pub max_subdomain_count: usize,
    /// Minimum unique subdomains to consider for tunneling
    pub min_unique_subdomains: usize,
    /// Maximum query frequency (queries per minute)
    pub max_query_frequency: f64,
    /// TXT record ratio threshold
    pub txt_record_threshold: f64,
    /// NULL record ratio threshold
    pub null_record_threshold: f64,
    /// Minimum entropy score for suspicious queries
    pub min_entropy_threshold: f64,
    /// Base64 pattern detection threshold
    pub base64_threshold: f64,
    /// Hex pattern detection threshold
    pub hex_threshold: f64,
    /// Time window for analysis (in seconds)
    pub analysis_window_secs: i64,
}

impl Default for TunnelDetectorConfig {
    fn default() -> Self {
        Self {
            max_avg_query_length: 50.0,
            max_subdomain_count: 5,
            min_unique_subdomains: 10,
            max_query_frequency: 60.0, // 60 queries per minute
            txt_record_threshold: 0.5,
            null_record_threshold: 0.3,
            min_entropy_threshold: 3.5,
            base64_threshold: 0.7,
            hex_threshold: 0.8,
            analysis_window_secs: 300, // 5 minutes
        }
    }
}

/// DNS tunnel detector
pub struct TunnelDetector {
    config: TunnelDetectorConfig,
    dga_detector: DgaDetector,
    /// Domain query history: domain -> (queries, timestamps)
    domain_history: HashMap<String, DomainQueryHistory>,
}

/// Query history for a domain
#[derive(Debug, Clone)]
struct DomainQueryHistory {
    queries: Vec<QueryRecord>,
    subdomains: HashMap<String, usize>,
    txt_count: usize,
    null_count: usize,
    total_count: usize,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    source_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
struct QueryRecord {
    query_name: String,
    query_type: String,
    timestamp: DateTime<Utc>,
    source_ip: IpAddr,
}

impl TunnelDetector {
    pub fn new() -> Self {
        Self::with_config(TunnelDetectorConfig::default())
    }

    pub fn with_config(config: TunnelDetectorConfig) -> Self {
        Self {
            config,
            dga_detector: DgaDetector::new(),
            domain_history: HashMap::new(),
        }
    }

    /// Process a DNS query for tunnel detection
    pub fn process_query(&mut self, query: &DnsQuery) {
        let base_domain = self.extract_base_domain(&query.query_name);
        let subdomain = self.extract_subdomain(&query.query_name, &base_domain);

        let history = self.domain_history
            .entry(base_domain.clone())
            .or_insert_with(|| DomainQueryHistory {
                queries: Vec::new(),
                subdomains: HashMap::new(),
                txt_count: 0,
                null_count: 0,
                total_count: 0,
                first_seen: query.timestamp,
                last_seen: query.timestamp,
                source_ips: Vec::new(),
            });

        // Update history
        history.queries.push(QueryRecord {
            query_name: query.query_name.clone(),
            query_type: format!("{:?}", query.query_type),
            timestamp: query.timestamp,
            source_ip: query.source_ip,
        });

        if let Some(sub) = subdomain {
            *history.subdomains.entry(sub).or_insert(0) += 1;
        }

        let query_type = format!("{:?}", query.query_type);
        if query_type == "TXT" {
            history.txt_count += 1;
        } else if query_type == "NULL" {
            history.null_count += 1;
        }

        history.total_count += 1;
        history.last_seen = query.timestamp;

        if !history.source_ips.contains(&query.source_ip) {
            history.source_ips.push(query.source_ip);
        }

        // Cleanup old entries
        self.cleanup_old_entries();
    }

    /// Analyze a domain for tunneling indicators
    pub fn analyze_domain(&self, domain: &str) -> Option<DnsAnomaly> {
        let base_domain = self.extract_base_domain(domain);
        let history = self.domain_history.get(&base_domain)?;

        let indicators = self.calculate_indicators(history)?;

        // Calculate tunnel probability
        let tunnel_score = self.calculate_tunnel_score(&indicators);

        if tunnel_score < 0.5 {
            return None;
        }

        let severity = if tunnel_score >= 0.9 {
            DnsAnomalySeverity::Critical
        } else if tunnel_score >= 0.75 {
            DnsAnomalySeverity::High
        } else if tunnel_score >= 0.6 {
            DnsAnomalySeverity::Medium
        } else {
            DnsAnomalySeverity::Low
        };

        Some(DnsAnomaly {
            id: uuid::Uuid::new_v4().to_string(),
            anomaly_type: DnsAnomalyType::Tunneling,
            domain: base_domain,
            severity,
            description: format!(
                "Potential DNS tunneling detected: {} unique subdomains, avg query length {:.1}, {:.1}% TXT records",
                indicators.unique_subdomains,
                indicators.avg_query_length,
                indicators.txt_record_ratio * 100.0
            ),
            indicators: serde_json::to_value(&indicators).unwrap_or_default(),
            entropy_score: Some(indicators.entropy_scores.iter().sum::<f64>() / indicators.entropy_scores.len().max(1) as f64),
            dga_probability: None,
            tunnel_indicators: Some(indicators),
            fast_flux_indicators: None,
            first_seen: history.first_seen,
            last_seen: history.last_seen,
            query_count: history.total_count as i64,
            status: DnsAnomalyStatus::New,
            source_ips: history.source_ips.clone(),
            created_at: Utc::now(),
        })
    }

    /// Analyze all tracked domains for tunneling
    pub fn analyze_all(&self) -> Vec<DnsAnomaly> {
        self.domain_history
            .keys()
            .filter_map(|domain| self.analyze_domain(domain))
            .collect()
    }

    /// Calculate tunnel indicators for a domain
    fn calculate_indicators(&self, history: &DomainQueryHistory) -> Option<TunnelIndicators> {
        if history.queries.is_empty() {
            return None;
        }

        // Calculate query lengths
        let query_lengths: Vec<usize> = history.queries
            .iter()
            .map(|q| q.query_name.len())
            .collect();

        let avg_query_length = query_lengths.iter().sum::<usize>() as f64 / query_lengths.len() as f64;
        let max_query_length = *query_lengths.iter().max().unwrap_or(&0);

        // Calculate subdomain metrics
        let subdomain_count = history.subdomains.len();
        let unique_subdomains = history.subdomains.values().filter(|&&count| count == 1).count();

        // Calculate query frequency
        let duration = history.last_seen.signed_duration_since(history.first_seen);
        let duration_mins = duration.num_seconds() as f64 / 60.0;
        let query_frequency = if duration_mins > 0.0 {
            history.total_count as f64 / duration_mins
        } else {
            history.total_count as f64
        };

        // Calculate record type ratios
        let txt_record_ratio = if history.total_count > 0 {
            history.txt_count as f64 / history.total_count as f64
        } else {
            0.0
        };

        let null_record_ratio = if history.total_count > 0 {
            history.null_count as f64 / history.total_count as f64
        } else {
            0.0
        };

        // Calculate entropy for subdomains
        let entropy_scores: Vec<f64> = history.subdomains
            .keys()
            .map(|sub| self.dga_detector.calculate_entropy(sub))
            .collect();

        // Detect encoding patterns
        let base64_likelihood = self.detect_base64_pattern(history);
        let hex_likelihood = self.detect_hex_pattern(history);

        Some(TunnelIndicators {
            avg_query_length,
            max_query_length,
            subdomain_count,
            unique_subdomains,
            query_frequency,
            txt_record_ratio,
            null_record_ratio,
            entropy_scores,
            base64_likelihood,
            hex_likelihood,
        })
    }

    /// Calculate overall tunnel score
    fn calculate_tunnel_score(&self, indicators: &TunnelIndicators) -> f64 {
        let mut score = 0.0;
        let mut weight_sum = 0.0;

        // High query length (weight: 20%)
        if indicators.avg_query_length > self.config.max_avg_query_length {
            let factor = ((indicators.avg_query_length - self.config.max_avg_query_length) / 50.0).min(1.0);
            score += factor * 0.20;
        }
        weight_sum += 0.20;

        // Many unique subdomains (weight: 25%)
        if indicators.unique_subdomains >= self.config.min_unique_subdomains {
            let factor = (indicators.unique_subdomains as f64 / 100.0).min(1.0);
            score += factor * 0.25;
        }
        weight_sum += 0.25;

        // High query frequency (weight: 15%)
        if indicators.query_frequency > self.config.max_query_frequency {
            let factor = ((indicators.query_frequency - self.config.max_query_frequency) / 100.0).min(1.0);
            score += factor * 0.15;
        }
        weight_sum += 0.15;

        // High TXT record ratio (weight: 15%)
        if indicators.txt_record_ratio > self.config.txt_record_threshold {
            let factor = ((indicators.txt_record_ratio - self.config.txt_record_threshold) / 0.5).min(1.0);
            score += factor * 0.15;
        }
        weight_sum += 0.15;

        // High entropy (weight: 15%)
        let avg_entropy = if !indicators.entropy_scores.is_empty() {
            indicators.entropy_scores.iter().sum::<f64>() / indicators.entropy_scores.len() as f64
        } else {
            0.0
        };
        if avg_entropy > self.config.min_entropy_threshold {
            let factor = ((avg_entropy - self.config.min_entropy_threshold) / 2.0).min(1.0);
            score += factor * 0.15;
        }
        weight_sum += 0.15;

        // Base64/Hex encoding (weight: 10%)
        let encoding_score = (indicators.base64_likelihood + indicators.hex_likelihood) / 2.0;
        if encoding_score > 0.5 {
            score += encoding_score * 0.10;
        }
        weight_sum += 0.10;

        score / weight_sum * weight_sum // Normalize to sum of active weights
    }

    /// Detect base64 encoding patterns in subdomains
    fn detect_base64_pattern(&self, history: &DomainQueryHistory) -> f64 {
        let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

        let mut total_score = 0.0;
        let mut count = 0;

        for subdomain in history.subdomains.keys() {
            // Check if subdomain looks like base64
            let valid_chars = subdomain.chars().filter(|c| base64_chars.contains(*c)).count();
            let char_ratio = valid_chars as f64 / subdomain.len().max(1) as f64;

            // Base64 typically has length divisible by 4 (with padding)
            let length_score = if subdomain.len() % 4 == 0 || subdomain.ends_with('=') {
                0.3
            } else {
                0.0
            };

            total_score += char_ratio * 0.7 + length_score;
            count += 1;
        }

        if count > 0 {
            total_score / count as f64
        } else {
            0.0
        }
    }

    /// Detect hex encoding patterns in subdomains
    fn detect_hex_pattern(&self, history: &DomainQueryHistory) -> f64 {
        let hex_chars = "0123456789abcdefABCDEF";

        let mut total_score = 0.0;
        let mut count = 0;

        for subdomain in history.subdomains.keys() {
            // Check if subdomain looks like hex
            let valid_chars = subdomain.chars().filter(|c| hex_chars.contains(*c)).count();
            let char_ratio = valid_chars as f64 / subdomain.len().max(1) as f64;

            // Hex strings typically have even length
            let length_score = if subdomain.len() % 2 == 0 && subdomain.len() >= 8 {
                0.3
            } else {
                0.0
            };

            total_score += char_ratio * 0.7 + length_score;
            count += 1;
        }

        if count > 0 {
            total_score / count as f64
        } else {
            0.0
        }
    }

    /// Extract base domain from FQDN
    fn extract_base_domain(&self, fqdn: &str) -> String {
        let parts: Vec<&str> = fqdn.split('.').collect();

        if parts.len() >= 2 {
            // Handle common multi-part TLDs
            let multi_tlds = ["co.uk", "com.au", "co.nz", "co.jp", "com.br"];
            let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

            if multi_tlds.contains(&last_two.as_str()) && parts.len() >= 3 {
                format!("{}.{}.{}", parts[parts.len() - 3], parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            }
        } else {
            fqdn.to_string()
        }
    }

    /// Extract subdomain from FQDN
    fn extract_subdomain(&self, fqdn: &str, base_domain: &str) -> Option<String> {
        if fqdn.len() > base_domain.len() + 1 {
            let subdomain = &fqdn[..fqdn.len() - base_domain.len() - 1];
            Some(subdomain.to_string())
        } else {
            None
        }
    }

    /// Cleanup entries older than analysis window
    fn cleanup_old_entries(&mut self) {
        let cutoff = Utc::now() - Duration::seconds(self.config.analysis_window_secs * 10);

        self.domain_history.retain(|_, history| {
            history.last_seen > cutoff
        });
    }

    /// Get statistics for a specific domain
    pub fn get_domain_stats(&self, domain: &str) -> Option<TunnelIndicators> {
        let base_domain = self.extract_base_domain(domain);
        self.domain_history.get(&base_domain)
            .and_then(|h| self.calculate_indicators(h))
    }

    /// Clear all history
    pub fn clear(&mut self) {
        self.domain_history.clear();
    }
}

impl Default for TunnelDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_analytics::types::DnsRecordType;

    fn create_test_query(query_name: &str, query_type: DnsRecordType) -> DnsQuery {
        DnsQuery {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source_ip: "192.168.1.100".parse().unwrap(),
            source_port: 12345,
            query_name: query_name.to_string(),
            query_type,
            response_code: crate::dns_analytics::types::DnsResponseCode::NoError,
            response_data: vec![],
            ttl: Some(300),
            latency_ms: Some(10),
            server_ip: None,
            is_recursive: true,
            is_dnssec: false,
        }
    }

    #[test]
    fn test_base_domain_extraction() {
        let detector = TunnelDetector::new();

        assert_eq!(detector.extract_base_domain("www.example.com"), "example.com");
        assert_eq!(detector.extract_base_domain("sub.domain.example.com"), "example.com");
        assert_eq!(detector.extract_base_domain("example.co.uk"), "example.co.uk");
    }

    #[test]
    fn test_subdomain_extraction() {
        let detector = TunnelDetector::new();

        let sub = detector.extract_subdomain("aGVsbG8.example.com", "example.com");
        assert_eq!(sub, Some("aGVsbG8".to_string()));
    }

    #[test]
    fn test_normal_traffic() {
        let mut detector = TunnelDetector::new();

        // Simulate normal DNS traffic
        for _ in 0..5 {
            detector.process_query(&create_test_query("www.example.com", DnsRecordType::A));
        }

        let anomaly = detector.analyze_domain("example.com");
        assert!(anomaly.is_none() || anomaly.unwrap().severity == DnsAnomalySeverity::Low);
    }

    #[test]
    fn test_tunnel_detection() {
        let mut detector = TunnelDetector::new();

        // Simulate DNS tunneling with base64-like subdomains
        let base64_subdomains = [
            "aGVsbG8gd29ybGQ=", "dGVzdCBkYXRh", "YW5vdGhlciB0ZXN0",
            "bW9yZSBkYXRhIGhlcmU=", "ZXZlbiBtb3JlIGRhdGE=",
        ];

        for sub in &base64_subdomains {
            let query_name = format!("{}.tunnel.example.com", sub);
            detector.process_query(&create_test_query(&query_name, DnsRecordType::TXT));
        }

        // Add more unique subdomains to trigger detection
        for i in 0..20 {
            let query_name = format!("data{:04x}.tunnel.example.com", i);
            detector.process_query(&create_test_query(&query_name, DnsRecordType::TXT));
        }

        let indicators = detector.get_domain_stats("tunnel.example.com");
        assert!(indicators.is_some());
        let ind = indicators.unwrap();
        assert!(ind.unique_subdomains >= 10);
    }
}
