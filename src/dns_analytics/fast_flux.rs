//! Fast-Flux Detection
//!
//! Detects fast-flux DNS networks by analyzing:
//! - Rapid IP address rotation
//! - Low TTL values
//! - Geographic diversity of resolved IPs
//! - ASN diversity

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use chrono::{DateTime, Utc, Duration};
use super::types::{DnsAnomaly, DnsAnomalyType, DnsAnomalySeverity, DnsAnomalyStatus, FastFluxIndicators};

/// Fast-flux detector configuration
#[derive(Debug, Clone)]
pub struct FastFluxConfig {
    /// Minimum unique IPs to consider fast-flux
    pub min_unique_ips: usize,
    /// Maximum average TTL (seconds) to consider fast-flux
    pub max_avg_ttl: f64,
    /// Minimum IP change rate (changes per hour)
    pub min_ip_change_rate: f64,
    /// Minimum geographic diversity score (0-1)
    pub min_geo_diversity: f64,
    /// Minimum ASN diversity count
    pub min_asn_diversity: usize,
    /// Analysis time window (seconds)
    pub analysis_window_secs: i64,
    /// Flux score threshold for flagging
    pub flux_threshold: f64,
}

impl Default for FastFluxConfig {
    fn default() -> Self {
        Self {
            min_unique_ips: 5,
            max_avg_ttl: 300.0, // 5 minutes
            min_ip_change_rate: 5.0, // 5 changes per hour
            min_geo_diversity: 0.3,
            min_asn_diversity: 3,
            analysis_window_secs: 3600, // 1 hour
            flux_threshold: 0.6,
        }
    }
}

/// DNS resolution record for fast-flux analysis
#[derive(Debug, Clone)]
pub struct DnsResolution {
    pub domain: String,
    pub resolved_ip: IpAddr,
    pub ttl: i32,
    pub timestamp: DateTime<Utc>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
}

/// Domain resolution history
#[derive(Debug, Clone)]
struct DomainHistory {
    resolutions: Vec<ResolutionRecord>,
    unique_ips: HashSet<IpAddr>,
    ttls: Vec<i32>,
    countries: HashSet<String>,
    asns: HashSet<u32>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct ResolutionRecord {
    ip: IpAddr,
    ttl: i32,
    timestamp: DateTime<Utc>,
    country: Option<String>,
    asn: Option<u32>,
}

/// Fast-flux detector
pub struct FastFluxDetector {
    config: FastFluxConfig,
    /// Domain resolution history
    domain_history: HashMap<String, DomainHistory>,
    /// Known CDN IP ranges (to exclude from detection)
    cdn_ranges: Vec<(IpAddr, u8)>, // (network, prefix_len)
}

impl FastFluxDetector {
    pub fn new() -> Self {
        Self::with_config(FastFluxConfig::default())
    }

    pub fn with_config(config: FastFluxConfig) -> Self {
        Self {
            config,
            domain_history: HashMap::new(),
            cdn_ranges: Self::load_cdn_ranges(),
        }
    }

    /// Process a DNS resolution for fast-flux analysis
    pub fn process_resolution(&mut self, resolution: &DnsResolution) {
        // Skip CDN IPs
        if self.is_cdn_ip(&resolution.resolved_ip) {
            return;
        }

        let history = self.domain_history
            .entry(resolution.domain.clone())
            .or_insert_with(|| DomainHistory {
                resolutions: Vec::new(),
                unique_ips: HashSet::new(),
                ttls: Vec::new(),
                countries: HashSet::new(),
                asns: HashSet::new(),
                first_seen: resolution.timestamp,
                last_seen: resolution.timestamp,
            });

        // Update history
        history.resolutions.push(ResolutionRecord {
            ip: resolution.resolved_ip,
            ttl: resolution.ttl,
            timestamp: resolution.timestamp,
            country: resolution.country.clone(),
            asn: resolution.asn,
        });

        history.unique_ips.insert(resolution.resolved_ip);
        history.ttls.push(resolution.ttl);

        if let Some(country) = &resolution.country {
            history.countries.insert(country.clone());
        }

        if let Some(asn) = resolution.asn {
            history.asns.insert(asn);
        }

        history.last_seen = resolution.timestamp;

        // Cleanup old entries
        self.cleanup_old_entries();
    }

    /// Analyze a domain for fast-flux behavior
    pub fn analyze_domain(&self, domain: &str) -> Option<DnsAnomaly> {
        let history = self.domain_history.get(domain)?;

        // Need enough data to analyze
        if history.resolutions.len() < 3 {
            return None;
        }

        let indicators = self.calculate_indicators(history)?;

        // Calculate flux score
        if indicators.flux_score < self.config.flux_threshold {
            return None;
        }

        let severity = if indicators.flux_score >= 0.9 {
            DnsAnomalySeverity::Critical
        } else if indicators.flux_score >= 0.75 {
            DnsAnomalySeverity::High
        } else if indicators.flux_score >= 0.6 {
            DnsAnomalySeverity::Medium
        } else {
            DnsAnomalySeverity::Low
        };

        Some(DnsAnomaly {
            id: uuid::Uuid::new_v4().to_string(),
            anomaly_type: DnsAnomalyType::FastFlux,
            domain: domain.to_string(),
            severity,
            description: format!(
                "Fast-flux behavior detected: {} unique IPs across {} countries, avg TTL {:.0}s, flux score {:.2}",
                indicators.unique_ips,
                indicators.countries.len(),
                indicators.avg_ttl,
                indicators.flux_score
            ),
            indicators: serde_json::to_value(&indicators).unwrap_or_default(),
            entropy_score: None,
            dga_probability: None,
            tunnel_indicators: None,
            fast_flux_indicators: Some(indicators),
            first_seen: history.first_seen,
            last_seen: history.last_seen,
            query_count: history.resolutions.len() as i64,
            status: DnsAnomalyStatus::New,
            source_ips: vec![],
            created_at: Utc::now(),
        })
    }

    /// Analyze all tracked domains for fast-flux
    pub fn analyze_all(&self) -> Vec<DnsAnomaly> {
        self.domain_history
            .keys()
            .filter_map(|domain| self.analyze_domain(domain))
            .collect()
    }

    /// Calculate fast-flux indicators
    fn calculate_indicators(&self, history: &DomainHistory) -> Option<FastFluxIndicators> {
        if history.resolutions.is_empty() {
            return None;
        }

        let unique_ips = history.unique_ips.len();

        // Calculate IP change rate
        let duration = history.last_seen.signed_duration_since(history.first_seen);
        let duration_hours = duration.num_seconds() as f64 / 3600.0;
        let ip_change_rate = if duration_hours > 0.0 {
            (history.resolutions.len() - 1) as f64 / duration_hours
        } else {
            0.0
        };

        // Calculate TTL statistics
        let ttl_sum: i64 = history.ttls.iter().map(|&t| t as i64).sum();
        let avg_ttl = ttl_sum as f64 / history.ttls.len() as f64;
        let min_ttl = *history.ttls.iter().min().unwrap_or(&0);
        let max_ttl = *history.ttls.iter().max().unwrap_or(&0);

        // Calculate geographic diversity (0-1 scale based on unique countries)
        let geographic_diversity = if unique_ips > 1 {
            (history.countries.len() as f64 / unique_ips as f64).min(1.0)
        } else {
            0.0
        };

        let asn_diversity = history.asns.len();

        // Calculate flux score
        let flux_score = self.calculate_flux_score(
            unique_ips,
            ip_change_rate,
            avg_ttl,
            geographic_diversity,
            asn_diversity,
        );

        Some(FastFluxIndicators {
            unique_ips,
            ip_change_rate,
            avg_ttl,
            min_ttl,
            max_ttl,
            geographic_diversity,
            asn_diversity,
            flux_score,
            ip_addresses: history.unique_ips.iter().cloned().collect(),
            countries: history.countries.iter().cloned().collect(),
        })
    }

    /// Calculate overall flux score
    fn calculate_flux_score(
        &self,
        unique_ips: usize,
        ip_change_rate: f64,
        avg_ttl: f64,
        geographic_diversity: f64,
        asn_diversity: usize,
    ) -> f64 {
        let mut score = 0.0;

        // High number of unique IPs (weight: 30%)
        if unique_ips >= self.config.min_unique_ips {
            let factor = (unique_ips as f64 / 20.0).min(1.0);
            score += factor * 0.30;
        }

        // High IP change rate (weight: 25%)
        if ip_change_rate >= self.config.min_ip_change_rate {
            let factor = (ip_change_rate / 20.0).min(1.0);
            score += factor * 0.25;
        }

        // Low TTL (weight: 20%)
        if avg_ttl <= self.config.max_avg_ttl {
            let factor = 1.0 - (avg_ttl / self.config.max_avg_ttl).min(1.0);
            score += factor * 0.20;
        }

        // Geographic diversity (weight: 15%)
        if geographic_diversity >= self.config.min_geo_diversity {
            score += geographic_diversity * 0.15;
        }

        // ASN diversity (weight: 10%)
        if asn_diversity >= self.config.min_asn_diversity {
            let factor = (asn_diversity as f64 / 10.0).min(1.0);
            score += factor * 0.10;
        }

        score
    }

    /// Check if IP belongs to a known CDN
    fn is_cdn_ip(&self, ip: &IpAddr) -> bool {
        // Simple check - in production, use proper CIDR matching
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();

                // CloudFlare ranges (simplified)
                if octets[0] == 104 && (octets[1] >= 16 && octets[1] <= 31) {
                    return true;
                }
                if octets[0] == 172 && (octets[1] >= 64 && octets[1] <= 71) {
                    return true;
                }

                // Fastly ranges (simplified)
                if octets[0] == 151 && octets[1] == 101 {
                    return true;
                }

                // Akamai ranges (simplified)
                if octets[0] == 23 && (octets[1] >= 0 && octets[1] <= 79) {
                    return true;
                }

                false
            }
            IpAddr::V6(_) => false, // Simplified - skip IPv6 CDN detection
        }
    }

    /// Load known CDN IP ranges
    fn load_cdn_ranges() -> Vec<(IpAddr, u8)> {
        // In production, load from a maintained list
        vec![]
    }

    /// Cleanup entries older than analysis window
    fn cleanup_old_entries(&mut self) {
        let cutoff = Utc::now() - Duration::seconds(self.config.analysis_window_secs * 2);

        for history in self.domain_history.values_mut() {
            history.resolutions.retain(|r| r.timestamp > cutoff);

            // Rebuild unique sets from remaining resolutions
            history.unique_ips.clear();
            history.countries.clear();
            history.asns.clear();
            history.ttls.clear();

            for r in &history.resolutions {
                history.unique_ips.insert(r.ip);
                if let Some(country) = &r.country {
                    history.countries.insert(country.clone());
                }
                if let Some(asn) = r.asn {
                    history.asns.insert(asn);
                }
                history.ttls.push(r.ttl);
            }
        }

        // Remove empty histories
        self.domain_history.retain(|_, h| !h.resolutions.is_empty());
    }

    /// Get indicators for a specific domain
    pub fn get_domain_indicators(&self, domain: &str) -> Option<FastFluxIndicators> {
        self.domain_history.get(domain)
            .and_then(|h| self.calculate_indicators(h))
    }

    /// Clear all history
    pub fn clear(&mut self) {
        self.domain_history.clear();
    }

    /// Check if domain appears to be fast-flux
    pub fn is_fast_flux(&self, domain: &str) -> bool {
        self.get_domain_indicators(domain)
            .map(|i| i.flux_score >= self.config.flux_threshold)
            .unwrap_or(false)
    }
}

impl Default for FastFluxDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_resolution(domain: &str, ip: &str, ttl: i32, country: Option<&str>) -> DnsResolution {
        DnsResolution {
            domain: domain.to_string(),
            resolved_ip: ip.parse().unwrap(),
            ttl,
            timestamp: Utc::now(),
            country: country.map(String::from),
            asn: None,
            asn_name: None,
        }
    }

    #[test]
    fn test_normal_domain() {
        let mut detector = FastFluxDetector::new();

        // Normal domain with consistent IP
        for _ in 0..5 {
            detector.process_resolution(&create_resolution(
                "example.com",
                "93.184.216.34",
                86400,
                Some("US"),
            ));
        }

        let indicators = detector.get_domain_indicators("example.com");
        assert!(indicators.is_some());
        let ind = indicators.unwrap();
        assert_eq!(ind.unique_ips, 1);
        assert!(ind.flux_score < 0.5);
    }

    #[test]
    fn test_fast_flux_domain() {
        let mut detector = FastFluxDetector::new();

        // Fast-flux domain with many IPs and low TTL
        let ips = vec![
            ("1.2.3.4", "US"),
            ("5.6.7.8", "DE"),
            ("9.10.11.12", "FR"),
            ("13.14.15.16", "UK"),
            ("17.18.19.20", "JP"),
            ("21.22.23.24", "AU"),
            ("25.26.27.28", "BR"),
            ("29.30.31.32", "CA"),
        ];

        for (ip, country) in &ips {
            detector.process_resolution(&create_resolution(
                "malware.example.com",
                ip,
                60, // Low TTL
                Some(country),
            ));
        }

        let indicators = detector.get_domain_indicators("malware.example.com");
        assert!(indicators.is_some());
        let ind = indicators.unwrap();
        assert!(ind.unique_ips >= 5);
        assert!(ind.avg_ttl <= 300.0);
    }

    #[test]
    fn test_cdn_ip_exclusion() {
        let detector = FastFluxDetector::new();

        // CloudFlare IP should be excluded
        assert!(detector.is_cdn_ip(&"104.16.1.1".parse().unwrap()));

        // Normal IP should not be excluded
        assert!(!detector.is_cdn_ip(&"8.8.8.8".parse().unwrap()));
    }
}
