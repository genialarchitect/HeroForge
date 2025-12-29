//! Newly Observed Domain (NOD) Tracking
//!
//! Tracks and analyzes domains that are seen for the first time.
//! Useful for detecting:
//! - Newly registered malicious domains
//! - DGA-generated domains
//! - Phishing domains
//! - Fast-flux networks

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use tokio::sync::RwLock;
use super::types::{
    NewlyObservedDomain, NodStatus, DnsThreatType, NodStats,
    NodAlert, NodAlertSeverity,
};
use super::dga_detection::DgaDetector;

/// NOD tracker configuration
#[derive(Debug, Clone)]
pub struct NodConfig {
    /// Days to consider a domain as "newly observed"
    pub nod_window_days: i64,
    /// Maximum domains to track in memory
    pub max_tracked_domains: usize,
    /// Enable automatic risk scoring
    pub enable_risk_scoring: bool,
    /// Risk score threshold for alerts (0-100)
    pub alert_threshold: i32,
    /// Enable WHOIS lookups
    pub enable_whois: bool,
    /// Known good TLDs (lower risk)
    pub trusted_tlds: HashSet<String>,
    /// High-risk TLDs
    pub risky_tlds: HashSet<String>,
}

impl Default for NodConfig {
    fn default() -> Self {
        let mut trusted_tlds = HashSet::new();
        trusted_tlds.insert("com".to_string());
        trusted_tlds.insert("org".to_string());
        trusted_tlds.insert("net".to_string());
        trusted_tlds.insert("edu".to_string());
        trusted_tlds.insert("gov".to_string());
        trusted_tlds.insert("mil".to_string());

        let mut risky_tlds = HashSet::new();
        risky_tlds.insert("xyz".to_string());
        risky_tlds.insert("top".to_string());
        risky_tlds.insert("club".to_string());
        risky_tlds.insert("work".to_string());
        risky_tlds.insert("click".to_string());
        risky_tlds.insert("link".to_string());
        risky_tlds.insert("gq".to_string());
        risky_tlds.insert("ml".to_string());
        risky_tlds.insert("ga".to_string());
        risky_tlds.insert("cf".to_string());
        risky_tlds.insert("tk".to_string());
        risky_tlds.insert("pw".to_string());
        risky_tlds.insert("cc".to_string());
        risky_tlds.insert("ws".to_string());
        risky_tlds.insert("su".to_string());
        risky_tlds.insert("ru".to_string());
        risky_tlds.insert("cn".to_string());

        Self {
            nod_window_days: 30,
            max_tracked_domains: 100_000,
            enable_risk_scoring: true,
            alert_threshold: 70,
            enable_whois: false, // Off by default (requires external API)
            trusted_tlds,
            risky_tlds,
        }
    }
}

/// Domain baseline for comparison
#[derive(Debug, Clone)]
struct DomainBaseline {
    domain: String,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    query_count: i64,
}

/// NOD Tracker
pub struct NodTracker {
    config: NodConfig,
    /// Known domains (not newly observed)
    known_domains: Arc<RwLock<HashSet<String>>>,
    /// Newly observed domains
    nod_domains: Arc<RwLock<HashMap<String, NewlyObservedDomain>>>,
    /// Domain baselines for historical reference
    domain_baselines: Arc<RwLock<HashMap<String, DomainBaseline>>>,
    /// DGA detector for risk scoring
    dga_detector: DgaDetector,
    /// Generated alerts
    alerts: Arc<RwLock<Vec<NodAlert>>>,
    /// Statistics
    stats: Arc<RwLock<NodStatsInternal>>,
}

#[derive(Debug, Default)]
struct NodStatsInternal {
    total_domains_seen: i64,
    total_nods: i64,
    high_risk_nods: i64,
    alerts_generated: i64,
    domains_by_tld: HashMap<String, i64>,
    nods_by_day: Vec<(DateTime<Utc>, i64)>,
}

impl NodTracker {
    pub fn new() -> Self {
        Self::with_config(NodConfig::default())
    }

    pub fn with_config(config: NodConfig) -> Self {
        Self {
            config,
            known_domains: Arc::new(RwLock::new(HashSet::new())),
            nod_domains: Arc::new(RwLock::new(HashMap::new())),
            domain_baselines: Arc::new(RwLock::new(HashMap::new())),
            dga_detector: DgaDetector::new(),
            alerts: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(NodStatsInternal::default())),
        }
    }

    /// Load known domains from historical data
    pub async fn load_known_domains(&self, domains: Vec<String>) {
        let mut known = self.known_domains.write().await;
        for domain in domains {
            known.insert(domain.to_lowercase());
        }
    }

    /// Process a domain query and check if it's a NOD
    pub async fn process_domain(
        &self,
        domain: &str,
        source_ip: std::net::IpAddr,
    ) -> Option<NewlyObservedDomain> {
        let domain_lower = domain.to_lowercase();
        let base_domain = Self::extract_base_domain(&domain_lower);

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_domains_seen += 1;
        }

        // Check if already known
        {
            let known = self.known_domains.read().await;
            if known.contains(&base_domain) {
                return None;
            }
        }

        // Check if already tracked as NOD
        {
            let nods = self.nod_domains.read().await;
            if let Some(existing) = nods.get(&base_domain) {
                // Update existing NOD
                let mut updated = existing.clone();
                updated.query_count += 1;
                updated.last_seen = Some(Utc::now());
                if !updated.querying_ips.contains(&source_ip) {
                    updated.querying_ips.push(source_ip);
                }
                drop(nods);

                let mut nods = self.nod_domains.write().await;
                nods.insert(base_domain.clone(), updated.clone());
                return Some(updated);
            }
        }

        // New domain - create NOD entry
        let tld = Self::extract_tld(&base_domain);
        let now = Utc::now();

        let mut nod = NewlyObservedDomain {
            id: uuid::Uuid::new_v4().to_string(),
            domain: base_domain.clone(),
            tld: tld.clone(),
            first_seen: now,
            last_seen: Some(now),
            first_query_ip: Some(source_ip),
            querying_ips: vec![source_ip],
            query_count: 1,
            registrar: None,
            registration_date: None,
            whois_data: None,
            risk_score: 0,
            threat_indicators: Vec::new(),
            threat_type: None,
            status: NodStatus::New,
            resolved_ips: Vec::new(),
            notes: None,
            created_at: now,
            updated_at: now,
        };

        // Calculate risk score if enabled
        if self.config.enable_risk_scoring {
            nod = self.calculate_risk_score(nod);
        }

        // Generate alert if high risk
        if nod.risk_score >= self.config.alert_threshold {
            self.generate_alert(&nod).await;
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_nods += 1;
            if nod.risk_score >= 70 {
                stats.high_risk_nods += 1;
            }
            *stats.domains_by_tld.entry(tld).or_insert(0) += 1;
        }

        // Store NOD
        {
            let mut nods = self.nod_domains.write().await;

            // Enforce max limit
            if nods.len() >= self.config.max_tracked_domains {
                self.cleanup_old_nods(&mut nods);
            }

            nods.insert(base_domain, nod.clone());
        }

        Some(nod)
    }

    /// Calculate risk score for a domain
    fn calculate_risk_score(&self, mut nod: NewlyObservedDomain) -> NewlyObservedDomain {
        let mut score = 0i32;
        let mut indicators = Vec::new();

        // DGA analysis
        let dga_result = self.dga_detector.analyze(&nod.domain);
        if dga_result.is_dga {
            score += (dga_result.probability * 50.0) as i32;
            indicators.push(format!(
                "DGA probability: {:.1}% (family: {})",
                dga_result.probability * 100.0,
                dga_result.detected_family.as_deref().unwrap_or("unknown")
            ));
            nod.threat_type = Some(DnsThreatType::Dga);
        }

        // High entropy
        if dga_result.entropy > 4.0 {
            score += 15;
            indicators.push(format!("High entropy: {:.2}", dga_result.entropy));
        }

        // TLD risk
        if self.config.risky_tlds.contains(&nod.tld) {
            score += 20;
            indicators.push(format!("High-risk TLD: .{}", nod.tld));
        } else if !self.config.trusted_tlds.contains(&nod.tld) {
            score += 5;
        }

        // Domain length
        let domain_without_tld = nod.domain.split('.').next().unwrap_or("");
        if domain_without_tld.len() > 20 {
            score += 10;
            indicators.push(format!("Long domain: {} chars", domain_without_tld.len()));
        }

        // Numbers in domain
        let digit_count = domain_without_tld.chars().filter(|c| c.is_ascii_digit()).count();
        let digit_ratio = digit_count as f64 / domain_without_tld.len().max(1) as f64;
        if digit_ratio > 0.3 {
            score += 15;
            indicators.push(format!("High digit ratio: {:.0}%", digit_ratio * 100.0));
        }

        // Consonant clusters (common in DGA)
        if dga_result.consonant_ratio > 0.7 {
            score += 10;
            indicators.push("Unusual consonant pattern".to_string());
        }

        // Hyphen abuse
        let hyphen_count = domain_without_tld.matches('-').count();
        if hyphen_count > 2 {
            score += 10;
            indicators.push(format!("Multiple hyphens: {}", hyphen_count));
        }

        // Known suspicious patterns
        let suspicious_patterns = [
            "secure", "login", "verify", "account", "update", "signin",
            "bank", "paypal", "amazon", "apple", "microsoft", "google",
        ];
        for pattern in &suspicious_patterns {
            if nod.domain.contains(pattern) && !nod.domain.ends_with(&format!("{}.com", pattern)) {
                score += 15;
                indicators.push(format!("Suspicious keyword: {}", pattern));
                if nod.threat_type.is_none() {
                    nod.threat_type = Some(DnsThreatType::Phishing);
                }
                break;
            }
        }

        nod.risk_score = score.min(100);
        nod.threat_indicators = indicators;

        // Update status based on risk
        nod.status = if nod.risk_score >= 80 {
            NodStatus::Malicious
        } else if nod.risk_score >= 50 {
            NodStatus::Suspicious
        } else if nod.risk_score >= 30 {
            NodStatus::Investigating
        } else {
            NodStatus::New
        };

        nod
    }

    /// Generate an alert for a high-risk NOD
    async fn generate_alert(&self, nod: &NewlyObservedDomain) {
        let severity = if nod.risk_score >= 90 {
            NodAlertSeverity::Critical
        } else if nod.risk_score >= 80 {
            NodAlertSeverity::High
        } else if nod.risk_score >= 70 {
            NodAlertSeverity::Medium
        } else {
            NodAlertSeverity::Low
        };

        let alert = NodAlert {
            id: uuid::Uuid::new_v4().to_string(),
            domain: nod.domain.clone(),
            risk_score: nod.risk_score,
            severity,
            threat_type: nod.threat_type,
            indicators: nod.threat_indicators.clone(),
            first_seen: nod.first_seen,
            source_ip: nod.first_query_ip,
            acknowledged: false,
            created_at: Utc::now(),
        };

        let mut alerts = self.alerts.write().await;
        alerts.push(alert);

        let mut stats = self.stats.write().await;
        stats.alerts_generated += 1;
    }

    /// Extract the base domain (remove subdomains)
    fn extract_base_domain(domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() <= 2 {
            return domain.to_string();
        }

        // Handle common two-part TLDs
        let two_part_tlds = ["co.uk", "com.au", "co.nz", "co.jp", "com.br", "co.za"];
        let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

        if two_part_tlds.contains(&last_two.as_str()) && parts.len() > 2 {
            format!("{}.{}", parts[parts.len() - 3], last_two)
        } else {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        }
    }

    /// Extract TLD from domain
    fn extract_tld(domain: &str) -> String {
        domain.split('.').last().unwrap_or("").to_string()
    }

    /// Cleanup old NOD entries
    fn cleanup_old_nods(&self, nods: &mut HashMap<String, NewlyObservedDomain>) {
        let cutoff = Utc::now() - Duration::days(self.config.nod_window_days);

        // Sort by first_seen and remove oldest
        let mut sorted: Vec<_> = nods.iter()
            .map(|(k, v)| (k.clone(), v.first_seen))
            .collect();
        sorted.sort_by(|a, b| a.1.cmp(&b.1));

        let to_remove = nods.len() - self.config.max_tracked_domains + (self.config.max_tracked_domains / 10);
        for (key, timestamp) in sorted.into_iter().take(to_remove) {
            if timestamp < cutoff {
                nods.remove(&key);
            }
        }
    }

    /// Get a specific NOD by domain
    pub async fn get_nod(&self, domain: &str) -> Option<NewlyObservedDomain> {
        let base_domain = Self::extract_base_domain(&domain.to_lowercase());
        let nods = self.nod_domains.read().await;
        nods.get(&base_domain).cloned()
    }

    /// Get all NODs within a time range
    pub async fn get_nods_in_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<NewlyObservedDomain> {
        let nods = self.nod_domains.read().await;
        nods.values()
            .filter(|n| n.first_seen >= start && n.first_seen <= end)
            .cloned()
            .collect()
    }

    /// Get high-risk NODs
    pub async fn get_high_risk_nods(&self, min_score: i32) -> Vec<NewlyObservedDomain> {
        let nods = self.nod_domains.read().await;
        nods.values()
            .filter(|n| n.risk_score >= min_score)
            .cloned()
            .collect()
    }

    /// Get NODs by status
    pub async fn get_nods_by_status(&self, status: NodStatus) -> Vec<NewlyObservedDomain> {
        let nods = self.nod_domains.read().await;
        nods.values()
            .filter(|n| n.status == status)
            .cloned()
            .collect()
    }

    /// Update NOD status
    pub async fn update_status(&self, domain: &str, status: NodStatus) -> bool {
        let base_domain = Self::extract_base_domain(&domain.to_lowercase());
        let mut nods = self.nod_domains.write().await;

        if let Some(nod) = nods.get_mut(&base_domain) {
            nod.status = status;
            nod.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Mark a domain as known (move from NOD to known)
    pub async fn mark_as_known(&self, domain: &str) {
        let base_domain = Self::extract_base_domain(&domain.to_lowercase());

        // Remove from NODs
        {
            let mut nods = self.nod_domains.write().await;
            nods.remove(&base_domain);
        }

        // Add to known
        {
            let mut known = self.known_domains.write().await;
            known.insert(base_domain);
        }
    }

    /// Get unacknowledged alerts
    pub async fn get_alerts(&self, unacknowledged_only: bool) -> Vec<NodAlert> {
        let alerts = self.alerts.read().await;
        if unacknowledged_only {
            alerts.iter().filter(|a| !a.acknowledged).cloned().collect()
        } else {
            alerts.clone()
        }
    }

    /// Acknowledge an alert
    pub async fn acknowledge_alert(&self, alert_id: &str) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Get statistics
    pub async fn get_stats(&self) -> NodStats {
        let stats = self.stats.read().await;
        let nods = self.nod_domains.read().await;
        let alerts = self.alerts.read().await;

        // Calculate recent NODs (last 24h)
        let day_ago = Utc::now() - Duration::hours(24);
        let recent_nods = nods.values()
            .filter(|n| n.first_seen > day_ago)
            .count() as i64;

        // Get top TLDs
        let mut tld_counts: Vec<_> = stats.domains_by_tld.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        tld_counts.sort_by(|a, b| b.1.cmp(&a.1));
        let top_tlds: Vec<(String, i64)> = tld_counts.into_iter().take(10).collect();

        // Get unacknowledged alerts count
        let unacked_alerts = alerts.iter().filter(|a| !a.acknowledged).count() as i64;

        NodStats {
            total_nods: nods.len() as i64,
            high_risk_nods: stats.high_risk_nods,
            recent_nods_24h: recent_nods,
            alerts_generated: stats.alerts_generated,
            unacknowledged_alerts: unacked_alerts,
            top_tlds,
            nods_by_status: self.count_by_status(&nods),
        }
    }

    fn count_by_status(&self, nods: &HashMap<String, NewlyObservedDomain>) -> HashMap<String, i64> {
        let mut counts = HashMap::new();
        for nod in nods.values() {
            let status_str = format!("{:?}", nod.status);
            *counts.entry(status_str).or_insert(0) += 1;
        }
        counts
    }

    /// Check if a domain is a NOD
    pub async fn is_nod(&self, domain: &str) -> bool {
        let base_domain = Self::extract_base_domain(&domain.to_lowercase());
        let nods = self.nod_domains.read().await;
        nods.contains_key(&base_domain)
    }

    /// Clear all data
    pub async fn clear(&self) {
        self.known_domains.write().await.clear();
        self.nod_domains.write().await.clear();
        self.alerts.write().await.clear();
        *self.stats.write().await = NodStatsInternal::default();
    }
}

impl Default for NodTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_new_domain_detection() {
        let tracker = NodTracker::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First time seeing domain
        let nod = tracker.process_domain("test.example.com", ip).await;
        assert!(nod.is_some());
        let nod = nod.unwrap();
        assert_eq!(nod.domain, "example.com");
        assert_eq!(nod.query_count, 1);
    }

    #[tokio::test]
    async fn test_known_domain_skip() {
        let tracker = NodTracker::new();
        tracker.load_known_domains(vec!["example.com".to_string()]).await;

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let nod = tracker.process_domain("test.example.com", ip).await;
        assert!(nod.is_none());
    }

    #[tokio::test]
    async fn test_risk_scoring() {
        let tracker = NodTracker::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // High-risk domain (DGA-like with risky TLD)
        let nod = tracker.process_domain("xjk38fds9wer.xyz", ip).await;
        assert!(nod.is_some());
        let nod = nod.unwrap();
        assert!(nod.risk_score > 30);
    }

    #[tokio::test]
    async fn test_tld_extraction() {
        assert_eq!(NodTracker::extract_tld("example.com"), "com");
        assert_eq!(NodTracker::extract_tld("test.co.uk"), "uk");
    }

    #[tokio::test]
    async fn test_base_domain_extraction() {
        assert_eq!(NodTracker::extract_base_domain("www.example.com"), "example.com");
        assert_eq!(NodTracker::extract_base_domain("sub.domain.example.com"), "example.com");
        assert_eq!(NodTracker::extract_base_domain("example.co.uk"), "example.co.uk");
    }

    #[tokio::test]
    async fn test_phishing_detection() {
        let tracker = NodTracker::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Phishing-like domain
        let nod = tracker.process_domain("paypal-secure-login.xyz", ip).await;
        assert!(nod.is_some());
        let nod = nod.unwrap();
        assert!(nod.threat_indicators.iter().any(|i| i.contains("paypal")));
    }
}
