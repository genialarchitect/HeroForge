//! DNS Analytics Module
//!
//! Comprehensive DNS security analytics including:
//! - Passive DNS collection and storage
//! - DGA (Domain Generation Algorithm) detection
//! - DNS tunneling detection
//! - Fast-flux network detection
//! - Newly Observed Domain (NOD) tracking
//! - DNS threat intelligence correlation

pub mod types;
pub mod dga_detection;
pub mod tunnel_detection;
pub mod fast_flux;
pub mod passive_dns;
pub mod nod_tracker;
pub mod whois;

// Re-export main types
pub use types::{
    DnsRecordType, DnsResponseCode, PassiveDnsRecord, DnsThreatType,
    DnsAnomaly, DnsAnomalyType, DnsAnomalySeverity, DnsAnomalyStatus,
    TunnelIndicators, FastFluxIndicators, DgaAnalysis, DgaConfidence,
    NewlyObservedDomain, NodStatus, NodStats, NodAlert, NodAlertSeverity,
    DnsBaseline, DnsBaselineType, BaselinePeriod,
    DnsQuery, DnsStats, DomainCount, QueryTypeCount, ClientQueryCount, TimeSeriesPoint,
    DnsThreatIntel, ThreatIntelSource,
    DnsCollectorConfig, DnsCollectorType,
    DnsDashboard,
};

// Re-export detectors
pub use dga_detection::{DgaDetector, DgaConfig};
pub use tunnel_detection::{TunnelDetector, TunnelDetectorConfig};
pub use fast_flux::{FastFluxDetector, FastFluxConfig, DnsResolution};
pub use passive_dns::{PassiveDnsStore, PassiveDnsConfig};
pub use nod_tracker::{NodTracker, NodConfig};
pub use whois::{WhoisClient, WhoisConfig, WhoisResult, WhoisError};

use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// DNS Analytics Engine
///
/// Orchestrates all DNS security analytics components
pub struct DnsAnalyticsEngine {
    /// Passive DNS store
    pub passive_dns: Arc<PassiveDnsStore>,
    /// DGA detector
    pub dga_detector: Arc<RwLock<DgaDetector>>,
    /// Tunnel detector
    pub tunnel_detector: Arc<RwLock<TunnelDetector>>,
    /// Fast-flux detector
    pub fast_flux_detector: Arc<RwLock<FastFluxDetector>>,
    /// NOD tracker
    pub nod_tracker: Arc<NodTracker>,
    /// Engine statistics
    stats: Arc<RwLock<EngineStats>>,
}

#[derive(Debug, Default)]
struct EngineStats {
    queries_processed: i64,
    anomalies_detected: i64,
    nods_detected: i64,
    last_processed: Option<DateTime<Utc>>,
}

impl DnsAnalyticsEngine {
    /// Create a new DNS analytics engine with default configuration
    pub fn new() -> Self {
        Self {
            passive_dns: Arc::new(PassiveDnsStore::new()),
            dga_detector: Arc::new(RwLock::new(DgaDetector::new())),
            tunnel_detector: Arc::new(RwLock::new(TunnelDetector::new())),
            fast_flux_detector: Arc::new(RwLock::new(FastFluxDetector::new())),
            nod_tracker: Arc::new(NodTracker::new()),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        }
    }

    /// Create a new DNS analytics engine with custom configuration
    pub fn with_config(
        passive_config: PassiveDnsConfig,
        dga_config: DgaConfig,
        tunnel_config: TunnelDetectorConfig,
        fast_flux_config: FastFluxConfig,
        nod_config: NodConfig,
    ) -> Self {
        Self {
            passive_dns: Arc::new(PassiveDnsStore::with_config(passive_config)),
            dga_detector: Arc::new(RwLock::new(DgaDetector::with_config(dga_config))),
            tunnel_detector: Arc::new(RwLock::new(TunnelDetector::with_config(tunnel_config))),
            fast_flux_detector: Arc::new(RwLock::new(FastFluxDetector::with_config(fast_flux_config))),
            nod_tracker: Arc::new(NodTracker::with_config(nod_config)),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        }
    }

    /// Process a DNS query through all analytics components
    pub async fn process_query(&self, query: &DnsQuery) -> AnalysisResult {
        let mut result = AnalysisResult::default();
        let now = Utc::now();

        // Store in passive DNS
        self.passive_dns.process_query(query).await;

        // DGA detection
        {
            let dga = self.dga_detector.read().await;
            let dga_result = dga.analyze(&query.query_name);
            if dga_result.is_dga {
                result.dga_detected = true;
                result.dga_analysis = Some(dga_result.clone());
                result.anomalies.push(DnsAnomaly {
                    id: uuid::Uuid::new_v4().to_string(),
                    anomaly_type: DnsAnomalyType::Dga,
                    domain: query.query_name.clone(),
                    severity: if dga_result.probability >= 0.9 {
                        DnsAnomalySeverity::Critical
                    } else if dga_result.probability >= 0.7 {
                        DnsAnomalySeverity::High
                    } else {
                        DnsAnomalySeverity::Medium
                    },
                    description: format!(
                        "DGA domain detected with {:.1}% probability{}",
                        dga_result.probability * 100.0,
                        dga_result.detected_family.as_ref()
                            .map(|f| format!(" (family: {})", f))
                            .unwrap_or_default()
                    ),
                    indicators: serde_json::to_value(&dga_result).unwrap_or_default(),
                    entropy_score: Some(dga_result.entropy),
                    dga_probability: Some(dga_result.probability),
                    tunnel_indicators: None,
                    fast_flux_indicators: None,
                    first_seen: now,
                    last_seen: now,
                    query_count: 1,
                    status: DnsAnomalyStatus::New,
                    source_ips: vec![query.source_ip],
                    created_at: now,
                });
            }
        }

        // Tunnel detection
        {
            let mut tunnel = self.tunnel_detector.write().await;
            tunnel.process_query(query);
            if let Some(anomaly) = tunnel.analyze_domain(&query.query_name) {
                result.tunneling_detected = true;
                result.tunnel_indicators = anomaly.tunnel_indicators.clone();
                result.anomalies.push(anomaly);
            }
        }

        // Fast-flux detection (if we have response data with IPs)
        for response in &query.response_data {
            if let Ok(ip) = response.parse::<std::net::IpAddr>() {
                let resolution = DnsResolution {
                    domain: query.query_name.clone(),
                    resolved_ip: ip,
                    ttl: query.ttl.unwrap_or(300),
                    timestamp: query.timestamp,
                    country: None, // Would need GeoIP lookup
                    asn: None,
                    asn_name: None,
                };

                let mut ff = self.fast_flux_detector.write().await;
                ff.process_resolution(&resolution);
                if let Some(anomaly) = ff.analyze_domain(&query.query_name) {
                    result.fast_flux_detected = true;
                    result.fast_flux_indicators = anomaly.fast_flux_indicators.clone();
                    if !result.anomalies.iter().any(|a| a.anomaly_type == DnsAnomalyType::FastFlux) {
                        result.anomalies.push(anomaly);
                    }
                }
            }
        }

        // NOD tracking
        if let Some(nod) = self.nod_tracker.process_domain(&query.query_name, query.source_ip).await {
            result.is_nod = true;
            result.nod = Some(nod);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.queries_processed += 1;
            stats.anomalies_detected += result.anomalies.len() as i64;
            if result.is_nod {
                stats.nods_detected += 1;
            }
            stats.last_processed = Some(now);
        }

        result
    }

    /// Get dashboard data
    pub async fn get_dashboard(&self) -> DnsDashboard {
        let stats = self.passive_dns.get_stats().await;
        let nod_alerts = self.nod_tracker.get_alerts(false).await;

        // Get recent NODs
        let day_ago = Utc::now() - chrono::Duration::hours(24);
        let recent_nods = self.nod_tracker.get_nods_in_range(day_ago, Utc::now()).await;

        // Build threat breakdown from NOD threat types
        let mut threat_breakdown = std::collections::HashMap::new();
        for nod in &recent_nods {
            if let Some(threat_type) = &nod.threat_type {
                *threat_breakdown.entry(threat_type.to_string()).or_insert(0) += 1;
            }
        }

        DnsDashboard {
            stats,
            recent_anomalies: vec![], // Would be populated from database
            recent_nods,
            threat_breakdown,
            query_trend: vec![], // Would be populated from database time series
            anomaly_trend: vec![],
        }
    }

    /// Get engine statistics
    pub async fn get_stats(&self) -> (i64, i64, i64) {
        let stats = self.stats.read().await;
        (stats.queries_processed, stats.anomalies_detected, stats.nods_detected)
    }

    /// Clear all analytics data
    pub async fn clear(&self) {
        self.passive_dns.clear().await;
        self.tunnel_detector.write().await.clear();
        self.fast_flux_detector.write().await.clear();
        self.nod_tracker.clear().await;
        *self.stats.write().await = EngineStats::default();
    }
}

impl Default for DnsAnalyticsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of analyzing a DNS query
#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    /// DGA was detected
    pub dga_detected: bool,
    /// DGA analysis details
    pub dga_analysis: Option<DgaAnalysis>,
    /// DNS tunneling was detected
    pub tunneling_detected: bool,
    /// Tunnel indicators
    pub tunnel_indicators: Option<TunnelIndicators>,
    /// Fast-flux was detected
    pub fast_flux_detected: bool,
    /// Fast-flux indicators
    pub fast_flux_indicators: Option<FastFluxIndicators>,
    /// Domain is newly observed
    pub is_nod: bool,
    /// NOD details
    pub nod: Option<NewlyObservedDomain>,
    /// All detected anomalies
    pub anomalies: Vec<DnsAnomaly>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn create_test_query(domain: &str) -> DnsQuery {
        DnsQuery {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            source_ip: "192.168.1.100".parse().unwrap(),
            source_port: 12345,
            query_name: domain.to_string(),
            query_type: DnsRecordType::A,
            response_code: DnsResponseCode::NoError,
            response_data: vec!["93.184.216.34".to_string()],
            ttl: Some(300),
            latency_ms: Some(10),
            server_ip: None,
            is_recursive: true,
            is_dnssec: false,
        }
    }

    #[tokio::test]
    async fn test_engine_basic() {
        let engine = DnsAnalyticsEngine::new();

        let query = create_test_query("example.com");
        let result = engine.process_query(&query).await;

        // Normal domain should not trigger DGA or tunneling
        assert!(!result.dga_detected);
        assert!(!result.tunneling_detected);
    }

    #[tokio::test]
    async fn test_engine_dga_detection() {
        let engine = DnsAnalyticsEngine::new();

        // DGA-like domain
        let query = create_test_query("xjk38fds9werqazx.com");
        let result = engine.process_query(&query).await;

        assert!(result.dga_detected || result.is_nod);
    }

    #[tokio::test]
    async fn test_dashboard() {
        let engine = DnsAnalyticsEngine::new();

        // Process some queries
        engine.process_query(&create_test_query("google.com")).await;
        engine.process_query(&create_test_query("example.com")).await;

        let dashboard = engine.get_dashboard().await;
        assert!(dashboard.stats.total_queries >= 2);
    }
}
