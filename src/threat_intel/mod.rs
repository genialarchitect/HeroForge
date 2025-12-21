#![allow(dead_code)]
//! Threat Intelligence Feed Integration
//!
//! This module provides integration with multiple threat intelligence sources:
//! - **Shodan**: Exposed service detection and historical data
//! - **ExploitDB**: Known exploit correlation for services and CVEs
//! - **NVD/CISA KEV**: Real-time CVE announcements and known exploited vulnerabilities
//!
//! The feed manager coordinates lookups across sources and generates actionable alerts.

pub mod cve_feeds;
pub mod exploit_db;
pub mod shodan;
pub mod types;

use anyhow::Result;
use chrono::Utc;
use log::{debug, info, warn};
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

pub use cve_feeds::CveFeedsClient;
pub use exploit_db::ExploitDbClient;
pub use shodan::ShodanClient;
pub use types::*;

/// Threat Intelligence Feed Manager
///
/// Coordinates lookups across multiple threat intel sources, manages caching,
/// and generates alerts based on scan results.
pub struct ThreatIntelManager {
    shodan: Option<ShodanClient>,
    exploit_db: ExploitDbClient,
    cve_feeds: CveFeedsClient,
    pool: Arc<SqlitePool>,
    config: ThreatIntelConfig,
}

impl ThreatIntelManager {
    /// Create a new threat intel manager with database pool
    pub fn new(pool: Arc<SqlitePool>, config: ThreatIntelConfig) -> Self {
        // Initialize Shodan client if API key is available
        let shodan = config.shodan_api_key.as_ref().and_then(|key| {
            if key.is_empty() {
                None
            } else {
                match ShodanClient::new(key.clone()) {
                    Ok(client) => {
                        info!("Shodan integration enabled");
                        Some(client)
                    }
                    Err(e) => {
                        warn!("Failed to initialize Shodan client: {}", e);
                        None
                    }
                }
            }
        });

        // Initialize ExploitDB client
        let exploit_db = ExploitDbClient::new(config.shodan_api_key.clone());

        // Initialize CVE feeds client
        let cve_feeds = CveFeedsClient::new(config.nvd_api_key.clone());

        Self {
            shodan,
            exploit_db,
            cve_feeds,
            pool,
            config,
        }
    }

    /// Create manager from environment variables
    pub fn from_env(pool: Arc<SqlitePool>) -> Self {
        Self::new(pool, ThreatIntelConfig::default())
    }

    /// Look up threat intelligence for an IP address
    pub async fn lookup_ip(&self, ip: &str) -> Result<IpThreatIntel> {
        info!("Looking up threat intel for IP: {}", ip);

        // Check cache first
        if let Ok(Some(cached)) = crate::db::threat_intel::get_cached_ip_intel(&self.pool, ip).await {
            debug!("Using cached threat intel for {}", ip);
            return Ok(cached);
        }

        let mut result = IpThreatIntel {
            ip: ip.to_string(),
            shodan_info: None,
            associated_cves: Vec::new(),
            available_exploits: Vec::new(),
            threat_score: 0,
            risk_factors: Vec::new(),
            last_updated: Utc::now(),
        };

        // Shodan lookup
        if self.config.enable_shodan {
            if let Some(ref shodan) = self.shodan {
                match shodan.lookup_host(ip).await {
                    Ok(host_info) => {
                        // Extract CVEs from Shodan data
                        let shodan_cves: Vec<String> = host_info.vulns.clone();

                        // Look up details for each CVE
                        for cve_id in &shodan_cves {
                            if let Ok(cve) = self.cve_feeds.get_cve(cve_id).await {
                                result.associated_cves.push(cve);
                            }
                        }

                        // Look for exploits
                        if self.config.enable_exploit_db {
                            for cve_id in &shodan_cves {
                                if let Ok(exploits) = self.exploit_db.search_by_cve(cve_id).await {
                                    result.available_exploits.extend(exploits);
                                }
                            }
                        }

                        result.shodan_info = Some(host_info);
                    }
                    Err(e) => {
                        debug!("Shodan lookup failed for {}: {}", ip, e);
                    }
                }
            }
        }

        // Calculate threat score
        result.threat_score = calculate_threat_score(&result);
        result.risk_factors = identify_risk_factors(&result);

        // Cache the result
        if let Err(e) = crate::db::threat_intel::cache_ip_intel(&self.pool, &result, self.config.cache_ttl_hours).await {
            warn!("Failed to cache threat intel: {}", e);
        }

        Ok(result)
    }

    /// Get enriched CVE information with exploit data
    pub async fn get_enriched_cve(&self, cve_id: &str) -> Result<EnrichedCve> {
        info!("Getting enriched CVE: {}", cve_id);

        // Check cache first
        if let Ok(Some(cached)) = crate::db::threat_intel::get_cached_cve(&self.pool, cve_id).await {
            debug!("Using cached CVE data for {}", cve_id);
            return Ok(cached);
        }

        // Fetch from NVD
        let mut cve = self.cve_feeds.get_cve(cve_id).await?;

        // Enrich with exploit data
        if self.config.enable_exploit_db {
            match self.exploit_db.search_by_cve(cve_id).await {
                Ok(exploits) => {
                    cve.exploits = exploits;
                }
                Err(e) => {
                    debug!("Exploit lookup failed for {}: {}", cve_id, e);
                }
            }
        }

        // Cache the result
        if let Err(e) = crate::db::threat_intel::cache_cve(&self.pool, &cve, self.config.cache_ttl_hours).await {
            warn!("Failed to cache CVE data: {}", e);
        }

        Ok(cve)
    }

    /// Enrich scan results with threat intelligence
    pub async fn enrich_scan(&self, scan_id: &str, hosts: &[crate::types::HostInfo]) -> Result<EnrichmentResult> {
        info!("Enriching scan {} with threat intel ({} hosts)", scan_id, hosts.len());

        let mut alerts = Vec::new();
        let mut total_exploits = 0;
        let mut kev_matches = 0;
        let mut critical_findings = 0;

        for host in hosts {
            let ip = host.target.ip.to_string();

            // Look up IP threat intel
            if let Ok(intel) = self.lookup_ip(&ip).await {
                // Generate alerts based on findings
                alerts.extend(generate_ip_alerts(&intel, scan_id, &host.target.hostname));

                if let Some(ref shodan) = intel.shodan_info {
                    // Check for exposed services
                    for service in &shodan.services {
                        if is_sensitive_service(&service.product.as_deref().unwrap_or("")) {
                            alerts.push(create_exposed_service_alert(
                                &ip,
                                service,
                                scan_id,
                            ));
                        }
                    }
                }

                total_exploits += intel.available_exploits.len();
            }

            // Check vulnerabilities found in scan
            for vuln in &host.vulnerabilities {
                if let Some(ref cve_id) = vuln.cve_id {
                    // Get enriched CVE data
                    if let Ok(enriched) = self.get_enriched_cve(cve_id).await {
                        // Check if in KEV
                        if enriched.in_cisa_kev {
                            kev_matches += 1;
                            alerts.push(create_kev_alert(&enriched, &ip, scan_id));
                        }

                        // Check for available exploits
                        if !enriched.exploits.is_empty() {
                            alerts.push(create_exploit_available_alert(&enriched, &ip, scan_id));
                            total_exploits += enriched.exploits.len();
                        }

                        // Check severity
                        if enriched.severity == ThreatSeverity::Critical {
                            critical_findings += 1;
                        }
                    }
                }
            }
        }

        // Deduplicate alerts
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
        alerts.dedup_by(|a, b| a.title == b.title);

        // Store alerts
        for alert in &alerts {
            if let Err(e) = crate::db::threat_intel::store_alert(&self.pool, alert).await {
                warn!("Failed to store alert: {}", e);
            }
        }

        let result = EnrichmentResult {
            scan_id: scan_id.to_string(),
            alerts_generated: alerts,
            enriched_hosts: hosts.len(),
            total_exploits_found: total_exploits,
            critical_findings,
            kev_matches,
            enriched_at: Utc::now(),
        };

        // Store enrichment result
        if let Err(e) = crate::db::threat_intel::store_enrichment_result(&self.pool, &result).await {
            warn!("Failed to store enrichment result: {}", e);
        }

        Ok(result)
    }

    /// Get recent threat alerts
    pub async fn get_recent_alerts(&self, limit: i32) -> Result<Vec<ThreatAlert>> {
        crate::db::threat_intel::get_recent_alerts(&self.pool, limit).await
    }

    /// Get alerts for a specific scan
    pub async fn get_scan_alerts(&self, scan_id: &str) -> Result<Vec<ThreatAlert>> {
        crate::db::threat_intel::get_alerts_for_scan(&self.pool, scan_id).await
    }

    /// Check Shodan availability
    pub fn is_shodan_available(&self) -> bool {
        self.shodan.is_some()
    }

    /// Get API quota info
    pub async fn get_api_status(&self) -> Result<ApiStatus> {
        let shodan_status = if let Some(ref shodan) = self.shodan {
            match shodan.get_api_info().await {
                Ok(info) => Some(ShodanApiStatus {
                    query_credits: info.query_credits,
                    scan_credits: info.scan_credits,
                    plan: info.plan,
                }),
                Err(_) => None,
            }
        } else {
            None
        };

        Ok(ApiStatus {
            shodan: shodan_status,
            nvd_api_key_configured: self.config.nvd_api_key.is_some(),
            shodan_api_key_configured: self.config.shodan_api_key.is_some(),
        })
    }
}

/// API status information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiStatus {
    pub shodan: Option<ShodanApiStatus>,
    pub nvd_api_key_configured: bool,
    pub shodan_api_key_configured: bool,
}

/// Shodan API status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShodanApiStatus {
    pub query_credits: i32,
    pub scan_credits: i32,
    pub plan: String,
}

/// Calculate threat score (0-100) based on intel data
fn calculate_threat_score(intel: &IpThreatIntel) -> u8 {
    let mut score = 0u32;

    // Shodan-based factors
    if let Some(ref shodan) = intel.shodan_info {
        // Ports exposed
        score += (shodan.ports.len() as u32).min(20);

        // Known vulnerabilities
        score += (shodan.vulns.len() as u32 * 5).min(30);

        // Sensitive services
        for service in &shodan.services {
            if is_sensitive_service(&service.product.as_deref().unwrap_or("")) {
                score += 10;
            }
        }
    }

    // CVE severity factors
    for cve in &intel.associated_cves {
        match cve.severity {
            ThreatSeverity::Critical => score += 15,
            ThreatSeverity::High => score += 10,
            ThreatSeverity::Medium => score += 5,
            _ => score += 1,
        }

        if cve.in_cisa_kev {
            score += 20;
        }
    }

    // Exploit availability
    score += (intel.available_exploits.len() as u32 * 10).min(30);

    score.min(100) as u8
}

/// Identify risk factors for an IP
fn identify_risk_factors(intel: &IpThreatIntel) -> Vec<String> {
    let mut factors = Vec::new();

    if let Some(ref shodan) = intel.shodan_info {
        if !shodan.vulns.is_empty() {
            factors.push(format!("{} known CVEs detected", shodan.vulns.len()));
        }

        if shodan.ports.len() > 10 {
            factors.push(format!("{} open ports exposed", shodan.ports.len()));
        }

        for service in &shodan.services {
            if let Some(ref product) = service.product {
                if is_sensitive_service(product) {
                    factors.push(format!("Sensitive service exposed: {} on port {}", product, service.port));
                }
            }
        }
    }

    for cve in &intel.associated_cves {
        if cve.in_cisa_kev {
            factors.push(format!("{} is in CISA KEV catalog", cve.cve_id));
        }
    }

    if !intel.available_exploits.is_empty() {
        factors.push(format!("{} public exploits available", intel.available_exploits.len()));
    }

    factors
}

/// Check if a service is considered sensitive
fn is_sensitive_service(product: &str) -> bool {
    let product_lower = product.to_lowercase();
    let sensitive = [
        "redis", "mongodb", "mysql", "postgres", "mssql",
        "elasticsearch", "memcached", "jenkins", "docker",
        "kubernetes", "etcd", "consul", "vault", "rabbitmq",
        "kafka", "zookeeper", "cassandra", "couchdb",
    ];

    sensitive.iter().any(|s| product_lower.contains(s))
}

/// Generate alerts from IP threat intel
fn generate_ip_alerts(intel: &IpThreatIntel, scan_id: &str, hostname: &Option<String>) -> Vec<ThreatAlert> {
    let mut alerts = Vec::new();

    // Critical CVE alerts
    for cve in &intel.associated_cves {
        if cve.severity == ThreatSeverity::Critical {
            alerts.push(ThreatAlert {
                id: Uuid::new_v4().to_string(),
                alert_type: AlertType::CriticalCve,
                severity: ThreatSeverity::Critical,
                title: format!("Critical CVE {} affects {}", cve.cve_id, intel.ip),
                description: cve.description.clone(),
                source: ThreatSource::NvdCve,
                affected_assets: vec![AffectedAsset {
                    ip: intel.ip.clone(),
                    hostname: hostname.clone(),
                    port: None,
                    service: None,
                    version: None,
                }],
                cve_ids: vec![cve.cve_id.clone()],
                exploit_available: !cve.exploits.is_empty(),
                in_cisa_kev: cve.in_cisa_kev,
                recommendations: vec![
                    "Patch immediately or apply vendor mitigations".to_string(),
                    "Isolate affected systems if patching is not immediately possible".to_string(),
                ],
                references: cve.references.clone(),
                created_at: Utc::now(),
                scan_id: Some(scan_id.to_string()),
            });
        }
    }

    alerts
}

/// Create alert for exposed service
fn create_exposed_service_alert(ip: &str, service: &ShodanService, scan_id: &str) -> ThreatAlert {
    ThreatAlert {
        id: Uuid::new_v4().to_string(),
        alert_type: AlertType::ExposedService,
        severity: ThreatSeverity::High,
        title: format!(
            "Sensitive service {} exposed on {}:{}",
            service.product.as_deref().unwrap_or("unknown"),
            ip,
            service.port
        ),
        description: format!(
            "The service {} is publicly accessible on port {}. This service should typically not be exposed to the internet.",
            service.product.as_deref().unwrap_or("unknown"),
            service.port
        ),
        source: ThreatSource::Shodan,
        affected_assets: vec![AffectedAsset {
            ip: ip.to_string(),
            hostname: None,
            port: Some(service.port),
            service: service.product.clone(),
            version: service.version.clone(),
        }],
        cve_ids: service.vulns.clone(),
        exploit_available: false,
        in_cisa_kev: false,
        recommendations: vec![
            "Restrict access using firewall rules".to_string(),
            "Enable authentication if not already configured".to_string(),
            "Consider using a VPN for remote access".to_string(),
        ],
        references: Vec::new(),
        created_at: Utc::now(),
        scan_id: Some(scan_id.to_string()),
    }
}

/// Create alert for KEV vulnerability
fn create_kev_alert(cve: &EnrichedCve, ip: &str, scan_id: &str) -> ThreatAlert {
    ThreatAlert {
        id: Uuid::new_v4().to_string(),
        alert_type: AlertType::KnownExploitedVulnerability,
        severity: ThreatSeverity::Critical,
        title: format!("{} is actively exploited in the wild", cve.cve_id),
        description: format!(
            "{}. This vulnerability is listed in CISA's Known Exploited Vulnerabilities catalog, indicating active exploitation.",
            cve.description
        ),
        source: ThreatSource::CisaKev,
        affected_assets: vec![AffectedAsset {
            ip: ip.to_string(),
            hostname: None,
            port: None,
            service: None,
            version: None,
        }],
        cve_ids: vec![cve.cve_id.clone()],
        exploit_available: !cve.exploits.is_empty(),
        in_cisa_kev: true,
        recommendations: vec![
            format!(
                "Remediate by {} as per CISA KEV requirement",
                cve.kev_due_date.as_deref().unwrap_or("ASAP")
            ),
            "Apply vendor patches immediately".to_string(),
            "If patches unavailable, apply mitigations or isolate affected systems".to_string(),
        ],
        references: cve.references.clone(),
        created_at: Utc::now(),
        scan_id: Some(scan_id.to_string()),
    }
}

/// Create alert for available exploit
fn create_exploit_available_alert(cve: &EnrichedCve, ip: &str, scan_id: &str) -> ThreatAlert {
    let exploit_names: Vec<String> = cve.exploits.iter().map(|e| e.title.clone()).collect();

    ThreatAlert {
        id: Uuid::new_v4().to_string(),
        alert_type: AlertType::ExploitAvailable,
        severity: if cve.severity == ThreatSeverity::Critical {
            ThreatSeverity::Critical
        } else {
            ThreatSeverity::High
        },
        title: format!(
            "Public exploit available for {} on {}",
            cve.cve_id, ip
        ),
        description: format!(
            "{} public exploit(s) available for {}: {}",
            cve.exploits.len(),
            cve.cve_id,
            exploit_names.join(", ")
        ),
        source: ThreatSource::ExploitDb,
        affected_assets: vec![AffectedAsset {
            ip: ip.to_string(),
            hostname: None,
            port: None,
            service: None,
            version: None,
        }],
        cve_ids: vec![cve.cve_id.clone()],
        exploit_available: true,
        in_cisa_kev: cve.in_cisa_kev,
        recommendations: vec![
            "Prioritize patching - public exploit increases risk significantly".to_string(),
            "Monitor for exploitation attempts".to_string(),
            "Consider additional network segmentation".to_string(),
        ],
        references: cve.exploits.iter().map(|e| e.url.clone()).collect(),
        created_at: Utc::now(),
        scan_id: Some(scan_id.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sensitive_service() {
        assert!(is_sensitive_service("Redis"));
        assert!(is_sensitive_service("MongoDB"));
        assert!(is_sensitive_service("mysql-server"));
        assert!(!is_sensitive_service("nginx"));
        assert!(!is_sensitive_service("apache"));
    }

    #[test]
    fn test_calculate_threat_score() {
        let intel = IpThreatIntel {
            ip: "1.2.3.4".to_string(),
            shodan_info: None,
            associated_cves: Vec::new(),
            available_exploits: Vec::new(),
            threat_score: 0,
            risk_factors: Vec::new(),
            last_updated: Utc::now(),
        };
        assert_eq!(calculate_threat_score(&intel), 0);
    }
}
