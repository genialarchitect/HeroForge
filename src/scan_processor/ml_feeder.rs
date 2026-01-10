//! ML Feature Extraction Module
//!
//! Extracts enhanced features from scan data to improve ML-based
//! vulnerability prioritization and risk scoring.

use chrono::{DateTime, Utc};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::types::{HostInfo, OsInfo, PortInfo, PortState, SslInfo};
use super::EnrichedVulnerability;

/// Enhanced feature set for ML prioritization
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnhancedFeatureSet {
    // === Existing features ===
    pub cvss_scores: Vec<f64>,
    pub exploit_availability: Vec<bool>,

    // === Service Version Features ===
    pub service_versions: Vec<ServiceVersionInfo>,
    pub version_currency_score: f64,  // 0-100, how current are versions
    pub outdated_service_count: usize,
    pub eol_service_count: usize,

    // === SSL/TLS Features ===
    pub weak_cipher_count: usize,
    pub weak_protocol_count: usize,
    pub expired_cert_count: usize,
    pub expiring_soon_count: usize,  // Within 30 days
    pub self_signed_count: usize,
    pub avg_cert_days_remaining: Option<f64>,
    pub ssl_grade_distribution: SslGradeDistribution,

    // === Network Exposure Features ===
    pub total_open_ports: usize,
    pub internet_facing_services: usize,
    pub high_risk_port_count: usize,  // Telnet, FTP, SMB, etc.
    pub database_exposure_count: usize,
    pub management_interface_count: usize,  // SSH, RDP, VNC

    // === OS Fingerprint Features ===
    pub os_detection_confidence: f64,  // Average confidence
    pub eol_os_count: usize,
    pub windows_hosts: usize,
    pub linux_hosts: usize,
    pub unknown_os_count: usize,

    // === Threat Intel Features ===
    pub threat_actor_targeting_score: f64,
    pub active_exploitation_count: usize,
    pub known_exploit_count: usize,
    pub cisa_kev_count: usize,  // CISA Known Exploited Vulnerabilities

    // === Temporal Features ===
    pub avg_vuln_age_days: Option<f64>,
    pub newest_vuln_days: Option<i64>,
    pub oldest_vuln_days: Option<i64>,

    // === Aggregate Metrics ===
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub unique_cve_count: usize,
    pub host_count: usize,
}

/// Service version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceVersionInfo {
    pub service_name: String,
    pub version: Option<String>,
    pub is_outdated: bool,
    pub is_eol: bool,
    pub days_since_release: Option<i64>,
}

/// SSL grade distribution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SslGradeDistribution {
    pub a_plus: usize,
    pub a: usize,
    pub b: usize,
    pub c: usize,
    pub d: usize,
    pub f: usize,
    pub unknown: usize,
}

/// Extract enhanced features from scan data
pub fn extract_enhanced_features(
    hosts: &[HostInfo],
    enriched_vulns: &[EnrichedVulnerability],
) -> EnhancedFeatureSet {
    let mut features = EnhancedFeatureSet {
        host_count: hosts.len(),
        ..Default::default()
    };

    // Process enriched vulnerabilities
    for vuln in enriched_vulns {
        if let Some(score) = vuln.cvss_v3_score {
            features.cvss_scores.push(score);
        }
        features.exploit_availability.push(vuln.exploit_available);

        if vuln.exploit_available {
            features.known_exploit_count += 1;
        }

        // Categorize by severity based on CVSS
        if let Some(score) = vuln.cvss_v3_score {
            match score {
                s if s >= 9.0 => features.critical_count += 1,
                s if s >= 7.0 => features.high_count += 1,
                s if s >= 4.0 => features.medium_count += 1,
                _ => features.low_count += 1,
            }
        }

        // Calculate vulnerability age
        if let Some(ref published) = vuln.published_date {
            if let Ok(date) = DateTime::parse_from_rfc3339(published) {
                let age_days = (Utc::now() - date.with_timezone(&Utc)).num_days();
                if features.newest_vuln_days.is_none() || age_days < features.newest_vuln_days.unwrap() {
                    features.newest_vuln_days = Some(age_days);
                }
                if features.oldest_vuln_days.is_none() || age_days > features.oldest_vuln_days.unwrap() {
                    features.oldest_vuln_days = Some(age_days);
                }
            }
        }
    }

    features.total_vulnerabilities = enriched_vulns.len();
    features.unique_cve_count = enriched_vulns
        .iter()
        .map(|v| &v.cve_id)
        .collect::<std::collections::HashSet<_>>()
        .len();

    // Calculate average CVSS
    if !features.cvss_scores.is_empty() {
        let _avg = features.cvss_scores.iter().sum::<f64>() / features.cvss_scores.len() as f64;
    }

    // Process hosts
    for host in hosts {
        // OS features
        if let Some(ref os) = host.os_guess {
            features.os_detection_confidence += os.confidence as f64;
            extract_os_features(&mut features, os);
        } else {
            features.unknown_os_count += 1;
        }

        // Port and service features
        for port in &host.ports {
            if port.state == PortState::Open {
                features.total_open_ports += 1;
                extract_port_features(&mut features, port);

                if let Some(ref service) = port.service {
                    // Service version features
                    let version_info = analyze_service_version(&service.name, service.version.as_deref());
                    if version_info.is_outdated {
                        features.outdated_service_count += 1;
                    }
                    if version_info.is_eol {
                        features.eol_service_count += 1;
                    }
                    features.service_versions.push(version_info);

                    // SSL features
                    if let Some(ref ssl) = service.ssl_info {
                        extract_ssl_features(&mut features, ssl);
                    }
                }
            }
        }

        // Vulnerability count from host
        features.total_vulnerabilities += host.vulnerabilities.len();
        for vuln in &host.vulnerabilities {
            match vuln.severity {
                crate::types::Severity::Critical => features.critical_count += 1,
                crate::types::Severity::High => features.high_count += 1,
                crate::types::Severity::Medium => features.medium_count += 1,
                crate::types::Severity::Low => features.low_count += 1,
            }
        }
    }

    // Calculate averages
    if hosts.len() > 0 {
        features.os_detection_confidence /= hosts.len() as f64;
    }

    // Calculate version currency score
    features.version_currency_score = calculate_version_currency(&features);

    // Calculate threat actor targeting score
    features.threat_actor_targeting_score = calculate_targeting_score(&features);

    debug!(
        "Extracted enhanced features: {} vulns, {} hosts, {} open ports",
        features.total_vulnerabilities,
        features.host_count,
        features.total_open_ports
    );

    features
}

/// Extract OS-related features
fn extract_os_features(features: &mut EnhancedFeatureSet, os: &OsInfo) {
    let family = os.os_family.to_lowercase();

    if family.contains("windows") {
        features.windows_hosts += 1;

        // Check for EOL Windows versions
        if family.contains("xp") || family.contains("vista")
            || family.contains("2003") || family.contains("2008")
            || family.contains("7") || family.contains("8")
        {
            features.eol_os_count += 1;
        }
    } else if family.contains("linux") || family.contains("unix") {
        features.linux_hosts += 1;

        // Check for EOL Linux versions
        if let Some(ref version) = os.os_version {
            if is_eol_linux_version(&family, version) {
                features.eol_os_count += 1;
            }
        }
    } else {
        features.unknown_os_count += 1;
    }
}

/// Check if Linux version is EOL
fn is_eol_linux_version(family: &str, version: &str) -> bool {
    // Simplified EOL checks
    if family.contains("ubuntu") {
        // Ubuntu LTS versions that are EOL
        let eol_versions = ["12.04", "14.04", "16.04", "18.04"];
        return eol_versions.iter().any(|v| version.contains(v));
    }
    if family.contains("centos") || family.contains("rhel") {
        // CentOS/RHEL EOL versions
        let eol_versions = ["5", "6", "7"];
        return eol_versions.iter().any(|v| version.starts_with(v));
    }
    if family.contains("debian") {
        // Debian EOL versions
        let eol_versions = ["6", "7", "8", "9"];
        return eol_versions.iter().any(|v| version.starts_with(v));
    }
    false
}

/// Extract port-related features
fn extract_port_features(features: &mut EnhancedFeatureSet, port: &PortInfo) {
    let port_num = port.port;

    // High-risk ports
    let high_risk_ports = [21, 23, 139, 445, 3389, 5900, 11211, 27017, 6379];
    if high_risk_ports.contains(&port_num) {
        features.high_risk_port_count += 1;
    }

    // Database ports
    let db_ports = [1433, 1521, 3306, 5432, 27017, 6379, 9200, 9300, 11211];
    if db_ports.contains(&port_num) {
        features.database_exposure_count += 1;
    }

    // Management interfaces
    let mgmt_ports = [22, 23, 3389, 5900, 5901, 8080, 8443, 9090];
    if mgmt_ports.contains(&port_num) {
        features.management_interface_count += 1;
    }

    // Internet-facing services (common web ports)
    let internet_facing = [80, 443, 8080, 8443];
    if internet_facing.contains(&port_num) {
        features.internet_facing_services += 1;
    }
}

/// Extract SSL/TLS features
fn extract_ssl_features(features: &mut EnhancedFeatureSet, ssl: &SslInfo) {
    // Weak ciphers
    features.weak_cipher_count += ssl.weak_ciphers.len();

    // Weak protocols
    features.weak_protocol_count += ssl.weak_protocols.len();

    // Certificate status
    if ssl.cert_expired {
        features.expired_cert_count += 1;
    }

    if let Some(days) = ssl.days_until_expiry {
        if days > 0 && days <= 30 {
            features.expiring_soon_count += 1;
        }

        // Track for average calculation
        if let Some(avg) = features.avg_cert_days_remaining {
            features.avg_cert_days_remaining = Some((avg + days as f64) / 2.0);
        } else {
            features.avg_cert_days_remaining = Some(days as f64);
        }
    }

    if ssl.self_signed {
        features.self_signed_count += 1;
    }

    // SSL grade distribution
    if let Some(ref grade) = ssl.ssl_grade {
        use crate::scanner::ssl_scanner::SslGradeLevel;
        match grade.grade {
            SslGradeLevel::APlus => features.ssl_grade_distribution.a_plus += 1,
            SslGradeLevel::A | SslGradeLevel::AMinus => features.ssl_grade_distribution.a += 1,
            SslGradeLevel::BPlus | SslGradeLevel::B | SslGradeLevel::BMinus => features.ssl_grade_distribution.b += 1,
            SslGradeLevel::C => features.ssl_grade_distribution.c += 1,
            SslGradeLevel::D => features.ssl_grade_distribution.d += 1,
            SslGradeLevel::F | SslGradeLevel::T | SslGradeLevel::M => features.ssl_grade_distribution.f += 1,
            SslGradeLevel::Unknown => features.ssl_grade_distribution.unknown += 1,
        }
    } else {
        features.ssl_grade_distribution.unknown += 1;
    }
}

/// Analyze service version for currency
fn analyze_service_version(service_name: &str, version: Option<&str>) -> ServiceVersionInfo {
    let name = service_name.to_lowercase();
    let is_outdated;
    let is_eol;

    match (name.as_str(), version) {
        ("apache" | "httpd", Some(v)) => {
            is_eol = v.starts_with("2.2.") || v.starts_with("2.0.");
            is_outdated = v.starts_with("2.4.4") || v.starts_with("2.4.3")
                || v.starts_with("2.4.2") || v.starts_with("2.4.1");
        }
        ("nginx", Some(v)) => {
            is_eol = v.starts_with("1.16.") || v.starts_with("1.14.") || v.starts_with("1.12.");
            is_outdated = v.starts_with("1.18.") || v.starts_with("1.20.");
        }
        ("openssh" | "ssh", Some(v)) => {
            is_eol = v.starts_with("5.") || v.starts_with("6.");
            is_outdated = v.starts_with("7.");
        }
        ("mysql" | "mariadb", Some(v)) => {
            is_eol = v.starts_with("5.1.") || v.starts_with("5.5.") || v.starts_with("5.6.");
            is_outdated = v.starts_with("5.7.");
        }
        ("postgresql" | "postgres", Some(v)) => {
            is_eol = v.starts_with("9.") || v.starts_with("10.");
            is_outdated = v.starts_with("11.") || v.starts_with("12.");
        }
        _ => {
            is_eol = false;
            is_outdated = false;
        }
    }

    ServiceVersionInfo {
        service_name: service_name.to_string(),
        version: version.map(String::from),
        is_outdated,
        is_eol,
        days_since_release: None,  // Would require version database
    }
}

/// Calculate overall version currency score
fn calculate_version_currency(features: &EnhancedFeatureSet) -> f64 {
    if features.service_versions.is_empty() {
        return 100.0;  // No services to evaluate
    }

    let total = features.service_versions.len() as f64;
    let eol = features.eol_service_count as f64;
    let outdated = features.outdated_service_count as f64;

    // Score: 100% if all current, reduced by EOL (more) and outdated (less)
    let eol_penalty = (eol / total) * 50.0;
    let outdated_penalty = (outdated / total) * 25.0;

    (100.0 - eol_penalty - outdated_penalty).max(0.0)
}

/// Calculate threat actor targeting score
fn calculate_targeting_score(features: &EnhancedFeatureSet) -> f64 {
    let mut score = 0.0;

    // Base on exploit availability
    let exploit_ratio = if features.total_vulnerabilities > 0 {
        features.known_exploit_count as f64 / features.total_vulnerabilities as f64
    } else {
        0.0
    };
    score += exploit_ratio * 30.0;

    // High/critical vulnerability ratio
    let severe_ratio = if features.total_vulnerabilities > 0 {
        (features.critical_count + features.high_count) as f64
            / features.total_vulnerabilities as f64
    } else {
        0.0
    };
    score += severe_ratio * 25.0;

    // Database exposure (high value targets)
    if features.database_exposure_count > 0 {
        score += 15.0;
    }

    // EOL systems (easy targets)
    if features.eol_os_count > 0 {
        score += 10.0;
    }
    if features.eol_service_count > 0 {
        score += 10.0;
    }

    // Internet-facing services
    let internet_exposure = (features.internet_facing_services as f64).min(5.0) * 2.0;
    score += internet_exposure;

    score.min(100.0)
}

/// Convert features to a flat vector for ML model input
pub fn features_to_vector(features: &EnhancedFeatureSet) -> Vec<f64> {
    vec![
        // Aggregate metrics
        features.total_vulnerabilities as f64,
        features.critical_count as f64,
        features.high_count as f64,
        features.medium_count as f64,
        features.low_count as f64,
        features.unique_cve_count as f64,
        features.host_count as f64,

        // CVSS statistics
        if features.cvss_scores.is_empty() {
            0.0
        } else {
            features.cvss_scores.iter().sum::<f64>() / features.cvss_scores.len() as f64
        },
        features.cvss_scores.iter().cloned().fold(0.0, f64::max),

        // Exploit features
        features.known_exploit_count as f64,
        features.active_exploitation_count as f64,
        features.cisa_kev_count as f64,

        // Network exposure
        features.total_open_ports as f64,
        features.internet_facing_services as f64,
        features.high_risk_port_count as f64,
        features.database_exposure_count as f64,
        features.management_interface_count as f64,

        // SSL/TLS health
        features.weak_cipher_count as f64,
        features.weak_protocol_count as f64,
        features.expired_cert_count as f64,
        features.expiring_soon_count as f64,
        features.self_signed_count as f64,

        // Version currency
        features.version_currency_score,
        features.outdated_service_count as f64,
        features.eol_service_count as f64,

        // OS features
        features.os_detection_confidence,
        features.eol_os_count as f64,

        // Computed scores
        features.threat_actor_targeting_score,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_service_version() {
        let info = analyze_service_version("apache", Some("2.2.34"));
        assert!(info.is_eol);

        let info = analyze_service_version("nginx", Some("1.24.0"));
        assert!(!info.is_eol);
        assert!(!info.is_outdated);
    }

    #[test]
    fn test_calculate_version_currency() {
        let mut features = EnhancedFeatureSet::default();
        features.service_versions = vec![
            ServiceVersionInfo {
                service_name: "apache".to_string(),
                version: Some("2.4.57".to_string()),
                is_outdated: false,
                is_eol: false,
                days_since_release: None,
            },
        ];

        let score = calculate_version_currency(&features);
        assert_eq!(score, 100.0);
    }

    #[test]
    fn test_features_to_vector_length() {
        let features = EnhancedFeatureSet::default();
        let vector = features_to_vector(&features);
        assert_eq!(vector.len(), 28);  // Expected feature count
    }
}
