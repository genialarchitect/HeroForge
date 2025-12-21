//! Feature Extraction for Vulnerability Prioritization
//!
//! This module handles extracting features from vulnerabilities
//! for use in the AI scoring model.

use crate::ai::models::{AssetCriticality, ExploitMaturity, NetworkExposure};
use serde::{Deserialize, Serialize};

/// Features extracted from a vulnerability for scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFeatures {
    /// Vulnerability tracking ID
    pub vulnerability_id: String,

    // CVSS Scores
    /// Base CVSS score (0.0 - 10.0)
    pub base_cvss: f64,
    /// Temporal CVSS score (adjusted for exploitability)
    pub temporal_cvss: Option<f64>,
    /// Environmental CVSS score (adjusted for environment)
    pub environmental_cvss: Option<f64>,

    // Exploit Information
    /// Whether an exploit is publicly available
    pub exploit_available: bool,
    /// Maturity of available exploits
    pub exploit_maturity: ExploitMaturity,

    // Asset Context
    /// Criticality of the affected asset
    pub asset_criticality: AssetCriticality,
    /// Network exposure level
    pub network_exposure: NetworkExposure,

    // Attack Path Context
    /// Score from attack path analysis (0-100)
    pub attack_path_score: f64,

    // Historical Data
    /// Average remediation time for similar vulnerabilities (days)
    pub historical_remediation_days: u32,

    // Compliance
    /// Compliance impact score (0-100)
    pub compliance_impact: f64,

    // Business Context
    /// Business context score (0-100)
    pub business_context_score: f64,

    // Additional Factors
    /// Age of the vulnerability in days
    pub age_days: u32,
    /// Whether this vulnerability has dependencies on other vulns
    pub has_dependencies: bool,
    /// Whether this vulnerability is known to be actively exploited
    pub is_actively_exploited: bool,
}

impl VulnerabilityFeatures {
    /// Create a new feature set with minimal information
    pub fn new(vulnerability_id: String, base_cvss: f64) -> Self {
        Self {
            vulnerability_id,
            base_cvss,
            temporal_cvss: None,
            environmental_cvss: None,
            exploit_available: false,
            exploit_maturity: ExploitMaturity::Unproven,
            asset_criticality: AssetCriticality::Medium,
            network_exposure: NetworkExposure::Internal,
            attack_path_score: 0.0,
            historical_remediation_days: 0,
            compliance_impact: 0.0,
            business_context_score: 50.0,
            age_days: 0,
            has_dependencies: false,
            is_actively_exploited: false,
        }
    }

    /// Get the effective CVSS score (environmental > temporal > base)
    pub fn effective_cvss(&self) -> f64 {
        self.environmental_cvss
            .or(self.temporal_cvss)
            .unwrap_or(self.base_cvss)
    }

    /// Check if this is a high-priority vulnerability based on features
    pub fn is_high_priority(&self) -> bool {
        self.base_cvss >= 7.0
            || self.exploit_available
            || self.is_actively_exploited
            || self.asset_criticality == AssetCriticality::Critical
    }
}

/// Feature extraction utilities
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Extract CVSS score from a CVE ID
    pub fn extract_cvss_from_cve(_cve_id: &str) -> Option<f64> {
        // In a real implementation, this would query the CVE database
        // For now, return None
        None
    }

    /// Map severity string to CVSS range
    pub fn severity_to_cvss_range(severity: &str) -> (f64, f64) {
        match severity.to_lowercase().as_str() {
            "critical" => (9.0, 10.0),
            "high" => (7.0, 8.9),
            "medium" => (4.0, 6.9),
            "low" => (0.1, 3.9),
            _ => (0.0, 10.0),
        }
    }

    /// Estimate CVSS from severity
    pub fn estimate_cvss_from_severity(severity: &str) -> f64 {
        match severity.to_lowercase().as_str() {
            "critical" => 9.5,
            "high" => 7.5,
            "medium" => 5.5,
            "low" => 2.5,
            _ => 5.0,
        }
    }

    /// Parse CVE IDs from a vulnerability description
    pub fn extract_cve_ids(description: &str) -> Vec<String> {
        let cve_pattern = regex::Regex::new(r"CVE-\d{4}-\d{4,}").unwrap();
        cve_pattern
            .find_iter(description)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    /// Determine if a service indicates internet exposure
    pub fn is_internet_facing_service(service_name: &str, port: u16) -> bool {
        let internet_services = [
            "http", "https", "nginx", "apache", "iis", "tomcat", "weblogic",
        ];
        let internet_ports = [80, 443, 8080, 8443, 8000, 3000];

        internet_services
            .iter()
            .any(|&s| service_name.to_lowercase().contains(s))
            || internet_ports.contains(&port)
    }

    /// Calculate age bonus/penalty based on vulnerability age
    pub fn calculate_age_factor(age_days: u32) -> f64 {
        // Older vulnerabilities that haven't been fixed get higher priority
        match age_days {
            0..=7 => 1.0,      // First week - standard
            8..=30 => 1.1,    // First month - slight increase
            31..=90 => 1.2,   // First quarter - moderate increase
            91..=180 => 1.3,  // First half year - higher
            _ => 1.5,         // Over 6 months - highest priority boost
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_features_new() {
        let features = VulnerabilityFeatures::new("vuln-123".to_string(), 7.5);
        assert_eq!(features.vulnerability_id, "vuln-123");
        assert_eq!(features.base_cvss, 7.5);
        assert!(!features.exploit_available);
    }

    #[test]
    fn test_effective_cvss() {
        let mut features = VulnerabilityFeatures::new("vuln-123".to_string(), 7.5);
        assert_eq!(features.effective_cvss(), 7.5);

        features.temporal_cvss = Some(7.0);
        assert_eq!(features.effective_cvss(), 7.0);

        features.environmental_cvss = Some(6.5);
        assert_eq!(features.effective_cvss(), 6.5);
    }

    #[test]
    fn test_is_high_priority() {
        let mut features = VulnerabilityFeatures::new("vuln-123".to_string(), 7.5);
        assert!(features.is_high_priority()); // CVSS >= 7.0

        features.base_cvss = 5.0;
        assert!(!features.is_high_priority());

        features.exploit_available = true;
        assert!(features.is_high_priority());
    }

    #[test]
    fn test_severity_to_cvss_range() {
        assert_eq!(FeatureExtractor::severity_to_cvss_range("critical"), (9.0, 10.0));
        assert_eq!(FeatureExtractor::severity_to_cvss_range("high"), (7.0, 8.9));
        assert_eq!(FeatureExtractor::severity_to_cvss_range("MEDIUM"), (4.0, 6.9));
        assert_eq!(FeatureExtractor::severity_to_cvss_range("Low"), (0.1, 3.9));
    }

    #[test]
    fn test_extract_cve_ids() {
        let description = "This vulnerability CVE-2023-1234 is related to CVE-2023-5678";
        let cves = FeatureExtractor::extract_cve_ids(description);
        assert_eq!(cves.len(), 2);
        assert!(cves.contains(&"CVE-2023-1234".to_string()));
        assert!(cves.contains(&"CVE-2023-5678".to_string()));
    }

    #[test]
    fn test_is_internet_facing_service() {
        assert!(FeatureExtractor::is_internet_facing_service("nginx", 443));
        assert!(FeatureExtractor::is_internet_facing_service("apache", 8080));
        assert!(FeatureExtractor::is_internet_facing_service("unknown", 80));
        assert!(!FeatureExtractor::is_internet_facing_service("mysql", 3306));
    }

    #[test]
    fn test_calculate_age_factor() {
        assert_eq!(FeatureExtractor::calculate_age_factor(1), 1.0);
        assert_eq!(FeatureExtractor::calculate_age_factor(15), 1.1);
        assert_eq!(FeatureExtractor::calculate_age_factor(60), 1.2);
        assert_eq!(FeatureExtractor::calculate_age_factor(120), 1.3);
        assert_eq!(FeatureExtractor::calculate_age_factor(200), 1.5);
    }
}
