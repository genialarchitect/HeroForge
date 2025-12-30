//! Vulnerability Matcher
//!
//! Matches dependencies against OSV vulnerability data using
//! semantic version range comparison.

use crate::yellow_team::sca::osv_client::{OsvVulnerability, OsvAffected, OsvRange, OsvEvent};
use crate::yellow_team::types::VulnSeverity;
use serde::{Deserialize, Serialize};

// ============================================================================
// Types
// ============================================================================

/// Result of matching a vulnerability against a specific version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedVulnerability {
    pub vuln_id: String,
    pub aliases: Vec<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: VulnSeverity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fixed_version: Option<String>,
    pub affected_versions: String,
    pub references: Vec<String>,
    pub is_affected: bool,
    pub source: String,
}

// ============================================================================
// Vulnerability Matcher
// ============================================================================

/// Matches packages against known vulnerabilities
pub struct VulnerabilityMatcher {
    // Cache could be added here for performance
}

impl VulnerabilityMatcher {
    /// Create a new vulnerability matcher
    pub fn new() -> Self {
        Self {}
    }

    /// Match a vulnerability against a specific package version
    pub fn match_vulnerability(
        &self,
        vuln: &OsvVulnerability,
        version: &str,
    ) -> MatchedVulnerability {
        let is_affected = self.is_version_affected(vuln, version);
        let severity = self.determine_severity(vuln);
        let fixed_version = self.extract_fixed_version(vuln);
        let affected_versions = self.format_affected_versions(vuln);

        MatchedVulnerability {
            vuln_id: vuln.id.clone(),
            aliases: vuln.aliases.clone(),
            title: vuln.summary.clone(),
            description: vuln.details.clone(),
            severity,
            cvss_score: vuln.cvss_score(),
            cvss_vector: self.extract_cvss_vector(vuln),
            fixed_version,
            affected_versions,
            references: vuln.reference_urls().iter().map(|s| s.to_string()).collect(),
            is_affected,
            source: "osv".to_string(),
        }
    }

    /// Check if a specific version is affected by the vulnerability
    pub fn is_version_affected(&self, vuln: &OsvVulnerability, version: &str) -> bool {
        for affected in &vuln.affected {
            // Check explicit version list first
            if affected.versions.contains(&version.to_string()) {
                return true;
            }

            // Check version ranges
            for range in &affected.ranges {
                if self.is_in_range(version, range) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a version falls within an OSV range
    fn is_in_range(&self, version: &str, range: &OsvRange) -> bool {
        match range.range_type.as_str() {
            "SEMVER" => self.check_semver_range(version, &range.events),
            "ECOSYSTEM" => self.check_ecosystem_range(version, &range.events),
            "GIT" => {
                // Git ranges require commit hash comparison, skip for now
                false
            }
            _ => false,
        }
    }

    /// Check if version is in semver range
    fn check_semver_range(&self, version: &str, events: &[OsvEvent]) -> bool {
        let parsed_version = match parse_semver(version) {
            Some(v) => v,
            None => return false, // Can't compare if we can't parse
        };

        let mut affected = false;

        for event in events {
            if let Some(introduced) = &event.introduced {
                // Version 0 means the beginning
                if introduced == "0" {
                    affected = true;
                } else if let Some(intro_ver) = parse_semver(introduced) {
                    if compare_versions(&parsed_version, &intro_ver) >= 0 {
                        affected = true;
                    }
                }
            }

            if let Some(fixed) = &event.fixed {
                if let Some(fix_ver) = parse_semver(fixed) {
                    if compare_versions(&parsed_version, &fix_ver) >= 0 {
                        affected = false;
                    }
                }
            }

            if let Some(last_affected) = &event.last_affected {
                if let Some(last_ver) = parse_semver(last_affected) {
                    if compare_versions(&parsed_version, &last_ver) > 0 {
                        affected = false;
                    }
                }
            }
        }

        affected
    }

    /// Check if version is in ecosystem-specific range
    fn check_ecosystem_range(&self, version: &str, events: &[OsvEvent]) -> bool {
        // Ecosystem ranges often use the same logic as semver
        // but may have different version formats
        self.check_semver_range(version, events)
    }

    /// Determine severity from vulnerability data
    fn determine_severity(&self, vuln: &OsvVulnerability) -> VulnSeverity {
        if let Some(score) = vuln.cvss_score() {
            return match score {
                s if s >= 9.0 => VulnSeverity::Critical,
                s if s >= 7.0 => VulnSeverity::High,
                s if s >= 4.0 => VulnSeverity::Medium,
                s if s > 0.0 => VulnSeverity::Low,
                _ => VulnSeverity::Unknown,
            };
        }

        // Check database_specific for severity hints
        if let Some(db_specific) = &vuln.database_specific {
            if let Some(severity) = db_specific.get("severity").and_then(|v| v.as_str()) {
                return match severity.to_lowercase().as_str() {
                    "critical" => VulnSeverity::Critical,
                    "high" => VulnSeverity::High,
                    "moderate" | "medium" => VulnSeverity::Medium,
                    "low" => VulnSeverity::Low,
                    _ => VulnSeverity::Unknown,
                };
            }
        }

        VulnSeverity::Unknown
    }

    /// Extract the fixed version from vulnerability data
    fn extract_fixed_version(&self, vuln: &OsvVulnerability) -> Option<String> {
        for affected in &vuln.affected {
            for range in &affected.ranges {
                for event in &range.events {
                    if let Some(fixed) = &event.fixed {
                        return Some(fixed.clone());
                    }
                }
            }
        }
        None
    }

    /// Extract CVSS vector string
    fn extract_cvss_vector(&self, vuln: &OsvVulnerability) -> Option<String> {
        for sev in &vuln.severity {
            if sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2" {
                // Check if it's a vector string (contains '/')
                if sev.score.contains('/') {
                    return Some(sev.score.clone());
                }
            }
        }
        None
    }

    /// Format affected versions for display
    fn format_affected_versions(&self, vuln: &OsvVulnerability) -> String {
        let mut parts = Vec::new();

        for affected in &vuln.affected {
            // Add explicit versions
            if !affected.versions.is_empty() {
                let versions: Vec<_> = affected.versions.iter().take(5).cloned().collect();
                if affected.versions.len() > 5 {
                    parts.push(format!("{} (+{} more)", versions.join(", "), affected.versions.len() - 5));
                } else {
                    parts.push(versions.join(", "));
                }
            }

            // Add range descriptions
            for range in &affected.ranges {
                let mut range_desc = String::new();
                for event in &range.events {
                    if let Some(introduced) = &event.introduced {
                        if introduced == "0" {
                            range_desc.push_str("all versions");
                        } else {
                            range_desc.push_str(&format!(">= {}", introduced));
                        }
                    }
                    if let Some(fixed) = &event.fixed {
                        if !range_desc.is_empty() {
                            range_desc.push_str(", ");
                        }
                        range_desc.push_str(&format!("< {}", fixed));
                    }
                    if let Some(last) = &event.last_affected {
                        if !range_desc.is_empty() {
                            range_desc.push_str(", ");
                        }
                        range_desc.push_str(&format!("<= {}", last));
                    }
                }
                if !range_desc.is_empty() {
                    parts.push(range_desc);
                }
            }
        }

        if parts.is_empty() {
            "unknown".to_string()
        } else {
            parts.join("; ")
        }
    }
}

impl Default for VulnerabilityMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Version Parsing and Comparison
// ============================================================================

/// Parsed semantic version
#[derive(Debug, Clone, PartialEq, Eq)]
struct SemVer {
    major: u32,
    minor: u32,
    patch: u32,
    prerelease: Option<String>,
}

/// Parse a version string into semver components
fn parse_semver(version: &str) -> Option<SemVer> {
    let version = version.trim_start_matches('v');
    let version = version.trim_start_matches('V');

    // Split on prerelease/build metadata
    let (version_part, prerelease) = if let Some(idx) = version.find(|c| c == '-' || c == '+') {
        let (v, p) = version.split_at(idx);
        (v, Some(p[1..].to_string()))
    } else {
        (version, None)
    };

    let parts: Vec<&str> = version_part.split('.').collect();

    let major = parts.first()?.parse().ok()?;
    let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    Some(SemVer {
        major,
        minor,
        patch,
        prerelease,
    })
}

/// Compare two semver versions
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
fn compare_versions(a: &SemVer, b: &SemVer) -> i32 {
    // Compare major
    match a.major.cmp(&b.major) {
        std::cmp::Ordering::Less => return -1,
        std::cmp::Ordering::Greater => return 1,
        std::cmp::Ordering::Equal => {}
    }

    // Compare minor
    match a.minor.cmp(&b.minor) {
        std::cmp::Ordering::Less => return -1,
        std::cmp::Ordering::Greater => return 1,
        std::cmp::Ordering::Equal => {}
    }

    // Compare patch
    match a.patch.cmp(&b.patch) {
        std::cmp::Ordering::Less => return -1,
        std::cmp::Ordering::Greater => return 1,
        std::cmp::Ordering::Equal => {}
    }

    // Prerelease handling: no prerelease > prerelease
    match (&a.prerelease, &b.prerelease) {
        (None, Some(_)) => 1,
        (Some(_), None) => -1,
        (Some(pa), Some(pb)) => pa.cmp(pb) as i32,
        (None, None) => 0,
    }
}

/// Check if version satisfies a constraint (e.g., ">=1.0.0", "<2.0.0")
pub fn satisfies_constraint(version: &str, constraint: &str) -> bool {
    let constraint = constraint.trim();

    // Handle exact version
    if !constraint.starts_with(|c| c == '>' || c == '<' || c == '=' || c == '~' || c == '^') {
        let parsed_version = match parse_semver(version) {
            Some(v) => v,
            None => return false,
        };
        let parsed_constraint = match parse_semver(constraint) {
            Some(v) => v,
            None => return false,
        };
        return compare_versions(&parsed_version, &parsed_constraint) == 0;
    }

    // Handle operators
    let (op, constraint_version) = if constraint.starts_with(">=") {
        (">=", &constraint[2..])
    } else if constraint.starts_with("<=") {
        ("<=", &constraint[2..])
    } else if constraint.starts_with("!=") {
        ("!=", &constraint[2..])
    } else if constraint.starts_with('>') {
        (">", &constraint[1..])
    } else if constraint.starts_with('<') {
        ("<", &constraint[1..])
    } else if constraint.starts_with('=') {
        ("=", &constraint[1..])
    } else if constraint.starts_with('^') {
        // Caret: compatible with version (same major if major > 0)
        return check_caret_constraint(version, &constraint[1..]);
    } else if constraint.starts_with('~') {
        // Tilde: approximately equivalent (same major.minor)
        return check_tilde_constraint(version, &constraint[1..]);
    } else {
        return false;
    };

    let parsed_version = match parse_semver(version) {
        Some(v) => v,
        None => return false,
    };
    let parsed_constraint = match parse_semver(constraint_version.trim()) {
        Some(v) => v,
        None => return false,
    };

    let cmp = compare_versions(&parsed_version, &parsed_constraint);

    match op {
        ">=" => cmp >= 0,
        "<=" => cmp <= 0,
        ">" => cmp > 0,
        "<" => cmp < 0,
        "=" => cmp == 0,
        "!=" => cmp != 0,
        _ => false,
    }
}

/// Check caret constraint (^)
fn check_caret_constraint(version: &str, constraint: &str) -> bool {
    let v = match parse_semver(version) {
        Some(v) => v,
        None => return false,
    };
    let c = match parse_semver(constraint) {
        Some(c) => c,
        None => return false,
    };

    if c.major > 0 {
        v.major == c.major && compare_versions(&v, &c) >= 0
    } else if c.minor > 0 {
        v.major == 0 && v.minor == c.minor && compare_versions(&v, &c) >= 0
    } else {
        v.major == 0 && v.minor == 0 && v.patch == c.patch
    }
}

/// Check tilde constraint (~)
fn check_tilde_constraint(version: &str, constraint: &str) -> bool {
    let v = match parse_semver(version) {
        Some(v) => v,
        None => return false,
    };
    let c = match parse_semver(constraint) {
        Some(c) => c,
        None => return false,
    };

    v.major == c.major && v.minor == c.minor && v.patch >= c.patch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver() {
        let v = parse_semver("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert_eq!(v.prerelease, None);

        let v = parse_semver("v2.0.0-alpha").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.prerelease, Some("alpha".to_string()));
    }

    #[test]
    fn test_compare_versions() {
        let v1 = parse_semver("1.0.0").unwrap();
        let v2 = parse_semver("2.0.0").unwrap();
        assert_eq!(compare_versions(&v1, &v2), -1);

        let v1 = parse_semver("1.2.3").unwrap();
        let v2 = parse_semver("1.2.3").unwrap();
        assert_eq!(compare_versions(&v1, &v2), 0);

        let v1 = parse_semver("1.2.4").unwrap();
        let v2 = parse_semver("1.2.3").unwrap();
        assert_eq!(compare_versions(&v1, &v2), 1);
    }

    #[test]
    fn test_satisfies_constraint() {
        assert!(satisfies_constraint("1.2.3", ">=1.0.0"));
        assert!(satisfies_constraint("1.2.3", "<2.0.0"));
        assert!(!satisfies_constraint("1.2.3", ">2.0.0"));
        assert!(satisfies_constraint("1.2.3", "1.2.3"));
        assert!(!satisfies_constraint("1.2.3", "1.2.4"));
    }

    #[test]
    fn test_caret_constraint() {
        assert!(check_caret_constraint("1.2.3", "1.0.0"));
        assert!(check_caret_constraint("1.9.9", "1.0.0"));
        assert!(!check_caret_constraint("2.0.0", "1.0.0"));
    }

    #[test]
    fn test_tilde_constraint() {
        assert!(check_tilde_constraint("1.2.3", "1.2.0"));
        assert!(check_tilde_constraint("1.2.9", "1.2.0"));
        assert!(!check_tilde_constraint("1.3.0", "1.2.0"));
    }
}
