//! License Compliance Checker
//!
//! Analyzes licenses of dependencies for compliance issues,
//! compatibility problems, and risk assessment.

use crate::yellow_team::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// License information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    /// SPDX license identifier
    pub spdx_id: Option<String>,
    /// License name
    pub name: String,
    /// License family
    pub family: LicenseFamily,
    /// Risk level
    pub risk: LicenseRisk,
    /// Is OSI approved
    pub osi_approved: bool,
    /// Is copyleft
    pub copyleft: bool,
    /// Requires attribution
    pub requires_attribution: bool,
    /// Requires source disclosure
    pub requires_source_disclosure: bool,
    /// Compatible with commercial use
    pub commercial_use: bool,
    /// URL to license text
    pub url: Option<String>,
}

/// License family categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseFamily {
    /// Permissive licenses (MIT, BSD, Apache)
    Permissive,
    /// Weak copyleft (LGPL, MPL, EPL)
    WeakCopyleft,
    /// Strong copyleft (GPL, AGPL)
    StrongCopyleft,
    /// Public domain (CC0, Unlicense)
    PublicDomain,
    /// Proprietary or custom
    Proprietary,
    /// Unknown or unrecognized
    Unknown,
}

/// License compliance issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseIssue {
    /// Component ID
    pub component_id: String,
    /// Component name
    pub component_name: String,
    /// License identifier
    pub license: String,
    /// Issue type
    pub issue_type: LicenseIssueType,
    /// Severity
    pub severity: Severity,
    /// Description
    pub description: String,
    /// Recommended action
    pub recommendation: String,
}

/// Types of license issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseIssueType {
    /// License is unknown or unrecognized
    UnknownLicense,
    /// License has high risk (copyleft, viral)
    HighRiskLicense,
    /// License incompatible with project license
    IncompatibleLicense,
    /// License requires attribution not provided
    MissingAttribution,
    /// License requires source disclosure
    SourceDisclosureRequired,
    /// Multiple incompatible licenses in same package
    LicenseConflict,
    /// Deprecated or problematic license
    DeprecatedLicense,
    /// License not OSI approved
    NotOsiApproved,
}

/// License compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseComplianceReport {
    /// Overall risk level
    pub overall_risk: LicenseRisk,
    /// Summary by license family
    pub family_summary: HashMap<String, u32>,
    /// Summary by risk level
    pub risk_summary: HashMap<String, u32>,
    /// List of issues found
    pub issues: Vec<LicenseIssue>,
    /// Components with unknown licenses
    pub unknown_licenses: Vec<String>,
    /// Copyleft licenses detected
    pub copyleft_licenses: Vec<String>,
}

/// Known licenses database
lazy_static::lazy_static! {
    static ref KNOWN_LICENSES: HashMap<&'static str, LicenseInfo> = {
        let mut m = HashMap::new();
        
        // Permissive licenses
        m.insert("MIT", LicenseInfo {
            spdx_id: Some("MIT".to_string()),
            name: "MIT License".to_string(),
            family: LicenseFamily::Permissive,
            risk: LicenseRisk::Low,
            osi_approved: true,
            copyleft: false,
            requires_attribution: true,
            requires_source_disclosure: false,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/MIT".to_string()),
        });
        
        m.insert("Apache-2.0", LicenseInfo {
            spdx_id: Some("Apache-2.0".to_string()),
            name: "Apache License 2.0".to_string(),
            family: LicenseFamily::Permissive,
            risk: LicenseRisk::Low,
            osi_approved: true,
            copyleft: false,
            requires_attribution: true,
            requires_source_disclosure: false,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/Apache-2.0".to_string()),
        });
        
        m.insert("BSD-2-Clause", LicenseInfo {
            spdx_id: Some("BSD-2-Clause".to_string()),
            name: "BSD 2-Clause License".to_string(),
            family: LicenseFamily::Permissive,
            risk: LicenseRisk::Low,
            osi_approved: true,
            copyleft: false,
            requires_attribution: true,
            requires_source_disclosure: false,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/BSD-2-Clause".to_string()),
        });
        
        m.insert("BSD-3-Clause", LicenseInfo {
            spdx_id: Some("BSD-3-Clause".to_string()),
            name: "BSD 3-Clause License".to_string(),
            family: LicenseFamily::Permissive,
            risk: LicenseRisk::Low,
            osi_approved: true,
            copyleft: false,
            requires_attribution: true,
            requires_source_disclosure: false,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/BSD-3-Clause".to_string()),
        });
        
        m.insert("ISC", LicenseInfo {
            spdx_id: Some("ISC".to_string()),
            name: "ISC License".to_string(),
            family: LicenseFamily::Permissive,
            risk: LicenseRisk::Low,
            osi_approved: true,
            copyleft: false,
            requires_attribution: true,
            requires_source_disclosure: false,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/ISC".to_string()),
        });
        
        // Weak copyleft
        m.insert("LGPL-2.1", LicenseInfo {
            spdx_id: Some("LGPL-2.1".to_string()),
            name: "GNU Lesser General Public License v2.1".to_string(),
            family: LicenseFamily::WeakCopyleft,
            risk: LicenseRisk::Medium,
            osi_approved: true,
            copyleft: true,
            requires_attribution: true,
            requires_source_disclosure: true,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/LGPL-2.1".to_string()),
        });
        
        m.insert("LGPL-3.0", LicenseInfo {
            spdx_id: Some("LGPL-3.0".to_string()),
            name: "GNU Lesser General Public License v3.0".to_string(),
            family: LicenseFamily::WeakCopyleft,
            risk: LicenseRisk::Medium,
            osi_approved: true,
            copyleft: true,
            requires_attribution: true,
            requires_source_disclosure: true,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/LGPL-3.0".to_string()),
        });
        
        m.insert("MPL-2.0", LicenseInfo {
            spdx_id: Some("MPL-2.0".to_string()),
            name: "Mozilla Public License 2.0".to_string(),
            family: LicenseFamily::WeakCopyleft,
            risk: LicenseRisk::Medium,
            osi_approved: true,
            copyleft: true,
            requires_attribution: true,
            requires_source_disclosure: true,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/MPL-2.0".to_string()),
        });
        
        m.insert("EPL-2.0", LicenseInfo {
            spdx_id: Some("EPL-2.0".to_string()),
            name: "Eclipse Public License 2.0".to_string(),
            family: LicenseFamily::WeakCopyleft,
            risk: LicenseRisk::Medium,
            osi_approved: true,
            copyleft: true,
            requires_attribution: true,
            requires_source_disclosure: true,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/EPL-2.0".to_string()),
        });
        
        // Strong copyleft
        m.insert("GPL-2.0", LicenseInfo {
            spdx_id: Some("GPL-2.0".to_string()),
            name: "GNU General Public License v2.0".to_string(),
            family: LicenseFamily::StrongCopyleft,
            risk: LicenseRisk::High,
            osi_approved: true,
            copyleft: true,
            requires_attribution: true,
            requires_source_disclosure: true,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/GPL-2.0".to_string()),
        });
        
        m.insert("GPL-3.0", LicenseInfo {
            spdx_id: Some("GPL-3.0".to_string()),
            name: "GNU General Public License v3.0".to_string(),
            family: LicenseFamily::StrongCopyleft,
            risk: LicenseRisk::High,
            osi_approved: true,
            copyleft: true,
            requires_attribution: true,
            requires_source_disclosure: true,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/GPL-3.0".to_string()),
        });
        
        m.insert("AGPL-3.0", LicenseInfo {
            spdx_id: Some("AGPL-3.0".to_string()),
            name: "GNU Affero General Public License v3.0".to_string(),
            family: LicenseFamily::StrongCopyleft,
            risk: LicenseRisk::Critical,
            osi_approved: true,
            copyleft: true,
            requires_attribution: true,
            requires_source_disclosure: true,
            commercial_use: true,
            url: Some("https://opensource.org/licenses/AGPL-3.0".to_string()),
        });
        
        // Public domain
        m.insert("CC0-1.0", LicenseInfo {
            spdx_id: Some("CC0-1.0".to_string()),
            name: "Creative Commons Zero v1.0 Universal".to_string(),
            family: LicenseFamily::PublicDomain,
            risk: LicenseRisk::Low,
            osi_approved: false,
            copyleft: false,
            requires_attribution: false,
            requires_source_disclosure: false,
            commercial_use: true,
            url: Some("https://creativecommons.org/publicdomain/zero/1.0/".to_string()),
        });
        
        m.insert("Unlicense", LicenseInfo {
            spdx_id: Some("Unlicense".to_string()),
            name: "The Unlicense".to_string(),
            family: LicenseFamily::PublicDomain,
            risk: LicenseRisk::Low,
            osi_approved: true,
            copyleft: false,
            requires_attribution: false,
            requires_source_disclosure: false,
            commercial_use: true,
            url: Some("https://unlicense.org/".to_string()),
        });
        
        m
    };
}

/// Assess license risk from license identifier
pub fn assess_license_risk(license: Option<&str>) -> LicenseRisk {
    match license {
        None => LicenseRisk::Unknown,
        Some(license) => {
            let normalized = normalize_license(license);
            if let Some(info) = KNOWN_LICENSES.get(normalized.as_str()) {
                info.risk
            } else {
                // Try to infer from name
                let lower = license.to_lowercase();
                if lower.contains("agpl") {
                    LicenseRisk::Critical
                } else if lower.contains("gpl") && !lower.contains("lgpl") {
                    LicenseRisk::High
                } else if lower.contains("lgpl") || lower.contains("mpl") || lower.contains("epl") {
                    LicenseRisk::Medium
                } else if lower.contains("mit") || lower.contains("apache") || lower.contains("bsd") {
                    LicenseRisk::Low
                } else {
                    LicenseRisk::Unknown
                }
            }
        }
    }
}

/// Get license information
pub fn get_license_info(license: &str) -> Option<&'static LicenseInfo> {
    let normalized = normalize_license(license);
    KNOWN_LICENSES.get(normalized.as_str())
}

/// Normalize license identifier
fn normalize_license(license: &str) -> String {
    let mut normalized = license.trim().to_string();
    
    // Remove common suffixes/prefixes
    normalized = normalized.replace("-only", "");
    normalized = normalized.replace("-or-later", "");
    normalized = normalized.replace("+", "");
    
    // Common aliases
    normalized = normalized.replace("Apache 2.0", "Apache-2.0");
    normalized = normalized.replace("Apache-2", "Apache-2.0");
    normalized = normalized.replace("BSD", "BSD-3-Clause");
    normalized = normalized.replace("GPLv2", "GPL-2.0");
    normalized = normalized.replace("GPLv3", "GPL-3.0");
    normalized = normalized.replace("LGPLv2.1", "LGPL-2.1");
    normalized = normalized.replace("LGPLv3", "LGPL-3.0");
    
    normalized
}

/// Check license compliance for a set of components
pub fn check_compliance(
    components: &[SbomComponent],
    project_license: Option<&str>,
) -> LicenseComplianceReport {
    let mut report = LicenseComplianceReport {
        overall_risk: LicenseRisk::Low,
        family_summary: HashMap::new(),
        risk_summary: HashMap::new(),
        issues: Vec::new(),
        unknown_licenses: Vec::new(),
        copyleft_licenses: Vec::new(),
    };
    
    let mut highest_risk = LicenseRisk::Low;

    for component in components {
        let license_owned = component.license();
        let license = license_owned.as_deref();
        let risk = assess_license_risk(license);
        
        // Update highest risk
        if risk_level(&risk) > risk_level(&highest_risk) {
            highest_risk = risk;
        }
        
        // Update risk summary
        let risk_key = format!("{:?}", risk);
        *report.risk_summary.entry(risk_key).or_insert(0) += 1;
        
        // Get license info
        if let Some(license_str) = license {
            if let Some(info) = get_license_info(license_str) {
                // Update family summary
                let family_key = format!("{:?}", info.family);
                *report.family_summary.entry(family_key).or_insert(0) += 1;
                
                // Check for copyleft
                if info.copyleft {
                    report.copyleft_licenses.push(format!(
                        "{}: {} ({})", component.name, license_str, component.version
                    ));
                }
                
                // Check for high risk
                if matches!(info.risk, LicenseRisk::High | LicenseRisk::Critical) {
                    report.issues.push(LicenseIssue {
                        component_id: component.id.clone(),
                        component_name: component.name.clone(),
                        license: license_str.to_string(),
                        issue_type: LicenseIssueType::HighRiskLicense,
                        severity: if info.risk == LicenseRisk::Critical {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        description: format!(
                            "{} uses {} which is a {} license",
                            component.name, license_str,
                            if info.copyleft { "copyleft" } else { "restrictive" }
                        ),
                        recommendation: "Review license obligations and ensure compliance. Consider alternative packages with more permissive licenses.".to_string(),
                    });
                }
                
                // Check compatibility with project license
                if let Some(proj_license) = project_license {
                    if !are_licenses_compatible(proj_license, license_str) {
                        report.issues.push(LicenseIssue {
                            component_id: component.id.clone(),
                            component_name: component.name.clone(),
                            license: license_str.to_string(),
                            issue_type: LicenseIssueType::IncompatibleLicense,
                            severity: Severity::High,
                            description: format!(
                                "{} ({}) may be incompatible with project license {}",
                                component.name, license_str, proj_license
                            ),
                            recommendation: "Consult with legal counsel or consider an alternative package".to_string(),
                        });
                    }
                }
            } else {
                // Unknown license
                report.unknown_licenses.push(format!(
                    "{}: {} ({})", component.name, license_str, component.version
                ));
                
                report.issues.push(LicenseIssue {
                    component_id: component.id.clone(),
                    component_name: component.name.clone(),
                    license: license_str.to_string(),
                    issue_type: LicenseIssueType::UnknownLicense,
                    severity: Severity::Medium,
                    description: format!(
                        "{} uses unrecognized license: {}",
                        component.name, license_str
                    ),
                    recommendation: "Manually review the license terms or contact the package maintainer".to_string(),
                });
            }
        } else {
            // No license specified
            report.unknown_licenses.push(format!(
                "{} ({}): No license specified", component.name, component.version
            ));
            
            report.issues.push(LicenseIssue {
                component_id: component.id.clone(),
                component_name: component.name.clone(),
                license: "NONE".to_string(),
                issue_type: LicenseIssueType::UnknownLicense,
                severity: Severity::High,
                description: format!("{} has no license specified", component.name),
                recommendation: "Contact the package maintainer to clarify licensing terms".to_string(),
            });
        }
    }
    
    report.overall_risk = highest_risk;
    report
}

/// Get numeric risk level for comparison
fn risk_level(risk: &LicenseRisk) -> u8 {
    match risk {
        LicenseRisk::Low | LicenseRisk::Permissive | LicenseRisk::PublicDomain => 0,
        LicenseRisk::Medium | LicenseRisk::WeakCopyleft => 1,
        LicenseRisk::High | LicenseRisk::Copyleft => 2,
        LicenseRisk::Critical | LicenseRisk::Proprietary => 3,
        LicenseRisk::Unknown => 4,
    }
}

/// Check if two licenses are compatible
fn are_licenses_compatible(project_license: &str, dep_license: &str) -> bool {
    let proj_info = get_license_info(project_license);
    let dep_info = get_license_info(dep_license);
    
    match (proj_info, dep_info) {
        (Some(proj), Some(dep)) => {
            // Strong copyleft cannot be used in non-copyleft projects
            if matches!(dep.family, LicenseFamily::StrongCopyleft) {
                matches!(proj.family, LicenseFamily::StrongCopyleft)
            } else if matches!(dep.family, LicenseFamily::WeakCopyleft) {
                // Weak copyleft has some restrictions but generally compatible
                !matches!(proj.family, LicenseFamily::Proprietary)
            } else {
                // Permissive and public domain are compatible with everything
                true
            }
        }
        _ => true, // Can't determine, assume compatible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assess_license_risk() {
        assert!(matches!(assess_license_risk(Some("MIT")), LicenseRisk::Low));
        assert!(matches!(assess_license_risk(Some("Apache-2.0")), LicenseRisk::Low));
        assert!(matches!(assess_license_risk(Some("GPL-3.0")), LicenseRisk::High));
        assert!(matches!(assess_license_risk(Some("AGPL-3.0")), LicenseRisk::Critical));
        assert!(matches!(assess_license_risk(None), LicenseRisk::Unknown));
    }

    #[test]
    fn test_get_license_info() {
        let mit = get_license_info("MIT").unwrap();
        assert_eq!(mit.name, "MIT License");
        assert!(!mit.copyleft);
        assert!(mit.osi_approved);
        
        let gpl = get_license_info("GPL-3.0").unwrap();
        assert!(gpl.copyleft);
        assert!(gpl.requires_source_disclosure);
    }

    #[test]
    fn test_normalize_license() {
        assert_eq!(normalize_license("Apache 2.0"), "Apache-2.0");
        assert_eq!(normalize_license("GPLv3"), "GPL-3.0");
        assert_eq!(normalize_license("MIT-only"), "MIT");
    }

    #[test]
    fn test_license_compatibility() {
        assert!(are_licenses_compatible("MIT", "MIT"));
        assert!(are_licenses_compatible("MIT", "Apache-2.0"));
        assert!(!are_licenses_compatible("MIT", "GPL-3.0"));
        assert!(are_licenses_compatible("GPL-3.0", "MIT"));
    }
}
