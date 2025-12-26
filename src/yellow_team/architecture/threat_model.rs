//! STRIDE Threat Modeling

use crate::yellow_team::types::*;
use serde::{Deserialize, Serialize};

/// STRIDE threat category descriptions
pub const STRIDE_DESCRIPTIONS: [(StrideCategory, &str, &str); 6] = [
    (
        StrideCategory::Spoofing,
        "Spoofing Identity",
        "Pretending to be something or someone other than yourself"
    ),
    (
        StrideCategory::Tampering,
        "Tampering with Data",
        "Modifying data or code without authorization"
    ),
    (
        StrideCategory::Repudiation,
        "Repudiation",
        "Claiming to have not performed an action"
    ),
    (
        StrideCategory::InformationDisclosure,
        "Information Disclosure",
        "Exposing information to unauthorized parties"
    ),
    (
        StrideCategory::DenialOfService,
        "Denial of Service",
        "Making a system unavailable or degraded"
    ),
    (
        StrideCategory::ElevationOfPrivilege,
        "Elevation of Privilege",
        "Gaining capabilities beyond what was authorized"
    ),
];

/// Threat template for common scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatTemplate {
    /// Template ID
    pub id: String,
    /// STRIDE category
    pub category: StrideCategory,
    /// Template name
    pub name: String,
    /// Description
    pub description: String,
    /// Applicable component types
    pub applicable_to: Vec<String>,
    /// Default severity
    pub default_severity: Severity,
    /// Common mitigations
    pub mitigations: Vec<String>,
    /// OWASP reference
    pub owasp_reference: Option<String>,
}

/// Get common threat templates
pub fn get_threat_templates() -> Vec<ThreatTemplate> {
    vec![
        // Spoofing threats
        ThreatTemplate {
            id: "SPOOF-001".to_string(),
            category: StrideCategory::Spoofing,
            name: "Credential Theft".to_string(),
            description: "An attacker could steal user credentials through phishing or other means".to_string(),
            applicable_to: vec!["WebApplication".to_string(), "MobileApp".to_string()],
            default_severity: Severity::High,
            mitigations: vec![
                "Implement MFA".to_string(),
                "Use strong password policies".to_string(),
                "Implement account lockout".to_string(),
            ],
            owasp_reference: Some("A07:2021 - Identification and Authentication Failures".to_string()),
        },
        ThreatTemplate {
            id: "SPOOF-002".to_string(),
            category: StrideCategory::Spoofing,
            name: "Session Hijacking".to_string(),
            description: "An attacker could hijack a valid user session".to_string(),
            applicable_to: vec!["WebApplication".to_string(), "ApiGateway".to_string()],
            default_severity: Severity::High,
            mitigations: vec![
                "Use secure session tokens".to_string(),
                "Implement session timeout".to_string(),
                "Bind sessions to client IP/fingerprint".to_string(),
            ],
            owasp_reference: Some("A07:2021 - Identification and Authentication Failures".to_string()),
        },
        // Tampering threats
        ThreatTemplate {
            id: "TAMP-001".to_string(),
            category: StrideCategory::Tampering,
            name: "SQL Injection".to_string(),
            description: "An attacker could modify database queries through malicious input".to_string(),
            applicable_to: vec!["Database".to_string(), "Microservice".to_string()],
            default_severity: Severity::Critical,
            mitigations: vec![
                "Use parameterized queries".to_string(),
                "Implement input validation".to_string(),
                "Apply least privilege to database accounts".to_string(),
            ],
            owasp_reference: Some("A03:2021 - Injection".to_string()),
        },
        ThreatTemplate {
            id: "TAMP-002".to_string(),
            category: StrideCategory::Tampering,
            name: "Man-in-the-Middle".to_string(),
            description: "An attacker could intercept and modify data in transit".to_string(),
            applicable_to: vec!["all".to_string()],
            default_severity: Severity::High,
            mitigations: vec![
                "Use TLS for all communications".to_string(),
                "Implement certificate pinning".to_string(),
                "Use message signing".to_string(),
            ],
            owasp_reference: Some("A02:2021 - Cryptographic Failures".to_string()),
        },
        // Information Disclosure threats
        ThreatTemplate {
            id: "INFO-001".to_string(),
            category: StrideCategory::InformationDisclosure,
            name: "Sensitive Data Exposure".to_string(),
            description: "Sensitive data could be exposed through logs, errors, or APIs".to_string(),
            applicable_to: vec!["all".to_string()],
            default_severity: Severity::High,
            mitigations: vec![
                "Encrypt sensitive data at rest".to_string(),
                "Mask sensitive data in logs".to_string(),
                "Implement proper error handling".to_string(),
            ],
            owasp_reference: Some("A02:2021 - Cryptographic Failures".to_string()),
        },
        // Denial of Service threats
        ThreatTemplate {
            id: "DOS-001".to_string(),
            category: StrideCategory::DenialOfService,
            name: "Resource Exhaustion".to_string(),
            description: "An attacker could exhaust system resources through malicious requests".to_string(),
            applicable_to: vec!["WebApplication".to_string(), "ApiGateway".to_string(), "Microservice".to_string()],
            default_severity: Severity::High,
            mitigations: vec![
                "Implement rate limiting".to_string(),
                "Set resource quotas".to_string(),
                "Use auto-scaling".to_string(),
            ],
            owasp_reference: None,
        },
        // Elevation of Privilege threats
        ThreatTemplate {
            id: "ELEV-001".to_string(),
            category: StrideCategory::ElevationOfPrivilege,
            name: "Privilege Escalation".to_string(),
            description: "An attacker could gain elevated privileges through vulnerability exploitation".to_string(),
            applicable_to: vec!["all".to_string()],
            default_severity: Severity::Critical,
            mitigations: vec![
                "Implement role-based access control".to_string(),
                "Apply principle of least privilege".to_string(),
                "Regularly audit permissions".to_string(),
            ],
            owasp_reference: Some("A01:2021 - Broken Access Control".to_string()),
        },
    ]
}

/// Calculate DREAD score for a threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DreadScore {
    /// Damage potential (0-10)
    pub damage: u8,
    /// Reproducibility (0-10)
    pub reproducibility: u8,
    /// Exploitability (0-10)
    pub exploitability: u8,
    /// Affected users (0-10)
    pub affected_users: u8,
    /// Discoverability (0-10)
    pub discoverability: u8,
}

impl DreadScore {
    /// Calculate overall score
    pub fn overall(&self) -> f64 {
        let sum = self.damage as f64
            + self.reproducibility as f64
            + self.exploitability as f64
            + self.affected_users as f64
            + self.discoverability as f64;
        sum / 5.0
    }

    /// Get severity based on DREAD score
    pub fn to_severity(&self) -> Severity {
        let score = self.overall();
        if score >= 8.0 {
            Severity::Critical
        } else if score >= 6.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score >= 2.0 {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dread_score() {
        let score = DreadScore {
            damage: 8,
            reproducibility: 7,
            exploitability: 6,
            affected_users: 9,
            discoverability: 5,
        };
        
        assert_eq!(score.overall(), 7.0);
        assert!(matches!(score.to_severity(), Severity::High));
    }

    #[test]
    fn test_get_threat_templates() {
        let templates = get_threat_templates();
        assert!(!templates.is_empty());
        assert!(templates.iter().any(|t| matches!(t.category, StrideCategory::Spoofing)));
    }
}
