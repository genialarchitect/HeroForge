//! Executive Order 14028 - Improving the Nation's Cybersecurity
//!
//! This module implements controls based on Executive Order 14028 (May 12, 2021)
//! which establishes requirements for improving the nation's cybersecurity.
//!
//! Key areas covered:
//! - Removing barriers to sharing threat information
//! - Modernizing federal government cybersecurity
//! - Enhancing software supply chain security
//! - Establishing cyber safety review board
//! - Standardizing federal government response to incidents
//! - Improving detection of vulnerabilities and incidents
//! - Improving investigative and remediation capabilities

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of EO 14028 controls
pub const CONTROL_COUNT: usize = 30;

/// Get all EO 14028 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Section 2: Removing Barriers to Sharing Threat Information
    // ========================================================================

    controls.push(ComplianceControl {
        id: "EO14028-2.1".to_string(),
        control_id: "EO-2.a".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Threat Information Sharing".to_string(),
        description: "IT service providers must promptly report cyber incidents and threat information to the government".to_string(),
        category: "Information Sharing".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-6".to_string(), "CISA-CPG-4.A".to_string()],
        remediation_guidance: Some("Establish contracts requiring cyber incident reporting within specified timeframes".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-2.2".to_string(),
        control_id: "EO-2.b".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Removal of Contractual Barriers".to_string(),
        description: "Remove contractual barriers to sharing threat and incident information with government".to_string(),
        category: "Information Sharing".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Review and update contracts to enable threat information sharing".to_string()),
    });

    // ========================================================================
    // Section 3: Modernizing Federal Government Cybersecurity
    // ========================================================================

    controls.push(ComplianceControl {
        id: "EO14028-3.1".to_string(),
        control_id: "EO-3.a".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Zero Trust Architecture".to_string(),
        description: "Develop a plan to implement Zero Trust Architecture".to_string(),
        category: "Modernization".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-ZTA".to_string(), "DoD-ZT".to_string()],
        remediation_guidance: Some("Develop and implement Zero Trust Architecture roadmap".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-3.2".to_string(),
        control_id: "EO-3.b".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Cloud Service Adoption".to_string(),
        description: "Accelerate movement to secure cloud services, including Software as a Service (SaaS), Infrastructure as a Service (IaaS), and Platform as a Service (PaaS)".to_string(),
        category: "Modernization".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["FedRAMP".to_string()],
        remediation_guidance: Some("Develop cloud migration strategy prioritizing FedRAMP-authorized services".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-3.3".to_string(),
        control_id: "EO-3.c".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Multi-Factor Authentication".to_string(),
        description: "Deploy multi-factor authentication and encryption for data at rest and in transit".to_string(),
        category: "Modernization".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2".to_string(), "NIST-SC-8".to_string()],
        remediation_guidance: Some("Implement phishing-resistant MFA and encrypt all sensitive data".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-3.4".to_string(),
        control_id: "EO-3.d".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Encryption of Data at Rest".to_string(),
        description: "Encrypt data at rest in systems and databases".to_string(),
        category: "Modernization".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-28".to_string()],
        remediation_guidance: Some("Enable encryption for all data at rest using approved algorithms".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-3.5".to_string(),
        control_id: "EO-3.e".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Encryption of Data in Transit".to_string(),
        description: "Encrypt data in transit using TLS 1.2 or higher".to_string(),
        category: "Modernization".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-8".to_string()],
        remediation_guidance: Some("Enforce TLS 1.2+ for all network communications".to_string()),
    });

    // ========================================================================
    // Section 4: Enhancing Software Supply Chain Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "EO14028-4.1".to_string(),
        control_id: "EO-4.a".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Secure Software Development".to_string(),
        description: "Develop software using secure development practices in accordance with NIST guidelines".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SSDF".to_string(), "NIST-SA-15".to_string()],
        remediation_guidance: Some("Implement NIST Secure Software Development Framework (SSDF) practices".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-4.2".to_string(),
        control_id: "EO-4.b".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Software Bill of Materials (SBOM)".to_string(),
        description: "Provide a Software Bill of Materials (SBOM) for each software product".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NTIA-SBOM".to_string()],
        remediation_guidance: Some("Generate and maintain SBOMs for all software products using standard formats".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-4.3".to_string(),
        control_id: "EO-4.c".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Vulnerability Disclosure Program".to_string(),
        description: "Maintain a vulnerability disclosure program for software products".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO-29147".to_string()],
        remediation_guidance: Some("Establish public vulnerability disclosure policy and process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-4.4".to_string(),
        control_id: "EO-4.d".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Automated Security Testing".to_string(),
        description: "Employ automated tools for vulnerability analysis and code scanning".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SA-11".to_string()],
        remediation_guidance: Some("Integrate SAST, DAST, and SCA tools into CI/CD pipelines".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-4.5".to_string(),
        control_id: "EO-4.e".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Software Integrity Verification".to_string(),
        description: "Provide mechanisms to verify software integrity and provenance".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-7".to_string()],
        remediation_guidance: Some("Implement code signing and artifact verification processes".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-4.6".to_string(),
        control_id: "EO-4.f".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Third-Party Component Management".to_string(),
        description: "Maintain provenance of software code and components".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SR-4".to_string()],
        remediation_guidance: Some("Track all third-party dependencies and their sources".to_string()),
    });

    // ========================================================================
    // Section 6: Standardizing Response to Incidents
    // ========================================================================

    controls.push(ComplianceControl {
        id: "EO14028-6.1".to_string(),
        control_id: "EO-6.a".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Incident Response Playbooks".to_string(),
        description: "Develop standardized playbooks for incident response".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-8".to_string()],
        remediation_guidance: Some("Create incident response playbooks aligned with CISA guidance".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-6.2".to_string(),
        control_id: "EO-6.b".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Incident Classification".to_string(),
        description: "Implement standardized incident classification system".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IR-4".to_string()],
        remediation_guidance: Some("Adopt standardized incident classification taxonomy".to_string()),
    });

    // ========================================================================
    // Section 7: Improving Detection of Vulnerabilities and Incidents
    // ========================================================================

    controls.push(ComplianceControl {
        id: "EO14028-7.1".to_string(),
        control_id: "EO-7.a".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Endpoint Detection and Response".to_string(),
        description: "Deploy Endpoint Detection and Response (EDR) capabilities".to_string(),
        category: "Detection".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-4".to_string()],
        remediation_guidance: Some("Deploy government-approved EDR solutions across all endpoints".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-7.2".to_string(),
        control_id: "EO-7.b".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Centralized Log Collection".to_string(),
        description: "Implement centralized log collection and analysis".to_string(),
        category: "Detection".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-6".to_string()],
        remediation_guidance: Some("Centralize security logs in SIEM with correlation and alerting".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-7.3".to_string(),
        control_id: "EO-7.c".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Log Retention Requirements".to_string(),
        description: "Maintain logs for required retention periods".to_string(),
        category: "Detection".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-11".to_string()],
        remediation_guidance: Some("Configure log retention for minimum 12 months (30 months for aggregated logs)".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-7.4".to_string(),
        control_id: "EO-7.d".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Network Traffic Monitoring".to_string(),
        description: "Implement network traffic analysis and anomaly detection".to_string(),
        category: "Detection".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-4(4)".to_string()],
        remediation_guidance: Some("Deploy network monitoring with behavioral analytics".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-7.5".to_string(),
        control_id: "EO-7.e".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Threat Hunting".to_string(),
        description: "Implement proactive threat hunting capabilities".to_string(),
        category: "Detection".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["CISA-Hunt".to_string()],
        remediation_guidance: Some("Establish threat hunting program with regular hunting activities".to_string()),
    });

    // ========================================================================
    // Section 8: Investigative and Remediation Capabilities
    // ========================================================================

    controls.push(ComplianceControl {
        id: "EO14028-8.1".to_string(),
        control_id: "EO-8.a".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Forensic Collection Capability".to_string(),
        description: "Maintain capability to collect and preserve forensic evidence".to_string(),
        category: "Investigation".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AU-9".to_string()],
        remediation_guidance: Some("Establish forensic collection and preservation capabilities".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-8.2".to_string(),
        control_id: "EO-8.b".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Event Log Analysis".to_string(),
        description: "Capability to analyze event logs to support investigations".to_string(),
        category: "Investigation".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-6".to_string()],
        remediation_guidance: Some("Implement log analysis tools and trained personnel".to_string()),
    });

    // ========================================================================
    // Additional Technical Requirements
    // ========================================================================

    controls.push(ComplianceControl {
        id: "EO14028-T.1".to_string(),
        control_id: "EO-T.1".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "DNS Security Extensions (DNSSEC)".to_string(),
        description: "Implement DNSSEC for all DNS zones".to_string(),
        category: "Technical Controls".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-20".to_string()],
        remediation_guidance: Some("Enable DNSSEC signing for all authoritative DNS zones".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-T.2".to_string(),
        control_id: "EO-T.2".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Email Authentication (DMARC)".to_string(),
        description: "Implement DMARC, DKIM, and SPF for email authentication".to_string(),
        category: "Technical Controls".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["BOD-18-01".to_string()],
        remediation_guidance: Some("Configure DMARC with reject policy and enable DKIM signing".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-T.3".to_string(),
        control_id: "EO-T.3".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "HTTPS Enforcement".to_string(),
        description: "Enforce HTTPS for all web services with HSTS".to_string(),
        category: "Technical Controls".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["BOD-18-01".to_string()],
        remediation_guidance: Some("Enable HTTPS with HSTS preloading for all public web services".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-T.4".to_string(),
        control_id: "EO-T.4".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Known Exploited Vulnerabilities".to_string(),
        description: "Remediate CISA Known Exploited Vulnerabilities within required timeframes".to_string(),
        category: "Technical Controls".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["BOD-22-01".to_string()],
        remediation_guidance: Some("Monitor CISA KEV catalog and remediate vulnerabilities per BOD 22-01".to_string()),
    });

    controls.push(ComplianceControl {
        id: "EO14028-T.5".to_string(),
        control_id: "EO-T.5".to_string(),
        framework: ComplianceFramework::Eo14028,
        title: "Privileged Access Management".to_string(),
        description: "Implement privileged access management with just-in-time access".to_string(),
        category: "Technical Controls".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string()],
        remediation_guidance: Some("Deploy PAM solution with session recording and JIT access".to_string()),
    });

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant EO 14028 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Zero Trust / Architecture
    if title_lower.contains("zero trust") || title_lower.contains("architecture") {
        mappings.push(("EO-3.a".to_string(), Severity::High));
    }

    // Authentication / MFA
    if title_lower.contains("authentication") || title_lower.contains("mfa") || title_lower.contains("multi-factor") {
        mappings.push(("EO-3.c".to_string(), Severity::Critical));
    }

    // Encryption
    if title_lower.contains("encryption") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("plaintext") || title_lower.contains("unencrypted") {
        mappings.push(("EO-3.d".to_string(), Severity::Critical));
        mappings.push(("EO-3.e".to_string(), Severity::Critical));
    }

    // Software supply chain / SBOM
    if title_lower.contains("supply chain") || title_lower.contains("sbom") || title_lower.contains("dependency") {
        mappings.push(("EO-4.a".to_string(), Severity::High));
        mappings.push(("EO-4.b".to_string(), Severity::High));
    }

    // Code security / SAST / DAST
    if title_lower.contains("code") || title_lower.contains("injection") || title_lower.contains("xss") {
        mappings.push(("EO-4.d".to_string(), Severity::High));
    }

    // Software integrity
    if title_lower.contains("integrity") || title_lower.contains("signing") || title_lower.contains("tampering") {
        mappings.push(("EO-4.e".to_string(), Severity::High));
    }

    // EDR / Endpoint
    if title_lower.contains("endpoint") || title_lower.contains("edr") || title_lower.contains("malware") {
        mappings.push(("EO-7.a".to_string(), Severity::High));
    }

    // Logging / SIEM
    if title_lower.contains("log") || title_lower.contains("siem") || title_lower.contains("audit") {
        mappings.push(("EO-7.b".to_string(), Severity::High));
        mappings.push(("EO-7.c".to_string(), Severity::Medium));
    }

    // DNS Security
    if title_lower.contains("dns") || title_lower.contains("dnssec") {
        mappings.push(("EO-T.1".to_string(), Severity::High));
    }

    // Email security
    if title_lower.contains("email") || title_lower.contains("dmarc") || title_lower.contains("spf") || title_lower.contains("dkim") {
        mappings.push(("EO-T.2".to_string(), Severity::High));
    }

    // HTTPS / Web security
    if title_lower.contains("https") || title_lower.contains("hsts") || title_lower.contains("certificate") {
        mappings.push(("EO-T.3".to_string(), Severity::High));
    }

    // Known vulnerabilities / KEV
    if title_lower.contains("cve") || title_lower.contains("kev") || title_lower.contains("exploit") {
        mappings.push(("EO-T.4".to_string(), Severity::Critical));
    }

    // Privileged access
    if title_lower.contains("privilege") || title_lower.contains("admin") || title_lower.contains("root") {
        mappings.push(("EO-T.5".to_string(), Severity::High));
    }

    // Default mapping
    if mappings.is_empty() {
        mappings.push(("EO-3.c".to_string(), Severity::Medium));
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_count() {
        let controls = get_controls();
        assert_eq!(controls.len(), CONTROL_COUNT);
    }

    #[test]
    fn test_all_controls_have_required_fields() {
        for control in get_controls() {
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
            assert_eq!(control.framework, ComplianceFramework::Eo14028);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Missing MFA authentication", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "EO-3.c"));

        let sbom_mappings = map_vulnerability("Software supply chain vulnerability", None, None, None);
        assert!(sbom_mappings.iter().any(|(id, _)| id == "EO-4.b"));
    }
}
