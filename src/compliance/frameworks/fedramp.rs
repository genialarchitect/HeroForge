//! FedRAMP (Federal Risk and Authorization Management Program)
//!
//! US federal government cloud security authorization program based on
//! NIST 800-53 controls with cloud-specific enhancements.

use crate::compliance::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of FedRAMP controls (High baseline)
pub const CONTROL_COUNT: usize = 325;

/// Get all FedRAMP controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // Access Control (AC)
        ComplianceControl {
            id: "FEDRAMP-AC-1".to_string(),
            control_id: "AC-1".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Access Control Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate access control policy and procedures".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AC-1".to_string()],
            remediation_guidance: Some("Establish and maintain access control policies".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-AC-2".to_string(),
            control_id: "AC-2".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Account Management".to_string(),
            description: "Manage information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AC-2".to_string()],
            remediation_guidance: Some("Implement automated account management".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-AC-3".to_string(),
            control_id: "AC-3".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Access Enforcement".to_string(),
            description: "Enforce approved authorizations for logical access".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AC-3".to_string()],
            remediation_guidance: Some("Implement role-based access control".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-AC-6".to_string(),
            control_id: "AC-6".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Least Privilege".to_string(),
            description: "Employ the principle of least privilege".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AC-6".to_string()],
            remediation_guidance: Some("Review and minimize user privileges".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-AC-17".to_string(),
            control_id: "AC-17".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Remote Access".to_string(),
            description: "Establish and document usage restrictions and guidance for remote access".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AC-17".to_string()],
            remediation_guidance: Some("Secure and monitor remote access".to_string()),
        },
        // Audit and Accountability (AU)
        ComplianceControl {
            id: "FEDRAMP-AU-2".to_string(),
            control_id: "AU-2".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Audit Events".to_string(),
            description: "Determine events requiring audit logging".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AU-2".to_string()],
            remediation_guidance: Some("Enable comprehensive audit logging".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-AU-6".to_string(),
            control_id: "AU-6".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Audit Review, Analysis, and Reporting".to_string(),
            description: "Review and analyze audit records for indications of inappropriate activity".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AU-6".to_string()],
            remediation_guidance: Some("Implement automated log analysis".to_string()),
        },
        // Configuration Management (CM)
        ComplianceControl {
            id: "FEDRAMP-CM-2".to_string(),
            control_id: "CM-2".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Baseline Configuration".to_string(),
            description: "Develop, document, and maintain baseline configuration".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CM-2".to_string()],
            remediation_guidance: Some("Establish and enforce baseline configurations".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-CM-6".to_string(),
            control_id: "CM-6".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Configuration Settings".to_string(),
            description: "Establish and document mandatory configuration settings".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CM-6".to_string()],
            remediation_guidance: Some("Apply security configuration benchmarks".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-CM-8".to_string(),
            control_id: "CM-8".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Information System Component Inventory".to_string(),
            description: "Develop and document an inventory of system components".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CM-8".to_string()],
            remediation_guidance: Some("Maintain accurate asset inventory".to_string()),
        },
        // Identification and Authentication (IA)
        ComplianceControl {
            id: "FEDRAMP-IA-2".to_string(),
            control_id: "IA-2".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Identification and Authentication (Organizational Users)".to_string(),
            description: "Uniquely identify and authenticate organizational users".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IA-2".to_string()],
            remediation_guidance: Some("Implement multi-factor authentication".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-IA-5".to_string(),
            control_id: "IA-5".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Authenticator Management".to_string(),
            description: "Manage information system authenticators".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IA-5".to_string()],
            remediation_guidance: Some("Enforce strong password policies".to_string()),
        },
        // System and Communications Protection (SC)
        ComplianceControl {
            id: "FEDRAMP-SC-7".to_string(),
            control_id: "SC-7".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Boundary Protection".to_string(),
            description: "Monitor and control communications at external boundary and key internal boundaries".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-7".to_string()],
            remediation_guidance: Some("Implement boundary protection controls".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-SC-8".to_string(),
            control_id: "SC-8".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Transmission Confidentiality and Integrity".to_string(),
            description: "Protect the confidentiality and integrity of transmitted information".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-8".to_string()],
            remediation_guidance: Some("Encrypt data in transit using TLS 1.2+".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-SC-12".to_string(),
            control_id: "SC-12".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Cryptographic Key Establishment and Management".to_string(),
            description: "Establish and manage cryptographic keys".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-12".to_string()],
            remediation_guidance: Some("Implement key management procedures".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-SC-13".to_string(),
            control_id: "SC-13".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Cryptographic Protection".to_string(),
            description: "Implement FIPS-validated cryptography".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-13".to_string()],
            remediation_guidance: Some("Use FIPS 140-2/3 validated cryptographic modules".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-SC-28".to_string(),
            control_id: "SC-28".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Protection of Information at Rest".to_string(),
            description: "Protect the confidentiality and integrity of information at rest".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-28".to_string()],
            remediation_guidance: Some("Encrypt data at rest".to_string()),
        },
        // System and Information Integrity (SI)
        ComplianceControl {
            id: "FEDRAMP-SI-2".to_string(),
            control_id: "SI-2".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Flaw Remediation".to_string(),
            description: "Identify, report, and correct information system flaws".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SI-2".to_string()],
            remediation_guidance: Some("Implement vulnerability management program".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-SI-3".to_string(),
            control_id: "SI-3".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Malicious Code Protection".to_string(),
            description: "Implement malicious code protection mechanisms".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SI-3".to_string()],
            remediation_guidance: Some("Deploy anti-malware solutions".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-SI-4".to_string(),
            control_id: "SI-4".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Information System Monitoring".to_string(),
            description: "Monitor the information system to detect attacks and unauthorized activities".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SI-4".to_string()],
            remediation_guidance: Some("Implement continuous monitoring".to_string()),
        },
        // Contingency Planning (CP)
        ComplianceControl {
            id: "FEDRAMP-CP-9".to_string(),
            control_id: "CP-9".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Information System Backup".to_string(),
            description: "Conduct backups of user-level and system-level information".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CP-9".to_string()],
            remediation_guidance: Some("Implement backup and recovery procedures".to_string()),
        },
        // Incident Response (IR)
        ComplianceControl {
            id: "FEDRAMP-IR-4".to_string(),
            control_id: "IR-4".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Incident Handling".to_string(),
            description: "Implement an incident handling capability".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IR-4".to_string()],
            remediation_guidance: Some("Establish incident response procedures".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-IR-6".to_string(),
            control_id: "IR-6".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Incident Reporting".to_string(),
            description: "Report incidents to appropriate authorities".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IR-6".to_string()],
            remediation_guidance: Some("Establish incident reporting procedures".to_string()),
        },
        // Risk Assessment (RA)
        ComplianceControl {
            id: "FEDRAMP-RA-5".to_string(),
            control_id: "RA-5".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Vulnerability Scanning".to_string(),
            description: "Scan for vulnerabilities in the information system".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 RA-5".to_string()],
            remediation_guidance: Some("Conduct regular vulnerability scans".to_string()),
        },
        // Security Assessment and Authorization (CA)
        ComplianceControl {
            id: "FEDRAMP-CA-2".to_string(),
            control_id: "CA-2".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Security Assessments".to_string(),
            description: "Develop a security assessment plan".to_string(),
            category: "Security Assessment and Authorization".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CA-2".to_string()],
            remediation_guidance: Some("Conduct annual security assessments".to_string()),
        },
        ComplianceControl {
            id: "FEDRAMP-CA-7".to_string(),
            control_id: "CA-7".to_string(),
            framework: ComplianceFramework::FedRamp,
            title: "Continuous Monitoring".to_string(),
            description: "Develop a continuous monitoring strategy".to_string(),
            category: "Security Assessment and Authorization".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CA-7".to_string()],
            remediation_guidance: Some("Implement continuous monitoring program".to_string()),
        },
    ]
}

/// Map vulnerability to FedRAMP controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control vulnerabilities
    if title_lower.contains("unauthorized") || title_lower.contains("privilege") {
        mappings.push(("AC-3".to_string(), Severity::High));
        mappings.push(("AC-6".to_string(), Severity::High));
    }

    // Authentication issues
    if title_lower.contains("default") && title_lower.contains("password")
        || title_lower.contains("weak auth")
    {
        mappings.push(("IA-2".to_string(), Severity::Critical));
        mappings.push(("IA-5".to_string(), Severity::High));
    }

    // Encryption/TLS issues
    if title_lower.contains("ssl") || title_lower.contains("tls") || title_lower.contains("cipher") {
        mappings.push(("SC-8".to_string(), Severity::High));
        mappings.push(("SC-13".to_string(), Severity::High));
    }

    // Vulnerability scanning related
    if title_lower.contains("cve") || title_lower.contains("vulnerability") {
        mappings.push(("RA-5".to_string(), Severity::High));
        mappings.push(("SI-2".to_string(), Severity::High));
    }

    // Malware/integrity
    if title_lower.contains("malware") || title_lower.contains("trojan") {
        mappings.push(("SI-3".to_string(), Severity::Critical));
    }

    // Monitoring
    if title_lower.contains("logging") || title_lower.contains("audit") {
        mappings.push(("AU-2".to_string(), Severity::Medium));
        mappings.push(("AU-6".to_string(), Severity::Medium));
    }

    // Remote access
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote") {
        mappings.push(("AC-17".to_string(), Severity::Medium));
    }

    // Network boundary
    if title_lower.contains("firewall") || title_lower.contains("boundary") {
        mappings.push(("SC-7".to_string(), Severity::High));
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_controls() {
        let controls = get_controls();
        assert!(!controls.is_empty());
        assert!(controls.iter().all(|c| c.framework == ComplianceFramework::FedRamp));
    }

    #[test]
    fn test_map_vulnerability() {
        let mappings = map_vulnerability("Weak TLS cipher", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());
    }
}
