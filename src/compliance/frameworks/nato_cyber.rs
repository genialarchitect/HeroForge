//! NATO Cyber Defence - NATO Cybersecurity Framework
//!
//! Security standards for NATO member nations' cyber defense.
//! Based on NATO's Cyber Defence Pledge and related directives.

use crate::compliance::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NATO Cyber Defence controls
pub const CONTROL_COUNT: usize = 40;

/// Get all NATO Cyber Defence controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // Strategic Governance
        ComplianceControl {
            id: "NATO-CD-GOV-01".to_string(),
            control_id: "GOV-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Cyber Defence Policy".to_string(),
            description: "Establish and maintain national cyber defence policy aligned with NATO standards".to_string(),
            category: "Governance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 PM-1".to_string()],
            remediation_guidance: Some("Develop cyber defence policy".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-GOV-02".to_string(),
            control_id: "GOV-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Cyber Defence Strategy".to_string(),
            description: "Develop comprehensive cyber defence strategy".to_string(),
            category: "Governance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Create cyber defence strategy".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-GOV-03".to_string(),
            control_id: "GOV-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Roles and Responsibilities".to_string(),
            description: "Define clear roles and responsibilities for cyber defence".to_string(),
            category: "Governance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 PM-2".to_string()],
            remediation_guidance: Some("Document cyber defence responsibilities".to_string()),
        },
        // Threat Intelligence
        ComplianceControl {
            id: "NATO-CD-TI-01".to_string(),
            control_id: "TI-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Threat Intelligence Sharing".to_string(),
            description: "Participate in NATO threat intelligence sharing".to_string(),
            category: "Threat Intelligence".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 PM-16".to_string()],
            remediation_guidance: Some("Establish intel sharing procedures".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-TI-02".to_string(),
            control_id: "TI-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Threat Analysis".to_string(),
            description: "Analyze threats to NATO and national systems".to_string(),
            category: "Threat Intelligence".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 RA-3".to_string()],
            remediation_guidance: Some("Conduct threat analysis".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-TI-03".to_string(),
            control_id: "TI-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Attribution Capability".to_string(),
            description: "Develop capability to attribute cyber attacks".to_string(),
            category: "Threat Intelligence".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Develop attribution capabilities".to_string()),
        },
        // Network Defence
        ComplianceControl {
            id: "NATO-CD-NET-01".to_string(),
            control_id: "NET-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Network Segmentation".to_string(),
            description: "Implement network segmentation to contain breaches".to_string(),
            category: "Network Defence".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-7".to_string()],
            remediation_guidance: Some("Implement network segmentation".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-NET-02".to_string(),
            control_id: "NET-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Perimeter Defence".to_string(),
            description: "Deploy perimeter defence capabilities".to_string(),
            category: "Network Defence".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-7".to_string()],
            remediation_guidance: Some("Deploy perimeter security".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-NET-03".to_string(),
            control_id: "NET-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Intrusion Detection".to_string(),
            description: "Deploy intrusion detection and prevention systems".to_string(),
            category: "Network Defence".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SI-4".to_string()],
            remediation_guidance: Some("Deploy IDS/IPS".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-NET-04".to_string(),
            control_id: "NET-04".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Encrypted Communications".to_string(),
            description: "Use approved encryption for classified communications".to_string(),
            category: "Network Defence".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-8".to_string()],
            remediation_guidance: Some("Implement approved encryption".to_string()),
        },
        // Identity Management
        ComplianceControl {
            id: "NATO-CD-IAM-01".to_string(),
            control_id: "IAM-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Identity Verification".to_string(),
            description: "Verify identity of users and systems".to_string(),
            category: "Identity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IA-2".to_string()],
            remediation_guidance: Some("Implement identity verification".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-IAM-02".to_string(),
            control_id: "IAM-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Multi-Factor Authentication".to_string(),
            description: "Require MFA for access to classified systems".to_string(),
            category: "Identity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IA-2(1)".to_string()],
            remediation_guidance: Some("Enable MFA".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-IAM-03".to_string(),
            control_id: "IAM-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Privileged Access".to_string(),
            description: "Control and monitor privileged access".to_string(),
            category: "Identity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AC-6".to_string()],
            remediation_guidance: Some("Implement PAM".to_string()),
        },
        // Incident Response
        ComplianceControl {
            id: "NATO-CD-IR-01".to_string(),
            control_id: "IR-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Incident Response Capability".to_string(),
            description: "Maintain incident response capability".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IR-4".to_string()],
            remediation_guidance: Some("Establish IR capability".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-IR-02".to_string(),
            control_id: "IR-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "CERT Integration".to_string(),
            description: "Integrate with national and NATO CERT capabilities".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Establish CERT coordination".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-IR-03".to_string(),
            control_id: "IR-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Incident Reporting".to_string(),
            description: "Report significant incidents to NATO".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 IR-6".to_string()],
            remediation_guidance: Some("Establish incident reporting".to_string()),
        },
        // Vulnerability Management
        ComplianceControl {
            id: "NATO-CD-VM-01".to_string(),
            control_id: "VM-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Vulnerability Scanning".to_string(),
            description: "Conduct regular vulnerability scans".to_string(),
            category: "Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 RA-5".to_string()],
            remediation_guidance: Some("Implement vulnerability scanning".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-VM-02".to_string(),
            control_id: "VM-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Patch Management".to_string(),
            description: "Implement timely patch management".to_string(),
            category: "Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SI-2".to_string()],
            remediation_guidance: Some("Establish patch management".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-VM-03".to_string(),
            control_id: "VM-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Secure Configuration".to_string(),
            description: "Maintain secure system configurations".to_string(),
            category: "Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CM-6".to_string()],
            remediation_guidance: Some("Apply security baselines".to_string()),
        },
        // Cyber Resilience
        ComplianceControl {
            id: "NATO-CD-RES-01".to_string(),
            control_id: "RES-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Resilience Planning".to_string(),
            description: "Plan for cyber resilience and recovery".to_string(),
            category: "Resilience".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CP-2".to_string()],
            remediation_guidance: Some("Develop resilience plans".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-RES-02".to_string(),
            control_id: "RES-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Backup and Recovery".to_string(),
            description: "Maintain backup and recovery capabilities".to_string(),
            category: "Resilience".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CP-9".to_string()],
            remediation_guidance: Some("Implement backup procedures".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-RES-03".to_string(),
            control_id: "RES-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Redundancy".to_string(),
            description: "Implement redundancy for critical systems".to_string(),
            category: "Resilience".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CP-6".to_string()],
            remediation_guidance: Some("Implement system redundancy".to_string()),
        },
        // Training and Exercises
        ComplianceControl {
            id: "NATO-CD-TRN-01".to_string(),
            control_id: "TRN-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Cyber Defence Training".to_string(),
            description: "Provide cyber defence training to personnel".to_string(),
            category: "Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AT-3".to_string()],
            remediation_guidance: Some("Implement training program".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-TRN-02".to_string(),
            control_id: "TRN-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Cyber Exercises".to_string(),
            description: "Participate in NATO cyber exercises".to_string(),
            category: "Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CP-4".to_string()],
            remediation_guidance: Some("Participate in exercises".to_string()),
        },
        // Security Monitoring
        ComplianceControl {
            id: "NATO-CD-MON-01".to_string(),
            control_id: "MON-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Continuous Monitoring".to_string(),
            description: "Implement continuous security monitoring".to_string(),
            category: "Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 CA-7".to_string()],
            remediation_guidance: Some("Deploy continuous monitoring".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-MON-02".to_string(),
            control_id: "MON-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Security Logging".to_string(),
            description: "Maintain comprehensive security logs".to_string(),
            category: "Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AU-2".to_string()],
            remediation_guidance: Some("Enable security logging".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-MON-03".to_string(),
            control_id: "MON-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "SIEM Integration".to_string(),
            description: "Integrate security event management".to_string(),
            category: "Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AU-6".to_string()],
            remediation_guidance: Some("Deploy SIEM solution".to_string()),
        },
        // Supply Chain Security
        ComplianceControl {
            id: "NATO-CD-SC-01".to_string(),
            control_id: "SC-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Supply Chain Risk Management".to_string(),
            description: "Manage risks from supply chain".to_string(),
            category: "Supply Chain".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SR-1".to_string()],
            remediation_guidance: Some("Implement supply chain risk management".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-SC-02".to_string(),
            control_id: "SC-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Vendor Assessment".to_string(),
            description: "Assess security of vendors and suppliers".to_string(),
            category: "Supply Chain".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SR-5".to_string()],
            remediation_guidance: Some("Conduct vendor assessments".to_string()),
        },
        // Cryptography
        ComplianceControl {
            id: "NATO-CD-CRY-01".to_string(),
            control_id: "CRY-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Approved Cryptography".to_string(),
            description: "Use NATO-approved cryptographic solutions".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-13".to_string()],
            remediation_guidance: Some("Use approved cryptography".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-CRY-02".to_string(),
            control_id: "CRY-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Key Management".to_string(),
            description: "Manage cryptographic keys securely".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-12".to_string()],
            remediation_guidance: Some("Implement key management".to_string()),
        },
        // Information Assurance
        ComplianceControl {
            id: "NATO-CD-IA-01".to_string(),
            control_id: "IA-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Information Classification".to_string(),
            description: "Classify information according to NATO security classifications".to_string(),
            category: "Information Assurance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 RA-2".to_string()],
            remediation_guidance: Some("Implement information classification scheme".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-IA-02".to_string(),
            control_id: "IA-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Data Handling".to_string(),
            description: "Handle classified data according to NATO standards".to_string(),
            category: "Information Assurance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 MP-2".to_string()],
            remediation_guidance: Some("Implement data handling procedures".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-IA-03".to_string(),
            control_id: "IA-03".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Data Loss Prevention".to_string(),
            description: "Prevent unauthorized data exfiltration".to_string(),
            category: "Information Assurance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SC-7(10)".to_string()],
            remediation_guidance: Some("Deploy DLP controls".to_string()),
        },
        // Personnel Security
        ComplianceControl {
            id: "NATO-CD-PS-01".to_string(),
            control_id: "PS-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Security Clearances".to_string(),
            description: "Ensure personnel have appropriate security clearances".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 PS-3".to_string()],
            remediation_guidance: Some("Verify security clearances".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-PS-02".to_string(),
            control_id: "PS-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Security Awareness".to_string(),
            description: "Provide security awareness training to all personnel".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 AT-2".to_string()],
            remediation_guidance: Some("Implement security awareness program".to_string()),
        },
        // Physical Security
        ComplianceControl {
            id: "NATO-CD-PHY-01".to_string(),
            control_id: "PHY-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Physical Access Control".to_string(),
            description: "Control physical access to cyber defence facilities".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 PE-3".to_string()],
            remediation_guidance: Some("Implement physical access controls".to_string()),
        },
        ComplianceControl {
            id: "NATO-CD-PHY-02".to_string(),
            control_id: "PHY-02".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Environmental Protection".to_string(),
            description: "Protect systems from environmental threats".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 PE-13".to_string()],
            remediation_guidance: Some("Implement environmental protections".to_string()),
        },
        // Cyber Operations
        ComplianceControl {
            id: "NATO-CD-OPS-01".to_string(),
            control_id: "OPS-01".to_string(),
            framework: ComplianceFramework::NatoCyber,
            title: "Cyber Situational Awareness".to_string(),
            description: "Maintain situational awareness of cyber threats".to_string(),
            category: "Cyber Operations".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST 800-53 SI-5".to_string()],
            remediation_guidance: Some("Establish cyber situational awareness".to_string()),
        },
    ]
}

/// Map vulnerability to NATO Cyber Defence controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Network vulnerabilities
    if title_lower.contains("firewall") || title_lower.contains("boundary") {
        mappings.push(("NET-02".to_string(), Severity::High));
    }

    // Intrusion detection
    if title_lower.contains("intrusion") || title_lower.contains("attack") {
        mappings.push(("NET-03".to_string(), Severity::High));
    }

    // Encryption
    if title_lower.contains("ssl") || title_lower.contains("tls") || title_lower.contains("cipher") {
        mappings.push(("NET-04".to_string(), Severity::High));
        mappings.push(("CRY-01".to_string(), Severity::High));
    }

    // Authentication
    if title_lower.contains("authentication") || title_lower.contains("password") {
        mappings.push(("IAM-01".to_string(), Severity::High));
        mappings.push(("IAM-02".to_string(), Severity::High));
    }

    // Vulnerability management
    if title_lower.contains("cve") || title_lower.contains("vulnerability") {
        mappings.push(("VM-01".to_string(), Severity::High));
        mappings.push(("VM-02".to_string(), Severity::High));
    }

    // Configuration
    if title_lower.contains("misconfiguration") || title_lower.contains("hardening") {
        mappings.push(("VM-03".to_string(), Severity::Medium));
    }

    // Logging
    if title_lower.contains("audit") || title_lower.contains("log") {
        mappings.push(("MON-02".to_string(), Severity::Medium));
    }

    // Privileged access
    if title_lower.contains("privilege") || title_lower.contains("admin") {
        mappings.push(("IAM-03".to_string(), Severity::High));
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
    fn test_controls_have_required_fields() {
        let controls = get_controls();
        for control in &controls {
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
            assert_eq!(control.framework, ComplianceFramework::NatoCyber);
        }
    }

    #[test]
    fn test_map_vulnerability() {
        let mappings = map_vulnerability("Weak TLS cipher", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());

        let mappings = map_vulnerability("Authentication bypass", None, None, None);
        assert!(!mappings.is_empty());

        let mappings = map_vulnerability("Unrelated issue", None, None, None);
        assert!(mappings.is_empty());
    }
}
