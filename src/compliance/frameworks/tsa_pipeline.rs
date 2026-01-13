//! TSA Pipeline Security Directives Compliance Controls
//!
//! This module implements controls based on TSA Security Directives for pipeline
//! cybersecurity. The directives require pipeline owners and operators to:
//!
//! - Designate a Cybersecurity Coordinator
//! - Report cybersecurity incidents to CISA
//! - Conduct vulnerability assessments
//! - Implement specific cybersecurity measures
//!
//! Key Directives covered:
//! - SD-01: Initial incident reporting and coordinator designation
//! - SD-02: Implementation of specific cybersecurity measures
//! - SD-02A-02D: Enhanced requirements for critical pipelines

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of TSA Pipeline Security controls
pub const CONTROL_COUNT: usize = 35;

/// Get all TSA Pipeline Security controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Governance and Coordination (SD-01)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-GOV-001".to_string(),
        control_id: "SD-01.1".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Cybersecurity Coordinator Designation".to_string(),
        description: "Designate a Cybersecurity Coordinator available 24/7 to coordinate cybersecurity practices and address incidents".to_string(),
        category: "Governance".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PM-2".to_string(), "CISA-CPG-1.A".to_string()],
        remediation_guidance: Some("Appoint a qualified Cybersecurity Coordinator with 24/7 availability and document contact information".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-GOV-002".to_string(),
        control_id: "SD-01.2".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Cybersecurity Incident Reporting".to_string(),
        description: "Report cybersecurity incidents to CISA within 12 hours of identification".to_string(),
        category: "Governance".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-6".to_string(), "CISA-CPG-4.A".to_string()],
        remediation_guidance: Some("Establish incident reporting procedures with 12-hour SLA to CISA".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-GOV-003".to_string(),
        control_id: "SD-01.3".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Cybersecurity Assessment".to_string(),
        description: "Conduct a cybersecurity vulnerability assessment and submit results to TSA and CISA".to_string(),
        category: "Governance".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-RA-5".to_string(), "CISA-CPG-2.A".to_string()],
        remediation_guidance: Some("Perform comprehensive vulnerability assessment and document findings".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-GOV-004".to_string(),
        control_id: "SD-02.1".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Cybersecurity Implementation Plan".to_string(),
        description: "Develop and implement a TSA-approved Cybersecurity Implementation Plan".to_string(),
        category: "Governance".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PM-1".to_string()],
        remediation_guidance: Some("Create comprehensive Cybersecurity Implementation Plan for TSA approval".to_string()),
    });

    // ========================================================================
    // Network Segmentation and Architecture
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-NET-001".to_string(),
        control_id: "SD-02.2".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "IT/OT Network Segmentation".to_string(),
        description: "Implement network segmentation policies and controls to ensure operational technology (OT) systems can continue to safely operate in the event IT systems are compromised".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string(), "IEC62443-3.2".to_string()],
        remediation_guidance: Some("Implement network segmentation between IT and OT environments with appropriate DMZs".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-NET-002".to_string(),
        control_id: "SD-02.3".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "OT Network Isolation".to_string(),
        description: "Ensure OT system networks are isolated from IT networks with appropriate security controls at interconnection points".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7(5)".to_string(), "IEC62443-3.3".to_string()],
        remediation_guidance: Some("Implement dedicated firewalls and security controls at IT/OT boundaries".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-NET-003".to_string(),
        control_id: "SD-02.4".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Remote Access Security".to_string(),
        description: "Implement secure remote access solutions with multi-factor authentication for all remote connections to OT networks".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-17".to_string(), "NIST-IA-2".to_string()],
        remediation_guidance: Some("Deploy VPN with MFA for all remote OT access; implement jump servers".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-NET-004".to_string(),
        control_id: "SD-02.5".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Network Traffic Monitoring".to_string(),
        description: "Implement continuous monitoring of network traffic between IT and OT systems for anomalous activity".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-4".to_string()],
        remediation_guidance: Some("Deploy network monitoring tools with anomaly detection at IT/OT boundaries".to_string()),
    });

    // ========================================================================
    // Access Control
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-ACC-001".to_string(),
        control_id: "SD-02.6".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Multi-Factor Authentication".to_string(),
        description: "Implement multi-factor authentication for remote access and privileged access to OT systems".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2(1)".to_string(), "CISA-CPG-1.E".to_string()],
        remediation_guidance: Some("Deploy MFA for all remote and privileged access to critical systems".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-ACC-002".to_string(),
        control_id: "SD-02.7".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Privileged Account Management".to_string(),
        description: "Implement controls to manage privileged accounts including shared accounts on OT systems".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string(), "NIST-AC-2".to_string()],
        remediation_guidance: Some("Deploy privileged access management solution with audit logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-ACC-003".to_string(),
        control_id: "SD-02.8".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Account Lifecycle Management".to_string(),
        description: "Implement processes to promptly disable or remove accounts when no longer needed".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2(3)".to_string()],
        remediation_guidance: Some("Establish account review processes with automated deprovisioning".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-ACC-004".to_string(),
        control_id: "SD-02.9".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Password Policy".to_string(),
        description: "Implement strong password policies for all accounts with access to pipeline systems".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-5".to_string()],
        remediation_guidance: Some("Configure password policies requiring complexity, length, and rotation".to_string()),
    });

    // ========================================================================
    // Patch and Vulnerability Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-VUL-001".to_string(),
        control_id: "SD-02.10".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Continuous Vulnerability Scanning".to_string(),
        description: "Implement continuous vulnerability scanning and assessment of IT and OT systems".to_string(),
        category: "Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-RA-5".to_string(), "CISA-CPG-2.A".to_string()],
        remediation_guidance: Some("Deploy vulnerability scanning tools with regular automated scans".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-VUL-002".to_string(),
        control_id: "SD-02.11".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Patch Management Process".to_string(),
        description: "Implement timely patching of known vulnerabilities based on risk prioritization".to_string(),
        category: "Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-2".to_string()],
        remediation_guidance: Some("Establish patch management process with defined SLAs based on severity".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-VUL-003".to_string(),
        control_id: "SD-02.12".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "OT Patch Testing".to_string(),
        description: "Implement patch testing procedures for OT systems to prevent operational impact".to_string(),
        category: "Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SI-2(2)".to_string()],
        remediation_guidance: Some("Establish OT patch testing environment and procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-VUL-004".to_string(),
        control_id: "SD-02.13".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Compensating Controls for Unpatched Systems".to_string(),
        description: "Implement compensating controls for systems that cannot be immediately patched".to_string(),
        category: "Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-2(6)".to_string()],
        remediation_guidance: Some("Document compensating controls including network isolation and monitoring".to_string()),
    });

    // ========================================================================
    // Incident Response and Recovery
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-IR-001".to_string(),
        control_id: "SD-02.14".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Incident Response Plan".to_string(),
        description: "Develop and maintain a cybersecurity incident response plan specific to pipeline operations".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-8".to_string(), "NIST-800-61".to_string()],
        remediation_guidance: Some("Create incident response plan with pipeline-specific scenarios and procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-IR-002".to_string(),
        control_id: "SD-02.15".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Incident Response Testing".to_string(),
        description: "Conduct annual testing of the cybersecurity incident response plan".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-3".to_string()],
        remediation_guidance: Some("Schedule and conduct annual tabletop exercises and incident response drills".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-IR-003".to_string(),
        control_id: "SD-02.16".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Recovery Procedures".to_string(),
        description: "Develop and test procedures to restore pipeline operations after a cybersecurity incident".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-10".to_string()],
        remediation_guidance: Some("Document and test recovery procedures for critical pipeline systems".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-IR-004".to_string(),
        control_id: "SD-02.17".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Backup and Restoration".to_string(),
        description: "Maintain secure backups of critical systems and configurations for rapid recovery".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-9".to_string()],
        remediation_guidance: Some("Implement offline backups of OT configurations and critical data".to_string()),
    });

    // ========================================================================
    // Security Architecture
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-ARC-001".to_string(),
        control_id: "SD-02.18".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Security Architecture Review".to_string(),
        description: "Conduct regular review of security architecture to identify gaps and improvements".to_string(),
        category: "Security Architecture".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PL-8".to_string()],
        remediation_guidance: Some("Perform annual security architecture review with documented findings".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-ARC-002".to_string(),
        control_id: "SD-02.19".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Defense in Depth".to_string(),
        description: "Implement defense-in-depth architecture with multiple layers of security controls".to_string(),
        category: "Security Architecture".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string(), "IEC62443-3.3".to_string()],
        remediation_guidance: Some("Implement layered security controls at network, host, and application levels".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-ARC-003".to_string(),
        control_id: "SD-02.20".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Asset Inventory".to_string(),
        description: "Maintain accurate inventory of all IT and OT assets including hardware, software, and network connections".to_string(),
        category: "Security Architecture".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-8".to_string(), "CISA-CPG-1.A".to_string()],
        remediation_guidance: Some("Implement automated asset discovery and maintain current inventory".to_string()),
    });

    // ========================================================================
    // Security Monitoring and Detection
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-MON-001".to_string(),
        control_id: "SD-02.21".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Security Event Logging".to_string(),
        description: "Implement comprehensive logging of security events across IT and OT systems".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-2".to_string(), "NIST-AU-3".to_string()],
        remediation_guidance: Some("Configure security event logging on all critical systems with centralized collection".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-MON-002".to_string(),
        control_id: "SD-02.22".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Log Retention".to_string(),
        description: "Retain security logs for a minimum period to support incident investigation".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-11".to_string()],
        remediation_guidance: Some("Configure log retention for minimum 12 months with secure storage".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-MON-003".to_string(),
        control_id: "SD-02.23".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Intrusion Detection".to_string(),
        description: "Implement intrusion detection capabilities for IT and OT networks".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-4".to_string()],
        remediation_guidance: Some("Deploy IDS/IPS with signatures for known OT/ICS threats".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-MON-004".to_string(),
        control_id: "SD-02.24".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Security Operations Center".to_string(),
        description: "Establish or contract with a Security Operations Center for 24/7 monitoring".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SI-4(10)".to_string()],
        remediation_guidance: Some("Establish SOC capability or engage managed security service provider".to_string()),
    });

    // ========================================================================
    // Training and Awareness
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-TRN-001".to_string(),
        control_id: "SD-02.25".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Cybersecurity Awareness Training".to_string(),
        description: "Provide cybersecurity awareness training to all personnel with access to pipeline systems".to_string(),
        category: "Training".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AT-2".to_string()],
        remediation_guidance: Some("Implement annual cybersecurity awareness training program".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-TRN-002".to_string(),
        control_id: "SD-02.26".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Role-Based Security Training".to_string(),
        description: "Provide role-specific security training for personnel with security responsibilities".to_string(),
        category: "Training".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AT-3".to_string()],
        remediation_guidance: Some("Develop and deliver role-specific training for security and OT personnel".to_string()),
    });

    // ========================================================================
    // Supply Chain Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "TSA-SUP-001".to_string(),
        control_id: "SD-02.27".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Third-Party Risk Assessment".to_string(),
        description: "Assess cybersecurity risks from third-party vendors with access to pipeline systems".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SR-3".to_string()],
        remediation_guidance: Some("Conduct security assessments of vendors before granting system access".to_string()),
    });

    controls.push(ComplianceControl {
        id: "TSA-SUP-002".to_string(),
        control_id: "SD-02.28".to_string(),
        framework: ComplianceFramework::TsaPipeline,
        title: "Vendor Access Controls".to_string(),
        description: "Implement controls to manage and monitor third-party access to pipeline systems".to_string(),
        category: "Supply Chain".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-24".to_string()],
        remediation_guidance: Some("Implement just-in-time access and monitoring for vendor connections".to_string()),
    });

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant TSA Pipeline Security controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Network segmentation issues
    if title_lower.contains("segment") || title_lower.contains("isolation") || title_lower.contains("dmz") {
        mappings.push(("SD-02.2".to_string(), Severity::Critical));
        mappings.push(("SD-02.3".to_string(), Severity::Critical));
    }

    // Remote access vulnerabilities
    if title_lower.contains("remote") || title_lower.contains("vpn") || title_lower.contains("rdp") {
        mappings.push(("SD-02.4".to_string(), Severity::Critical));
        mappings.push(("SD-02.6".to_string(), Severity::Critical));
    }

    // Authentication issues
    if title_lower.contains("authentication") || title_lower.contains("mfa") || title_lower.contains("password") {
        mappings.push(("SD-02.6".to_string(), Severity::Critical));
        mappings.push(("SD-02.9".to_string(), Severity::High));
    }

    // Privileged access
    if title_lower.contains("privilege") || title_lower.contains("admin") || title_lower.contains("root") {
        mappings.push(("SD-02.7".to_string(), Severity::High));
    }

    // Vulnerability/patch management
    if title_lower.contains("patch") || title_lower.contains("outdated") || title_lower.contains("vulnerability") {
        mappings.push(("SD-02.10".to_string(), Severity::High));
        mappings.push(("SD-02.11".to_string(), Severity::High));
    }

    // Logging and monitoring
    if title_lower.contains("log") || title_lower.contains("audit") || title_lower.contains("monitor") {
        mappings.push(("SD-02.21".to_string(), Severity::High));
        mappings.push(("SD-02.22".to_string(), Severity::Medium));
    }

    // Intrusion detection
    if title_lower.contains("intrusion") || title_lower.contains("ids") || title_lower.contains("ips") {
        mappings.push(("SD-02.23".to_string(), Severity::High));
    }

    // Backup and recovery
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("SD-02.17".to_string(), Severity::High));
    }

    // OT/ICS specific
    if title_lower.contains("scada") || title_lower.contains("plc") || title_lower.contains("hmi")
        || title_lower.contains("ics") || title_lower.contains("ot ") {
        mappings.push(("SD-02.2".to_string(), Severity::Critical));
        mappings.push(("SD-02.3".to_string(), Severity::Critical));
        mappings.push(("SD-02.12".to_string(), Severity::High));
    }

    // Third-party/vendor access
    if title_lower.contains("vendor") || title_lower.contains("third-party") || title_lower.contains("supplier") {
        mappings.push(("SD-02.27".to_string(), Severity::High));
        mappings.push(("SD-02.28".to_string(), Severity::High));
    }

    // Default mapping for general security issues
    if mappings.is_empty() {
        mappings.push(("SD-02.19".to_string(), Severity::Medium));
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
            assert_eq!(control.framework, ComplianceFramework::TsaPipeline);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Remote access vulnerability", None, None, None);
        assert!(!mappings.is_empty());

        let scada_mappings = map_vulnerability("SCADA system exposed", None, None, None);
        assert!(scada_mappings.iter().any(|(id, _)| id == "SD-02.2"));
    }
}
