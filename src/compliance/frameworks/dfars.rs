//! DFARS 252.204-7012 Compliance Framework
//!
//! Defense Federal Acquisition Regulation Supplement (DFARS) clause 252.204-7012
//! establishes cybersecurity requirements for contractors handling Covered Defense
//! Information (CDI) and operationally critical support systems.
//!
//! Key requirements include:
//! - Implementing NIST SP 800-171 security controls
//! - Reporting cyber incidents within 72 hours
//! - Preserving media for 90 days following incident
//! - Providing DoD access for damage assessment
//! - Flowing down requirements to subcontractors
//!
//! This framework maps DFARS requirements to NIST 800-171 controls and provides
//! cross-references to CMMC 2.0 for organizations pursuing certification.
//!
//! Control Categories:
//! - Adequate Security (NIST 800-171 derived)
//! - Cyber Incident Reporting
//! - Malicious Software Protection
//! - Media Preservation and Protection
//! - Access Controls
//! - Audit and Accountability
//! - Configuration Management
//! - Identification and Authentication
//! - System and Communications Protection
//! - System and Information Integrity

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of DFARS controls in this module
pub const CONTROL_COUNT: usize = 40;

/// Get all DFARS 252.204-7012 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // Add controls by category
    controls.extend(get_adequate_security_controls());
    controls.extend(get_incident_reporting_controls());
    controls.extend(get_malicious_software_controls());
    controls.extend(get_media_preservation_controls());
    controls.extend(get_access_control_controls());
    controls.extend(get_audit_controls());
    controls.extend(get_configuration_management_controls());
    controls.extend(get_identification_authentication_controls());
    controls.extend(get_system_communications_controls());
    controls.extend(get_system_integrity_controls());

    controls
}

/// Adequate Security controls - implementing NIST 800-171 requirements
fn get_adequate_security_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-AS-001".to_string(),
            control_id: "252.204-7012(b)(1)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Provide adequate security for covered defense information".to_string(),
            description: "Contractors must provide adequate security on all covered contractor \
                information systems. Adequate security means protective measures commensurate \
                with the consequences and probability of loss, misuse, or unauthorized access \
                to or modification of information.".to_string(),
            category: "Adequate Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.1".to_string(),
                "CMMC-AC.L1-3.1.1".to_string(),
            ],
            remediation_guidance: Some(
                "Implement NIST SP 800-171 controls for all systems processing, storing, \
                or transmitting Covered Defense Information (CDI). Conduct a gap assessment \
                and develop a System Security Plan (SSP).".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AS-002".to_string(),
            control_id: "252.204-7012(b)(2)(i)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Implement NIST SP 800-171 security requirements".to_string(),
            description: "Contractors must implement NIST SP 800-171 'Protecting Controlled \
                Unclassified Information in Nonfederal Systems and Organizations' as the \
                minimum security standard for covered contractor information systems.".to_string(),
            category: "Adequate Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("DFARS-AS-001".to_string()),
            cross_references: vec![
                "NIST-800-171".to_string(),
                "CMMC-2.0".to_string(),
            ],
            remediation_guidance: Some(
                "Complete a NIST SP 800-171 self-assessment and document compliance status \
                for all 110 security requirements. Submit assessment score to SPRS.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AS-003".to_string(),
            control_id: "252.204-7012(b)(2)(ii)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Apply additional security measures for operationally critical support".to_string(),
            description: "For operationally critical support, contractors must apply other \
                information systems security measures when the Contracting Officer specifies \
                additional requirements based on risk assessment.".to_string(),
            category: "Adequate Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("DFARS-AS-001".to_string()),
            cross_references: vec![
                "NIST-800-171-3.12.4".to_string(),
                "CMMC-CA.L2-3.12.4".to_string(),
            ],
            remediation_guidance: Some(
                "Review contract for additional security requirements beyond NIST 800-171. \
                Implement enhanced controls as specified for operationally critical systems.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AS-004".to_string(),
            control_id: "252.204-7012(b)(3)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Apply cloud computing security requirements".to_string(),
            description: "When using cloud computing, contractors must ensure the cloud \
                service provider meets security requirements equivalent to FedRAMP Moderate \
                baseline for covered defense information.".to_string(),
            category: "Adequate Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "FedRAMP-Moderate".to_string(),
                "NIST-800-171-3.12.1".to_string(),
            ],
            remediation_guidance: Some(
                "Verify cloud service providers have FedRAMP Moderate authorization or \
                equivalent. Document cloud security responsibilities in contracts.".to_string(),
            ),
        },
    ]
}

/// Cyber Incident Reporting controls
fn get_incident_reporting_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-IR-001".to_string(),
            control_id: "252.204-7012(c)(1)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Report cyber incidents within 72 hours".to_string(),
            description: "Contractors must rapidly report cyber incidents that affect covered \
                contractor information systems or covered defense information to DoD within \
                72 hours of discovery.".to_string(),
            category: "Cyber Incident Reporting".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.6.1".to_string(),
                "CMMC-IR.L2-3.6.1".to_string(),
            ],
            remediation_guidance: Some(
                "Establish incident response procedures with 72-hour reporting capability. \
                Register with DC3 (Defense Cyber Crime Center) for incident reporting. \
                Train personnel on incident identification and reporting procedures.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-IR-002".to_string(),
            control_id: "252.204-7012(c)(2)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Include required information in cyber incident reports".to_string(),
            description: "Cyber incident reports must include: a description of the technique \
                used, a sample of malicious software (if applicable), and a summary of \
                information compromised.".to_string(),
            category: "Cyber Incident Reporting".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("DFARS-IR-001".to_string()),
            cross_references: vec![
                "NIST-800-171-3.6.2".to_string(),
                "CMMC-IR.L2-3.6.2".to_string(),
            ],
            remediation_guidance: Some(
                "Develop incident report templates that capture required information. \
                Establish procedures for collecting and preserving evidence for reports.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-IR-003".to_string(),
            control_id: "252.204-7012(d)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Support DoD damage assessment activities".to_string(),
            description: "Contractors must provide DoD access to affected media, personnel, \
                and additional information or equipment to conduct damage assessment when \
                requested following a cyber incident.".to_string(),
            category: "Cyber Incident Reporting".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.6.3".to_string(),
            ],
            remediation_guidance: Some(
                "Establish procedures for DoD damage assessment support. Identify personnel \
                authorized to coordinate with DoD. Document chain of custody for evidence.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-IR-004".to_string(),
            control_id: "252.204-7012(e)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Submit malicious software to DC3".to_string(),
            description: "Contractors must submit malicious software discovered in connection \
                with a cyber incident to the DoD Cyber Crime Center (DC3).".to_string(),
            category: "Cyber Incident Reporting".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.4".to_string(),
            ],
            remediation_guidance: Some(
                "Establish procedures for capturing and submitting malware samples to DC3. \
                Configure sandboxed analysis environment for safe malware handling.".to_string(),
            ),
        },
    ]
}

/// Malicious Software Protection controls
fn get_malicious_software_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-MS-001".to_string(),
            control_id: "252.204-7012(c)(3)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Isolate and protect malicious software for analysis".to_string(),
            description: "When malicious software is discovered, contractors must isolate \
                and submit a sample to DC3, and protect the sample from further damage.".to_string(),
            category: "Malicious Software Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.2".to_string(),
                "CMMC-SI.L1-3.14.2".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy endpoint detection and response (EDR) with malware isolation \
                capabilities. Configure automated quarantine for detected malware.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-MS-002".to_string(),
            control_id: "DFARS-3.14.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Implement malware protection mechanisms".to_string(),
            description: "Identify, report, and correct system flaws in a timely manner. \
                Provide protection from malicious code at designated locations.".to_string(),
            category: "Malicious Software Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.1".to_string(),
                "CMMC-SI.L1-3.14.1".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy antivirus/anti-malware on all endpoints and servers. Configure \
                automatic updates for malware signatures. Enable real-time scanning.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-MS-003".to_string(),
            control_id: "DFARS-3.14.3".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Monitor system security alerts and advisories".to_string(),
            description: "Monitor system security alerts, advisories, and directives from \
                authoritative sources and take appropriate actions in response.".to_string(),
            category: "Malicious Software Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.3".to_string(),
                "CMMC-SI.L2-3.14.3".to_string(),
            ],
            remediation_guidance: Some(
                "Subscribe to CISA alerts, vendor security bulletins, and CVE feeds. \
                Establish procedures for reviewing and acting on security advisories.".to_string(),
            ),
        },
    ]
}

/// Media Preservation and Protection controls
fn get_media_preservation_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-MP-001".to_string(),
            control_id: "252.204-7012(f)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Preserve media for 90 days following cyber incident".to_string(),
            description: "Contractors must preserve and protect images of all known affected \
                information systems and all relevant monitoring/packet capture data for at \
                least 90 days following a cyber incident.".to_string(),
            category: "Media Preservation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.6.1".to_string(),
                "NIST-800-171-3.8.9".to_string(),
            ],
            remediation_guidance: Some(
                "Implement forensic imaging capability. Configure log retention for minimum \
                90 days. Establish evidence preservation procedures and chain of custody.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-MP-002".to_string(),
            control_id: "DFARS-3.8.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Protect media containing CUI during transport".to_string(),
            description: "Protect the confidentiality of CUI stored on digital media during \
                transport outside of controlled areas using cryptographic mechanisms.".to_string(),
            category: "Media Preservation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.1".to_string(),
                "CMMC-MP.L2-3.8.1".to_string(),
            ],
            remediation_guidance: Some(
                "Encrypt all removable media containing CUI. Use FIPS 140-2 validated \
                encryption. Implement hardware-encrypted USB drives for data transport.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-MP-003".to_string(),
            control_id: "DFARS-3.8.3".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Sanitize or destroy media before disposal".to_string(),
            description: "Sanitize or destroy information system media containing CUI \
                before disposal or release for reuse using approved sanitization methods.".to_string(),
            category: "Media Preservation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.3".to_string(),
                "CMMC-MP.L2-3.8.3".to_string(),
                "NIST-800-88".to_string(),
            ],
            remediation_guidance: Some(
                "Implement media sanitization procedures per NIST SP 800-88. Document \
                destruction methods. Maintain sanitization/destruction logs.".to_string(),
            ),
        },
    ]
}

/// Access Control controls
fn get_access_control_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-AC-001".to_string(),
            control_id: "DFARS-3.1.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Limit system access to authorized users".to_string(),
            description: "Limit information system access to authorized users, processes \
                acting on behalf of authorized users, or devices including other systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.1".to_string(),
                "CMMC-AC.L1-3.1.1".to_string(),
                "NIST-AC-2".to_string(),
            ],
            remediation_guidance: Some(
                "Implement identity management with unique user accounts. Configure access \
                controls on all systems. Disable shared/anonymous accounts.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AC-002".to_string(),
            control_id: "DFARS-3.1.2".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Limit system access to authorized transactions and functions".to_string(),
            description: "Limit information system access to the types of transactions and \
                functions that authorized users are permitted to execute.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.2".to_string(),
                "CMMC-AC.L1-3.1.2".to_string(),
                "NIST-AC-3".to_string(),
            ],
            remediation_guidance: Some(
                "Implement role-based access control (RBAC). Define and enforce least \
                privilege principles. Review and audit user permissions regularly.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AC-003".to_string(),
            control_id: "DFARS-3.1.3".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Control flow of CUI in accordance with approved authorizations".to_string(),
            description: "Control the flow of CUI in accordance with approved authorizations, \
                including controlling information flow between security domains.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.3".to_string(),
                "CMMC-AC.L2-3.1.3".to_string(),
                "NIST-AC-4".to_string(),
            ],
            remediation_guidance: Some(
                "Implement network segmentation for CUI systems. Configure firewalls to \
                control information flow. Deploy DLP solutions to prevent unauthorized transfers.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AC-004".to_string(),
            control_id: "DFARS-3.1.5".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Employ principle of least privilege".to_string(),
            description: "Employ the principle of least privilege, including for specific \
                security functions and privileged accounts.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.5".to_string(),
                "CMMC-AC.L2-3.1.5".to_string(),
                "NIST-AC-6".to_string(),
            ],
            remediation_guidance: Some(
                "Grant minimum necessary privileges. Implement privileged access management. \
                Conduct regular access reviews and remove unnecessary privileges.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AC-005".to_string(),
            control_id: "DFARS-3.1.12".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Monitor and control remote access sessions".to_string(),
            description: "Monitor and control remote access sessions, employing automated \
                mechanisms to facilitate monitoring and control.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.12".to_string(),
                "CMMC-AC.L2-3.1.12".to_string(),
                "NIST-AC-17".to_string(),
            ],
            remediation_guidance: Some(
                "Implement VPN with logging for remote access. Deploy session monitoring \
                tools. Configure session timeouts and MFA for remote access.".to_string(),
            ),
        },
    ]
}

/// Audit and Accountability controls
fn get_audit_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-AU-001".to_string(),
            control_id: "DFARS-3.3.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Create and retain system audit logs".to_string(),
            description: "Create and retain system audit logs and records to the extent \
                needed to enable monitoring, analysis, investigation, and reporting.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.1".to_string(),
                "CMMC-AU.L2-3.3.1".to_string(),
                "NIST-AU-2".to_string(),
            ],
            remediation_guidance: Some(
                "Enable audit logging on all systems. Configure centralized log collection. \
                Retain logs for minimum 90 days online, 1 year offline.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AU-002".to_string(),
            control_id: "DFARS-3.3.2".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Ensure individual accountability through audit records".to_string(),
            description: "Ensure that the actions of individual system users can be uniquely \
                traced to those users so they can be held accountable.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.2".to_string(),
                "CMMC-AU.L2-3.3.2".to_string(),
                "NIST-AU-3".to_string(),
            ],
            remediation_guidance: Some(
                "Configure audit logs to include user identification. Prohibit shared \
                accounts. Implement unique user IDs for all users.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AU-003".to_string(),
            control_id: "DFARS-3.3.4".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Alert on audit logging process failures".to_string(),
            description: "Alert in the event of an audit logging process failure and take \
                defined actions to address the failure.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.4".to_string(),
                "CMMC-AU.L2-3.3.4".to_string(),
                "NIST-AU-5".to_string(),
            ],
            remediation_guidance: Some(
                "Configure monitoring for audit system failures. Implement alerts to \
                security personnel. Define failover procedures for logging systems.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-AU-004".to_string(),
            control_id: "DFARS-3.3.5".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Correlate audit review and analysis".to_string(),
            description: "Correlate audit record review, analysis, and reporting processes \
                for investigation and response to indications of unlawful activity.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.5".to_string(),
                "CMMC-AU.L2-3.3.5".to_string(),
                "NIST-AU-6".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy SIEM for log correlation. Configure automated alerting rules. \
                Establish incident investigation procedures using correlated logs.".to_string(),
            ),
        },
    ]
}

/// Configuration Management controls
fn get_configuration_management_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-CM-001".to_string(),
            control_id: "DFARS-3.4.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Establish and maintain baseline configurations".to_string(),
            description: "Establish and maintain baseline configurations and inventories \
                of organizational systems throughout the system development life cycle.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.1".to_string(),
                "CMMC-CM.L2-3.4.1".to_string(),
                "NIST-CM-2".to_string(),
            ],
            remediation_guidance: Some(
                "Create baseline configurations using CIS Benchmarks or DISA STIGs. \
                Document and version control all configuration baselines.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-CM-002".to_string(),
            control_id: "DFARS-3.4.2".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Establish and enforce security configuration settings".to_string(),
            description: "Establish and enforce security configuration settings for \
                information technology products employed in organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.2".to_string(),
                "CMMC-CM.L2-3.4.2".to_string(),
                "NIST-CM-6".to_string(),
            ],
            remediation_guidance: Some(
                "Apply security hardening standards. Deploy configuration management tools. \
                Monitor for configuration drift with automated scanning.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-CM-003".to_string(),
            control_id: "DFARS-3.4.3".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Track and control configuration changes".to_string(),
            description: "Track, review, approve or disapprove, and log changes to \
                organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.3".to_string(),
                "CMMC-CM.L2-3.4.3".to_string(),
                "NIST-CM-3".to_string(),
            ],
            remediation_guidance: Some(
                "Implement change management process. Require approval for system changes. \
                Maintain change logs and audit trail.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-CM-004".to_string(),
            control_id: "DFARS-3.4.6".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Employ principle of least functionality".to_string(),
            description: "Employ the principle of least functionality by configuring \
                systems to provide only essential capabilities.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.6".to_string(),
                "CMMC-CM.L2-3.4.6".to_string(),
                "NIST-CM-7".to_string(),
            ],
            remediation_guidance: Some(
                "Disable unnecessary services and ports. Remove unused software. \
                Implement application whitelisting where feasible.".to_string(),
            ),
        },
    ]
}

/// Identification and Authentication controls
fn get_identification_authentication_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-IA-001".to_string(),
            control_id: "DFARS-3.5.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Identify system users, processes, and devices".to_string(),
            description: "Identify information system users, processes acting on behalf \
                of users, or devices.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.1".to_string(),
                "CMMC-IA.L1-3.5.1".to_string(),
                "NIST-IA-2".to_string(),
            ],
            remediation_guidance: Some(
                "Implement centralized identity management. Assign unique identifiers to \
                all users, service accounts, and devices. Maintain identity inventory.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-IA-002".to_string(),
            control_id: "DFARS-3.5.2".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Authenticate users, processes, and devices".to_string(),
            description: "Authenticate (or verify) the identities of those users, processes, \
                or devices as a prerequisite to allowing access.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.2".to_string(),
                "CMMC-IA.L1-3.5.2".to_string(),
                "NIST-IA-2".to_string(),
            ],
            remediation_guidance: Some(
                "Implement strong authentication mechanisms. Deploy MFA for privileged \
                access and remote access. Use certificate-based authentication for devices.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-IA-003".to_string(),
            control_id: "DFARS-3.5.3".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Employ multi-factor authentication".to_string(),
            description: "Use multifactor authentication for local and network access to \
                privileged accounts and for network access to non-privileged accounts.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.3".to_string(),
                "CMMC-IA.L2-3.5.3".to_string(),
                "NIST-IA-2(1)".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy MFA solution (hardware tokens, authenticator apps, or PIV/CAC). \
                Configure MFA for VPN, privileged access, and administrative interfaces.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-IA-004".to_string(),
            control_id: "DFARS-3.5.7".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Enforce minimum password complexity".to_string(),
            description: "Enforce a minimum password complexity and change of characters \
                when new passwords are created.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.7".to_string(),
                "CMMC-IA.L2-3.5.7".to_string(),
                "NIST-IA-5".to_string(),
            ],
            remediation_guidance: Some(
                "Configure password policy: minimum 12 characters, complexity requirements, \
                no dictionary words. Consider passphrase policies for enhanced security.".to_string(),
            ),
        },
    ]
}

/// System and Communications Protection controls
fn get_system_communications_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-SC-001".to_string(),
            control_id: "DFARS-3.13.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Monitor communications at system boundaries".to_string(),
            description: "Monitor, control, and protect communications at external \
                boundaries and key internal boundaries of the system.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.1".to_string(),
                "CMMC-SC.L1-3.13.1".to_string(),
                "NIST-SC-7".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy firewalls at network boundaries. Implement network monitoring \
                and IDS/IPS. Segment CUI networks from general-purpose networks.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-SC-002".to_string(),
            control_id: "DFARS-3.13.8".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Implement cryptographic mechanisms for CUI transmission".to_string(),
            description: "Implement cryptographic mechanisms to prevent unauthorized \
                disclosure of CUI during transmission.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.8".to_string(),
                "CMMC-SC.L2-3.13.8".to_string(),
                "NIST-SC-8".to_string(),
            ],
            remediation_guidance: Some(
                "Use TLS 1.2 or higher for all CUI transmissions. Encrypt email containing \
                CUI. Implement VPN for remote access to CUI systems.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-SC-003".to_string(),
            control_id: "DFARS-3.13.11".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Employ FIPS-validated cryptography".to_string(),
            description: "Employ FIPS-validated cryptography when used to protect the \
                confidentiality of CUI.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.11".to_string(),
                "CMMC-SC.L2-3.13.11".to_string(),
                "NIST-SC-13".to_string(),
            ],
            remediation_guidance: Some(
                "Use FIPS 140-2 or 140-3 validated cryptographic modules. Enable FIPS \
                mode on operating systems. Verify encryption implementations are validated.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-SC-004".to_string(),
            control_id: "DFARS-3.13.16".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Protect CUI at rest".to_string(),
            description: "Protect the confidentiality of CUI at rest by employing \
                cryptographic mechanisms.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.16".to_string(),
                "CMMC-SC.L2-3.13.16".to_string(),
                "NIST-SC-28".to_string(),
            ],
            remediation_guidance: Some(
                "Enable full disk encryption on all systems with CUI. Encrypt databases \
                containing CUI. Use AES-256 or equivalent for data at rest.".to_string(),
            ),
        },
    ]
}

/// System and Information Integrity controls
fn get_system_integrity_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-SI-001".to_string(),
            control_id: "DFARS-3.14.1".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Identify and correct system flaws".to_string(),
            description: "Identify, report, and correct information system flaws in a \
                timely manner.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.1".to_string(),
                "CMMC-SI.L1-3.14.1".to_string(),
                "NIST-SI-2".to_string(),
            ],
            remediation_guidance: Some(
                "Implement vulnerability scanning and patch management. Remediate critical \
                vulnerabilities within 30 days, high within 60 days.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-SI-002".to_string(),
            control_id: "DFARS-3.14.2".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Provide malicious code protection".to_string(),
            description: "Provide protection from malicious code at appropriate locations \
                within organizational information systems.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.2".to_string(),
                "CMMC-SI.L1-3.14.2".to_string(),
                "NIST-SI-3".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy endpoint protection on all systems. Configure automatic signature \
                updates. Enable email and web gateway malware scanning.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-SI-003".to_string(),
            control_id: "DFARS-3.14.6".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Monitor organizational systems".to_string(),
            description: "Monitor organizational systems, including inbound and outbound \
                communications traffic, to detect attacks and indicators of potential attacks.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.6".to_string(),
                "CMMC-SI.L2-3.14.6".to_string(),
                "NIST-SI-4".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy network monitoring and IDS/IPS. Implement SIEM for security event \
                monitoring. Configure alerting for suspicious activities.".to_string(),
            ),
        },
        ComplianceControl {
            id: "DFARS-SI-004".to_string(),
            control_id: "DFARS-3.14.7".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Identify unauthorized use of systems".to_string(),
            description: "Identify unauthorized use of organizational systems and take \
                appropriate actions.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.7".to_string(),
                "CMMC-SI.L2-3.14.7".to_string(),
                "NIST-SI-4".to_string(),
            ],
            remediation_guidance: Some(
                "Monitor for unauthorized access attempts. Implement UEBA for anomaly \
                detection. Configure alerts for policy violations.".to_string(),
            ),
        },
    ]
}

/// Subcontractor flow-down control
fn _get_flowdown_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "DFARS-FD-001".to_string(),
            control_id: "252.204-7012(m)".to_string(),
            framework: ComplianceFramework::Dfars,
            title: "Flow down DFARS requirements to subcontractors".to_string(),
            description: "Include this clause in subcontracts, or contractual instruments, \
                for operationally critical support, or when subcontract performance will \
                involve covered defense information.".to_string(),
            category: "Subcontractor Flow-down".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-NFO".to_string(),
                "CMMC-2.0".to_string(),
            ],
            remediation_guidance: Some(
                "Include DFARS 252.204-7012 clause in all subcontracts involving CDI. \
                Verify subcontractor compliance with NIST 800-171 requirements.".to_string(),
            ),
        },
    ]
}

/// Get controls by DFARS category
pub fn get_controls_by_category(category: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get all DFARS categories
pub fn get_categories() -> Vec<&'static str> {
    vec![
        "Adequate Security",
        "Cyber Incident Reporting",
        "Malicious Software Protection",
        "Media Preservation",
        "Access Control",
        "Audit and Accountability",
        "Configuration Management",
        "Identification and Authentication",
        "System and Communications Protection",
        "System and Information Integrity",
    ]
}

/// Map a vulnerability to relevant DFARS controls
///
/// This function maps discovered vulnerabilities to applicable DFARS controls
/// based on the vulnerability characteristics. It returns a vector of tuples
/// containing the control ID and the severity of the finding.
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("access control")
        || title_lower.contains("privilege")
    {
        mappings.push(("DFARS-3.1.1".to_string(), Severity::High));
        mappings.push(("DFARS-3.1.2".to_string(), Severity::High));
        mappings.push(("DFARS-3.1.5".to_string(), Severity::High));
    }

    // Authentication vulnerabilities
    if title_lower.contains("authentication")
        || title_lower.contains("password")
        || title_lower.contains("credential")
        || title_lower.contains("weak password")
    {
        mappings.push(("DFARS-3.5.1".to_string(), Severity::High));
        mappings.push(("DFARS-3.5.2".to_string(), Severity::High));
        mappings.push(("DFARS-3.5.7".to_string(), Severity::Medium));
    }

    // MFA vulnerabilities
    if title_lower.contains("mfa")
        || title_lower.contains("multi-factor")
        || title_lower.contains("two-factor")
        || title_lower.contains("2fa")
    {
        mappings.push(("DFARS-3.5.3".to_string(), Severity::High));
    }

    // Encryption vulnerabilities
    if title_lower.contains("unencrypted")
        || title_lower.contains("weak encryption")
        || title_lower.contains("plaintext")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
    {
        mappings.push(("DFARS-3.13.8".to_string(), Severity::High));
        mappings.push(("DFARS-3.13.11".to_string(), Severity::High));
        mappings.push(("DFARS-3.13.16".to_string(), Severity::High));
    }

    // FIPS compliance
    if title_lower.contains("fips")
        || title_lower.contains("cryptographic")
        || title_lower.contains("crypto")
    {
        mappings.push(("DFARS-3.13.11".to_string(), Severity::High));
    }

    // Malware/antivirus vulnerabilities
    if title_lower.contains("malware")
        || title_lower.contains("antivirus")
        || title_lower.contains("anti-virus")
        || title_lower.contains("virus")
        || title_lower.contains("endpoint protection")
    {
        mappings.push(("DFARS-3.14.2".to_string(), Severity::High));
        mappings.push(("DFARS-MS-001".to_string(), Severity::High));
        mappings.push(("DFARS-MS-002".to_string(), Severity::High));
    }

    // Patching/vulnerability management
    if title_lower.contains("unpatched")
        || title_lower.contains("outdated")
        || title_lower.contains("missing patch")
        || title_lower.contains("end of life")
        || title_lower.contains("eol")
    {
        mappings.push(("DFARS-3.14.1".to_string(), Severity::High));
    }

    // Logging/audit vulnerabilities
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("no log")
        || title_lower.contains("log disabled")
    {
        mappings.push(("DFARS-3.3.1".to_string(), Severity::Medium));
        mappings.push(("DFARS-3.3.2".to_string(), Severity::Medium));
    }

    // Network/firewall vulnerabilities
    if title_lower.contains("firewall")
        || title_lower.contains("network boundary")
        || title_lower.contains("open port")
        || title_lower.contains("exposed")
    {
        mappings.push(("DFARS-3.13.1".to_string(), Severity::High));
    }

    // Configuration vulnerabilities
    if title_lower.contains("misconfigur")
        || title_lower.contains("default config")
        || title_lower.contains("hardening")
    {
        mappings.push(("DFARS-3.4.1".to_string(), Severity::Medium));
        mappings.push(("DFARS-3.4.2".to_string(), Severity::Medium));
    }

    // Unnecessary services
    if title_lower.contains("unnecessary service")
        || title_lower.contains("unused port")
        || title_lower.contains("telnet")
        || title_lower.contains("ftp")
    {
        mappings.push(("DFARS-3.4.6".to_string(), Severity::Medium));
    }

    // Remote access vulnerabilities
    if title_lower.contains("remote access")
        || title_lower.contains("vpn")
        || title_lower.contains("ssh")
        || title_lower.contains("rdp")
    {
        mappings.push(("DFARS-3.1.12".to_string(), Severity::High));
    }

    // Information flow/DLP
    if title_lower.contains("data leak")
        || title_lower.contains("exfiltration")
        || title_lower.contains("dlp")
        || title_lower.contains("information flow")
    {
        mappings.push(("DFARS-3.1.3".to_string(), Severity::High));
    }

    // Monitoring vulnerabilities
    if title_lower.contains("monitoring")
        || title_lower.contains("ids")
        || title_lower.contains("ips")
        || title_lower.contains("detection")
    {
        mappings.push(("DFARS-3.14.6".to_string(), Severity::Medium));
        mappings.push(("DFARS-3.14.7".to_string(), Severity::Medium));
    }

    // Media protection
    if title_lower.contains("removable media")
        || title_lower.contains("usb")
        || title_lower.contains("media sanitization")
    {
        mappings.push(("DFARS-3.8.1".to_string(), Severity::Medium));
        mappings.push(("DFARS-3.8.3".to_string(), Severity::Medium));
    }

    // Cloud security
    if title_lower.contains("cloud")
        || title_lower.contains("aws")
        || title_lower.contains("azure")
        || title_lower.contains("fedramp")
    {
        mappings.push(("252.204-7012(b)(3)".to_string(), Severity::High));
    }

    // Incident response
    if title_lower.contains("incident")
        || title_lower.contains("breach")
        || title_lower.contains("compromise")
    {
        mappings.push(("252.204-7012(c)(1)".to_string(), Severity::High));
        mappings.push(("252.204-7012(f)".to_string(), Severity::High));
    }

    mappings
}

/// Map DFARS controls to NIST 800-171 requirements
pub fn map_to_nist_800_171(control_id: &str) -> Vec<String> {
    match control_id {
        "DFARS-AC-001" | "DFARS-3.1.1" => vec!["3.1.1".to_string()],
        "DFARS-AC-002" | "DFARS-3.1.2" => vec!["3.1.2".to_string()],
        "DFARS-AC-003" | "DFARS-3.1.3" => vec!["3.1.3".to_string()],
        "DFARS-AC-004" | "DFARS-3.1.5" => vec!["3.1.5".to_string()],
        "DFARS-AC-005" | "DFARS-3.1.12" => vec!["3.1.12".to_string()],
        "DFARS-AU-001" | "DFARS-3.3.1" => vec!["3.3.1".to_string()],
        "DFARS-AU-002" | "DFARS-3.3.2" => vec!["3.3.2".to_string()],
        "DFARS-AU-003" | "DFARS-3.3.4" => vec!["3.3.4".to_string()],
        "DFARS-AU-004" | "DFARS-3.3.5" => vec!["3.3.5".to_string()],
        "DFARS-CM-001" | "DFARS-3.4.1" => vec!["3.4.1".to_string()],
        "DFARS-CM-002" | "DFARS-3.4.2" => vec!["3.4.2".to_string()],
        "DFARS-CM-003" | "DFARS-3.4.3" => vec!["3.4.3".to_string()],
        "DFARS-CM-004" | "DFARS-3.4.6" => vec!["3.4.6".to_string()],
        "DFARS-IA-001" | "DFARS-3.5.1" => vec!["3.5.1".to_string()],
        "DFARS-IA-002" | "DFARS-3.5.2" => vec!["3.5.2".to_string()],
        "DFARS-IA-003" | "DFARS-3.5.3" => vec!["3.5.3".to_string()],
        "DFARS-IA-004" | "DFARS-3.5.7" => vec!["3.5.7".to_string()],
        "DFARS-SC-001" | "DFARS-3.13.1" => vec!["3.13.1".to_string()],
        "DFARS-SC-002" | "DFARS-3.13.8" => vec!["3.13.8".to_string()],
        "DFARS-SC-003" | "DFARS-3.13.11" => vec!["3.13.11".to_string()],
        "DFARS-SC-004" | "DFARS-3.13.16" => vec!["3.13.16".to_string()],
        "DFARS-SI-001" | "DFARS-3.14.1" => vec!["3.14.1".to_string()],
        "DFARS-SI-002" | "DFARS-3.14.2" => vec!["3.14.2".to_string()],
        "DFARS-SI-003" | "DFARS-3.14.6" => vec!["3.14.6".to_string()],
        "DFARS-SI-004" | "DFARS-3.14.7" => vec!["3.14.7".to_string()],
        "DFARS-MP-002" | "DFARS-3.8.1" => vec!["3.8.1".to_string()],
        "DFARS-MP-003" | "DFARS-3.8.3" => vec!["3.8.3".to_string()],
        _ => vec![],
    }
}

/// Map DFARS controls to CMMC 2.0 practices
pub fn map_to_cmmc(control_id: &str) -> Vec<String> {
    match control_id {
        "DFARS-AC-001" | "DFARS-3.1.1" => vec!["AC.L1-3.1.1".to_string()],
        "DFARS-AC-002" | "DFARS-3.1.2" => vec!["AC.L1-3.1.2".to_string()],
        "DFARS-AC-003" | "DFARS-3.1.3" => vec!["AC.L2-3.1.3".to_string()],
        "DFARS-AC-004" | "DFARS-3.1.5" => vec!["AC.L2-3.1.5".to_string()],
        "DFARS-AC-005" | "DFARS-3.1.12" => vec!["AC.L2-3.1.12".to_string()],
        "DFARS-AU-001" | "DFARS-3.3.1" => vec!["AU.L2-3.3.1".to_string()],
        "DFARS-AU-002" | "DFARS-3.3.2" => vec!["AU.L2-3.3.2".to_string()],
        "DFARS-IA-001" | "DFARS-3.5.1" => vec!["IA.L1-3.5.1".to_string()],
        "DFARS-IA-002" | "DFARS-3.5.2" => vec!["IA.L1-3.5.2".to_string()],
        "DFARS-IA-003" | "DFARS-3.5.3" => vec!["IA.L2-3.5.3".to_string()],
        "DFARS-SC-001" | "DFARS-3.13.1" => vec!["SC.L1-3.13.1".to_string()],
        "DFARS-SC-002" | "DFARS-3.13.8" => vec!["SC.L2-3.13.8".to_string()],
        "DFARS-SI-001" | "DFARS-3.14.1" => vec!["SI.L1-3.14.1".to_string()],
        "DFARS-SI-002" | "DFARS-3.14.2" => vec!["SI.L1-3.14.2".to_string()],
        _ => vec![],
    }
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
            assert!(!control.id.is_empty(), "Control ID should not be empty");
            assert!(!control.control_id.is_empty(), "Control ID should not be empty");
            assert!(!control.title.is_empty(), "Title should not be empty");
            assert!(!control.description.is_empty(), "Description should not be empty");
            assert!(!control.category.is_empty(), "Category should not be empty");
            assert_eq!(control.framework, ComplianceFramework::Dfars);
        }
    }

    #[test]
    fn test_categories() {
        let categories = get_categories();
        assert!(categories.len() >= 10);
        assert!(categories.contains(&"Adequate Security"));
        assert!(categories.contains(&"Cyber Incident Reporting"));
        assert!(categories.contains(&"Access Control"));
        assert!(categories.contains(&"Audit and Accountability"));
    }

    #[test]
    fn test_get_controls_by_category() {
        let access_controls = get_controls_by_category("Access Control");
        assert!(!access_controls.is_empty());
        for control in access_controls {
            assert_eq!(control.category, "Access Control");
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        // Test encryption vulnerability mapping
        let mappings = map_vulnerability("Unencrypted data transmission", None, None, None);
        assert!(!mappings.is_empty());

        // Test authentication vulnerability mapping
        let mappings = map_vulnerability("Weak password policy", None, None, None);
        assert!(!mappings.is_empty());

        // Test patching vulnerability mapping
        let mappings = map_vulnerability("Unpatched system vulnerability", None, None, None);
        assert!(!mappings.is_empty());
    }

    #[test]
    fn test_nist_800_171_mapping() {
        let nist_controls = map_to_nist_800_171("DFARS-AC-001");
        assert!(!nist_controls.is_empty());
        assert!(nist_controls.contains(&"3.1.1".to_string()));
    }

    #[test]
    fn test_cmmc_mapping() {
        let cmmc_practices = map_to_cmmc("DFARS-AC-001");
        assert!(!cmmc_practices.is_empty());
        assert!(cmmc_practices.contains(&"AC.L1-3.1.1".to_string()));
    }

    #[test]
    fn test_incident_reporting_controls() {
        let ir_controls = get_controls_by_category("Cyber Incident Reporting");
        assert!(!ir_controls.is_empty());

        // Verify 72-hour reporting control exists
        let has_72hr_control = ir_controls.iter().any(|c|
            c.control_id.contains("252.204-7012(c)(1)") ||
            c.title.contains("72 hours")
        );
        assert!(has_72hr_control, "Should have 72-hour reporting control");
    }

    #[test]
    fn test_media_preservation_controls() {
        let mp_controls = get_controls_by_category("Media Preservation");
        assert!(!mp_controls.is_empty());

        // Verify 90-day preservation control exists
        let has_90day_control = mp_controls.iter().any(|c|
            c.title.contains("90 days") ||
            c.description.contains("90 days")
        );
        assert!(has_90day_control, "Should have 90-day preservation control");
    }
}
