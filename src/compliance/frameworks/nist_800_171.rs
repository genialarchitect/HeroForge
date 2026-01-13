//! NIST SP 800-171 Rev 3 Controls
//!
//! Protecting Controlled Unclassified Information (CUI) in Nonfederal Systems
//! and Organizations. This framework is required for defense contractors and
//! organizations handling CUI under DFARS 252.204-7012.
//!
//! NIST 800-171 contains 110 security requirements organized into 14 families:
//! - Access Control (3.1)
//! - Awareness and Training (3.2)
//! - Audit and Accountability (3.3)
//! - Configuration Management (3.4)
//! - Identification and Authentication (3.5)
//! - Incident Response (3.6)
//! - Maintenance (3.7)
//! - Media Protection (3.8)
//! - Personnel Security (3.9)
//! - Physical Protection (3.10)
//! - Risk Assessment (3.11)
//! - Security Assessment (3.12)
//! - System and Communications Protection (3.13)
//! - System and Information Integrity (3.14)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NIST 800-171 controls in this module
pub const CONTROL_COUNT: usize = 110;

/// Get all NIST 800-171 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    controls.extend(get_access_control());
    controls.extend(get_awareness_training());
    controls.extend(get_audit_accountability());
    controls.extend(get_configuration_management());
    controls.extend(get_identification_authentication());
    controls.extend(get_incident_response());
    controls.extend(get_maintenance());
    controls.extend(get_media_protection());
    controls.extend(get_personnel_security());
    controls.extend(get_physical_protection());
    controls.extend(get_risk_assessment());
    controls.extend(get_security_assessment());
    controls.extend(get_system_communications_protection());
    controls.extend(get_system_information_integrity());

    controls
}

/// 3.1 Access Control (22 requirements)
fn get_access_control() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.1.1".to_string(),
            control_id: "3.1.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Limit system access to authorized users".to_string(),
            description: "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "NIST-AC-3".to_string(), "CMMC-AC.L1-3.1.1".to_string()],
            remediation_guidance: Some("Implement access control mechanisms to ensure only authorized users, processes, and devices can access the system.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.2".to_string(),
            control_id: "3.1.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Limit system access to authorized transactions and functions".to_string(),
            description: "Limit system access to the types of transactions and functions that authorized users are permitted to execute.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string(), "CMMC-AC.L1-3.1.2".to_string()],
            remediation_guidance: Some("Implement role-based access control to restrict users to only the transactions and functions required for their roles.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.3".to_string(),
            control_id: "3.1.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control CUI flow".to_string(),
            description: "Control the flow of CUI in accordance with approved authorizations.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string(), "CMMC-AC.L2-3.1.3".to_string()],
            remediation_guidance: Some("Implement information flow controls to manage how CUI moves between systems and network segments.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.4".to_string(),
            control_id: "3.1.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Separate duties of individuals".to_string(),
            description: "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-5".to_string(), "CMMC-AC.L2-3.1.4".to_string()],
            remediation_guidance: Some("Implement separation of duties for critical functions to prevent single points of failure or fraud.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.5".to_string(),
            control_id: "3.1.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Employ least privilege".to_string(),
            description: "Employ the principle of least privilege, including for specific security functions and privileged accounts.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CMMC-AC.L2-3.1.5".to_string()],
            remediation_guidance: Some("Configure user accounts and processes with minimum necessary privileges to perform their functions.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.6".to_string(),
            control_id: "3.1.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Use non-privileged accounts for non-security functions".to_string(),
            description: "Use non-privileged accounts or roles when accessing nonsecurity functions.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CMMC-AC.L2-3.1.6".to_string()],
            remediation_guidance: Some("Require administrators to use separate non-privileged accounts for non-administrative tasks.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.7".to_string(),
            control_id: "3.1.7".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Prevent non-privileged users from executing privileged functions".to_string(),
            description: "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CMMC-AC.L2-3.1.7".to_string()],
            remediation_guidance: Some("Implement controls to prevent privilege escalation and audit all privileged function executions.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.8".to_string(),
            control_id: "3.1.8".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Limit unsuccessful logon attempts".to_string(),
            description: "Limit unsuccessful logon attempts.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-7".to_string(), "CMMC-AC.L2-3.1.8".to_string()],
            remediation_guidance: Some("Configure account lockout policies to lock accounts after 3-5 failed login attempts.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.9".to_string(),
            control_id: "3.1.9".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Provide privacy and security notices".to_string(),
            description: "Provide privacy and security notices consistent with applicable CUI rules.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-8".to_string(), "CMMC-AC.L2-3.1.9".to_string()],
            remediation_guidance: Some("Display login banners with privacy and security notices before granting access.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.10".to_string(),
            control_id: "3.1.10".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Use session lock with pattern-hiding displays".to_string(),
            description: "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-11".to_string(), "CMMC-AC.L2-3.1.10".to_string()],
            remediation_guidance: Some("Configure screen lock to activate after 15 minutes of inactivity with pattern-hiding display.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.11".to_string(),
            control_id: "3.1.11".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Terminate user sessions automatically".to_string(),
            description: "Terminate (automatically) a user session after a defined condition.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-12".to_string(), "CMMC-AC.L2-3.1.11".to_string()],
            remediation_guidance: Some("Configure automatic session termination after defined period of inactivity or other conditions.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.12".to_string(),
            control_id: "3.1.12".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Monitor and control remote access sessions".to_string(),
            description: "Monitor and control remote access sessions.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "CMMC-AC.L2-3.1.12".to_string()],
            remediation_guidance: Some("Implement monitoring and logging for all remote access sessions including VPN and remote desktop.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.13".to_string(),
            control_id: "3.1.13".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Employ cryptographic mechanisms for remote access".to_string(),
            description: "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "CMMC-AC.L2-3.1.13".to_string()],
            remediation_guidance: Some("Require encrypted VPN connections for all remote access using TLS 1.2+ or IPsec.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.14".to_string(),
            control_id: "3.1.14".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Route remote access via managed access control points".to_string(),
            description: "Route remote access via managed access control points.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "CMMC-AC.L2-3.1.14".to_string()],
            remediation_guidance: Some("Configure all remote access to route through centralized VPN concentrators or access points.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.15".to_string(),
            control_id: "3.1.15".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Authorize remote execution of privileged commands".to_string(),
            description: "Authorize remote execution of privileged commands and remote access to security-relevant information.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "CMMC-AC.L2-3.1.15".to_string()],
            remediation_guidance: Some("Implement authorization controls for remote privileged command execution with logging.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.16".to_string(),
            control_id: "3.1.16".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Authorize wireless access".to_string(),
            description: "Authorize wireless access prior to allowing such connections.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-18".to_string(), "CMMC-AC.L2-3.1.16".to_string()],
            remediation_guidance: Some("Implement wireless access authorization using 802.1X and WPA3-Enterprise.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.17".to_string(),
            control_id: "3.1.17".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect wireless access using authentication and encryption".to_string(),
            description: "Protect wireless access using authentication and encryption.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-18".to_string(), "CMMC-AC.L2-3.1.17".to_string()],
            remediation_guidance: Some("Configure wireless networks with WPA3-Enterprise or WPA2-Enterprise with strong encryption.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.18".to_string(),
            control_id: "3.1.18".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control connection of mobile devices".to_string(),
            description: "Control connection of mobile devices.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-19".to_string(), "CMMC-AC.L2-3.1.18".to_string()],
            remediation_guidance: Some("Implement MDM solution to control and manage mobile device connections.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.19".to_string(),
            control_id: "3.1.19".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Encrypt CUI on mobile devices".to_string(),
            description: "Encrypt CUI on mobile devices and mobile computing platforms.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-19".to_string(), "CMMC-AC.L2-3.1.19".to_string()],
            remediation_guidance: Some("Require full-device encryption on all mobile devices that may contain CUI.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.20".to_string(),
            control_id: "3.1.20".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Verify and control connections to external systems".to_string(),
            description: "Verify and control/limit connections to and use of external systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-20".to_string(), "CMMC-AC.L2-3.1.20".to_string()],
            remediation_guidance: Some("Implement controls to manage and monitor connections to external systems.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.21".to_string(),
            control_id: "3.1.21".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Limit use of portable storage devices".to_string(),
            description: "Limit use of portable storage devices on external systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-20".to_string(), "CMMC-AC.L2-3.1.21".to_string()],
            remediation_guidance: Some("Restrict USB and portable storage device usage through policy and technical controls.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.1.22".to_string(),
            control_id: "3.1.22".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control CUI posted or processed on publicly accessible systems".to_string(),
            description: "Control CUI posted or processed on publicly accessible systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-22".to_string(), "CMMC-AC.L2-3.1.22".to_string()],
            remediation_guidance: Some("Implement review and approval processes before posting any CUI to public systems.".to_string()),
        },
    ]
}

/// 3.2 Awareness and Training (3 requirements)
fn get_awareness_training() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.2.1".to_string(),
            control_id: "3.2.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Ensure personnel are aware of security risks".to_string(),
            description: "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "CMMC-AT.L1-3.2.1".to_string()],
            remediation_guidance: Some("Conduct regular security awareness training for all personnel.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.2.2".to_string(),
            control_id: "3.2.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Ensure personnel are trained to carry out security responsibilities".to_string(),
            description: "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-3".to_string(), "CMMC-AT.L1-3.2.2".to_string()],
            remediation_guidance: Some("Provide role-based security training for personnel with security responsibilities.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.2.3".to_string(),
            control_id: "3.2.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Provide security awareness training on recognizing social engineering".to_string(),
            description: "Provide security awareness training on recognizing and reporting potential indicators of insider threat.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "CMMC-AT.L2-3.2.3".to_string()],
            remediation_guidance: Some("Include insider threat and social engineering recognition in security awareness training.".to_string()),
        },
    ]
}

/// 3.3 Audit and Accountability (9 requirements)
fn get_audit_accountability() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.3.1".to_string(),
            control_id: "3.3.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Create and retain system audit logs and records".to_string(),
            description: "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "NIST-AU-3".to_string(), "CMMC-AU.L2-3.3.1".to_string()],
            remediation_guidance: Some("Enable comprehensive audit logging and retain logs for at least 1 year.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.2".to_string(),
            control_id: "3.3.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Ensure actions can be traced to individual users".to_string(),
            description: "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "CMMC-AU.L2-3.3.2".to_string()],
            remediation_guidance: Some("Configure audit logs to capture user identity for all actions.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.3".to_string(),
            control_id: "3.3.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Review and update logged events".to_string(),
            description: "Review and update logged events.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "CMMC-AU.L2-3.3.3".to_string()],
            remediation_guidance: Some("Periodically review and update the list of events being audited.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.4".to_string(),
            control_id: "3.3.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Alert on audit logging process failures".to_string(),
            description: "Alert in the event of an audit logging process failure.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-5".to_string(), "CMMC-AU.L2-3.3.4".to_string()],
            remediation_guidance: Some("Configure alerts for audit log failures and storage capacity issues.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.5".to_string(),
            control_id: "3.3.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Correlate audit record review, analysis, and reporting".to_string(),
            description: "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string(), "CMMC-AU.L2-3.3.5".to_string()],
            remediation_guidance: Some("Deploy SIEM solution for log correlation and analysis.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.6".to_string(),
            control_id: "3.3.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Provide audit record reduction and report generation".to_string(),
            description: "Provide audit record reduction and report generation to support on-demand analysis and reporting.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-7".to_string(), "CMMC-AU.L2-3.3.6".to_string()],
            remediation_guidance: Some("Implement log management tools for filtering, analysis, and reporting.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.7".to_string(),
            control_id: "3.3.7".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Provide system capability for time correlation".to_string(),
            description: "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-8".to_string(), "CMMC-AU.L2-3.3.7".to_string()],
            remediation_guidance: Some("Configure NTP synchronization with authoritative time sources.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.8".to_string(),
            control_id: "3.3.8".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect audit information and audit logging tools".to_string(),
            description: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string(), "CMMC-AU.L2-3.3.8".to_string()],
            remediation_guidance: Some("Restrict access to audit logs and tools to authorized personnel only.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.3.9".to_string(),
            control_id: "3.3.9".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Limit management of audit logging functionality".to_string(),
            description: "Limit management of audit logging functionality to a subset of privileged users.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string(), "CMMC-AU.L2-3.3.9".to_string()],
            remediation_guidance: Some("Restrict audit configuration changes to designated security administrators.".to_string()),
        },
    ]
}

/// 3.4 Configuration Management (9 requirements)
fn get_configuration_management() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.4.1".to_string(),
            control_id: "3.4.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Establish and maintain baseline configurations".to_string(),
            description: "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string(), "CMMC-CM.L2-3.4.1".to_string()],
            remediation_guidance: Some("Document and maintain baseline configurations for all system types.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.2".to_string(),
            control_id: "3.4.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Establish and enforce security configuration settings".to_string(),
            description: "Establish and enforce security configuration settings for information technology products employed in organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string(), "CMMC-CM.L2-3.4.2".to_string()],
            remediation_guidance: Some("Apply and enforce security configuration baselines such as CIS Benchmarks.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.3".to_string(),
            control_id: "3.4.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Track, review, approve, and audit changes".to_string(),
            description: "Track, review, approve, and log changes to organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "CMMC-CM.L2-3.4.3".to_string()],
            remediation_guidance: Some("Implement change management process with approval workflows.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.4".to_string(),
            control_id: "3.4.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Analyze security impact of changes".to_string(),
            description: "Analyze the security impact of changes prior to implementation.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-4".to_string(), "CMMC-CM.L2-3.4.4".to_string()],
            remediation_guidance: Some("Require security impact analysis for all system changes.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.5".to_string(),
            control_id: "3.4.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Define and document physical and logical access restrictions".to_string(),
            description: "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-5".to_string(), "CMMC-CM.L2-3.4.5".to_string()],
            remediation_guidance: Some("Document access restrictions for system changes and enforce through technical controls.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.6".to_string(),
            control_id: "3.4.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Employ least functionality".to_string(),
            description: "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CMMC-CM.L2-3.4.6".to_string()],
            remediation_guidance: Some("Disable unnecessary services, ports, and protocols on all systems.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.7".to_string(),
            control_id: "3.4.7".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Restrict, disable, or prevent nonessential programs".to_string(),
            description: "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CMMC-CM.L2-3.4.7".to_string()],
            remediation_guidance: Some("Implement application whitelisting and disable unnecessary network services.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.8".to_string(),
            control_id: "3.4.8".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Apply deny-by-exception policy for software execution".to_string(),
            description: "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CMMC-CM.L2-3.4.8".to_string()],
            remediation_guidance: Some("Implement application control using whitelisting or blacklisting.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.4.9".to_string(),
            control_id: "3.4.9".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control and monitor user-installed software".to_string(),
            description: "Control and monitor user-installed software.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-11".to_string(), "CMMC-CM.L2-3.4.9".to_string()],
            remediation_guidance: Some("Restrict user software installation rights and monitor for unauthorized software.".to_string()),
        },
    ]
}

/// 3.5 Identification and Authentication (11 requirements)
fn get_identification_authentication() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.5.1".to_string(),
            control_id: "3.5.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Identify system users, processes, and devices".to_string(),
            description: "Identify system users, processes acting on behalf of users, and devices.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "NIST-IA-3".to_string(), "CMMC-IA.L1-3.5.1".to_string()],
            remediation_guidance: Some("Implement unique identification for all users, processes, and devices.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.2".to_string(),
            control_id: "3.5.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Authenticate users, processes, and devices".to_string(),
            description: "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "NIST-IA-3".to_string(), "CMMC-IA.L1-3.5.2".to_string()],
            remediation_guidance: Some("Require authentication before granting system access.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.3".to_string(),
            control_id: "3.5.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Use multifactor authentication for local and network access".to_string(),
            description: "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "CMMC-IA.L2-3.5.3".to_string()],
            remediation_guidance: Some("Implement MFA for all privileged access and network access to non-privileged accounts.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.4".to_string(),
            control_id: "3.5.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Employ replay-resistant authentication mechanisms".to_string(),
            description: "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "CMMC-IA.L2-3.5.4".to_string()],
            remediation_guidance: Some("Use authentication protocols resistant to replay attacks such as TOTP, FIDO2, or Kerberos.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.5".to_string(),
            control_id: "3.5.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Prevent reuse of identifiers".to_string(),
            description: "Prevent reuse of identifiers for a defined period.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-4".to_string(), "CMMC-IA.L2-3.5.5".to_string()],
            remediation_guidance: Some("Prevent identifier reuse and disable inactive accounts after defined period.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.6".to_string(),
            control_id: "3.5.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Disable identifiers after period of inactivity".to_string(),
            description: "Disable identifiers after a defined period of inactivity.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-4".to_string(), "CMMC-IA.L2-3.5.6".to_string()],
            remediation_guidance: Some("Configure automatic account disabling after 90 days of inactivity.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.7".to_string(),
            control_id: "3.5.7".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Enforce minimum password complexity".to_string(),
            description: "Enforce a minimum password complexity and change of characters when new passwords are created.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "CMMC-IA.L2-3.5.7".to_string()],
            remediation_guidance: Some("Enforce password complexity: minimum 12 characters with mixed case, numbers, and symbols.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.8".to_string(),
            control_id: "3.5.8".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Prohibit password reuse".to_string(),
            description: "Prohibit password reuse for a specified number of generations.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "CMMC-IA.L2-3.5.8".to_string()],
            remediation_guidance: Some("Configure password history to prevent reuse of last 24 passwords.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.9".to_string(),
            control_id: "3.5.9".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Allow temporary password use for system logons".to_string(),
            description: "Allow temporary password use for system logons with an immediate change to a permanent password.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "CMMC-IA.L2-3.5.9".to_string()],
            remediation_guidance: Some("Require password change on first login for temporary passwords.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.10".to_string(),
            control_id: "3.5.10".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Store and transmit only cryptographically-protected passwords".to_string(),
            description: "Store and transmit only cryptographically-protected passwords.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "CMMC-IA.L2-3.5.10".to_string()],
            remediation_guidance: Some("Use bcrypt, Argon2, or PBKDF2 for password storage and TLS for transmission.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.5.11".to_string(),
            control_id: "3.5.11".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Obscure feedback of authentication information".to_string(),
            description: "Obscure feedback of authentication information.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-6".to_string(), "CMMC-IA.L2-3.5.11".to_string()],
            remediation_guidance: Some("Mask password input and provide generic error messages for failed authentication.".to_string()),
        },
    ]
}

/// 3.6 Incident Response (3 requirements)
fn get_incident_response() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.6.1".to_string(),
            control_id: "3.6.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Establish incident handling capability".to_string(),
            description: "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-2".to_string(), "NIST-IR-4".to_string(), "CMMC-IR.L2-3.6.1".to_string()],
            remediation_guidance: Some("Develop and maintain an incident response plan with defined roles and procedures.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.6.2".to_string(),
            control_id: "3.6.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Track, document, and report incidents".to_string(),
            description: "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string(), "CMMC-IR.L2-3.6.2".to_string()],
            remediation_guidance: Some("Implement incident tracking system and define reporting procedures for CUI incidents.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.6.3".to_string(),
            control_id: "3.6.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Test incident response capability".to_string(),
            description: "Test the organizational incident response capability.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-3".to_string(), "CMMC-IR.L2-3.6.3".to_string()],
            remediation_guidance: Some("Conduct annual incident response exercises and tabletop drills.".to_string()),
        },
    ]
}

/// 3.7 Maintenance (6 requirements)
fn get_maintenance() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.7.1".to_string(),
            control_id: "3.7.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Perform maintenance on organizational systems".to_string(),
            description: "Perform maintenance on organizational systems.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MA-2".to_string(), "CMMC-MA.L2-3.7.1".to_string()],
            remediation_guidance: Some("Establish and follow maintenance schedules for all systems.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.7.2".to_string(),
            control_id: "3.7.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Provide controls for maintenance tools".to_string(),
            description: "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MA-3".to_string(), "CMMC-MA.L2-3.7.2".to_string()],
            remediation_guidance: Some("Maintain inventory of approved maintenance tools and inspect before use.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.7.3".to_string(),
            control_id: "3.7.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Sanitize equipment removed for off-site maintenance".to_string(),
            description: "Ensure equipment removed for off-site maintenance is sanitized of any CUI.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MA-2".to_string(), "CMMC-MA.L2-3.7.3".to_string()],
            remediation_guidance: Some("Sanitize or encrypt all CUI before equipment leaves the premises.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.7.4".to_string(),
            control_id: "3.7.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Check media containing diagnostic programs".to_string(),
            description: "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MA-3".to_string(), "CMMC-MA.L2-3.7.4".to_string()],
            remediation_guidance: Some("Scan all maintenance media for malware before use on production systems.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.7.5".to_string(),
            control_id: "3.7.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Require multifactor authentication for nonlocal maintenance".to_string(),
            description: "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MA-4".to_string(), "CMMC-MA.L2-3.7.5".to_string()],
            remediation_guidance: Some("Require MFA for all remote maintenance sessions and enforce session termination.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.7.6".to_string(),
            control_id: "3.7.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Supervise maintenance personnel".to_string(),
            description: "Supervise the maintenance activities of maintenance personnel without required access authorization.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MA-5".to_string(), "CMMC-MA.L2-3.7.6".to_string()],
            remediation_guidance: Some("Escort and supervise maintenance personnel who lack required clearances.".to_string()),
        },
    ]
}

/// 3.8 Media Protection (9 requirements)
fn get_media_protection() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.8.1".to_string(),
            control_id: "3.8.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect system media containing CUI".to_string(),
            description: "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-2".to_string(), "NIST-MP-4".to_string(), "CMMC-MP.L1-3.8.1".to_string()],
            remediation_guidance: Some("Store CUI media in locked containers and control physical access.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.2".to_string(),
            control_id: "3.8.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Limit access to CUI on system media".to_string(),
            description: "Limit access to CUI on system media to authorized users.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MP-2".to_string(), "CMMC-MP.L1-3.8.2".to_string()],
            remediation_guidance: Some("Implement access controls on all media containing CUI.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.3".to_string(),
            control_id: "3.8.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Sanitize or destroy CUI media before disposal".to_string(),
            description: "Sanitize or destroy system media containing CUI before disposal or release for reuse.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string(), "CMMC-MP.L1-3.8.3".to_string()],
            remediation_guidance: Some("Use NIST SP 800-88 approved sanitization methods for CUI media.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.4".to_string(),
            control_id: "3.8.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Mark media with CUI markings".to_string(),
            description: "Mark media with necessary CUI markings and distribution limitations.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-3".to_string(), "CMMC-MP.L2-3.8.4".to_string()],
            remediation_guidance: Some("Apply appropriate CUI markings to all media containing controlled information.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.5".to_string(),
            control_id: "3.8.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control access to CUI media".to_string(),
            description: "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-5".to_string(), "CMMC-MP.L2-3.8.5".to_string()],
            remediation_guidance: Some("Use chain of custody procedures for CUI media transport.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.6".to_string(),
            control_id: "3.8.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Implement cryptographic mechanisms for CUI on portable media".to_string(),
            description: "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MP-5".to_string(), "CMMC-MP.L2-3.8.6".to_string()],
            remediation_guidance: Some("Encrypt all portable media containing CUI using AES-256 or equivalent.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.7".to_string(),
            control_id: "3.8.7".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control removable media use".to_string(),
            description: "Control the use of removable media on system components.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MP-7".to_string(), "CMMC-MP.L2-3.8.7".to_string()],
            remediation_guidance: Some("Implement policies and technical controls for removable media usage.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.8".to_string(),
            control_id: "3.8.8".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Prohibit portable storage without identifiable owner".to_string(),
            description: "Prohibit the use of portable storage devices when such devices have no identifiable owner.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MP-7".to_string(), "CMMC-MP.L2-3.8.8".to_string()],
            remediation_guidance: Some("Block unknown USB devices and require device registration.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.8.9".to_string(),
            control_id: "3.8.9".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect CUI backups at storage locations".to_string(),
            description: "Protect the confidentiality of backup CUI at storage locations.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-9".to_string(), "CMMC-MP.L2-3.8.9".to_string()],
            remediation_guidance: Some("Encrypt backups containing CUI and secure backup storage locations.".to_string()),
        },
    ]
}

/// 3.9 Personnel Security (2 requirements)
fn get_personnel_security() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.9.1".to_string(),
            control_id: "3.9.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Screen individuals prior to authorizing access".to_string(),
            description: "Screen individuals prior to authorizing access to organizational systems containing CUI.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-3".to_string(), "CMMC-PS.L2-3.9.1".to_string()],
            remediation_guidance: Some("Conduct background checks on personnel before granting CUI access.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.9.2".to_string(),
            control_id: "3.9.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect CUI during personnel actions".to_string(),
            description: "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-4".to_string(), "NIST-PS-5".to_string(), "CMMC-PS.L2-3.9.2".to_string()],
            remediation_guidance: Some("Implement offboarding procedures to revoke access promptly upon termination.".to_string()),
        },
    ]
}

/// 3.10 Physical Protection (6 requirements)
fn get_physical_protection() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.10.1".to_string(),
            control_id: "3.10.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Limit physical access to authorized individuals".to_string(),
            description: "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-2".to_string(), "NIST-PE-3".to_string(), "CMMC-PE.L1-3.10.1".to_string()],
            remediation_guidance: Some("Implement physical access controls such as badge readers and mantraps.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.10.2".to_string(),
            control_id: "3.10.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect and monitor the physical facility".to_string(),
            description: "Protect and monitor the physical facility and support infrastructure for organizational systems.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-2".to_string(), "NIST-PE-6".to_string(), "CMMC-PE.L1-3.10.2".to_string()],
            remediation_guidance: Some("Install surveillance systems and monitor physical access points.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.10.3".to_string(),
            control_id: "3.10.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Escort visitors and monitor visitor activity".to_string(),
            description: "Escort visitors and monitor visitor activity.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string(), "CMMC-PE.L2-3.10.3".to_string()],
            remediation_guidance: Some("Require visitor escorts and maintain visitor logs.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.10.4".to_string(),
            control_id: "3.10.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Maintain audit logs of physical access".to_string(),
            description: "Maintain audit logs of physical access.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string(), "CMMC-PE.L2-3.10.4".to_string()],
            remediation_guidance: Some("Retain physical access logs for at least 1 year.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.10.5".to_string(),
            control_id: "3.10.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control and manage physical access devices".to_string(),
            description: "Control and manage physical access devices.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string(), "CMMC-PE.L2-3.10.5".to_string()],
            remediation_guidance: Some("Maintain inventory of keys, badges, and access cards with deactivation procedures.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.10.6".to_string(),
            control_id: "3.10.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Enforce safeguarding measures for CUI at alternate work sites".to_string(),
            description: "Enforce safeguarding measures for CUI at alternate work sites.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-17".to_string(), "CMMC-PE.L2-3.10.6".to_string()],
            remediation_guidance: Some("Establish telework security policies and controls for remote CUI handling.".to_string()),
        },
    ]
}

/// 3.11 Risk Assessment (3 requirements)
fn get_risk_assessment() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.11.1".to_string(),
            control_id: "3.11.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Periodically assess risk".to_string(),
            description: "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string(), "CMMC-RA.L2-3.11.1".to_string()],
            remediation_guidance: Some("Conduct annual risk assessments for systems processing CUI.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.11.2".to_string(),
            control_id: "3.11.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Scan for vulnerabilities periodically".to_string(),
            description: "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string(), "CMMC-RA.L2-3.11.2".to_string()],
            remediation_guidance: Some("Perform vulnerability scans weekly (internal) and quarterly (external).".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.11.3".to_string(),
            control_id: "3.11.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Remediate vulnerabilities".to_string(),
            description: "Remediate vulnerabilities in accordance with risk assessments.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string(), "CMMC-RA.L2-3.11.3".to_string()],
            remediation_guidance: Some("Remediate critical vulnerabilities within 15 days, high within 30 days.".to_string()),
        },
    ]
}

/// 3.12 Security Assessment (4 requirements)
fn get_security_assessment() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.12.1".to_string(),
            control_id: "3.12.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Periodically assess security controls".to_string(),
            description: "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CA-2".to_string(), "CMMC-CA.L2-3.12.1".to_string()],
            remediation_guidance: Some("Conduct annual security control assessments.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.12.2".to_string(),
            control_id: "3.12.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Develop and implement plans of action".to_string(),
            description: "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CA-5".to_string(), "CMMC-CA.L2-3.12.2".to_string()],
            remediation_guidance: Some("Maintain POA&M for tracking remediation of identified deficiencies.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.12.3".to_string(),
            control_id: "3.12.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Monitor security controls continuously".to_string(),
            description: "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CA-7".to_string(), "CMMC-CA.L2-3.12.3".to_string()],
            remediation_guidance: Some("Implement continuous monitoring using SIEM and vulnerability management tools.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.12.4".to_string(),
            control_id: "3.12.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Develop and maintain system security plan".to_string(),
            description: "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-2".to_string(), "CMMC-CA.L2-3.12.4".to_string()],
            remediation_guidance: Some("Develop and maintain System Security Plans for all systems processing CUI.".to_string()),
        },
    ]
}

/// 3.13 System and Communications Protection (16 requirements)
fn get_system_communications_protection() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.13.1".to_string(),
            control_id: "3.13.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Monitor communications at external boundaries".to_string(),
            description: "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CMMC-SC.L1-3.13.1".to_string()],
            remediation_guidance: Some("Deploy firewalls and IDS/IPS at network boundaries.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.2".to_string(),
            control_id: "3.13.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Employ architectural designs with security principles".to_string(),
            description: "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-8".to_string(), "CMMC-SC.L2-3.13.2".to_string()],
            remediation_guidance: Some("Apply security-by-design principles in system architecture.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.3".to_string(),
            control_id: "3.13.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Separate user functionality from system management".to_string(),
            description: "Separate user functionality from system management functionality.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-2".to_string(), "CMMC-SC.L2-3.13.3".to_string()],
            remediation_guidance: Some("Implement separate interfaces for user and administrative functions.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.4".to_string(),
            control_id: "3.13.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Prevent unauthorized and unintended information transfer".to_string(),
            description: "Prevent unauthorized and unintended information transfer via shared system resources.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-4".to_string(), "CMMC-SC.L2-3.13.4".to_string()],
            remediation_guidance: Some("Implement resource isolation and data sanitization between processes.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.5".to_string(),
            control_id: "3.13.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Implement subnetworks for publicly accessible systems".to_string(),
            description: "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CMMC-SC.L1-3.13.5".to_string()],
            remediation_guidance: Some("Deploy DMZ for publicly accessible systems isolated from internal networks.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.6".to_string(),
            control_id: "3.13.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Deny network traffic by default".to_string(),
            description: "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CMMC-SC.L2-3.13.6".to_string()],
            remediation_guidance: Some("Configure firewalls with default-deny rules.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.7".to_string(),
            control_id: "3.13.7".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Prevent remote devices from establishing split tunneling".to_string(),
            description: "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CMMC-SC.L2-3.13.7".to_string()],
            remediation_guidance: Some("Configure VPN clients to disable split tunneling.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.8".to_string(),
            control_id: "3.13.8".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Implement cryptographic mechanisms for CUI transmission".to_string(),
            description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "CMMC-SC.L2-3.13.8".to_string()],
            remediation_guidance: Some("Use TLS 1.2+ for all CUI data transmission.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.9".to_string(),
            control_id: "3.13.9".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Terminate network connections at session end".to_string(),
            description: "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-10".to_string(), "CMMC-SC.L2-3.13.9".to_string()],
            remediation_guidance: Some("Configure session timeout and automatic disconnection after inactivity.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.10".to_string(),
            control_id: "3.13.10".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Establish and manage cryptographic keys".to_string(),
            description: "Establish and manage cryptographic keys for cryptography employed in organizational systems.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string(), "CMMC-SC.L2-3.13.10".to_string()],
            remediation_guidance: Some("Implement key management system with secure generation, distribution, and rotation.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.11".to_string(),
            control_id: "3.13.11".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Employ FIPS-validated cryptography".to_string(),
            description: "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string(), "CMMC-SC.L2-3.13.11".to_string()],
            remediation_guidance: Some("Use FIPS 140-2/3 validated cryptographic modules for CUI protection.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.12".to_string(),
            control_id: "3.13.12".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Prohibit remote activation of collaborative devices".to_string(),
            description: "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-15".to_string(), "CMMC-SC.L2-3.13.12".to_string()],
            remediation_guidance: Some("Disable remote activation of cameras and microphones; provide visual indicators.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.13".to_string(),
            control_id: "3.13.13".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control and monitor mobile code".to_string(),
            description: "Control and monitor the use of mobile code.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-18".to_string(), "CMMC-SC.L2-3.13.13".to_string()],
            remediation_guidance: Some("Implement controls for JavaScript, ActiveX, and other mobile code technologies.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.14".to_string(),
            control_id: "3.13.14".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Control and monitor VoIP".to_string(),
            description: "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-19".to_string(), "CMMC-SC.L2-3.13.14".to_string()],
            remediation_guidance: Some("Implement security controls for VoIP including encryption and access control.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.15".to_string(),
            control_id: "3.13.15".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect authenticity of communications sessions".to_string(),
            description: "Protect the authenticity of communications sessions.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-23".to_string(), "CMMC-SC.L2-3.13.15".to_string()],
            remediation_guidance: Some("Implement session integrity protections against hijacking and replay attacks.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.13.16".to_string(),
            control_id: "3.13.16".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Protect CUI at rest".to_string(),
            description: "Protect the confidentiality of CUI at rest.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "CMMC-SC.L2-3.13.16".to_string()],
            remediation_guidance: Some("Encrypt CUI at rest using AES-256 or FIPS-validated equivalent.".to_string()),
        },
    ]
}

/// 3.14 System and Information Integrity (7 requirements)
fn get_system_information_integrity() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "NIST171-3.14.1".to_string(),
            control_id: "3.14.1".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Identify, report, and correct system flaws".to_string(),
            description: "Identify, report, and correct system flaws in a timely manner.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "CMMC-SI.L1-3.14.1".to_string()],
            remediation_guidance: Some("Implement patch management process with timely remediation of vulnerabilities.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.14.2".to_string(),
            control_id: "3.14.2".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Provide protection from malicious code".to_string(),
            description: "Provide protection from malicious code at designated locations within organizational systems.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "CMMC-SI.L1-3.14.2".to_string()],
            remediation_guidance: Some("Deploy endpoint protection with real-time scanning on all systems.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.14.3".to_string(),
            control_id: "3.14.3".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Monitor system security alerts".to_string(),
            description: "Monitor system security alerts and advisories and take action in response.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-5".to_string(), "CMMC-SI.L2-3.14.3".to_string()],
            remediation_guidance: Some("Subscribe to security advisories and implement monitoring for alerts.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.14.4".to_string(),
            control_id: "3.14.4".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Update malicious code protection mechanisms".to_string(),
            description: "Update malicious code protection mechanisms when new releases are available.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "CMMC-SI.L1-3.14.4".to_string()],
            remediation_guidance: Some("Configure automatic updates for antivirus signatures and endpoint protection.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.14.5".to_string(),
            control_id: "3.14.5".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Perform periodic and real-time scans".to_string(),
            description: "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "CMMC-SI.L1-3.14.5".to_string()],
            remediation_guidance: Some("Enable real-time scanning and schedule weekly full system scans.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.14.6".to_string(),
            control_id: "3.14.6".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Monitor systems for unauthorized use".to_string(),
            description: "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "CMMC-SI.L2-3.14.6".to_string()],
            remediation_guidance: Some("Deploy SIEM and network monitoring for attack detection.".to_string()),
        },
        ComplianceControl {
            id: "NIST171-3.14.7".to_string(),
            control_id: "3.14.7".to_string(),
            framework: ComplianceFramework::Nist800171,
            title: "Identify unauthorized use of systems".to_string(),
            description: "Identify unauthorized use of organizational systems.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "CMMC-SI.L2-3.14.7".to_string()],
            remediation_guidance: Some("Implement user behavior analytics and anomaly detection.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant NIST 800-171 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control vulnerabilities
    if title_lower.contains("unauthorized access") || title_lower.contains("privilege escalation") {
        mappings.push(("3.1.1".to_string(), Severity::Critical));
        mappings.push(("3.1.2".to_string(), Severity::Critical));
        mappings.push(("3.1.5".to_string(), Severity::High));
        mappings.push(("3.1.7".to_string(), Severity::High));
    }

    // Authentication vulnerabilities
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("weak password")
    {
        mappings.push(("3.5.1".to_string(), Severity::Critical));
        mappings.push(("3.5.2".to_string(), Severity::Critical));
        mappings.push(("3.5.7".to_string(), Severity::High));
        mappings.push(("3.5.10".to_string(), Severity::High));
    }

    // MFA missing
    if title_lower.contains("mfa") || title_lower.contains("multi-factor") || title_lower.contains("two-factor") {
        mappings.push(("3.5.3".to_string(), Severity::High));
    }

    // Default credentials
    if title_lower.contains("default password") || title_lower.contains("default credentials") {
        mappings.push(("3.5.7".to_string(), Severity::Critical));
        mappings.push(("3.4.2".to_string(), Severity::High));
    }

    // Account lockout
    if title_lower.contains("brute force") || title_lower.contains("lockout") {
        mappings.push(("3.1.8".to_string(), Severity::High));
    }

    // Encryption vulnerabilities
    if title_lower.contains("unencrypted")
        || title_lower.contains("weak encryption")
        || title_lower.contains("ssl") && title_lower.contains("vulnerable")
        || title_lower.contains("tls") && title_lower.contains("weak")
    {
        mappings.push(("3.13.8".to_string(), Severity::High));
        mappings.push(("3.13.11".to_string(), Severity::High));
        mappings.push(("3.13.16".to_string(), Severity::High));
    }

    // Patching vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
    {
        mappings.push(("3.14.1".to_string(), Severity::High));
        mappings.push(("3.11.2".to_string(), Severity::High));
        mappings.push(("3.11.3".to_string(), Severity::High));
    }

    // Injection vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("xss")
    {
        mappings.push(("3.13.2".to_string(), Severity::Critical));
        mappings.push(("3.14.1".to_string(), Severity::Critical));
    }

    // Malware/antivirus issues
    if title_lower.contains("no antivirus") || title_lower.contains("malware") {
        mappings.push(("3.14.2".to_string(), Severity::High));
        mappings.push(("3.14.4".to_string(), Severity::High));
        mappings.push(("3.14.5".to_string(), Severity::High));
    }

    // Logging/monitoring issues
    if title_lower.contains("no logging") || title_lower.contains("audit disabled") {
        mappings.push(("3.3.1".to_string(), Severity::Medium));
        mappings.push(("3.3.2".to_string(), Severity::Medium));
        mappings.push(("3.14.6".to_string(), Severity::Medium));
    }

    // Firewall/boundary issues
    if title_lower.contains("firewall") || title_lower.contains("open port") {
        mappings.push(("3.13.1".to_string(), Severity::Medium));
        mappings.push(("3.13.5".to_string(), Severity::Medium));
        mappings.push(("3.13.6".to_string(), Severity::Medium));
    }

    // Remote access issues
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
            mappings.push(("3.1.12".to_string(), Severity::High));
            mappings.push(("3.1.13".to_string(), Severity::High));
            mappings.push(("3.1.14".to_string(), Severity::High));
        }
    }

    // Wireless security
    if title_lower.contains("wireless") || title_lower.contains("wifi") || title_lower.contains("wpa") {
        mappings.push(("3.1.16".to_string(), Severity::High));
        mappings.push(("3.1.17".to_string(), Severity::High));
    }

    // Mobile device issues
    if title_lower.contains("mobile") || title_lower.contains("byod") {
        mappings.push(("3.1.18".to_string(), Severity::Medium));
        mappings.push(("3.1.19".to_string(), Severity::High));
    }

    // USB/removable media
    if title_lower.contains("usb") || title_lower.contains("removable media") {
        mappings.push(("3.1.21".to_string(), Severity::Medium));
        mappings.push(("3.8.7".to_string(), Severity::Medium));
    }

    // Configuration issues
    if title_lower.contains("misconfiguration") || title_lower.contains("insecure configuration") {
        mappings.push(("3.4.1".to_string(), Severity::Medium));
        mappings.push(("3.4.2".to_string(), Severity::High));
        mappings.push(("3.4.6".to_string(), Severity::Medium));
    }

    // Session management
    if title_lower.contains("session") && (title_lower.contains("hijack") || title_lower.contains("fixation")) {
        mappings.push(("3.13.15".to_string(), Severity::High));
    }

    // CUI exposure
    if title_lower.contains("cui") || title_lower.contains("controlled unclassified") {
        mappings.push(("3.1.3".to_string(), Severity::Critical));
        mappings.push(("3.8.1".to_string(), Severity::High));
    }

    mappings
}

/// Get all NIST 800-171 families
pub fn get_families() -> Vec<&'static str> {
    vec![
        "Access Control",
        "Awareness and Training",
        "Audit and Accountability",
        "Configuration Management",
        "Identification and Authentication",
        "Incident Response",
        "Maintenance",
        "Media Protection",
        "Personnel Security",
        "Physical Protection",
        "Risk Assessment",
        "Security Assessment",
        "System and Communications Protection",
        "System and Information Integrity",
    ]
}

/// Get controls by family
pub fn get_controls_by_family(family: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(family))
        .collect()
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
            assert!(control.framework == ComplianceFramework::Nist800171);
        }
    }

    #[test]
    fn test_families() {
        let families = get_families();
        assert_eq!(families.len(), 14);
        assert!(families.contains(&"Access Control"));
        assert!(families.contains(&"System and Information Integrity"));
    }

    #[test]
    fn test_cross_references_exist() {
        for control in get_controls() {
            // All controls should have cross-references to NIST 800-53 or CMMC
            assert!(
                !control.cross_references.is_empty(),
                "Control {} missing cross-references",
                control.control_id
            );
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Weak Password Policy", None, None, None);
        assert!(!mappings.is_empty());

        let mappings = map_vulnerability("SQL Injection", None, None, None);
        assert!(!mappings.is_empty());

        let mappings = map_vulnerability("Unpatched System", None, None, None);
        assert!(!mappings.is_empty());
    }

    #[test]
    fn test_control_ids_format() {
        for control in get_controls() {
            // Control IDs should be in format 3.X.Y
            assert!(
                control.control_id.starts_with("3."),
                "Control ID {} should start with 3.",
                control.control_id
            );
        }
    }
}
