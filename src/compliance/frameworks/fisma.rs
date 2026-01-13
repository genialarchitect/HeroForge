//! FISMA - Federal Information Security Modernization Act
//!
//! FISMA requires federal agencies to develop, document, and implement programs
//! providing security for information and information systems. FISMA maps directly
//! to NIST 800-53 controls as the technical implementation framework.
//!
//! This module organizes FISMA controls by the main NIST 800-53 control families:
//! - Access Control (AC)
//! - Audit and Accountability (AU)
//! - Configuration Management (CM)
//! - Contingency Planning (CP)
//! - Identification and Authentication (IA)
//! - Incident Response (IR)
//! - System and Communications Protection (SC)
//! - System and Information Integrity (SI)
//!
//! FISMA Impact Levels:
//! - Low Impact: Systems with limited adverse effect
//! - Moderate Impact: Systems with serious adverse effect
//! - High Impact: Systems with severe or catastrophic adverse effect
//!
//! Reference: NIST SP 800-53 Rev 5, FIPS 199, FIPS 200

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of FISMA controls in this module
pub const CONTROL_COUNT: usize = 50;

/// FISMA impact level for system categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FismaImpactLevel {
    /// Low impact - limited adverse effect
    Low,
    /// Moderate impact - serious adverse effect
    Moderate,
    /// High impact - severe or catastrophic adverse effect
    High,
}

impl FismaImpactLevel {
    pub fn to_priority(self) -> ControlPriority {
        match self {
            FismaImpactLevel::High => ControlPriority::Critical,
            FismaImpactLevel::Moderate => ControlPriority::High,
            FismaImpactLevel::Low => ControlPriority::Medium,
        }
    }
}

/// Get all FISMA controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // Add controls by family
    controls.extend(get_access_control_family());
    controls.extend(get_audit_accountability_family());
    controls.extend(get_configuration_management_family());
    controls.extend(get_contingency_planning_family());
    controls.extend(get_identification_authentication_family());
    controls.extend(get_incident_response_family());
    controls.extend(get_system_protection_family());
    controls.extend(get_system_integrity_family());

    controls
}

/// Access Control (AC) Family - Controls for managing access to systems and data
fn get_access_control_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-AC-1".to_string(),
            control_id: "AC-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Access Control Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate access control policy that addresses purpose, scope, roles, and responsibilities.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-1".to_string(), "CIS-6.1".to_string()],
            remediation_guidance: Some("Establish and maintain an access control policy reviewed at least annually.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AC-2".to_string(),
            control_id: "AC-2".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Account Management".to_string(),
            description: "Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "CIS-5.1".to_string(), "CIS-5.3".to_string()],
            remediation_guidance: Some("Implement automated account management with periodic reviews. Disable inactive accounts after 90 days.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AC-3".to_string(),
            control_id: "AC-3".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Access Enforcement".to_string(),
            description: "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string(), "CIS-3.3".to_string()],
            remediation_guidance: Some("Implement role-based access control (RBAC) with least privilege enforcement.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AC-4".to_string(),
            control_id: "AC-4".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Information Flow Enforcement".to_string(),
            description: "Enforce approved authorizations for controlling the flow of information within the system and between interconnected systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string(), "CIS-12.1".to_string()],
            remediation_guidance: Some("Implement network segmentation and data flow controls between security domains.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AC-6".to_string(),
            control_id: "AC-6".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Least Privilege".to_string(),
            description: "Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned organizational tasks.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CIS-5.4".to_string()],
            remediation_guidance: Some("Restrict privileged accounts to specific personnel. Implement just-in-time access for administrative functions.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AC-7".to_string(),
            control_id: "AC-7".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Unsuccessful Logon Attempts".to_string(),
            description: "Enforce a limit of consecutive invalid logon attempts by a user during a specified time period and automatically lock the account when exceeded.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-7".to_string(), "CIS-5.5".to_string()],
            remediation_guidance: Some("Configure account lockout after 3 consecutive failed attempts. Implement progressive delay mechanisms.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AC-17".to_string(),
            control_id: "AC-17".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Remote Access".to_string(),
            description: "Establish and document usage restrictions, configuration requirements, and implementation guidance for each type of remote access allowed.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "CIS-6.4".to_string()],
            remediation_guidance: Some("Require VPN with multi-factor authentication for all remote access. Monitor and log all remote sessions.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AC-18".to_string(),
            control_id: "AC-18".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Wireless Access".to_string(),
            description: "Establish usage restrictions, configuration requirements, and implementation guidance for wireless access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-18".to_string(), "CIS-15.1".to_string()],
            remediation_guidance: Some("Implement WPA3 Enterprise with 802.1X authentication. Disable SSID broadcast for sensitive networks.".to_string()),
        },
    ]
}

/// Audit and Accountability (AU) Family - Controls for event logging and monitoring
fn get_audit_accountability_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-AU-1".to_string(),
            control_id: "AU-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Audit and Accountability Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate audit and accountability policy and procedures.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AU-1".to_string(), "CIS-8.1".to_string()],
            remediation_guidance: Some("Document audit policies defining what events to log, retention periods, and review procedures.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AU-2".to_string(),
            control_id: "AU-2".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Event Logging".to_string(),
            description: "Identify the types of events that the system is capable of logging in support of the audit function.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "CIS-8.2".to_string()],
            remediation_guidance: Some("Log authentication events, privilege changes, system modifications, and data access. Configure comprehensive event logging.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AU-3".to_string(),
            control_id: "AU-3".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Content of Audit Records".to_string(),
            description: "Ensure that audit records contain information that establishes what type of event occurred, when, where, the source, the outcome, and identity of individuals or subjects.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-3".to_string(), "CIS-8.5".to_string()],
            remediation_guidance: Some("Configure audit records to include timestamp, event type, user ID, source IP, action taken, and success/failure status.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AU-6".to_string(),
            control_id: "AU-6".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Audit Record Review, Analysis, and Reporting".to_string(),
            description: "Review and analyze system audit records for indications of inappropriate or unusual activity.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string(), "CIS-8.11".to_string()],
            remediation_guidance: Some("Implement SIEM for automated log analysis and correlation. Review audit logs at least weekly.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AU-9".to_string(),
            control_id: "AU-9".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Protection of Audit Information".to_string(),
            description: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string(), "CIS-8.3".to_string()],
            remediation_guidance: Some("Implement write-once logging, restrict access to audit logs, and store logs on separate systems.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AU-11".to_string(),
            control_id: "AU-11".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Audit Record Retention".to_string(),
            description: "Retain audit records for a defined period to provide support for after-the-fact investigations and to meet regulatory requirements.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-11".to_string(), "CIS-8.10".to_string()],
            remediation_guidance: Some("Retain audit logs for minimum 1 year online, 3 years archived. Implement automated retention management.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-AU-12".to_string(),
            control_id: "AU-12".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Audit Record Generation".to_string(),
            description: "Provide audit record generation capability for the event types the system is capable of auditing.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-12".to_string(), "CIS-8.2".to_string()],
            remediation_guidance: Some("Enable audit logging on all systems and applications. Configure centralized log collection.".to_string()),
        },
    ]
}

/// Configuration Management (CM) Family - Controls for system configuration
fn get_configuration_management_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-CM-1".to_string(),
            control_id: "CM-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Configuration Management Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate configuration management policy and procedures.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-1".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Document configuration management policies including baseline configuration and change control procedures.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CM-2".to_string(),
            control_id: "CM-2".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Baseline Configuration".to_string(),
            description: "Develop, document, and maintain under configuration control, a current baseline configuration of the system.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Create and maintain secure baseline configurations using CIS Benchmarks or DISA STIGs.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CM-3".to_string(),
            control_id: "CM-3".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Configuration Change Control".to_string(),
            description: "Determine and document the types of changes to the system that are configuration-controlled.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Implement formal change management process with approval workflows, testing, and rollback procedures.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CM-6".to_string(),
            control_id: "CM-6".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Configuration Settings".to_string(),
            description: "Establish and document configuration settings for system components that reflect the most restrictive mode consistent with operational requirements.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Apply security configuration guides (STIGs, CIS Benchmarks). Document and justify any deviations.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CM-7".to_string(),
            control_id: "CM-7".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Least Functionality".to_string(),
            description: "Configure the system to provide only mission essential capabilities and prohibit or restrict the use of functions, ports, protocols, and services not required.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CIS-2.3".to_string(), "CIS-4.8".to_string()],
            remediation_guidance: Some("Disable unnecessary services, close unused ports, implement application whitelisting.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CM-8".to_string(),
            control_id: "CM-8".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "System Component Inventory".to_string(),
            description: "Develop and document an inventory of system components that accurately reflects the system and is granular enough to support tracking and reporting.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "CIS-1.1".to_string(), "CIS-2.1".to_string()],
            remediation_guidance: Some("Implement automated asset discovery and maintain comprehensive CMDB with regular reconciliation.".to_string()),
        },
    ]
}

/// Contingency Planning (CP) Family - Controls for disaster recovery and business continuity
fn get_contingency_planning_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-CP-1".to_string(),
            control_id: "CP-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Contingency Planning Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate contingency planning policy and procedures.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-1".to_string()],
            remediation_guidance: Some("Document business continuity and disaster recovery policies with defined RTOs and RPOs.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CP-2".to_string(),
            control_id: "CP-2".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Contingency Plan".to_string(),
            description: "Develop a contingency plan that identifies essential mission functions, provides recovery objectives, and defines roles and responsibilities.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-2".to_string()],
            remediation_guidance: Some("Develop comprehensive contingency plan covering preparation, activation, recovery, and reconstitution phases.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CP-4".to_string(),
            control_id: "CP-4".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Contingency Plan Testing".to_string(),
            description: "Test the contingency plan to determine the effectiveness of the plan and organizational readiness to execute the plan.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-4".to_string(), "CIS-11.5".to_string()],
            remediation_guidance: Some("Conduct annual tabletop exercises and periodic full-scale recovery tests. Document results and lessons learned.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CP-9".to_string(),
            control_id: "CP-9".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "System Backup".to_string(),
            description: "Conduct backups of user-level and system-level information contained in the system.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-9".to_string(), "CIS-11.2".to_string()],
            remediation_guidance: Some("Implement automated daily backups with encryption. Store backups offsite and test restoration quarterly.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-CP-10".to_string(),
            control_id: "CP-10".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "System Recovery and Reconstitution".to_string(),
            description: "Provide for the recovery and reconstitution of the system to a known state within defined time periods.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-10".to_string()],
            remediation_guidance: Some("Document and test recovery procedures. Maintain recovery capabilities to meet defined RTO/RPO objectives.".to_string()),
        },
    ]
}

/// Identification and Authentication (IA) Family - Controls for identity verification
fn get_identification_authentication_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-IA-1".to_string(),
            control_id: "IA-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Identification and Authentication Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate identification and authentication policy and procedures.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IA-1".to_string()],
            remediation_guidance: Some("Document authentication policies including password requirements, MFA, and PIV/CAC usage.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IA-2".to_string(),
            control_id: "IA-2".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Identification and Authentication (Organizational Users)".to_string(),
            description: "Uniquely identify and authenticate organizational users and associate that unique identification with processes acting on behalf of those users.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "CIS-6.3".to_string()],
            remediation_guidance: Some("Implement multi-factor authentication for all users. Require PIV/CAC for privileged access.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IA-3".to_string(),
            control_id: "IA-3".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Device Identification and Authentication".to_string(),
            description: "Uniquely identify and authenticate devices before establishing a connection.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-3".to_string(), "CIS-1.4".to_string()],
            remediation_guidance: Some("Implement 802.1X for network access control. Use device certificates for machine authentication.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IA-5".to_string(),
            control_id: "IA-5".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Authenticator Management".to_string(),
            description: "Manage system authenticators by verifying identity before issuing authenticators, establishing initial content, and ensuring sufficient strength.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "CIS-5.2".to_string()],
            remediation_guidance: Some("Enforce password complexity: minimum 12 characters, complexity requirements, 24 password history. Implement password expiration.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IA-6".to_string(),
            control_id: "IA-6".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Authentication Feedback".to_string(),
            description: "Obscure feedback of authentication information during the authentication process to protect the information from possible exploitation.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-6".to_string()],
            remediation_guidance: Some("Mask password fields during entry. Do not display detailed error messages for failed authentication.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IA-8".to_string(),
            control_id: "IA-8".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Identification and Authentication (Non-Organizational Users)".to_string(),
            description: "Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-8".to_string()],
            remediation_guidance: Some("Implement identity proofing for external users. Use federated identity where appropriate.".to_string()),
        },
    ]
}

/// Incident Response (IR) Family - Controls for security incident handling
fn get_incident_response_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-IR-1".to_string(),
            control_id: "IR-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Incident Response Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate incident response policy and procedures.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string()],
            remediation_guidance: Some("Document incident response plan with roles, responsibilities, communication procedures, and escalation paths.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IR-2".to_string(),
            control_id: "IR-2".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Incident Response Training".to_string(),
            description: "Provide incident response training to system users consistent with assigned roles and responsibilities.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-2".to_string()],
            remediation_guidance: Some("Conduct annual incident response training and tabletop exercises for incident response team.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IR-4".to_string(),
            control_id: "IR-4".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Incident Handling".to_string(),
            description: "Implement an incident handling capability for incidents that includes preparation, detection, analysis, containment, eradication, and recovery.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Establish incident response team with documented procedures for each phase of incident handling.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IR-5".to_string(),
            control_id: "IR-5".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Incident Monitoring".to_string(),
            description: "Track and document system security and privacy incidents on an ongoing basis.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-5".to_string()],
            remediation_guidance: Some("Implement incident tracking system with categorization, metrics, and trend analysis.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IR-6".to_string(),
            control_id: "IR-6".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Incident Reporting".to_string(),
            description: "Require personnel to report suspected incidents to the organizational incident response capability within defined time periods.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Report incidents to US-CERT within required timeframes. Document internal and external reporting procedures.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-IR-8".to_string(),
            control_id: "IR-8".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Incident Response Plan".to_string(),
            description: "Develop an incident response plan that provides a roadmap for implementing incident response capability.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-8".to_string()],
            remediation_guidance: Some("Create incident response plan with mission, strategies, organization structure, and integration with other plans.".to_string()),
        },
    ]
}

/// System and Communications Protection (SC) Family - Controls for network and data protection
fn get_system_protection_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-SC-1".to_string(),
            control_id: "SC-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "System and Communications Protection Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate system and communications protection policy and procedures.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-1".to_string()],
            remediation_guidance: Some("Document network security policies including encryption requirements and boundary protection.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SC-7".to_string(),
            control_id: "SC-7".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Boundary Protection".to_string(),
            description: "Monitor and control communications at the external managed interface boundary and at key internal boundaries within the system.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CIS-12.1".to_string(), "CIS-13.1".to_string()],
            remediation_guidance: Some("Deploy firewalls at network boundaries. Implement DMZ architecture and network segmentation.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SC-8".to_string(),
            control_id: "SC-8".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Transmission Confidentiality and Integrity".to_string(),
            description: "Protect the confidentiality and integrity of transmitted information.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "CIS-3.10".to_string()],
            remediation_guidance: Some("Use TLS 1.2 or higher for all data in transit. Disable SSLv3, TLS 1.0, and TLS 1.1.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SC-12".to_string(),
            control_id: "SC-12".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Cryptographic Key Establishment and Management".to_string(),
            description: "Establish and manage cryptographic keys when cryptography is employed within the system.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string()],
            remediation_guidance: Some("Implement key management system with key generation, distribution, storage, rotation, and destruction procedures.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SC-13".to_string(),
            control_id: "SC-13".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Cryptographic Protection".to_string(),
            description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of information and detect changes to information.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string(), "CIS-3.11".to_string()],
            remediation_guidance: Some("Use FIPS 140-2/3 validated cryptographic modules. Implement AES-256 for data at rest.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SC-28".to_string(),
            control_id: "SC-28".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Protection of Information at Rest".to_string(),
            description: "Protect the confidentiality and integrity of information at rest.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "CIS-3.6".to_string()],
            remediation_guidance: Some("Enable full-disk encryption on all endpoints. Encrypt databases containing sensitive data.".to_string()),
        },
    ]
}

/// System and Information Integrity (SI) Family - Controls for system integrity and malware protection
fn get_system_integrity_family() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "FISMA-SI-1".to_string(),
            control_id: "SI-1".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "System and Information Integrity Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate system and information integrity policy and procedures.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-1".to_string()],
            remediation_guidance: Some("Document integrity policies for malware protection, patch management, and file integrity monitoring.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SI-2".to_string(),
            control_id: "SI-2".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Flaw Remediation".to_string(),
            description: "Identify, report, and correct system flaws in a timely manner.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "CIS-7.1".to_string(), "CIS-7.4".to_string()],
            remediation_guidance: Some("Apply critical patches within 30 days. Implement automated patch management and vulnerability scanning.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SI-3".to_string(),
            control_id: "SI-3".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Malicious Code Protection".to_string(),
            description: "Implement malicious code protection at system entry and exit points and at workstations to detect and eradicate malicious code.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "CIS-10.1".to_string()],
            remediation_guidance: Some("Deploy endpoint protection on all systems with real-time scanning and automatic updates.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SI-4".to_string(),
            control_id: "SI-4".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "System Monitoring".to_string(),
            description: "Monitor the system to detect attacks and indicators of potential attacks, unauthorized connections, and anomalous behavior.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "CIS-8.11".to_string()],
            remediation_guidance: Some("Deploy SIEM, IDS/IPS, and establish 24/7 security monitoring capabilities.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SI-5".to_string(),
            control_id: "SI-5".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Security Alerts, Advisories, and Directives".to_string(),
            description: "Receive system security alerts, advisories, and directives from designated external organizations on an ongoing basis.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-5".to_string()],
            remediation_guidance: Some("Subscribe to US-CERT, vendor security advisories, and CVE feeds. Implement processes to act on alerts.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SI-7".to_string(),
            control_id: "SI-7".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Software, Firmware, and Information Integrity".to_string(),
            description: "Employ integrity verification tools to detect unauthorized changes to software, firmware, and information.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-7".to_string(), "CIS-3.14".to_string()],
            remediation_guidance: Some("Deploy file integrity monitoring on critical system files and directories.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SI-10".to_string(),
            control_id: "SI-10".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Information Input Validation".to_string(),
            description: "Check the validity of information inputs to prevent injection attacks and other input-based vulnerabilities.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string(), "CIS-16.1".to_string()],
            remediation_guidance: Some("Implement input validation, output encoding, and parameterized queries in all applications.".to_string()),
        },
        ComplianceControl {
            id: "FISMA-SI-12".to_string(),
            control_id: "SI-12".to_string(),
            framework: ComplianceFramework::Fisma,
            title: "Information Management and Retention".to_string(),
            description: "Manage and retain information within the system and information output from the system in accordance with applicable laws.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-12".to_string(), "CIS-3.4".to_string()],
            remediation_guidance: Some("Implement data retention policies compliant with NARA requirements and agency records schedules.".to_string()),
        },
    ]
}

/// Get controls by FISMA category
pub fn get_controls_by_category(category: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get all FISMA categories
pub fn get_categories() -> Vec<&'static str> {
    vec![
        "Access Control",
        "Audit and Accountability",
        "Configuration Management",
        "Contingency Planning",
        "Identification and Authentication",
        "Incident Response",
        "System and Communications Protection",
        "System and Information Integrity",
    ]
}

/// Map vulnerability to relevant FISMA controls with severity
/// FISMA maps directly to NIST 800-53 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("privilege escalation")
        || title_lower.contains("access control")
    {
        mappings.push(("FISMA-AC-3".to_string(), Severity::Critical));
        mappings.push(("FISMA-AC-6".to_string(), Severity::Critical));
    }

    // Authentication vulnerabilities
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("weak password")
        || title_lower.contains("brute force")
    {
        mappings.push(("FISMA-IA-2".to_string(), Severity::Critical));
        mappings.push(("FISMA-IA-5".to_string(), Severity::High));
        mappings.push(("FISMA-AC-7".to_string(), Severity::High));
    }

    // Default credentials
    if title_lower.contains("default password")
        || title_lower.contains("default credentials")
    {
        mappings.push(("FISMA-IA-5".to_string(), Severity::Critical));
        mappings.push(("FISMA-CM-6".to_string(), Severity::High));
    }

    // Encryption vulnerabilities
    if title_lower.contains("unencrypted")
        || title_lower.contains("weak encryption")
        || title_lower.contains("ssl") && title_lower.contains("vulnerable")
        || title_lower.contains("tls") && title_lower.contains("weak")
        || title_lower.contains("plaintext")
    {
        mappings.push(("FISMA-SC-8".to_string(), Severity::High));
        mappings.push(("FISMA-SC-13".to_string(), Severity::High));
        mappings.push(("FISMA-SC-28".to_string(), Severity::High));
    }

    // Patching vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("missing patch")
    {
        mappings.push(("FISMA-SI-2".to_string(), Severity::High));
        mappings.push(("FISMA-CM-6".to_string(), Severity::Medium));
    }

    // Injection vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("xss")
        || title_lower.contains("cross-site scripting")
    {
        mappings.push(("FISMA-SI-10".to_string(), Severity::Critical));
    }

    // Missing malware protection
    if title_lower.contains("no antivirus")
        || title_lower.contains("malware")
        || title_lower.contains("virus")
    {
        mappings.push(("FISMA-SI-3".to_string(), Severity::High));
    }

    // Logging/monitoring issues
    if title_lower.contains("no logging")
        || title_lower.contains("audit disabled")
        || title_lower.contains("monitoring disabled")
    {
        mappings.push(("FISMA-AU-2".to_string(), Severity::Medium));
        mappings.push(("FISMA-AU-12".to_string(), Severity::Medium));
        mappings.push(("FISMA-SI-4".to_string(), Severity::Medium));
    }

    // Firewall/boundary issues
    if title_lower.contains("firewall")
        || title_lower.contains("open port")
        || title_lower.contains("exposed service")
    {
        mappings.push(("FISMA-SC-7".to_string(), Severity::Medium));
        mappings.push(("FISMA-CM-7".to_string(), Severity::Medium));
    }

    // Remote access issues
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
            mappings.push(("FISMA-AC-17".to_string(), Severity::High));
        }
    }

    // Insecure protocols
    if port == Some(23) || title_lower.contains("telnet") || title_lower.contains("ftp") {
        mappings.push(("FISMA-SC-8".to_string(), Severity::High));
        mappings.push(("FISMA-CM-7".to_string(), Severity::Medium));
    }

    // Backup issues
    if title_lower.contains("backup") && (title_lower.contains("missing") || title_lower.contains("failed")) {
        mappings.push(("FISMA-CP-9".to_string(), Severity::Medium));
    }

    // Configuration issues
    if title_lower.contains("misconfigur")
        || title_lower.contains("insecure config")
        || title_lower.contains("default config")
    {
        mappings.push(("FISMA-CM-6".to_string(), Severity::Medium));
        mappings.push(("FISMA-CM-2".to_string(), Severity::Medium));
    }

    // Information disclosure
    if title_lower.contains("information disclosure")
        || title_lower.contains("data leak")
        || title_lower.contains("sensitive data")
    {
        mappings.push(("FISMA-SC-28".to_string(), Severity::High));
        mappings.push(("FISMA-AC-4".to_string(), Severity::High));
    }

    // Account management issues
    if title_lower.contains("inactive account")
        || title_lower.contains("orphan account")
        || title_lower.contains("excessive privilege")
    {
        mappings.push(("FISMA-AC-2".to_string(), Severity::Medium));
        mappings.push(("FISMA-AC-6".to_string(), Severity::Medium));
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
            assert!(control.framework == ComplianceFramework::Fisma);
        }
    }

    #[test]
    fn test_all_controls_have_nist_cross_references() {
        for control in get_controls() {
            let has_nist_ref = control.cross_references.iter().any(|r| r.starts_with("NIST-"));
            assert!(has_nist_ref, "Control {} should have NIST cross-reference", control.id);
        }
    }

    #[test]
    fn test_categories() {
        let categories = get_categories();
        assert_eq!(categories.len(), 8);
        assert!(categories.contains(&"Access Control"));
        assert!(categories.contains(&"Audit and Accountability"));
        assert!(categories.contains(&"Incident Response"));
    }

    #[test]
    fn test_vulnerability_mapping() {
        // Test authentication vulnerability
        let mappings = map_vulnerability("Weak Password Policy Detected", None, None, None);
        assert!(!mappings.is_empty());
        let control_ids: Vec<&str> = mappings.iter().map(|(id, _)| id.as_str()).collect();
        assert!(control_ids.contains(&"FISMA-IA-5"));

        // Test encryption vulnerability
        let mappings = map_vulnerability("Unencrypted Data Transmission", None, None, None);
        assert!(!mappings.is_empty());
        let control_ids: Vec<&str> = mappings.iter().map(|(id, _)| id.as_str()).collect();
        assert!(control_ids.contains(&"FISMA-SC-8"));

        // Test SQL injection
        let mappings = map_vulnerability("SQL Injection Vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        let control_ids: Vec<&str> = mappings.iter().map(|(id, _)| id.as_str()).collect();
        assert!(control_ids.contains(&"FISMA-SI-10"));
    }

    #[test]
    fn test_impact_level_to_priority() {
        assert_eq!(FismaImpactLevel::High.to_priority(), ControlPriority::Critical);
        assert_eq!(FismaImpactLevel::Moderate.to_priority(), ControlPriority::High);
        assert_eq!(FismaImpactLevel::Low.to_priority(), ControlPriority::Medium);
    }
}
