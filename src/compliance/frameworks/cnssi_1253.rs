//! CNSSI 1253 - Security Categorization and Control Selection for National Security Systems
//!
//! Committee on National Security Systems Instruction (CNSSI) No. 1253 provides guidance
//! for security categorization and control selection for National Security Systems (NSS).
//! It builds upon NIST SP 800-53 controls but tailors them specifically for systems
//! that process, store, or transmit classified or sensitive national security information.
//!
//! Security Categorization follows the FIPS 199 model:
//! - Confidentiality Impact (Low, Moderate, High)
//! - Integrity Impact (Low, Moderate, High)
//! - Availability Impact (Low, Moderate, High)
//!
//! Control Overlay Categories (aligned with NIST 800-53):
//! - Access Control (AC)
//! - Audit and Accountability (AU)
//! - Configuration Management (CM)
//! - Identification and Authentication (IA)
//! - System and Communications Protection (SC)
//!
//! This module implements approximately 60 controls representative of CNSSI 1253
//! requirements for protecting National Security Systems.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of CNSSI 1253 controls in this module
pub const CONTROL_COUNT: usize = 60;

/// Security impact level for NSS categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpactLevel {
    /// Low impact - Limited adverse effect
    Low,
    /// Moderate impact - Serious adverse effect
    Moderate,
    /// High impact - Severe or catastrophic adverse effect
    High,
}

impl ImpactLevel {
    pub fn to_priority(self) -> ControlPriority {
        match self {
            ImpactLevel::High => ControlPriority::Critical,
            ImpactLevel::Moderate => ControlPriority::High,
            ImpactLevel::Low => ControlPriority::Medium,
        }
    }
}

/// NSS Security Categorization (C-I-A triad)
#[derive(Debug, Clone, Copy)]
pub struct NssSecurityCategorization {
    pub confidentiality: ImpactLevel,
    pub integrity: ImpactLevel,
    pub availability: ImpactLevel,
}

impl NssSecurityCategorization {
    /// Get the overall system categorization (highest impact level)
    pub fn overall_impact(&self) -> ImpactLevel {
        let impacts = [self.confidentiality, self.integrity, self.availability];
        if impacts.iter().any(|i| matches!(i, ImpactLevel::High)) {
            ImpactLevel::High
        } else if impacts.iter().any(|i| matches!(i, ImpactLevel::Moderate)) {
            ImpactLevel::Moderate
        } else {
            ImpactLevel::Low
        }
    }
}

/// Get all CNSSI 1253 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // Add controls by category
    controls.extend(get_access_control_controls());
    controls.extend(get_audit_accountability_controls());
    controls.extend(get_configuration_management_controls());
    controls.extend(get_identification_authentication_controls());
    controls.extend(get_system_communications_protection_controls());

    controls
}

/// Access Control (AC) family controls for NSS
fn get_access_control_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "CNSSI-AC-1".to_string(),
            control_id: "AC-1".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Access Control Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate access control policy for NSS that addresses purpose, scope, roles, responsibilities, management commitment, coordination, and compliance.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-1".to_string(), "PCI-DSS-7.1".to_string()],
            remediation_guidance: Some("Document and maintain NSS-specific access control policies reviewed annually with approval from the authorizing official.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-2".to_string(),
            control_id: "AC-2".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Account Management for NSS".to_string(),
            description: "Manage NSS accounts including identifying account types, establishing conditions for group membership, specifying authorized users, and requiring approvals for account creation.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "CIS-5.1".to_string()],
            remediation_guidance: Some("Implement centralized identity management for NSS with mandatory security clearance verification and need-to-know validation.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-3".to_string(),
            control_id: "AC-3".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Access Enforcement".to_string(),
            description: "Enforce approved authorizations for logical access to NSS information and system resources in accordance with applicable access control policies.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string(), "CIS-3.3".to_string()],
            remediation_guidance: Some("Implement mandatory access controls (MAC) based on security labels and discretionary access controls (DAC) based on need-to-know.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-4".to_string(),
            control_id: "AC-4".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Information Flow Enforcement".to_string(),
            description: "Enforce approved authorizations for controlling the flow of information within NSS and between interconnected systems based on security policy.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string(), "PCI-DSS-1.3".to_string()],
            remediation_guidance: Some("Implement cross-domain solutions (CDS) and guards for information flow between different security domains.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-5".to_string(),
            control_id: "AC-5".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Separation of Duties".to_string(),
            description: "Separate duties of individuals in NSS operations to prevent malicious activity without collusion and ensure no single individual has complete control over critical functions.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-5".to_string()],
            remediation_guidance: Some("Implement two-person integrity (TPI) for critical NSS functions and separate security administration from system administration.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-6".to_string(),
            control_id: "AC-6".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Least Privilege".to_string(),
            description: "Employ the principle of least privilege on NSS, allowing only authorized accesses necessary to accomplish assigned organizational tasks.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CIS-5.4".to_string()],
            remediation_guidance: Some("Implement role-based access control with just-in-time privileged access for NSS administration.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-7".to_string(),
            control_id: "AC-7".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Unsuccessful Logon Attempts".to_string(),
            description: "Enforce a limit of consecutive invalid logon attempts by a user during a specified time period and automatically lock the account when exceeded.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-7".to_string(), "PCI-DSS-8.1.6".to_string()],
            remediation_guidance: Some("Configure account lockout after 3 failed attempts with administrator unlock required for NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-8".to_string(),
            control_id: "AC-8".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "System Use Notification".to_string(),
            description: "Display an approved NSS use notification message before granting access that includes privacy and security notices, conditions for use, and consent to monitoring.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-8".to_string()],
            remediation_guidance: Some("Configure login banners with DoD-approved warning text and classification markings appropriate to system level.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-11".to_string(),
            control_id: "AC-11".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Device Lock".to_string(),
            description: "Prevent further access to NSS by initiating a device lock after a period of inactivity, requiring user re-authentication.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-11".to_string(), "CIS-4.3".to_string()],
            remediation_guidance: Some("Configure screen lock timeout to 15 minutes or less for unclassified NSS, 10 minutes for classified.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-17".to_string(),
            control_id: "AC-17".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Remote Access".to_string(),
            description: "Establish and document usage restrictions, configuration requirements, and implementation guidance for each allowed remote access method to NSS.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "CIS-6.4".to_string()],
            remediation_guidance: Some("Require NSA-approved cryptographic solutions for remote access with multi-factor authentication.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-18".to_string(),
            control_id: "AC-18".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Wireless Access".to_string(),
            description: "Establish and document usage restrictions and implementation guidance for wireless access to NSS components.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-18".to_string()],
            remediation_guidance: Some("Implement NSA-approved wireless security solutions; prohibit wireless in classified processing areas without specific authorization.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AC-19".to_string(),
            control_id: "AC-19".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Access Control for Mobile Devices".to_string(),
            description: "Establish usage restrictions, configuration requirements, and implementation guidance for mobile devices accessing or processing NSS data.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-19".to_string()],
            remediation_guidance: Some("Implement CSfC-approved mobile solutions with remote wipe capability and mandatory encryption for classified data.".to_string()),
        },
    ]
}

/// Audit and Accountability (AU) family controls for NSS
fn get_audit_accountability_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "CNSSI-AU-1".to_string(),
            control_id: "AU-1".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Audit and Accountability Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate audit and accountability policy for NSS that addresses purpose, scope, roles, and compliance requirements.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AU-1".to_string(), "CIS-8.1".to_string()],
            remediation_guidance: Some("Document NSS audit policies including what to log, retention requirements, and incident correlation procedures.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-2".to_string(),
            control_id: "AU-2".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Event Logging".to_string(),
            description: "Identify the types of events that NSS is capable of logging in support of the audit function and coordinate with other organizational entities requiring audit-related information.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "CIS-8.2".to_string()],
            remediation_guidance: Some("Log all authentication events, privilege escalations, security-relevant configuration changes, and data access on NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-3".to_string(),
            control_id: "AU-3".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Content of Audit Records".to_string(),
            description: "Ensure NSS audit records contain information that establishes what type of event occurred, when it occurred, where it occurred, the source, outcome, and identity of individuals involved.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-3".to_string(), "CIS-8.5".to_string()],
            remediation_guidance: Some("Configure logging to include timestamp, source IP, user ID, action, result, and security classification level accessed.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-4".to_string(),
            control_id: "AU-4".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Audit Log Storage Capacity".to_string(),
            description: "Allocate audit log storage capacity for NSS and configure audit log behavior when storage capacity is reached to prevent audit failure.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-4".to_string()],
            remediation_guidance: Some("Allocate sufficient storage for 1 year of audit logs; alert at 75% capacity and configure fail-secure behavior.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-5".to_string(),
            control_id: "AU-5".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Response to Audit Logging Process Failures".to_string(),
            description: "Alert appropriate personnel in the event of an NSS audit logging process failure and take defined actions including system shutdown if required.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-5".to_string()],
            remediation_guidance: Some("Configure alerts for logging failures; for high-impact NSS, configure automatic shutdown on audit failure.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-6".to_string(),
            control_id: "AU-6".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Audit Record Review, Analysis, and Reporting".to_string(),
            description: "Review and analyze NSS audit records for indications of inappropriate or unusual activity and report findings to designated officials.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string()],
            remediation_guidance: Some("Implement automated SIEM analysis with daily manual review; integrate with intelligence feeds for threat correlation.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-8".to_string(),
            control_id: "AU-8".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Time Stamps".to_string(),
            description: "Use internal system clocks to generate time stamps for NSS audit records synchronized to an authoritative time source.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-8".to_string(), "CIS-8.4".to_string()],
            remediation_guidance: Some("Configure NTP synchronization to DoD or agency-approved time sources with monitoring for drift.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-9".to_string(),
            control_id: "AU-9".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Protection of Audit Information".to_string(),
            description: "Protect NSS audit information and audit logging tools from unauthorized access, modification, and deletion.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string(), "PCI-DSS-10.5".to_string()],
            remediation_guidance: Some("Implement write-once logging to separate systems, cryptographic protection, and two-person integrity for log access.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-10".to_string(),
            control_id: "AU-10".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Non-repudiation".to_string(),
            description: "Provide irrefutable evidence that an individual or process performed a specific action on NSS.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-10".to_string()],
            remediation_guidance: Some("Implement digital signatures for critical transactions and cryptographic binding of user identity to actions.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-11".to_string(),
            control_id: "AU-11".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Audit Record Retention".to_string(),
            description: "Retain NSS audit records for a minimum period to support after-the-fact investigations and meet regulatory/policy requirements.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-11".to_string()],
            remediation_guidance: Some("Retain audit logs for minimum 1 year online and 5 years archived for NSS; classified system logs may require longer retention.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-AU-12".to_string(),
            control_id: "AU-12".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Audit Record Generation".to_string(),
            description: "Provide audit record generation capability for defined auditable events at all NSS components capable of generating audit records.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-12".to_string()],
            remediation_guidance: Some("Enable comprehensive audit logging on all NSS components including operating systems, applications, databases, and network devices.".to_string()),
        },
    ]
}

/// Configuration Management (CM) family controls for NSS
fn get_configuration_management_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "CNSSI-CM-1".to_string(),
            control_id: "CM-1".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Configuration Management Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate configuration management policy for NSS that addresses purpose, scope, roles, and compliance.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-1".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Document NSS configuration management policies including change control board procedures and security impact analysis requirements.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-2".to_string(),
            control_id: "CM-2".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Baseline Configuration".to_string(),
            description: "Develop, document, and maintain a current baseline configuration of NSS under configuration control.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string()],
            remediation_guidance: Some("Create and maintain STIG-compliant baseline configurations with automated compliance monitoring.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-3".to_string(),
            control_id: "CM-3".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Configuration Change Control".to_string(),
            description: "Determine and document types of changes to NSS that are configuration-controlled, approve changes with explicit consideration for security impact.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string()],
            remediation_guidance: Some("Implement configuration control board (CCB) review for all NSS changes with mandatory security impact analysis.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-4".to_string(),
            control_id: "CM-4".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Security Impact Analysis".to_string(),
            description: "Analyze changes to NSS to determine potential security impacts prior to change implementation.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-4".to_string()],
            remediation_guidance: Some("Conduct formal security impact analysis for all proposed changes including vulnerability assessment and risk evaluation.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-5".to_string(),
            control_id: "CM-5".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Access Restrictions for Change".to_string(),
            description: "Define, document, approve, and enforce physical and logical access restrictions associated with changes to NSS.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-5".to_string()],
            remediation_guidance: Some("Implement role-based change authorization with separation between development, test, and production environments.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-6".to_string(),
            control_id: "CM-6".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Configuration Settings".to_string(),
            description: "Establish and document configuration settings for NSS components using security configuration guides (STIGs, SRGs).".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string(), "CIS-4.2".to_string()],
            remediation_guidance: Some("Apply DISA STIGs and document all deviations with risk acceptance from the authorizing official.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-7".to_string(),
            control_id: "CM-7".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Least Functionality".to_string(),
            description: "Configure NSS to provide only essential capabilities and prohibit or restrict use of non-essential functions, ports, protocols, and services.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CIS-2.3".to_string()],
            remediation_guidance: Some("Disable all unnecessary services; implement application whitelisting; use PPSM-compliant ports and protocols only.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-8".to_string(),
            control_id: "CM-8".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "System Component Inventory".to_string(),
            description: "Develop and document an accurate, current inventory of NSS components including hardware, software, and firmware.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "CIS-1.1".to_string()],
            remediation_guidance: Some("Maintain automated asset inventory with serial numbers, locations, security classifications, and authorization status.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-9".to_string(),
            control_id: "CM-9".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Configuration Management Plan".to_string(),
            description: "Develop, document, and implement a configuration management plan for NSS that addresses roles, responsibilities, and processes.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-9".to_string()],
            remediation_guidance: Some("Document CM plan including configuration identification, change control, configuration status accounting, and configuration auditing.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-10".to_string(),
            control_id: "CM-10".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Software Usage Restrictions".to_string(),
            description: "Use software and associated documentation on NSS in accordance with contract agreements, copyright laws, and acquisition requirements.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-10".to_string()],
            remediation_guidance: Some("Track software licenses; ensure all NSS software is from approved sources with valid licensing.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-CM-11".to_string(),
            control_id: "CM-11".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "User-Installed Software".to_string(),
            description: "Establish and enforce policies for the installation of software by users on NSS.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-11".to_string()],
            remediation_guidance: Some("Prohibit user software installation; implement application whitelisting enforced through technical controls.".to_string()),
        },
    ]
}

/// Identification and Authentication (IA) family controls for NSS
fn get_identification_authentication_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "CNSSI-IA-1".to_string(),
            control_id: "IA-1".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Identification and Authentication Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate identification and authentication policy for NSS addressing purpose, scope, roles, and compliance.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IA-1".to_string()],
            remediation_guidance: Some("Document I&A policies including PKI requirements, password standards, and multi-factor authentication requirements for NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-2".to_string(),
            control_id: "IA-2".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Identification and Authentication (Organizational Users)".to_string(),
            description: "Uniquely identify and authenticate organizational users accessing NSS, implementing multi-factor authentication for privileged and network access.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "CIS-6.3".to_string()],
            remediation_guidance: Some("Implement CAC/PIV-based authentication for all NSS access; require hardware token MFA for privileged access.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-3".to_string(),
            control_id: "IA-3".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Device Identification and Authentication".to_string(),
            description: "Uniquely identify and authenticate devices before establishing a network connection to NSS using cryptographic mechanisms.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-3".to_string()],
            remediation_guidance: Some("Implement 802.1X with device certificates and network access control for all NSS network connections.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-4".to_string(),
            control_id: "IA-4".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Identifier Management".to_string(),
            description: "Manage NSS identifiers by receiving authorization, assigning unique identifiers, preventing reuse, and disabling identifiers after inactivity.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-4".to_string(), "CIS-5.3".to_string()],
            remediation_guidance: Some("Implement identity lifecycle management; disable accounts after 35 days of inactivity; never reuse identifiers.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-5".to_string(),
            control_id: "IA-5".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Authenticator Management".to_string(),
            description: "Manage NSS authenticators by verifying identity, establishing initial authenticator content, and ensuring sufficient strength for intended use.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "CIS-5.2".to_string()],
            remediation_guidance: Some("Enforce 15+ character passwords, complexity requirements, 60-day expiration, and 24 password history for NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-6".to_string(),
            control_id: "IA-6".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Authentication Feedback".to_string(),
            description: "Obscure feedback of authentication information during the authentication process to protect against shoulder surfing.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-6".to_string()],
            remediation_guidance: Some("Configure password masking on all authentication interfaces; disable password hints.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-7".to_string(),
            control_id: "IA-7".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Cryptographic Module Authentication".to_string(),
            description: "Implement mechanisms for authentication to a cryptographic module that meet NSA/NIAP requirements for the security level.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-7".to_string()],
            remediation_guidance: Some("Use NSA-approved cryptographic modules (CSfC) or FIPS 140-2/3 Level 2+ validated modules.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-8".to_string(),
            control_id: "IA-8".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Identification and Authentication (Non-Organizational Users)".to_string(),
            description: "Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-8".to_string()],
            remediation_guidance: Some("Implement PIV-I or approved external identity federation for non-organizational access; maintain access agreements.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-11".to_string(),
            control_id: "IA-11".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Re-authentication".to_string(),
            description: "Require users to re-authenticate when organization-defined circumstances or situations require.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-11".to_string()],
            remediation_guidance: Some("Require re-authentication for privileged actions, role changes, and after session timeout on NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-IA-12".to_string(),
            control_id: "IA-12".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Identity Proofing".to_string(),
            description: "Identity proof users that require accounts for logical access to NSS in accordance with applicable standards.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IA-12".to_string()],
            remediation_guidance: Some("Conduct in-person identity proofing with government-issued ID and verification of security clearance status.".to_string()),
        },
    ]
}

/// System and Communications Protection (SC) family controls for NSS
fn get_system_communications_protection_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "CNSSI-SC-1".to_string(),
            control_id: "SC-1".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "System and Communications Protection Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate system and communications protection policy for NSS.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-1".to_string()],
            remediation_guidance: Some("Document network security policies including encryption requirements, boundary protection, and cross-domain solution usage.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-2".to_string(),
            control_id: "SC-2".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Separation of System and User Functionality".to_string(),
            description: "Separate user functionality from NSS management functionality including physically or logically separating user interfaces from management interfaces.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-2".to_string()],
            remediation_guidance: Some("Implement separate management networks and interfaces for NSS administration; use jump servers for privileged access.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-3".to_string(),
            control_id: "SC-3".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Security Function Isolation".to_string(),
            description: "Isolate security functions from nonsecurity functions within NSS using hardware separation, software separation, or virtualization.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-3".to_string()],
            remediation_guidance: Some("Implement security domain separation using Type 1 encryption boundaries or accredited cross-domain solutions.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-5".to_string(),
            control_id: "SC-5".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Denial of Service Protection".to_string(),
            description: "Protect NSS against or limit the effects of denial of service attacks using safeguards defined in policy.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-5".to_string()],
            remediation_guidance: Some("Implement rate limiting, traffic filtering, and DDoS protection services appropriate to the NSS availability requirements.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-7".to_string(),
            control_id: "SC-7".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Boundary Protection".to_string(),
            description: "Monitor and control communications at external managed interfaces and key internal boundaries of NSS.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CIS-9.2".to_string()],
            remediation_guidance: Some("Implement defense-in-depth with multiple security boundaries, IDS/IPS, and cross-domain guards for NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-8".to_string(),
            control_id: "SC-8".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Transmission Confidentiality and Integrity".to_string(),
            description: "Protect the confidentiality and integrity of transmitted information using NSA-approved cryptographic mechanisms.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Use NSA Type 1 encryption for classified data in transit; TLS 1.2/1.3 with approved cipher suites for unclassified NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-12".to_string(),
            control_id: "SC-12".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Cryptographic Key Establishment and Management".to_string(),
            description: "Establish and manage cryptographic keys for required cryptography within NSS using approved key management technology and processes.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string()],
            remediation_guidance: Some("Implement NSA-approved key management system with COMSEC custodian procedures; use hardware security modules.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-13".to_string(),
            control_id: "SC-13".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Cryptographic Protection".to_string(),
            description: "Implement NSA-approved or NIST-compliant cryptographic mechanisms in accordance with applicable policies and regulations.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string()],
            remediation_guidance: Some("Use NSA Suite B (CNSA) algorithms for classified; FIPS 140-3 validated for unclassified NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-17".to_string(),
            control_id: "SC-17".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Public Key Infrastructure Certificates".to_string(),
            description: "Issue public key certificates under an organization-specific certificate policy or obtain certificates from an approved service provider.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-17".to_string()],
            remediation_guidance: Some("Use DoD PKI or NSA-approved PKI; implement certificate pinning and revocation checking for NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-23".to_string(),
            control_id: "SC-23".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Session Authenticity".to_string(),
            description: "Protect the authenticity of communications sessions on NSS using cryptographic mechanisms.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-23".to_string()],
            remediation_guidance: Some("Implement mutual TLS authentication; use cryptographic session tokens; protect against session hijacking.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-28".to_string(),
            control_id: "SC-28".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Protection of Information at Rest".to_string(),
            description: "Protect the confidentiality and integrity of information at rest on NSS using NSA-approved encryption.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "CIS-3.6".to_string()],
            remediation_guidance: Some("Use NSA-approved encryption for classified data at rest; AES-256 with FIPS-validated modules for unclassified NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-39".to_string(),
            control_id: "SC-39".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Process Isolation".to_string(),
            description: "Maintain a separate execution domain for each executing process on NSS.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-39".to_string()],
            remediation_guidance: Some("Enable address space layout randomization (ASLR), DEP/NX, and process sandboxing on NSS.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-42".to_string(),
            control_id: "SC-42".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "Sensor Capability and Data".to_string(),
            description: "Prohibit remote activation of sensing capabilities on NSS and provide explicit indication of sensor use.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-42".to_string()],
            remediation_guidance: Some("Disable unused sensors; implement hardware indicators for active cameras/microphones; restrict remote sensor activation.".to_string()),
        },
        ComplianceControl {
            id: "CNSSI-SC-45".to_string(),
            control_id: "SC-45".to_string(),
            framework: ComplianceFramework::Cnssi1253,
            title: "System Time Synchronization".to_string(),
            description: "Synchronize NSS clocks to an authoritative time source and protect time synchronization from unauthorized modification.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-45".to_string()],
            remediation_guidance: Some("Use authenticated NTP from authoritative government sources; monitor for time drift and manipulation.".to_string()),
        },
    ]
}

/// Get controls by category
pub fn get_controls_by_category(category: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get all CNSSI 1253 categories
pub fn get_categories() -> Vec<&'static str> {
    vec![
        "Access Control",
        "Audit and Accountability",
        "Configuration Management",
        "Identification and Authentication",
        "System and Communications Protection",
    ]
}

/// Get controls applicable for a given security categorization
pub fn get_controls_for_categorization(categorization: &NssSecurityCategorization) -> Vec<ComplianceControl> {
    let overall = categorization.overall_impact();
    let min_priority = match overall {
        ImpactLevel::High => ControlPriority::Medium, // All controls for high-impact
        ImpactLevel::Moderate => ControlPriority::High, // High and Critical for moderate
        ImpactLevel::Low => ControlPriority::Critical, // Only Critical for low
    };

    get_controls()
        .into_iter()
        .filter(|c| {
            match min_priority {
                ControlPriority::Critical => matches!(c.priority, ControlPriority::Critical),
                ControlPriority::High => matches!(c.priority, ControlPriority::Critical | ControlPriority::High),
                ControlPriority::Medium => matches!(c.priority, ControlPriority::Critical | ControlPriority::High | ControlPriority::Medium),
                ControlPriority::Low => true,
            }
        })
        .collect()
}

/// Map a vulnerability to relevant CNSSI 1253 controls
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
        || title_lower.contains("privilege")
    {
        mappings.push(("CNSSI-AC-3".to_string(), Severity::Critical));
        mappings.push(("CNSSI-AC-6".to_string(), Severity::Critical));
        mappings.push(("CNSSI-AC-5".to_string(), Severity::High));
    }

    // Authentication vulnerabilities
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("weak password")
        || title_lower.contains("authentication")
    {
        mappings.push(("CNSSI-IA-2".to_string(), Severity::Critical));
        mappings.push(("CNSSI-IA-5".to_string(), Severity::Critical));
        mappings.push(("CNSSI-AC-7".to_string(), Severity::High));
    }

    // Default credentials - critical for NSS
    if title_lower.contains("default password")
        || title_lower.contains("default credentials")
    {
        mappings.push(("CNSSI-IA-5".to_string(), Severity::Critical));
        mappings.push(("CNSSI-CM-6".to_string(), Severity::Critical));
    }

    // Encryption vulnerabilities - critical for NSS
    if title_lower.contains("unencrypted")
        || title_lower.contains("weak encryption")
        || title_lower.contains("cleartext")
        || title_lower.contains("plaintext")
        || (title_lower.contains("ssl") && title_lower.contains("vulnerable"))
        || (title_lower.contains("tls") && title_lower.contains("weak"))
    {
        mappings.push(("CNSSI-SC-8".to_string(), Severity::Critical));
        mappings.push(("CNSSI-SC-13".to_string(), Severity::Critical));
        mappings.push(("CNSSI-SC-28".to_string(), Severity::Critical));
    }

    // Cryptographic issues
    if title_lower.contains("fips")
        || title_lower.contains("crypto")
        || title_lower.contains("cipher")
        || title_lower.contains("certificate")
    {
        mappings.push(("CNSSI-SC-13".to_string(), Severity::Critical));
        mappings.push(("CNSSI-IA-7".to_string(), Severity::High));
        mappings.push(("CNSSI-SC-17".to_string(), Severity::High));
    }

    // Patching vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("cve")
    {
        mappings.push(("CNSSI-CM-6".to_string(), Severity::Critical));
        mappings.push(("CNSSI-CM-2".to_string(), Severity::High));
    }

    // Configuration issues
    if title_lower.contains("misconfiguration")
        || title_lower.contains("configuration")
        || title_lower.contains("hardening")
    {
        mappings.push(("CNSSI-CM-6".to_string(), Severity::High));
        mappings.push(("CNSSI-CM-7".to_string(), Severity::High));
    }

    // Injection vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("xss")
        || title_lower.contains("injection")
    {
        mappings.push(("CNSSI-SC-39".to_string(), Severity::Critical));
        mappings.push(("CNSSI-SC-3".to_string(), Severity::High));
    }

    // Logging/monitoring issues
    if title_lower.contains("no logging")
        || title_lower.contains("audit disabled")
        || title_lower.contains("logging")
        || title_lower.contains("monitoring")
    {
        mappings.push(("CNSSI-AU-2".to_string(), Severity::High));
        mappings.push(("CNSSI-AU-12".to_string(), Severity::High));
        mappings.push(("CNSSI-AU-6".to_string(), Severity::Medium));
    }

    // Audit protection issues
    if title_lower.contains("audit log")
        || title_lower.contains("log tampering")
        || title_lower.contains("log deletion")
    {
        mappings.push(("CNSSI-AU-9".to_string(), Severity::Critical));
        mappings.push(("CNSSI-AU-5".to_string(), Severity::High));
    }

    // Firewall/boundary issues
    if title_lower.contains("firewall")
        || title_lower.contains("open port")
        || title_lower.contains("boundary")
        || title_lower.contains("network segmentation")
    {
        mappings.push(("CNSSI-SC-7".to_string(), Severity::High));
        mappings.push(("CNSSI-SC-5".to_string(), Severity::Medium));
    }

    // Remote access issues
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
            mappings.push(("CNSSI-AC-17".to_string(), Severity::Critical));
            mappings.push(("CNSSI-AC-18".to_string(), Severity::High));
        }
    }

    // SSH vulnerabilities
    if title_lower.contains("ssh") {
        mappings.push(("CNSSI-SC-8".to_string(), Severity::High));
        mappings.push(("CNSSI-SC-13".to_string(), Severity::High));
    }

    // Insecure protocols
    if port == Some(23) || title_lower.contains("telnet") || title_lower.contains("ftp") && !title_lower.contains("sftp") {
        mappings.push(("CNSSI-SC-8".to_string(), Severity::Critical));
        mappings.push(("CNSSI-CM-7".to_string(), Severity::High));
    }

    // Session management
    if title_lower.contains("session")
        || title_lower.contains("timeout")
        || title_lower.contains("cookie")
    {
        mappings.push(("CNSSI-SC-23".to_string(), Severity::High));
        mappings.push(("CNSSI-AC-11".to_string(), Severity::Medium));
    }

    // Device authentication
    if title_lower.contains("device")
        || title_lower.contains("802.1x")
        || title_lower.contains("nac")
    {
        mappings.push(("CNSSI-IA-3".to_string(), Severity::High));
    }

    // Mobile device security
    if title_lower.contains("mobile")
        || title_lower.contains("byod")
        || title_lower.contains("mdm")
    {
        mappings.push(("CNSSI-AC-19".to_string(), Severity::High));
    }

    // Wireless security
    if title_lower.contains("wireless")
        || title_lower.contains("wifi")
        || title_lower.contains("wpa")
    {
        mappings.push(("CNSSI-AC-18".to_string(), Severity::High));
    }

    // Key management
    if title_lower.contains("key management")
        || title_lower.contains("key exposure")
        || title_lower.contains("weak key")
    {
        mappings.push(("CNSSI-SC-12".to_string(), Severity::Critical));
    }

    // Information flow
    if title_lower.contains("data leak")
        || title_lower.contains("data exfiltration")
        || title_lower.contains("information disclosure")
    {
        mappings.push(("CNSSI-AC-4".to_string(), Severity::Critical));
        mappings.push(("CNSSI-SC-7".to_string(), Severity::High));
    }

    // Inventory/asset management
    if title_lower.contains("unknown device")
        || title_lower.contains("rogue")
        || title_lower.contains("unauthorized device")
    {
        mappings.push(("CNSSI-CM-8".to_string(), Severity::High));
        mappings.push(("CNSSI-IA-3".to_string(), Severity::High));
    }

    mappings
}

/// Map vulnerability to CNSSI 1253 control IDs only (without severity)
pub fn map_vulnerability_to_controls(vuln_title: &str, vuln_description: &str) -> Vec<String> {
    let combined = format!("{} {}", vuln_title, vuln_description).to_lowercase();
    let mut matched_controls = Vec::new();

    // Authentication and access control
    if combined.contains("password") || combined.contains("credential") || combined.contains("authentication") {
        matched_controls.extend(vec!["AC-2", "AC-7", "IA-2", "IA-5"]);
    }

    // Encryption and cryptography
    if combined.contains("encrypt") || combined.contains("tls") || combined.contains("ssl")
        || combined.contains("fips") || combined.contains("crypto") {
        matched_controls.extend(vec!["SC-8", "SC-12", "SC-13", "SC-28", "IA-7"]);
    }

    // Configuration and hardening
    if combined.contains("configuration") || combined.contains("hardening") || combined.contains("stig") {
        matched_controls.extend(vec!["CM-2", "CM-6", "CM-7"]);
    }

    // Audit and logging
    if combined.contains("audit") || combined.contains("log") || combined.contains("monitoring") {
        matched_controls.extend(vec!["AU-2", "AU-3", "AU-6", "AU-9", "AU-12"]);
    }

    // Network and boundary
    if combined.contains("firewall") || combined.contains("network") || combined.contains("boundary") {
        matched_controls.extend(vec!["SC-7", "AC-4"]);
    }

    // Remote access
    if combined.contains("remote") || combined.contains("ssh") || combined.contains("rdp") {
        matched_controls.extend(vec!["AC-17", "SC-8"]);
    }

    // Session management
    if combined.contains("session") || combined.contains("timeout") {
        matched_controls.extend(vec!["SC-23", "AC-11"]);
    }

    // Privilege escalation
    if combined.contains("privilege") || combined.contains("escalation") || combined.contains("root") {
        matched_controls.extend(vec!["AC-3", "AC-5", "AC-6"]);
    }

    matched_controls.sort();
    matched_controls.dedup();
    matched_controls.into_iter().map(String::from).collect()
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
            assert!(control.framework == ComplianceFramework::Cnssi1253);
        }
    }

    #[test]
    fn test_categories() {
        let categories = get_categories();
        assert_eq!(categories.len(), 5);
        assert!(categories.contains(&"Access Control"));
        assert!(categories.contains(&"Audit and Accountability"));
        assert!(categories.contains(&"Configuration Management"));
        assert!(categories.contains(&"Identification and Authentication"));
        assert!(categories.contains(&"System and Communications Protection"));
    }

    #[test]
    fn test_get_controls_by_category() {
        let ac_controls = get_controls_by_category("Access Control");
        assert!(!ac_controls.is_empty());
        for control in ac_controls {
            assert_eq!(control.category, "Access Control");
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Weak SSL/TLS Configuration", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("SC-8") || id.contains("SC-13")));
    }

    #[test]
    fn test_nss_categorization() {
        let high_impact = NssSecurityCategorization {
            confidentiality: ImpactLevel::High,
            integrity: ImpactLevel::Moderate,
            availability: ImpactLevel::Low,
        };
        assert!(matches!(high_impact.overall_impact(), ImpactLevel::High));

        let moderate_impact = NssSecurityCategorization {
            confidentiality: ImpactLevel::Low,
            integrity: ImpactLevel::Moderate,
            availability: ImpactLevel::Low,
        };
        assert!(matches!(moderate_impact.overall_impact(), ImpactLevel::Moderate));
    }

    #[test]
    fn test_controls_for_categorization() {
        let high_cat = NssSecurityCategorization {
            confidentiality: ImpactLevel::High,
            integrity: ImpactLevel::High,
            availability: ImpactLevel::High,
        };
        let high_controls = get_controls_for_categorization(&high_cat);
        assert!(high_controls.len() >= 40); // Should include most controls

        let low_cat = NssSecurityCategorization {
            confidentiality: ImpactLevel::Low,
            integrity: ImpactLevel::Low,
            availability: ImpactLevel::Low,
        };
        let low_controls = get_controls_for_categorization(&low_cat);
        assert!(low_controls.len() < high_controls.len()); // Should have fewer controls
    }

    #[test]
    fn test_cross_references_to_nist() {
        let controls = get_controls();
        let with_nist_refs: Vec<_> = controls
            .iter()
            .filter(|c| c.cross_references.iter().any(|r| r.starts_with("NIST-")))
            .collect();

        // Most CNSSI 1253 controls should reference NIST 800-53
        assert!(with_nist_refs.len() >= 50);
    }
}
