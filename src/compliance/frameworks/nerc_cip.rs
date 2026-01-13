//! NERC CIP Compliance Framework
//!
//! North American Electric Reliability Corporation Critical Infrastructure Protection
//! standards for the Bulk Electric System (BES). These standards establish requirements
//! for securing cyber assets essential to the reliable operation of the electric grid.
//!
//! Version: CIP v7 (with CIP-013 Supply Chain updates)

use crate::compliance::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NERC CIP controls in this module
pub const CONTROL_COUNT: usize = 62;

/// Get all NERC CIP controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // CIP-002: BES Cyber System Categorization
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-002-r1".to_string(),
            control_id: "CIP-002-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "BES Cyber System Identification".to_string(),
            description: "Identify and categorize BES Cyber Systems and their associated BES Cyber Assets for the protection of the BES.".to_string(),
            category: "BES Cyber System Categorization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "IEC62443-2-1".to_string()],
            remediation_guidance: Some("Document and maintain an inventory of all BES Cyber Systems categorized as High, Medium, or Low impact.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-002-r2".to_string(),
            control_id: "CIP-002-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "BES Cyber System Categorization Review".to_string(),
            description: "Review the identification and categorization of BES Cyber Systems at least once every 15 calendar months.".to_string(),
            category: "BES Cyber System Categorization".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string()],
            remediation_guidance: Some("Establish a 15-month review cycle for BES Cyber System categorization with documented approval by CIP Senior Manager.".to_string()),
        },

        // ============================================================
        // CIP-003: Security Management Controls
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-003-r1".to_string(),
            control_id: "CIP-003-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Cyber Security Policies".to_string(),
            description: "Document and implement one or more cyber security policies that collectively address personnel and training, electronic security perimeters, physical security, system security management, incident reporting and response, recovery plans, configuration change management, information protection, and physical security.".to_string(),
            category: "Security Management Controls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-1".to_string(), "ISO27001-A.5".to_string()],
            remediation_guidance: Some("Develop comprehensive cyber security policies covering all required CIP areas. Review and approve annually by CIP Senior Manager.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-003-r2".to_string(),
            control_id: "CIP-003-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "CIP Senior Manager Designation".to_string(),
            description: "Identify by name a CIP Senior Manager who has overall authority and responsibility for leading and managing the entity's implementation of CIP standards.".to_string(),
            category: "Security Management Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-2".to_string()],
            remediation_guidance: Some("Formally designate a CIP Senior Manager with documented authority. Update designation within 30 days of any change.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-003-r3".to_string(),
            control_id: "CIP-003-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Delegate Authority".to_string(),
            description: "Where allowed by the CIP Standards, the CIP Senior Manager may delegate authority to one or more delegates.".to_string(),
            category: "Security Management Controls".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-2".to_string()],
            remediation_guidance: Some("Document all delegations of authority with specific actions delegated and delegate identification.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-003-r4".to_string(),
            control_id: "CIP-003-R4".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Low Impact BES Cyber System Security Plan".to_string(),
            description: "Implement one or more documented cyber security plans for low impact BES Cyber Systems that include electronic access controls, physical security controls, and cyber security awareness.".to_string(),
            category: "Security Management Controls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-2".to_string()],
            remediation_guidance: Some("Develop and implement security plans for all low impact BES Cyber Systems addressing access controls, physical security, and awareness training.".to_string()),
        },

        // ============================================================
        // CIP-004: Personnel & Training
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-004-r1".to_string(),
            control_id: "CIP-004-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Security Awareness Program".to_string(),
            description: "Implement a security awareness program that reinforces cyber security practices at least once every calendar quarter.".to_string(),
            category: "Personnel and Training".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "ISO27001-A.7.2.2".to_string()],
            remediation_guidance: Some("Establish quarterly security awareness training covering physical security, social engineering, and proper handling of BES Cyber System Information.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-004-r2".to_string(),
            control_id: "CIP-004-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Cyber Security Training".to_string(),
            description: "Ensure personnel with authorized electronic or unescorted physical access receive role-specific cyber security training prior to access authorization and at least once every 15 calendar months.".to_string(),
            category: "Personnel and Training".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-3".to_string()],
            remediation_guidance: Some("Implement role-based training program with initial training before access and refresher training every 15 months.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-004-r3".to_string(),
            control_id: "CIP-004-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Personnel Risk Assessment".to_string(),
            description: "Conduct personnel risk assessments (background checks) prior to granting authorized electronic or unescorted physical access and at least once every seven calendar years.".to_string(),
            category: "Personnel and Training".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-3".to_string()],
            remediation_guidance: Some("Conduct comprehensive background checks including identity verification, 7-year criminal history, and validation against restricted lists.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-004-r4".to_string(),
            control_id: "CIP-004-R4".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Access Management Program".to_string(),
            description: "Implement a documented access management program for authorizing, verifying, and revoking provisioned access to BES Cyber Systems.".to_string(),
            category: "Personnel and Training".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "NIST-AC-6".to_string()],
            remediation_guidance: Some("Establish formal access authorization workflow with quarterly access reviews and 24-hour revocation for terminated personnel.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-004-r5".to_string(),
            control_id: "CIP-004-R5".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Access Revocation".to_string(),
            description: "Revoke access to BES Cyber Systems within 24 hours for personnel no longer needing such access, and within the next calendar day for reassignments.".to_string(),
            category: "Personnel and Training".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "NIST-PS-4".to_string()],
            remediation_guidance: Some("Implement automated access revocation tied to HR systems with 24-hour SLA for terminations.".to_string()),
        },

        // ============================================================
        // CIP-005: Electronic Security Perimeter
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-005-r1".to_string(),
            control_id: "CIP-005-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Electronic Security Perimeter".to_string(),
            description: "Define and implement an Electronic Security Perimeter (ESP) around BES Cyber Systems using one or more discrete Electronic Access Points (EAPs).".to_string(),
            category: "Electronic Security Perimeter".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "IEC62443-3-3".to_string()],
            remediation_guidance: Some("Implement network segmentation with defined ESPs. Deploy firewalls at all EAPs with deny-by-default rules.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-005-r1.1".to_string(),
            control_id: "CIP-005-R1.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Inbound and Outbound Access Permissions".to_string(),
            description: "Require inbound and outbound access permissions at each EAP, including reason for granting access.".to_string(),
            category: "Electronic Security Perimeter".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-005-r1".to_string()),
            cross_references: vec!["NIST-SC-7".to_string(), "NIST-AC-4".to_string()],
            remediation_guidance: Some("Document all EAP access rules with business justification. Implement deny-all, permit-by-exception firewall policies.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-005-r1.2".to_string(),
            control_id: "CIP-005-R1.2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Dial-up Connectivity Protection".to_string(),
            description: "Protect against dial-up connectivity through use of encryption, callback capability, or physical device isolation.".to_string(),
            category: "Electronic Security Perimeter".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-005-r1".to_string()),
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Eliminate dial-up where possible. Where required, implement encryption and callback verification.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-005-r2".to_string(),
            control_id: "CIP-005-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Interactive Remote Access Management".to_string(),
            description: "Implement controls for Interactive Remote Access (IRA) including multi-factor authentication and encryption.".to_string(),
            category: "Electronic Security Perimeter".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "NIST-IA-2".to_string()],
            remediation_guidance: Some("Require multi-factor authentication for all remote access. Use encrypted VPN tunnels with intermediate systems.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-005-r2.1".to_string(),
            control_id: "CIP-005-R2.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Intermediate System for Remote Access".to_string(),
            description: "Utilize an Intermediate System such that the Cyber Asset initiating Interactive Remote Access does not directly access an applicable Cyber Asset.".to_string(),
            category: "Electronic Security Perimeter".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("nerc-cip-005-r2".to_string()),
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Deploy jump servers or bastion hosts for all remote access to BES Cyber Systems. Prohibit direct remote connections.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-005-r2.2".to_string(),
            control_id: "CIP-005-R2.2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Remote Access Encryption".to_string(),
            description: "Encrypt Interactive Remote Access sessions using encryption that terminates at an Intermediate System.".to_string(),
            category: "Electronic Security Perimeter".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-005-r2".to_string()),
            cross_references: vec!["NIST-SC-8".to_string(), "NIST-SC-13".to_string()],
            remediation_guidance: Some("Implement TLS 1.2+ or IPsec VPN for all remote access sessions terminating at intermediate systems.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-005-r2.3".to_string(),
            control_id: "CIP-005-R2.3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Multi-Factor Authentication".to_string(),
            description: "Require multi-factor authentication for all Interactive Remote Access sessions.".to_string(),
            category: "Electronic Security Perimeter".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("nerc-cip-005-r2".to_string()),
            cross_references: vec!["NIST-IA-2(1)".to_string()],
            remediation_guidance: Some("Deploy hardware tokens, smart cards, or authenticator apps for MFA. Do not allow SMS-based MFA for BES systems.".to_string()),
        },

        // ============================================================
        // CIP-006: Physical Security
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-006-r1".to_string(),
            control_id: "CIP-006-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Physical Security Plan".to_string(),
            description: "Document and implement a physical security plan that defines physical security perimeters (PSPs) and associated access controls.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string(), "ISO27001-A.11".to_string()],
            remediation_guidance: Some("Define PSPs using six-wall boundaries. Implement access control systems with audit logging at all access points.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-006-r1.1".to_string(),
            control_id: "CIP-006-R1.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Operational or Procedural Controls".to_string(),
            description: "Implement operational or procedural controls to restrict physical access at each PSP access point.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("nerc-cip-006-r1".to_string()),
            cross_references: vec!["NIST-PE-3".to_string()],
            remediation_guidance: Some("Implement badge readers, biometrics, or key-controlled locks with documented access procedures.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-006-r1.2".to_string(),
            control_id: "CIP-006-R1.2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Physical Access Point Monitoring".to_string(),
            description: "Monitor each Physical Access Point (PAP) for unauthorized access either continuously or through alarmed entry.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("nerc-cip-006-r1".to_string()),
            cross_references: vec!["NIST-PE-6".to_string()],
            remediation_guidance: Some("Deploy CCTV monitoring at all PAPs or implement door alarm systems with 24x7 monitoring.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-006-r1.3".to_string(),
            control_id: "CIP-006-R1.3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Visitor Control Program".to_string(),
            description: "Implement a visitor control program including logging of entry and continuous escort within PSPs.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("nerc-cip-006-r1".to_string()),
            cross_references: vec!["NIST-PE-8".to_string()],
            remediation_guidance: Some("Require visitor sign-in/sign-out with identification. Ensure continuous escort for all visitors within PSPs.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-006-r2".to_string(),
            control_id: "CIP-006-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Physical Access Control Systems".to_string(),
            description: "Protect Physical Access Control Systems (PACS) and their cabling by locating within identified PSPs or encrypting communications.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string()],
            remediation_guidance: Some("Locate PACS servers within PSPs. Encrypt communications between PACS components outside PSPs.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-006-r3".to_string(),
            control_id: "CIP-006-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Physical Access Logging".to_string(),
            description: "Log physical entry at each PSP access point and retain logs for 90 days.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-PE-8".to_string(), "NIST-AU-11".to_string()],
            remediation_guidance: Some("Configure PACS to log all access events with timestamps. Implement 90-day log retention with integrity protection.".to_string()),
        },

        // ============================================================
        // CIP-007: System Security Management
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-007-r1".to_string(),
            control_id: "CIP-007-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Ports and Services".to_string(),
            description: "Enable only logical network accessible ports that have been determined to be needed for operation.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CIS-4.8".to_string()],
            remediation_guidance: Some("Document all enabled ports and services with business justification. Disable or remove unnecessary ports and services.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r2".to_string(),
            control_id: "CIP-007-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Security Patch Management".to_string(),
            description: "Implement a patch management process for tracking, evaluating, and installing security patches for BES Cyber Systems within 35 calendar days.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "CIS-7.3".to_string()],
            remediation_guidance: Some("Establish patch management process with 35-day evaluation cycle. Document compensating measures for delayed patches.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r2.1".to_string(),
            control_id: "CIP-007-R2.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Patch Source Identification".to_string(),
            description: "Identify patch sources for tracking security patches for applicable BES Cyber Systems.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("nerc-cip-007-r2".to_string()),
            cross_references: vec!["NIST-SI-2".to_string()],
            remediation_guidance: Some("Document all vendor patch sources. Subscribe to security advisories and CVE notifications.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r3".to_string(),
            control_id: "CIP-007-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Malicious Code Prevention".to_string(),
            description: "Deploy methods to deter, detect, or prevent malicious code on applicable BES Cyber Systems.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "CIS-10.1".to_string()],
            remediation_guidance: Some("Deploy anti-malware on all applicable systems. Implement application whitelisting where AV is not feasible.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r3.1".to_string(),
            control_id: "CIP-007-R3.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Malicious Code Signature Updates".to_string(),
            description: "Update signatures or patterns for malicious code prevention methods per vendor recommendations or 35 calendar days.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-007-r3".to_string()),
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Enable automatic signature updates. Document manual update procedures for air-gapped systems.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r4".to_string(),
            control_id: "CIP-007-R4".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Security Event Monitoring".to_string(),
            description: "Log events at the BES Cyber System level for identification of, and after-the-fact investigations of, cyber security incidents.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "NIST-AU-3".to_string()],
            remediation_guidance: Some("Enable logging for authentication, access control, and security events. Implement centralized log collection.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r4.1".to_string(),
            control_id: "CIP-007-R4.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Security Event Log Retention".to_string(),
            description: "Retain security event logs for at least 90 consecutive calendar days.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-007-r4".to_string()),
            cross_references: vec!["NIST-AU-11".to_string()],
            remediation_guidance: Some("Configure 90-day log retention minimum. Implement log integrity monitoring and archival procedures.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r4.2".to_string(),
            control_id: "CIP-007-R4.2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Security Event Alert Generation".to_string(),
            description: "Generate alerts for security events that the Responsible Entity determines necessitate an alert.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-007-r4".to_string()),
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Define alerting thresholds for critical security events. Implement SIEM-based correlation and alerting.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r5".to_string(),
            control_id: "CIP-007-R5".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "System Access Control".to_string(),
            description: "Implement technical and procedural controls to enforce authentication and access controls for BES Cyber Systems.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string(), "NIST-IA-2".to_string()],
            remediation_guidance: Some("Implement role-based access control. Require unique user identification for all interactive access.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r5.1".to_string(),
            control_id: "CIP-007-R5.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Authentication Methods".to_string(),
            description: "Enforce authentication for interactive user access.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("nerc-cip-007-r5".to_string()),
            cross_references: vec!["NIST-IA-2".to_string()],
            remediation_guidance: Some("Require strong authentication for all interactive access. Implement MFA for privileged accounts.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r5.2".to_string(),
            control_id: "CIP-007-R5.2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Default and Generic Account Control".to_string(),
            description: "Identify default or other generic account types and change default passwords or disable accounts where possible.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("nerc-cip-007-r5".to_string()),
            cross_references: vec!["NIST-CM-6".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Identify and document all default accounts. Change default passwords or disable accounts before deployment.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r5.5".to_string(),
            control_id: "CIP-007-R5.5".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Password Policy".to_string(),
            description: "Enforce password complexity and change requirements for user and shared accounts.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-007-r5".to_string()),
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Enforce minimum 8-character passwords with complexity. Require password changes at least every 15 months.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-007-r5.6".to_string(),
            control_id: "CIP-007-R5.6".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Failed Authentication Lockout".to_string(),
            description: "Limit the number of unsuccessful authentication attempts or generate alerts after a threshold of unsuccessful attempts.".to_string(),
            category: "System Security Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-007-r5".to_string()),
            cross_references: vec!["NIST-AC-7".to_string()],
            remediation_guidance: Some("Configure account lockout after 5 failed attempts or implement alerting for failed authentication attempts.".to_string()),
        },

        // ============================================================
        // CIP-008: Incident Reporting and Response
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-008-r1".to_string(),
            control_id: "CIP-008-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Cyber Security Incident Response Plan".to_string(),
            description: "Document one or more Cyber Security Incident Response Plans that include identification, classification, and response procedures.".to_string(),
            category: "Incident Reporting and Response".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string(), "NIST-IR-4".to_string()],
            remediation_guidance: Some("Develop comprehensive incident response plan covering identification, classification, containment, eradication, and recovery.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-008-r2".to_string(),
            control_id: "CIP-008-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Incident Response Plan Implementation".to_string(),
            description: "Implement the Cyber Security Incident Response Plan including documentation of incidents and evidence retention.".to_string(),
            category: "Incident Reporting and Response".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Train incident response team. Retain evidence for at least 3 years for reportable incidents.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-008-r3".to_string(),
            control_id: "CIP-008-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Incident Response Plan Review and Testing".to_string(),
            description: "Test the Cyber Security Incident Response Plan at least once every 15 calendar months.".to_string(),
            category: "Incident Reporting and Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-3".to_string()],
            remediation_guidance: Some("Conduct tabletop exercises or drills annually. Document lessons learned and update plans accordingly.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-008-r4".to_string(),
            control_id: "CIP-008-R4".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Incident Notification".to_string(),
            description: "Notify the Electricity Subsector Coordinating Council (ESCC) of Cyber Security Incidents within required timeframes.".to_string(),
            category: "Incident Reporting and Response".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Establish notification procedures with ESCC contact information. Report incidents within 1 hour of determination.".to_string()),
        },

        // ============================================================
        // CIP-009: Recovery Plans
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-009-r1".to_string(),
            control_id: "CIP-009-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Recovery Plan Specifications".to_string(),
            description: "Document one or more recovery plans for BES Cyber Systems that include conditions for activation and required actions.".to_string(),
            category: "Recovery Plans".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-2".to_string()],
            remediation_guidance: Some("Document recovery plans including activation conditions, recovery procedures, and roles/responsibilities.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-009-r2".to_string(),
            control_id: "CIP-009-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Recovery Plan Implementation".to_string(),
            description: "Implement the recovery plan including testing and backup media verification.".to_string(),
            category: "Recovery Plans".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-4".to_string(), "NIST-CP-9".to_string()],
            remediation_guidance: Some("Test recovery capabilities at least once every 15 months. Verify backup media integrity annually.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-009-r3".to_string(),
            control_id: "CIP-009-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Recovery Plan Review and Update".to_string(),
            description: "Review and update recovery plans within 90 days of any changes that impact the plans.".to_string(),
            category: "Recovery Plans".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-2".to_string()],
            remediation_guidance: Some("Establish 90-day review trigger for plan changes. Document all updates with CIP Senior Manager approval.".to_string()),
        },

        // ============================================================
        // CIP-010: Configuration Change Management
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-010-r1".to_string(),
            control_id: "CIP-010-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Configuration Change Management".to_string(),
            description: "Develop and implement a documented process for managing configuration changes to BES Cyber Systems.".to_string(),
            category: "Configuration Change Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string()],
            remediation_guidance: Some("Implement formal change management process including authorization, documentation, and testing requirements.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-010-r1.1".to_string(),
            control_id: "CIP-010-R1.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Baseline Configuration".to_string(),
            description: "Develop and maintain a baseline configuration including operating system, firmware, software, open ports, and security patches.".to_string(),
            category: "Configuration Change Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("nerc-cip-010-r1".to_string()),
            cross_references: vec!["NIST-CM-2".to_string()],
            remediation_guidance: Some("Document baseline configurations for all BES Cyber Assets. Include OS version, firmware, installed software, and network configuration.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-010-r1.2".to_string(),
            control_id: "CIP-010-R1.2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Configuration Change Authorization".to_string(),
            description: "Authorize and document changes to the baseline configuration.".to_string(),
            category: "Configuration Change Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("nerc-cip-010-r1".to_string()),
            cross_references: vec!["NIST-CM-3".to_string()],
            remediation_guidance: Some("Require formal authorization for all baseline configuration changes. Document approver and date.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-010-r2".to_string(),
            control_id: "CIP-010-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Configuration Monitoring".to_string(),
            description: "Monitor for changes to the baseline configuration at least once every 35 calendar days.".to_string(),
            category: "Configuration Change Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "NIST-SI-7".to_string()],
            remediation_guidance: Some("Implement automated configuration monitoring tools. Alert on unauthorized baseline deviations.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-010-r3".to_string(),
            control_id: "CIP-010-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Vulnerability Assessments".to_string(),
            description: "Conduct vulnerability assessments at least once every 15 calendar months for BES Cyber Systems.".to_string(),
            category: "Configuration Change Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string()],
            remediation_guidance: Some("Perform comprehensive vulnerability assessments annually. Include paper-based assessments where active scanning is not feasible.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-010-r4".to_string(),
            control_id: "CIP-010-R4".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Transient Cyber Asset Management".to_string(),
            description: "Implement one or more documented plan(s) to manage Transient Cyber Assets and Removable Media.".to_string(),
            category: "Configuration Change Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-7".to_string()],
            remediation_guidance: Some("Document procedures for authorization, malware scanning, and tracking of transient devices and removable media.".to_string()),
        },

        // ============================================================
        // CIP-011: Information Protection
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-011-r1".to_string(),
            control_id: "CIP-011-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "BES Cyber System Information Protection".to_string(),
            description: "Implement methods to protect BES Cyber System Information in storage and transit.".to_string(),
            category: "Information Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "NIST-SC-28".to_string()],
            remediation_guidance: Some("Classify and label BES Cyber System Information. Implement encryption for storage and transit.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-011-r2".to_string(),
            control_id: "CIP-011-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "BES Cyber Asset Reuse and Disposal".to_string(),
            description: "Implement methods to prevent unauthorized retrieval of BES Cyber System Information from BES Cyber Assets prior to reuse or disposal.".to_string(),
            category: "Information Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Implement secure data destruction procedures. Verify sanitization before reuse or disposal.".to_string()),
        },

        // ============================================================
        // CIP-012: Communications between Control Centers
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-012-r1".to_string(),
            control_id: "CIP-012-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Control Center Communication Protection".to_string(),
            description: "Implement security protection for Real-time Assessment and Real-time monitoring data transmitted between Control Centers.".to_string(),
            category: "Communications between Control Centers".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "NIST-SC-12".to_string()],
            remediation_guidance: Some("Implement encryption and authentication for inter-Control Center communications. Use approved cryptographic methods.".to_string()),
        },

        // ============================================================
        // CIP-013: Supply Chain Risk Management
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-013-r1".to_string(),
            control_id: "CIP-013-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Supply Chain Cyber Security Risk Management Plan".to_string(),
            description: "Develop one or more documented supply chain cyber security risk management plan(s) for high and medium impact BES Cyber Systems.".to_string(),
            category: "Supply Chain Risk Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-12".to_string(), "NIST-SR-3".to_string()],
            remediation_guidance: Some("Document supply chain risk management plans addressing vendor risk assessment, integrity verification, and security controls.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-013-r1.1".to_string(),
            control_id: "CIP-013-R1.1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Vendor Security Notification".to_string(),
            description: "Process to obtain notification of vendor-identified security vulnerabilities.".to_string(),
            category: "Supply Chain Risk Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("nerc-cip-013-r1".to_string()),
            cross_references: vec!["NIST-SI-5".to_string()],
            remediation_guidance: Some("Establish vendor notification processes. Subscribe to vendor security advisories and bulletins.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-013-r1.2".to_string(),
            control_id: "CIP-013-R1.2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Software Integrity Verification".to_string(),
            description: "Process to verify integrity of software and patches provided by vendors.".to_string(),
            category: "Supply Chain Risk Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("nerc-cip-013-r1".to_string()),
            cross_references: vec!["NIST-SI-7".to_string()],
            remediation_guidance: Some("Verify software integrity using vendor-provided checksums or digital signatures before deployment.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-013-r2".to_string(),
            control_id: "CIP-013-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Supply Chain Risk Management Plan Implementation".to_string(),
            description: "Implement the supply chain cyber security risk management plan(s).".to_string(),
            category: "Supply Chain Risk Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-12".to_string()],
            remediation_guidance: Some("Execute supply chain risk assessments during procurement. Document vendor risk acceptance decisions.".to_string()),
        },

        // ============================================================
        // CIP-014: Physical Security
        // ============================================================
        ComplianceControl {
            id: "nerc-cip-014-r1".to_string(),
            control_id: "CIP-014-R1".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Transmission Station Risk Assessment".to_string(),
            description: "Perform an initial risk assessment and subsequent risk assessments for Transmission stations and substations.".to_string(),
            category: "Physical Security (Transmission)".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string()],
            remediation_guidance: Some("Conduct risk assessments for transmission stations identifying potential physical attack vectors and impacts.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-014-r2".to_string(),
            control_id: "CIP-014-R2".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Third-Party Verification of Risk Assessment".to_string(),
            description: "Have an unaffiliated third party verify the risk assessment performed under Requirement R1.".to_string(),
            category: "Physical Security (Transmission)".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string()],
            remediation_guidance: Some("Engage independent third party to verify risk assessment methodology and conclusions within 90 days.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-014-r3".to_string(),
            control_id: "CIP-014-R3".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Primary Control Center Risk Notification".to_string(),
            description: "Notify operators of primary control centers of identified risks.".to_string(),
            category: "Physical Security (Transmission)".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-9".to_string()],
            remediation_guidance: Some("Notify primary control center operators within 7 days of risk assessment completion.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-014-r4".to_string(),
            control_id: "CIP-014-R4".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Physical Security Plan Development".to_string(),
            description: "Develop and implement a physical security plan that covers each identified Transmission station or substation.".to_string(),
            category: "Physical Security (Transmission)".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-1".to_string()],
            remediation_guidance: Some("Develop physical security plans addressing threat deterrence, detection, delay, and response capabilities.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-014-r5".to_string(),
            control_id: "CIP-014-R5".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Third-Party Review of Physical Security Plan".to_string(),
            description: "Have an unaffiliated third party review the physical security plan developed under Requirement R4.".to_string(),
            category: "Physical Security (Transmission)".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-1".to_string()],
            remediation_guidance: Some("Engage independent third party to review physical security plan within 90 days of completion.".to_string()),
        },
        ComplianceControl {
            id: "nerc-cip-014-r6".to_string(),
            control_id: "CIP-014-R6".to_string(),
            framework: ComplianceFramework::NercCip,
            title: "Physical Security Plan Evaluation".to_string(),
            description: "Evaluate the effectiveness of physical security measures every 30 calendar months.".to_string(),
            category: "Physical Security (Transmission)".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-1".to_string()],
            remediation_guidance: Some("Evaluate physical security effectiveness every 30 months. Update plans based on evaluation findings.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant NERC CIP controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Remote access vulnerabilities
    if title_lower.contains("remote access")
        || title_lower.contains("rdp")
        || title_lower.contains("ssh")
        || title_lower.contains("vpn")
    {
        mappings.push(("nerc-cip-005-r2".to_string(), Severity::Critical));
        mappings.push(("nerc-cip-005-r2.2".to_string(), Severity::High));
        mappings.push(("nerc-cip-005-r2.3".to_string(), Severity::Critical));
    }

    // Authentication and access control
    if title_lower.contains("authentication")
        || title_lower.contains("password")
        || title_lower.contains("credential")
        || title_lower.contains("default")
    {
        mappings.push(("nerc-cip-007-r5".to_string(), Severity::Critical));
        mappings.push(("nerc-cip-007-r5.1".to_string(), Severity::High));
        mappings.push(("nerc-cip-007-r5.2".to_string(), Severity::Critical));
        mappings.push(("nerc-cip-007-r5.5".to_string(), Severity::High));
    }

    // Weak or missing multi-factor authentication
    if title_lower.contains("mfa")
        || title_lower.contains("multi-factor")
        || title_lower.contains("two-factor")
    {
        mappings.push(("nerc-cip-005-r2.3".to_string(), Severity::Critical));
    }

    // Encryption and cryptographic issues
    if title_lower.contains("encryption")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("cipher")
        || title_lower.contains("unencrypted")
    {
        mappings.push(("nerc-cip-005-r2.2".to_string(), Severity::High));
        mappings.push(("nerc-cip-011-r1".to_string(), Severity::High));
        mappings.push(("nerc-cip-012-r1".to_string(), Severity::Critical));
    }

    // Patch management and outdated software
    if title_lower.contains("patch")
        || title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("update")
        || title_lower.contains("end of life")
    {
        mappings.push(("nerc-cip-007-r2".to_string(), Severity::Critical));
        mappings.push(("nerc-cip-010-r1.1".to_string(), Severity::High));
    }

    // Malware and malicious code
    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("trojan")
        || title_lower.contains("ransomware")
    {
        mappings.push(("nerc-cip-007-r3".to_string(), Severity::Critical));
        mappings.push(("nerc-cip-007-r3.1".to_string(), Severity::High));
    }

    // Firewall and perimeter security
    if title_lower.contains("firewall")
        || title_lower.contains("network segmentation")
        || title_lower.contains("perimeter")
    {
        mappings.push(("nerc-cip-005-r1".to_string(), Severity::Critical));
        mappings.push(("nerc-cip-005-r1.1".to_string(), Severity::High));
    }

    // Logging and monitoring issues
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("monitoring")
    {
        mappings.push(("nerc-cip-007-r4".to_string(), Severity::High));
        mappings.push(("nerc-cip-007-r4.1".to_string(), Severity::Medium));
        mappings.push(("nerc-cip-007-r4.2".to_string(), Severity::Medium));
    }

    // Configuration management
    if title_lower.contains("configuration")
        || title_lower.contains("misconfiguration")
        || title_lower.contains("hardening")
    {
        mappings.push(("nerc-cip-010-r1".to_string(), Severity::High));
        mappings.push(("nerc-cip-010-r1.1".to_string(), Severity::High));
        mappings.push(("nerc-cip-010-r2".to_string(), Severity::Medium));
    }

    // Vulnerability scanning
    if title_lower.contains("vulnerability")
        || title_lower.contains("cve")
        || title_lower.contains("exploit")
    {
        mappings.push(("nerc-cip-010-r3".to_string(), Severity::High));
    }

    // Unnecessary services and ports
    if title_lower.contains("unnecessary service")
        || title_lower.contains("open port")
        || title_lower.contains("unused service")
    {
        mappings.push(("nerc-cip-007-r1".to_string(), Severity::High));
    }

    // Physical security
    if title_lower.contains("physical")
        || title_lower.contains("badge")
        || title_lower.contains("access control")
    {
        mappings.push(("nerc-cip-006-r1".to_string(), Severity::High));
        mappings.push(("nerc-cip-006-r3".to_string(), Severity::Medium));
    }

    // Supply chain
    if title_lower.contains("supply chain")
        || title_lower.contains("vendor")
        || title_lower.contains("third party")
    {
        mappings.push(("nerc-cip-013-r1".to_string(), Severity::High));
        mappings.push(("nerc-cip-013-r1.2".to_string(), Severity::Medium));
    }

    // Account lockout issues
    if title_lower.contains("brute force")
        || title_lower.contains("lockout")
        || title_lower.contains("rate limit")
    {
        mappings.push(("nerc-cip-007-r5.6".to_string(), Severity::High));
    }

    // Port-based mappings for ICS/SCADA protocols
    match port {
        // Modbus
        Some(502) => {
            mappings.push(("nerc-cip-005-r1".to_string(), Severity::Critical));
            mappings.push(("nerc-cip-011-r1".to_string(), Severity::High));
        }
        // DNP3
        Some(20000) | Some(19999) => {
            mappings.push(("nerc-cip-005-r1".to_string(), Severity::Critical));
            mappings.push(("nerc-cip-012-r1".to_string(), Severity::Critical));
        }
        // IEC 61850 / GOOSE
        Some(102) => {
            mappings.push(("nerc-cip-005-r1".to_string(), Severity::Critical));
            mappings.push(("nerc-cip-012-r1".to_string(), Severity::Critical));
        }
        // IEC 60870-5-104
        Some(2404) => {
            mappings.push(("nerc-cip-005-r1".to_string(), Severity::Critical));
            mappings.push(("nerc-cip-012-r1".to_string(), Severity::Critical));
        }
        // OPC UA
        Some(4840) | Some(4843) => {
            mappings.push(("nerc-cip-005-r1".to_string(), Severity::High));
            mappings.push(("nerc-cip-011-r1".to_string(), Severity::Medium));
        }
        // Telnet (insecure remote access)
        Some(23) => {
            mappings.push(("nerc-cip-005-r2".to_string(), Severity::Critical));
            mappings.push(("nerc-cip-005-r2.2".to_string(), Severity::Critical));
        }
        // FTP (insecure file transfer)
        Some(21) => {
            mappings.push(("nerc-cip-011-r1".to_string(), Severity::High));
        }
        // RDP
        Some(3389) => {
            mappings.push(("nerc-cip-005-r2".to_string(), Severity::High));
            mappings.push(("nerc-cip-005-r2.3".to_string(), Severity::Critical));
        }
        // SSH
        Some(22) => {
            if title_lower.contains("weak") || title_lower.contains("vulnerable") {
                mappings.push(("nerc-cip-005-r2.2".to_string(), Severity::High));
            }
        }
        _ => {}
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
    fn test_all_controls_have_framework() {
        let controls = get_controls();
        for control in controls {
            assert_eq!(control.framework, ComplianceFramework::NercCip);
        }
    }

    #[test]
    fn test_categories_present() {
        let controls = get_controls();
        let categories: Vec<&str> = controls.iter().map(|c| c.category.as_str()).collect();

        assert!(categories.contains(&"BES Cyber System Categorization"));
        assert!(categories.contains(&"Security Management Controls"));
        assert!(categories.contains(&"Personnel and Training"));
        assert!(categories.contains(&"Electronic Security Perimeter"));
        assert!(categories.contains(&"Physical Security"));
        assert!(categories.contains(&"System Security Management"));
        assert!(categories.contains(&"Incident Reporting and Response"));
        assert!(categories.contains(&"Recovery Plans"));
        assert!(categories.contains(&"Configuration Change Management"));
        assert!(categories.contains(&"Information Protection"));
        assert!(categories.contains(&"Communications between Control Centers"));
        assert!(categories.contains(&"Supply Chain Risk Management"));
        assert!(categories.contains(&"Physical Security (Transmission)"));
    }

    #[test]
    fn test_vulnerability_mapping_remote_access() {
        let mappings = map_vulnerability("Remote access vulnerability in VPN", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("cip-005-r2")));
    }

    #[test]
    fn test_vulnerability_mapping_authentication() {
        let mappings = map_vulnerability("Default password on device", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("cip-007-r5")));
    }

    #[test]
    fn test_vulnerability_mapping_modbus_port() {
        let mappings = map_vulnerability("Exposed Modbus service", None, Some(502), Some("modbus"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("cip-005-r1")));
    }

    #[test]
    fn test_vulnerability_mapping_dnp3_port() {
        let mappings = map_vulnerability("DNP3 communication exposed", None, Some(20000), Some("dnp3"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("cip-012-r1")));
    }

    #[test]
    fn test_vulnerability_mapping_patch() {
        let mappings = map_vulnerability("Unpatched system component", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("cip-007-r2")));
    }

    #[test]
    fn test_critical_controls_present() {
        let controls = get_controls();
        let critical_controls: Vec<_> = controls
            .iter()
            .filter(|c| c.priority == ControlPriority::Critical)
            .collect();

        // Ensure we have critical controls across key areas
        assert!(critical_controls.iter().any(|c| c.category.contains("Electronic Security")));
        assert!(critical_controls.iter().any(|c| c.category.contains("System Security")));
        assert!(critical_controls.iter().any(|c| c.category.contains("Incident")));
    }
}
