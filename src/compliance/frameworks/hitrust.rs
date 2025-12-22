//! HITRUST CSF (Common Security Framework) Controls
//!
//! HITRUST CSF is a comprehensive, certifiable framework that provides organizations
//! with a prescriptive set of controls that meet the requirements of multiple
//! regulations and standards. It harmonizes HIPAA, NIST, PCI-DSS, ISO 27001, and more.
//!
//! Based on HITRUST CSF v11.3 with 19 domains and 156+ control specifications.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of HITRUST CSF controls in this module
pub const CONTROL_COUNT: usize = 156;

/// Get all HITRUST CSF controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================================
        // Domain 0: Information Security Management Program
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-00.a".to_string(),
            control_id: "00.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Information Security Management Program".to_string(),
            description: "An information security management program shall be established and maintained.".to_string(),
            category: "Information Security Management Program".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-1".to_string(), "ISO-5.1".to_string()],
            remediation_guidance: Some("Establish a formal ISMP with executive sponsorship, policies, and procedures.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-00.b".to_string(),
            control_id: "00.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Risk Management Program".to_string(),
            description: "A risk management program shall be implemented to identify, assess, and mitigate risks.".to_string(),
            category: "Information Security Management Program".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-1".to_string(), "HIPAA-164.308(a)(1)(ii)(A)".to_string()],
            remediation_guidance: Some("Implement continuous risk assessment and treatment processes.".to_string()),
        },

        // ============================================================================
        // Domain 1: Access Control
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-01.a".to_string(),
            control_id: "01.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Access Control Policy".to_string(),
            description: "An access control policy shall be established, documented, and reviewed.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-1".to_string(), "HIPAA-164.312(a)(1)".to_string(), "PCI-DSS-7.1".to_string()],
            remediation_guidance: Some("Document access control policies aligned with business requirements.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.b".to_string(),
            control_id: "01.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "User Registration and Deregistration".to_string(),
            description: "A formal user registration and de-registration process shall be implemented.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "HIPAA-164.308(a)(3)(ii)(C)".to_string()],
            remediation_guidance: Some("Implement automated provisioning and timely de-provisioning of user accounts.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.c".to_string(),
            control_id: "01.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Privilege Management".to_string(),
            description: "The allocation and use of privileged access rights shall be restricted and controlled.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "PCI-DSS-7.2".to_string()],
            remediation_guidance: Some("Implement least privilege principle and regularly review privileged access.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.d".to_string(),
            control_id: "01.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "User Access Provisioning".to_string(),
            description: "A formal user access provisioning process shall be implemented.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string()],
            remediation_guidance: Some("Implement role-based access control with formal approval workflows.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.e".to_string(),
            control_id: "01.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Review of User Access Rights".to_string(),
            description: "Access rights shall be reviewed at regular intervals.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "HIPAA-164.308(a)(4)(ii)(C)".to_string()],
            remediation_guidance: Some("Conduct quarterly access reviews with documented attestation.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.f".to_string(),
            control_id: "01.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Removal or Adjustment of Access Rights".to_string(),
            description: "Access rights shall be removed upon termination or adjusted upon role change.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "HIPAA-164.308(a)(3)(ii)(C)".to_string()],
            remediation_guidance: Some("Implement immediate access revocation upon termination.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.g".to_string(),
            control_id: "01.g".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Password Management".to_string(),
            description: "Password management processes shall enforce strong password requirements.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "HIPAA-164.308(a)(5)(ii)(D)".to_string(), "PCI-DSS-8.3".to_string()],
            remediation_guidance: Some("Enforce password complexity, length, and rotation policies.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.h".to_string(),
            control_id: "01.h".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Secure Log-on Procedures".to_string(),
            description: "Access to systems shall be controlled by secure log-on procedures.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-7".to_string(), "HIPAA-164.308(a)(5)(ii)(C)".to_string()],
            remediation_guidance: Some("Implement account lockout, failed login monitoring, and MFA.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.i".to_string(),
            control_id: "01.i".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "User Identification and Authentication".to_string(),
            description: "All users shall have a unique identifier and shall authenticate before access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "HIPAA-164.312(a)(2)(i)".to_string(), "PCI-DSS-8.1".to_string()],
            remediation_guidance: Some("Ensure unique user IDs and prohibit shared accounts.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.j".to_string(),
            control_id: "01.j".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Session Time-out".to_string(),
            description: "Inactive sessions shall time out after a defined period.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-11".to_string(), "HIPAA-164.312(a)(2)(iii)".to_string()],
            remediation_guidance: Some("Configure 15-minute session timeout for sensitive systems.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.k".to_string(),
            control_id: "01.k".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Multi-Factor Authentication".to_string(),
            description: "Multi-factor authentication shall be implemented for remote and privileged access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "HIPAA-164.312(d)".to_string(), "PCI-DSS-8.4".to_string()],
            remediation_guidance: Some("Implement MFA for all remote access and privileged operations.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.l".to_string(),
            control_id: "01.l".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Network Access Control".to_string(),
            description: "Access to networks and network services shall be controlled.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "PCI-DSS-1.2".to_string()],
            remediation_guidance: Some("Implement network segmentation and access controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.m".to_string(),
            control_id: "01.m".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Remote Access".to_string(),
            description: "Remote access to systems shall be secured and monitored.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string(), "HIPAA-164.312(e)(1)".to_string()],
            remediation_guidance: Some("Use VPN with strong encryption for all remote access.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-01.n".to_string(),
            control_id: "01.n".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Wireless Access".to_string(),
            description: "Wireless access shall be secured using strong authentication and encryption.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-18".to_string(), "PCI-DSS-4.1.1".to_string()],
            remediation_guidance: Some("Use WPA3 or WPA2-Enterprise with certificate-based authentication.".to_string()),
        },

        // ============================================================================
        // Domain 2: Human Resources Security
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-02.a".to_string(),
            control_id: "02.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Roles and Responsibilities".to_string(),
            description: "Security roles and responsibilities shall be defined and communicated.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-1".to_string()],
            remediation_guidance: Some("Document security responsibilities in job descriptions.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-02.b".to_string(),
            control_id: "02.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Background Screening".to_string(),
            description: "Background verification checks shall be carried out for all candidates.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-3".to_string(), "HIPAA-164.308(a)(3)(ii)(B)".to_string()],
            remediation_guidance: Some("Conduct background checks commensurate with access level.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-02.c".to_string(),
            control_id: "02.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Terms and Conditions of Employment".to_string(),
            description: "Employment agreements shall state security responsibilities.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-4".to_string()],
            remediation_guidance: Some("Include confidentiality and security clauses in employment contracts.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-02.d".to_string(),
            control_id: "02.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Security Awareness Training".to_string(),
            description: "All employees shall receive appropriate security awareness training.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "HIPAA-164.308(a)(5)(i)".to_string(), "PCI-DSS-12.6".to_string()],
            remediation_guidance: Some("Conduct annual security awareness training with phishing simulations.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-02.e".to_string(),
            control_id: "02.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Disciplinary Process".to_string(),
            description: "A formal disciplinary process shall exist for security violations.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-8".to_string(), "HIPAA-164.308(a)(1)(ii)(C)".to_string()],
            remediation_guidance: Some("Document and communicate disciplinary procedures for policy violations.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-02.f".to_string(),
            control_id: "02.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Termination Responsibilities".to_string(),
            description: "Security responsibilities upon termination shall be defined and enforced.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-4".to_string(), "HIPAA-164.308(a)(3)(ii)(C)".to_string()],
            remediation_guidance: Some("Implement exit procedures including asset return and access revocation.".to_string()),
        },

        // ============================================================================
        // Domain 3: Risk Management
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-03.a".to_string(),
            control_id: "03.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Risk Assessment".to_string(),
            description: "Risk assessments shall be performed to identify threats and vulnerabilities.".to_string(),
            category: "Risk Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string(), "HIPAA-164.308(a)(1)(ii)(A)".to_string()],
            remediation_guidance: Some("Conduct annual risk assessments and after significant changes.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-03.b".to_string(),
            control_id: "03.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Risk Treatment".to_string(),
            description: "Identified risks shall be treated according to risk treatment options.".to_string(),
            category: "Risk Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-7".to_string(), "HIPAA-164.308(a)(1)(ii)(B)".to_string()],
            remediation_guidance: Some("Document risk treatment decisions with risk acceptance sign-off.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-03.c".to_string(),
            control_id: "03.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Vulnerability Management".to_string(),
            description: "Technical vulnerabilities shall be identified and remediated timely.".to_string(),
            category: "Risk Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string(), "PCI-DSS-6.1".to_string()],
            remediation_guidance: Some("Perform regular vulnerability scans and remediate based on severity.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-03.d".to_string(),
            control_id: "03.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Penetration Testing".to_string(),
            description: "Penetration testing shall be performed periodically.".to_string(),
            category: "Risk Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CA-8".to_string(), "PCI-DSS-11.3".to_string()],
            remediation_guidance: Some("Conduct annual penetration testing by qualified testers.".to_string()),
        },

        // ============================================================================
        // Domain 4: Security Policy
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-04.a".to_string(),
            control_id: "04.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Information Security Policy".to_string(),
            description: "An information security policy shall be defined and approved by management.".to_string(),
            category: "Security Policy".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-1".to_string(), "HIPAA-164.308(a)(1)(i)".to_string()],
            remediation_guidance: Some("Establish comprehensive security policies with executive approval.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-04.b".to_string(),
            control_id: "04.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Policy Review".to_string(),
            description: "Security policies shall be reviewed at planned intervals.".to_string(),
            category: "Security Policy".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-1".to_string()],
            remediation_guidance: Some("Review policies annually or after significant changes.".to_string()),
        },

        // ============================================================================
        // Domain 5: Organization of Information Security
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-05.a".to_string(),
            control_id: "05.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Information Security Roles".to_string(),
            description: "Information security responsibilities shall be defined and allocated.".to_string(),
            category: "Organization of Information Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-2".to_string(), "HIPAA-164.308(a)(2)".to_string()],
            remediation_guidance: Some("Designate CISO and security committee with clear responsibilities.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-05.b".to_string(),
            control_id: "05.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Segregation of Duties".to_string(),
            description: "Conflicting duties shall be segregated to reduce opportunities for misuse.".to_string(),
            category: "Organization of Information Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-5".to_string(), "PCI-DSS-6.4.2".to_string()],
            remediation_guidance: Some("Separate development, testing, and production environments and duties.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-05.c".to_string(),
            control_id: "05.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Contact with Authorities".to_string(),
            description: "Appropriate contacts with relevant authorities shall be maintained.".to_string(),
            category: "Organization of Information Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Maintain contact list for law enforcement and regulators.".to_string()),
        },

        // ============================================================================
        // Domain 6: Compliance
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-06.a".to_string(),
            control_id: "06.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Identification of Applicable Legislation".to_string(),
            description: "All relevant statutory and regulatory requirements shall be identified.".to_string(),
            category: "Compliance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string()],
            remediation_guidance: Some("Maintain a compliance obligations register.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-06.b".to_string(),
            control_id: "06.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Intellectual Property Rights".to_string(),
            description: "Procedures shall ensure compliance with intellectual property requirements.".to_string(),
            category: "Compliance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement software asset management and license tracking.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-06.c".to_string(),
            control_id: "06.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Protection of Records".to_string(),
            description: "Records shall be protected from loss, destruction, and falsification.".to_string(),
            category: "Compliance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string()],
            remediation_guidance: Some("Implement tamper-evident audit logging and secure backup.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-06.d".to_string(),
            control_id: "06.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Privacy and PII Protection".to_string(),
            description: "Privacy and protection of PII shall be ensured per applicable legislation.".to_string(),
            category: "Compliance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["HIPAA-164.502".to_string()],
            remediation_guidance: Some("Implement privacy by design and data minimization principles.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-06.e".to_string(),
            control_id: "06.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Independent Security Review".to_string(),
            description: "The organization's security approach shall be independently reviewed.".to_string(),
            category: "Compliance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CA-7".to_string()],
            remediation_guidance: Some("Conduct annual third-party security assessments.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-06.f".to_string(),
            control_id: "06.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Technical Compliance Checking".to_string(),
            description: "Information systems shall be regularly checked for technical compliance.".to_string(),
            category: "Compliance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CA-2".to_string(), "PCI-DSS-11.2".to_string()],
            remediation_guidance: Some("Implement automated compliance scanning and monitoring.".to_string()),
        },

        // ============================================================================
        // Domain 7: Asset Management
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-07.a".to_string(),
            control_id: "07.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Inventory of Assets".to_string(),
            description: "Assets associated with information shall be identified and inventoried.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "PCI-DSS-2.4".to_string()],
            remediation_guidance: Some("Maintain complete asset inventory with ownership and classification.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-07.b".to_string(),
            control_id: "07.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Ownership of Assets".to_string(),
            description: "Assets shall have an owner who is accountable for their protection.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string()],
            remediation_guidance: Some("Assign and document asset owners for all critical systems.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-07.c".to_string(),
            control_id: "07.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Classification of Information".to_string(),
            description: "Information shall be classified according to its sensitivity.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-2".to_string()],
            remediation_guidance: Some("Implement data classification scheme (Public, Internal, Confidential, PHI).".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-07.d".to_string(),
            control_id: "07.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Labeling of Information".to_string(),
            description: "An appropriate set of procedures for labeling shall be developed.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-3".to_string()],
            remediation_guidance: Some("Label documents and media according to classification level.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-07.e".to_string(),
            control_id: "07.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Handling of Assets".to_string(),
            description: "Procedures for handling assets shall be developed and implemented.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-4".to_string(), "HIPAA-164.310(d)(1)".to_string()],
            remediation_guidance: Some("Document handling procedures for each classification level.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-07.f".to_string(),
            control_id: "07.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Media Disposal".to_string(),
            description: "Media shall be disposed of securely when no longer required.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string(), "HIPAA-164.310(d)(2)(i)".to_string()],
            remediation_guidance: Some("Implement secure media destruction with certificates of destruction.".to_string()),
        },

        // ============================================================================
        // Domain 8: Physical and Environmental Security
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-08.a".to_string(),
            control_id: "08.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Physical Security Perimeter".to_string(),
            description: "Physical security perimeters shall be defined to protect sensitive areas.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string(), "HIPAA-164.310(a)(1)".to_string(), "PCI-DSS-9.1".to_string()],
            remediation_guidance: Some("Define and secure physical security zones with appropriate controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-08.b".to_string(),
            control_id: "08.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Physical Entry Controls".to_string(),
            description: "Secure areas shall be protected by appropriate entry controls.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string(), "HIPAA-164.310(a)(2)(iii)".to_string(), "PCI-DSS-9.1".to_string()],
            remediation_guidance: Some("Implement badge access, biometrics, and visitor management.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-08.c".to_string(),
            control_id: "08.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Securing Offices and Rooms".to_string(),
            description: "Physical security for offices and rooms shall be designed and applied.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-5".to_string()],
            remediation_guidance: Some("Secure server rooms and sensitive areas with additional controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-08.d".to_string(),
            control_id: "08.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Protecting Against External Threats".to_string(),
            description: "Physical protection against natural disasters and attacks shall be applied.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-15".to_string()],
            remediation_guidance: Some("Implement fire suppression, flood protection, and environmental controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-08.e".to_string(),
            control_id: "08.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Working in Secure Areas".to_string(),
            description: "Procedures for working in secure areas shall be designed and applied.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-18".to_string()],
            remediation_guidance: Some("Define and enforce secure area working procedures.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-08.f".to_string(),
            control_id: "08.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Equipment Siting and Protection".to_string(),
            description: "Equipment shall be sited and protected to reduce environmental threats.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-14".to_string()],
            remediation_guidance: Some("Install equipment in climate-controlled, secured locations.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-08.g".to_string(),
            control_id: "08.g".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Supporting Utilities".to_string(),
            description: "Equipment shall be protected from power failures and other disruptions.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-11".to_string()],
            remediation_guidance: Some("Install UPS and backup generators for critical systems.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-08.h".to_string(),
            control_id: "08.h".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Cabling Security".to_string(),
            description: "Power and telecommunications cabling shall be protected from damage.".to_string(),
            category: "Physical and Environmental Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-9".to_string()],
            remediation_guidance: Some("Protect and secure network cabling from unauthorized access.".to_string()),
        },

        // ============================================================================
        // Domain 9: Communications and Operations Management
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-09.a".to_string(),
            control_id: "09.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Documented Operating Procedures".to_string(),
            description: "Operating procedures shall be documented and made available.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-5".to_string()],
            remediation_guidance: Some("Document and maintain operational procedures for critical systems.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.b".to_string(),
            control_id: "09.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Change Management".to_string(),
            description: "Changes to systems and facilities shall be controlled.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "PCI-DSS-6.4".to_string()],
            remediation_guidance: Some("Implement formal change management with testing and approval.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.c".to_string(),
            control_id: "09.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Separation of Development and Production".to_string(),
            description: "Development, testing, and production shall be separated.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-4".to_string(), "PCI-DSS-6.4.1".to_string()],
            remediation_guidance: Some("Maintain separate environments with appropriate access controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.d".to_string(),
            control_id: "09.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Third-Party Service Delivery".to_string(),
            description: "Service delivery by third parties shall be monitored and reviewed.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string(), "HIPAA-164.308(b)(1)".to_string()],
            remediation_guidance: Some("Monitor third-party services and review security compliance.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.e".to_string(),
            control_id: "09.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Capacity Management".to_string(),
            description: "Resource use shall be monitored and capacity projections made.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-2".to_string()],
            remediation_guidance: Some("Monitor system capacity and plan for growth.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.f".to_string(),
            control_id: "09.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "System Acceptance".to_string(),
            description: "Acceptance criteria shall be established for new systems.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string()],
            remediation_guidance: Some("Define and test acceptance criteria before production deployment.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.g".to_string(),
            control_id: "09.g".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Malware Protection".to_string(),
            description: "Detection, prevention, and recovery controls for malware shall be implemented.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "HIPAA-164.308(a)(5)(ii)(B)".to_string(), "PCI-DSS-5.1".to_string()],
            remediation_guidance: Some("Deploy anti-malware with real-time protection and regular updates.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.h".to_string(),
            control_id: "09.h".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Information Backup".to_string(),
            description: "Backup copies of information and software shall be taken and tested.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-9".to_string(), "HIPAA-164.308(a)(7)(ii)(A)".to_string()],
            remediation_guidance: Some("Implement automated encrypted backups with regular testing.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.i".to_string(),
            control_id: "09.i".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Event Logging".to_string(),
            description: "Event logs shall record user activities, exceptions, and security events.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "HIPAA-164.312(b)".to_string(), "PCI-DSS-10.1".to_string()],
            remediation_guidance: Some("Implement comprehensive logging of security-relevant events.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.j".to_string(),
            control_id: "09.j".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Protection of Log Information".to_string(),
            description: "Logging facilities and log information shall be protected.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string(), "PCI-DSS-10.5".to_string()],
            remediation_guidance: Some("Protect logs from unauthorized access and tampering.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.k".to_string(),
            control_id: "09.k".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Administrator and Operator Logs".to_string(),
            description: "System administrator and operator activities shall be logged.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-12".to_string(), "PCI-DSS-10.2.2".to_string()],
            remediation_guidance: Some("Log all administrative and privileged operations.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.l".to_string(),
            control_id: "09.l".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Clock Synchronization".to_string(),
            description: "Clocks of all relevant systems shall be synchronized.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-8".to_string(), "PCI-DSS-10.4".to_string()],
            remediation_guidance: Some("Synchronize all systems using NTP with accurate time sources.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.m".to_string(),
            control_id: "09.m".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Network Security Management".to_string(),
            description: "Networks shall be managed and controlled to protect information.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.1".to_string()],
            remediation_guidance: Some("Implement network segmentation and security monitoring.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.n".to_string(),
            control_id: "09.n".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Security of Network Services".to_string(),
            description: "Security features and service levels of network services shall be identified.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Document and monitor network service security requirements.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.o".to_string(),
            control_id: "09.o".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Network Segregation".to_string(),
            description: "Groups of information services, users, and systems shall be segregated.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.3".to_string()],
            remediation_guidance: Some("Segment networks based on sensitivity and access requirements.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.p".to_string(),
            control_id: "09.p".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Media Handling".to_string(),
            description: "Procedures shall be established for the management of removable media.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-4".to_string()],
            remediation_guidance: Some("Control and track removable media with encryption requirements.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.q".to_string(),
            control_id: "09.q".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Information Transfer Policies".to_string(),
            description: "Formal transfer policies and procedures shall protect information exchange.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "HIPAA-164.312(e)(1)".to_string()],
            remediation_guidance: Some("Encrypt data in transit and establish secure transfer procedures.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.r".to_string(),
            control_id: "09.r".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Electronic Messaging".to_string(),
            description: "Information involved in electronic messaging shall be protected.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Implement email encryption and secure messaging systems.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-09.s".to_string(),
            control_id: "09.s".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "E-commerce Services".to_string(),
            description: "Information in e-commerce transactions shall be protected.".to_string(),
            category: "Communications and Operations Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["PCI-DSS-6.6".to_string()],
            remediation_guidance: Some("Implement secure e-commerce with TLS and input validation.".to_string()),
        },

        // ============================================================================
        // Domain 10: Information Systems Acquisition, Development, and Maintenance
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-10.a".to_string(),
            control_id: "10.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Security Requirements Analysis".to_string(),
            description: "Security requirements shall be included in requirements for new systems.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-3".to_string(), "PCI-DSS-6.3".to_string()],
            remediation_guidance: Some("Include security in requirements and design phases.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.b".to_string(),
            control_id: "10.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Securing Application Services".to_string(),
            description: "Information in application services shall be protected from threats.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-8".to_string()],
            remediation_guidance: Some("Implement secure coding practices and application security testing.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.c".to_string(),
            control_id: "10.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Protection of Application Transactions".to_string(),
            description: "Application transactions shall be protected from incomplete transmission.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Implement transaction integrity controls and error handling.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.d".to_string(),
            control_id: "10.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Secure Development Policy".to_string(),
            description: "Rules for development of software and systems shall be established.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-3".to_string(), "PCI-DSS-6.3".to_string()],
            remediation_guidance: Some("Establish secure SDLC with security gates and reviews.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.e".to_string(),
            control_id: "10.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "System Change Control".to_string(),
            description: "Changes to systems shall be controlled using change management procedures.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "PCI-DSS-6.4".to_string()],
            remediation_guidance: Some("Implement formal change control with testing and approval.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.f".to_string(),
            control_id: "10.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Review of Applications After Platform Changes".to_string(),
            description: "Applications shall be reviewed and tested after platform changes.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-4".to_string()],
            remediation_guidance: Some("Test applications after operating platform changes.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.g".to_string(),
            control_id: "10.g".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Restrictions on Software Packages Changes".to_string(),
            description: "Modifications to software packages shall be discouraged and controlled.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-5".to_string()],
            remediation_guidance: Some("Control vendor package modifications with documented justification.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.h".to_string(),
            control_id: "10.h".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Secure System Engineering Principles".to_string(),
            description: "Principles for engineering secure systems shall be established and applied.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-8".to_string()],
            remediation_guidance: Some("Apply defense in depth and secure design principles.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.i".to_string(),
            control_id: "10.i".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Secure Development Environment".to_string(),
            description: "Organizations shall establish secure development environments.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-3".to_string()],
            remediation_guidance: Some("Secure development tools and environments.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.j".to_string(),
            control_id: "10.j".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Outsourced Development".to_string(),
            description: "Outsourced development shall be supervised and monitored.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string()],
            remediation_guidance: Some("Include security requirements in outsourcing contracts.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.k".to_string(),
            control_id: "10.k".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "System Security Testing".to_string(),
            description: "Security functionality testing shall be carried out during development.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string(), "PCI-DSS-6.5".to_string()],
            remediation_guidance: Some("Perform security testing including SAST, DAST, and penetration testing.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.l".to_string(),
            control_id: "10.l".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "System Acceptance Testing".to_string(),
            description: "Acceptance testing shall be established for new systems and upgrades.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string()],
            remediation_guidance: Some("Define acceptance criteria including security requirements.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-10.m".to_string(),
            control_id: "10.m".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Protection of Test Data".to_string(),
            description: "Test data shall be selected carefully and protected.".to_string(),
            category: "Information Systems Acquisition, Development, and Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-15".to_string()],
            remediation_guidance: Some("Use synthetic or anonymized data for testing. Never use production PHI.".to_string()),
        },

        // ============================================================================
        // Domain 11: Information Security Incident Management
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-11.a".to_string(),
            control_id: "11.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Responsibilities and Procedures".to_string(),
            description: "Management responsibilities and procedures for incidents shall be established.".to_string(),
            category: "Information Security Incident Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string(), "HIPAA-164.308(a)(6)(i)".to_string()],
            remediation_guidance: Some("Document incident response procedures with defined roles.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-11.b".to_string(),
            control_id: "11.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Reporting Security Events".to_string(),
            description: "Security events shall be reported through appropriate channels.".to_string(),
            category: "Information Security Incident Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string(), "HIPAA-164.308(a)(6)(ii)".to_string()],
            remediation_guidance: Some("Establish clear incident reporting procedures and escalation paths.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-11.c".to_string(),
            control_id: "11.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Reporting Security Weaknesses".to_string(),
            description: "Employees shall report observed or suspected security weaknesses.".to_string(),
            category: "Information Security Incident Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Provide secure channels for reporting security concerns.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-11.d".to_string(),
            control_id: "11.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Assessment and Decision on Events".to_string(),
            description: "Security events shall be assessed to determine if they are incidents.".to_string(),
            category: "Information Security Incident Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Define incident classification criteria and escalation thresholds.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-11.e".to_string(),
            control_id: "11.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Response to Security Incidents".to_string(),
            description: "Security incidents shall be responded to in accordance with procedures.".to_string(),
            category: "Information Security Incident Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Execute incident response procedures promptly.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-11.f".to_string(),
            control_id: "11.f".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Learning from Security Incidents".to_string(),
            description: "Knowledge gained from incidents shall be used to reduce future likelihood.".to_string(),
            category: "Information Security Incident Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Conduct post-incident reviews and implement lessons learned.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-11.g".to_string(),
            control_id: "11.g".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Collection of Evidence".to_string(),
            description: "Procedures for evidence collection shall be defined and followed.".to_string(),
            category: "Information Security Incident Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Follow chain of custody procedures for forensic evidence.".to_string()),
        },

        // ============================================================================
        // Domain 12: Business Continuity Management
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-12.a".to_string(),
            control_id: "12.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Information Security in Business Continuity".to_string(),
            description: "Information security shall be embedded in business continuity plans.".to_string(),
            category: "Business Continuity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-1".to_string(), "HIPAA-164.308(a)(7)(i)".to_string()],
            remediation_guidance: Some("Include security requirements in BCP and DR planning.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-12.b".to_string(),
            control_id: "12.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Business Continuity Planning".to_string(),
            description: "Business continuity plans shall address security requirements.".to_string(),
            category: "Business Continuity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-2".to_string()],
            remediation_guidance: Some("Develop documented BCP with RTO/RPO requirements.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-12.c".to_string(),
            control_id: "12.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Implementing Business Continuity Plans".to_string(),
            description: "Plans shall be implemented to maintain or restore operations.".to_string(),
            category: "Business Continuity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-10".to_string(), "HIPAA-164.308(a)(7)(ii)(B)".to_string()],
            remediation_guidance: Some("Implement DR capabilities to meet recovery objectives.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-12.d".to_string(),
            control_id: "12.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Testing Business Continuity Plans".to_string(),
            description: "Business continuity plans shall be tested and updated regularly.".to_string(),
            category: "Business Continuity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-4".to_string(), "HIPAA-164.308(a)(7)(ii)(D)".to_string()],
            remediation_guidance: Some("Test DR plans at least annually with documented results.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-12.e".to_string(),
            control_id: "12.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Redundancy".to_string(),
            description: "Sufficient redundancy shall be implemented to meet availability requirements.".to_string(),
            category: "Business Continuity Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-7".to_string()],
            remediation_guidance: Some("Implement redundant systems and geographic distribution.".to_string()),
        },

        // ============================================================================
        // Domain 13: Privacy Practices
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-13.a".to_string(),
            control_id: "13.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Notice of Privacy Practices".to_string(),
            description: "A notice of privacy practices shall be maintained and provided.".to_string(),
            category: "Privacy Practices".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["HIPAA-164.520".to_string()],
            remediation_guidance: Some("Maintain current privacy notice and provide to patients/clients.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-13.b".to_string(),
            control_id: "13.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Uses and Disclosures".to_string(),
            description: "Uses and disclosures of PHI shall comply with policies.".to_string(),
            category: "Privacy Practices".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["HIPAA-164.502".to_string()],
            remediation_guidance: Some("Implement minimum necessary use and disclosure controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-13.c".to_string(),
            control_id: "13.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Individual Rights".to_string(),
            description: "Procedures shall be implemented to respond to individual rights requests.".to_string(),
            category: "Privacy Practices".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["HIPAA-164.524".to_string(), "HIPAA-164.526".to_string()],
            remediation_guidance: Some("Implement processes for access, amendment, and accounting of disclosures.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-13.d".to_string(),
            control_id: "13.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Authorization".to_string(),
            description: "Valid authorizations shall be obtained when required.".to_string(),
            category: "Privacy Practices".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["HIPAA-164.508".to_string()],
            remediation_guidance: Some("Obtain and document valid authorization for non-TPO disclosures.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-13.e".to_string(),
            control_id: "13.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Minimum Necessary".to_string(),
            description: "The minimum necessary PHI shall be used or disclosed.".to_string(),
            category: "Privacy Practices".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["HIPAA-164.502(b)".to_string()],
            remediation_guidance: Some("Implement role-based access limiting PHI exposure to job requirements.".to_string()),
        },

        // ============================================================================
        // Domain 14: Cryptography
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-14.a".to_string(),
            control_id: "14.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Policy on Use of Cryptographic Controls".to_string(),
            description: "A policy on use of cryptographic controls shall be developed.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string()],
            remediation_guidance: Some("Document cryptographic standards and approved algorithms.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-14.b".to_string(),
            control_id: "14.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Encryption".to_string(),
            description: "Encryption shall be used to protect sensitive information.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "HIPAA-164.312(a)(2)(iv)".to_string(), "PCI-DSS-3.4".to_string()],
            remediation_guidance: Some("Encrypt PHI at rest and in transit using AES-256.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-14.c".to_string(),
            control_id: "14.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Key Management".to_string(),
            description: "A policy on the use of cryptographic keys shall be developed.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string(), "PCI-DSS-3.5".to_string()],
            remediation_guidance: Some("Implement key management with secure storage and rotation.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-14.d".to_string(),
            control_id: "14.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Transmission Security".to_string(),
            description: "Data in transit shall be protected using approved encryption.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "HIPAA-164.312(e)(1)".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Use TLS 1.2 or higher for all data transmission.".to_string()),
        },

        // ============================================================================
        // Domain 15: Supplier Relationships
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-15.a".to_string(),
            control_id: "15.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Information Security in Supplier Relationships".to_string(),
            description: "Security requirements for mitigating supplier risks shall be agreed.".to_string(),
            category: "Supplier Relationships".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string(), "HIPAA-164.308(b)(1)".to_string()],
            remediation_guidance: Some("Include security requirements in supplier contracts.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-15.b".to_string(),
            control_id: "15.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Addressing Security in Supplier Agreements".to_string(),
            description: "Relevant security requirements shall be established in supplier agreements.".to_string(),
            category: "Supplier Relationships".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string()],
            remediation_guidance: Some("Require BAAs and security attestation from suppliers.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-15.c".to_string(),
            control_id: "15.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Supply Chain Security".to_string(),
            description: "Agreements shall address security risks in the supply chain.".to_string(),
            category: "Supplier Relationships".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SR-3".to_string()],
            remediation_guidance: Some("Assess supply chain risks and implement controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-15.d".to_string(),
            control_id: "15.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Monitoring Supplier Services".to_string(),
            description: "Organizations shall monitor and review supplier service delivery.".to_string(),
            category: "Supplier Relationships".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string()],
            remediation_guidance: Some("Conduct periodic security reviews of critical suppliers.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-15.e".to_string(),
            control_id: "15.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Managing Changes to Supplier Services".to_string(),
            description: "Changes to supplier services shall be managed.".to_string(),
            category: "Supplier Relationships".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string()],
            remediation_guidance: Some("Review and approve changes to supplier services.".to_string()),
        },

        // ============================================================================
        // Domain 16: Mobile Devices and Teleworking
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-16.a".to_string(),
            control_id: "16.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Mobile Device Policy".to_string(),
            description: "A policy and supporting measures shall manage risks from mobile devices.".to_string(),
            category: "Mobile Devices and Teleworking".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-19".to_string()],
            remediation_guidance: Some("Implement MDM with encryption, remote wipe, and app controls.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-16.b".to_string(),
            control_id: "16.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Teleworking".to_string(),
            description: "A policy and measures shall protect information accessed remotely.".to_string(),
            category: "Mobile Devices and Teleworking".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Require VPN, MFA, and secure endpoint for remote work.".to_string()),
        },

        // ============================================================================
        // Domain 17: Endpoint Protection
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-17.a".to_string(),
            control_id: "17.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Endpoint Detection and Response".to_string(),
            description: "Endpoint detection and response capabilities shall be deployed.".to_string(),
            category: "Endpoint Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Deploy EDR solution with real-time threat detection.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-17.b".to_string(),
            control_id: "17.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Endpoint Hardening".to_string(),
            description: "Endpoints shall be hardened according to security baselines.".to_string(),
            category: "Endpoint Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string(), "CIS-4".to_string()],
            remediation_guidance: Some("Apply CIS benchmarks and disable unnecessary services.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-17.c".to_string(),
            control_id: "17.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Patch Management".to_string(),
            description: "Patches shall be applied in a timely manner.".to_string(),
            category: "Endpoint Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Implement automated patch management with SLAs based on severity.".to_string()),
        },

        // ============================================================================
        // Domain 18: Configuration Management
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-18.a".to_string(),
            control_id: "18.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Baseline Configurations".to_string(),
            description: "Baseline configurations for systems shall be developed and maintained.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string(), "PCI-DSS-2.2".to_string()],
            remediation_guidance: Some("Document and enforce secure baseline configurations.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-18.b".to_string(),
            control_id: "18.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Configuration Change Control".to_string(),
            description: "Changes to configurations shall be documented and controlled.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string()],
            remediation_guidance: Some("Implement change tracking and drift detection.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-18.c".to_string(),
            control_id: "18.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Least Functionality".to_string(),
            description: "Systems shall be configured to provide only essential capabilities.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "PCI-DSS-2.2.2".to_string()],
            remediation_guidance: Some("Disable unnecessary ports, protocols, and services.".to_string()),
        },

        // ============================================================================
        // Domain 19: Network Security
        // ============================================================================
        ComplianceControl {
            id: "HITRUST-19.a".to_string(),
            control_id: "19.a".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Boundary Protection".to_string(),
            description: "Communications at external boundaries shall be monitored and controlled.".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.1".to_string()],
            remediation_guidance: Some("Deploy and configure firewalls at network boundaries.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-19.b".to_string(),
            control_id: "19.b".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Intrusion Detection and Prevention".to_string(),
            description: "Intrusion detection and prevention systems shall be deployed.".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "PCI-DSS-11.4".to_string()],
            remediation_guidance: Some("Deploy IDS/IPS with current signatures at critical points.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-19.c".to_string(),
            control_id: "19.c".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Denial of Service Protection".to_string(),
            description: "Systems shall be protected against denial of service attacks.".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-5".to_string()],
            remediation_guidance: Some("Implement DDoS protection and rate limiting.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-19.d".to_string(),
            control_id: "19.d".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "Web Filtering".to_string(),
            description: "Web traffic shall be filtered to block malicious content.".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Deploy web proxy with content filtering and malware scanning.".to_string()),
        },
        ComplianceControl {
            id: "HITRUST-19.e".to_string(),
            control_id: "19.e".to_string(),
            framework: ComplianceFramework::HitrustCsf,
            title: "DNS Security".to_string(),
            description: "DNS services shall be protected and monitored.".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-20".to_string()],
            remediation_guidance: Some("Implement DNSSEC and DNS filtering for malicious domains.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant HITRUST CSF controls
pub fn map_vulnerability(
    vuln_title: &str,
    cve_id: Option<&str>,
    port: Option<u16>,
    service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();
    let service_lower = service.map(|s| s.to_lowercase()).unwrap_or_default();

    // Access Control issues
    if title_lower.contains("unauthorized access")
        || title_lower.contains("authentication bypass")
        || title_lower.contains("broken authentication")
    {
        mappings.push(("HITRUST-01.a".to_string(), Severity::Critical));
        mappings.push(("HITRUST-01.i".to_string(), Severity::Critical));
        mappings.push(("HITRUST-01.k".to_string(), Severity::High));
    }

    // Password and credential issues
    if title_lower.contains("weak password")
        || title_lower.contains("default password")
        || title_lower.contains("default credential")
        || title_lower.contains("hardcoded")
    {
        mappings.push(("HITRUST-01.g".to_string(), Severity::High));
        mappings.push(("HITRUST-01.h".to_string(), Severity::High));
    }

    // Session management
    if title_lower.contains("session")
        || title_lower.contains("timeout")
        || title_lower.contains("token")
    {
        mappings.push(("HITRUST-01.j".to_string(), Severity::Medium));
    }

    // Encryption and TLS issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("weak cipher")
        || title_lower.contains("weak crypto")
    {
        mappings.push(("HITRUST-14.b".to_string(), Severity::High));
        mappings.push(("HITRUST-14.d".to_string(), Severity::High));
        mappings.push(("HITRUST-09.q".to_string(), Severity::High));
    }

    // Certificate issues
    if title_lower.contains("certificate")
        || title_lower.contains("cert expired")
        || title_lower.contains("self-signed")
    {
        mappings.push(("HITRUST-14.d".to_string(), Severity::High));
    }

    // Logging and monitoring issues
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("monitoring")
    {
        mappings.push(("HITRUST-09.i".to_string(), Severity::Medium));
        mappings.push(("HITRUST-09.j".to_string(), Severity::Medium));
    }

    // Malware and endpoint protection
    if title_lower.contains("malware")
        || title_lower.contains("antivirus")
        || title_lower.contains("ransomware")
    {
        mappings.push(("HITRUST-09.g".to_string(), Severity::High));
        mappings.push(("HITRUST-17.a".to_string(), Severity::High));
    }

    // Vulnerability and patching issues
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || cve_id.is_some()
    {
        mappings.push(("HITRUST-03.c".to_string(), Severity::High));
        mappings.push(("HITRUST-17.c".to_string(), Severity::High));
    }

    // Network security issues
    if title_lower.contains("firewall")
        || title_lower.contains("network segmentation")
        || title_lower.contains("exposed service")
    {
        mappings.push(("HITRUST-09.o".to_string(), Severity::High));
        mappings.push(("HITRUST-19.a".to_string(), Severity::High));
    }

    // Remote access and VPN issues
    if title_lower.contains("remote access")
        || title_lower.contains("vpn")
        || title_lower.contains("rdp exposed")
        || title_lower.contains("ssh exposed")
    {
        mappings.push(("HITRUST-01.m".to_string(), Severity::High));
        mappings.push(("HITRUST-16.b".to_string(), Severity::High));
    }

    // Wireless security
    if title_lower.contains("wireless")
        || title_lower.contains("wifi")
        || title_lower.contains("wpa")
    {
        mappings.push(("HITRUST-01.n".to_string(), Severity::High));
    }

    // Configuration issues
    if title_lower.contains("misconfigur")
        || title_lower.contains("insecure config")
        || title_lower.contains("default config")
    {
        mappings.push(("HITRUST-18.a".to_string(), Severity::Medium));
        mappings.push(("HITRUST-18.c".to_string(), Severity::Medium));
    }

    // Change management issues
    if title_lower.contains("unauthorized change")
        || title_lower.contains("drift")
    {
        mappings.push(("HITRUST-09.b".to_string(), Severity::High));
        mappings.push(("HITRUST-18.b".to_string(), Severity::Medium));
    }

    // Backup and recovery issues
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
        || title_lower.contains("disaster")
    {
        mappings.push(("HITRUST-09.h".to_string(), Severity::High));
        mappings.push(("HITRUST-12.c".to_string(), Severity::High));
    }

    // Web application vulnerabilities (OWASP Top 10)
    if title_lower.contains("injection")
        || title_lower.contains("sqli")
        || title_lower.contains("xss")
        || title_lower.contains("csrf")
    {
        mappings.push(("HITRUST-10.b".to_string(), Severity::Critical));
        mappings.push(("HITRUST-10.k".to_string(), Severity::High));
    }

    // Privacy and PHI exposure
    if title_lower.contains("phi")
        || title_lower.contains("pii")
        || title_lower.contains("data exposure")
        || title_lower.contains("data breach")
    {
        mappings.push(("HITRUST-06.d".to_string(), Severity::Critical));
        mappings.push(("HITRUST-13.b".to_string(), Severity::Critical));
        mappings.push(("HITRUST-13.e".to_string(), Severity::High));
    }

    // Healthcare-specific services
    if service_lower.contains("hl7")
        || service_lower.contains("dicom")
        || service_lower.contains("fhir")
        || port == Some(2575)
        || port == Some(104)
        || port == Some(11112)
    {
        mappings.push(("HITRUST-06.d".to_string(), Severity::Critical));
        mappings.push(("HITRUST-14.d".to_string(), Severity::Critical));
    }

    // Telnet and other insecure protocols
    if port == Some(23) || service_lower.contains("telnet") {
        mappings.push(("HITRUST-14.d".to_string(), Severity::High));
        mappings.push(("HITRUST-18.c".to_string(), Severity::High));
    }

    // FTP unencrypted
    if port == Some(21) || (service_lower.contains("ftp") && !service_lower.contains("sftp")) {
        mappings.push(("HITRUST-14.d".to_string(), Severity::High));
        mappings.push(("HITRUST-09.q".to_string(), Severity::High));
    }

    // SNMP weak versions
    if port == Some(161) || port == Some(162) || service_lower.contains("snmp") {
        if title_lower.contains("v1") || title_lower.contains("v2") {
            mappings.push(("HITRUST-09.m".to_string(), Severity::Medium));
        }
    }

    // Intrusion detection issues
    if title_lower.contains("intrusion")
        || title_lower.contains("ids")
        || title_lower.contains("ips")
    {
        mappings.push(("HITRUST-19.b".to_string(), Severity::High));
    }

    // DOS/DDOS vulnerabilities
    if title_lower.contains("denial of service")
        || title_lower.contains("dos")
        || title_lower.contains("ddos")
    {
        mappings.push(("HITRUST-19.c".to_string(), Severity::High));
    }

    mappings
}
