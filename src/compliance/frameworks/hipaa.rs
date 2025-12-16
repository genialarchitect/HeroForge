//! HIPAA Security Rule Controls
//!
//! Security standards for protecting electronic protected health information (ePHI).
//! Based on the HIPAA Security Rule (45 CFR Part 164, Subpart C).

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of HIPAA controls in this module
pub const CONTROL_COUNT: usize = 42;

/// Get all HIPAA Security Rule controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // Administrative Safeguards (164.308)
        ComplianceControl {
            id: "HIPAA-164.308(a)(1)(i)".to_string(),
            control_id: "164.308(a)(1)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Security Management Process".to_string(),
            description: "Implement policies and procedures to prevent, detect, contain, and correct security violations.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-1".to_string()],
            remediation_guidance: Some("Establish comprehensive security management program with documented policies.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(1)(ii)(A)".to_string(),
            control_id: "164.308(a)(1)(ii)(A)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Risk Analysis".to_string(),
            description: "Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(1)(i)".to_string()),
            cross_references: vec!["NIST-RA-3".to_string(), "CIS-7.1".to_string()],
            remediation_guidance: Some("Perform annual risk assessments covering all ePHI systems and processes.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(1)(ii)(B)".to_string(),
            control_id: "164.308(a)(1)(ii)(B)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Risk Management".to_string(),
            description: "Implement security measures to reduce risks and vulnerabilities to a reasonable and appropriate level.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(1)(i)".to_string()),
            cross_references: vec!["NIST-RA-7".to_string()],
            remediation_guidance: Some("Document risk treatment decisions and track remediation progress.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(1)(ii)(C)".to_string(),
            control_id: "164.308(a)(1)(ii)(C)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Sanction Policy".to_string(),
            description: "Apply appropriate sanctions against workforce members who fail to comply with security policies.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(1)(i)".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Document and communicate sanctions for security policy violations.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(1)(ii)(D)".to_string(),
            control_id: "164.308(a)(1)(ii)(D)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Information System Activity Review".to_string(),
            description: "Implement procedures to regularly review records of information system activity.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(1)(i)".to_string()),
            cross_references: vec!["NIST-AU-6".to_string(), "CIS-8.5".to_string()],
            remediation_guidance: Some("Review audit logs regularly and investigate anomalous activity.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(2)".to_string(),
            control_id: "164.308(a)(2)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Assigned Security Responsibility".to_string(),
            description: "Identify the security official responsible for developing and implementing security policies.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Designate a HIPAA Security Officer with documented responsibilities.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(3)(i)".to_string(),
            control_id: "164.308(a)(3)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Workforce Security".to_string(),
            description: "Implement policies to ensure workforce members have appropriate access to ePHI.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "CIS-5.1".to_string()],
            remediation_guidance: Some("Implement role-based access control for ePHI systems.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(3)(ii)(A)".to_string(),
            control_id: "164.308(a)(3)(ii)(A)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Authorization and/or Supervision".to_string(),
            description: "Implement procedures for authorizing and supervising workforce members who work with ePHI.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(3)(i)".to_string()),
            cross_references: vec!["NIST-AC-1".to_string()],
            remediation_guidance: Some("Document authorization procedures and supervision requirements.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(3)(ii)(B)".to_string(),
            control_id: "164.308(a)(3)(ii)(B)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Workforce Clearance Procedure".to_string(),
            description: "Implement procedures to determine appropriate access to ePHI for workforce members.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(3)(i)".to_string()),
            cross_references: vec!["NIST-AC-2".to_string()],
            remediation_guidance: Some("Implement background checks and access level determination process.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(3)(ii)(C)".to_string(),
            control_id: "164.308(a)(3)(ii)(C)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Termination Procedures".to_string(),
            description: "Implement procedures for terminating access to ePHI when employment ends.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(3)(i)".to_string()),
            cross_references: vec!["NIST-AC-2".to_string(), "CIS-6.2".to_string()],
            remediation_guidance: Some("Implement immediate access revocation upon employment termination.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(4)(i)".to_string(),
            control_id: "164.308(a)(4)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Information Access Management".to_string(),
            description: "Implement policies for authorizing access to ePHI consistent with the minimum necessary standard.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CIS-5.4".to_string()],
            remediation_guidance: Some("Implement least privilege access with documented access policies.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(4)(ii)(B)".to_string(),
            control_id: "164.308(a)(4)(ii)(B)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Access Authorization".to_string(),
            description: "Implement policies for granting access to ePHI through access to workstations and software.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(4)(i)".to_string()),
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Define formal access request and approval workflow.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(4)(ii)(C)".to_string(),
            control_id: "164.308(a)(4)(ii)(C)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Access Establishment and Modification".to_string(),
            description: "Implement policies for granting and modifying access based on role changes.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(4)(i)".to_string()),
            cross_references: vec!["NIST-AC-2".to_string()],
            remediation_guidance: Some("Implement access modification procedures triggered by role changes.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(5)(i)".to_string(),
            control_id: "164.308(a)(5)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Security Awareness and Training".to_string(),
            description: "Implement a security awareness and training program for all workforce members.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "PCI-DSS-12.6".to_string()],
            remediation_guidance: Some("Conduct annual HIPAA security awareness training for all staff.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(5)(ii)(A)".to_string(),
            control_id: "164.308(a)(5)(ii)(A)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Security Reminders".to_string(),
            description: "Implement procedures for periodic security reminders.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::Low,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(5)(i)".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Send regular security awareness communications to workforce.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(5)(ii)(B)".to_string(),
            control_id: "164.308(a)(5)(ii)(B)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Protection from Malicious Software".to_string(),
            description: "Implement procedures for guarding against, detecting, and reporting malicious software.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(5)(i)".to_string()),
            cross_references: vec!["NIST-SI-3".to_string(), "CIS-10.1".to_string()],
            remediation_guidance: Some("Deploy and maintain anti-malware software on all endpoints.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(5)(ii)(C)".to_string(),
            control_id: "164.308(a)(5)(ii)(C)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Log-in Monitoring".to_string(),
            description: "Implement procedures for monitoring log-in attempts and reporting discrepancies.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(5)(i)".to_string()),
            cross_references: vec!["NIST-AC-7".to_string(), "CIS-8.2".to_string()],
            remediation_guidance: Some("Monitor failed login attempts and implement account lockout.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(5)(ii)(D)".to_string(),
            control_id: "164.308(a)(5)(ii)(D)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Password Management".to_string(),
            description: "Implement procedures for creating, changing, and safeguarding passwords.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(5)(i)".to_string()),
            cross_references: vec!["NIST-IA-5".to_string(), "CIS-5.2".to_string()],
            remediation_guidance: Some("Implement strong password policy with complexity and rotation requirements.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(6)(i)".to_string(),
            control_id: "164.308(a)(6)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Security Incident Procedures".to_string(),
            description: "Implement policies for identifying, responding to, and reporting security incidents.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string(), "PCI-DSS-12.10".to_string()],
            remediation_guidance: Some("Document incident response procedures specific to ePHI breaches.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(6)(ii)".to_string(),
            control_id: "164.308(a)(6)(ii)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Response and Reporting".to_string(),
            description: "Identify and respond to suspected or known security incidents; mitigate harmful effects; document incidents.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(6)(i)".to_string()),
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Establish incident response team and document all incidents.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(7)(i)".to_string(),
            control_id: "164.308(a)(7)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Contingency Plan".to_string(),
            description: "Establish policies for responding to emergencies that damage systems containing ePHI.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-1".to_string()],
            remediation_guidance: Some("Develop business continuity and disaster recovery plans for ePHI systems.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(7)(ii)(A)".to_string(),
            control_id: "164.308(a)(7)(ii)(A)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Data Backup Plan".to_string(),
            description: "Establish procedures to create and maintain retrievable exact copies of ePHI.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.308(a)(7)(i)".to_string()),
            cross_references: vec!["NIST-CP-9".to_string(), "CIS-11.2".to_string()],
            remediation_guidance: Some("Implement automated encrypted backups of all ePHI.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(7)(ii)(B)".to_string(),
            control_id: "164.308(a)(7)(ii)(B)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Disaster Recovery Plan".to_string(),
            description: "Establish procedures to restore any loss of data.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(7)(i)".to_string()),
            cross_references: vec!["NIST-CP-10".to_string()],
            remediation_guidance: Some("Document and test disaster recovery procedures.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(7)(ii)(D)".to_string(),
            control_id: "164.308(a)(7)(ii)(D)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Testing and Revision Procedures".to_string(),
            description: "Implement procedures for periodic testing and revision of contingency plans.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.308(a)(7)(i)".to_string()),
            cross_references: vec!["NIST-CP-4".to_string(), "CIS-11.5".to_string()],
            remediation_guidance: Some("Test DR plans annually and after significant changes.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(a)(8)".to_string(),
            control_id: "164.308(a)(8)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Evaluation".to_string(),
            description: "Perform periodic technical and nontechnical evaluation of security controls.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string(), "CIS-7.5".to_string()],
            remediation_guidance: Some("Conduct annual security assessments and vulnerability scans.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.308(b)(1)".to_string(),
            control_id: "164.308(b)(1)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Business Associate Contracts".to_string(),
            description: "Ensure Business Associate Agreements are in place with all entities handling ePHI.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Maintain BAAs with all vendors with access to ePHI.".to_string()),
        },

        // Physical Safeguards (164.310)
        ComplianceControl {
            id: "HIPAA-164.310(a)(1)".to_string(),
            control_id: "164.310(a)(1)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Facility Access Controls".to_string(),
            description: "Implement policies to limit physical access to electronic information systems.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["PCI-DSS-9.1".to_string()],
            remediation_guidance: Some("Implement physical access controls to facilities housing ePHI.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.310(a)(2)(ii)".to_string(),
            control_id: "164.310(a)(2)(ii)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Facility Security Plan".to_string(),
            description: "Implement policies to safeguard the facility and equipment from unauthorized access.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.310(a)(1)".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Document physical security procedures including visitor policies.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.310(a)(2)(iii)".to_string(),
            control_id: "164.310(a)(2)(iii)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Access Control and Validation Procedures".to_string(),
            description: "Implement procedures to control and validate access to facilities based on role.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.310(a)(1)".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Implement badge access systems and visitor logs.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.310(b)".to_string(),
            control_id: "164.310(b)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Workstation Use".to_string(),
            description: "Implement policies specifying proper functions and physical attributes of workstations.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.3".to_string()],
            remediation_guidance: Some("Configure automatic screen lock and enforce secure workstation use.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.310(c)".to_string(),
            control_id: "164.310(c)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Workstation Security".to_string(),
            description: "Implement physical safeguards for workstations that access ePHI.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Secure workstations with cable locks in public areas.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.310(d)(1)".to_string(),
            control_id: "164.310(d)(1)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Device and Media Controls".to_string(),
            description: "Implement policies governing receipt and removal of hardware and media containing ePHI.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string(), "CIS-3.5".to_string()],
            remediation_guidance: Some("Document media handling and disposal procedures.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.310(d)(2)(i)".to_string(),
            control_id: "164.310(d)(2)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Media Disposal".to_string(),
            description: "Implement policies addressing final disposition of ePHI and hardware.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("HIPAA-164.310(d)(1)".to_string()),
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Implement secure media destruction with documented chain of custody.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.310(d)(2)(ii)".to_string(),
            control_id: "164.310(d)(2)(ii)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Media Re-use".to_string(),
            description: "Implement procedures for removal of ePHI before media is re-used.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.310(d)(1)".to_string()),
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Implement secure wipe procedures before media reuse.".to_string()),
        },

        // Technical Safeguards (164.312)
        ComplianceControl {
            id: "HIPAA-164.312(a)(1)".to_string(),
            control_id: "164.312(a)(1)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Access Control".to_string(),
            description: "Implement technical policies to allow access only to authorized persons or software.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string(), "CIS-6.1".to_string()],
            remediation_guidance: Some("Implement RBAC with minimum necessary access to ePHI.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(a)(2)(i)".to_string(),
            control_id: "164.312(a)(2)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Unique User Identification".to_string(),
            description: "Assign a unique name and/or number for identifying and tracking user identity.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.312(a)(1)".to_string()),
            cross_references: vec!["NIST-IA-4".to_string(), "PCI-DSS-8.1".to_string()],
            remediation_guidance: Some("Ensure all users have unique identifiers; prohibit shared accounts.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(a)(2)(ii)".to_string(),
            control_id: "164.312(a)(2)(ii)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Emergency Access Procedure".to_string(),
            description: "Establish procedures for obtaining necessary ePHI during an emergency.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("HIPAA-164.312(a)(1)".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Document break-glass procedures for emergency access.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(a)(2)(iii)".to_string(),
            control_id: "164.312(a)(2)(iii)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Automatic Logoff".to_string(),
            description: "Implement electronic procedures to terminate sessions after predetermined inactivity.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("HIPAA-164.312(a)(1)".to_string()),
            cross_references: vec!["NIST-AC-11".to_string(), "CIS-4.3".to_string()],
            remediation_guidance: Some("Configure 15-minute session timeout for ePHI systems.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(a)(2)(iv)".to_string(),
            control_id: "164.312(a)(2)(iv)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Encryption and Decryption".to_string(),
            description: "Implement a mechanism to encrypt and decrypt ePHI.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.312(a)(1)".to_string()),
            cross_references: vec!["NIST-SC-28".to_string(), "CIS-3.6".to_string()],
            remediation_guidance: Some("Implement AES-256 encryption for ePHI at rest.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(b)".to_string(),
            control_id: "164.312(b)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Audit Controls".to_string(),
            description: "Implement hardware, software, or procedural mechanisms to record and examine activity.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "CIS-8.2".to_string()],
            remediation_guidance: Some("Enable comprehensive audit logging for all ePHI access.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(c)(1)".to_string(),
            control_id: "164.312(c)(1)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Integrity".to_string(),
            description: "Implement policies to protect ePHI from improper alteration or destruction.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-7".to_string()],
            remediation_guidance: Some("Implement integrity controls and file integrity monitoring.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(d)".to_string(),
            control_id: "164.312(d)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Person or Entity Authentication".to_string(),
            description: "Implement procedures to verify that persons seeking access are who they claim to be.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "CIS-6.3".to_string()],
            remediation_guidance: Some("Implement MFA for ePHI system access.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(e)(1)".to_string(),
            control_id: "164.312(e)(1)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Transmission Security".to_string(),
            description: "Implement technical security measures to guard against unauthorized access during transmission.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Use TLS 1.2+ for all ePHI transmission.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(e)(2)(i)".to_string(),
            control_id: "164.312(e)(2)(i)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Integrity Controls".to_string(),
            description: "Implement security measures to ensure ePHI is not improperly modified without detection.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("HIPAA-164.312(e)(1)".to_string()),
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Implement message authentication codes for data integrity.".to_string()),
        },
        ComplianceControl {
            id: "HIPAA-164.312(e)(2)(ii)".to_string(),
            control_id: "164.312(e)(2)(ii)".to_string(),
            framework: ComplianceFramework::Hipaa,
            title: "Encryption".to_string(),
            description: "Implement a mechanism to encrypt ePHI whenever appropriate.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("HIPAA-164.312(e)(1)".to_string()),
            cross_references: vec!["NIST-SC-8".to_string(), "NIST-SC-13".to_string()],
            remediation_guidance: Some("Encrypt all ePHI in transit using TLS 1.2 or higher.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant HIPAA controls
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
        || title_lower.contains("authentication bypass")
    {
        mappings.push(("HIPAA-164.312(a)(1)".to_string(), Severity::Critical));
        mappings.push(("HIPAA-164.312(d)".to_string(), Severity::Critical));
    }

    // Authentication issues
    if title_lower.contains("weak password")
        || title_lower.contains("default password")
        || title_lower.contains("credential")
    {
        mappings.push(("HIPAA-164.308(a)(5)(ii)(D)".to_string(), Severity::High));
        mappings.push(("HIPAA-164.312(d)".to_string(), Severity::High));
    }

    // Encryption issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
    {
        mappings.push(("HIPAA-164.312(a)(2)(iv)".to_string(), Severity::High));
        mappings.push(("HIPAA-164.312(e)(1)".to_string(), Severity::High));
        mappings.push(("HIPAA-164.312(e)(2)(ii)".to_string(), Severity::High));
    }

    // Logging/audit issues
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("no log")
    {
        mappings.push(("HIPAA-164.312(b)".to_string(), Severity::Medium));
        mappings.push(("HIPAA-164.308(a)(1)(ii)(D)".to_string(), Severity::Medium));
    }

    // Malware protection issues
    if title_lower.contains("malware")
        || title_lower.contains("antivirus")
        || title_lower.contains("endpoint protection")
    {
        mappings.push(("HIPAA-164.308(a)(5)(ii)(B)".to_string(), Severity::High));
    }

    // Vulnerability/patch issues
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("cve")
    {
        mappings.push(("HIPAA-164.308(a)(1)(ii)(A)".to_string(), Severity::High));
        mappings.push(("HIPAA-164.308(a)(8)".to_string(), Severity::High));
    }

    // Session management issues
    if title_lower.contains("session")
        || title_lower.contains("timeout")
    {
        mappings.push(("HIPAA-164.312(a)(2)(iii)".to_string(), Severity::Medium));
    }

    // Backup issues
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
    {
        mappings.push(("HIPAA-164.308(a)(7)(ii)(A)".to_string(), Severity::Medium));
    }

    // Integrity issues
    if title_lower.contains("integrity")
        || title_lower.contains("tampering")
    {
        mappings.push(("HIPAA-164.312(c)(1)".to_string(), Severity::High));
        mappings.push(("HIPAA-164.312(e)(2)(i)".to_string(), Severity::Medium));
    }

    // Login monitoring
    if title_lower.contains("brute force")
        || title_lower.contains("login attempt")
    {
        mappings.push(("HIPAA-164.308(a)(5)(ii)(C)".to_string(), Severity::High));
    }

    mappings
}
