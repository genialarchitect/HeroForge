//! GLBA (Gramm-Leach-Bliley Act) Compliance Framework
//!
//! The Gramm-Leach-Bliley Act Safeguards Rule requires financial institutions
//! to develop, implement, and maintain an information security program to
//! protect customer information.
//!
//! Based on the FTC Safeguards Rule (16 CFR Part 314) as amended in 2021.
//!
//! Key Requirements:
//! - Designate employees to coordinate security
//! - Identify and assess risks to customer information
//! - Design and implement safeguards to control identified risks
//! - Select appropriate service providers and contractually require safeguards
//! - Evaluate and adjust the security program regularly

use crate::compliance::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of GLBA controls in this module
pub const CONTROL_COUNT: usize = 45;

/// Get all GLBA Safeguards Rule controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ========================================
        // Administrative Safeguards
        // ========================================
        ComplianceControl {
            id: "GLBA-314.4(a)".to_string(),
            control_id: "314.4(a)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Qualified Individual".to_string(),
            description: "Designate a Qualified Individual responsible for overseeing, implementing, and enforcing the information security program.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["HIPAA-164.308(a)(2)".to_string(), "NIST-PM-2".to_string()],
            remediation_guidance: Some("Appoint a CISO or equivalent role with clear authority and responsibility for the security program.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(b)(1)".to_string(),
            control_id: "314.4(b)(1)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Risk Assessment - Customer Information".to_string(),
            description: "Base the information security program on a written risk assessment that identifies reasonably foreseeable internal and external risks to customer information.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string(), "HIPAA-164.308(a)(1)(ii)(A)".to_string()],
            remediation_guidance: Some("Conduct annual risk assessments covering all systems processing customer financial information.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(b)(2)".to_string(),
            control_id: "314.4(b)(2)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Risk Assessment - Criteria".to_string(),
            description: "Include criteria for evaluating and categorizing identified security risks based on likelihood and potential damage.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("GLBA-314.4(b)(1)".to_string()),
            cross_references: vec!["NIST-RA-5".to_string()],
            remediation_guidance: Some("Develop risk rating methodology with likelihood and impact scoring.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(b)(3)".to_string(),
            control_id: "314.4(b)(3)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Risk Assessment - Sufficiency of Safeguards".to_string(),
            description: "Assess the sufficiency of any safeguards in place to control identified risks.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("GLBA-314.4(b)(1)".to_string()),
            cross_references: vec!["NIST-CA-2".to_string()],
            remediation_guidance: Some("Perform control gap analysis and document remediation plans for deficiencies.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(1)".to_string(),
            control_id: "314.4(c)(1)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Access Controls Implementation".to_string(),
            description: "Implement and periodically review access controls, including restricting access to customer information.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-1".to_string(), "PCI-DSS-7.1".to_string()],
            remediation_guidance: Some("Implement role-based access control with periodic access reviews.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(2)".to_string(),
            control_id: "314.4(c)(2)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Data Inventory".to_string(),
            description: "Identify and manage the data, personnel, devices, systems, and facilities that enable achievement of business purposes.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-5".to_string(), "CIS-1.1".to_string()],
            remediation_guidance: Some("Maintain comprehensive inventory of all systems processing customer information.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(d)(1)".to_string(),
            control_id: "314.4(d)(1)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Security Awareness Training".to_string(),
            description: "Provide security awareness training for personnel, including training on recognizing social engineering attacks.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "PCI-DSS-12.6".to_string()],
            remediation_guidance: Some("Implement annual security awareness training with phishing simulation exercises.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(d)(2)".to_string(),
            control_id: "314.4(d)(2)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Qualified Individual Training".to_string(),
            description: "Provide specialized security training for the Qualified Individual overseeing the program.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("GLBA-314.4(d)(1)".to_string()),
            cross_references: vec!["NIST-AT-3".to_string()],
            remediation_guidance: Some("Ensure CISO/security lead maintains relevant certifications and ongoing education.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(e)".to_string(),
            control_id: "314.4(e)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Incident Response Plan".to_string(),
            description: "Develop, implement, and maintain a written incident response plan to respond to and recover from security events.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string(), "PCI-DSS-12.10".to_string()],
            remediation_guidance: Some("Create incident response plan addressing detection, response, recovery, and notification procedures.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(e)(1)".to_string(),
            control_id: "314.4(e)(1)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Incident Response Goals".to_string(),
            description: "Define goals of the incident response plan including containment, recovery, and customer notification.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("GLBA-314.4(e)".to_string()),
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Document specific objectives for each phase of incident response.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(e)(2)".to_string(),
            control_id: "314.4(e)(2)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Incident Response Roles".to_string(),
            description: "Define internal processes for responding to security events, including roles and responsibilities.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("GLBA-314.4(e)".to_string()),
            cross_references: vec!["NIST-IR-2".to_string()],
            remediation_guidance: Some("Document RACI matrix for incident response team roles.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(e)(3)".to_string(),
            control_id: "314.4(e)(3)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Incident Communication".to_string(),
            description: "Define communication procedures for notifying management, board, and affected parties.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("GLBA-314.4(e)".to_string()),
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Establish escalation procedures and notification templates.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(f)(1)".to_string(),
            control_id: "314.4(f)(1)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Board Reporting".to_string(),
            description: "Report to the board of directors or equivalent governing body at least annually on the overall status of the information security program.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-1".to_string()],
            remediation_guidance: Some("Prepare annual security program status report for board review and approval.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(f)(2)".to_string(),
            control_id: "314.4(f)(2)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Material Issues Reporting".to_string(),
            description: "Report material matters related to the information security program to the board, including risk assessments and security incidents.".to_string(),
            category: "Administrative Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("GLBA-314.4(f)(1)".to_string()),
            cross_references: vec!["NIST-PM-9".to_string()],
            remediation_guidance: Some("Establish criteria and process for escalating material security matters to board.".to_string()),
        },

        // ========================================
        // Technical Safeguards
        // ========================================
        ComplianceControl {
            id: "GLBA-314.4(c)(3)".to_string(),
            control_id: "314.4(c)(3)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Encryption - Data in Transit".to_string(),
            description: "Encrypt customer information in transit over external networks and at rest.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Implement TLS 1.2+ for all data transmission over external networks.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(3)(i)".to_string(),
            control_id: "314.4(c)(3)(i)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Encryption - Data at Rest".to_string(),
            description: "Encrypt customer information at rest using industry-standard encryption methods.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("GLBA-314.4(c)(3)".to_string()),
            cross_references: vec!["NIST-SC-28".to_string(), "PCI-DSS-3.4".to_string()],
            remediation_guidance: Some("Implement AES-256 encryption for customer data stored in databases and files.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(4)".to_string(),
            control_id: "314.4(c)(4)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Secure Development".to_string(),
            description: "Adopt secure development practices for in-house developed applications and evaluate third-party applications.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Implement SDLC with security code review, SAST, and DAST testing.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(5)".to_string(),
            control_id: "314.4(c)(5)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Multi-Factor Authentication".to_string(),
            description: "Implement multi-factor authentication for accessing customer information, unless alternative compensating controls are approved.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "PCI-DSS-8.4".to_string()],
            remediation_guidance: Some("Deploy MFA for all access to systems containing customer information.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(6)".to_string(),
            control_id: "314.4(c)(6)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Secure Disposal".to_string(),
            description: "Implement secure disposal procedures for customer information no later than two years after last use.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string(), "PCI-DSS-3.1".to_string()],
            remediation_guidance: Some("Implement data retention schedule with secure deletion/destruction procedures.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(7)".to_string(),
            control_id: "314.4(c)(7)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Change Management".to_string(),
            description: "Adopt procedures for change management including formal approval and testing of changes to information systems.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "PCI-DSS-6.4".to_string()],
            remediation_guidance: Some("Implement change advisory board process with testing and rollback procedures.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(c)(8)".to_string(),
            control_id: "314.4(c)(8)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Monitoring and Logging".to_string(),
            description: "Implement policies and procedures to monitor and log activity of authorized users and detect unauthorized access.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "PCI-DSS-10.2".to_string()],
            remediation_guidance: Some("Deploy SIEM with comprehensive logging of access to customer information.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-TS-01".to_string(),
            control_id: "TS-01".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Network Security".to_string(),
            description: "Implement network security controls including firewalls and intrusion detection systems.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.1".to_string()],
            remediation_guidance: Some("Deploy firewalls with deny-all default rules and IDS/IPS at network perimeter.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-TS-02".to_string(),
            control_id: "TS-02".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Vulnerability Management".to_string(),
            description: "Implement procedures for identifying and remediating vulnerabilities in information systems.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string(), "PCI-DSS-11.3".to_string()],
            remediation_guidance: Some("Perform quarterly vulnerability scans and remediate high-risk findings within 30 days.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-TS-03".to_string(),
            control_id: "TS-03".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Patch Management".to_string(),
            description: "Implement timely installation of security patches for all systems.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "PCI-DSS-6.3.3".to_string()],
            remediation_guidance: Some("Deploy critical security patches within 30 days of release.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-TS-04".to_string(),
            control_id: "TS-04".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Malware Protection".to_string(),
            description: "Deploy anti-malware solutions on all endpoints and servers.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "PCI-DSS-5.2".to_string()],
            remediation_guidance: Some("Deploy EDR/antimalware with automatic updates on all systems.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-TS-05".to_string(),
            control_id: "TS-05".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Session Management".to_string(),
            description: "Implement automatic session timeout and re-authentication for systems accessing customer information.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-11".to_string(), "HIPAA-164.312(a)(2)(iii)".to_string()],
            remediation_guidance: Some("Configure 15-minute session timeout for applications accessing customer data.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-TS-06".to_string(),
            control_id: "TS-06".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Password Requirements".to_string(),
            description: "Enforce strong password policies including complexity and expiration requirements.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "PCI-DSS-8.3.6".to_string()],
            remediation_guidance: Some("Require 12+ character passwords with complexity or passphrase requirements.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-TS-07".to_string(),
            control_id: "TS-07".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Account Lockout".to_string(),
            description: "Implement account lockout policies after failed authentication attempts.".to_string(),
            category: "Technical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-7".to_string(), "PCI-DSS-8.1.6".to_string()],
            remediation_guidance: Some("Lock accounts after 5 failed login attempts for minimum 30 minutes.".to_string()),
        },

        // ========================================
        // Physical Safeguards
        // ========================================
        ComplianceControl {
            id: "GLBA-PS-01".to_string(),
            control_id: "PS-01".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Facility Access Control".to_string(),
            description: "Control physical access to facilities containing customer information.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-2".to_string(), "PCI-DSS-9.1".to_string()],
            remediation_guidance: Some("Implement badge access and visitor management for data centers and offices.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PS-02".to_string(),
            control_id: "PS-02".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Workstation Security".to_string(),
            description: "Implement policies for secure use and placement of workstations accessing customer information.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-18".to_string(), "HIPAA-164.310(c)".to_string()],
            remediation_guidance: Some("Position screens away from public view; implement privacy screens where needed.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PS-03".to_string(),
            control_id: "PS-03".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Device and Media Controls".to_string(),
            description: "Implement controls for movement and disposal of electronic media containing customer information.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-5".to_string(), "HIPAA-164.310(d)".to_string()],
            remediation_guidance: Some("Track media with customer data; use certified destruction services.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PS-04".to_string(),
            control_id: "PS-04".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Paper Document Security".to_string(),
            description: "Implement secure storage and disposal for paper documents containing customer information.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Use locked cabinets for sensitive documents; cross-cut shred before disposal.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PS-05".to_string(),
            control_id: "PS-05".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Environmental Controls".to_string(),
            description: "Implement environmental controls to protect systems containing customer information from natural disasters.".to_string(),
            category: "Physical Safeguards".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-13".to_string(), "NIST-PE-14".to_string()],
            remediation_guidance: Some("Deploy fire suppression, temperature monitoring, and water detection in data centers.".to_string()),
        },

        // ========================================
        // Service Provider Oversight
        // ========================================
        ComplianceControl {
            id: "GLBA-314.4(d)(3)".to_string(),
            control_id: "314.4(d)(3)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Service Provider Due Diligence".to_string(),
            description: "Exercise due diligence in selecting service providers capable of maintaining appropriate safeguards.".to_string(),
            category: "Service Provider Oversight".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string(), "PCI-DSS-12.8".to_string()],
            remediation_guidance: Some("Assess vendor security posture before engagement using questionnaires and certifications.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(d)(4)".to_string(),
            control_id: "314.4(d)(4)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Service Provider Contracts".to_string(),
            description: "Require service providers by contract to implement and maintain appropriate safeguards for customer information.".to_string(),
            category: "Service Provider Oversight".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string(), "HIPAA-164.308(b)(1)".to_string()],
            remediation_guidance: Some("Include security requirements, audit rights, and breach notification in vendor contracts.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-SPO-01".to_string(),
            control_id: "SPO-01".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Service Provider Inventory".to_string(),
            description: "Maintain an inventory of all service providers with access to customer information.".to_string(),
            category: "Service Provider Oversight".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["PCI-DSS-12.8.1".to_string()],
            remediation_guidance: Some("Document all third parties with customer data access including data types and access levels.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-SPO-02".to_string(),
            control_id: "SPO-02".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Service Provider Monitoring".to_string(),
            description: "Periodically assess service providers based on the risk they present and adequacy of their safeguards.".to_string(),
            category: "Service Provider Oversight".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string()],
            remediation_guidance: Some("Conduct annual vendor security assessments; review SOC 2 reports and certifications.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-SPO-03".to_string(),
            control_id: "SPO-03".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Service Provider Access Control".to_string(),
            description: "Control and monitor service provider access to customer information systems.".to_string(),
            category: "Service Provider Oversight".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Implement dedicated accounts and monitoring for vendor access; use PAM for privileged access.".to_string()),
        },

        // ========================================
        // Program Evaluation
        // ========================================
        ComplianceControl {
            id: "GLBA-314.4(g)".to_string(),
            control_id: "314.4(g)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Continuous Evaluation".to_string(),
            description: "Evaluate and adjust the information security program in light of changes to operations or business arrangements.".to_string(),
            category: "Program Evaluation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CA-7".to_string()],
            remediation_guidance: Some("Review security program after significant changes; conduct annual comprehensive review.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-314.4(h)".to_string(),
            control_id: "314.4(h)".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Annual Penetration Testing".to_string(),
            description: "Conduct annual penetration testing and vulnerability assessments of information systems.".to_string(),
            category: "Program Evaluation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CA-8".to_string(), "PCI-DSS-11.4".to_string()],
            remediation_guidance: Some("Engage qualified third party for annual penetration testing of critical systems.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PE-01".to_string(),
            control_id: "PE-01".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Security Program Documentation".to_string(),
            description: "Maintain written documentation of the information security program.".to_string(),
            category: "Program Evaluation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-1".to_string()],
            remediation_guidance: Some("Document all security policies, procedures, and standards in an accessible repository.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PE-02".to_string(),
            control_id: "PE-02".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Control Testing".to_string(),
            description: "Periodically test the key controls, systems, and procedures of the information security program.".to_string(),
            category: "Program Evaluation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CA-2".to_string()],
            remediation_guidance: Some("Conduct semi-annual control testing; document results and remediate gaps.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PE-03".to_string(),
            control_id: "PE-03".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Incident Response Testing".to_string(),
            description: "Test the incident response plan through tabletop exercises or simulations.".to_string(),
            category: "Program Evaluation".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-3".to_string()],
            remediation_guidance: Some("Conduct annual tabletop exercises; update plan based on lessons learned.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PE-04".to_string(),
            control_id: "PE-04".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Business Continuity Planning".to_string(),
            description: "Maintain business continuity and disaster recovery plans for critical information systems.".to_string(),
            category: "Program Evaluation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-2".to_string()],
            remediation_guidance: Some("Document BCP/DR plans; test recovery procedures annually.".to_string()),
        },
        ComplianceControl {
            id: "GLBA-PE-05".to_string(),
            control_id: "PE-05".to_string(),
            framework: ComplianceFramework::Glba,
            title: "Backup and Recovery".to_string(),
            description: "Implement regular backup procedures and test recovery of customer information.".to_string(),
            category: "Program Evaluation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-9".to_string(), "HIPAA-164.308(a)(7)(ii)(A)".to_string()],
            remediation_guidance: Some("Perform daily encrypted backups; test restoration quarterly.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant GLBA controls
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
        || title_lower.contains("authentication bypass")
        || title_lower.contains("privilege escalation")
    {
        mappings.push(("GLBA-314.4(c)(1)".to_string(), Severity::Critical));
        mappings.push(("GLBA-314.4(c)(5)".to_string(), Severity::Critical));
    }

    // Authentication/credential issues
    if title_lower.contains("weak password")
        || title_lower.contains("default password")
        || title_lower.contains("credential")
        || title_lower.contains("default credential")
    {
        mappings.push(("GLBA-TS-06".to_string(), Severity::High));
        mappings.push(("GLBA-314.4(c)(5)".to_string(), Severity::High));
    }

    // Missing MFA
    if title_lower.contains("no mfa")
        || title_lower.contains("single factor")
        || title_lower.contains("without multi-factor")
    {
        mappings.push(("GLBA-314.4(c)(5)".to_string(), Severity::High));
    }

    // Encryption issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("cleartext")
    {
        mappings.push(("GLBA-314.4(c)(3)".to_string(), Severity::High));
        mappings.push(("GLBA-314.4(c)(3)(i)".to_string(), Severity::High));
    }

    // TLS/SSL vulnerabilities
    if title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("certificate")
        || title_lower.contains("heartbleed")
    {
        mappings.push(("GLBA-314.4(c)(3)".to_string(), Severity::High));
    }

    // Logging/audit issues
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("no log")
        || title_lower.contains("insufficient logging")
    {
        mappings.push(("GLBA-314.4(c)(8)".to_string(), Severity::Medium));
    }

    // Malware/antivirus issues
    if title_lower.contains("malware")
        || title_lower.contains("antivirus")
        || title_lower.contains("endpoint protection")
    {
        mappings.push(("GLBA-TS-04".to_string(), Severity::High));
    }

    // Vulnerability/patch issues
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("missing patch")
        || title_lower.contains("cve-")
    {
        mappings.push(("GLBA-TS-02".to_string(), Severity::High));
        mappings.push(("GLBA-TS-03".to_string(), Severity::High));
    }

    // Session management issues
    if title_lower.contains("session")
        || title_lower.contains("timeout")
        || title_lower.contains("session fixation")
    {
        mappings.push(("GLBA-TS-05".to_string(), Severity::Medium));
    }

    // Network security issues
    if title_lower.contains("firewall")
        || title_lower.contains("network segmentation")
        || title_lower.contains("intrusion")
    {
        mappings.push(("GLBA-TS-01".to_string(), Severity::High));
    }

    // Brute force/account lockout
    if title_lower.contains("brute force")
        || title_lower.contains("account lockout")
        || title_lower.contains("rate limit")
    {
        mappings.push(("GLBA-TS-07".to_string(), Severity::High));
    }

    // Web application vulnerabilities
    if title_lower.contains("xss")
        || title_lower.contains("sql injection")
        || title_lower.contains("injection")
        || title_lower.contains("csrf")
    {
        mappings.push(("GLBA-314.4(c)(4)".to_string(), Severity::Critical));
        mappings.push(("GLBA-TS-02".to_string(), Severity::High));
    }

    // Database exposure
    if port == Some(1433)
        || port == Some(3306)
        || port == Some(5432)
        || port == Some(27017)
        || port == Some(1521)
    {
        mappings.push(("GLBA-314.4(c)(1)".to_string(), Severity::High));
        mappings.push(("GLBA-TS-01".to_string(), Severity::High));
    }

    // Remote access exposure
    if port == Some(3389) || port == Some(22) || title_lower.contains("rdp") {
        mappings.push(("GLBA-314.4(c)(5)".to_string(), Severity::High));
    }

    // Change management issues
    if title_lower.contains("unauthorized change")
        || title_lower.contains("configuration drift")
    {
        mappings.push(("GLBA-314.4(c)(7)".to_string(), Severity::Medium));
    }

    // Backup issues
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
        || title_lower.contains("disaster recovery")
    {
        mappings.push(("GLBA-PE-05".to_string(), Severity::Medium));
        mappings.push(("GLBA-PE-04".to_string(), Severity::Medium));
    }

    // Data exposure/leakage
    if title_lower.contains("data exposure")
        || title_lower.contains("data leak")
        || title_lower.contains("sensitive data")
        || title_lower.contains("pii")
    {
        mappings.push(("GLBA-314.4(c)(3)".to_string(), Severity::Critical));
        mappings.push(("GLBA-314.4(c)(1)".to_string(), Severity::Critical));
    }

    // Third-party/vendor issues
    if title_lower.contains("third party")
        || title_lower.contains("vendor")
        || title_lower.contains("supply chain")
    {
        mappings.push(("GLBA-314.4(d)(3)".to_string(), Severity::High));
        mappings.push(("GLBA-SPO-02".to_string(), Severity::High));
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
    fn test_all_controls_have_glba_framework() {
        let controls = get_controls();
        for control in &controls {
            assert_eq!(control.framework, ComplianceFramework::Glba);
        }
    }

    #[test]
    fn test_control_categories() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> = controls.iter().map(|c| c.category.as_str()).collect();

        assert!(categories.contains("Administrative Safeguards"));
        assert!(categories.contains("Technical Safeguards"));
        assert!(categories.contains("Physical Safeguards"));
        assert!(categories.contains("Service Provider Oversight"));
        assert!(categories.contains("Program Evaluation"));
    }

    #[test]
    fn test_vulnerability_mapping_encryption() {
        let mappings = map_vulnerability("Unencrypted data transmission", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "GLBA-314.4(c)(3)"));
    }

    #[test]
    fn test_vulnerability_mapping_authentication() {
        let mappings = map_vulnerability("Weak password policy detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "GLBA-TS-06"));
    }

    #[test]
    fn test_vulnerability_mapping_database_port() {
        let mappings = map_vulnerability("Open database port", None, Some(3306), Some("mysql"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "GLBA-314.4(c)(1)"));
    }

    #[test]
    fn test_unique_control_ids() {
        let controls = get_controls();
        let ids: std::collections::HashSet<_> = controls.iter().map(|c| &c.id).collect();
        assert_eq!(ids.len(), controls.len(), "All control IDs should be unique");
    }
}
