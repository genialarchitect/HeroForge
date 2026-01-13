//! Australian Information Security Manual (ISM) Controls
//!
//! The Information Security Manual (ISM) is produced by the Australian Cyber Security Centre (ACSC)
//! within the Australian Signals Directorate (ASD). It outlines a cyber security framework that
//! organizations can apply to protect their systems and data from cyber threats.
//!
//! This module contains controls aligned with the ISM's security guidelines covering:
//! - Cyber Security Roles
//! - Cyber Security Incidents
//! - Outsourcing
//! - Security Documentation
//! - Physical Security
//! - Personnel Security
//! - Communications Infrastructure
//! - Communications Systems
//! - Enterprise Mobility
//! - Evaluated Products
//! - ICT Equipment Management
//! - Media Management
//! - System Hardening
//! - System Management
//! - System Monitoring
//! - Software Development
//! - Database Systems
//! - Email
//! - Networking
//! - Cryptography
//! - Gateway Management
//! - Data Transfers

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of Australian ISM controls in this module
pub const CONTROL_COUNT: usize = 80;

/// Get all Australian ISM controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============ Cyber Security Roles ============
        ComplianceControl {
            id: "ISM-0714".to_string(),
            control_id: "ISM-0714".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Chief Information Security Officer Appointment".to_string(),
            description: "A Chief Information Security Officer is appointed to provide cyber security leadership for an organisation.".to_string(),
            category: "Cyber Security Roles".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-2".to_string(), "ISO27001-A.6.1.1".to_string()],
            remediation_guidance: Some("Appoint a CISO with appropriate authority and resources to manage cyber security.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0717".to_string(),
            control_id: "ISM-0717".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Cyber Security Personnel Qualifications".to_string(),
            description: "Cyber security personnel have the appropriate skills and qualifications.".to_string(),
            category: "Cyber Security Roles".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-13".to_string()],
            remediation_guidance: Some("Ensure cyber security personnel have relevant certifications and training.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1478".to_string(),
            control_id: "ISM-1478".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Cyber Security Awareness Training".to_string(),
            description: "Cyber security awareness training is provided to all personnel.".to_string(),
            category: "Cyber Security Roles".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "PCI-DSS-12.6".to_string()],
            remediation_guidance: Some("Implement regular cyber security awareness training for all staff.".to_string()),
        },

        // ============ Cyber Security Incidents ============
        ComplianceControl {
            id: "ISM-0123".to_string(),
            control_id: "ISM-0123".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Cyber Security Incident Response Plan".to_string(),
            description: "A cyber security incident response plan is developed and implemented.".to_string(),
            category: "Cyber Security Incidents".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string(), "PCI-DSS-12.10".to_string()],
            remediation_guidance: Some("Develop and document an incident response plan with roles, procedures, and communication protocols.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0125".to_string(),
            control_id: "ISM-0125".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Cyber Security Incident Reporting".to_string(),
            description: "Cyber security incidents are reported to the ACSC.".to_string(),
            category: "Cyber Security Incidents".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Establish procedures for reporting cyber security incidents to ACSC.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0140".to_string(),
            control_id: "ISM-0140".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Incident Response Testing".to_string(),
            description: "The cyber security incident response plan is tested at least annually.".to_string(),
            category: "Cyber Security Incidents".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-3".to_string()],
            remediation_guidance: Some("Conduct annual incident response exercises and tabletop drills.".to_string()),
        },

        // ============ Outsourcing ============
        ComplianceControl {
            id: "ISM-0072".to_string(),
            control_id: "ISM-0072".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Service Provider Security Requirements".to_string(),
            description: "Security requirements for outsourced ICT services are documented in contracts.".to_string(),
            category: "Outsourcing".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-9".to_string(), "ISO27001-A.15.1".to_string()],
            remediation_guidance: Some("Include detailed security requirements and compliance obligations in all outsourcing contracts.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1395".to_string(),
            control_id: "ISM-1395".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Cloud Service Provider Assessment".to_string(),
            description: "Cloud service providers are assessed for compliance with security requirements.".to_string(),
            category: "Outsourcing".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CSA-CCM".to_string(), "NIST-SA-9".to_string()],
            remediation_guidance: Some("Conduct security assessments of cloud providers; require IRAP certification where applicable.".to_string()),
        },

        // ============ Security Documentation ============
        ComplianceControl {
            id: "ISM-0027".to_string(),
            control_id: "ISM-0027".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "System Security Plan".to_string(),
            description: "A system security plan is developed and implemented for each system.".to_string(),
            category: "Security Documentation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-2".to_string()],
            remediation_guidance: Some("Document system security plans covering security controls and risk management.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0888".to_string(),
            control_id: "ISM-0888".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Security Risk Assessment".to_string(),
            description: "Security risk assessments are conducted before systems are authorised for operation.".to_string(),
            category: "Security Documentation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string(), "ISO27001-A.8.2".to_string()],
            remediation_guidance: Some("Perform formal security risk assessments for all systems before deployment.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1163".to_string(),
            control_id: "ISM-1163".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Continuous Monitoring Plan".to_string(),
            description: "A continuous monitoring plan is developed and implemented.".to_string(),
            category: "Security Documentation".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CA-7".to_string()],
            remediation_guidance: Some("Establish ongoing security monitoring with defined metrics and reporting.".to_string()),
        },

        // ============ Physical Security ============
        ComplianceControl {
            id: "ISM-0810".to_string(),
            control_id: "ISM-0810".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Facility Physical Security".to_string(),
            description: "Facilities housing systems are physically secure.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string(), "PCI-DSS-9.1".to_string()],
            remediation_guidance: Some("Implement physical access controls including locks, badges, and monitoring.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1053".to_string(),
            control_id: "ISM-1053".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Server Room Access Control".to_string(),
            description: "Server rooms have appropriate physical access controls.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-3".to_string()],
            remediation_guidance: Some("Restrict server room access to authorised personnel with logging.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0161".to_string(),
            control_id: "ISM-0161".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Visitor Management".to_string(),
            description: "Visitors are escorted and their access is logged.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-6".to_string()],
            remediation_guidance: Some("Implement visitor sign-in procedures and escort requirements.".to_string()),
        },

        // ============ Personnel Security ============
        ComplianceControl {
            id: "ISM-0434".to_string(),
            control_id: "ISM-0434".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Personnel Security Clearances".to_string(),
            description: "Personnel with access to classified information hold appropriate security clearances.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-3".to_string()],
            remediation_guidance: Some("Ensure all personnel accessing sensitive systems have appropriate clearances.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0435".to_string(),
            control_id: "ISM-0435".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Personnel Vetting".to_string(),
            description: "Personnel undergo appropriate pre-employment screening.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PS-2".to_string()],
            remediation_guidance: Some("Conduct background checks and verify qualifications before employment.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0430".to_string(),
            control_id: "ISM-0430".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Access Termination".to_string(),
            description: "System access is revoked when personnel leave or change roles.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-PS-4".to_string(), "CIS-5.3".to_string()],
            remediation_guidance: Some("Implement immediate access revocation procedures for departing personnel.".to_string()),
        },

        // ============ Communications Infrastructure ============
        ComplianceControl {
            id: "ISM-0181".to_string(),
            control_id: "ISM-0181".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Cable Infrastructure Protection".to_string(),
            description: "Cabling is protected from damage, interference, and interception.".to_string(),
            category: "Communications Infrastructure".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PE-9".to_string()],
            remediation_guidance: Some("Use conduits, cable trays, and physical protection for network cabling.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1114".to_string(),
            control_id: "ISM-1114".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Wireless Network Security".to_string(),
            description: "Wireless networks are secured using WPA3 or equivalent encryption.".to_string(),
            category: "Communications Infrastructure".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-18".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Implement WPA3 Enterprise with 802.1X authentication for wireless networks.".to_string()),
        },

        // ============ Communications Systems ============
        ComplianceControl {
            id: "ISM-0229".to_string(),
            control_id: "ISM-0229".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Video Conferencing Security".to_string(),
            description: "Video conferencing systems are configured securely.".to_string(),
            category: "Communications Systems".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Enable encryption and authentication for video conferencing; disable auto-answer.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1078".to_string(),
            control_id: "ISM-1078".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "VoIP Security".to_string(),
            description: "VoIP systems are segregated from data networks and encrypted.".to_string(),
            category: "Communications Systems".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Implement VLAN segregation and SRTP encryption for VoIP traffic.".to_string()),
        },

        // ============ Enterprise Mobility ============
        ComplianceControl {
            id: "ISM-1082".to_string(),
            control_id: "ISM-1082".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Mobile Device Management".to_string(),
            description: "Mobile devices are managed using a Mobile Device Management solution.".to_string(),
            category: "Enterprise Mobility".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-19".to_string(), "CIS-15.1".to_string()],
            remediation_guidance: Some("Deploy MDM solution to enforce security policies on mobile devices.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0869".to_string(),
            control_id: "ISM-0869".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Mobile Device Encryption".to_string(),
            description: "Mobile devices use encryption to protect data at rest.".to_string(),
            category: "Enterprise Mobility".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string()],
            remediation_guidance: Some("Enable full device encryption on all mobile devices.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1084".to_string(),
            control_id: "ISM-1084".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Remote Wipe Capability".to_string(),
            description: "Mobile devices can be remotely wiped if lost or stolen.".to_string(),
            category: "Enterprise Mobility".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Configure MDM with remote wipe capability for all managed devices.".to_string()),
        },

        // ============ Evaluated Products ============
        ComplianceControl {
            id: "ISM-0289".to_string(),
            control_id: "ISM-0289".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Use of Evaluated Products".to_string(),
            description: "High assurance ICT equipment uses evaluated products where available.".to_string(),
            category: "Evaluated Products".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-4".to_string()],
            remediation_guidance: Some("Prefer Common Criteria evaluated products for security-critical functions.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0290".to_string(),
            control_id: "ISM-0290".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "ASD Approved Cryptographic Algorithms".to_string(),
            description: "Cryptographic equipment uses ASD Approved Cryptographic Algorithms.".to_string(),
            category: "Evaluated Products".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string()],
            remediation_guidance: Some("Use only ASD-approved cryptographic algorithms and implementations.".to_string()),
        },

        // ============ ICT Equipment Management ============
        ComplianceControl {
            id: "ISM-0336".to_string(),
            control_id: "ISM-0336".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "ICT Equipment Register".to_string(),
            description: "An ICT equipment register is maintained.".to_string(),
            category: "ICT Equipment Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "CIS-1.1".to_string()],
            remediation_guidance: Some("Maintain accurate asset inventory with hardware, software, and configuration details.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1599".to_string(),
            control_id: "ISM-1599".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "ICT Equipment Disposal".to_string(),
            description: "ICT equipment is sanitised before disposal or reuse.".to_string(),
            category: "ICT Equipment Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string(), "PCI-DSS-9.8".to_string()],
            remediation_guidance: Some("Use ASD-approved sanitisation methods before equipment disposal.".to_string()),
        },

        // ============ Media Management ============
        ComplianceControl {
            id: "ISM-0347".to_string(),
            control_id: "ISM-0347".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Removable Media Controls".to_string(),
            description: "The use of removable media is controlled and restricted.".to_string(),
            category: "Media Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MP-7".to_string(), "CIS-10.3".to_string()],
            remediation_guidance: Some("Implement USB device control policies; whitelist approved devices.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0348".to_string(),
            control_id: "ISM-0348".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Media Encryption".to_string(),
            description: "Removable media containing sensitive information is encrypted.".to_string(),
            category: "Media Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "PCI-DSS-3.4".to_string()],
            remediation_guidance: Some("Require encryption for all removable media using approved algorithms.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0351".to_string(),
            control_id: "ISM-0351".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Media Sanitisation".to_string(),
            description: "Media is sanitised before disposal, reuse, or release.".to_string(),
            category: "Media Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Follow ASD media destruction guidelines; maintain sanitisation records.".to_string()),
        },

        // ============ System Hardening ============
        ComplianceControl {
            id: "ISM-0380".to_string(),
            control_id: "ISM-0380".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Operating System Hardening".to_string(),
            description: "Operating systems are hardened using a security configuration guide.".to_string(),
            category: "System Hardening".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Apply CIS Benchmarks or ASD hardening guides to all operating systems.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1407".to_string(),
            control_id: "ISM-1407".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Application Control".to_string(),
            description: "Application control is implemented to prevent execution of unauthorised software.".to_string(),
            category: "System Hardening".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CIS-2.5".to_string()],
            remediation_guidance: Some("Implement application whitelisting using AppLocker or similar controls.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1492".to_string(),
            control_id: "ISM-1492".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Software Restriction Policies".to_string(),
            description: "Users cannot install or run unauthorised software.".to_string(),
            category: "System Hardening".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-11".to_string()],
            remediation_guidance: Some("Remove local admin rights; implement software request workflows.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1409".to_string(),
            control_id: "ISM-1409".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Unnecessary Services Disabled".to_string(),
            description: "Unneeded operating system components, services, and ports are disabled.".to_string(),
            category: "System Hardening".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string(), "CIS-2.3".to_string()],
            remediation_guidance: Some("Audit and disable all unnecessary services and open ports.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1418".to_string(),
            control_id: "ISM-1418".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Macro Security".to_string(),
            description: "Microsoft Office macros are disabled or restricted.".to_string(),
            category: "System Hardening".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-10.1".to_string()],
            remediation_guidance: Some("Block macros from the internet; only allow vetted macros in trusted locations.".to_string()),
        },

        // ============ System Management ============
        ComplianceControl {
            id: "ISM-1144".to_string(),
            control_id: "ISM-1144".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Patch Management".to_string(),
            description: "Security vulnerabilities in applications and operating systems are patched within timeframes.".to_string(),
            category: "System Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Patch critical vulnerabilities within 48 hours; high within 2 weeks.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1472".to_string(),
            control_id: "ISM-1472".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Vulnerability Scanning".to_string(),
            description: "Vulnerability assessments are performed regularly.".to_string(),
            category: "System Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string(), "PCI-DSS-11.2".to_string()],
            remediation_guidance: Some("Conduct vulnerability scans at least weekly; remediate findings promptly.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1467".to_string(),
            control_id: "ISM-1467".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Change Management".to_string(),
            description: "A change management process is implemented for system changes.".to_string(),
            category: "System Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "PCI-DSS-6.4".to_string()],
            remediation_guidance: Some("Implement formal change management with approval, testing, and rollback procedures.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1490".to_string(),
            control_id: "ISM-1490".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Configuration Management".to_string(),
            description: "Standard Operating Environments are documented and maintained.".to_string(),
            category: "System Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string()],
            remediation_guidance: Some("Document and maintain baseline configurations for all system types.".to_string()),
        },

        // ============ System Monitoring ============
        ComplianceControl {
            id: "ISM-0109".to_string(),
            control_id: "ISM-0109".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Event Logging".to_string(),
            description: "Centralised event logging is implemented.".to_string(),
            category: "System Monitoring".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "PCI-DSS-10.2".to_string()],
            remediation_guidance: Some("Implement centralised SIEM for log collection from all systems.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0580".to_string(),
            control_id: "ISM-0580".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Log Content".to_string(),
            description: "Event logs capture date, time, user, source, event type, and outcome.".to_string(),
            category: "System Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-3".to_string(), "PCI-DSS-10.3".to_string()],
            remediation_guidance: Some("Configure logging to capture required fields for all security events.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0585".to_string(),
            control_id: "ISM-0585".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Log Protection".to_string(),
            description: "Event logs are protected from unauthorised access and modification.".to_string(),
            category: "System Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string(), "PCI-DSS-10.5".to_string()],
            remediation_guidance: Some("Implement write-once logging; restrict access to log management systems.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0859".to_string(),
            control_id: "ISM-0859".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Log Retention".to_string(),
            description: "Event logs are retained for at least 7 years.".to_string(),
            category: "System Monitoring".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-11".to_string()],
            remediation_guidance: Some("Implement log archival with 7-year retention for compliance.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1228".to_string(),
            control_id: "ISM-1228".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Security Information and Event Management".to_string(),
            description: "A SIEM solution is implemented for real-time analysis and alerting.".to_string(),
            category: "System Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy SIEM with correlation rules for security event detection.".to_string()),
        },

        // ============ Software Development ============
        ComplianceControl {
            id: "ISM-0400".to_string(),
            control_id: "ISM-0400".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Secure Development Lifecycle".to_string(),
            description: "Software development follows a secure development lifecycle.".to_string(),
            category: "Software Development".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SA-3".to_string(), "OWASP-SDL".to_string()],
            remediation_guidance: Some("Integrate security into all phases of software development lifecycle.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0402".to_string(),
            control_id: "ISM-0402".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Code Review".to_string(),
            description: "Source code is reviewed for security vulnerabilities.".to_string(),
            category: "Software Development".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string(), "PCI-DSS-6.3".to_string()],
            remediation_guidance: Some("Perform security code reviews and SAST scanning before deployment.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1420".to_string(),
            control_id: "ISM-1420".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Application Security Testing".to_string(),
            description: "Web applications undergo security testing before deployment.".to_string(),
            category: "Software Development".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-11".to_string(), "PCI-DSS-6.6".to_string()],
            remediation_guidance: Some("Conduct DAST, penetration testing, and vulnerability assessment.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1238".to_string(),
            control_id: "ISM-1238".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Development Environment Separation".to_string(),
            description: "Development, testing, and production environments are separated.".to_string(),
            category: "Software Development".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-4".to_string(), "PCI-DSS-6.4".to_string()],
            remediation_guidance: Some("Maintain separate environments; no production data in dev/test.".to_string()),
        },

        // ============ Database Systems ============
        ComplianceControl {
            id: "ISM-1425".to_string(),
            control_id: "ISM-1425".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Database Security".to_string(),
            description: "Database management systems are hardened and secured.".to_string(),
            category: "Database Systems".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string(), "CIS-DB".to_string()],
            remediation_guidance: Some("Apply database hardening guides; remove default accounts.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1260".to_string(),
            control_id: "ISM-1260".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Database Access Control".to_string(),
            description: "Access to database systems is restricted to authorised personnel.".to_string(),
            category: "Database Systems".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Implement role-based access; use service accounts for applications.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1268".to_string(),
            control_id: "ISM-1268".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Database Encryption".to_string(),
            description: "Sensitive data in databases is encrypted.".to_string(),
            category: "Database Systems".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "PCI-DSS-3.4".to_string()],
            remediation_guidance: Some("Enable transparent data encryption; encrypt sensitive columns.".to_string()),
        },

        // ============ Email ============
        ComplianceControl {
            id: "ISM-0261".to_string(),
            control_id: "ISM-0261".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Email Gateway Security".to_string(),
            description: "Email gateways block malicious content and attachments.".to_string(),
            category: "Email".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Deploy email security gateway with anti-malware and sandboxing.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0269".to_string(),
            control_id: "ISM-0269".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "SPF/DKIM/DMARC".to_string(),
            description: "SPF, DKIM, and DMARC are implemented for email authentication.".to_string(),
            category: "Email".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Configure SPF, DKIM, and DMARC with reject policy for domain protection.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1234".to_string(),
            control_id: "ISM-1234".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Email Content Filtering".to_string(),
            description: "Email content filtering blocks prohibited attachments and content.".to_string(),
            category: "Email".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Block dangerous file types; scan compressed attachments.".to_string()),
        },

        // ============ Networking ============
        ComplianceControl {
            id: "ISM-0520".to_string(),
            control_id: "ISM-0520".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Network Segmentation".to_string(),
            description: "Networks are segmented based on sensitivity and security requirements.".to_string(),
            category: "Networking".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.2".to_string()],
            remediation_guidance: Some("Implement VLANs and firewall rules to segment network zones.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1416".to_string(),
            control_id: "ISM-1416".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Network Access Control".to_string(),
            description: "Network access control is implemented (802.1X).".to_string(),
            category: "Networking".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-3".to_string()],
            remediation_guidance: Some("Deploy 802.1X with certificate-based authentication.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1034".to_string(),
            control_id: "ISM-1034".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Firewall Implementation".to_string(),
            description: "Firewalls are implemented to control traffic between network zones.".to_string(),
            category: "Networking".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.1".to_string()],
            remediation_guidance: Some("Implement host and network firewalls with deny-by-default rules.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1427".to_string(),
            control_id: "ISM-1427".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Intrusion Detection".to_string(),
            description: "Network and host-based intrusion detection systems are deployed.".to_string(),
            category: "Networking".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "PCI-DSS-11.4".to_string()],
            remediation_guidance: Some("Deploy NIDS at network perimeter and HIDS on critical hosts.".to_string()),
        },

        // ============ Cryptography ============
        ComplianceControl {
            id: "ISM-0457".to_string(),
            control_id: "ISM-0457".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Encryption of Data at Rest".to_string(),
            description: "Data at rest is encrypted using ASD approved algorithms.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "PCI-DSS-3.4".to_string()],
            remediation_guidance: Some("Use AES-256 for data at rest; implement key management.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0465".to_string(),
            control_id: "ISM-0465".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Encryption of Data in Transit".to_string(),
            description: "Data in transit is encrypted using TLS 1.2 or higher.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Enforce TLS 1.2+; disable SSLv3, TLS 1.0, TLS 1.1.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0469".to_string(),
            control_id: "ISM-0469".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Key Management".to_string(),
            description: "Cryptographic keys are securely generated, stored, and managed.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string(), "PCI-DSS-3.5".to_string()],
            remediation_guidance: Some("Use HSMs for key storage; implement key rotation policies.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1139".to_string(),
            control_id: "ISM-1139".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Certificate Management".to_string(),
            description: "Digital certificates are managed throughout their lifecycle.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Implement certificate lifecycle management with renewal alerts.".to_string()),
        },

        // ============ Gateway Management ============
        ComplianceControl {
            id: "ISM-0631".to_string(),
            control_id: "ISM-0631".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Web Content Filtering".to_string(),
            description: "Web content filtering blocks malicious and inappropriate content.".to_string(),
            category: "Gateway Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Deploy web proxy with URL filtering and malware scanning.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0659".to_string(),
            control_id: "ISM-0659".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "TLS Inspection".to_string(),
            description: "TLS traffic is inspected at gateways for malicious content.".to_string(),
            category: "Gateway Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Implement TLS inspection with appropriate privacy controls.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1170".to_string(),
            control_id: "ISM-1170".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Gateway Anti-Malware".to_string(),
            description: "Gateway anti-malware solutions scan inbound and outbound traffic.".to_string(),
            category: "Gateway Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "PCI-DSS-5.1".to_string()],
            remediation_guidance: Some("Deploy multi-engine anti-malware at network gateway.".to_string()),
        },

        // ============ Data Transfers ============
        ComplianceControl {
            id: "ISM-0663".to_string(),
            control_id: "ISM-0663".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Data Import Controls".to_string(),
            description: "Data imports are scanned for malicious content.".to_string(),
            category: "Data Transfers".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Scan all imported data with multiple anti-malware engines.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0664".to_string(),
            control_id: "ISM-0664".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Data Export Controls".to_string(),
            description: "Data exports are authorised and logged.".to_string(),
            category: "Data Transfers".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string()],
            remediation_guidance: Some("Implement DLP to monitor and control data exports.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1187".to_string(),
            control_id: "ISM-1187".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Data Loss Prevention".to_string(),
            description: "Data loss prevention controls are implemented.".to_string(),
            category: "Data Transfers".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Deploy DLP solution at endpoints, network, and cloud.".to_string()),
        },

        // ============ Access Control (Additional) ============
        ComplianceControl {
            id: "ISM-0415".to_string(),
            control_id: "ISM-0415".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Identification and Authentication".to_string(),
            description: "Users are uniquely identified and authenticated before access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "PCI-DSS-8.1".to_string()],
            remediation_guidance: Some("Implement unique user IDs with strong authentication.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1173".to_string(),
            control_id: "ISM-1173".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Multi-Factor Authentication".to_string(),
            description: "Multi-factor authentication is used for privileged access and remote access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string(), "PCI-DSS-8.3".to_string()],
            remediation_guidance: Some("Implement MFA for all privileged access and remote connections.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0423".to_string(),
            control_id: "ISM-0423".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Privileged Access Management".to_string(),
            description: "Privileged access is restricted and managed.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CIS-5.4".to_string()],
            remediation_guidance: Some("Implement PAM solution with just-in-time access and session recording.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1503".to_string(),
            control_id: "ISM-1503".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Password Policy".to_string(),
            description: "Password policies enforce complexity and regular changes.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "PCI-DSS-8.2".to_string()],
            remediation_guidance: Some("Enforce minimum 14 character passwords with complexity requirements.".to_string()),
        },
        ComplianceControl {
            id: "ISM-0421".to_string(),
            control_id: "ISM-0421".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Session Timeout".to_string(),
            description: "Sessions are locked or terminated after a period of inactivity.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-11".to_string()],
            remediation_guidance: Some("Configure session timeout of 15 minutes for standard users.".to_string()),
        },

        // ============ Backup and Recovery ============
        ComplianceControl {
            id: "ISM-1511".to_string(),
            control_id: "ISM-1511".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Backup Strategy".to_string(),
            description: "A backup strategy is documented and implemented.".to_string(),
            category: "Backup and Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-9".to_string(), "CIS-11.1".to_string()],
            remediation_guidance: Some("Document backup strategy including frequency, retention, and offsite storage.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1515".to_string(),
            control_id: "ISM-1515".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Backup Testing".to_string(),
            description: "Backup restoration is tested regularly.".to_string(),
            category: "Backup and Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-4".to_string(), "CIS-11.5".to_string()],
            remediation_guidance: Some("Test backup restoration quarterly; document results.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1513".to_string(),
            control_id: "ISM-1513".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Backup Encryption".to_string(),
            description: "Backups are encrypted using approved cryptographic algorithms.".to_string(),
            category: "Backup and Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string()],
            remediation_guidance: Some("Encrypt all backups with AES-256; secure encryption keys separately.".to_string()),
        },

        // ============ Additional Security Controls ============
        ComplianceControl {
            id: "ISM-1526".to_string(),
            control_id: "ISM-1526".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Secure Administration Workstations".to_string(),
            description: "Privileged access is performed from dedicated secure administration workstations.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string(), "CIS-5.5".to_string()],
            remediation_guidance: Some("Implement dedicated PAWs with restricted network access and hardened configurations.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1528".to_string(),
            control_id: "ISM-1528".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Jump Server Usage".to_string(),
            description: "Access to sensitive servers is performed via jump servers.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Implement jump servers with session recording and MFA for all administrative access.".to_string()),
        },
        ComplianceControl {
            id: "ISM-1647".to_string(),
            control_id: "ISM-1647".to_string(),
            framework: ComplianceFramework::IsmAustralia,
            title: "Cyber Threat Intelligence".to_string(),
            description: "Cyber threat intelligence is used to inform cyber security activities.".to_string(),
            category: "Cyber Security Incidents".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-5".to_string()],
            remediation_guidance: Some("Subscribe to threat intelligence feeds; integrate with security monitoring tools.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant Australian ISM controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Patch management vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("eol")
    {
        mappings.push(("ISM-1144".to_string(), Severity::Critical));
        mappings.push(("ISM-1472".to_string(), Severity::High));
    }

    // Authentication vulnerabilities
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("weak password")
        || title_lower.contains("default password")
        || title_lower.contains("default credentials")
    {
        mappings.push(("ISM-0415".to_string(), Severity::Critical));
        mappings.push(("ISM-1173".to_string(), Severity::Critical));
        mappings.push(("ISM-1503".to_string(), Severity::High));
    }

    // MFA related
    if title_lower.contains("mfa") || title_lower.contains("multi-factor") || title_lower.contains("2fa") {
        mappings.push(("ISM-1173".to_string(), Severity::Critical));
    }

    // Privileged access vulnerabilities
    if title_lower.contains("privilege escalation")
        || title_lower.contains("unauthorized access")
        || title_lower.contains("admin access")
    {
        mappings.push(("ISM-0423".to_string(), Severity::Critical));
    }

    // Encryption vulnerabilities - data in transit
    if title_lower.contains("unencrypted")
        || title_lower.contains("cleartext")
        || title_lower.contains("plain text")
        || (title_lower.contains("ssl") && title_lower.contains("vulnerable"))
        || (title_lower.contains("tls") && (title_lower.contains("weak") || title_lower.contains("1.0") || title_lower.contains("1.1")))
    {
        mappings.push(("ISM-0465".to_string(), Severity::Critical));
        mappings.push(("ISM-0457".to_string(), Severity::High));
    }

    // Certificate issues
    if title_lower.contains("certificate")
        || title_lower.contains("expired cert")
        || title_lower.contains("self-signed")
    {
        mappings.push(("ISM-1139".to_string(), Severity::Medium));
    }

    // Injection vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("xss")
        || title_lower.contains("cross-site scripting")
    {
        mappings.push(("ISM-0402".to_string(), Severity::Critical));
        mappings.push(("ISM-1420".to_string(), Severity::Critical));
    }

    // Missing malware protection
    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("no antivirus")
    {
        mappings.push(("ISM-0261".to_string(), Severity::High));
        mappings.push(("ISM-1170".to_string(), Severity::High));
    }

    // Logging and monitoring issues
    if title_lower.contains("no logging")
        || title_lower.contains("audit disabled")
        || title_lower.contains("logging disabled")
    {
        mappings.push(("ISM-0109".to_string(), Severity::High));
        mappings.push(("ISM-0580".to_string(), Severity::Medium));
        mappings.push(("ISM-1228".to_string(), Severity::High));
    }

    // Firewall and network issues
    if title_lower.contains("firewall") || title_lower.contains("open port") || title_lower.contains("exposed service") {
        mappings.push(("ISM-1034".to_string(), Severity::Medium));
        mappings.push(("ISM-0520".to_string(), Severity::Medium));
    }

    // IDS/IPS issues
    if title_lower.contains("intrusion") || title_lower.contains("ids") || title_lower.contains("ips") {
        mappings.push(("ISM-1427".to_string(), Severity::High));
    }

    // Remote access issues
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") || title_lower.contains("rdp") || title_lower.contains("ssh") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") || title_lower.contains("weak") {
            mappings.push(("ISM-1173".to_string(), Severity::High));
        }
    }

    // Insecure protocols
    if port == Some(23) || title_lower.contains("telnet") || title_lower.contains("ftp") && !title_lower.contains("sftp") {
        mappings.push(("ISM-0465".to_string(), Severity::High));
        mappings.push(("ISM-1409".to_string(), Severity::Medium));
    }

    // Wireless security
    if title_lower.contains("wireless") || title_lower.contains("wifi") || title_lower.contains("wpa") {
        mappings.push(("ISM-1114".to_string(), Severity::High));
    }

    // Application control / software issues
    if title_lower.contains("unauthorized software")
        || title_lower.contains("unapproved application")
    {
        mappings.push(("ISM-1407".to_string(), Severity::High));
        mappings.push(("ISM-1492".to_string(), Severity::Medium));
    }

    // Macro/script vulnerabilities
    if title_lower.contains("macro") || title_lower.contains("vba") || title_lower.contains("office vulnerability") {
        mappings.push(("ISM-1418".to_string(), Severity::High));
    }

    // System hardening issues
    if title_lower.contains("hardening") || title_lower.contains("misconfiguration") || title_lower.contains("default config") {
        mappings.push(("ISM-0380".to_string(), Severity::High));
        mappings.push(("ISM-1490".to_string(), Severity::Medium));
    }

    // Database vulnerabilities
    if title_lower.contains("database") || title_lower.contains("sql server") || title_lower.contains("mysql") || title_lower.contains("postgresql") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") || title_lower.contains("unencrypted") {
            mappings.push(("ISM-1425".to_string(), Severity::High));
            mappings.push(("ISM-1260".to_string(), Severity::High));
            mappings.push(("ISM-1268".to_string(), Severity::High));
        }
    }

    // Email security
    if title_lower.contains("email") || title_lower.contains("smtp") || title_lower.contains("mail server") {
        if title_lower.contains("spf") || title_lower.contains("dkim") || title_lower.contains("dmarc") {
            mappings.push(("ISM-0269".to_string(), Severity::Medium));
        }
        if title_lower.contains("malware") || title_lower.contains("phishing") {
            mappings.push(("ISM-0261".to_string(), Severity::High));
            mappings.push(("ISM-1234".to_string(), Severity::High));
        }
    }

    // Mobile device issues
    if title_lower.contains("mobile") || title_lower.contains("mdm") || title_lower.contains("byod") {
        mappings.push(("ISM-1082".to_string(), Severity::High));
        mappings.push(("ISM-0869".to_string(), Severity::High));
    }

    // Removable media
    if title_lower.contains("usb") || title_lower.contains("removable media") || title_lower.contains("thumb drive") {
        mappings.push(("ISM-0347".to_string(), Severity::Medium));
        mappings.push(("ISM-0348".to_string(), Severity::Medium));
    }

    // Data leakage / DLP
    if title_lower.contains("data leak") || title_lower.contains("data loss") || title_lower.contains("exfiltration") {
        mappings.push(("ISM-1187".to_string(), Severity::High));
        mappings.push(("ISM-0664".to_string(), Severity::High));
    }

    // Backup issues
    if title_lower.contains("backup") {
        if title_lower.contains("missing") || title_lower.contains("no backup") {
            mappings.push(("ISM-1511".to_string(), Severity::High));
        }
        if title_lower.contains("unencrypted") {
            mappings.push(("ISM-1513".to_string(), Severity::High));
        }
    }

    // Asset management
    if title_lower.contains("unknown asset") || title_lower.contains("unmanaged device") || title_lower.contains("rogue device") {
        mappings.push(("ISM-0336".to_string(), Severity::Medium));
    }

    // Web proxy / content filtering
    if title_lower.contains("web proxy") || title_lower.contains("content filter") || title_lower.contains("url filter") {
        mappings.push(("ISM-0631".to_string(), Severity::Medium));
    }

    // Development security
    if title_lower.contains("source code") || title_lower.contains("code review") || title_lower.contains("sdlc") {
        mappings.push(("ISM-0400".to_string(), Severity::Medium));
        mappings.push(("ISM-0402".to_string(), Severity::Medium));
    }

    // Environment separation
    if title_lower.contains("production data in dev") || title_lower.contains("environment separation") {
        mappings.push(("ISM-1238".to_string(), Severity::High));
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
        let controls = get_controls();
        for control in &controls {
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
            assert!(control.framework == ComplianceFramework::IsmAustralia);
        }
    }

    #[test]
    fn test_categories_coverage() {
        let controls = get_controls();
        let categories: std::collections::HashSet<&str> = controls.iter().map(|c| c.category.as_str()).collect();

        // Verify key ISM categories are covered
        assert!(categories.contains("Cyber Security Roles"));
        assert!(categories.contains("Cyber Security Incidents"));
        assert!(categories.contains("System Hardening"));
        assert!(categories.contains("System Monitoring"));
        assert!(categories.contains("Cryptography"));
        assert!(categories.contains("Networking"));
        assert!(categories.contains("Email"));
        assert!(categories.contains("Gateway Management"));
    }

    #[test]
    fn test_vulnerability_mapping_patch_management() {
        let mappings = map_vulnerability("Outdated Apache version detected", None, Some(80), Some("http"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ISM-1144"));
    }

    #[test]
    fn test_vulnerability_mapping_authentication() {
        let mappings = map_vulnerability("Default credentials on admin panel", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ISM-0415"));
    }

    #[test]
    fn test_vulnerability_mapping_encryption() {
        let mappings = map_vulnerability("TLS 1.0 enabled - weak encryption", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ISM-0465"));
    }

    #[test]
    fn test_vulnerability_mapping_injection() {
        let mappings = map_vulnerability("SQL injection in login form", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ISM-0402"));
    }
}
