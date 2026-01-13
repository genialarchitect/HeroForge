//! CISA Cybersecurity Performance Goals (CPGs) Framework
//!
//! The CISA CPGs are a prioritized subset of IT and OT cybersecurity practices
//! aimed at reducing the most significant risks to critical infrastructure.
//! These voluntary cross-sector goals provide a common set of fundamental
//! protections that all critical infrastructure organizations should implement.
//!
//! Released October 2022, Version 1.0
//!
//! CPG Categories (Cross-Sector):
//! 1. Account Security
//! 2. Device Security
//! 3. Data Security
//! 4. Governance and Training
//! 5. Vulnerability Management
//! 6. Supply Chain / Third Party
//! 7. Response and Recovery
//! 8. Other (Network Segmentation, Detection, Email Security)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of CISA CPG controls in this module
pub const CONTROL_COUNT: usize = 42;

/// Get all CISA CPG controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // CATEGORY 1: ACCOUNT SECURITY
        // ============================================================
        ComplianceControl {
            id: "CPG-1.A".to_string(),
            control_id: "1.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Multi-Factor Authentication for Remote Access".to_string(),
            description: "Require multi-factor authentication (MFA) for all remote access to the organization's network.".to_string(),
            category: "Account Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-02".to_string(),
                "NIST-IA-2(1)".to_string(),
                "CIS-6.3".to_string(),
            ],
            remediation_guidance: Some("Implement MFA for VPN, remote desktop, and all external access points using TOTP, hardware tokens, or push notifications.".to_string()),
        },
        ComplianceControl {
            id: "CPG-1.B".to_string(),
            control_id: "1.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Multi-Factor Authentication for Privileged Users".to_string(),
            description: "Require multi-factor authentication for all users with administrative or elevated privileges.".to_string(),
            category: "Account Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-02".to_string(),
                "NIST-IA-2(2)".to_string(),
                "CIS-6.5".to_string(),
            ],
            remediation_guidance: Some("Enforce MFA for domain admins, database admins, cloud admins, and all privileged account access.".to_string()),
        },
        ComplianceControl {
            id: "CPG-1.C".to_string(),
            control_id: "1.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Strong Password Requirements".to_string(),
            description: "Implement minimum password length of 15 characters for all accounts where MFA is not implemented, or 8 characters with MFA.".to_string(),
            category: "Account Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-01".to_string(),
                "NIST-IA-5".to_string(),
                "CIS-5.2".to_string(),
            ],
            remediation_guidance: Some("Configure password policies to require minimum 15 characters without MFA, or 8 characters with MFA. Ban common passwords.".to_string()),
        },
        ComplianceControl {
            id: "CPG-1.D".to_string(),
            control_id: "1.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Unique Credentials".to_string(),
            description: "Ensure all user accounts have unique credentials and prohibit shared accounts.".to_string(),
            category: "Account Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-01".to_string(),
                "NIST-IA-2".to_string(),
                "CIS-5.1".to_string(),
            ],
            remediation_guidance: Some("Eliminate shared accounts, implement individual accountability, and use service accounts with unique credentials for automation.".to_string()),
        },
        ComplianceControl {
            id: "CPG-1.E".to_string(),
            control_id: "1.E".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Revoke Credentials for Departing Users".to_string(),
            description: "Revoke credentials for departing employees and contractors within 24 hours of termination.".to_string(),
            category: "Account Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-01".to_string(),
                "NIST-PS-4".to_string(),
                "CIS-5.3".to_string(),
            ],
            remediation_guidance: Some("Implement offboarding procedures with HR integration, automated account disablement, and access review processes.".to_string()),
        },
        ComplianceControl {
            id: "CPG-1.F".to_string(),
            control_id: "1.F".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Separate Admin and User Accounts".to_string(),
            description: "Administrative users should have separate accounts for administrative and non-administrative activities.".to_string(),
            category: "Account Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-03".to_string(),
                "NIST-AC-6(2)".to_string(),
                "CIS-5.4".to_string(),
            ],
            remediation_guidance: Some("Create separate privileged accounts for admins, implement PAM solutions, and restrict daily activities to standard user accounts.".to_string()),
        },

        // ============================================================
        // CATEGORY 2: DEVICE SECURITY
        // ============================================================
        ComplianceControl {
            id: "CPG-2.A".to_string(),
            control_id: "2.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Hardware Asset Inventory".to_string(),
            description: "Maintain an accurate and current inventory of all hardware assets, including IT, OT, and IoT devices.".to_string(),
            category: "Device Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-ID.AM-01".to_string(),
                "NIST-CM-8".to_string(),
                "CIS-1.1".to_string(),
            ],
            remediation_guidance: Some("Deploy automated asset discovery tools, maintain CMDB, and conduct regular physical audits of hardware.".to_string()),
        },
        ComplianceControl {
            id: "CPG-2.B".to_string(),
            control_id: "2.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Software Asset Inventory".to_string(),
            description: "Maintain an accurate and current inventory of all installed software and services.".to_string(),
            category: "Device Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-ID.AM-02".to_string(),
                "NIST-CM-8".to_string(),
                "CIS-2.1".to_string(),
            ],
            remediation_guidance: Some("Implement software inventory tools, maintain application catalog, and track software versions and licenses.".to_string()),
        },
        ComplianceControl {
            id: "CPG-2.C".to_string(),
            control_id: "2.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Disable Macros by Default".to_string(),
            description: "Disable macros by default in office applications and only allow signed macros from trusted publishers.".to_string(),
            category: "Device Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.PS-01".to_string(),
                "NIST-CM-7".to_string(),
                "CIS-2.7".to_string(),
            ],
            remediation_guidance: Some("Configure Group Policy to disable macros, implement AMSI protection, and establish trusted publisher signing.".to_string()),
        },
        ComplianceControl {
            id: "CPG-2.D".to_string(),
            control_id: "2.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Change Default Credentials".to_string(),
            description: "Change all default passwords and credentials on network devices, applications, and OT systems before deployment.".to_string(),
            category: "Device Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-01".to_string(),
                "NIST-IA-5".to_string(),
                "CIS-4.2".to_string(),
            ],
            remediation_guidance: Some("Document and change all default credentials, scan for default passwords, and implement credential management procedures.".to_string()),
        },
        ComplianceControl {
            id: "CPG-2.E".to_string(),
            control_id: "2.E".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Secure Configuration Baselines".to_string(),
            description: "Apply secure configuration baselines (hardening) to all systems before deployment.".to_string(),
            category: "Device Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.PS-01".to_string(),
                "NIST-CM-2".to_string(),
                "CIS-4.1".to_string(),
            ],
            remediation_guidance: Some("Implement CIS Benchmarks or DISA STIGs, use configuration management tools, and validate compliance regularly.".to_string()),
        },
        ComplianceControl {
            id: "CPG-2.F".to_string(),
            control_id: "2.F".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Disable Unnecessary Services".to_string(),
            description: "Disable all unnecessary services, ports, and protocols on all systems and devices.".to_string(),
            category: "Device Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.PS-01".to_string(),
                "NIST-CM-7".to_string(),
                "CIS-4.8".to_string(),
            ],
            remediation_guidance: Some("Audit running services, disable unused ports, remove unnecessary software, and apply least functionality principle.".to_string()),
        },

        // ============================================================
        // CATEGORY 3: DATA SECURITY
        // ============================================================
        ComplianceControl {
            id: "CPG-3.A".to_string(),
            control_id: "3.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Encrypt Data at Rest".to_string(),
            description: "Encrypt sensitive data at rest using industry-standard encryption algorithms (AES-256 or equivalent).".to_string(),
            category: "Data Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.DS-01".to_string(),
                "NIST-SC-28".to_string(),
                "CIS-3.6".to_string(),
            ],
            remediation_guidance: Some("Implement full disk encryption, database encryption (TDE), and encrypted storage solutions for sensitive data.".to_string()),
        },
        ComplianceControl {
            id: "CPG-3.B".to_string(),
            control_id: "3.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Encrypt Data in Transit".to_string(),
            description: "Encrypt all sensitive data in transit using TLS 1.2 or higher.".to_string(),
            category: "Data Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.DS-02".to_string(),
                "NIST-SC-8".to_string(),
                "CIS-3.10".to_string(),
            ],
            remediation_guidance: Some("Enforce TLS 1.2+ for all network communications, disable weak ciphers, and implement certificate validation.".to_string()),
        },
        ComplianceControl {
            id: "CPG-3.C".to_string(),
            control_id: "3.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Secure Log Storage".to_string(),
            description: "Store and protect logs securely, ensuring integrity and availability for forensic analysis.".to_string(),
            category: "Data Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.PS-04".to_string(),
                "NIST-AU-9".to_string(),
                "CIS-8.1".to_string(),
            ],
            remediation_guidance: Some("Centralize logs in SIEM, implement log integrity controls, retain logs per policy, and restrict log access.".to_string()),
        },
        ComplianceControl {
            id: "CPG-3.D".to_string(),
            control_id: "3.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Secure Backup Procedures".to_string(),
            description: "Implement secure, encrypted backups with regular testing of restoration procedures.".to_string(),
            category: "Data Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.DS-11".to_string(),
                "NIST-CP-9".to_string(),
                "CIS-11.2".to_string(),
            ],
            remediation_guidance: Some("Implement 3-2-1 backup strategy, encrypt backups, store offsite copies, and test restore procedures quarterly.".to_string()),
        },
        ComplianceControl {
            id: "CPG-3.E".to_string(),
            control_id: "3.E".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Data Classification".to_string(),
            description: "Classify data based on sensitivity and implement appropriate protections for each classification level.".to_string(),
            category: "Data Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-ID.AM-05".to_string(),
                "NIST-RA-2".to_string(),
                "CIS-3.1".to_string(),
            ],
            remediation_guidance: Some("Develop data classification policy, label sensitive data, implement DLP controls, and train users on handling procedures.".to_string()),
        },

        // ============================================================
        // CATEGORY 4: GOVERNANCE AND TRAINING
        // ============================================================
        ComplianceControl {
            id: "CPG-4.A".to_string(),
            control_id: "4.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Organizational Cybersecurity Leadership".to_string(),
            description: "Assign a qualified individual responsibility for cybersecurity leadership at the organizational level.".to_string(),
            category: "Governance and Training".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-GV.OC-01".to_string(),
                "NIST-PM-2".to_string(),
            ],
            remediation_guidance: Some("Appoint CISO or equivalent, define cybersecurity roles and responsibilities, and establish reporting lines to leadership.".to_string()),
        },
        ComplianceControl {
            id: "CPG-4.B".to_string(),
            control_id: "4.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "OT/ICS Cybersecurity Leadership".to_string(),
            description: "Assign a qualified individual responsibility for OT/ICS cybersecurity if operational technology is present.".to_string(),
            category: "Governance and Training".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-GV.OC-01".to_string(),
                "NIST-PM-2".to_string(),
            ],
            remediation_guidance: Some("Designate OT security lead, ensure IT/OT coordination, and establish OT-specific security governance.".to_string()),
        },
        ComplianceControl {
            id: "CPG-4.C".to_string(),
            control_id: "4.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Basic Cybersecurity Training".to_string(),
            description: "Provide basic cybersecurity awareness training to all employees upon hiring and annually thereafter.".to_string(),
            category: "Governance and Training".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AT-01".to_string(),
                "NIST-AT-2".to_string(),
                "CIS-14.1".to_string(),
            ],
            remediation_guidance: Some("Implement security awareness program, track completion, include phishing awareness, and conduct annual refresher training.".to_string()),
        },
        ComplianceControl {
            id: "CPG-4.D".to_string(),
            control_id: "4.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "OT/ICS-Specific Training".to_string(),
            description: "Provide OT/ICS-specific cybersecurity training to personnel working with operational technology.".to_string(),
            category: "Governance and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AT-01".to_string(),
                "NIST-AT-3".to_string(),
            ],
            remediation_guidance: Some("Develop OT-specific training curriculum, include safety considerations, and train on OT security procedures.".to_string()),
        },
        ComplianceControl {
            id: "CPG-4.E".to_string(),
            control_id: "4.E".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Documented Cybersecurity Policies".to_string(),
            description: "Maintain documented cybersecurity policies that are reviewed and updated regularly.".to_string(),
            category: "Governance and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-GV.RM-01".to_string(),
                "NIST-PL-1".to_string(),
            ],
            remediation_guidance: Some("Document security policies, review annually, communicate to staff, and maintain version control.".to_string()),
        },

        // ============================================================
        // CATEGORY 5: VULNERABILITY MANAGEMENT
        // ============================================================
        ComplianceControl {
            id: "CPG-5.A".to_string(),
            control_id: "5.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Known Exploited Vulnerability Remediation".to_string(),
            description: "Remediate vulnerabilities in CISA's Known Exploited Vulnerabilities (KEV) catalog within the specified timeframes.".to_string(),
            category: "Vulnerability Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-ID.RA-01".to_string(),
                "NIST-SI-2".to_string(),
                "CIS-7.4".to_string(),
            ],
            remediation_guidance: Some("Monitor CISA KEV catalog, prioritize KEV patches, track remediation progress, and report exceptions to leadership.".to_string()),
        },
        ComplianceControl {
            id: "CPG-5.B".to_string(),
            control_id: "5.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Critical Vulnerability Remediation".to_string(),
            description: "Remediate critical and high-severity vulnerabilities within defined timeframes (e.g., 15 days for critical, 30 days for high).".to_string(),
            category: "Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-ID.RA-06".to_string(),
                "NIST-SI-2".to_string(),
                "CIS-7.5".to_string(),
            ],
            remediation_guidance: Some("Define vulnerability SLAs by severity, automate patch deployment, track metrics, and escalate overdue items.".to_string()),
        },
        ComplianceControl {
            id: "CPG-5.C".to_string(),
            control_id: "5.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Regular Vulnerability Scanning".to_string(),
            description: "Perform automated vulnerability scanning of all internet-facing systems at least monthly.".to_string(),
            category: "Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-DE.CM-09".to_string(),
                "NIST-RA-5".to_string(),
                "CIS-7.1".to_string(),
            ],
            remediation_guidance: Some("Deploy vulnerability scanners, schedule regular scans, integrate with ticketing, and validate remediation.".to_string()),
        },
        ComplianceControl {
            id: "CPG-5.D".to_string(),
            control_id: "5.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "End-of-Life Software Replacement".to_string(),
            description: "Replace or mitigate software and hardware that has reached end-of-life and no longer receives security updates.".to_string(),
            category: "Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.PS-02".to_string(),
                "NIST-SA-22".to_string(),
                "CIS-2.2".to_string(),
            ],
            remediation_guidance: Some("Maintain EOL tracking, plan migrations, apply compensating controls for exceptions, and document risk acceptance.".to_string()),
        },

        // ============================================================
        // CATEGORY 6: SUPPLY CHAIN / THIRD PARTY
        // ============================================================
        ComplianceControl {
            id: "CPG-6.A".to_string(),
            control_id: "6.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Vendor Security Assessment".to_string(),
            description: "Assess the cybersecurity practices of vendors and third parties before granting access to systems or data.".to_string(),
            category: "Supply Chain / Third Party".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-GV.SC-01".to_string(),
                "NIST-SR-6".to_string(),
            ],
            remediation_guidance: Some("Implement vendor risk assessment process, require security questionnaires, review SOC 2 reports, and assess before onboarding.".to_string()),
        },
        ComplianceControl {
            id: "CPG-6.B".to_string(),
            control_id: "6.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Supply Chain Security Requirements".to_string(),
            description: "Include cybersecurity requirements in contracts with vendors and third parties.".to_string(),
            category: "Supply Chain / Third Party".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-GV.SC-01".to_string(),
                "NIST-SR-3".to_string(),
            ],
            remediation_guidance: Some("Update contract templates with security clauses, require incident notification, and include audit rights.".to_string()),
        },
        ComplianceControl {
            id: "CPG-6.C".to_string(),
            control_id: "6.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Software Bill of Materials".to_string(),
            description: "Request and maintain Software Bill of Materials (SBOM) for critical software products.".to_string(),
            category: "Supply Chain / Third Party".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-ID.AM-02".to_string(),
                "NIST-SR-4".to_string(),
            ],
            remediation_guidance: Some("Request SBOMs from vendors, generate SBOMs for internally developed software, and monitor component vulnerabilities.".to_string()),
        },
        ComplianceControl {
            id: "CPG-6.D".to_string(),
            control_id: "6.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Third-Party Access Management".to_string(),
            description: "Limit and monitor third-party access to only what is necessary for their function.".to_string(),
            category: "Supply Chain / Third Party".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-03".to_string(),
                "NIST-AC-6".to_string(),
            ],
            remediation_guidance: Some("Implement least privilege for vendors, use PAM for third-party access, monitor sessions, and review access quarterly.".to_string()),
        },

        // ============================================================
        // CATEGORY 7: RESPONSE AND RECOVERY
        // ============================================================
        ComplianceControl {
            id: "CPG-7.A".to_string(),
            control_id: "7.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Incident Response Plan".to_string(),
            description: "Develop, document, and maintain an incident response plan that is tested at least annually.".to_string(),
            category: "Response and Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.IR-01".to_string(),
                "NIST-IR-1".to_string(),
            ],
            remediation_guidance: Some("Document IR plan with roles, procedures, and contacts. Conduct tabletop exercises annually and after major incidents.".to_string()),
        },
        ComplianceControl {
            id: "CPG-7.B".to_string(),
            control_id: "7.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Incident Reporting Procedures".to_string(),
            description: "Establish procedures for reporting significant cybersecurity incidents to CISA and other authorities.".to_string(),
            category: "Response and Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-RS.CO-02".to_string(),
                "NIST-IR-6".to_string(),
            ],
            remediation_guidance: Some("Document reporting requirements, establish contact with CISA, define incident thresholds, and train staff on procedures.".to_string()),
        },
        ComplianceControl {
            id: "CPG-7.C".to_string(),
            control_id: "7.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Business Continuity Planning".to_string(),
            description: "Develop and maintain business continuity and disaster recovery plans that address cybersecurity scenarios.".to_string(),
            category: "Response and Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-RC.RP-01".to_string(),
                "NIST-CP-2".to_string(),
            ],
            remediation_guidance: Some("Document BCP/DR plans, include cyber scenarios, define RTOs/RPOs, and test recovery procedures annually.".to_string()),
        },
        ComplianceControl {
            id: "CPG-7.D".to_string(),
            control_id: "7.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Backup Testing".to_string(),
            description: "Test restoration from backups at least annually to verify recovery capability.".to_string(),
            category: "Response and Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CSF-RC.RP-03".to_string(),
                "NIST-CP-4".to_string(),
                "CIS-11.5".to_string(),
            ],
            remediation_guidance: Some("Schedule regular restore tests, document results, verify data integrity, and update procedures based on findings.".to_string()),
        },

        // ============================================================
        // CATEGORY 8: OTHER (Network Security, Detection, Email)
        // ============================================================
        ComplianceControl {
            id: "CPG-8.A".to_string(),
            control_id: "8.A".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Network Segmentation".to_string(),
            description: "Segment networks to limit lateral movement and separate IT from OT networks where applicable.".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-05".to_string(),
                "NIST-SC-7".to_string(),
                "CIS-12.1".to_string(),
            ],
            remediation_guidance: Some("Implement VLANs, firewalls between zones, microsegmentation, and ensure IT/OT separation with DMZs.".to_string()),
        },
        ComplianceControl {
            id: "CPG-8.B".to_string(),
            control_id: "8.B".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "DNS Protection".to_string(),
            description: "Implement protective DNS services to block access to known malicious domains.".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-DE.CM-01".to_string(),
                "NIST-SC-20".to_string(),
            ],
            remediation_guidance: Some("Deploy protective DNS (e.g., CISA's Protective DNS, Cisco Umbrella), block known malicious domains, and monitor DNS queries.".to_string()),
        },
        ComplianceControl {
            id: "CPG-8.C".to_string(),
            control_id: "8.C".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Email Security Controls".to_string(),
            description: "Implement email security controls including SPF, DKIM, and DMARC for all organization domains.".to_string(),
            category: "Email Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.DS-02".to_string(),
                "NIST-SC-7".to_string(),
            ],
            remediation_guidance: Some("Configure SPF, DKIM, and DMARC (reject policy) for all domains. Monitor DMARC reports and block spoofed emails.".to_string()),
        },
        ComplianceControl {
            id: "CPG-8.D".to_string(),
            control_id: "8.D".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Phishing-Resistant Authentication".to_string(),
            description: "Implement phishing-resistant MFA (FIDO2/WebAuthn) for high-value targets and privileged users.".to_string(),
            category: "Email Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-02".to_string(),
                "NIST-IA-2(6)".to_string(),
            ],
            remediation_guidance: Some("Deploy FIDO2 security keys or platform authenticators for executives, admins, and high-value users.".to_string()),
        },
        ComplianceControl {
            id: "CPG-8.E".to_string(),
            control_id: "8.E".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Centralized Log Collection".to_string(),
            description: "Collect and aggregate security logs from all critical systems in a centralized location.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-DE.AE-03".to_string(),
                "NIST-AU-6".to_string(),
                "CIS-8.2".to_string(),
            ],
            remediation_guidance: Some("Deploy SIEM, configure log forwarding from all systems, ensure adequate storage, and implement log retention policy.".to_string()),
        },
        ComplianceControl {
            id: "CPG-8.F".to_string(),
            control_id: "8.F".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Intrusion Detection".to_string(),
            description: "Deploy intrusion detection capabilities to identify potentially malicious activity.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-DE.CM-01".to_string(),
                "NIST-SI-4".to_string(),
                "CIS-13.3".to_string(),
            ],
            remediation_guidance: Some("Deploy IDS/IPS at network boundaries, implement host-based detection, tune signatures, and monitor alerts 24/7.".to_string()),
        },
        ComplianceControl {
            id: "CPG-8.G".to_string(),
            control_id: "8.G".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Endpoint Detection and Response".to_string(),
            description: "Deploy EDR solutions on all endpoints to detect and respond to malicious activity.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-DE.CM-01".to_string(),
                "NIST-SI-4".to_string(),
                "CIS-10.1".to_string(),
            ],
            remediation_guidance: Some("Deploy EDR to all endpoints, configure automatic blocking, integrate with SIEM, and ensure 24/7 monitoring coverage.".to_string()),
        },
        ComplianceControl {
            id: "CPG-8.H".to_string(),
            control_id: "8.H".to_string(),
            framework: ComplianceFramework::CisaCpgs,
            title: "Remote Access Security".to_string(),
            description: "Secure all remote access methods and remove insecure protocols (Telnet, unencrypted FTP, etc.).".to_string(),
            category: "Network Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "CSF-PR.AA-05".to_string(),
                "NIST-AC-17".to_string(),
                "CIS-12.7".to_string(),
            ],
            remediation_guidance: Some("Disable Telnet, FTP, and other insecure protocols. Use SSH, SFTP, VPN with MFA for all remote access.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant CISA CPG controls
pub fn map_vulnerability(
    vuln_title: &str,
    cve_id: Option<&str>,
    _port: Option<u16>,
    service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();
    let service_lower = service.map(|s| s.to_lowercase()).unwrap_or_default();

    // Known Exploited Vulnerabilities (check CVE against KEV catalog concept)
    if cve_id.is_some() {
        // All CVEs should be evaluated against KEV
        mappings.push(("CPG-5.A".to_string(), Severity::Critical));
        // Critical vulnerabilities mapping
        if title_lower.contains("critical") || title_lower.contains("remote code execution") || title_lower.contains("rce") {
            mappings.push(("CPG-5.B".to_string(), Severity::Critical));
        }
    }

    // MFA-related findings
    if title_lower.contains("mfa")
        || title_lower.contains("multi-factor")
        || title_lower.contains("two-factor")
        || title_lower.contains("2fa")
    {
        mappings.push(("CPG-1.A".to_string(), Severity::Critical));
        mappings.push(("CPG-1.B".to_string(), Severity::Critical));
    }

    // Password/credential issues
    if title_lower.contains("password")
        || title_lower.contains("credential")
        || title_lower.contains("weak auth")
    {
        mappings.push(("CPG-1.C".to_string(), Severity::High));
        mappings.push(("CPG-1.D".to_string(), Severity::High));
    }

    // Default credentials
    if title_lower.contains("default password")
        || title_lower.contains("default credential")
        || title_lower.contains("default login")
    {
        mappings.push(("CPG-2.D".to_string(), Severity::Critical));
    }

    // Phishing-resistant auth
    if title_lower.contains("phishing") || title_lower.contains("credential theft") {
        mappings.push(("CPG-8.D".to_string(), Severity::High));
    }

    // Asset inventory issues
    if title_lower.contains("unknown device")
        || title_lower.contains("unauthorized asset")
        || title_lower.contains("rogue device")
    {
        mappings.push(("CPG-2.A".to_string(), Severity::Medium));
        mappings.push(("CPG-2.B".to_string(), Severity::Medium));
    }

    // Macro-related vulnerabilities
    if title_lower.contains("macro") || title_lower.contains("vba") {
        mappings.push(("CPG-2.C".to_string(), Severity::High));
    }

    // Configuration issues
    if title_lower.contains("misconfigur")
        || title_lower.contains("hardening")
        || title_lower.contains("insecure config")
    {
        mappings.push(("CPG-2.E".to_string(), Severity::High));
    }

    // Unnecessary services
    if title_lower.contains("unnecessary service")
        || title_lower.contains("unused port")
        || title_lower.contains("disabled service")
    {
        mappings.push(("CPG-2.F".to_string(), Severity::Medium));
    }

    // Encryption at rest issues
    if title_lower.contains("unencrypted data")
        || title_lower.contains("plaintext storage")
        || title_lower.contains("encryption at rest")
    {
        mappings.push(("CPG-3.A".to_string(), Severity::High));
    }

    // Encryption in transit issues
    if title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("certificate")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted connection")
    {
        mappings.push(("CPG-3.B".to_string(), Severity::High));
    }

    // Backup issues
    if title_lower.contains("backup") || title_lower.contains("restore") {
        mappings.push(("CPG-3.D".to_string(), Severity::High));
        mappings.push(("CPG-7.D".to_string(), Severity::High));
    }

    // Vulnerability scanning gaps
    if title_lower.contains("unscanned") || title_lower.contains("scan coverage") {
        mappings.push(("CPG-5.C".to_string(), Severity::Medium));
    }

    // End-of-life software
    if title_lower.contains("end of life")
        || title_lower.contains("eol")
        || title_lower.contains("unsupported")
        || title_lower.contains("deprecated")
    {
        mappings.push(("CPG-5.D".to_string(), Severity::High));
    }

    // Third-party/supply chain issues
    if title_lower.contains("third party")
        || title_lower.contains("vendor")
        || title_lower.contains("supply chain")
    {
        mappings.push(("CPG-6.A".to_string(), Severity::Medium));
        mappings.push(("CPG-6.D".to_string(), Severity::High));
    }

    // SBOM-related
    if title_lower.contains("sbom") || title_lower.contains("software composition") {
        mappings.push(("CPG-6.C".to_string(), Severity::Medium));
    }

    // Network segmentation issues
    if title_lower.contains("segmentation")
        || title_lower.contains("lateral movement")
        || title_lower.contains("network isolation")
        || title_lower.contains("flat network")
    {
        mappings.push(("CPG-8.A".to_string(), Severity::High));
    }

    // DNS security issues
    if title_lower.contains("dns") && (title_lower.contains("poison") || title_lower.contains("hijack") || title_lower.contains("spoof")) {
        mappings.push(("CPG-8.B".to_string(), Severity::High));
    }

    // Email security issues
    if title_lower.contains("spf")
        || title_lower.contains("dkim")
        || title_lower.contains("dmarc")
        || title_lower.contains("email spoof")
    {
        mappings.push(("CPG-8.C".to_string(), Severity::High));
    }

    // Logging issues
    if title_lower.contains("logging") || title_lower.contains("audit log") || title_lower.contains("log collection") {
        mappings.push(("CPG-3.C".to_string(), Severity::High));
        mappings.push(("CPG-8.E".to_string(), Severity::High));
    }

    // IDS/Detection issues
    if title_lower.contains("intrusion detection")
        || title_lower.contains("ids")
        || title_lower.contains("detection gap")
    {
        mappings.push(("CPG-8.F".to_string(), Severity::High));
    }

    // EDR/Endpoint issues
    if title_lower.contains("edr")
        || title_lower.contains("endpoint detection")
        || title_lower.contains("antivirus")
        || title_lower.contains("malware protection")
    {
        mappings.push(("CPG-8.G".to_string(), Severity::High));
    }

    // Insecure remote access
    if title_lower.contains("telnet")
        || (service_lower.contains("telnet"))
        || (service_lower.contains("ftp") && !service_lower.contains("sftp"))
        || title_lower.contains("insecure remote")
    {
        mappings.push(("CPG-8.H".to_string(), Severity::High));
    }

    // Service-specific mappings for common insecure services
    match service_lower.as_str() {
        "telnet" => {
            mappings.push(("CPG-8.H".to_string(), Severity::High));
        }
        "ftp" => {
            mappings.push(("CPG-8.H".to_string(), Severity::High));
            mappings.push(("CPG-3.B".to_string(), Severity::High));
        }
        "http" => {
            mappings.push(("CPG-3.B".to_string(), Severity::Medium));
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
    fn test_all_controls_have_required_fields() {
        for control in get_controls() {
            assert!(!control.id.is_empty(), "Control ID should not be empty");
            assert!(!control.control_id.is_empty(), "Control control_id should not be empty");
            assert!(!control.title.is_empty(), "Control title should not be empty");
            assert!(!control.description.is_empty(), "Control description should not be empty");
            assert!(!control.category.is_empty(), "Control category should not be empty");
            assert_eq!(control.framework, ComplianceFramework::CisaCpgs);
        }
    }

    #[test]
    fn test_control_categories() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> = controls.iter().map(|c| c.category.clone()).collect();

        // Verify all expected categories are present
        assert!(categories.contains("Account Security"));
        assert!(categories.contains("Device Security"));
        assert!(categories.contains("Data Security"));
        assert!(categories.contains("Governance and Training"));
        assert!(categories.contains("Vulnerability Management"));
        assert!(categories.contains("Supply Chain / Third Party"));
        assert!(categories.contains("Response and Recovery"));
        assert!(categories.contains("Network Security"));
        assert!(categories.contains("Email Security"));
        assert!(categories.contains("Detection"));
    }

    #[test]
    fn test_cross_references_to_nist_csf() {
        let controls = get_controls();
        let mut has_csf_reference = false;

        for control in &controls {
            for xref in &control.cross_references {
                if xref.starts_with("CSF-") {
                    has_csf_reference = true;
                    break;
                }
            }
            if has_csf_reference {
                break;
            }
        }

        assert!(has_csf_reference, "Should have NIST CSF cross-references");
    }

    #[test]
    fn test_vulnerability_mapping_cve() {
        let mappings = map_vulnerability("Critical vulnerability CVE-2024-1234", Some("CVE-2024-1234"), None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CPG-5.A"));
    }

    #[test]
    fn test_vulnerability_mapping_mfa() {
        let mappings = map_vulnerability("Missing MFA for remote access", None, None, None);
        assert!(mappings.iter().any(|(id, _)| id == "CPG-1.A"));
        assert!(mappings.iter().any(|(id, _)| id == "CPG-1.B"));
    }

    #[test]
    fn test_vulnerability_mapping_default_credentials() {
        let mappings = map_vulnerability("Default password detected", None, None, None);
        assert!(mappings.iter().any(|(id, _)| id == "CPG-2.D"));
    }

    #[test]
    fn test_vulnerability_mapping_telnet() {
        let mappings = map_vulnerability("Telnet service exposed", None, Some(23), Some("telnet"));
        assert!(mappings.iter().any(|(id, _)| id == "CPG-8.H"));
    }

    #[test]
    fn test_vulnerability_mapping_email_security() {
        let mappings = map_vulnerability("Missing DMARC record", None, None, None);
        assert!(mappings.iter().any(|(id, _)| id == "CPG-8.C"));
    }

    #[test]
    fn test_vulnerability_mapping_eol_software() {
        let mappings = map_vulnerability("End of life Windows Server 2012", None, None, None);
        assert!(mappings.iter().any(|(id, _)| id == "CPG-5.D"));
    }
}
