//! Australian IRAP (Information Security Registered Assessors Program)
//!
//! This module implements controls based on the Australian Government's
//! Information Security Manual (ISM) used for IRAP assessments.
//!
//! Key areas covered:
//! - Cyber Security Principles
//! - Guidelines for Cyber Security Roles
//! - Guidelines for Cyber Security Incidents
//! - Guidelines for Outsourcing
//! - Guidelines for Security Documentation
//! - Physical Security
//! - Personnel Security
//! - Communications Infrastructure
//! - Communications Systems
//! - Enterprise Mobility
//! - Network Security
//! - Cryptography
//! - Software Development

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of IRAP controls
pub const CONTROL_COUNT: usize = 45;

/// Get all IRAP controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Cyber Security Roles and Governance
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-GOV-001".to_string(),
        control_id: "ISM-0714".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Chief Information Security Officer".to_string(),
        description: "A Chief Information Security Officer provides cyber security leadership for their organisation".to_string(),
        category: "Governance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.2".to_string()],
        remediation_guidance: Some("Appoint a CISO with appropriate authority and resources".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-GOV-002".to_string(),
        control_id: "ISM-0724".to_string(),
        framework: ComplianceFramework::Irap,
        title: "System Security Plan".to_string(),
        description: "A system security plan is developed and maintained for each system".to_string(),
        category: "Governance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PL-2".to_string()],
        remediation_guidance: Some("Develop comprehensive system security plan documenting security controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-GOV-003".to_string(),
        control_id: "ISM-1526".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Cyber Security Strategy".to_string(),
        description: "A cyber security strategy is developed, implemented and maintained".to_string(),
        category: "Governance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Develop organization-wide cyber security strategy aligned with business objectives".to_string()),
    });

    // ========================================================================
    // Cyber Security Incidents
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-INC-001".to_string(),
        control_id: "ISM-0123".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Cyber Security Incident Register".to_string(),
        description: "A cyber security incident register is maintained with security incidents recorded".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IR-5".to_string()],
        remediation_guidance: Some("Implement incident tracking system with comprehensive logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-INC-002".to_string(),
        control_id: "ISM-0125".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Cyber Security Incident Response Plan".to_string(),
        description: "A cyber security incident response plan is developed, implemented and maintained".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-8".to_string()],
        remediation_guidance: Some("Develop and document incident response procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-INC-003".to_string(),
        control_id: "ISM-0140".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Reporting Cyber Security Incidents".to_string(),
        description: "Cyber security incidents are reported to the ACSC as soon as practicable".to_string(),
        category: "Incident Response".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-6".to_string()],
        remediation_guidance: Some("Establish process for reporting incidents to ACSC".to_string()),
    });

    // ========================================================================
    // Personnel Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-PER-001".to_string(),
        control_id: "ISM-0434".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Cyber Security Awareness Training".to_string(),
        description: "Personnel are provided with ongoing cyber security awareness training".to_string(),
        category: "Personnel Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AT-2".to_string()],
        remediation_guidance: Some("Implement ongoing security awareness training program".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-PER-002".to_string(),
        control_id: "ISM-0252".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Access to Systems".to_string(),
        description: "Personnel are granted access to systems and information based on their duties".to_string(),
        category: "Personnel Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2".to_string()],
        remediation_guidance: Some("Implement role-based access control aligned with job functions".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-PER-003".to_string(),
        control_id: "ISM-0430".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Privileged Access".to_string(),
        description: "Privileged access to systems is limited to personnel who require it".to_string(),
        category: "Personnel Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string()],
        remediation_guidance: Some("Restrict privileged access using least privilege principle".to_string()),
    });

    // ========================================================================
    // Access Control
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-ACC-001".to_string(),
        control_id: "ISM-0974".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Multi-Factor Authentication".to_string(),
        description: "Multi-factor authentication is used to authenticate privileged users of systems".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2(1)".to_string()],
        remediation_guidance: Some("Implement MFA for all privileged access".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-ACC-002".to_string(),
        control_id: "ISM-1173".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Multi-Factor Authentication for Remote Access".to_string(),
        description: "Multi-factor authentication is used to authenticate all users for remote access".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2(1)".to_string()],
        remediation_guidance: Some("Require MFA for all remote access connections".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-ACC-003".to_string(),
        control_id: "ISM-0421".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Passphrase Requirements".to_string(),
        description: "Passphrases used for single-factor authentication are at least 14 characters".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-5".to_string()],
        remediation_guidance: Some("Configure minimum passphrase length of 14 characters".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-ACC-004".to_string(),
        control_id: "ISM-0428".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Account Lockout".to_string(),
        description: "Accounts are locked out after a maximum of five failed authentication attempts".to_string(),
        category: "Access Control".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-7".to_string()],
        remediation_guidance: Some("Configure account lockout after 5 failed attempts".to_string()),
    });

    // ========================================================================
    // Network Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-NET-001".to_string(),
        control_id: "ISM-1192".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Network Segmentation".to_string(),
        description: "Networks are segmented and segregated based on the sensitivity of information".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string()],
        remediation_guidance: Some("Implement network segmentation based on data classification".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-NET-002".to_string(),
        control_id: "ISM-1037".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Firewall Configuration".to_string(),
        description: "A firewall is implemented between networks of different security domains".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7(5)".to_string()],
        remediation_guidance: Some("Deploy firewalls at security domain boundaries".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-NET-003".to_string(),
        control_id: "ISM-1416".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Denial of Service Protection".to_string(),
        description: "Denial of service protection is implemented for internet-facing services".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-5".to_string()],
        remediation_guidance: Some("Implement DDoS protection for public-facing services".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-NET-004".to_string(),
        control_id: "ISM-0520".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Wireless Network Security".to_string(),
        description: "Only WPA2 or WPA3 Enterprise with AES is used for wireless networks".to_string(),
        category: "Network Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-8".to_string()],
        remediation_guidance: Some("Configure wireless networks with WPA2/WPA3 Enterprise".to_string()),
    });

    // ========================================================================
    // Cryptography
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-CRY-001".to_string(),
        control_id: "ISM-0457".to_string(),
        framework: ComplianceFramework::Irap,
        title: "ASD Approved Cryptographic Algorithms".to_string(),
        description: "Only ASD Approved Cryptographic Algorithms are used".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-13".to_string()],
        remediation_guidance: Some("Use only ASD-approved cryptographic algorithms".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-CRY-002".to_string(),
        control_id: "ISM-1139".to_string(),
        framework: ComplianceFramework::Irap,
        title: "TLS Configuration".to_string(),
        description: "Only the latest version of TLS is used for protecting data in transit".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-8".to_string()],
        remediation_guidance: Some("Configure systems to use TLS 1.3 or TLS 1.2 with approved cipher suites".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-CRY-003".to_string(),
        control_id: "ISM-0459".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Encryption at Rest".to_string(),
        description: "Encryption is implemented for data at rest".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-28".to_string()],
        remediation_guidance: Some("Implement full disk encryption and database encryption".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-CRY-004".to_string(),
        control_id: "ISM-0462".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Cryptographic Key Management".to_string(),
        description: "Cryptographic keys are protected from unauthorised access".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-12".to_string()],
        remediation_guidance: Some("Implement secure key management with HSM or equivalent".to_string()),
    });

    // ========================================================================
    // System Hardening
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-HAR-001".to_string(),
        control_id: "ISM-0843".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Operating System Hardening".to_string(),
        description: "Operating systems are hardened by disabling unnecessary functionality".to_string(),
        category: "System Hardening".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-7".to_string()],
        remediation_guidance: Some("Apply operating system hardening benchmarks".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-HAR-002".to_string(),
        control_id: "ISM-0380".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Application Control".to_string(),
        description: "Application control is implemented on workstations".to_string(),
        category: "System Hardening".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-7(5)".to_string()],
        remediation_guidance: Some("Implement application whitelisting on all workstations".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-HAR-003".to_string(),
        control_id: "ISM-1490".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Microsoft Office Macro Settings".to_string(),
        description: "Microsoft Office macros are disabled or only enabled for trusted documents".to_string(),
        category: "System Hardening".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-7".to_string()],
        remediation_guidance: Some("Configure Office to disable macros except in trusted locations".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-HAR-004".to_string(),
        control_id: "ISM-1412".to_string(),
        framework: ComplianceFramework::Irap,
        title: "User Application Hardening".to_string(),
        description: "Web browsers are configured to block advertisements, Flash, and Java".to_string(),
        category: "System Hardening".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-7".to_string()],
        remediation_guidance: Some("Harden web browsers by blocking unnecessary plugins".to_string()),
    });

    // ========================================================================
    // Patch Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-PAT-001".to_string(),
        control_id: "ISM-1143".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Patch Applications Within 48 Hours".to_string(),
        description: "Security vulnerabilities in internet-facing services are patched within 48 hours".to_string(),
        category: "Patch Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-2".to_string()],
        remediation_guidance: Some("Implement automated patching for critical vulnerabilities within 48 hours".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-PAT-002".to_string(),
        control_id: "ISM-1144".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Patch Operating Systems Within Two Weeks".to_string(),
        description: "Security vulnerabilities in operating systems are patched within two weeks".to_string(),
        category: "Patch Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-2".to_string()],
        remediation_guidance: Some("Establish process to patch OS vulnerabilities within 14 days".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-PAT-003".to_string(),
        control_id: "ISM-1472".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Patch Applications Within One Month".to_string(),
        description: "Security vulnerabilities in other applications are patched within one month".to_string(),
        category: "Patch Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-2".to_string()],
        remediation_guidance: Some("Patch non-critical applications within 30 days".to_string()),
    });

    // ========================================================================
    // Monitoring and Logging
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-LOG-001".to_string(),
        control_id: "ISM-0580".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Event Logging".to_string(),
        description: "Event logs are collected and analysed in a timely manner".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-6".to_string()],
        remediation_guidance: Some("Implement centralized log collection and analysis".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-LOG-002".to_string(),
        control_id: "ISM-0585".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Event Log Content".to_string(),
        description: "Event logs capture sufficient information for forensic purposes".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-3".to_string()],
        remediation_guidance: Some("Configure comprehensive logging including user, action, timestamp, and outcome".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-LOG-003".to_string(),
        control_id: "ISM-0859".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Log Retention".to_string(),
        description: "Event logs are retained for at least 7 years".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-11".to_string()],
        remediation_guidance: Some("Configure log retention for minimum 7 years".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-LOG-004".to_string(),
        control_id: "ISM-1405".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Log Protection".to_string(),
        description: "Event logs are protected from unauthorised modification and deletion".to_string(),
        category: "Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-9".to_string()],
        remediation_guidance: Some("Implement write-once logging or tamper-evident storage".to_string()),
    });

    // ========================================================================
    // Data Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-DAT-001".to_string(),
        control_id: "ISM-0663".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Data Classification".to_string(),
        description: "Information and systems are classified based on sensitivity".to_string(),
        category: "Data Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-RA-2".to_string()],
        remediation_guidance: Some("Implement data classification scheme aligned with PSPF".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-DAT-002".to_string(),
        control_id: "ISM-0664".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Data Labelling".to_string(),
        description: "Information is labelled with its protective marking".to_string(),
        category: "Data Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-MP-3".to_string()],
        remediation_guidance: Some("Implement data labelling for all sensitive information".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-DAT-003".to_string(),
        control_id: "ISM-0348".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Media Sanitisation".to_string(),
        description: "Media is sanitised before disposal or reuse".to_string(),
        category: "Data Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-MP-6".to_string()],
        remediation_guidance: Some("Implement secure media sanitisation procedures".to_string()),
    });

    // ========================================================================
    // Backup and Recovery
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-BCK-001".to_string(),
        control_id: "ISM-1511".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Regular Backups".to_string(),
        description: "Backups of important data, software and configuration settings are performed and tested".to_string(),
        category: "Backup".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-9".to_string()],
        remediation_guidance: Some("Implement regular tested backups with offsite storage".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-BCK-002".to_string(),
        control_id: "ISM-1515".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Backup Retention".to_string(),
        description: "Backups are retained for an appropriate period".to_string(),
        category: "Backup".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-9".to_string()],
        remediation_guidance: Some("Define and implement backup retention policy".to_string()),
    });

    // ========================================================================
    // Software Development
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-DEV-001".to_string(),
        control_id: "ISM-0400".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Secure Development Practices".to_string(),
        description: "Software is developed using secure development practices".to_string(),
        category: "Development".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SA-15".to_string()],
        remediation_guidance: Some("Implement SDLC with security gates and testing".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-DEV-002".to_string(),
        control_id: "ISM-1419".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Code Review".to_string(),
        description: "Source code is reviewed for security vulnerabilities".to_string(),
        category: "Development".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SA-11".to_string()],
        remediation_guidance: Some("Implement mandatory code review including security analysis".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-DEV-003".to_string(),
        control_id: "ISM-1420".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Development Environment Separation".to_string(),
        description: "Development, testing and production environments are separated".to_string(),
        category: "Development".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-4".to_string()],
        remediation_guidance: Some("Maintain separate dev, test, and production environments".to_string()),
    });

    // ========================================================================
    // Email Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "IRAP-EML-001".to_string(),
        control_id: "ISM-0569".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Email Content Filtering".to_string(),
        description: "Email content filtering is implemented for inbound and outbound email".to_string(),
        category: "Email Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-3".to_string()],
        remediation_guidance: Some("Deploy email gateway with content filtering and malware scanning".to_string()),
    });

    controls.push(ComplianceControl {
        id: "IRAP-EML-002".to_string(),
        control_id: "ISM-0574".to_string(),
        framework: ComplianceFramework::Irap,
        title: "Email Authentication".to_string(),
        description: "SPF, DKIM and DMARC are implemented for email authentication".to_string(),
        category: "Email Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["BOD-18-01".to_string()],
        remediation_guidance: Some("Configure SPF, DKIM, and DMARC with enforcement".to_string()),
    });

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant IRAP controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication / MFA
    if title_lower.contains("authentication") || title_lower.contains("mfa") || title_lower.contains("password") {
        mappings.push(("ISM-0974".to_string(), Severity::Critical));
        mappings.push(("ISM-0421".to_string(), Severity::High));
        mappings.push(("ISM-0428".to_string(), Severity::High));
    }

    // Encryption / TLS
    if title_lower.contains("encryption") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("plaintext") {
        mappings.push(("ISM-0457".to_string(), Severity::Critical));
        mappings.push(("ISM-1139".to_string(), Severity::Critical));
        mappings.push(("ISM-0459".to_string(), Severity::High));
    }

    // Network segmentation
    if title_lower.contains("segment") || title_lower.contains("firewall") || title_lower.contains("network") {
        mappings.push(("ISM-1192".to_string(), Severity::High));
        mappings.push(("ISM-1037".to_string(), Severity::High));
    }

    // Patching
    if title_lower.contains("patch") || title_lower.contains("outdated") || title_lower.contains("vulnerability")
        || title_lower.contains("cve") {
        mappings.push(("ISM-1143".to_string(), Severity::Critical));
        mappings.push(("ISM-1144".to_string(), Severity::High));
    }

    // Logging / Monitoring
    if title_lower.contains("log") || title_lower.contains("audit") || title_lower.contains("monitor") {
        mappings.push(("ISM-0580".to_string(), Severity::High));
        mappings.push(("ISM-0585".to_string(), Severity::High));
    }

    // Application control / Hardening
    if title_lower.contains("whitelist") || title_lower.contains("harden") || title_lower.contains("macro") {
        mappings.push(("ISM-0380".to_string(), Severity::Critical));
        mappings.push(("ISM-1490".to_string(), Severity::High));
    }

    // Privileged access
    if title_lower.contains("privilege") || title_lower.contains("admin") || title_lower.contains("root") {
        mappings.push(("ISM-0430".to_string(), Severity::Critical));
        mappings.push(("ISM-0974".to_string(), Severity::Critical));
    }

    // Email security
    if title_lower.contains("email") || title_lower.contains("spf") || title_lower.contains("dkim")
        || title_lower.contains("dmarc") {
        mappings.push(("ISM-0574".to_string(), Severity::High));
        mappings.push(("ISM-0569".to_string(), Severity::High));
    }

    // Wireless
    if title_lower.contains("wireless") || title_lower.contains("wifi") || title_lower.contains("wpa") {
        mappings.push(("ISM-0520".to_string(), Severity::High));
    }

    // Backup
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("ISM-1511".to_string(), Severity::High));
    }

    // Default mapping
    if mappings.is_empty() {
        mappings.push(("ISM-0843".to_string(), Severity::Medium));
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
            assert_eq!(control.framework, ComplianceFramework::Irap);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Missing MFA on privileged accounts", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ISM-0974"));

        let patch_mappings = map_vulnerability("Outdated software version CVE-2023-1234", None, None, None);
        assert!(patch_mappings.iter().any(|(id, _)| id == "ISM-1143"));
    }
}
