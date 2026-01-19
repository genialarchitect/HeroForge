//! German C5 (Cloud Computing Compliance Criteria Catalogue) Controls
//!
//! This module implements controls based on the German BSI C5:2020
//! (Cloud Computing Compliance Criteria Catalogue), which provides
//! a framework for assessing cloud service providers' security.
//!
//! Key domains covered:
//! - Organization of Information Security (OIS)
//! - Security Policies (SP)
//! - Personnel (HR)
//! - Asset Management (AM)
//! - Physical Security (PS)
//! - Operations Management (OPS)
//! - Identity and Access Management (IDM)
//! - Cryptography and Key Management (CRY)
//! - Communication Security (COS)
//! - Portability and Interoperability (PI)
//! - Procurement and Development (DEV)
//! - Supplier Management (SSO)
//! - Incident Management (SIM)
//! - Business Continuity (BCM)
//! - Compliance (COM)
//! - Documentation (DOC)
//! - Auditing (AUD)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of C5 controls
pub const CONTROL_COUNT: usize = 49;

/// Get all C5 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // OIS - Organization of Information Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-OIS-01".to_string(),
        control_id: "OIS-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Information Security Management System".to_string(),
        description: "An Information Security Management System (ISMS) is implemented, documented, and continuously improved".to_string(),
        category: "Organization of Information Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-4".to_string()],
        remediation_guidance: Some("Implement an ISMS aligned with ISO 27001".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OIS-02".to_string(),
        control_id: "OIS-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Roles and Responsibilities".to_string(),
        description: "Information security roles and responsibilities are defined and assigned".to_string(),
        category: "Organization of Information Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.2".to_string()],
        remediation_guidance: Some("Define and document security roles and responsibilities".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OIS-03".to_string(),
        control_id: "OIS-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Risk Management".to_string(),
        description: "A risk management process is established for information security risks".to_string(),
        category: "Organization of Information Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-6.1".to_string(), "NIST-RA-3".to_string()],
        remediation_guidance: Some("Implement comprehensive risk management process".to_string()),
    });

    // ========================================================================
    // SP - Security Policies
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-SP-01".to_string(),
        control_id: "SP-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Information Security Policy".to_string(),
        description: "An information security policy approved by management is documented and communicated".to_string(),
        category: "Security Policies".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Develop and approve comprehensive security policy".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-SP-02".to_string(),
        control_id: "SP-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Policy Review".to_string(),
        description: "Security policies are reviewed and updated at planned intervals".to_string(),
        category: "Security Policies".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Establish annual policy review process".to_string()),
    });

    // ========================================================================
    // HR - Personnel
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-HR-01".to_string(),
        control_id: "HR-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Security Screening".to_string(),
        description: "Background verification checks are carried out for all candidates for employment".to_string(),
        category: "Personnel".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.6.1".to_string()],
        remediation_guidance: Some("Implement background check procedures for employees".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-HR-02".to_string(),
        control_id: "HR-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Security Awareness Training".to_string(),
        description: "All employees receive appropriate security awareness training".to_string(),
        category: "Personnel".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AT-2".to_string()],
        remediation_guidance: Some("Implement security awareness training program".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-HR-03".to_string(),
        control_id: "HR-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Termination Process".to_string(),
        description: "Access rights are revoked promptly upon termination of employment".to_string(),
        category: "Personnel".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PS-4".to_string()],
        remediation_guidance: Some("Implement automated account deprovisioning".to_string()),
    });

    // ========================================================================
    // AM - Asset Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-AM-01".to_string(),
        control_id: "AM-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Asset Inventory".to_string(),
        description: "An inventory of all assets associated with information and information processing is maintained".to_string(),
        category: "Asset Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-8".to_string()],
        remediation_guidance: Some("Maintain comprehensive asset inventory".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-AM-02".to_string(),
        control_id: "AM-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Asset Classification".to_string(),
        description: "Information is classified according to its value, legal requirements, and sensitivity".to_string(),
        category: "Asset Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.12".to_string()],
        remediation_guidance: Some("Implement data classification scheme".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-AM-03".to_string(),
        control_id: "AM-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Media Handling".to_string(),
        description: "Procedures for the secure handling of media are implemented".to_string(),
        category: "Asset Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-MP-6".to_string()],
        remediation_guidance: Some("Implement secure media handling and disposal procedures".to_string()),
    });

    // ========================================================================
    // PS - Physical Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-PS-01".to_string(),
        control_id: "PS-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Physical Security Perimeter".to_string(),
        description: "Security perimeters are defined and implemented to protect areas containing information".to_string(),
        category: "Physical Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PE-3".to_string()],
        remediation_guidance: Some("Define and implement physical security perimeters".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-PS-02".to_string(),
        control_id: "PS-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Physical Access Control".to_string(),
        description: "Access to secure areas is controlled through appropriate entry controls".to_string(),
        category: "Physical Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PE-3".to_string()],
        remediation_guidance: Some("Implement physical access controls with logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-PS-03".to_string(),
        control_id: "PS-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Environmental Protection".to_string(),
        description: "Protection against environmental threats is implemented".to_string(),
        category: "Physical Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PE-13".to_string()],
        remediation_guidance: Some("Implement environmental controls (fire, flood, HVAC)".to_string()),
    });

    // ========================================================================
    // OPS - Operations Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-OPS-01".to_string(),
        control_id: "OPS-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Operating Procedures".to_string(),
        description: "Operating procedures are documented, maintained, and made available".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.37".to_string()],
        remediation_guidance: Some("Document and maintain operating procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OPS-02".to_string(),
        control_id: "OPS-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Change Management".to_string(),
        description: "Changes to information systems are controlled through formal change management".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-3".to_string()],
        remediation_guidance: Some("Implement formal change management process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OPS-03".to_string(),
        control_id: "OPS-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Capacity Management".to_string(),
        description: "Resource capacity is monitored and adjusted to meet availability requirements".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.6".to_string()],
        remediation_guidance: Some("Implement capacity monitoring and planning".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OPS-04".to_string(),
        control_id: "OPS-04".to_string(),
        framework: ComplianceFramework::C5,
        title: "Malware Protection".to_string(),
        description: "Protection against malware is implemented and updated regularly".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-3".to_string()],
        remediation_guidance: Some("Deploy and maintain anti-malware solutions".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OPS-05".to_string(),
        control_id: "OPS-05".to_string(),
        framework: ComplianceFramework::C5,
        title: "Backup".to_string(),
        description: "Backup copies of information and software are taken and tested regularly".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-9".to_string()],
        remediation_guidance: Some("Implement and test backup procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OPS-06".to_string(),
        control_id: "OPS-06".to_string(),
        framework: ComplianceFramework::C5,
        title: "Event Logging".to_string(),
        description: "Event logs recording user activities and security events are produced and retained".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-2".to_string()],
        remediation_guidance: Some("Configure comprehensive security event logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OPS-07".to_string(),
        control_id: "OPS-07".to_string(),
        framework: ComplianceFramework::C5,
        title: "Log Protection".to_string(),
        description: "Logging facilities and log information are protected against tampering".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-9".to_string()],
        remediation_guidance: Some("Implement log integrity protection".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-OPS-08".to_string(),
        control_id: "OPS-08".to_string(),
        framework: ComplianceFramework::C5,
        title: "Vulnerability Management".to_string(),
        description: "Technical vulnerabilities are identified and remediated in a timely manner".to_string(),
        category: "Operations Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-RA-5".to_string()],
        remediation_guidance: Some("Implement vulnerability scanning and patch management".to_string()),
    });

    // ========================================================================
    // IDM - Identity and Access Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-IDM-01".to_string(),
        control_id: "IDM-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Access Control Policy".to_string(),
        description: "An access control policy is established based on business requirements".to_string(),
        category: "Identity and Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AC-1".to_string()],
        remediation_guidance: Some("Develop and implement access control policy".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-IDM-02".to_string(),
        control_id: "IDM-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "User Registration".to_string(),
        description: "A formal user registration and de-registration process is implemented".to_string(),
        category: "Identity and Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2".to_string()],
        remediation_guidance: Some("Implement formal user provisioning process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-IDM-03".to_string(),
        control_id: "IDM-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Privileged Access".to_string(),
        description: "Privileged access rights are restricted and controlled".to_string(),
        category: "Identity and Access Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string()],
        remediation_guidance: Some("Implement privileged access management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-IDM-04".to_string(),
        control_id: "IDM-04".to_string(),
        framework: ComplianceFramework::C5,
        title: "Authentication".to_string(),
        description: "Access to systems requires authentication through secure procedures".to_string(),
        category: "Identity and Access Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2".to_string()],
        remediation_guidance: Some("Implement strong authentication including MFA".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-IDM-05".to_string(),
        control_id: "IDM-05".to_string(),
        framework: ComplianceFramework::C5,
        title: "Access Review".to_string(),
        description: "Access rights are reviewed at regular intervals".to_string(),
        category: "Identity and Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2(3)".to_string()],
        remediation_guidance: Some("Implement periodic access reviews".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-IDM-06".to_string(),
        control_id: "IDM-06".to_string(),
        framework: ComplianceFramework::C5,
        title: "Multi-Factor Authentication".to_string(),
        description: "Multi-factor authentication is used for remote access and privileged accounts".to_string(),
        category: "Identity and Access Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2(1)".to_string()],
        remediation_guidance: Some("Deploy MFA for all remote and privileged access".to_string()),
    });

    // ========================================================================
    // CRY - Cryptography and Key Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-CRY-01".to_string(),
        control_id: "CRY-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Cryptographic Policy".to_string(),
        description: "A policy on the use of cryptographic controls is implemented".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.24".to_string()],
        remediation_guidance: Some("Develop and implement cryptographic policy".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-CRY-02".to_string(),
        control_id: "CRY-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Key Management".to_string(),
        description: "Cryptographic keys are protected throughout their lifecycle".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-12".to_string()],
        remediation_guidance: Some("Implement secure key management procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-CRY-03".to_string(),
        control_id: "CRY-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Encryption at Rest".to_string(),
        description: "Customer data is encrypted at rest using approved algorithms".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-28".to_string()],
        remediation_guidance: Some("Encrypt all customer data at rest".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-CRY-04".to_string(),
        control_id: "CRY-04".to_string(),
        framework: ComplianceFramework::C5,
        title: "Encryption in Transit".to_string(),
        description: "Data in transit is protected using TLS 1.2 or higher".to_string(),
        category: "Cryptography".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-8".to_string()],
        remediation_guidance: Some("Enforce TLS 1.2+ for all communications".to_string()),
    });

    // ========================================================================
    // COS - Communication Security
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-COS-01".to_string(),
        control_id: "COS-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Network Segmentation".to_string(),
        description: "Networks are segregated based on security requirements".to_string(),
        category: "Communication Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string()],
        remediation_guidance: Some("Implement network segmentation".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-COS-02".to_string(),
        control_id: "COS-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Network Security Controls".to_string(),
        description: "Network security controls including firewalls and IDS/IPS are implemented".to_string(),
        category: "Communication Security".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7(5)".to_string()],
        remediation_guidance: Some("Deploy and configure network security controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-COS-03".to_string(),
        control_id: "COS-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "DDoS Protection".to_string(),
        description: "Protection against denial of service attacks is implemented".to_string(),
        category: "Communication Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-5".to_string()],
        remediation_guidance: Some("Implement DDoS mitigation measures".to_string()),
    });

    // ========================================================================
    // PI - Portability and Interoperability
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-PI-01".to_string(),
        control_id: "PI-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Data Portability".to_string(),
        description: "Customers can export their data in standard formats".to_string(),
        category: "Portability".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.20".to_string()],
        remediation_guidance: Some("Provide data export capabilities in standard formats".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-PI-02".to_string(),
        control_id: "PI-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Service Interoperability".to_string(),
        description: "Standard interfaces and protocols are used for interoperability".to_string(),
        category: "Portability".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Use standard APIs and protocols".to_string()),
    });

    // ========================================================================
    // DEV - Procurement and Development
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-DEV-01".to_string(),
        control_id: "DEV-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Secure Development Policy".to_string(),
        description: "A secure development policy is established and applied".to_string(),
        category: "Development".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-15".to_string()],
        remediation_guidance: Some("Implement secure SDLC".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-DEV-02".to_string(),
        control_id: "DEV-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Security Testing".to_string(),
        description: "Security testing is performed during development".to_string(),
        category: "Development".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SA-11".to_string()],
        remediation_guidance: Some("Integrate security testing in CI/CD".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-DEV-03".to_string(),
        control_id: "DEV-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Environment Separation".to_string(),
        description: "Development, testing and production environments are separated".to_string(),
        category: "Development".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-4".to_string()],
        remediation_guidance: Some("Maintain separate environments".to_string()),
    });

    // ========================================================================
    // SSO - Supplier Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-SSO-01".to_string(),
        control_id: "SSO-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Supplier Security Policy".to_string(),
        description: "Security requirements for suppliers are defined and monitored".to_string(),
        category: "Supplier Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SR-3".to_string()],
        remediation_guidance: Some("Define supplier security requirements".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-SSO-02".to_string(),
        control_id: "SSO-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Supplier Risk Assessment".to_string(),
        description: "Risks from suppliers are assessed and managed".to_string(),
        category: "Supplier Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SR-6".to_string()],
        remediation_guidance: Some("Conduct supplier risk assessments".to_string()),
    });

    // ========================================================================
    // SIM - Incident Management
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-SIM-01".to_string(),
        control_id: "SIM-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Incident Management Process".to_string(),
        description: "An incident management process is established and implemented".to_string(),
        category: "Incident Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-8".to_string()],
        remediation_guidance: Some("Establish incident response process".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-SIM-02".to_string(),
        control_id: "SIM-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Incident Reporting".to_string(),
        description: "Security incidents are reported through appropriate channels".to_string(),
        category: "Incident Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IR-6".to_string()],
        remediation_guidance: Some("Implement incident reporting procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-SIM-03".to_string(),
        control_id: "SIM-03".to_string(),
        framework: ComplianceFramework::C5,
        title: "Customer Notification".to_string(),
        description: "Customers are notified of security incidents affecting their data".to_string(),
        category: "Incident Management".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.33".to_string()],
        remediation_guidance: Some("Establish customer notification procedures".to_string()),
    });

    // ========================================================================
    // BCM - Business Continuity
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-BCM-01".to_string(),
        control_id: "BCM-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Business Continuity Plan".to_string(),
        description: "Business continuity plans are developed, implemented, and tested".to_string(),
        category: "Business Continuity".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-2".to_string()],
        remediation_guidance: Some("Develop and test BCP".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-BCM-02".to_string(),
        control_id: "BCM-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Redundancy".to_string(),
        description: "Sufficient redundancy is implemented to meet availability requirements".to_string(),
        category: "Business Continuity".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-7".to_string()],
        remediation_guidance: Some("Implement redundant systems and data centers".to_string()),
    });

    // ========================================================================
    // COM - Compliance
    // ========================================================================

    controls.push(ComplianceControl {
        id: "C5-COM-01".to_string(),
        control_id: "COM-01".to_string(),
        framework: ComplianceFramework::C5,
        title: "Legal Requirements".to_string(),
        description: "Applicable legal, regulatory, and contractual requirements are identified".to_string(),
        category: "Compliance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.31".to_string()],
        remediation_guidance: Some("Identify and document compliance requirements".to_string()),
    });

    controls.push(ComplianceControl {
        id: "C5-COM-02".to_string(),
        control_id: "COM-02".to_string(),
        framework: ComplianceFramework::C5,
        title: "Data Location".to_string(),
        description: "Customers are informed of data storage locations".to_string(),
        category: "Compliance".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.44".to_string()],
        remediation_guidance: Some("Document and communicate data locations".to_string()),
    });

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant C5 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication / Access Control
    if title_lower.contains("authentication") || title_lower.contains("mfa") || title_lower.contains("password") {
        mappings.push(("IDM-04".to_string(), Severity::Critical));
        mappings.push(("IDM-06".to_string(), Severity::Critical));
    }

    // Privileged access
    if title_lower.contains("privilege") || title_lower.contains("admin") || title_lower.contains("root") {
        mappings.push(("IDM-03".to_string(), Severity::Critical));
    }

    // Encryption
    if title_lower.contains("encryption") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("plaintext") {
        mappings.push(("CRY-03".to_string(), Severity::Critical));
        mappings.push(("CRY-04".to_string(), Severity::Critical));
    }

    // Key management
    if title_lower.contains("key") || title_lower.contains("certificate") {
        mappings.push(("CRY-02".to_string(), Severity::Critical));
    }

    // Network security
    if title_lower.contains("network") || title_lower.contains("firewall") || title_lower.contains("segment") {
        mappings.push(("COS-01".to_string(), Severity::High));
        mappings.push(("COS-02".to_string(), Severity::High));
    }

    // DDoS
    if title_lower.contains("dos") || title_lower.contains("ddos") {
        mappings.push(("COS-03".to_string(), Severity::High));
    }

    // Vulnerability management
    if title_lower.contains("vulnerability") || title_lower.contains("patch") || title_lower.contains("cve") {
        mappings.push(("OPS-08".to_string(), Severity::Critical));
    }

    // Malware
    if title_lower.contains("malware") || title_lower.contains("virus") || title_lower.contains("ransomware") {
        mappings.push(("OPS-04".to_string(), Severity::Critical));
    }

    // Logging
    if title_lower.contains("log") || title_lower.contains("audit") || title_lower.contains("monitor") {
        mappings.push(("OPS-06".to_string(), Severity::High));
        mappings.push(("OPS-07".to_string(), Severity::High));
    }

    // Backup
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("OPS-05".to_string(), Severity::High));
    }

    // Development security
    if title_lower.contains("code") || title_lower.contains("injection") || title_lower.contains("xss") {
        mappings.push(("DEV-02".to_string(), Severity::High));
    }

    // Configuration
    if title_lower.contains("config") || title_lower.contains("change") {
        mappings.push(("OPS-02".to_string(), Severity::High));
    }

    // Default mapping
    if mappings.is_empty() {
        mappings.push(("OIS-03".to_string(), Severity::Medium));
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
            assert_eq!(control.framework, ComplianceFramework::C5);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Weak TLS configuration", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CRY-04"));

        let auth_mappings = map_vulnerability("Missing multi-factor authentication", None, None, None);
        assert!(auth_mappings.iter().any(|(id, _)| id == "IDM-06"));
    }
}
