//! CSA Cloud Controls Matrix (CCM) v4.0 Controls
//!
//! This module implements the Cloud Security Alliance (CSA) Cloud Controls Matrix v4.0,
//! a cybersecurity control framework for cloud computing environments.
//!
//! The CCM v4.0 consists of 17 domains covering 197 control specifications.
//! This implementation includes the most critical and commonly assessed controls
//! across all domains for automated and manual compliance assessment.
//!
//! Domains:
//! - AIS: Application & Interface Security
//! - AAC: Audit Assurance & Compliance
//! - BCM: Business Continuity Management
//! - CCC: Change Control & Configuration
//! - CEK: Cryptography, Encryption & Key Management
//! - DCS: Datacenter Security
//! - DSP: Data Security & Privacy
//! - GRC: Governance, Risk & Compliance
//! - HRS: Human Resources
//! - IAM: Identity & Access Management
//! - IVS: Infrastructure & Virtualization Security
//! - IPY: Interoperability & Portability
//! - LOG: Logging & Monitoring
//! - SEF: Security Incident Management
//! - STA: Supply Chain Management
//! - TVM: Threat & Vulnerability Management
//! - UEM: Universal Endpoint Management

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of CSA CCM v4.0 controls in this implementation
pub const CONTROL_COUNT: usize = 80;

/// Get all CSA CCM v4.0 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Application & Interface Security (AIS)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-AIS-01".to_string(),
        control_id: "AIS-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Application Security".to_string(),
        description: "Establish, document, and implement application security policies and procedures to ensure application security throughout the development lifecycle".to_string(),
        category: "Application & Interface Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-3".to_string(), "ISO27001-A.8.25".to_string()],
        remediation_guidance: Some("Implement secure SDLC policies including security requirements, secure coding standards, and security testing".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-AIS-02".to_string(),
        control_id: "AIS-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Application Security Baseline Requirements".to_string(),
        description: "Establish and maintain baseline requirements for securing different applications".to_string(),
        category: "Application & Interface Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SA-8".to_string(), "PCI-DSS-6.5".to_string()],
        remediation_guidance: Some("Define and enforce minimum security requirements for all applications based on data sensitivity and exposure".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-AIS-03".to_string(),
        control_id: "AIS-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Application Security Metrics".to_string(),
        description: "Establish metrics to identify and document application security findings and remediation activities".to_string(),
        category: "Application & Interface Security".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SA-11".to_string()],
        remediation_guidance: Some("Track and report on application vulnerabilities, time-to-remediation, and security testing coverage".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-AIS-04".to_string(),
        control_id: "AIS-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Secure Application Design and Development".to_string(),
        description: "Design and develop applications using secure coding practices to prevent common vulnerabilities".to_string(),
        category: "Application & Interface Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["OWASP-A03".to_string(), "ISO27001-A.8.28".to_string()],
        remediation_guidance: Some("Implement OWASP secure coding guidelines, perform code reviews, and use static analysis tools".to_string()),
    });

    // ========================================================================
    // Audit Assurance & Compliance (AAC)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-AAC-01".to_string(),
        control_id: "AAC-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Audit Planning".to_string(),
        description: "Plan and scope audit assurance evaluations to assess applicable cloud security and privacy controls".to_string(),
        category: "Audit Assurance & Compliance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AU-1".to_string(), "SOC2-CC1.1".to_string()],
        remediation_guidance: Some("Develop annual audit plans covering cloud security controls with defined scope and methodology".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-AAC-02".to_string(),
        control_id: "AAC-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Independent Assessments".to_string(),
        description: "Conduct independent audits and assessments to verify conformance with standards, policies, and regulations".to_string(),
        category: "Audit Assurance & Compliance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CA-7".to_string(), "ISO27001-A.5.35".to_string()],
        remediation_guidance: Some("Engage qualified independent assessors for annual security assessments and penetration testing".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-AAC-03".to_string(),
        control_id: "AAC-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Risk Based Planning Assessment".to_string(),
        description: "Use risk-based planning to determine audit scope, frequency, and focus areas".to_string(),
        category: "Audit Assurance & Compliance".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-RA-3".to_string()],
        remediation_guidance: Some("Align audit activities with risk assessment results, focusing on high-risk areas".to_string()),
    });

    // ========================================================================
    // Business Continuity Management (BCM)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-BCM-01".to_string(),
        control_id: "BCM-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Business Continuity Planning".to_string(),
        description: "Establish and maintain business continuity and disaster recovery plans for cloud services".to_string(),
        category: "Business Continuity Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-2".to_string(), "ISO27001-A.5.29".to_string()],
        remediation_guidance: Some("Develop documented BC/DR plans covering RTO/RPO requirements, failover procedures, and communication plans".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-BCM-02".to_string(),
        control_id: "BCM-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Business Continuity Testing".to_string(),
        description: "Test business continuity and disaster recovery plans at least annually".to_string(),
        category: "Business Continuity Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-4".to_string(), "ISO27001-A.5.30".to_string()],
        remediation_guidance: Some("Conduct annual tabletop exercises and periodic failover tests to validate recovery procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-BCM-03".to_string(),
        control_id: "BCM-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Datacenter Utilities / Environmental Conditions".to_string(),
        description: "Ensure environmental controls protect infrastructure from disruption".to_string(),
        category: "Business Continuity Management".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PE-14".to_string()],
        remediation_guidance: Some("Implement redundant power, cooling, and fire suppression systems with automated failover".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-BCM-04".to_string(),
        control_id: "BCM-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Documentation".to_string(),
        description: "Maintain documentation of business continuity and disaster recovery procedures".to_string(),
        category: "Business Continuity Management".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CP-2".to_string()],
        remediation_guidance: Some("Document and regularly update BC/DR procedures, contact lists, and recovery runbooks".to_string()),
    });

    // ========================================================================
    // Change Control & Configuration (CCC)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-CCC-01".to_string(),
        control_id: "CCC-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Change Management Policy".to_string(),
        description: "Establish policies and procedures for managing changes to cloud infrastructure and applications".to_string(),
        category: "Change Control & Configuration".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CM-3".to_string(), "ISO27001-A.8.32".to_string()],
        remediation_guidance: Some("Implement formal change management processes including approval workflows and impact assessment".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CCC-02".to_string(),
        control_id: "CCC-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Quality Testing".to_string(),
        description: "Test changes in a non-production environment before deployment to production".to_string(),
        category: "Change Control & Configuration".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-4".to_string(), "ISO27001-A.8.31".to_string()],
        remediation_guidance: Some("Maintain separate dev/test/prod environments and require testing sign-off before production deployment".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CCC-03".to_string(),
        control_id: "CCC-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Change Agreements".to_string(),
        description: "Document agreements regarding changes that may impact cloud service customers".to_string(),
        category: "Change Control & Configuration".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-4".to_string()],
        remediation_guidance: Some("Include change notification requirements in customer contracts and SLAs".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CCC-04".to_string(),
        control_id: "CCC-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Unauthorized Change Protection".to_string(),
        description: "Implement controls to detect and prevent unauthorized changes".to_string(),
        category: "Change Control & Configuration".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-5".to_string(), "ISO27001-A.8.9".to_string()],
        remediation_guidance: Some("Deploy file integrity monitoring, configuration management tools, and change detection alerts".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CCC-05".to_string(),
        control_id: "CCC-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Change Restoration".to_string(),
        description: "Maintain the ability to restore systems and data to a known good state after changes".to_string(),
        category: "Change Control & Configuration".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-10".to_string()],
        remediation_guidance: Some("Implement version control, backup before change procedures, and automated rollback capabilities".to_string()),
    });

    // ========================================================================
    // Cryptography, Encryption & Key Management (CEK)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-CEK-01".to_string(),
        control_id: "CEK-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Encryption & Key Management".to_string(),
        description: "Establish policies for cryptography and key management to protect sensitive data".to_string(),
        category: "Cryptography, Encryption & Key Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SC-12".to_string(), "ISO27001-A.8.24".to_string()],
        remediation_guidance: Some("Document cryptographic policies covering algorithm standards, key lengths, and key lifecycle management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CEK-02".to_string(),
        control_id: "CEK-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "CEK Audit Logging".to_string(),
        description: "Log and monitor cryptographic key management activities".to_string(),
        category: "Cryptography, Encryption & Key Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-12".to_string()],
        remediation_guidance: Some("Enable audit logging for all key generation, access, rotation, and destruction events".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CEK-03".to_string(),
        control_id: "CEK-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Data Encryption".to_string(),
        description: "Encrypt sensitive data at rest and in transit using industry-standard algorithms".to_string(),
        category: "Cryptography, Encryption & Key Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-28".to_string(), "PCI-DSS-3.4".to_string()],
        remediation_guidance: Some("Implement AES-256 for data at rest and TLS 1.2+ for data in transit".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CEK-04".to_string(),
        control_id: "CEK-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Encryption Algorithm".to_string(),
        description: "Use encryption algorithms appropriate for the classification of data being protected".to_string(),
        category: "Cryptography, Encryption & Key Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-13".to_string()],
        remediation_guidance: Some("Use FIPS 140-2 validated cryptographic modules and approved algorithms".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CEK-05".to_string(),
        control_id: "CEK-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Key Generation".to_string(),
        description: "Generate cryptographic keys using approved methods and sufficient entropy".to_string(),
        category: "Cryptography, Encryption & Key Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-12".to_string()],
        remediation_guidance: Some("Use hardware security modules (HSMs) or approved random number generators for key generation".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-CEK-06".to_string(),
        control_id: "CEK-06".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Key Rotation".to_string(),
        description: "Rotate cryptographic keys according to defined schedules and upon suspected compromise".to_string(),
        category: "Cryptography, Encryption & Key Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-12".to_string(), "PCI-DSS-3.6".to_string()],
        remediation_guidance: Some("Implement automated key rotation at least annually and immediately upon suspected compromise".to_string()),
    });

    // ========================================================================
    // Datacenter Security (DCS)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-DCS-01".to_string(),
        control_id: "DCS-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Off-Site Equipment Disposal".to_string(),
        description: "Securely dispose of equipment containing sensitive data when moved off-site".to_string(),
        category: "Datacenter Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-MP-6".to_string(), "ISO27001-A.7.14".to_string()],
        remediation_guidance: Some("Implement certified media sanitization or destruction procedures for all storage media".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DCS-02".to_string(),
        control_id: "DCS-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Asset Classification".to_string(),
        description: "Classify assets according to business criticality and sensitivity".to_string(),
        category: "Datacenter Security".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-RA-2".to_string(), "ISO27001-A.5.12".to_string()],
        remediation_guidance: Some("Maintain asset inventory with classification labels and handling requirements".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DCS-03".to_string(),
        control_id: "DCS-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Controlled Access Points".to_string(),
        description: "Restrict physical access to datacenters through controlled access points".to_string(),
        category: "Datacenter Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PE-3".to_string(), "ISO27001-A.7.2".to_string()],
        remediation_guidance: Some("Implement multi-factor physical access controls, visitor management, and access logging".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DCS-04".to_string(),
        control_id: "DCS-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Equipment Location".to_string(),
        description: "Locate and protect equipment to reduce environmental and unauthorized access risks".to_string(),
        category: "Datacenter Security".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PE-18".to_string(), "ISO27001-A.7.8".to_string()],
        remediation_guidance: Some("Site critical equipment away from public areas and environmental hazards".to_string()),
    });

    // ========================================================================
    // Data Security & Privacy (DSP)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-DSP-01".to_string(),
        control_id: "DSP-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Security and Privacy Policy & Procedures".to_string(),
        description: "Establish and maintain security and privacy policies and procedures".to_string(),
        category: "Data Security & Privacy".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PL-1".to_string(), "GDPR-Art5".to_string()],
        remediation_guidance: Some("Develop comprehensive data security and privacy policies covering data classification, handling, and retention".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DSP-02".to_string(),
        control_id: "DSP-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Secure Disposal".to_string(),
        description: "Securely dispose of data when no longer needed according to retention policies".to_string(),
        category: "Data Security & Privacy".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-MP-6".to_string(), "ISO27001-A.8.10".to_string()],
        remediation_guidance: Some("Implement automated data deletion workflows and secure erasure verification".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DSP-03".to_string(),
        control_id: "DSP-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Data Inventory".to_string(),
        description: "Maintain an inventory of sensitive data including location, classification, and handling requirements".to_string(),
        category: "Data Security & Privacy".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-8".to_string(), "GDPR-Art30".to_string()],
        remediation_guidance: Some("Implement data discovery and classification tools to maintain comprehensive data inventory".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DSP-04".to_string(),
        control_id: "DSP-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Data Access".to_string(),
        description: "Restrict access to sensitive data based on least privilege and need-to-know".to_string(),
        category: "Data Security & Privacy".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string(), "ISO27001-A.8.3".to_string()],
        remediation_guidance: Some("Implement role-based access controls and regular access reviews for sensitive data".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DSP-05".to_string(),
        control_id: "DSP-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Data Flow Documentation".to_string(),
        description: "Document data flows to understand where sensitive data is stored, processed, and transmitted".to_string(),
        category: "Data Security & Privacy".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PL-8".to_string()],
        remediation_guidance: Some("Create and maintain data flow diagrams showing data movement across systems and networks".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-DSP-06".to_string(),
        control_id: "DSP-06".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Data Protection by Design and Default".to_string(),
        description: "Implement data protection measures by design and default in all processing activities".to_string(),
        category: "Data Security & Privacy".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art25".to_string(), "ISO27001-A.8.27".to_string()],
        remediation_guidance: Some("Incorporate privacy and security requirements into system design from inception".to_string()),
    });

    // ========================================================================
    // Governance, Risk & Compliance (GRC)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-GRC-01".to_string(),
        control_id: "GRC-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Governance Program".to_string(),
        description: "Establish and maintain an information security governance program".to_string(),
        category: "Governance, Risk & Compliance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PM-1".to_string(), "ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Establish security governance structure with defined roles, responsibilities, and oversight".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-GRC-02".to_string(),
        control_id: "GRC-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Risk Management Program".to_string(),
        description: "Implement and maintain a risk management program aligned with business objectives".to_string(),
        category: "Governance, Risk & Compliance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-RA-1".to_string()],
        remediation_guidance: Some("Establish formal risk management processes including risk identification, assessment, and treatment".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-GRC-03".to_string(),
        control_id: "GRC-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Organizational Policy".to_string(),
        description: "Develop, document, and communicate security policies to all stakeholders".to_string(),
        category: "Governance, Risk & Compliance".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PL-1".to_string(), "ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Maintain documented security policies with annual review and stakeholder acknowledgment".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-GRC-04".to_string(),
        control_id: "GRC-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Policy Exception Process".to_string(),
        description: "Establish a formal process for policy exception requests and approvals".to_string(),
        category: "Governance, Risk & Compliance".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PM-10".to_string()],
        remediation_guidance: Some("Implement policy exception workflow with risk assessment, approval, and time-bound exceptions".to_string()),
    });

    // ========================================================================
    // Human Resources (HRS)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-HRS-01".to_string(),
        control_id: "HRS-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Background Screening".to_string(),
        description: "Conduct background verification checks on candidates prior to employment".to_string(),
        category: "Human Resources".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PS-3".to_string(), "ISO27001-A.6.1".to_string()],
        remediation_guidance: Some("Perform background checks appropriate to job role and access levels".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-HRS-02".to_string(),
        control_id: "HRS-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Acceptable Use of Technology".to_string(),
        description: "Define acceptable use policies for organizational technology and assets".to_string(),
        category: "Human Resources".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PL-4".to_string(), "ISO27001-A.5.10".to_string()],
        remediation_guidance: Some("Document and communicate acceptable use policies with employee acknowledgment".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-HRS-03".to_string(),
        control_id: "HRS-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Security Awareness Training".to_string(),
        description: "Provide security awareness training to all personnel upon hire and annually".to_string(),
        category: "Human Resources".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AT-2".to_string(), "ISO27001-A.6.3".to_string()],
        remediation_guidance: Some("Implement mandatory security awareness training with completion tracking".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-HRS-04".to_string(),
        control_id: "HRS-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Employment Termination".to_string(),
        description: "Define and execute procedures for employment termination or change".to_string(),
        category: "Human Resources".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-PS-4".to_string(), "ISO27001-A.6.5".to_string()],
        remediation_guidance: Some("Implement automated access revocation upon termination and periodic access reviews".to_string()),
    });

    // ========================================================================
    // Identity & Access Management (IAM)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-IAM-01".to_string(),
        control_id: "IAM-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Identity and Access Management Policy".to_string(),
        description: "Establish policies for identity and access management including lifecycle management".to_string(),
        category: "Identity & Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AC-1".to_string(), "ISO27001-A.5.16".to_string()],
        remediation_guidance: Some("Document IAM policies covering user provisioning, authentication, authorization, and deprovisioning".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IAM-02".to_string(),
        control_id: "IAM-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Strong Authentication".to_string(),
        description: "Implement strong authentication mechanisms including multi-factor authentication".to_string(),
        category: "Identity & Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IA-2".to_string(), "ISO27001-A.8.5".to_string()],
        remediation_guidance: Some("Require MFA for all privileged access and remote connections".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IAM-03".to_string(),
        control_id: "IAM-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Identity Inventory".to_string(),
        description: "Maintain an inventory of all system identities and access privileges".to_string(),
        category: "Identity & Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2".to_string()],
        remediation_guidance: Some("Implement identity governance tools for comprehensive identity inventory and access tracking".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IAM-04".to_string(),
        control_id: "IAM-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Separation of Duties".to_string(),
        description: "Implement separation of duties to prevent conflicts of interest".to_string(),
        category: "Identity & Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-5".to_string(), "ISO27001-A.5.3".to_string()],
        remediation_guidance: Some("Define incompatible duties and implement access controls to enforce separation".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IAM-05".to_string(),
        control_id: "IAM-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Least Privilege".to_string(),
        description: "Implement least privilege access for all users and service accounts".to_string(),
        category: "Identity & Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-6".to_string(), "ISO27001-A.8.2".to_string()],
        remediation_guidance: Some("Review and minimize access rights, implement just-in-time privileged access".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IAM-06".to_string(),
        control_id: "IAM-06".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "User Access Reviews".to_string(),
        description: "Conduct periodic reviews of user access rights and privileges".to_string(),
        category: "Identity & Access Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-2".to_string(), "ISO27001-A.5.18".to_string()],
        remediation_guidance: Some("Perform quarterly access reviews for privileged accounts and annual reviews for all users".to_string()),
    });

    // ========================================================================
    // Infrastructure & Virtualization Security (IVS)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-IVS-01".to_string(),
        control_id: "IVS-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Infrastructure and Virtualization Security Policy".to_string(),
        description: "Establish policies for securing infrastructure and virtualization environments".to_string(),
        category: "Infrastructure & Virtualization Security".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SC-1".to_string()],
        remediation_guidance: Some("Document security requirements for network, compute, and virtualization infrastructure".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IVS-02".to_string(),
        control_id: "IVS-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Capacity and Resource Planning".to_string(),
        description: "Plan and monitor capacity to ensure adequate resources and availability".to_string(),
        category: "Infrastructure & Virtualization Security".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CP-2".to_string(), "ISO27001-A.8.6".to_string()],
        remediation_guidance: Some("Implement capacity monitoring and alerting with automated scaling where applicable".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IVS-03".to_string(),
        control_id: "IVS-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Network Security".to_string(),
        description: "Implement network security controls including segmentation and perimeter protection".to_string(),
        category: "Infrastructure & Virtualization Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string(), "ISO27001-A.8.22".to_string()],
        remediation_guidance: Some("Deploy firewalls, network segmentation, and intrusion detection/prevention systems".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IVS-04".to_string(),
        control_id: "IVS-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "OS Hardening and Base Controls".to_string(),
        description: "Harden operating systems according to industry benchmarks and security baselines".to_string(),
        category: "Infrastructure & Virtualization Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-6".to_string(), "CIS-v8".to_string()],
        remediation_guidance: Some("Apply CIS benchmarks or equivalent hardening standards to all operating systems".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IVS-05".to_string(),
        control_id: "IVS-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Segmentation and Segregation".to_string(),
        description: "Segment networks and systems to isolate sensitive environments".to_string(),
        category: "Infrastructure & Virtualization Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.4".to_string()],
        remediation_guidance: Some("Implement network segmentation for production, development, and sensitive data environments".to_string()),
    });

    // ========================================================================
    // Interoperability & Portability (IPY)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-IPY-01".to_string(),
        control_id: "IPY-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Interoperability and Portability Policy".to_string(),
        description: "Establish policies for data interoperability and portability".to_string(),
        category: "Interoperability & Portability".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art20".to_string()],
        remediation_guidance: Some("Define data portability requirements including formats, APIs, and migration procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IPY-02".to_string(),
        control_id: "IPY-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Data Portability".to_string(),
        description: "Ensure data can be exported in standard formats for portability".to_string(),
        category: "Interoperability & Portability".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art20".to_string()],
        remediation_guidance: Some("Provide data export capabilities in standard machine-readable formats".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-IPY-03".to_string(),
        control_id: "IPY-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Policy and Legal".to_string(),
        description: "Establish agreements addressing data portability and interoperability requirements".to_string(),
        category: "Interoperability & Portability".to_string(),
        priority: ControlPriority::Low,
        automated_check: false,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Include data portability clauses in cloud service agreements and contracts".to_string()),
    });

    // ========================================================================
    // Logging & Monitoring (LOG)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-LOG-01".to_string(),
        control_id: "LOG-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Logging and Monitoring Policy".to_string(),
        description: "Establish policies and procedures for logging and monitoring security events".to_string(),
        category: "Logging & Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-AU-1".to_string(), "ISO27001-A.8.15".to_string()],
        remediation_guidance: Some("Define logging requirements, retention periods, and monitoring procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-LOG-02".to_string(),
        control_id: "LOG-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Audit Logging".to_string(),
        description: "Enable audit logging for all system components and security-relevant events".to_string(),
        category: "Logging & Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-2".to_string(), "PCI-DSS-10.2".to_string()],
        remediation_guidance: Some("Configure comprehensive audit logging covering authentication, authorization, and administrative activities".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-LOG-03".to_string(),
        control_id: "LOG-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Security Monitoring and Alerting".to_string(),
        description: "Implement continuous monitoring and alerting for security events".to_string(),
        category: "Logging & Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-4".to_string(), "ISO27001-A.8.16".to_string()],
        remediation_guidance: Some("Deploy SIEM solution with correlation rules and automated alerting for security events".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-LOG-04".to_string(),
        control_id: "LOG-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Log Protection".to_string(),
        description: "Protect logs from unauthorized modification and deletion".to_string(),
        category: "Logging & Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-9".to_string()],
        remediation_guidance: Some("Implement write-once log storage, access controls, and integrity monitoring for logs".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-LOG-05".to_string(),
        control_id: "LOG-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Audit Log Access".to_string(),
        description: "Restrict access to audit logs to authorized personnel only".to_string(),
        category: "Logging & Monitoring".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AU-9".to_string(), "PCI-DSS-10.5".to_string()],
        remediation_guidance: Some("Implement role-based access controls for log access with separation from system administrators".to_string()),
    });

    // ========================================================================
    // Security Incident Management (SEF)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-SEF-01".to_string(),
        control_id: "SEF-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Security Incident Management Policy".to_string(),
        description: "Establish policies and procedures for security incident management".to_string(),
        category: "Security Incident Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-1".to_string(), "ISO27001-A.5.24".to_string()],
        remediation_guidance: Some("Develop incident response policies covering detection, response, communication, and recovery".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-SEF-02".to_string(),
        control_id: "SEF-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Service Management".to_string(),
        description: "Integrate security incident management with IT service management processes".to_string(),
        category: "Security Incident Management".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-4".to_string()],
        remediation_guidance: Some("Integrate incident management with ITSM tools for coordinated response".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-SEF-03".to_string(),
        control_id: "SEF-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Incident Response Plans".to_string(),
        description: "Develop and maintain incident response plans for different incident types".to_string(),
        category: "Security Incident Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-8".to_string(), "ISO27001-A.5.26".to_string()],
        remediation_guidance: Some("Create incident playbooks covering common incident types with defined escalation paths".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-SEF-04".to_string(),
        control_id: "SEF-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Incident Response Testing".to_string(),
        description: "Test incident response plans at least annually".to_string(),
        category: "Security Incident Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-IR-3".to_string()],
        remediation_guidance: Some("Conduct annual tabletop exercises and periodic incident response drills".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-SEF-05".to_string(),
        control_id: "SEF-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Incident Evidence Collection".to_string(),
        description: "Establish procedures for collecting, preserving, and analyzing digital evidence during security incidents".to_string(),
        category: "Security Incident Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-IR-4".to_string(), "ISO27001-A.5.28".to_string()],
        remediation_guidance: Some("Implement forensic evidence collection procedures with chain of custody documentation".to_string()),
    });

    // ========================================================================
    // Supply Chain Management (STA)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-STA-01".to_string(),
        control_id: "STA-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Supply Chain Management Policy".to_string(),
        description: "Establish policies for managing supply chain security risks".to_string(),
        category: "Supply Chain Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SR-1".to_string(), "ISO27001-A.5.19".to_string()],
        remediation_guidance: Some("Develop supply chain security policies covering vendor assessment, monitoring, and risk management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-STA-02".to_string(),
        control_id: "STA-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Supply Chain Risk Management".to_string(),
        description: "Assess and manage risks from supply chain relationships".to_string(),
        category: "Supply Chain Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SR-3".to_string(), "ISO27001-A.5.21".to_string()],
        remediation_guidance: Some("Perform vendor risk assessments and maintain risk register for critical suppliers".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-STA-03".to_string(),
        control_id: "STA-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Primary Service and Contractual Agreement".to_string(),
        description: "Include security requirements in supplier contracts and agreements".to_string(),
        category: "Supply Chain Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-SA-4".to_string(), "ISO27001-A.5.20".to_string()],
        remediation_guidance: Some("Include security requirements, audit rights, and incident notification in contracts".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-STA-04".to_string(),
        control_id: "STA-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Supply Chain Data Security".to_string(),
        description: "Protect data shared with or accessed by supply chain partners".to_string(),
        category: "Supply Chain Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SR-11".to_string()],
        remediation_guidance: Some("Implement data protection controls for data shared with suppliers including encryption and access controls".to_string()),
    });

    // ========================================================================
    // Threat & Vulnerability Management (TVM)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-TVM-01".to_string(),
        control_id: "TVM-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Threat and Vulnerability Management Policy".to_string(),
        description: "Establish policies for threat and vulnerability management".to_string(),
        category: "Threat & Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-RA-5".to_string(), "ISO27001-A.8.8".to_string()],
        remediation_guidance: Some("Define vulnerability scanning requirements, remediation timelines, and risk acceptance processes".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-TVM-02".to_string(),
        control_id: "TVM-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Malware Protection".to_string(),
        description: "Implement malware protection on all systems".to_string(),
        category: "Threat & Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-3".to_string(), "ISO27001-A.8.7".to_string()],
        remediation_guidance: Some("Deploy endpoint protection with real-time scanning, behavioral analysis, and automatic updates".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-TVM-03".to_string(),
        control_id: "TVM-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Vulnerability Scanning".to_string(),
        description: "Conduct regular vulnerability scanning of all systems and applications".to_string(),
        category: "Threat & Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-RA-5".to_string(), "PCI-DSS-11.2".to_string()],
        remediation_guidance: Some("Perform authenticated vulnerability scans at least monthly and after significant changes".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-TVM-04".to_string(),
        control_id: "TVM-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Vulnerability Remediation".to_string(),
        description: "Remediate identified vulnerabilities within defined timeframes".to_string(),
        category: "Threat & Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-2".to_string()],
        remediation_guidance: Some("Establish SLAs for vulnerability remediation: critical 24-48h, high 7 days, medium 30 days".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-TVM-05".to_string(),
        control_id: "TVM-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Penetration Testing".to_string(),
        description: "Conduct penetration testing at least annually or after significant changes".to_string(),
        category: "Threat & Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CA-8".to_string(), "PCI-DSS-11.3".to_string()],
        remediation_guidance: Some("Engage qualified penetration testers for annual assessments and after major changes".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-TVM-06".to_string(),
        control_id: "TVM-06".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Penetration Testing Remediation".to_string(),
        description: "Remediate findings from penetration testing within defined timeframes".to_string(),
        category: "Threat & Vulnerability Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CA-5".to_string()],
        remediation_guidance: Some("Track and remediate penetration test findings with formal remediation verification".to_string()),
    });

    // ========================================================================
    // Universal Endpoint Management (UEM)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "CSA-CCM-UEM-01".to_string(),
        control_id: "UEM-01".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Endpoint Devices Policy".to_string(),
        description: "Establish policies for endpoint device security and management".to_string(),
        category: "Universal Endpoint Management".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CM-1".to_string(), "ISO27001-A.8.1".to_string()],
        remediation_guidance: Some("Define endpoint security requirements including encryption, patching, and configuration standards".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-UEM-02".to_string(),
        control_id: "UEM-02".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Application and Service Approval".to_string(),
        description: "Control and approve applications and services installed on endpoints".to_string(),
        category: "Universal Endpoint Management".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-7".to_string(), "ISO27001-A.8.19".to_string()],
        remediation_guidance: Some("Implement application whitelisting and formal software approval processes".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-UEM-03".to_string(),
        control_id: "UEM-03".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Endpoint Inventory".to_string(),
        description: "Maintain an inventory of all endpoints accessing organizational resources".to_string(),
        category: "Universal Endpoint Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CM-8".to_string()],
        remediation_guidance: Some("Deploy endpoint discovery and inventory management tools for comprehensive visibility".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-UEM-04".to_string(),
        control_id: "UEM-04".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Anti-Malware Detection and Prevention".to_string(),
        description: "Deploy anti-malware solutions on all endpoints".to_string(),
        category: "Universal Endpoint Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SI-3".to_string(), "ISO27001-A.8.7".to_string()],
        remediation_guidance: Some("Install and maintain endpoint protection with automatic updates and centralized management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-UEM-05".to_string(),
        control_id: "UEM-05".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Remote Wipe".to_string(),
        description: "Enable remote wipe capabilities for mobile and lost devices".to_string(),
        category: "Universal Endpoint Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-19".to_string()],
        remediation_guidance: Some("Implement MDM solution with remote wipe capability for all mobile devices accessing corporate data".to_string()),
    });

    controls.push(ComplianceControl {
        id: "CSA-CCM-UEM-06".to_string(),
        control_id: "UEM-06".to_string(),
        framework: ComplianceFramework::CsaCcm,
        title: "Storage Encryption".to_string(),
        description: "Encrypt storage on all endpoint devices".to_string(),
        category: "Universal Endpoint Management".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-SC-28".to_string(), "ISO27001-A.8.24".to_string()],
        remediation_guidance: Some("Enable full-disk encryption (BitLocker, FileVault) on all endpoints with centralized key management".to_string()),
    });

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant CSA CCM controls (with severity)
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication/Access Control issues
    if title_lower.contains("authentication")
        || title_lower.contains("password")
        || title_lower.contains("mfa")
        || title_lower.contains("credential")
    {
        mappings.push(("IAM-02".to_string(), Severity::High));
        mappings.push(("IAM-05".to_string(), Severity::High));
    }

    // Access control/authorization vulnerabilities
    if title_lower.contains("access control")
        || title_lower.contains("authorization")
        || title_lower.contains("privilege")
        || title_lower.contains("permission")
    {
        mappings.push(("IAM-04".to_string(), Severity::High));
        mappings.push(("IAM-05".to_string(), Severity::High));
        mappings.push(("DSP-04".to_string(), Severity::High));
    }

    // Encryption/cryptography issues
    if title_lower.contains("encryption")
        || title_lower.contains("tls")
        || title_lower.contains("ssl")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted")
        || title_lower.contains("certificate")
    {
        mappings.push(("CEK-03".to_string(), Severity::High));
        mappings.push(("CEK-04".to_string(), Severity::High));
        mappings.push(("UEM-06".to_string(), Severity::Medium));
    }

    // Key management issues
    if title_lower.contains("key management")
        || title_lower.contains("key rotation")
        || title_lower.contains("key exposure")
    {
        mappings.push(("CEK-01".to_string(), Severity::High));
        mappings.push(("CEK-05".to_string(), Severity::High));
        mappings.push(("CEK-06".to_string(), Severity::High));
    }

    // Malware/Virus
    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("ransomware")
        || title_lower.contains("trojan")
    {
        mappings.push(("TVM-02".to_string(), Severity::Critical));
        mappings.push(("UEM-04".to_string(), Severity::Critical));
    }

    // Vulnerability/Patching
    if title_lower.contains("outdated")
        || title_lower.contains("patch")
        || title_lower.contains("update")
        || title_lower.contains("end of life")
        || title_lower.contains("deprecated")
    {
        mappings.push(("TVM-03".to_string(), Severity::High));
        mappings.push(("TVM-04".to_string(), Severity::High));
    }

    // Logging/Monitoring deficiencies
    if title_lower.contains("logging")
        || title_lower.contains("monitoring")
        || title_lower.contains("audit")
        || title_lower.contains("log")
    {
        mappings.push(("LOG-02".to_string(), Severity::Medium));
        mappings.push(("LOG-03".to_string(), Severity::Medium));
        mappings.push(("LOG-04".to_string(), Severity::Medium));
    }

    // Backup/Recovery issues
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("BCM-01".to_string(), Severity::High));
        mappings.push(("CCC-05".to_string(), Severity::High));
    }

    // Network security
    if title_lower.contains("network")
        || title_lower.contains("firewall")
        || title_lower.contains("segmentation")
        || title_lower.contains("port")
    {
        mappings.push(("IVS-03".to_string(), Severity::High));
        mappings.push(("IVS-05".to_string(), Severity::High));
    }

    // Configuration/hardening
    if title_lower.contains("configuration")
        || title_lower.contains("hardening")
        || title_lower.contains("misconfiguration")
        || title_lower.contains("default")
    {
        mappings.push(("IVS-04".to_string(), Severity::High));
        mappings.push(("CCC-04".to_string(), Severity::Medium));
    }

    // Data protection/Privacy
    if title_lower.contains("pii")
        || title_lower.contains("privacy")
        || title_lower.contains("personal data")
        || title_lower.contains("data leak")
        || title_lower.contains("data exposure")
    {
        mappings.push(("DSP-01".to_string(), Severity::High));
        mappings.push(("DSP-03".to_string(), Severity::High));
        mappings.push(("DSP-06".to_string(), Severity::High));
    }

    // Secure development/application security
    if title_lower.contains("injection")
        || title_lower.contains("xss")
        || title_lower.contains("code")
        || title_lower.contains("sqli")
        || title_lower.contains("rce")
    {
        mappings.push(("AIS-01".to_string(), Severity::High));
        mappings.push(("AIS-04".to_string(), Severity::High));
    }

    // Incident response
    if title_lower.contains("incident") || title_lower.contains("breach") {
        mappings.push(("SEF-01".to_string(), Severity::High));
        mappings.push(("SEF-03".to_string(), Severity::High));
    }

    // Change management
    if title_lower.contains("change")
        || title_lower.contains("unauthorized modification")
        || title_lower.contains("integrity")
    {
        mappings.push(("CCC-01".to_string(), Severity::Medium));
        mappings.push(("CCC-04".to_string(), Severity::High));
    }

    // Supply chain/third-party
    if title_lower.contains("supply chain")
        || title_lower.contains("third party")
        || title_lower.contains("vendor")
        || title_lower.contains("dependency")
    {
        mappings.push(("STA-01".to_string(), Severity::High));
        mappings.push(("STA-02".to_string(), Severity::High));
        mappings.push(("STA-04".to_string(), Severity::Medium));
    }

    // Endpoint security
    if title_lower.contains("endpoint")
        || title_lower.contains("device")
        || title_lower.contains("mobile")
        || title_lower.contains("laptop")
    {
        mappings.push(("UEM-01".to_string(), Severity::Medium));
        mappings.push(("UEM-03".to_string(), Severity::Medium));
    }

    // Identity management
    if title_lower.contains("identity")
        || title_lower.contains("user account")
        || title_lower.contains("orphan")
    {
        mappings.push(("IAM-01".to_string(), Severity::Medium));
        mappings.push(("IAM-03".to_string(), Severity::Medium));
        mappings.push(("IAM-06".to_string(), Severity::Medium));
    }

    // Cloud-specific issues
    if title_lower.contains("cloud")
        || title_lower.contains("aws")
        || title_lower.contains("azure")
        || title_lower.contains("gcp")
        || title_lower.contains("s3")
    {
        mappings.push(("IVS-01".to_string(), Severity::Medium));
        mappings.push(("DSP-03".to_string(), Severity::Medium));
    }

    // Default - map to general vulnerability management
    if mappings.is_empty() {
        mappings.push(("TVM-01".to_string(), Severity::Medium));
    }

    mappings
}

/// Map a vulnerability type to relevant CSA CCM controls (control IDs only)
pub fn map_vulnerability_to_controls(vuln_type: &str) -> Vec<String> {
    match vuln_type.to_lowercase().as_str() {
        "authentication" | "password" | "mfa" | "credential" => {
            vec!["IAM-02".to_string(), "IAM-05".to_string()]
        }
        "access_control" | "authorization" | "privilege" => vec![
            "IAM-04".to_string(),
            "IAM-05".to_string(),
            "DSP-04".to_string(),
        ],
        "encryption" | "cryptography" | "tls" | "ssl" => vec![
            "CEK-03".to_string(),
            "CEK-04".to_string(),
            "UEM-06".to_string(),
        ],
        "key_management" | "key_rotation" => vec![
            "CEK-01".to_string(),
            "CEK-05".to_string(),
            "CEK-06".to_string(),
        ],
        "malware" | "virus" | "ransomware" => {
            vec!["TVM-02".to_string(), "UEM-04".to_string()]
        }
        "vulnerability" | "patching" | "update" => {
            vec!["TVM-03".to_string(), "TVM-04".to_string()]
        }
        "logging" | "monitoring" | "audit" => vec![
            "LOG-02".to_string(),
            "LOG-03".to_string(),
            "LOG-04".to_string(),
        ],
        "backup" | "recovery" | "continuity" => {
            vec!["BCM-01".to_string(), "CCC-05".to_string()]
        }
        "network" | "firewall" | "segmentation" => {
            vec!["IVS-03".to_string(), "IVS-05".to_string()]
        }
        "configuration" | "hardening" | "misconfiguration" => {
            vec!["IVS-04".to_string(), "CCC-04".to_string()]
        }
        "data_protection" | "pii" | "privacy" => vec![
            "DSP-01".to_string(),
            "DSP-03".to_string(),
            "DSP-06".to_string(),
        ],
        "application_security" | "injection" | "xss" | "sqli" => {
            vec!["AIS-01".to_string(), "AIS-04".to_string()]
        }
        "incident" | "breach" => {
            vec!["SEF-01".to_string(), "SEF-03".to_string()]
        }
        "change_management" | "unauthorized_change" => {
            vec!["CCC-01".to_string(), "CCC-04".to_string()]
        }
        "supply_chain" | "third_party" | "vendor" => vec![
            "STA-01".to_string(),
            "STA-02".to_string(),
            "STA-04".to_string(),
        ],
        "endpoint" | "device" | "mobile" => vec![
            "UEM-01".to_string(),
            "UEM-03".to_string(),
            "UEM-04".to_string(),
        ],
        "identity" | "user_account" => vec![
            "IAM-01".to_string(),
            "IAM-03".to_string(),
            "IAM-06".to_string(),
        ],
        "penetration_testing" | "pentest" => {
            vec!["TVM-05".to_string(), "TVM-06".to_string()]
        }
        "cloud" | "iaas" | "paas" | "saas" => {
            vec!["IVS-01".to_string(), "DSP-03".to_string()]
        }
        _ => vec!["TVM-01".to_string()],
    }
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
            assert!(
                !control.control_id.is_empty(),
                "Control control_id should not be empty"
            );
            assert!(!control.title.is_empty(), "Control title should not be empty");
            assert!(
                !control.description.is_empty(),
                "Control description should not be empty"
            );
            assert!(
                !control.category.is_empty(),
                "Control category should not be empty"
            );
            assert!(
                control.framework == ComplianceFramework::CsaCcm,
                "Framework should be CsaCcm"
            );
        }
    }

    #[test]
    fn test_all_domains_covered() {
        let controls = get_controls();
        let categories: Vec<&str> = controls.iter().map(|c| c.category.as_str()).collect();

        // Verify all 17 domains are represented
        assert!(
            categories.contains(&"Application & Interface Security"),
            "AIS domain missing"
        );
        assert!(
            categories.contains(&"Audit Assurance & Compliance"),
            "AAC domain missing"
        );
        assert!(
            categories.contains(&"Business Continuity Management"),
            "BCM domain missing"
        );
        assert!(
            categories.contains(&"Change Control & Configuration"),
            "CCC domain missing"
        );
        assert!(
            categories.contains(&"Cryptography, Encryption & Key Management"),
            "CEK domain missing"
        );
        assert!(
            categories.contains(&"Datacenter Security"),
            "DCS domain missing"
        );
        assert!(
            categories.contains(&"Data Security & Privacy"),
            "DSP domain missing"
        );
        assert!(
            categories.contains(&"Governance, Risk & Compliance"),
            "GRC domain missing"
        );
        assert!(categories.contains(&"Human Resources"), "HRS domain missing");
        assert!(
            categories.contains(&"Identity & Access Management"),
            "IAM domain missing"
        );
        assert!(
            categories.contains(&"Infrastructure & Virtualization Security"),
            "IVS domain missing"
        );
        assert!(
            categories.contains(&"Interoperability & Portability"),
            "IPY domain missing"
        );
        assert!(
            categories.contains(&"Logging & Monitoring"),
            "LOG domain missing"
        );
        assert!(
            categories.contains(&"Security Incident Management"),
            "SEF domain missing"
        );
        assert!(
            categories.contains(&"Supply Chain Management"),
            "STA domain missing"
        );
        assert!(
            categories.contains(&"Threat & Vulnerability Management"),
            "TVM domain missing"
        );
        assert!(
            categories.contains(&"Universal Endpoint Management"),
            "UEM domain missing"
        );
    }

    #[test]
    fn test_vulnerability_mapping() {
        let controls = map_vulnerability_to_controls("authentication");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"IAM-02".to_string()));

        let controls = map_vulnerability_to_controls("encryption");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"CEK-03".to_string()));

        let controls = map_vulnerability_to_controls("malware");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"TVM-02".to_string()));
    }

    #[test]
    fn test_vulnerability_mapping_with_severity() {
        let mappings = map_vulnerability("SQL injection vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "AIS-04"));

        let mappings = map_vulnerability("Weak TLS configuration", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CEK-03"));

        let mappings = map_vulnerability("Ransomware detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings
            .iter()
            .any(|(id, sev)| id == "TVM-02" && *sev == Severity::Critical));
    }

    #[test]
    fn test_control_ids_format() {
        for control in get_controls() {
            // Control IDs should follow pattern: XXX-NN (e.g., AIS-01, IAM-06)
            assert!(
                control.control_id.contains('-'),
                "Control ID {} should contain hyphen",
                control.control_id
            );
            let parts: Vec<&str> = control.control_id.split('-').collect();
            assert_eq!(
                parts.len(),
                2,
                "Control ID {} should have exactly 2 parts",
                control.control_id
            );
            assert!(
                parts[0].len() == 3,
                "Domain prefix should be 3 characters: {}",
                control.control_id
            );
        }
    }

    #[test]
    fn test_high_priority_controls_have_remediation() {
        for control in get_controls() {
            if control.priority == ControlPriority::High {
                assert!(
                    control.remediation_guidance.is_some(),
                    "High priority control {} should have remediation guidance",
                    control.control_id
                );
            }
        }
    }
}
