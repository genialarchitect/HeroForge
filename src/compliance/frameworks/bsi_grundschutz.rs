//! BSI IT-Grundschutz Compliance Framework
//!
//! This module implements controls from the German Federal Office for Information Security
//! (Bundesamt fuer Sicherheit in der Informationstechnik - BSI) IT-Grundschutz methodology.
//!
//! BSI IT-Grundschutz is a comprehensive framework for establishing an Information Security
//! Management System (ISMS) that is aligned with ISO/IEC 27001 and recognized for
//! ISO 27001 certification based on IT-Grundschutz.
//!
//! The controls are organized into the following layers (Bausteine/Modules):
//! - ISMS: Information Security Management System
//! - ORP: Organization and Personnel (Organisation und Personal)
//! - CON: Concepts and Procedures (Konzeption und Vorgehensweisen)
//! - OPS: Operations (Betrieb)
//! - DER: Detection and Response (Detektion und Reaktion)
//! - APP: Applications (Anwendungen)
//! - SYS: IT Systems (IT-Systeme)
//! - IND: Industrial IT (Industrielle IT)
//! - NET: Networks and Communication (Netze und Kommunikation)
//! - INF: Infrastructure (Infrastruktur)
//!
//! Reference: BSI IT-Grundschutz Compendium Edition 2023

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of BSI IT-Grundschutz controls in this module
pub const CONTROL_COUNT: usize = 65;

/// Get all BSI IT-Grundschutz controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // ISMS - Information Security Management System
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-ISMS.1.A1".to_string(),
        control_id: "ISMS.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Assumption of overall responsibility for information security by management".to_string(),
        description: "The management level must assume overall responsibility for information security. Management must initiate, control, and monitor the security process.".to_string(),
        category: "ISMS".to_string(),
        priority: ControlPriority::Critical,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string(), "ISO27001-A.5.2".to_string()],
        remediation_guidance: Some("Document management commitment and establish governance structure for information security".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ISMS.1.A2".to_string(),
        control_id: "ISMS.1.A2".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Appointment of security management".to_string(),
        description: "A security management team must be appointed with clearly defined roles for the Information Security Officer (ISO) and supporting staff.".to_string(),
        category: "ISMS".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.2".to_string()],
        remediation_guidance: Some("Appoint Information Security Officer with clearly defined responsibilities and authority".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ISMS.1.A3".to_string(),
        control_id: "ISMS.1.A3".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Definition of security objectives and strategy".to_string(),
        description: "Information security objectives aligned with business objectives must be defined and documented in a security strategy.".to_string(),
        category: "ISMS".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Develop and document information security strategy aligned with business objectives".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ISMS.1.A4".to_string(),
        control_id: "ISMS.1.A4".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Creation of information security guidelines".to_string(),
        description: "An information security policy must be created, approved by management, and communicated to all employees.".to_string(),
        category: "ISMS".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string(), "NIST-PL-1".to_string()],
        remediation_guidance: Some("Create comprehensive information security policy document approved by management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ISMS.1.A5".to_string(),
        control_id: "ISMS.1.A5".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Risk analysis according to IT-Grundschutz".to_string(),
        description: "Risk analysis must be performed systematically using the IT-Grundschutz methodology or equivalent approach.".to_string(),
        category: "ISMS".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.7".to_string(), "NIST-RA-3".to_string()],
        remediation_guidance: Some("Conduct systematic risk analysis following IT-Grundschutz methodology".to_string()),
    });

    // ========================================================================
    // ORP - Organization and Personnel
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-ORP.1.A1".to_string(),
        control_id: "ORP.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Defining responsibilities and regulations".to_string(),
        description: "Responsibilities for all information security tasks must be clearly defined and documented. This includes roles, reporting lines, and escalation paths.".to_string(),
        category: "ORP".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.2".to_string(), "ISO27001-A.5.3".to_string()],
        remediation_guidance: Some("Define and document all security responsibilities with clear accountability".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ORP.2.A1".to_string(),
        control_id: "ORP.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Regulations for employees".to_string(),
        description: "Clear regulations regarding information security must be established for all employees, contractors, and third parties.".to_string(),
        category: "ORP".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.6.2".to_string()],
        remediation_guidance: Some("Establish binding security regulations in employment contracts and agreements".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ORP.3.A1".to_string(),
        control_id: "ORP.3.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Sensitization and training of employees".to_string(),
        description: "All employees must receive regular security awareness training appropriate to their role and access level.".to_string(),
        category: "ORP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.6.3".to_string(), "NIST-AT-2".to_string()],
        remediation_guidance: Some("Implement mandatory security awareness training program with regular updates".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ORP.4.A1".to_string(),
        control_id: "ORP.4.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Identity management".to_string(),
        description: "A formal identity management process must be established covering the entire lifecycle of user identities.".to_string(),
        category: "ORP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.16".to_string(), "NIST-IA-4".to_string()],
        remediation_guidance: Some("Implement identity management system with lifecycle management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ORP.4.A2".to_string(),
        control_id: "ORP.4.A2".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Access rights management".to_string(),
        description: "Access rights must be managed according to the principle of least privilege with regular reviews.".to_string(),
        category: "ORP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.18".to_string(), "ISO27001-A.8.2".to_string(), "NIST-AC-6".to_string()],
        remediation_guidance: Some("Implement role-based access control with regular access reviews".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-ORP.5.A1".to_string(),
        control_id: "ORP.5.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Compliance management".to_string(),
        description: "Legal, regulatory, and contractual requirements relevant to information security must be identified, documented, and monitored.".to_string(),
        category: "ORP".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.31".to_string()],
        remediation_guidance: Some("Establish compliance monitoring program for all applicable regulations".to_string()),
    });

    // ========================================================================
    // CON - Concepts and Procedures
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-CON.1.A1".to_string(),
        control_id: "CON.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Cryptographic concept".to_string(),
        description: "A cryptographic concept must be defined specifying approved algorithms, key lengths, and key management procedures.".to_string(),
        category: "CON".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.24".to_string(), "NIST-SC-12".to_string(), "NIST-SC-13".to_string()],
        remediation_guidance: Some("Define cryptographic policy with approved algorithms and key management procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-CON.2.A1".to_string(),
        control_id: "CON.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Data protection concept".to_string(),
        description: "A data protection concept must be implemented covering personal data handling according to GDPR and BDSG.".to_string(),
        category: "CON".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.34".to_string()],
        remediation_guidance: Some("Implement data protection measures compliant with GDPR and German BDSG".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-CON.3.A1".to_string(),
        control_id: "CON.3.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Data backup concept".to_string(),
        description: "A comprehensive data backup concept must be developed including backup strategy, retention periods, and recovery testing.".to_string(),
        category: "CON".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.13".to_string(), "NIST-CP-9".to_string()],
        remediation_guidance: Some("Develop and implement data backup strategy with regular testing of recovery procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-CON.4.A1".to_string(),
        control_id: "CON.4.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Selection of suitable software".to_string(),
        description: "Software must be selected based on security requirements and evaluated for security vulnerabilities before deployment.".to_string(),
        category: "CON".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.26".to_string()],
        remediation_guidance: Some("Establish software evaluation process including security assessment".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-CON.6.A1".to_string(),
        control_id: "CON.6.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Deletion and destruction concept".to_string(),
        description: "A concept for secure deletion and destruction of data and media must be implemented.".to_string(),
        category: "CON".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.10".to_string(), "ISO27001-A.7.14".to_string()],
        remediation_guidance: Some("Implement secure data deletion and media destruction procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-CON.7.A1".to_string(),
        control_id: "CON.7.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Information classification and handling".to_string(),
        description: "Information must be classified according to its protection needs and handled according to classification level.".to_string(),
        category: "CON".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.12".to_string(), "ISO27001-A.5.13".to_string()],
        remediation_guidance: Some("Implement information classification scheme with appropriate handling procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-CON.8.A1".to_string(),
        control_id: "CON.8.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Software development".to_string(),
        description: "Secure software development practices must be implemented including secure coding guidelines and security testing.".to_string(),
        category: "CON".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.25".to_string(), "ISO27001-A.8.28".to_string()],
        remediation_guidance: Some("Implement secure SDLC with security testing integration".to_string()),
    });

    // ========================================================================
    // OPS - Operations
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-OPS.1.1.1.A1".to_string(),
        control_id: "OPS.1.1.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Documented administration".to_string(),
        description: "All system administration activities must be documented and traceable.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.37".to_string()],
        remediation_guidance: Some("Implement administration logging and change documentation".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-OPS.1.1.2.A1".to_string(),
        control_id: "OPS.1.1.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "System administrator qualification".to_string(),
        description: "System administrators must be properly trained and qualified for their responsibilities.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.6.3".to_string()],
        remediation_guidance: Some("Ensure administrators have appropriate training and certifications".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-OPS.1.1.3.A1".to_string(),
        control_id: "OPS.1.1.3.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Patch and change management".to_string(),
        description: "A formal patch and change management process must be implemented including testing and rollback procedures.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.8".to_string(), "ISO27001-A.8.32".to_string(), "NIST-SI-2".to_string()],
        remediation_guidance: Some("Implement patch management process with testing and approval workflow".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-OPS.1.1.4.A1".to_string(),
        control_id: "OPS.1.1.4.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Malware protection".to_string(),
        description: "Comprehensive malware protection must be implemented on all systems with regular updates.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.7".to_string(), "NIST-SI-3".to_string()],
        remediation_guidance: Some("Deploy endpoint protection on all systems with automatic updates enabled".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-OPS.1.1.5.A1".to_string(),
        control_id: "OPS.1.1.5.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Logging".to_string(),
        description: "Security-relevant events must be logged on all systems with appropriate retention and protection.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.15".to_string(), "NIST-AU-2".to_string(), "NIST-AU-3".to_string()],
        remediation_guidance: Some("Implement centralized logging with tamper protection and appropriate retention".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-OPS.1.1.6.A1".to_string(),
        control_id: "OPS.1.1.6.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Software management".to_string(),
        description: "Only approved and licensed software may be installed. Software inventory must be maintained.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.19".to_string(), "NIST-CM-11".to_string()],
        remediation_guidance: Some("Implement software inventory and whitelist controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-OPS.1.2.1.A1".to_string(),
        control_id: "OPS.1.2.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Remote maintenance".to_string(),
        description: "Remote maintenance access must be secured with strong authentication and encryption.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.6.7".to_string(), "NIST-AC-17".to_string()],
        remediation_guidance: Some("Implement secure remote access with MFA and session monitoring".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-OPS.2.2.A1".to_string(),
        control_id: "OPS.2.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Cloud usage".to_string(),
        description: "Cloud services must be evaluated for security and compliance requirements before use.".to_string(),
        category: "OPS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.23".to_string()],
        remediation_guidance: Some("Implement cloud security assessment and governance procedures".to_string()),
    });

    // ========================================================================
    // DER - Detection and Response
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-DER.1.A1".to_string(),
        control_id: "DER.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Definition of reportable security events".to_string(),
        description: "Security events that must be reported must be clearly defined and communicated.".to_string(),
        category: "DER".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.24".to_string(), "ISO27001-A.6.8".to_string()],
        remediation_guidance: Some("Define and document security event categories and reporting requirements".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-DER.2.1.A1".to_string(),
        control_id: "DER.2.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Security incident management process".to_string(),
        description: "A formal security incident management process must be established with clear roles and procedures.".to_string(),
        category: "DER".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.24".to_string(), "ISO27001-A.5.26".to_string(), "NIST-IR-4".to_string()],
        remediation_guidance: Some("Implement incident response plan with defined roles and escalation paths".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-DER.2.2.A1".to_string(),
        control_id: "DER.2.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Security monitoring".to_string(),
        description: "Continuous security monitoring must be implemented to detect security incidents in a timely manner.".to_string(),
        category: "DER".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.16".to_string(), "NIST-SI-4".to_string()],
        remediation_guidance: Some("Deploy SIEM and security monitoring tools with 24/7 alerting".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-DER.2.3.A1".to_string(),
        control_id: "DER.2.3.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Forensic readiness".to_string(),
        description: "The organization must be prepared for forensic investigations with proper evidence collection capabilities.".to_string(),
        category: "DER".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.28".to_string()],
        remediation_guidance: Some("Implement forensic readiness procedures and evidence handling guidelines".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-DER.3.1.A1".to_string(),
        control_id: "DER.3.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Security audit and revision".to_string(),
        description: "Regular security audits and revisions must be performed to verify compliance and effectiveness.".to_string(),
        category: "DER".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.35".to_string(), "ISO27001-A.5.36".to_string()],
        remediation_guidance: Some("Establish regular audit program with internal and external reviews".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-DER.4.A1".to_string(),
        control_id: "DER.4.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Emergency management".to_string(),
        description: "Emergency management procedures must be established for business continuity and disaster recovery.".to_string(),
        category: "DER".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.29".to_string(), "ISO27001-A.5.30".to_string(), "NIST-CP-10".to_string()],
        remediation_guidance: Some("Develop and test business continuity and disaster recovery plans".to_string()),
    });

    // ========================================================================
    // APP - Applications
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-APP.1.1.A1".to_string(),
        control_id: "APP.1.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Office application security".to_string(),
        description: "Office applications must be configured securely with macro restrictions and automatic update mechanisms.".to_string(),
        category: "APP".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string()],
        remediation_guidance: Some("Configure office applications with security hardening and macro restrictions".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-APP.1.2.A1".to_string(),
        control_id: "APP.1.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Web browser security".to_string(),
        description: "Web browsers must be configured securely with appropriate content filtering and plugin restrictions.".to_string(),
        category: "APP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.23".to_string()],
        remediation_guidance: Some("Implement browser security policies and content filtering".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-APP.2.1.A1".to_string(),
        control_id: "APP.2.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Directory service security".to_string(),
        description: "Directory services must be configured securely with appropriate access controls and monitoring.".to_string(),
        category: "APP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.15".to_string(), "ISO27001-A.8.2".to_string()],
        remediation_guidance: Some("Harden directory services with secure configuration and access controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-APP.3.1.A1".to_string(),
        control_id: "APP.3.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Web application security".to_string(),
        description: "Web applications must be developed and operated securely following OWASP guidelines.".to_string(),
        category: "APP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.26".to_string(), "ISO27001-A.8.29".to_string()],
        remediation_guidance: Some("Implement web application security testing and secure configuration".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-APP.3.2.A1".to_string(),
        control_id: "APP.3.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Web server security".to_string(),
        description: "Web servers must be hardened and configured securely with appropriate TLS settings.".to_string(),
        category: "APP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string(), "NIST-SC-8".to_string()],
        remediation_guidance: Some("Harden web servers with secure TLS configuration and access controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-APP.4.3.A1".to_string(),
        control_id: "APP.4.3.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Database security".to_string(),
        description: "Databases must be configured securely with encryption, access controls, and audit logging.".to_string(),
        category: "APP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.3".to_string(), "NIST-SC-28".to_string()],
        remediation_guidance: Some("Implement database hardening with encryption and access controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-APP.5.2.A1".to_string(),
        control_id: "APP.5.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Email security".to_string(),
        description: "Email systems must be secured with spam filtering, malware scanning, and encryption capabilities.".to_string(),
        category: "APP".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.14".to_string()],
        remediation_guidance: Some("Implement email security controls including SPF, DKIM, DMARC, and TLS".to_string()),
    });

    // ========================================================================
    // SYS - IT Systems
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-SYS.1.1.A1".to_string(),
        control_id: "SYS.1.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Appropriate server installation".to_string(),
        description: "Servers must be installed using secure baseline configurations and hardening guidelines.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string(), "NIST-CM-2".to_string()],
        remediation_guidance: Some("Deploy servers using secure baseline images and hardening standards".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.1.1.A2".to_string(),
        control_id: "SYS.1.1.A2".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "User authentication on servers".to_string(),
        description: "Strong authentication mechanisms must be implemented for server access.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.5".to_string(), "NIST-IA-2".to_string()],
        remediation_guidance: Some("Implement strong authentication with MFA for privileged access".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.1.2.A1".to_string(),
        control_id: "SYS.1.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Windows Server hardening".to_string(),
        description: "Windows servers must be hardened according to BSI and CIS guidelines.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string()],
        remediation_guidance: Some("Apply Windows Server hardening using CIS Benchmarks".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.1.3.A1".to_string(),
        control_id: "SYS.1.3.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Linux/Unix Server hardening".to_string(),
        description: "Linux and Unix servers must be hardened according to BSI and CIS guidelines.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string()],
        remediation_guidance: Some("Apply Linux/Unix hardening using CIS Benchmarks".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.1.5.A1".to_string(),
        control_id: "SYS.1.5.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Virtualization security".to_string(),
        description: "Virtualization platforms must be secured with appropriate isolation and access controls.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.22".to_string()],
        remediation_guidance: Some("Harden hypervisors and implement VM isolation controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.1.6.A1".to_string(),
        control_id: "SYS.1.6.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Container security".to_string(),
        description: "Container environments must be secured with image scanning, runtime protection, and orchestration security.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string()],
        remediation_guidance: Some("Implement container security with image scanning and runtime controls".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.2.1.A1".to_string(),
        control_id: "SYS.2.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Client system security".to_string(),
        description: "Client systems must be secured with appropriate endpoint protection and configuration management.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.1".to_string()],
        remediation_guidance: Some("Deploy endpoint protection and configuration management on all clients".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.3.1.A1".to_string(),
        control_id: "SYS.3.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Mobile device security".to_string(),
        description: "Mobile devices must be managed with MDM including encryption, remote wipe, and app controls.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.1".to_string(), "NIST-AC-19".to_string()],
        remediation_guidance: Some("Implement MDM with encryption, remote wipe, and application management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-SYS.4.4.A1".to_string(),
        control_id: "SYS.4.4.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "IoT device security".to_string(),
        description: "IoT devices must be inventoried, segmented, and monitored for security vulnerabilities.".to_string(),
        category: "SYS".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.9".to_string(), "ISO27001-A.8.20".to_string()],
        remediation_guidance: Some("Inventory IoT devices and implement network segmentation".to_string()),
    });

    // ========================================================================
    // IND - Industrial IT
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-IND.1.A1".to_string(),
        control_id: "IND.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "OT/ICS security management".to_string(),
        description: "Industrial control systems must have dedicated security management with appropriate policies and procedures.".to_string(),
        category: "IND".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Establish OT-specific security policies and governance".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-IND.2.1.A1".to_string(),
        control_id: "IND.2.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "ICS network segmentation".to_string(),
        description: "Industrial control networks must be segmented from corporate networks with appropriate security controls.".to_string(),
        category: "IND".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.22".to_string()],
        remediation_guidance: Some("Implement Purdue Model network segmentation for OT environments".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-IND.2.2.A1".to_string(),
        control_id: "IND.2.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "PLC/SCADA security".to_string(),
        description: "Programmable logic controllers and SCADA systems must be protected with appropriate access controls.".to_string(),
        category: "IND".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.15".to_string()],
        remediation_guidance: Some("Implement PLC/SCADA access controls and change management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-IND.2.7.A1".to_string(),
        control_id: "IND.2.7.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Safety system security".to_string(),
        description: "Safety instrumented systems must be protected to ensure availability and integrity.".to_string(),
        category: "IND".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.14".to_string()],
        remediation_guidance: Some("Implement safety system security controls and change management".to_string()),
    });

    // ========================================================================
    // NET - Networks and Communication
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-NET.1.1.A1".to_string(),
        control_id: "NET.1.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Network architecture documentation".to_string(),
        description: "Network architecture must be documented including topology, security zones, and data flows.".to_string(),
        category: "NET".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.20".to_string()],
        remediation_guidance: Some("Document network architecture with security zones and data flow diagrams".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-NET.1.2.A1".to_string(),
        control_id: "NET.1.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Network management".to_string(),
        description: "Network devices must be centrally managed with secure configuration and change control.".to_string(),
        category: "NET".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string()],
        remediation_guidance: Some("Implement centralized network management with configuration control".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-NET.2.1.A1".to_string(),
        control_id: "NET.2.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "WLAN security".to_string(),
        description: "Wireless networks must use strong encryption (WPA3) and authentication (802.1X).".to_string(),
        category: "NET".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.21".to_string(), "NIST-AC-18".to_string()],
        remediation_guidance: Some("Implement WPA3-Enterprise with 802.1X authentication".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-NET.3.1.A1".to_string(),
        control_id: "NET.3.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Router and switch security".to_string(),
        description: "Network devices must be hardened with secure configurations and access controls.".to_string(),
        category: "NET".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.9".to_string(), "NIST-CM-6".to_string()],
        remediation_guidance: Some("Apply network device hardening using vendor and CIS guidelines".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-NET.3.2.A1".to_string(),
        control_id: "NET.3.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Firewall security".to_string(),
        description: "Firewalls must be configured with deny-by-default rules and regular rule review.".to_string(),
        category: "NET".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.20".to_string(), "NIST-SC-7".to_string()],
        remediation_guidance: Some("Implement firewall with default-deny and documented rule set".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-NET.3.3.A1".to_string(),
        control_id: "NET.3.3.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "VPN security".to_string(),
        description: "VPN connections must use strong encryption and authentication mechanisms.".to_string(),
        category: "NET".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.24".to_string(), "NIST-AC-17".to_string()],
        remediation_guidance: Some("Configure VPN with strong ciphers and multi-factor authentication".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-NET.4.1.A1".to_string(),
        control_id: "NET.4.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "TLS configuration".to_string(),
        description: "TLS must be configured with secure protocol versions and cipher suites.".to_string(),
        category: "NET".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.24".to_string(), "NIST-SC-8".to_string()],
        remediation_guidance: Some("Configure TLS 1.2+ with secure cipher suites according to BSI TR-02102".to_string()),
    });

    // ========================================================================
    // INF - Infrastructure
    // ========================================================================

    controls.push(ComplianceControl {
        id: "BSI-INF.1.A1".to_string(),
        control_id: "INF.1.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Building security concept".to_string(),
        description: "A building security concept must be developed covering physical access controls and zones.".to_string(),
        category: "INF".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.7.1".to_string(), "ISO27001-A.7.2".to_string()],
        remediation_guidance: Some("Develop building security concept with defined security zones".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-INF.2.A1".to_string(),
        control_id: "INF.2.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Data center security".to_string(),
        description: "Data centers must have comprehensive physical security including access control, surveillance, and environmental controls.".to_string(),
        category: "INF".to_string(),
        priority: ControlPriority::Critical,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.7.3".to_string(), "ISO27001-A.7.4".to_string()],
        remediation_guidance: Some("Implement data center physical security with multi-layer access control".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-INF.2.A2".to_string(),
        control_id: "INF.2.A2".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Power supply protection".to_string(),
        description: "Critical IT systems must have redundant power supply with UPS and generator backup.".to_string(),
        category: "INF".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.7.11".to_string()],
        remediation_guidance: Some("Implement redundant power supply with UPS and generator".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-INF.2.A3".to_string(),
        control_id: "INF.2.A3".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Environmental monitoring".to_string(),
        description: "Environmental conditions (temperature, humidity, water detection) must be monitored with automated alerting.".to_string(),
        category: "INF".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.7.5".to_string()],
        remediation_guidance: Some("Deploy environmental monitoring sensors with automated alerts".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-INF.5.A1".to_string(),
        control_id: "INF.5.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Technical room security".to_string(),
        description: "Technical rooms must be secured with appropriate physical access controls.".to_string(),
        category: "INF".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.7.3".to_string()],
        remediation_guidance: Some("Secure technical rooms with access control and monitoring".to_string()),
    });

    controls.push(ComplianceControl {
        id: "BSI-INF.9.A1".to_string(),
        control_id: "INF.9.A1".to_string(),
        framework: ComplianceFramework::BsiGrundschutz,
        title: "Remote workplace security".to_string(),
        description: "Remote/home office workplaces must meet minimum security requirements for equipment and data protection.".to_string(),
        category: "INF".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.6.7".to_string()],
        remediation_guidance: Some("Define and enforce security requirements for remote work".to_string()),
    });

    controls
}

/// Map a vulnerability to relevant BSI IT-Grundschutz controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication/Access Control vulnerabilities
    if title_lower.contains("authentication")
        || title_lower.contains("password")
        || title_lower.contains("credential")
        || title_lower.contains("mfa")
    {
        mappings.push(("ORP.4.A1".to_string(), Severity::High));
        mappings.push(("ORP.4.A2".to_string(), Severity::High));
        mappings.push(("SYS.1.1.A2".to_string(), Severity::High));
    }

    // Encryption/TLS vulnerabilities
    if title_lower.contains("encryption")
        || title_lower.contains("tls")
        || title_lower.contains("ssl")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted")
        || title_lower.contains("weak cipher")
    {
        mappings.push(("CON.1.A1".to_string(), Severity::High));
        mappings.push(("NET.4.1.A1".to_string(), Severity::High));
        mappings.push(("NET.3.3.A1".to_string(), Severity::High));
    }

    // Malware/Endpoint protection
    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("ransomware")
        || title_lower.contains("trojan")
    {
        mappings.push(("OPS.1.1.4.A1".to_string(), Severity::Critical));
    }

    // Patching/Update vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("patch")
        || title_lower.contains("end of life")
        || title_lower.contains("update")
    {
        mappings.push(("OPS.1.1.3.A1".to_string(), Severity::High));
    }

    // Logging/Monitoring issues
    if title_lower.contains("logging")
        || title_lower.contains("monitoring")
        || title_lower.contains("audit")
    {
        mappings.push(("OPS.1.1.5.A1".to_string(), Severity::Medium));
        mappings.push(("DER.2.2.A1".to_string(), Severity::Medium));
    }

    // Backup/Recovery issues
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
        || title_lower.contains("disaster")
    {
        mappings.push(("CON.3.A1".to_string(), Severity::High));
        mappings.push(("DER.4.A1".to_string(), Severity::High));
    }

    // Network security vulnerabilities
    if title_lower.contains("firewall")
        || title_lower.contains("network")
        || title_lower.contains("segmentation")
    {
        mappings.push(("NET.3.2.A1".to_string(), Severity::High));
        mappings.push(("NET.1.1.A1".to_string(), Severity::Medium));
    }

    // Wireless security
    if title_lower.contains("wifi")
        || title_lower.contains("wireless")
        || title_lower.contains("wlan")
        || title_lower.contains("wpa")
    {
        mappings.push(("NET.2.1.A1".to_string(), Severity::High));
    }

    // Web application vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("xss")
        || title_lower.contains("csrf")
        || title_lower.contains("injection")
    {
        mappings.push(("APP.3.1.A1".to_string(), Severity::Critical));
        mappings.push(("CON.8.A1".to_string(), Severity::High));
    }

    // Server hardening issues
    if title_lower.contains("hardening")
        || title_lower.contains("misconfiguration")
        || title_lower.contains("default configuration")
    {
        mappings.push(("SYS.1.1.A1".to_string(), Severity::High));
        mappings.push(("SYS.1.2.A1".to_string(), Severity::High));
        mappings.push(("SYS.1.3.A1".to_string(), Severity::High));
    }

    // Container/Virtualization vulnerabilities
    if title_lower.contains("container")
        || title_lower.contains("docker")
        || title_lower.contains("kubernetes")
    {
        mappings.push(("SYS.1.6.A1".to_string(), Severity::High));
    }

    if title_lower.contains("virtual")
        || title_lower.contains("hypervisor")
        || title_lower.contains("vmware")
        || title_lower.contains("hyper-v")
    {
        mappings.push(("SYS.1.5.A1".to_string(), Severity::High));
    }

    // Mobile device vulnerabilities
    if title_lower.contains("mobile")
        || title_lower.contains("mdm")
        || title_lower.contains("byod")
    {
        mappings.push(("SYS.3.1.A1".to_string(), Severity::High));
    }

    // IoT vulnerabilities
    if title_lower.contains("iot")
        || title_lower.contains("embedded")
        || title_lower.contains("smart device")
    {
        mappings.push(("SYS.4.4.A1".to_string(), Severity::High));
    }

    // ICS/OT vulnerabilities
    if title_lower.contains("ics")
        || title_lower.contains("scada")
        || title_lower.contains("plc")
        || title_lower.contains("ot ")
        || title_lower.contains("industrial")
    {
        mappings.push(("IND.1.A1".to_string(), Severity::Critical));
        mappings.push(("IND.2.1.A1".to_string(), Severity::Critical));
        mappings.push(("IND.2.2.A1".to_string(), Severity::Critical));
    }

    // Remote access vulnerabilities
    if title_lower.contains("remote access")
        || title_lower.contains("vpn")
        || title_lower.contains("rdp")
    {
        mappings.push(("OPS.1.2.1.A1".to_string(), Severity::High));
        mappings.push(("NET.3.3.A1".to_string(), Severity::High));
    }

    // Port-specific mappings
    if let Some(p) = port {
        match p {
            22 => {
                if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
                    mappings.push(("OPS.1.2.1.A1".to_string(), Severity::High));
                }
            }
            23 => {
                // Telnet - insecure protocol
                mappings.push(("NET.4.1.A1".to_string(), Severity::High));
                mappings.push(("SYS.1.1.A1".to_string(), Severity::High));
            }
            3389 => {
                if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
                    mappings.push(("OPS.1.2.1.A1".to_string(), Severity::High));
                }
            }
            80 | 443 | 8080 | 8443 => {
                if title_lower.contains("vulnerable") {
                    mappings.push(("APP.3.2.A1".to_string(), Severity::High));
                }
            }
            _ => {}
        }
    }

    // Data protection/Privacy
    if title_lower.contains("pii")
        || title_lower.contains("gdpr")
        || title_lower.contains("personal data")
        || title_lower.contains("privacy")
    {
        mappings.push(("CON.2.A1".to_string(), Severity::High));
    }

    // Incident response
    if title_lower.contains("incident")
        || title_lower.contains("breach")
    {
        mappings.push(("DER.2.1.A1".to_string(), Severity::High));
        mappings.push(("DER.1.A1".to_string(), Severity::Medium));
    }

    // Physical security
    if title_lower.contains("physical")
        || title_lower.contains("data center")
        || title_lower.contains("facility")
    {
        mappings.push(("INF.1.A1".to_string(), Severity::High));
        mappings.push(("INF.2.A1".to_string(), Severity::High));
    }

    // Default mapping if nothing else matches
    if mappings.is_empty() {
        mappings.push(("ISMS.1.A5".to_string(), Severity::Medium));
    }

    mappings
}

/// Map vulnerability type string to BSI IT-Grundschutz control IDs
pub fn map_vulnerability_to_controls(vuln_type: &str) -> Vec<String> {
    match vuln_type.to_lowercase().as_str() {
        "authentication" | "password" | "credential" => vec![
            "ORP.4.A1".to_string(),
            "ORP.4.A2".to_string(),
            "SYS.1.1.A2".to_string(),
        ],
        "encryption" | "cryptography" | "tls" | "ssl" => vec![
            "CON.1.A1".to_string(),
            "NET.4.1.A1".to_string(),
        ],
        "malware" | "virus" | "endpoint" => vec![
            "OPS.1.1.4.A1".to_string(),
        ],
        "patching" | "update" | "vulnerability" => vec![
            "OPS.1.1.3.A1".to_string(),
        ],
        "logging" | "monitoring" | "audit" => vec![
            "OPS.1.1.5.A1".to_string(),
            "DER.2.2.A1".to_string(),
        ],
        "backup" | "recovery" | "continuity" => vec![
            "CON.3.A1".to_string(),
            "DER.4.A1".to_string(),
        ],
        "network" | "firewall" | "segmentation" => vec![
            "NET.3.2.A1".to_string(),
            "NET.1.1.A1".to_string(),
        ],
        "wireless" | "wifi" | "wlan" => vec![
            "NET.2.1.A1".to_string(),
        ],
        "web_application" | "webapp" | "injection" => vec![
            "APP.3.1.A1".to_string(),
            "CON.8.A1".to_string(),
        ],
        "server" | "hardening" | "configuration" => vec![
            "SYS.1.1.A1".to_string(),
            "SYS.1.2.A1".to_string(),
            "SYS.1.3.A1".to_string(),
        ],
        "container" | "docker" | "kubernetes" => vec![
            "SYS.1.6.A1".to_string(),
        ],
        "virtualization" | "hypervisor" => vec![
            "SYS.1.5.A1".to_string(),
        ],
        "mobile" | "mdm" => vec![
            "SYS.3.1.A1".to_string(),
        ],
        "iot" | "embedded" => vec![
            "SYS.4.4.A1".to_string(),
        ],
        "ics" | "scada" | "ot" | "industrial" => vec![
            "IND.1.A1".to_string(),
            "IND.2.1.A1".to_string(),
            "IND.2.2.A1".to_string(),
        ],
        "remote_access" | "vpn" => vec![
            "OPS.1.2.1.A1".to_string(),
            "NET.3.3.A1".to_string(),
        ],
        "privacy" | "gdpr" | "data_protection" => vec![
            "CON.2.A1".to_string(),
        ],
        "incident" | "breach" => vec![
            "DER.2.1.A1".to_string(),
            "DER.1.A1".to_string(),
        ],
        "physical" | "datacenter" => vec![
            "INF.1.A1".to_string(),
            "INF.2.A1".to_string(),
        ],
        "awareness" | "training" => vec![
            "ORP.3.A1".to_string(),
        ],
        "policy" | "governance" => vec![
            "ISMS.1.A4".to_string(),
            "ISMS.1.A3".to_string(),
        ],
        _ => vec!["ISMS.1.A5".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_count() {
        let controls = get_controls();
        assert_eq!(controls.len(), CONTROL_COUNT,
            "Expected {} controls, got {}", CONTROL_COUNT, controls.len());
    }

    #[test]
    fn test_all_controls_have_required_fields() {
        for control in get_controls() {
            assert!(!control.id.is_empty(), "Control ID should not be empty");
            assert!(!control.control_id.is_empty(), "Control control_id should not be empty");
            assert!(!control.title.is_empty(), "Control title should not be empty");
            assert!(!control.description.is_empty(), "Control description should not be empty");
            assert!(!control.category.is_empty(), "Control category should not be empty");
            assert!(control.remediation_guidance.is_some(), "Control should have remediation guidance");
        }
    }

    #[test]
    fn test_all_controls_have_iso27001_cross_references() {
        let controls = get_controls();
        let controls_with_iso_refs: Vec<_> = controls.iter()
            .filter(|c| c.cross_references.iter().any(|r| r.starts_with("ISO27001")))
            .collect();

        // At least 50% should have ISO 27001 cross-references
        assert!(
            controls_with_iso_refs.len() >= controls.len() / 2,
            "At least half of controls should have ISO 27001 cross-references"
        );
    }

    #[test]
    fn test_vulnerability_mapping() {
        let controls = map_vulnerability_to_controls("authentication");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"ORP.4.A1".to_string()));
    }

    #[test]
    fn test_categories_present() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> = controls.iter()
            .map(|c| c.category.as_str())
            .collect();

        // Verify all expected categories are present
        assert!(categories.contains("ISMS"), "ISMS category should be present");
        assert!(categories.contains("ORP"), "ORP category should be present");
        assert!(categories.contains("CON"), "CON category should be present");
        assert!(categories.contains("OPS"), "OPS category should be present");
        assert!(categories.contains("DER"), "DER category should be present");
        assert!(categories.contains("APP"), "APP category should be present");
        assert!(categories.contains("SYS"), "SYS category should be present");
        assert!(categories.contains("IND"), "IND category should be present");
        assert!(categories.contains("NET"), "NET category should be present");
        assert!(categories.contains("INF"), "INF category should be present");
    }

    #[test]
    fn test_map_vulnerability_returns_results() {
        let mappings = map_vulnerability("SQL injection vulnerability", None, Some(443), None);
        assert!(!mappings.is_empty(), "SQL injection should map to controls");

        let mappings = map_vulnerability("Outdated OpenSSL version", None, None, None);
        assert!(!mappings.is_empty(), "Patching vulnerability should map to controls");

        let mappings = map_vulnerability("Weak TLS configuration", None, Some(443), None);
        assert!(!mappings.is_empty(), "TLS vulnerability should map to controls");
    }

    #[test]
    fn test_framework_is_correct() {
        for control in get_controls() {
            assert_eq!(
                control.framework,
                ComplianceFramework::BsiGrundschutz,
                "All controls should belong to BsiGrundschutz framework"
            );
        }
    }
}
