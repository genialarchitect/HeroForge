//! FERPA Controls
//!
//! Family Educational Rights and Privacy Act requirements for protecting
//! student education records and privacy in educational institutions.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of FERPA controls in this module
pub const CONTROL_COUNT: usize = 22;

/// Get all FERPA controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // Access Control Requirements
        ComplianceControl {
            id: "FERPA-AC-1".to_string(),
            control_id: "AC-1".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Access Control Policy".to_string(),
            description: "Establish policies and procedures for controlling access to student education records.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-1".to_string()],
            remediation_guidance: Some("Document access control policies specific to education records.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-AC-2".to_string(),
            control_id: "AC-2".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Access Authorization".to_string(),
            description: "Implement mechanisms to ensure only authorized school officials access student records.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "NIST-AC-3".to_string()],
            remediation_guidance: Some("Implement role-based access control for student information systems.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-AC-3".to_string(),
            control_id: "AC-3".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Legitimate Educational Interest".to_string(),
            description: "Ensure access is granted only to officials with legitimate educational interest.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string()],
            remediation_guidance: Some("Define and document what constitutes legitimate educational interest.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-AC-4".to_string(),
            control_id: "AC-4".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Access Logging and Monitoring".to_string(),
            description: "Maintain records of who accesses student education records and for what purpose.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "NIST-AU-12".to_string()],
            remediation_guidance: Some("Enable comprehensive audit logging for student record access.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-AC-5".to_string(),
            control_id: "AC-5".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Directory Information Designation".to_string(),
            description: "Clearly define what information is designated as directory information.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document directory information categories and opt-out procedures.".to_string()),
        },

        // Consent Requirements
        ComplianceControl {
            id: "FERPA-CN-1".to_string(),
            control_id: "CN-1".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Consent Requirements".to_string(),
            description: "Obtain written consent before disclosing personally identifiable information.".to_string(),
            category: "Consent".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement consent tracking system for record disclosures.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-CN-2".to_string(),
            control_id: "CN-2".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Consent Documentation".to_string(),
            description: "Maintain records of consent obtained for disclosure of education records.".to_string(),
            category: "Consent".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("FERPA-CN-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Archive consent forms with appropriate retention periods.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-CN-3".to_string(),
            control_id: "CN-3".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Exception Documentation".to_string(),
            description: "Document disclosures made under FERPA exceptions without consent.".to_string(),
            category: "Consent".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("FERPA-CN-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Maintain records of all exception-based disclosures.".to_string()),
        },

        // Data Protection Requirements
        ComplianceControl {
            id: "FERPA-DP-1".to_string(),
            control_id: "DP-1".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Data Protection Policy".to_string(),
            description: "Implement policies to protect the confidentiality of education records.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string()],
            remediation_guidance: Some("Document data protection policies for student records.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-DP-2".to_string(),
            control_id: "DP-2".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Encryption at Rest".to_string(),
            description: "Encrypt stored education records containing personally identifiable information.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string(), "CIS-3.6".to_string()],
            remediation_guidance: Some("Implement AES-256 encryption for student record databases.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-DP-3".to_string(),
            control_id: "DP-3".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Encryption in Transit".to_string(),
            description: "Encrypt education records during electronic transmission.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Use TLS 1.2+ for all student record transmissions.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-DP-4".to_string(),
            control_id: "DP-4".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Secure Storage".to_string(),
            description: "Store physical and electronic education records in secure locations.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement physical and logical access controls for record storage.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-DP-5".to_string(),
            control_id: "DP-5".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Data Minimization".to_string(),
            description: "Collect and retain only the minimum education record information necessary.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Review and minimize data collection in student systems.".to_string()),
        },

        // Third Party Requirements
        ComplianceControl {
            id: "FERPA-TP-1".to_string(),
            control_id: "TP-1".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Third Party Agreements".to_string(),
            description: "Establish agreements with third parties receiving education records.".to_string(),
            category: "Third Party Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Execute data protection agreements with all third-party processors.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-TP-2".to_string(),
            control_id: "TP-2".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Service Provider Oversight".to_string(),
            description: "Monitor service providers for compliance with FERPA requirements.".to_string(),
            category: "Third Party Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("FERPA-TP-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Conduct periodic assessments of third-party FERPA compliance.".to_string()),
        },

        // Notification and Rights
        ComplianceControl {
            id: "FERPA-NR-1".to_string(),
            control_id: "NR-1".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Annual Notification".to_string(),
            description: "Provide annual notification of rights under FERPA to parents and eligible students.".to_string(),
            category: "Notification and Rights".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Publish and distribute annual FERPA rights notification.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-NR-2".to_string(),
            control_id: "NR-2".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Inspection and Review Rights".to_string(),
            description: "Implement procedures for parents/students to inspect and review education records.".to_string(),
            category: "Notification and Rights".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document record inspection request and fulfillment procedures.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-NR-3".to_string(),
            control_id: "NR-3".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Amendment Request Procedures".to_string(),
            description: "Implement procedures for handling requests to amend education records.".to_string(),
            category: "Notification and Rights".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document amendment request handling and appeal procedures.".to_string()),
        },

        // Incident Response
        ComplianceControl {
            id: "FERPA-IR-1".to_string(),
            control_id: "IR-1".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Breach Response Plan".to_string(),
            description: "Establish procedures for responding to unauthorized disclosure of education records.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string()],
            remediation_guidance: Some("Develop breach response plan specific to education records.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-IR-2".to_string(),
            control_id: "IR-2".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Breach Notification".to_string(),
            description: "Notify affected individuals and relevant authorities of unauthorized disclosures.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("FERPA-IR-1".to_string()),
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Document breach notification procedures and contacts.".to_string()),
        },

        // Training and Awareness
        ComplianceControl {
            id: "FERPA-TA-1".to_string(),
            control_id: "TA-1".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Staff Training".to_string(),
            description: "Train all staff who access education records on FERPA requirements.".to_string(),
            category: "Training and Awareness".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string()],
            remediation_guidance: Some("Conduct annual FERPA training for all staff with record access.".to_string()),
        },
        ComplianceControl {
            id: "FERPA-TA-2".to_string(),
            control_id: "TA-2".to_string(),
            framework: ComplianceFramework::Ferpa,
            title: "Training Documentation".to_string(),
            description: "Maintain records of FERPA training completion.".to_string(),
            category: "Training and Awareness".to_string(),
            priority: ControlPriority::Low,
            automated_check: false,
            parent_id: Some("FERPA-TA-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Track and archive training completion records.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant FERPA controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control issues
    if title_lower.contains("unauthorized access")
        || title_lower.contains("authentication")
    {
        mappings.push(("FERPA-AC-2".to_string(), Severity::Critical));
        mappings.push(("FERPA-AC-3".to_string(), Severity::High));
    }

    // Logging issues
    if title_lower.contains("logging")
        || title_lower.contains("audit")
    {
        mappings.push(("FERPA-AC-4".to_string(), Severity::Medium));
    }

    // Encryption issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
    {
        mappings.push(("FERPA-DP-2".to_string(), Severity::High));
        mappings.push(("FERPA-DP-3".to_string(), Severity::High));
    }

    // TLS/SSL issues
    if title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("certificate")
    {
        mappings.push(("FERPA-DP-3".to_string(), Severity::High));
    }

    // Data exposure
    if title_lower.contains("data exposure")
        || title_lower.contains("information disclosure")
        || title_lower.contains("data leak")
    {
        mappings.push(("FERPA-DP-1".to_string(), Severity::Critical));
        mappings.push(("FERPA-IR-1".to_string(), Severity::High));
    }

    // Credential issues
    if title_lower.contains("password")
        || title_lower.contains("credential")
        || title_lower.contains("default")
    {
        mappings.push(("FERPA-AC-2".to_string(), Severity::High));
    }

    mappings
}
