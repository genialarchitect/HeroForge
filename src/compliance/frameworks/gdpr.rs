//! GDPR (General Data Protection Regulation) Compliance Controls
//!
//! This module implements controls based on the EU General Data Protection
//! Regulation (GDPR) requirements. The controls cover:
//!
//! - Data Processing Principles (Articles 5-11)
//! - Rights of Data Subjects (Articles 12-23)
//! - Controller and Processor Obligations (Articles 24-43)
//! - Security and Breach Notification (Articles 32-34)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of GDPR controls
pub const CONTROL_COUNT: usize = 37;

/// Get all GDPR controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Data Processing Principles (Articles 5-11)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "GDPR-5.1a".to_string(),
        control_id: "Art.5.1(a)".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Lawfulness, fairness and transparency".to_string(),
        description: "Personal data shall be processed lawfully, fairly and in a transparent manner in relation to the data subject".to_string(),
        category: "Processing Principles".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.34".to_string()],
        remediation_guidance: Some("Ensure all data processing has a lawful basis and is transparent to data subjects".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-5.1b".to_string(),
        control_id: "Art.5.1(b)".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Purpose limitation".to_string(),
        description: "Personal data shall be collected for specified, explicit and legitimate purposes and not further processed in a manner that is incompatible with those purposes".to_string(),
        category: "Processing Principles".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Document and limit processing purposes for all personal data".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-5.1c".to_string(),
        control_id: "Art.5.1(c)".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Data minimization".to_string(),
        description: "Personal data shall be adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed".to_string(),
        category: "Processing Principles".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Review and minimize personal data collection to only what is necessary".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-5.1d".to_string(),
        control_id: "Art.5.1(d)".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Accuracy".to_string(),
        description: "Personal data shall be accurate and, where necessary, kept up to date".to_string(),
        category: "Processing Principles".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Implement processes to ensure data accuracy and enable rectification".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-5.1e".to_string(),
        control_id: "Art.5.1(e)".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Storage limitation".to_string(),
        description: "Personal data shall be kept for no longer than is necessary for the purposes for which they are processed".to_string(),
        category: "Processing Principles".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.10".to_string()],
        remediation_guidance: Some("Implement data retention policies and automated deletion".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-5.1f".to_string(),
        control_id: "Art.5.1(f)".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Integrity and confidentiality".to_string(),
        description: "Personal data shall be processed in a manner that ensures appropriate security".to_string(),
        category: "Processing Principles".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.24".to_string(), "ISO27001-A.5.15".to_string()],
        remediation_guidance: Some("Implement appropriate technical and organizational security measures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-5.2".to_string(),
        control_id: "Art.5.2".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Accountability".to_string(),
        description: "The controller shall be responsible for and be able to demonstrate compliance".to_string(),
        category: "Processing Principles".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Maintain documentation demonstrating GDPR compliance".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-6".to_string(),
        control_id: "Art.6".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Lawfulness of processing".to_string(),
        description: "Processing shall be lawful only if at least one of the lawful bases applies".to_string(),
        category: "Lawful Basis".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Document and validate lawful basis for all processing activities".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-7".to_string(),
        control_id: "Art.7".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Conditions for consent".to_string(),
        description: "Where processing is based on consent, the controller shall be able to demonstrate consent".to_string(),
        category: "Lawful Basis".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Implement consent management with clear opt-in and withdrawal mechanisms".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-9".to_string(),
        control_id: "Art.9".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Processing of special categories of personal data".to_string(),
        description: "Processing of special categories shall be prohibited unless specific conditions apply".to_string(),
        category: "Special Categories".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Implement additional safeguards for special category data processing".to_string()),
    });

    // ========================================================================
    // Data Subject Rights (Articles 12-23)
    // ========================================================================

    let rights_controls = vec![
        ("Art.12", "Transparent information and communication", "The controller shall provide information in a transparent and accessible form", false),
        ("Art.13", "Information when data collected from data subject", "The controller shall provide required information at the time of collection", false),
        ("Art.14", "Information when data not obtained from data subject", "The controller shall provide required information within a reasonable period", false),
        ("Art.15", "Right of access by the data subject", "The data subject has the right to obtain confirmation of processing and access to data", true),
        ("Art.16", "Right to rectification", "The data subject has the right to obtain rectification of inaccurate data", true),
        ("Art.17", "Right to erasure (right to be forgotten)", "The data subject has the right to obtain erasure of personal data", true),
        ("Art.18", "Right to restriction of processing", "The data subject has the right to obtain restriction of processing", true),
        ("Art.19", "Notification obligation regarding rectification or erasure", "The controller shall communicate rectification or erasure to each recipient", false),
        ("Art.20", "Right to data portability", "The data subject has the right to receive data in a structured, machine-readable format", true),
        ("Art.21", "Right to object", "The data subject has the right to object to processing", true),
        ("Art.22", "Automated individual decision-making, including profiling", "The data subject has the right not to be subject to automated decision-making", true),
    ];

    for (control_id, title, desc, automated) in rights_controls {
        controls.push(ComplianceControl {
            id: format!("GDPR-{}", control_id.replace("Art.", "")),
            control_id: control_id.to_string(),
            framework: ComplianceFramework::Gdpr,
            title: title.to_string(),
            description: desc.to_string(),
            category: "Data Subject Rights".to_string(),
            priority: ControlPriority::High,
            automated_check: automated,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some(format!("Implement processes to fulfill {}", title)),
        });
    }

    // ========================================================================
    // Controller and Processor Obligations (Articles 24-31)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "GDPR-24".to_string(),
        control_id: "Art.24".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Responsibility of the controller".to_string(),
        description: "The controller shall implement appropriate measures to ensure processing is performed in accordance with GDPR".to_string(),
        category: "Controller Obligations".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.1".to_string()],
        remediation_guidance: Some("Implement and document data protection measures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-25".to_string(),
        control_id: "Art.25".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Data protection by design and by default".to_string(),
        description: "The controller shall implement measures ensuring only necessary personal data are processed".to_string(),
        category: "Controller Obligations".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Embed data protection into system design and default settings".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-28".to_string(),
        control_id: "Art.28".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Processor requirements".to_string(),
        description: "The controller shall use only processors providing sufficient guarantees".to_string(),
        category: "Controller Obligations".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.19".to_string()],
        remediation_guidance: Some("Ensure data processing agreements are in place with all processors".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-30".to_string(),
        control_id: "Art.30".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Records of processing activities".to_string(),
        description: "Each controller shall maintain a record of processing activities".to_string(),
        category: "Controller Obligations".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Maintain and regularly update Records of Processing Activities (RoPA)".to_string()),
    });

    // ========================================================================
    // Security and Breach Notification (Articles 32-34)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "GDPR-32".to_string(),
        control_id: "Art.32".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Security of processing".to_string(),
        description: "The controller and processor shall implement appropriate security measures".to_string(),
        category: "Security".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.8.24".to_string(), "ISO27001-A.8.13".to_string()],
        remediation_guidance: Some("Implement security measures including encryption and resilience".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-33".to_string(),
        control_id: "Art.33".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Notification of personal data breach to supervisory authority".to_string(),
        description: "The controller shall notify the supervisory authority within 72 hours of becoming aware of a breach".to_string(),
        category: "Breach Notification".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.24".to_string()],
        remediation_guidance: Some("Implement breach detection and 72-hour notification procedures".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-34".to_string(),
        control_id: "Art.34".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Communication of personal data breach to data subject".to_string(),
        description: "When the breach is likely to result in high risk, the controller shall notify the data subject".to_string(),
        category: "Breach Notification".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["ISO27001-A.5.26".to_string()],
        remediation_guidance: Some("Implement procedures for notifying data subjects of high-risk breaches".to_string()),
    });

    // ========================================================================
    // Data Protection Impact Assessment and DPO (Articles 35-39)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "GDPR-35".to_string(),
        control_id: "Art.35".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Data protection impact assessment".to_string(),
        description: "The controller shall carry out a DPIA for high-risk processing".to_string(),
        category: "Impact Assessment".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Conduct DPIAs for high-risk processing activities".to_string()),
    });

    controls.push(ComplianceControl {
        id: "GDPR-37".to_string(),
        control_id: "Art.37".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "Designation of the data protection officer".to_string(),
        description: "The controller and processor shall designate a DPO in specified circumstances".to_string(),
        category: "DPO".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Appoint DPO if required based on processing activities".to_string()),
    });

    // ========================================================================
    // International Transfers (Articles 44-49)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "GDPR-44".to_string(),
        control_id: "Art.44".to_string(),
        framework: ComplianceFramework::Gdpr,
        title: "General principle for transfers".to_string(),
        description: "Any transfer of personal data to a third country shall take place only in compliance with GDPR".to_string(),
        category: "International Transfers".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Ensure appropriate safeguards for international data transfers".to_string()),
    });

    // ========================================================================
    // Technical Controls
    // ========================================================================

    let tech_controls = vec![
        ("GDPR-ENC", "Encryption of personal data", "Implement encryption for personal data at rest and in transit", true),
        ("GDPR-PSEUDO", "Pseudonymisation", "Apply pseudonymisation techniques to reduce identifiability", true),
        ("GDPR-ACCESS", "Access controls for personal data", "Implement role-based access controls for personal data", true),
        ("GDPR-AUDIT", "Audit logging for personal data access", "Maintain audit logs of personal data access and modifications", true),
        ("GDPR-BACKUP", "Backup and recovery of personal data", "Ensure resilience through appropriate backups", true),
        ("GDPR-TEST", "Regular testing of security measures", "Regularly test and evaluate the effectiveness of measures", true),
    ];

    for (control_id, title, desc, automated) in tech_controls {
        controls.push(ComplianceControl {
            id: control_id.to_string(),
            control_id: control_id.to_string(),
            framework: ComplianceFramework::Gdpr,
            title: title.to_string(),
            description: desc.to_string(),
            category: "Technical Measures".to_string(),
            priority: ControlPriority::High,
            automated_check: automated,
            parent_id: Some("GDPR-32".to_string()),
            cross_references: vec!["ISO27001-A.8.24".to_string()],
            remediation_guidance: Some(format!("Implement {}", title.to_lowercase())),
        });
    }

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant GDPR controls (with severity)
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Encryption issues
    if title_lower.contains("encryption") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("plaintext") || title_lower.contains("unencrypted") {
        mappings.push(("GDPR-ENC".to_string(), Severity::High));
        mappings.push(("Art.32".to_string(), Severity::High));
    }

    // Access control / Authorization
    if title_lower.contains("access control") || title_lower.contains("authorization") || title_lower.contains("authentication") {
        mappings.push(("GDPR-ACCESS".to_string(), Severity::High));
        mappings.push(("Art.32".to_string(), Severity::High));
    }

    // Logging / Audit
    if title_lower.contains("logging") || title_lower.contains("audit") || title_lower.contains("monitoring") {
        mappings.push(("GDPR-AUDIT".to_string(), Severity::Medium));
        mappings.push(("Art.5.2".to_string(), Severity::Medium));
    }

    // Data breach / Incident
    if title_lower.contains("breach") || title_lower.contains("incident") || title_lower.contains("leak") {
        mappings.push(("Art.33".to_string(), Severity::Critical));
        mappings.push(("Art.34".to_string(), Severity::Critical));
    }

    // Consent issues
    if title_lower.contains("consent") {
        mappings.push(("Art.7".to_string(), Severity::High));
        mappings.push(("Art.6".to_string(), Severity::High));
    }

    // Data retention / Deletion
    if title_lower.contains("retention") || title_lower.contains("deletion") || title_lower.contains("erasure") {
        mappings.push(("Art.5.1(e)".to_string(), Severity::Medium));
        mappings.push(("Art.17".to_string(), Severity::High));
    }

    // Privacy / PII
    if title_lower.contains("privacy") || title_lower.contains("pii") || title_lower.contains("personal data") {
        mappings.push(("Art.5.1(f)".to_string(), Severity::High));
        mappings.push(("GDPR-PSEUDO".to_string(), Severity::Medium));
        mappings.push(("Art.32".to_string(), Severity::High));
    }

    // Data transfer
    if title_lower.contains("transfer") || title_lower.contains("cross-border") {
        mappings.push(("Art.44".to_string(), Severity::High));
    }

    // Backup / Recovery
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("GDPR-BACKUP".to_string(), Severity::Medium));
        mappings.push(("Art.32".to_string(), Severity::Medium));
    }

    // Default - map to security of processing
    if mappings.is_empty() {
        mappings.push(("Art.32".to_string(), Severity::Medium));
    }

    mappings
}

/// Map a vulnerability to relevant GDPR controls (control IDs only)
pub fn map_vulnerability_to_controls(vuln_type: &str) -> Vec<String> {
    match vuln_type.to_lowercase().as_str() {
        "encryption" | "tls" | "ssl" | "data_at_rest" => vec![
            "GDPR-ENC".to_string(),
            "Art.32".to_string(),
        ],
        "access_control" | "authorization" | "authentication" => vec![
            "GDPR-ACCESS".to_string(),
            "Art.32".to_string(),
        ],
        "logging" | "audit" | "monitoring" => vec![
            "GDPR-AUDIT".to_string(),
            "Art.5.2".to_string(),
        ],
        "data_breach" | "incident" => vec![
            "Art.33".to_string(),
            "Art.34".to_string(),
        ],
        "consent" => vec![
            "Art.7".to_string(),
            "Art.6".to_string(),
        ],
        "data_retention" | "deletion" => vec![
            "Art.5.1(e)".to_string(),
            "Art.17".to_string(),
        ],
        "privacy" | "pii" | "personal_data" => vec![
            "Art.5.1(f)".to_string(),
            "GDPR-PSEUDO".to_string(),
            "Art.32".to_string(),
        ],
        "data_transfer" | "cross_border" => vec![
            "Art.44".to_string(),
        ],
        "backup" | "recovery" => vec![
            "GDPR-BACKUP".to_string(),
            "Art.32".to_string(),
        ],
        _ => vec!["Art.32".to_string()],
    }
}

/// Get GDPR fines and penalties context
pub fn get_penalty_context(article: &str) -> Option<String> {
    match article {
        "Art.5" | "Art.6" | "Art.7" | "Art.9" => {
            Some("Up to 20 million EUR or 4% of total worldwide annual turnover".to_string())
        }
        "Art.12" | "Art.13" | "Art.14" | "Art.15" | "Art.16" | "Art.17" | "Art.18" | "Art.19" | "Art.20" | "Art.21" | "Art.22" => {
            Some("Up to 20 million EUR or 4% of total worldwide annual turnover".to_string())
        }
        "Art.25" | "Art.28" | "Art.30" | "Art.32" | "Art.33" | "Art.34" | "Art.35" | "Art.37" => {
            Some("Up to 10 million EUR or 2% of total worldwide annual turnover".to_string())
        }
        "Art.44" => {
            Some("Up to 20 million EUR or 4% of total worldwide annual turnover".to_string())
        }
        _ => None,
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
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let controls = map_vulnerability_to_controls("encryption");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"GDPR-ENC".to_string()));
    }

    #[test]
    fn test_penalty_context() {
        let penalty = get_penalty_context("Art.5");
        assert!(penalty.is_some());
        assert!(penalty.unwrap().contains("4%"));
    }
}
