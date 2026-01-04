//! ISO 27001:2022 Information Security Management System Controls
//!
//! This module implements the controls from ISO/IEC 27001:2022 Annex A
//! which references the 93 controls in ISO/IEC 27002:2022.
//!
//! The controls are organized into 4 themes:
//! - Organizational controls (37 controls)
//! - People controls (8 controls)
//! - Physical controls (14 controls)
//! - Technological controls (34 controls)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of ISO 27001:2022 Annex A controls
pub const CONTROL_COUNT: usize = 93;

/// Get all ISO 27001:2022 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // Organizational Controls (A.5)
    // ========================================================================

    controls.push(ComplianceControl {
        id: "ISO27001-A.5.1".to_string(),
        control_id: "A.5.1".to_string(),
        framework: ComplianceFramework::Iso27001,
        title: "Policies for information security".to_string(),
        description: "Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties".to_string(),
        category: "Organizational".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PL-1".to_string(), "PCI-DSS-12.1".to_string()],
        remediation_guidance: Some("Define and publish information security policies approved by management".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ISO27001-A.5.2".to_string(),
        control_id: "A.5.2".to_string(),
        framework: ComplianceFramework::Iso27001,
        title: "Information security roles and responsibilities".to_string(),
        description: "Information security roles and responsibilities shall be defined and allocated according to the organization needs".to_string(),
        category: "Organizational".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-PM-2".to_string()],
        remediation_guidance: Some("Define and document information security roles and responsibilities".to_string()),
    });

    controls.push(ComplianceControl {
        id: "ISO27001-A.5.3".to_string(),
        control_id: "A.5.3".to_string(),
        framework: ComplianceFramework::Iso27001,
        title: "Segregation of duties".to_string(),
        description: "Conflicting duties and conflicting areas of responsibility shall be segregated".to_string(),
        category: "Organizational".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-AC-5".to_string(), "PCI-DSS-6.4.2".to_string()],
        remediation_guidance: Some("Implement segregation of duties for critical functions".to_string()),
    });

    // A.5.4 - A.5.37: Additional organizational controls
    let org_controls = vec![
        ("A.5.4", "Management responsibilities", "Management shall require all personnel to apply information security in accordance with the established information security policy", false),
        ("A.5.5", "Contact with authorities", "The organization shall establish and maintain contact with relevant authorities", false),
        ("A.5.6", "Contact with special interest groups", "The organization shall establish and maintain contact with special interest groups", false),
        ("A.5.7", "Threat intelligence", "Information relating to information security threats shall be collected and analysed to produce threat intelligence", true),
        ("A.5.8", "Information security in project management", "Information security shall be integrated into project management", false),
        ("A.5.9", "Inventory of information and other associated assets", "An inventory of information and other associated assets shall be developed and maintained", true),
        ("A.5.10", "Acceptable use of information and other associated assets", "Rules for the acceptable use and procedures for handling information shall be identified, documented and implemented", false),
        ("A.5.11", "Return of assets", "Personnel and other interested parties shall return all organizational assets upon change or termination", false),
        ("A.5.12", "Classification of information", "Information shall be classified according to the information security needs of the organization", true),
        ("A.5.13", "Labelling of information", "An appropriate set of procedures for information labelling shall be developed and implemented", true),
        ("A.5.14", "Information transfer", "Information transfer rules, procedures, or agreements shall be in place for all types of transfer facilities", true),
        ("A.5.15", "Access control", "Rules to control physical and logical access to information and other associated assets shall be established", true),
        ("A.5.16", "Identity management", "The full life cycle of identities shall be managed", true),
        ("A.5.17", "Authentication information", "Allocation and management of authentication information shall be controlled by a management process", true),
        ("A.5.18", "Access rights", "Access rights to information shall be provisioned, reviewed, modified and removed in accordance with policy", true),
        ("A.5.19", "Information security in supplier relationships", "Information security requirements shall be established and agreed with each supplier", false),
        ("A.5.20", "Addressing information security within supplier agreements", "Relevant information security requirements shall be established and agreed with each supplier", false),
        ("A.5.21", "Managing information security in the ICT supply chain", "Processes for managing ICT supply chain information security risks shall be defined", true),
        ("A.5.22", "Monitoring, review and change management of supplier services", "The organization shall regularly monitor, review, evaluate and manage change in supplier practices", false),
        ("A.5.23", "Information security for use of cloud services", "Processes for acquisition, use, management and exit from cloud services shall be established", true),
        ("A.5.24", "Information security incident management planning and preparation", "The organization shall plan and prepare for managing information security incidents", true),
        ("A.5.25", "Assessment and decision on information security events", "The organization shall assess security events and decide if they are to be categorized as incidents", true),
        ("A.5.26", "Response to information security incidents", "Information security incidents shall be responded to in accordance with documented procedures", true),
        ("A.5.27", "Learning from information security incidents", "Knowledge gained from incidents shall be used to strengthen and improve controls", false),
        ("A.5.28", "Collection of evidence", "Procedures for identification, collection, acquisition and preservation of evidence shall be established", true),
        ("A.5.29", "Information security during disruption", "The organization shall plan how to maintain information security during disruption", false),
        ("A.5.30", "ICT readiness for business continuity", "ICT readiness shall be planned, implemented, maintained and tested based on business continuity objectives", true),
        ("A.5.31", "Legal, statutory, regulatory and contractual requirements", "Legal requirements relevant to information security shall be identified, documented and kept up to date", false),
        ("A.5.32", "Intellectual property rights", "The organization shall implement appropriate procedures to protect intellectual property rights", false),
        ("A.5.33", "Protection of records", "Records shall be protected from loss, destruction, falsification, unauthorized access and release", true),
        ("A.5.34", "Privacy and protection of PII", "The organization shall identify and meet the requirements for preservation of privacy and protection of PII", true),
        ("A.5.35", "Independent review of information security", "The organization's approach to managing information security shall be independently reviewed", false),
        ("A.5.36", "Compliance with policies, rules and standards for information security", "Compliance with the organization's information security policy shall be regularly reviewed", true),
        ("A.5.37", "Documented operating procedures", "Operating procedures for information processing facilities shall be documented", false),
    ];

    for (control_id, title, desc, automated) in org_controls {
        controls.push(ComplianceControl {
            id: format!("ISO27001-{}", control_id),
            control_id: control_id.to_string(),
            framework: ComplianceFramework::Iso27001,
            title: title.to_string(),
            description: desc.to_string(),
            category: "Organizational".to_string(),
            priority: if control_id.contains("5.24") || control_id.contains("5.34") || control_id.contains("5.15") {
                ControlPriority::High
            } else {
                ControlPriority::High
            },
            automated_check: automated,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some(format!("Implement control: {}", title)),
        });
    }

    // ========================================================================
    // People Controls (A.6)
    // ========================================================================

    let people_controls = vec![
        ("A.6.1", "Screening", "Background verification checks on all candidates shall be carried out prior to joining the organization", false),
        ("A.6.2", "Terms and conditions of employment", "The employment agreements shall state the personnel's and organization's responsibilities for information security", false),
        ("A.6.3", "Information security awareness, education and training", "Personnel shall receive appropriate information security awareness, education and training", true),
        ("A.6.4", "Disciplinary process", "A disciplinary process shall be formalized to take actions against personnel who commit security policy violations", false),
        ("A.6.5", "Responsibilities after termination or change of employment", "Information security responsibilities that remain valid after termination shall be defined and communicated", false),
        ("A.6.6", "Confidentiality or non-disclosure agreements", "Confidentiality agreements shall be identified, documented, regularly reviewed and signed", false),
        ("A.6.7", "Remote working", "Security measures shall be implemented when personnel are working remotely", true),
        ("A.6.8", "Information security event reporting", "The organization shall provide a mechanism for personnel to report observed or suspected security events", true),
    ];

    for (control_id, title, desc, automated) in people_controls {
        controls.push(ComplianceControl {
            id: format!("ISO27001-{}", control_id),
            control_id: control_id.to_string(),
            framework: ComplianceFramework::Iso27001,
            title: title.to_string(),
            description: desc.to_string(),
            category: "People".to_string(),
            priority: ControlPriority::High,
            automated_check: automated,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some(format!("Implement control: {}", title)),
        });
    }

    // ========================================================================
    // Physical Controls (A.7)
    // ========================================================================

    let physical_controls = vec![
        ("A.7.1", "Physical security perimeters", "Security perimeters shall be defined and used to protect areas that contain information and other associated assets"),
        ("A.7.2", "Physical entry", "Secure areas shall be protected by appropriate entry controls and access points"),
        ("A.7.3", "Securing offices, rooms and facilities", "Physical security for offices, rooms and facilities shall be designed and implemented"),
        ("A.7.4", "Physical security monitoring", "Premises shall be continuously monitored for unauthorized physical access"),
        ("A.7.5", "Protecting against physical and environmental threats", "Protection against physical and environmental threats shall be designed and implemented"),
        ("A.7.6", "Working in secure areas", "Security measures for working in secure areas shall be designed and implemented"),
        ("A.7.7", "Clear desk and clear screen", "Clear desk rules for papers and removable storage media and clear screen rules shall be defined"),
        ("A.7.8", "Equipment siting and protection", "Equipment shall be sited securely and protected"),
        ("A.7.9", "Security of assets off-premises", "Off-site assets shall be protected"),
        ("A.7.10", "Storage media", "Storage media shall be managed through their life cycle"),
        ("A.7.11", "Supporting utilities", "Information processing facilities shall be protected from power failures and other disruptions"),
        ("A.7.12", "Cabling security", "Cables carrying power, data or supporting information services shall be protected"),
        ("A.7.13", "Equipment maintenance", "Equipment shall be maintained correctly to ensure availability, integrity and confidentiality"),
        ("A.7.14", "Secure disposal or re-use of equipment", "Items of equipment containing storage media shall be verified to ensure sensitive data has been removed"),
    ];

    for (control_id, title, desc) in physical_controls {
        controls.push(ComplianceControl {
            id: format!("ISO27001-{}", control_id),
            control_id: control_id.to_string(),
            framework: ComplianceFramework::Iso27001,
            title: title.to_string(),
            description: desc.to_string(),
            category: "Physical".to_string(),
            priority: ControlPriority::High,
            automated_check: control_id == "A.7.4" || control_id == "A.7.14",
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some(format!("Implement control: {}", title)),
        });
    }

    // ========================================================================
    // Technological Controls (A.8)
    // ========================================================================

    let tech_controls = vec![
        ("A.8.1", "User endpoint devices", "Information stored on, processed by or accessible via user endpoint devices shall be protected", true),
        ("A.8.2", "Privileged access rights", "The allocation and use of privileged access rights shall be restricted and managed", true),
        ("A.8.3", "Information access restriction", "Access to information and other associated assets shall be restricted", true),
        ("A.8.4", "Access to source code", "Read and write access to source code, development tools and software libraries shall be managed", true),
        ("A.8.5", "Secure authentication", "Secure authentication technologies and procedures shall be implemented", true),
        ("A.8.6", "Capacity management", "The use of resources shall be monitored and adjusted in line with capacity requirements", true),
        ("A.8.7", "Protection against malware", "Protection against malware shall be implemented and supported by appropriate user awareness", true),
        ("A.8.8", "Management of technical vulnerabilities", "Information about technical vulnerabilities shall be obtained, evaluated and appropriate measures taken", true),
        ("A.8.9", "Configuration management", "Configurations including security configurations of hardware, software, services and networks shall be managed", true),
        ("A.8.10", "Information deletion", "Information stored in systems, devices or storage media shall be deleted when no longer required", true),
        ("A.8.11", "Data masking", "Data masking shall be used in accordance with the organization's policy on access control", true),
        ("A.8.12", "Data leakage prevention", "Data leakage prevention measures shall be applied to systems that process, store or transmit sensitive information", true),
        ("A.8.13", "Information backup", "Backup copies of information, software and systems shall be maintained and regularly tested", true),
        ("A.8.14", "Redundancy of information processing facilities", "Information processing facilities shall be implemented with redundancy to meet availability requirements", true),
        ("A.8.15", "Logging", "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed", true),
        ("A.8.16", "Monitoring activities", "Networks, systems and applications shall be monitored for anomalous behaviour", true),
        ("A.8.17", "Clock synchronization", "The clocks of information processing systems shall be synchronized to approved time sources", true),
        ("A.8.18", "Use of privileged utility programs", "The use of utility programs that might override system and application controls shall be controlled", true),
        ("A.8.19", "Installation of software on operational systems", "Procedures shall be implemented to securely manage software installation on operational systems", true),
        ("A.8.20", "Networks security", "Networks and network devices shall be secured, managed and controlled", true),
        ("A.8.21", "Security of network services", "Security mechanisms, service levels and service requirements of network services shall be identified and monitored", true),
        ("A.8.22", "Segregation of networks", "Groups of information services, users and information systems shall be segregated in networks", true),
        ("A.8.23", "Web filtering", "Access to external websites shall be managed to reduce exposure to malicious content", true),
        ("A.8.24", "Use of cryptography", "Rules for the effective use of cryptography shall be defined and implemented", true),
        ("A.8.25", "Secure development life cycle", "Rules for the secure development of software and systems shall be established and applied", true),
        ("A.8.26", "Application security requirements", "Information security requirements shall be identified when developing or acquiring applications", true),
        ("A.8.27", "Secure system architecture and engineering principles", "Principles for engineering secure systems shall be established, documented and applied", true),
        ("A.8.28", "Secure coding", "Secure coding principles shall be applied to software development", true),
        ("A.8.29", "Security testing in development and acceptance", "Security testing processes shall be defined and implemented in the development life cycle", true),
        ("A.8.30", "Outsourced development", "The organization shall direct, monitor and review activities related to outsourced development", false),
        ("A.8.31", "Separation of development, test and production environments", "Development, testing and production environments shall be separated and secured", true),
        ("A.8.32", "Change management", "Changes to information processing facilities and information systems shall be subject to change management", true),
        ("A.8.33", "Test information", "Test information shall be appropriately selected, protected and managed", true),
        ("A.8.34", "Protection of information systems during audit testing", "Audit tests involving assessment of operational systems shall be planned and agreed", false),
    ];

    for (control_id, title, desc, automated) in tech_controls {
        controls.push(ComplianceControl {
            id: format!("ISO27001-{}", control_id),
            control_id: control_id.to_string(),
            framework: ComplianceFramework::Iso27001,
            title: title.to_string(),
            description: desc.to_string(),
            category: "Technological".to_string(),
            priority: if control_id.contains("8.2") || control_id.contains("8.5") || control_id.contains("8.7") || control_id.contains("8.15") {
                ControlPriority::High
            } else {
                ControlPriority::High
            },
            automated_check: automated,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some(format!("Implement control: {}", title)),
        });
    }

    controls
}

use crate::types::Severity;

/// Map a vulnerability to relevant ISO 27001 controls (with severity)
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication/Access Control issues
    if title_lower.contains("authentication") || title_lower.contains("password") || title_lower.contains("mfa") {
        mappings.push(("A.5.16".to_string(), Severity::High));
        mappings.push(("A.5.17".to_string(), Severity::High));
        mappings.push(("A.8.5".to_string(), Severity::High));
    }

    // Access control vulnerabilities
    if title_lower.contains("access control") || title_lower.contains("authorization") || title_lower.contains("privilege") {
        mappings.push(("A.5.15".to_string(), Severity::High));
        mappings.push(("A.5.18".to_string(), Severity::High));
        mappings.push(("A.8.2".to_string(), Severity::High));
        mappings.push(("A.8.3".to_string(), Severity::High));
    }

    // Encryption issues
    if title_lower.contains("encryption") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("plaintext") || title_lower.contains("unencrypted") {
        mappings.push(("A.5.14".to_string(), Severity::High));
        mappings.push(("A.8.24".to_string(), Severity::High));
    }

    // Malware/Virus
    if title_lower.contains("malware") || title_lower.contains("virus") || title_lower.contains("ransomware") {
        mappings.push(("A.8.7".to_string(), Severity::Critical));
    }

    // Vulnerability/Patching
    if title_lower.contains("outdated") || title_lower.contains("patch") || title_lower.contains("update")
        || title_lower.contains("end of life") {
        mappings.push(("A.8.8".to_string(), Severity::High));
        mappings.push(("A.8.9".to_string(), Severity::Medium));
    }

    // Logging/Monitoring
    if title_lower.contains("logging") || title_lower.contains("monitoring") || title_lower.contains("audit") {
        mappings.push(("A.8.15".to_string(), Severity::Medium));
        mappings.push(("A.8.16".to_string(), Severity::Medium));
    }

    // Backup/Recovery
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("A.8.13".to_string(), Severity::High));
        mappings.push(("A.8.14".to_string(), Severity::Medium));
    }

    // Network security
    if title_lower.contains("network") || title_lower.contains("firewall") || title_lower.contains("segmentation") {
        mappings.push(("A.8.20".to_string(), Severity::High));
        mappings.push(("A.8.21".to_string(), Severity::High));
        mappings.push(("A.8.22".to_string(), Severity::Medium));
    }

    // Data protection/Privacy
    if title_lower.contains("pii") || title_lower.contains("privacy") || title_lower.contains("personal data") {
        mappings.push(("A.5.34".to_string(), Severity::High));
        mappings.push(("A.8.10".to_string(), Severity::Medium));
        mappings.push(("A.8.11".to_string(), Severity::Medium));
    }

    // Secure development
    if title_lower.contains("injection") || title_lower.contains("xss") || title_lower.contains("code") {
        mappings.push(("A.8.25".to_string(), Severity::High));
        mappings.push(("A.8.28".to_string(), Severity::High));
        mappings.push(("A.8.29".to_string(), Severity::High));
    }

    // Incident response
    if title_lower.contains("incident") || title_lower.contains("breach") {
        mappings.push(("A.5.24".to_string(), Severity::High));
        mappings.push(("A.5.25".to_string(), Severity::Medium));
        mappings.push(("A.5.26".to_string(), Severity::High));
    }

    // Default - map to general access control
    if mappings.is_empty() {
        mappings.push(("A.5.15".to_string(), Severity::Medium));
    }

    mappings
}

/// Map a vulnerability to relevant ISO 27001 controls (control IDs only)
pub fn map_vulnerability_to_controls(vuln_type: &str) -> Vec<String> {
    match vuln_type.to_lowercase().as_str() {
        "authentication" | "password" | "mfa" => vec![
            "A.5.16".to_string(),
            "A.5.17".to_string(),
            "A.8.5".to_string(),
        ],
        "access_control" | "authorization" => vec![
            "A.5.15".to_string(),
            "A.5.18".to_string(),
            "A.8.2".to_string(),
            "A.8.3".to_string(),
        ],
        "encryption" | "cryptography" | "tls" | "ssl" => vec![
            "A.5.14".to_string(),
            "A.8.24".to_string(),
        ],
        "malware" | "virus" | "ransomware" => vec![
            "A.8.7".to_string(),
        ],
        "vulnerability" | "patching" | "update" => vec![
            "A.8.8".to_string(),
            "A.8.9".to_string(),
        ],
        "logging" | "monitoring" | "audit" => vec![
            "A.8.15".to_string(),
            "A.8.16".to_string(),
        ],
        "backup" | "recovery" => vec![
            "A.8.13".to_string(),
            "A.8.14".to_string(),
        ],
        "network" | "firewall" | "segmentation" => vec![
            "A.8.20".to_string(),
            "A.8.21".to_string(),
            "A.8.22".to_string(),
        ],
        "data_protection" | "pii" | "privacy" => vec![
            "A.5.34".to_string(),
            "A.8.10".to_string(),
            "A.8.11".to_string(),
        ],
        "secure_development" | "sdlc" | "code" => vec![
            "A.8.25".to_string(),
            "A.8.26".to_string(),
            "A.8.28".to_string(),
            "A.8.29".to_string(),
        ],
        "incident" | "breach" => vec![
            "A.5.24".to_string(),
            "A.5.25".to_string(),
            "A.5.26".to_string(),
        ],
        "supplier" | "third_party" | "vendor" => vec![
            "A.5.19".to_string(),
            "A.5.20".to_string(),
            "A.5.21".to_string(),
        ],
        _ => vec!["A.5.15".to_string()],
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
        let controls = map_vulnerability_to_controls("authentication");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"A.5.17".to_string()));
    }
}
