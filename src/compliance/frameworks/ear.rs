//! EAR (Export Administration Regulations) Controls
//!
//! Export Administration Regulations (15 CFR Parts 730-774) requirements for
//! controlling the export, reexport, and transfer of dual-use items, technology,
//! and software that have both commercial and military/proliferation applications.
//!
//! Key EAR requirements covered:
//! - Classification of items (ECCN determination)
//! - License requirements and exceptions
//! - Deemed exports and technology transfer controls
//! - End-user and end-use screening
//! - Recordkeeping requirements
//! - Compliance program elements

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of EAR controls in this module
pub const CONTROL_COUNT: usize = 25;

/// Get all EAR controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============ Classification Controls (ECCN) ============
        ComplianceControl {
            id: "EAR-CL-1".to_string(),
            control_id: "CL-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "ECCN Classification Program".to_string(),
            description: "Establish a formal program to classify items, technology, and software according to Export Control Classification Numbers (ECCNs) in the Commerce Control List (CCL).".to_string(),
            category: "Classification".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ITAR-CL-1".to_string()],
            remediation_guidance: Some("Develop ECCN classification procedures with qualified personnel or external classification services.".to_string()),
        },
        ComplianceControl {
            id: "EAR-CL-2".to_string(),
            control_id: "CL-2".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Self-Classification Documentation".to_string(),
            description: "Document self-classification determinations with supporting technical analysis and maintain records of classification rationale.".to_string(),
            category: "Classification".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-CL-1".to_string()),
            cross_references: vec!["EAR-RK-1".to_string()],
            remediation_guidance: Some("Create standardized classification worksheets documenting technical parameters and ECCN determination logic.".to_string()),
        },
        ComplianceControl {
            id: "EAR-CL-3".to_string(),
            control_id: "CL-3".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Technology and Source Code Classification".to_string(),
            description: "Classify technology (technical data) and source code separately from hardware, applying appropriate ECCN entries for development, production, and use technology.".to_string(),
            category: "Classification".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-CL-1".to_string()),
            cross_references: vec!["EAR-TT-1".to_string()],
            remediation_guidance: Some("Maintain separate classification records for technology and source code with clear mapping to associated hardware ECCNs.".to_string()),
        },
        ComplianceControl {
            id: "EAR-CL-4".to_string(),
            control_id: "CL-4".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Classification Review Process".to_string(),
            description: "Implement periodic review of existing classifications to ensure accuracy when products are modified or regulations change.".to_string(),
            category: "Classification".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("EAR-CL-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Establish annual classification review schedule and triggers for re-classification on product changes.".to_string()),
        },

        // ============ License Determination Controls ============
        ComplianceControl {
            id: "EAR-LD-1".to_string(),
            control_id: "LD-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "License Requirement Determination".to_string(),
            description: "Determine license requirements by analyzing ECCN, destination country, end-user, and end-use against Country Chart and General Prohibitions.".to_string(),
            category: "Licensing".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["EAR-CL-1".to_string()],
            remediation_guidance: Some("Implement systematic license determination process using Country Chart cross-references and reason-for-control analysis.".to_string()),
        },
        ComplianceControl {
            id: "EAR-LD-2".to_string(),
            control_id: "LD-2".to_string(),
            framework: ComplianceFramework::Ear,
            title: "License Exception Eligibility".to_string(),
            description: "Evaluate eligibility for license exceptions (e.g., TMP, RPL, TSR, ENC) and document compliance with exception conditions.".to_string(),
            category: "Licensing".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-LD-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Create license exception eligibility checklists for commonly used exceptions with required conditions.".to_string()),
        },
        ComplianceControl {
            id: "EAR-LD-3".to_string(),
            control_id: "LD-3".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Encryption Controls (ENC)".to_string(),
            description: "Comply with encryption-specific controls including classification review requirements, reporting obligations, and License Exception ENC conditions.".to_string(),
            category: "Licensing".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("EAR-LD-1".to_string()),
            cross_references: vec!["NIST-SC-13".to_string()],
            remediation_guidance: Some("Submit encryption classification reviews (ECCN 5D002/5A002) to BIS as required and maintain encryption product records.".to_string()),
        },
        ComplianceControl {
            id: "EAR-LD-4".to_string(),
            control_id: "LD-4".to_string(),
            framework: ComplianceFramework::Ear,
            title: "License Application Process".to_string(),
            description: "Maintain documented procedures for preparing and submitting export license applications when required.".to_string(),
            category: "Licensing".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-LD-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Document license application workflow including internal approvals, BIS submission procedures, and license tracking.".to_string()),
        },

        // ============ Deemed Export Controls ============
        ComplianceControl {
            id: "EAR-DE-1".to_string(),
            control_id: "DE-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Deemed Export Policy".to_string(),
            description: "Establish policies to control deemed exports - release of controlled technology or source code to foreign nationals within the United States.".to_string(),
            category: "Deemed Exports".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["EAR-TT-1".to_string()],
            remediation_guidance: Some("Develop deemed export policy addressing foreign national access to controlled technology and required licensing.".to_string()),
        },
        ComplianceControl {
            id: "EAR-DE-2".to_string(),
            control_id: "DE-2".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Foreign National Identification".to_string(),
            description: "Identify and track foreign national employees, contractors, and visitors who may require deemed export licenses.".to_string(),
            category: "Deemed Exports".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-DE-1".to_string()),
            cross_references: vec!["ITAR-DE-2".to_string()],
            remediation_guidance: Some("Coordinate with HR to identify foreign national status and maintain current records of citizenship/immigration status.".to_string()),
        },
        ComplianceControl {
            id: "EAR-DE-3".to_string(),
            control_id: "DE-3".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Technology Access Controls".to_string(),
            description: "Implement access controls to prevent unauthorized release of controlled technology to foreign nationals without proper authorization.".to_string(),
            category: "Deemed Exports".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("EAR-DE-1".to_string()),
            cross_references: vec!["NIST-AC-3".to_string(), "NIST-AC-6".to_string()],
            remediation_guidance: Some("Implement role-based access controls restricting foreign national access to controlled technology based on license status.".to_string()),
        },
        ComplianceControl {
            id: "EAR-DE-4".to_string(),
            control_id: "DE-4".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Deemed Export Licensing".to_string(),
            description: "Obtain deemed export licenses when required before releasing controlled technology to foreign nationals from countries requiring a license.".to_string(),
            category: "Deemed Exports".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: Some("EAR-DE-1".to_string()),
            cross_references: vec!["EAR-LD-1".to_string()],
            remediation_guidance: Some("Integrate deemed export license requirements into onboarding process for foreign national employees.".to_string()),
        },

        // ============ End-User Screening Controls ============
        ComplianceControl {
            id: "EAR-EU-1".to_string(),
            control_id: "EU-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Denied Party Screening".to_string(),
            description: "Screen all parties to transactions against BIS denied persons lists, Entity List, Unverified List, and other restricted party lists.".to_string(),
            category: "End-User Screening".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ITAR-EU-1".to_string()],
            remediation_guidance: Some("Implement automated screening against consolidated screening list with documented escalation procedures for potential matches.".to_string()),
        },
        ComplianceControl {
            id: "EAR-EU-2".to_string(),
            control_id: "EU-2".to_string(),
            framework: ComplianceFramework::Ear,
            title: "End-Use Verification".to_string(),
            description: "Verify the stated end-use of items and refuse transactions when there is knowledge or reason to know of prohibited end-uses.".to_string(),
            category: "End-User Screening".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-EU-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Document end-use statements from customers and implement red flag review procedures.".to_string()),
        },
        ComplianceControl {
            id: "EAR-EU-3".to_string(),
            control_id: "EU-3".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Red Flag Recognition".to_string(),
            description: "Train personnel to recognize red flags indicating potential diversion or prohibited end-uses, and implement escalation procedures.".to_string(),
            category: "End-User Screening".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-EU-1".to_string()),
            cross_references: vec!["EAR-TR-1".to_string()],
            remediation_guidance: Some("Develop red flag indicator training materials and document recognition/escalation procedures.".to_string()),
        },
        ComplianceControl {
            id: "EAR-EU-4".to_string(),
            control_id: "EU-4".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Customer Due Diligence".to_string(),
            description: "Conduct appropriate due diligence on new customers and periodic reviews of existing customers based on risk factors.".to_string(),
            category: "End-User Screening".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("EAR-EU-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Implement risk-based customer due diligence procedures with enhanced scrutiny for high-risk destinations.".to_string()),
        },

        // ============ Technology Transfer Controls ============
        ComplianceControl {
            id: "EAR-TT-1".to_string(),
            control_id: "TT-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Technology Transfer Policy".to_string(),
            description: "Establish policies controlling the transfer of controlled technology, technical data, and source code via any means including electronic transmission.".to_string(),
            category: "Technology Transfer".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["EAR-DE-1".to_string(), "ITAR-TT-1".to_string()],
            remediation_guidance: Some("Document technology transfer procedures covering all transmission methods including cloud storage and collaboration tools.".to_string()),
        },
        ComplianceControl {
            id: "EAR-TT-2".to_string(),
            control_id: "TT-2".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Electronic Transmission Controls".to_string(),
            description: "Control electronic transmission of controlled technology including email, cloud storage, remote access, and collaboration platforms.".to_string(),
            category: "Technology Transfer".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("EAR-TT-1".to_string()),
            cross_references: vec!["NIST-SC-8".to_string(), "NIST-SC-28".to_string()],
            remediation_guidance: Some("Implement data loss prevention controls for controlled technology and restrict cloud storage to approved platforms.".to_string()),
        },
        ComplianceControl {
            id: "EAR-TT-3".to_string(),
            control_id: "TT-3".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Technology Marking and Labeling".to_string(),
            description: "Mark or label controlled technology with export control classification and handling restrictions.".to_string(),
            category: "Technology Transfer".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("EAR-TT-1".to_string()),
            cross_references: vec!["ITAR-TT-3".to_string()],
            remediation_guidance: Some("Implement technology marking procedures indicating ECCN, export restrictions, and handling requirements.".to_string()),
        },

        // ============ Recordkeeping Controls ============
        ComplianceControl {
            id: "EAR-RK-1".to_string(),
            control_id: "RK-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Export Records Retention".to_string(),
            description: "Maintain records of all exports, reexports, and transfers for minimum 5 years from date of export or last act related to the transaction.".to_string(),
            category: "Recordkeeping".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ITAR-RK-1".to_string()],
            remediation_guidance: Some("Implement record retention system ensuring 5-year minimum retention of all export transaction documentation.".to_string()),
        },
        ComplianceControl {
            id: "EAR-RK-2".to_string(),
            control_id: "RK-2".to_string(),
            framework: ComplianceFramework::Ear,
            title: "License and Exception Documentation".to_string(),
            description: "Maintain complete records of licenses used, license exception eligibility determinations, and No License Required (NLR) justifications.".to_string(),
            category: "Recordkeeping".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-RK-1".to_string()),
            cross_references: vec!["EAR-LD-2".to_string()],
            remediation_guidance: Some("Create systematic filing of all license determinations with supporting documentation and approval records.".to_string()),
        },
        ComplianceControl {
            id: "EAR-RK-3".to_string(),
            control_id: "RK-3".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Screening Records".to_string(),
            description: "Document all denied party screening results and resolution of potential matches.".to_string(),
            category: "Recordkeeping".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("EAR-RK-1".to_string()),
            cross_references: vec!["EAR-EU-1".to_string()],
            remediation_guidance: Some("Maintain audit trail of all screening checks including date, parties screened, results, and match resolution.".to_string()),
        },

        // ============ Compliance Program Controls ============
        ComplianceControl {
            id: "EAR-CP-1".to_string(),
            control_id: "CP-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Export Compliance Program".to_string(),
            description: "Establish a formal Export Management and Compliance Program (EMCP) with management commitment, risk assessment, and internal controls.".to_string(),
            category: "Compliance Program".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ITAR-CP-1".to_string()],
            remediation_guidance: Some("Develop comprehensive EMCP following BIS guidelines with executive sponsorship and dedicated compliance resources.".to_string()),
        },
        ComplianceControl {
            id: "EAR-TR-1".to_string(),
            control_id: "TR-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Export Compliance Training".to_string(),
            description: "Provide regular training on EAR requirements to personnel involved in export activities, classification, and technology access decisions.".to_string(),
            category: "Compliance Program".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("EAR-CP-1".to_string()),
            cross_references: vec!["NIST-AT-2".to_string()],
            remediation_guidance: Some("Implement role-based export compliance training with annual refreshers and documentation of completion.".to_string()),
        },
        ComplianceControl {
            id: "EAR-AU-1".to_string(),
            control_id: "AU-1".to_string(),
            framework: ComplianceFramework::Ear,
            title: "Internal Audits".to_string(),
            description: "Conduct periodic internal audits of export compliance program effectiveness and transaction accuracy.".to_string(),
            category: "Compliance Program".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("EAR-CP-1".to_string()),
            cross_references: vec![],
            remediation_guidance: Some("Establish annual audit schedule covering classification accuracy, screening completeness, and recordkeeping compliance.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant EAR controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control issues - map to technology access controls
    if title_lower.contains("unauthorized access")
        || title_lower.contains("authentication bypass")
        || title_lower.contains("privilege escalation")
    {
        mappings.push(("EAR-DE-3".to_string(), Severity::Critical));
        mappings.push(("EAR-TT-1".to_string(), Severity::High));
    }

    // Authentication and authorization issues
    if title_lower.contains("authentication")
        || title_lower.contains("authorization")
        || title_lower.contains("rbac")
        || title_lower.contains("access control")
    {
        mappings.push(("EAR-DE-3".to_string(), Severity::High));
    }

    // Encryption and cryptography issues - map to encryption controls
    if title_lower.contains("encryption")
        || title_lower.contains("cryptograph")
        || title_lower.contains("cipher")
        || title_lower.contains("crypto")
    {
        mappings.push(("EAR-LD-3".to_string(), Severity::High));
        mappings.push(("EAR-CL-3".to_string(), Severity::Medium));
    }

    // Data transmission and transfer issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("data transfer")
        || title_lower.contains("data transmission")
    {
        mappings.push(("EAR-TT-2".to_string(), Severity::High));
    }

    // Cloud and electronic transmission issues
    if title_lower.contains("cloud")
        || title_lower.contains("remote access")
        || title_lower.contains("file sharing")
        || title_lower.contains("collaboration")
    {
        mappings.push(("EAR-TT-2".to_string(), Severity::Medium));
        mappings.push(("EAR-TT-1".to_string(), Severity::Medium));
    }

    // TLS/SSL issues - electronic transmission security
    if title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("certificate")
    {
        mappings.push(("EAR-TT-2".to_string(), Severity::High));
    }

    // Data exposure and leakage issues
    if title_lower.contains("data exposure")
        || title_lower.contains("information disclosure")
        || title_lower.contains("data leak")
        || title_lower.contains("sensitive data")
    {
        mappings.push(("EAR-TT-1".to_string(), Severity::Critical));
        mappings.push(("EAR-DE-3".to_string(), Severity::High));
        mappings.push(("EAR-TT-2".to_string(), Severity::High));
    }

    // Logging and audit issues - map to recordkeeping and screening
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("monitoring")
    {
        mappings.push(("EAR-RK-3".to_string(), Severity::Medium));
        mappings.push(("EAR-RK-1".to_string(), Severity::Medium));
    }

    // Screening and validation issues
    if title_lower.contains("input validation")
        || title_lower.contains("saniti")
    {
        mappings.push(("EAR-EU-1".to_string(), Severity::Medium));
    }

    // Configuration and misconfiguration issues
    if title_lower.contains("misconfigur")
        || title_lower.contains("default config")
        || title_lower.contains("insecure config")
    {
        mappings.push(("EAR-DE-3".to_string(), Severity::High));
        mappings.push(("EAR-TT-2".to_string(), Severity::Medium));
    }

    // DLP (Data Loss Prevention) issues
    if title_lower.contains("data loss")
        || title_lower.contains("dlp")
        || title_lower.contains("exfiltration")
    {
        mappings.push(("EAR-TT-2".to_string(), Severity::Critical));
        mappings.push(("EAR-TT-1".to_string(), Severity::High));
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
    fn test_all_controls_have_ear_framework() {
        let controls = get_controls();
        for control in &controls {
            assert_eq!(control.framework, ComplianceFramework::Ear);
        }
    }

    #[test]
    fn test_control_ids_unique() {
        let controls = get_controls();
        let mut ids: Vec<&String> = controls.iter().map(|c| &c.id).collect();
        ids.sort();
        let original_len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "Control IDs must be unique");
    }

    #[test]
    fn test_categories_present() {
        let controls = get_controls();
        let categories: Vec<&String> = controls.iter().map(|c| &c.category).collect();

        assert!(categories.contains(&&"Classification".to_string()));
        assert!(categories.contains(&&"Licensing".to_string()));
        assert!(categories.contains(&&"Deemed Exports".to_string()));
        assert!(categories.contains(&&"End-User Screening".to_string()));
        assert!(categories.contains(&&"Technology Transfer".to_string()));
        assert!(categories.contains(&&"Recordkeeping".to_string()));
        assert!(categories.contains(&&"Compliance Program".to_string()));
    }

    #[test]
    fn test_vulnerability_mapping_access_control() {
        let mappings = map_vulnerability("Unauthorized access to system", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "EAR-DE-3"));
    }

    #[test]
    fn test_vulnerability_mapping_encryption() {
        let mappings = map_vulnerability("Weak encryption algorithm detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "EAR-LD-3"));
    }

    #[test]
    fn test_vulnerability_mapping_data_exposure() {
        let mappings = map_vulnerability("Sensitive data exposure vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "EAR-TT-1"));
    }

    #[test]
    fn test_vulnerability_mapping_no_match() {
        let mappings = map_vulnerability("Some random unrelated issue", None, None, None);
        assert!(mappings.is_empty());
    }

    #[test]
    fn test_critical_controls_present() {
        let controls = get_controls();
        let critical_controls: Vec<&ComplianceControl> = controls
            .iter()
            .filter(|c| c.priority == ControlPriority::Critical)
            .collect();

        // Should have critical controls for key requirements
        assert!(critical_controls.len() >= 5);

        // Verify key critical controls exist
        let critical_ids: Vec<&String> = critical_controls.iter().map(|c| &c.id).collect();
        assert!(critical_ids.contains(&&"EAR-CL-1".to_string())); // Classification
        assert!(critical_ids.contains(&&"EAR-LD-1".to_string())); // License determination
        assert!(critical_ids.contains(&&"EAR-DE-1".to_string())); // Deemed export policy
        assert!(critical_ids.contains(&&"EAR-EU-1".to_string())); // Denied party screening
        assert!(critical_ids.contains(&&"EAR-RK-1".to_string())); // Records retention
    }

    #[test]
    fn test_automated_checks() {
        let controls = get_controls();
        let automated: Vec<&ComplianceControl> = controls
            .iter()
            .filter(|c| c.automated_check)
            .collect();

        // Should have some automated checks
        assert!(!automated.is_empty());

        // Verify technical controls are marked as automated
        let automated_ids: Vec<&String> = automated.iter().map(|c| &c.id).collect();
        assert!(automated_ids.contains(&&"EAR-DE-3".to_string())); // Technology access controls
        assert!(automated_ids.contains(&&"EAR-EU-1".to_string())); // Denied party screening
        assert!(automated_ids.contains(&&"EAR-TT-2".to_string())); // Electronic transmission controls
    }
}
