//! International Traffic in Arms Regulations (ITAR) Compliance Framework
//!
//! ITAR (22 CFR Parts 120-130) regulates the export and temporary import of
//! defense articles and services on the United States Munitions List (USML).
//! Organizations handling ITAR-controlled technical data must implement
//! comprehensive security controls.
//!
//! Key ITAR requirements covered:
//! - Access control for technical data (22 CFR 120.10, 120.11)
//! - Foreign person restrictions (22 CFR 120.16)
//! - Export authorization and licensing (22 CFR 123, 124, 125)
//! - Secure storage and transmission (22 CFR 120.17)
//! - Audit and recordkeeping (22 CFR 122.5, 123.22)
//! - Training requirements (22 CFR 120.10(a)(5))
//!
//! Control Categories:
//! - Access Control: Technical data access restrictions
//! - Personnel Security: Foreign person screening and restrictions
//! - Export Control: Licensing and authorization management
//! - Data Protection: Secure storage, transmission, and marking
//! - Audit & Records: Recordkeeping and compliance documentation
//! - Training & Awareness: ITAR compliance training programs

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of ITAR controls in this module
pub const CONTROL_COUNT: usize = 30;

/// Get all ITAR compliance controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    controls.extend(get_access_control_controls());
    controls.extend(get_personnel_security_controls());
    controls.extend(get_export_control_controls());
    controls.extend(get_data_protection_controls());
    controls.extend(get_audit_records_controls());
    controls.extend(get_training_awareness_controls());

    controls
}

/// Access control for technical data (22 CFR 120.10, 120.11)
fn get_access_control_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ITAR-AC-001".to_string(),
            control_id: "22CFR120.10-AC1".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Technical data access must be restricted to authorized US persons".to_string(),
            description: "Access to ITAR-controlled technical data must be limited to US persons \
                (US citizens, lawful permanent residents, or protected individuals) with a \
                legitimate need-to-know. Access control systems must verify citizenship/residency \
                status before granting access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-2".to_string(),
                "NIST-AC-3".to_string(),
                "CMMC-AC.L2-3.1.1".to_string(),
            ],
            remediation_guidance: Some(
                "Implement role-based access control (RBAC) with citizenship verification. \
                Configure identity management systems to validate US person status before \
                granting access to ITAR-controlled data repositories.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AC-002".to_string(),
            control_id: "22CFR120.10-AC2".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Need-to-know access enforcement for defense articles".to_string(),
            description: "Access to ITAR-controlled information must be granted only to \
                individuals who require the information to perform their job duties. \
                Need-to-know determinations must be documented and periodically reviewed.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-6".to_string(),
                "CMMC-AC.L2-3.1.5".to_string(),
            ],
            remediation_guidance: Some(
                "Establish formal need-to-know authorization procedures. Document access \
                justifications and implement quarterly access reviews for all ITAR data repositories.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AC-003".to_string(),
            control_id: "22CFR120.10-AC3".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Multi-factor authentication for ITAR data systems".to_string(),
            description: "Systems containing ITAR-controlled technical data must require \
                multi-factor authentication (MFA) for all user access. MFA must use at \
                least two of: something you know, something you have, something you are.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-IA-2".to_string(),
                "CMMC-IA.L2-3.5.3".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy hardware tokens, smart cards, or authenticator apps as second factor. \
                Configure all ITAR systems to require MFA. Disable single-factor authentication.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AC-004".to_string(),
            control_id: "22CFR120.10-AC4".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Physical access controls for ITAR facilities".to_string(),
            description: "Physical locations containing ITAR-controlled materials must have \
                access controls including badge readers, visitor logs, and escort requirements \
                for non-authorized personnel. Foreign nationals must be escorted at all times.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PE-2".to_string(),
                "NIST-PE-3".to_string(),
                "CMMC-PE.L2-3.10.1".to_string(),
            ],
            remediation_guidance: Some(
                "Implement badge-controlled access to ITAR areas. Maintain visitor logs with \
                citizenship status. Train personnel on escort requirements for foreign visitors.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AC-005".to_string(),
            control_id: "22CFR120.10-AC5".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Privileged access management for ITAR systems".to_string(),
            description: "Administrative and privileged access to systems containing ITAR data \
                must be strictly controlled and monitored. Privileged accounts must use \
                separate credentials and enhanced authentication.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-6".to_string(),
                "CMMC-AC.L2-3.1.7".to_string(),
            ],
            remediation_guidance: Some(
                "Implement privileged access management (PAM) solution. Use just-in-time \
                privileged access. Monitor and audit all privileged sessions.".to_string()
            ),
        },
    ]
}

/// Personnel security and foreign person restrictions (22 CFR 120.16)
fn get_personnel_security_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ITAR-PS-001".to_string(),
            control_id: "22CFR120.16-PS1".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Foreign person identification and screening".to_string(),
            description: "Organizations must identify and screen all personnel to determine \
                citizenship status. Foreign persons (non-US persons) must be identified and \
                restricted from accessing ITAR-controlled technical data without proper authorization.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PS-2".to_string(),
                "NIST-PS-3".to_string(),
            ],
            remediation_guidance: Some(
                "Implement citizenship verification during hiring. Maintain current citizenship \
                records in HR systems. Flag foreign person status in access control systems.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-PS-002".to_string(),
            control_id: "22CFR120.16-PS2".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Deemed export controls for foreign national employees".to_string(),
            description: "Release of ITAR technical data to foreign nationals within the US \
                constitutes a deemed export requiring a license. Organizations must implement \
                controls to prevent unauthorized deemed exports to foreign national employees.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-3".to_string(),
                "CMMC-AC.L2-3.1.3".to_string(),
            ],
            remediation_guidance: Some(
                "Configure access controls to restrict foreign national employees from ITAR data. \
                Implement technology control plans (TCPs) for any approved foreign national access.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-PS-003".to_string(),
            control_id: "22CFR120.16-PS3".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Visitor management for foreign nationals".to_string(),
            description: "Foreign national visitors must be identified, logged, and escorted \
                when in areas containing ITAR-controlled materials. Visual and technical barriers \
                must prevent inadvertent disclosure during visits.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PE-2".to_string(),
                "NIST-PE-8".to_string(),
            ],
            remediation_guidance: Some(
                "Implement visitor registration system capturing citizenship. Require escorts for \
                all foreign visitors. Use screen privacy filters and lock workstations during visits.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-PS-004".to_string(),
            control_id: "22CFR120.16-PS4".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Personnel termination procedures for ITAR access".to_string(),
            description: "Upon termination or role change, access to ITAR-controlled data must be \
                immediately revoked. Exit procedures must include retrieval of all ITAR materials \
                and acknowledgment of continuing obligations.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-PS-4".to_string(),
                "CMMC-PS.L2-3.9.2".to_string(),
            ],
            remediation_guidance: Some(
                "Automate access revocation in identity management systems. Include ITAR-specific \
                items in termination checklists. Require signed acknowledgment of post-employment obligations.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-PS-005".to_string(),
            control_id: "22CFR120.16-PS5".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Background investigations for ITAR personnel".to_string(),
            description: "Personnel with access to ITAR-controlled technical data should undergo \
                appropriate background investigations. The depth of investigation should be \
                commensurate with the sensitivity of the data accessed.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PS-3".to_string(),
                "CMMC-PS.L2-3.9.1".to_string(),
            ],
            remediation_guidance: Some(
                "Conduct background checks for all personnel requiring ITAR access. \
                Re-investigate personnel periodically based on risk assessment.".to_string()
            ),
        },
    ]
}

/// Export authorization and licensing (22 CFR 123, 124, 125)
fn get_export_control_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ITAR-EC-001".to_string(),
            control_id: "22CFR123-EC1".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Export license verification before disclosure".to_string(),
            description: "Prior to any export or deemed export of ITAR-controlled technical data, \
                organizations must verify that a valid export license or license exemption exists. \
                Exports without proper authorization violate ITAR.".to_string(),
            category: "Export Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-4".to_string(),
            ],
            remediation_guidance: Some(
                "Implement export control review process before any foreign disclosure. \
                Maintain license database and verify authorization before each export.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-EC-002".to_string(),
            control_id: "22CFR123-EC2".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Technical Assistance Agreement (TAA) management".to_string(),
            description: "Defense services provided to foreign persons require an approved TAA. \
                Organizations must track TAA scope, parties, and expiration dates. Services must \
                not exceed TAA authorizations.".to_string(),
            category: "Export Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some(
                "Maintain TAA registry with scope and expiration tracking. Implement alerts \
                for expiring agreements. Review activities against TAA limitations.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-EC-003".to_string(),
            control_id: "22CFR125-EC3".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Electronic transmission export controls".to_string(),
            description: "Transmission of ITAR technical data via electronic means (email, file \
                transfer, cloud storage) to foreign persons or foreign countries constitutes an \
                export requiring authorization. Controls must prevent unauthorized electronic exports.".to_string(),
            category: "Export Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "NIST-SC-8".to_string(),
            ],
            remediation_guidance: Some(
                "Implement DLP to detect ITAR data in outbound communications. Block cloud \
                storage services to foreign locations. Monitor and control email to foreign addresses.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-EC-004".to_string(),
            control_id: "22CFR120-EC4".to_string(),
            framework: ComplianceFramework::Itar,
            title: "USML classification determination".to_string(),
            description: "Organizations must properly classify items against the US Munitions List \
                (USML) to determine ITAR applicability. Classification determinations must be \
                documented and maintained.".to_string(),
            category: "Export Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some(
                "Establish commodity jurisdiction and classification process. Document all \
                USML determinations. Seek DDTC commodity jurisdiction rulings when uncertain.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-EC-005".to_string(),
            control_id: "22CFR123-EC5".to_string(),
            framework: ComplianceFramework::Itar,
            title: "End-use and end-user verification".to_string(),
            description: "Before export, organizations must verify the end-use and end-user of \
                ITAR-controlled items. Red flags indicating diversion or prohibited end-users \
                must trigger additional scrutiny or export denial.".to_string(),
            category: "Export Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-4".to_string(),
            ],
            remediation_guidance: Some(
                "Screen parties against denied persons and entity lists. Document end-use \
                certifications. Implement red flag review process.".to_string()
            ),
        },
    ]
}

/// Secure storage and transmission (22 CFR 120.17)
fn get_data_protection_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ITAR-DP-001".to_string(),
            control_id: "22CFR120.17-DP1".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Encryption of ITAR technical data at rest".to_string(),
            description: "ITAR-controlled technical data stored electronically must be encrypted \
                using FIPS 140-2 validated encryption (AES-256 or equivalent). Encryption keys \
                must be managed separately from encrypted data.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-28".to_string(),
                "CMMC-SC.L2-3.13.11".to_string(),
            ],
            remediation_guidance: Some(
                "Enable full-disk encryption on all systems storing ITAR data. Encrypt \
                databases and file shares containing technical data. Use HSM for key management.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-DP-002".to_string(),
            control_id: "22CFR120.17-DP2".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Encryption of ITAR technical data in transit".to_string(),
            description: "ITAR-controlled technical data transmitted over networks must be \
                encrypted end-to-end using TLS 1.2 or higher, or equivalent encryption. \
                Unencrypted transmission of ITAR data is prohibited.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-8".to_string(),
                "CMMC-SC.L2-3.13.8".to_string(),
            ],
            remediation_guidance: Some(
                "Configure TLS 1.2+ on all systems handling ITAR data. Use VPN for remote access. \
                Implement email encryption for ITAR communications.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-DP-003".to_string(),
            control_id: "22CFR120.17-DP3".to_string(),
            framework: ComplianceFramework::Itar,
            title: "ITAR data marking and labeling".to_string(),
            description: "ITAR-controlled technical data must be marked with appropriate export \
                control warnings. Documents, files, and media must include ITAR notices indicating \
                export restrictions and authorized handling.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-16".to_string(),
            ],
            remediation_guidance: Some(
                "Implement document classification and marking tools. Add ITAR banners to \
                documents and systems. Train personnel on marking requirements.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-DP-004".to_string(),
            control_id: "22CFR120.17-DP4".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Secure media destruction for ITAR data".to_string(),
            description: "Media containing ITAR technical data must be destroyed using methods \
                that prevent reconstruction (degaussing, physical destruction, or cryptographic \
                erasure). Destruction must be documented.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-MP-6".to_string(),
                "CMMC-MP.L2-3.8.3".to_string(),
            ],
            remediation_guidance: Some(
                "Establish media destruction procedures per NIST SP 800-88. Use certified \
                destruction vendors. Maintain destruction certificates.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-DP-005".to_string(),
            control_id: "22CFR120.17-DP5".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Cloud storage restrictions for ITAR data".to_string(),
            description: "ITAR technical data stored in cloud environments must be in US-based \
                data centers with access restricted to US persons. Cloud providers must meet \
                ITAR security requirements and may require export authorization.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-4".to_string(),
                "NIST-SC-7".to_string(),
            ],
            remediation_guidance: Some(
                "Use ITAR-compliant cloud services (AWS GovCloud, Azure Government). \
                Verify data residency is US-only. Confirm provider employee access restrictions.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-DP-006".to_string(),
            control_id: "22CFR120.17-DP6".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Data loss prevention for ITAR technical data".to_string(),
            description: "Organizations must implement data loss prevention (DLP) controls to \
                detect and prevent unauthorized disclosure of ITAR-controlled technical data \
                through email, web uploads, removable media, and other channels.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-4".to_string(),
                "NIST-SC-7".to_string(),
            ],
            remediation_guidance: Some(
                "Deploy DLP solution with ITAR-specific content rules. Monitor network egress \
                points. Block or quarantine potential ITAR disclosures for review.".to_string()
            ),
        },
    ]
}

/// Audit and recordkeeping (22 CFR 122.5, 123.22)
fn get_audit_records_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ITAR-AR-001".to_string(),
            control_id: "22CFR122.5-AR1".to_string(),
            framework: ComplianceFramework::Itar,
            title: "ITAR transaction records retention".to_string(),
            description: "Records of ITAR-controlled exports, including licenses, agreements, \
                shipping documents, and correspondence, must be retained for a minimum of five \
                years from date of export or termination of agreement.".to_string(),
            category: "Audit & Records".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-11".to_string(),
            ],
            remediation_guidance: Some(
                "Implement document retention system for export records. Configure 5-year \
                minimum retention. Protect records from modification or deletion.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AR-002".to_string(),
            control_id: "22CFR122.5-AR2".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Access logging for ITAR systems".to_string(),
            description: "All access to systems containing ITAR-controlled technical data must \
                be logged. Logs must include user identity, timestamp, data accessed, and actions \
                performed. Logs must be protected from tampering.".to_string(),
            category: "Audit & Records".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-2".to_string(),
                "NIST-AU-3".to_string(),
                "CMMC-AU.L2-3.3.1".to_string(),
            ],
            remediation_guidance: Some(
                "Enable comprehensive audit logging on all ITAR systems. Forward logs to \
                centralized SIEM. Implement log integrity monitoring.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AR-003".to_string(),
            control_id: "22CFR122.5-AR3".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Audit log review for ITAR compliance".to_string(),
            description: "Audit logs of ITAR system access must be reviewed regularly to detect \
                unauthorized access, policy violations, or indicators of compromise. Review \
                findings must be documented and acted upon.".to_string(),
            category: "Audit & Records".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-6".to_string(),
                "CMMC-AU.L2-3.3.5".to_string(),
            ],
            remediation_guidance: Some(
                "Establish weekly log review procedures. Configure automated alerts for \
                suspicious activity. Document review activities and findings.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AR-004".to_string(),
            control_id: "22CFR123.22-AR4".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Annual self-assessment of ITAR compliance".to_string(),
            description: "Organizations must conduct annual self-assessments of their ITAR \
                compliance program effectiveness. Assessments must evaluate controls, identify \
                gaps, and track remediation.".to_string(),
            category: "Audit & Records".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-2".to_string(),
                "CMMC-CA.L2-3.12.1".to_string(),
            ],
            remediation_guidance: Some(
                "Develop ITAR compliance assessment checklist. Conduct annual assessments. \
                Create remediation plans for identified gaps. Track to closure.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-AR-005".to_string(),
            control_id: "22CFR127.1-AR5".to_string(),
            framework: ComplianceFramework::Itar,
            title: "ITAR violation reporting to DDTC".to_string(),
            description: "Known or suspected violations of ITAR must be voluntarily disclosed to \
                the Directorate of Defense Trade Controls (DDTC). Organizations must have \
                procedures for identifying, investigating, and reporting violations.".to_string(),
            category: "Audit & Records".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-6".to_string(),
            ],
            remediation_guidance: Some(
                "Establish violation reporting procedures. Train personnel to recognize \
                potential violations. Document investigation and disclosure processes.".to_string()
            ),
        },
    ]
}

/// Training and awareness requirements (22 CFR 120.10(a)(5))
fn get_training_awareness_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "ITAR-TA-001".to_string(),
            control_id: "22CFR120.10-TA1".to_string(),
            framework: ComplianceFramework::Itar,
            title: "ITAR awareness training for all employees".to_string(),
            description: "All employees must receive basic ITAR awareness training covering \
                export control concepts, their responsibilities, and consequences of violations. \
                Training must be provided upon hire and annually thereafter.".to_string(),
            category: "Training & Awareness".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AT-2".to_string(),
                "CMMC-AT.L2-3.2.1".to_string(),
            ],
            remediation_guidance: Some(
                "Develop ITAR awareness training program. Track completion. Require annual \
                refresher training. Include in new employee onboarding.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-TA-002".to_string(),
            control_id: "22CFR120.10-TA2".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Role-specific ITAR training for technical staff".to_string(),
            description: "Technical staff with access to ITAR-controlled data must receive \
                role-specific training on handling requirements, marking, transmission controls, \
                and reporting procedures for their specific job functions.".to_string(),
            category: "Training & Awareness".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AT-3".to_string(),
                "CMMC-AT.L2-3.2.2".to_string(),
            ],
            remediation_guidance: Some(
                "Develop role-specific training modules. Train technical staff before granting \
                ITAR access. Include practical exercises on data handling.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-TA-003".to_string(),
            control_id: "22CFR120.10-TA3".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Empowered Official designation and training".to_string(),
            description: "Organizations must designate qualified Empowered Officials to sign \
                export license applications and agreements. Empowered Officials must receive \
                comprehensive training on ITAR requirements and their legal responsibilities.".to_string(),
            category: "Training & Awareness".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AT-3".to_string(),
            ],
            remediation_guidance: Some(
                "Designate qualified Empowered Officials. Provide specialized training on \
                ITAR licensing. Document designation and maintain training records.".to_string()
            ),
        },
        ComplianceControl {
            id: "ITAR-TA-004".to_string(),
            control_id: "22CFR120.10-TA4".to_string(),
            framework: ComplianceFramework::Itar,
            title: "Training documentation and records".to_string(),
            description: "Organizations must maintain records of ITAR training including \
                attendees, dates, content covered, and assessment results. Training records \
                must be retained for the duration of employment plus five years.".to_string(),
            category: "Training & Awareness".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AT-4".to_string(),
            ],
            remediation_guidance: Some(
                "Implement training management system. Track completion and assessment scores. \
                Retain records per ITAR requirements.".to_string()
            ),
        },
    ]
}

/// Get controls by ITAR category
pub fn get_controls_by_category(category: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get all ITAR control categories
pub fn get_categories() -> Vec<&'static str> {
    vec![
        "Access Control",
        "Personnel Security",
        "Export Control",
        "Data Protection",
        "Audit & Records",
        "Training & Awareness",
    ]
}

/// Map a vulnerability to relevant ITAR controls
///
/// Returns a list of (control_id, severity) tuples for controls that are
/// impacted by the given vulnerability.
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control vulnerabilities
    if title_lower.contains("access control")
        || title_lower.contains("authorization")
        || title_lower.contains("authentication")
        || title_lower.contains("unauthorized access")
    {
        mappings.push(("22CFR120.10-AC1".to_string(), Severity::Critical));
        mappings.push(("22CFR120.10-AC2".to_string(), Severity::Critical));
        mappings.push(("22CFR120.10-AC3".to_string(), Severity::High));
    }

    // MFA and credential vulnerabilities
    if title_lower.contains("mfa")
        || title_lower.contains("multi-factor")
        || title_lower.contains("two-factor")
        || title_lower.contains("password")
        || title_lower.contains("credential")
    {
        mappings.push(("22CFR120.10-AC3".to_string(), Severity::Critical));
        mappings.push(("22CFR120.10-AC5".to_string(), Severity::High));
    }

    // Encryption vulnerabilities
    if title_lower.contains("encrypt")
        || title_lower.contains("tls")
        || title_lower.contains("ssl")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted")
        || title_lower.contains("weak cipher")
    {
        mappings.push(("22CFR120.17-DP1".to_string(), Severity::Critical));
        mappings.push(("22CFR120.17-DP2".to_string(), Severity::Critical));
    }

    // Data leakage and DLP
    if title_lower.contains("data leak")
        || title_lower.contains("information disclosure")
        || title_lower.contains("data exposure")
        || title_lower.contains("sensitive data")
    {
        mappings.push(("22CFR120.17-DP6".to_string(), Severity::Critical));
        mappings.push(("22CFR125-EC3".to_string(), Severity::Critical));
    }

    // Cloud security
    if title_lower.contains("cloud")
        || title_lower.contains("s3")
        || title_lower.contains("azure")
        || title_lower.contains("aws")
        || title_lower.contains("bucket")
        || title_lower.contains("storage")
    {
        mappings.push(("22CFR120.17-DP5".to_string(), Severity::Critical));
    }

    // Logging and audit
    if title_lower.contains("audit")
        || title_lower.contains("logging")
        || title_lower.contains("log")
        || title_lower.contains("monitoring")
    {
        mappings.push(("22CFR122.5-AR2".to_string(), Severity::High));
        mappings.push(("22CFR122.5-AR3".to_string(), Severity::Medium));
    }

    // Physical security
    if title_lower.contains("physical")
        || title_lower.contains("badge")
        || title_lower.contains("facility")
    {
        mappings.push(("22CFR120.10-AC4".to_string(), Severity::High));
    }

    // Session and privilege management
    if title_lower.contains("session")
        || title_lower.contains("privilege")
        || title_lower.contains("admin")
        || title_lower.contains("escalation")
    {
        mappings.push(("22CFR120.10-AC5".to_string(), Severity::High));
    }

    // Insider threat / personnel
    if title_lower.contains("insider")
        || title_lower.contains("employee")
        || title_lower.contains("personnel")
    {
        mappings.push(("22CFR120.16-PS1".to_string(), Severity::High));
        mappings.push(("22CFR120.16-PS4".to_string(), Severity::High));
    }

    // Media and destruction
    if title_lower.contains("media")
        || title_lower.contains("destruction")
        || title_lower.contains("disposal")
        || title_lower.contains("sanitization")
    {
        mappings.push(("22CFR120.17-DP4".to_string(), Severity::High));
    }

    // Training gaps
    if title_lower.contains("training")
        || title_lower.contains("awareness")
        || title_lower.contains("human")
    {
        mappings.push(("22CFR120.10-TA1".to_string(), Severity::Medium));
        mappings.push(("22CFR120.10-TA2".to_string(), Severity::Medium));
    }

    // Export control specific
    if title_lower.contains("export")
        || title_lower.contains("foreign")
        || title_lower.contains("international")
        || title_lower.contains("transfer")
    {
        mappings.push(("22CFR123-EC1".to_string(), Severity::Critical));
        mappings.push(("22CFR125-EC3".to_string(), Severity::Critical));
        mappings.push(("22CFR123-EC5".to_string(), Severity::High));
    }

    // Marking and labeling
    if title_lower.contains("marking")
        || title_lower.contains("label")
        || title_lower.contains("classification")
    {
        mappings.push(("22CFR120.17-DP3".to_string(), Severity::High));
    }

    mappings
}

/// Map vulnerability to control IDs (simplified interface)
pub fn map_vulnerability_to_controls(vuln_title: &str, vuln_description: &str) -> Vec<String> {
    let combined = format!("{} {}", vuln_title, vuln_description).to_lowercase();
    let mut matched_controls = Vec::new();

    // Access control
    if combined.contains("access") || combined.contains("authorization") || combined.contains("authentication") {
        matched_controls.extend(vec![
            "22CFR120.10-AC1", "22CFR120.10-AC2", "22CFR120.10-AC3",
        ]);
    }

    // Encryption
    if combined.contains("encrypt") || combined.contains("tls") || combined.contains("ssl") || combined.contains("plaintext") {
        matched_controls.extend(vec!["22CFR120.17-DP1", "22CFR120.17-DP2"]);
    }

    // Data protection
    if combined.contains("data") || combined.contains("leak") || combined.contains("disclosure") {
        matched_controls.extend(vec!["22CFR120.17-DP6", "22CFR125-EC3"]);
    }

    // Cloud
    if combined.contains("cloud") || combined.contains("s3") || combined.contains("bucket") || combined.contains("aws") {
        matched_controls.push("22CFR120.17-DP5");
    }

    // Audit
    if combined.contains("audit") || combined.contains("log") {
        matched_controls.extend(vec!["22CFR122.5-AR2", "22CFR122.5-AR3"]);
    }

    // Export
    if combined.contains("export") || combined.contains("foreign") || combined.contains("transfer") {
        matched_controls.extend(vec!["22CFR123-EC1", "22CFR125-EC3"]);
    }

    matched_controls.sort();
    matched_controls.dedup();
    matched_controls.into_iter().map(String::from).collect()
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
            assert!(!control.id.is_empty(), "Control missing ID");
            assert!(!control.control_id.is_empty(), "Control missing control_id");
            assert!(!control.title.is_empty(), "Control missing title");
            assert!(!control.description.is_empty(), "Control missing description");
            assert!(!control.category.is_empty(), "Control missing category");
            assert_eq!(control.framework, ComplianceFramework::Itar);
        }
    }

    #[test]
    fn test_categories() {
        let categories = get_categories();
        assert_eq!(categories.len(), 6);
        assert!(categories.contains(&"Access Control"));
        assert!(categories.contains(&"Personnel Security"));
        assert!(categories.contains(&"Export Control"));
        assert!(categories.contains(&"Data Protection"));
        assert!(categories.contains(&"Audit & Records"));
        assert!(categories.contains(&"Training & Awareness"));
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("Weak encryption in transit", None, None, None);
        assert!(!mappings.is_empty());

        let control_ids: Vec<&str> = mappings.iter().map(|(id, _)| id.as_str()).collect();
        assert!(control_ids.contains(&"22CFR120.17-DP1") || control_ids.contains(&"22CFR120.17-DP2"));
    }

    #[test]
    fn test_vulnerability_to_controls_mapping() {
        let controls = map_vulnerability_to_controls(
            "Unauthorized access to restricted data",
            "System allows access without proper authentication"
        );
        assert!(!controls.is_empty());
    }

    #[test]
    fn test_controls_by_category() {
        let access_controls = get_controls_by_category("Access Control");
        assert_eq!(access_controls.len(), 5);

        let dp_controls = get_controls_by_category("Data Protection");
        assert_eq!(dp_controls.len(), 6);
    }

    #[test]
    fn test_export_control_mappings() {
        let mappings = map_vulnerability("Foreign data transfer detected", None, None, None);
        let control_ids: Vec<&str> = mappings.iter().map(|(id, _)| id.as_str()).collect();
        assert!(control_ids.contains(&"22CFR123-EC1") || control_ids.contains(&"22CFR125-EC3"));
    }
}
