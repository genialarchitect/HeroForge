//! NIST Privacy Framework Controls
//!
//! This module implements controls based on the NIST Privacy Framework v1.0.
//! The framework provides a common language for understanding, managing, and
//! communicating privacy risks. It consists of five core functions:
//!
//! - Identify-P (ID-P): Inventory, Mapping, Risk Assessment
//! - Govern-P (GV-P): Policies, Roles, Awareness
//! - Control-P (CT-P): Data Processing, Disassociation
//! - Communicate-P (CM-P): Transparency, Data Processing Awareness
//! - Protect-P (PR-P): Data Protection Policies, Identity Management

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NIST Privacy Framework controls
pub const CONTROL_COUNT: usize = 47;

/// Get all NIST Privacy Framework controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // ========================================================================
    // IDENTIFY-P (ID-P) Function
    // Develop organizational understanding to manage privacy risk for
    // individuals arising from data processing.
    // ========================================================================

    // ID-P.IM: Inventory and Mapping
    controls.push(ComplianceControl {
        id: "NPF-ID-P.IM-P1".to_string(),
        control_id: "ID-P.IM-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Personal Data Inventory".to_string(),
        description: "Systems, products, or services that process personal data are inventoried.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "NIST-CSF-ID.AM-01".to_string(),
            "GDPR-Art.30".to_string(),
        ],
        remediation_guidance: Some("Maintain a comprehensive inventory of all systems processing personal data including data types, volumes, and locations.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-ID-P.IM-P2".to_string(),
        control_id: "ID-P.IM-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Processing Owners".to_string(),
        description: "Owners or operators of systems, products, or services that process personal data are identified.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.24".to_string()],
        remediation_guidance: Some("Assign data stewards and processing owners for each system containing personal data.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-ID-P.IM-P3".to_string(),
        control_id: "ID-P.IM-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Categories Identification".to_string(),
        description: "Categories of personal data and the processing associated with them are identified.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.9".to_string(),
            "NIST-CSF-ID.AM-03".to_string(),
        ],
        remediation_guidance: Some("Classify and document all categories of personal data (e.g., PII, sensitive data, special categories).".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-ID-P.IM-P4".to_string(),
        control_id: "ID-P.IM-P4".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Flow Mapping".to_string(),
        description: "Data flows are identified and mapped, including internal and external flows.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "NIST-CSF-ID.AM-03".to_string(),
            "GDPR-Art.44".to_string(),
        ],
        remediation_guidance: Some("Create and maintain data flow diagrams showing how personal data moves through systems.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-ID-P.IM-P5".to_string(),
        control_id: "ID-P.IM-P5".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Processing Purposes".to_string(),
        description: "The purposes for processing personal data are identified and documented.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5.1(b)".to_string()],
        remediation_guidance: Some("Document the specific, explicit, and legitimate purposes for each data processing activity.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-ID-P.IM-P6".to_string(),
        control_id: "ID-P.IM-P6".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Sharing Identification".to_string(),
        description: "Data sharing with third parties is identified and documented.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.28".to_string(),
            "GDPR-Art.44".to_string(),
        ],
        remediation_guidance: Some("Maintain records of all third parties with whom personal data is shared and the legal basis.".to_string()),
    });

    // ID-P.RA: Risk Assessment
    controls.push(ComplianceControl {
        id: "NPF-ID-P.RA-P1".to_string(),
        control_id: "ID-P.RA-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Risk Assessment".to_string(),
        description: "Privacy risks related to data processing are assessed.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.35".to_string(),
            "NIST-CSF-ID.RA-01".to_string(),
        ],
        remediation_guidance: Some("Conduct privacy impact assessments (PIAs) for all data processing activities.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-ID-P.RA-P2".to_string(),
        control_id: "ID-P.RA-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Risk Prioritization".to_string(),
        description: "Privacy risks are prioritized based on likelihood and impact.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CSF-ID.RA-05".to_string()],
        remediation_guidance: Some("Implement risk scoring methodology for privacy risks and maintain prioritized risk register.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-ID-P.RA-P3".to_string(),
        control_id: "ID-P.RA-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Risk Response".to_string(),
        description: "Privacy risk responses are identified and prioritized.".to_string(),
        category: "Identify-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CSF-ID.RA-06".to_string()],
        remediation_guidance: Some("Document risk treatment decisions (accept, mitigate, transfer, avoid) for each privacy risk.".to_string()),
    });

    // ========================================================================
    // GOVERN-P (GV-P) Function
    // Develop and implement the organizational governance structure to enable
    // an ongoing understanding of the organization's privacy risk management.
    // ========================================================================

    // GV-P.PO: Policies
    controls.push(ComplianceControl {
        id: "NPF-GV-P.PO-P1".to_string(),
        control_id: "GV-P.PO-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Policy".to_string(),
        description: "Organizational privacy policy is established, communicated, and enforced.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.12".to_string(),
            "NIST-CSF-GV.RM-01".to_string(),
        ],
        remediation_guidance: Some("Develop and publish comprehensive privacy policy aligned with regulatory requirements.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-GV-P.PO-P2".to_string(),
        control_id: "GV-P.PO-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Legal and Regulatory Requirements".to_string(),
        description: "Legal and regulatory requirements regarding privacy are identified and managed.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5".to_string()],
        remediation_guidance: Some("Maintain inventory of applicable privacy laws and map requirements to organizational practices.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-GV-P.PO-P3".to_string(),
        control_id: "GV-P.PO-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Processing Standards".to_string(),
        description: "Standards for data processing are established and maintained.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CSF-PR.PS-01".to_string()],
        remediation_guidance: Some("Document data handling standards including collection, use, retention, and disposal.".to_string()),
    });

    // GV-P.RO: Roles and Responsibilities
    controls.push(ComplianceControl {
        id: "NPF-GV-P.RO-P1".to_string(),
        control_id: "GV-P.RO-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Roles Assignment".to_string(),
        description: "Privacy roles and responsibilities are assigned for data processing.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.37".to_string()],
        remediation_guidance: Some("Designate privacy officer (DPO) and define roles for privacy management across organization.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-GV-P.RO-P2".to_string(),
        control_id: "GV-P.RO-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Governance Structure".to_string(),
        description: "Governance and oversight structures for privacy are established.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CSF-GV.OC-01".to_string()],
        remediation_guidance: Some("Establish privacy steering committee with executive sponsorship and defined charter.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-GV-P.RO-P3".to_string(),
        control_id: "GV-P.RO-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Third Party Accountability".to_string(),
        description: "Third-party processors are held accountable for privacy requirements.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.28".to_string(),
            "NIST-CSF-GV.SC-01".to_string(),
        ],
        remediation_guidance: Some("Execute data processing agreements with all vendors and conduct periodic compliance reviews.".to_string()),
    });

    // GV-P.AW: Awareness and Training
    controls.push(ComplianceControl {
        id: "NPF-GV-P.AW-P1".to_string(),
        control_id: "GV-P.AW-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Awareness Training".to_string(),
        description: "Privacy awareness training is provided to personnel.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CSF-PR.AT-01".to_string()],
        remediation_guidance: Some("Implement annual privacy awareness training program for all employees.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-GV-P.AW-P2".to_string(),
        control_id: "GV-P.AW-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Role-Based Privacy Training".to_string(),
        description: "Role-based privacy training is provided to personnel handling personal data.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["NIST-CSF-PR.AT-01".to_string()],
        remediation_guidance: Some("Develop specialized training for employees based on their data handling responsibilities.".to_string()),
    });

    // GV-P.MT: Monitoring and Review
    controls.push(ComplianceControl {
        id: "NPF-GV-P.MT-P1".to_string(),
        control_id: "GV-P.MT-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Program Monitoring".to_string(),
        description: "Privacy program effectiveness is monitored and reviewed.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5.2".to_string()],
        remediation_guidance: Some("Establish privacy metrics and KPIs with regular reporting to leadership.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-GV-P.MT-P2".to_string(),
        control_id: "GV-P.MT-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Compliance Auditing".to_string(),
        description: "Privacy compliance is periodically audited and assessed.".to_string(),
        category: "Govern-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5.2".to_string()],
        remediation_guidance: Some("Conduct annual privacy audits and address findings through remediation plans.".to_string()),
    });

    // ========================================================================
    // CONTROL-P (CT-P) Function
    // Develop and implement appropriate data processing management activities.
    // ========================================================================

    // CT-P.DM: Data Processing Management
    controls.push(ComplianceControl {
        id: "NPF-CT-P.DM-P1".to_string(),
        control_id: "CT-P.DM-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Minimization".to_string(),
        description: "Personal data processing is limited to what is necessary.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5.1(c)".to_string()],
        remediation_guidance: Some("Review data collection practices and eliminate unnecessary data elements.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CT-P.DM-P2".to_string(),
        control_id: "CT-P.DM-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Quality".to_string(),
        description: "Personal data is accurate, complete, and current.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5.1(d)".to_string()],
        remediation_guidance: Some("Implement data quality controls and processes for individuals to update their information.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CT-P.DM-P3".to_string(),
        control_id: "CT-P.DM-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Retention Management".to_string(),
        description: "Personal data retention periods are established and enforced.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5.1(e)".to_string()],
        remediation_guidance: Some("Define retention schedules and implement automated data deletion or anonymization.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CT-P.DM-P4".to_string(),
        control_id: "CT-P.DM-P4".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Consent Management".to_string(),
        description: "Consent is obtained, recorded, and managed for data processing.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.7".to_string()],
        remediation_guidance: Some("Implement consent management platform with granular consent tracking and withdrawal capability.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CT-P.DM-P5".to_string(),
        control_id: "CT-P.DM-P5".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Purpose Limitation Enforcement".to_string(),
        description: "Data processing is limited to specified purposes.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.5.1(b)".to_string()],
        remediation_guidance: Some("Implement technical controls to prevent data use beyond original purpose without re-consent.".to_string()),
    });

    // CT-P.DA: Disassociated Processing
    controls.push(ComplianceControl {
        id: "NPF-CT-P.DA-P1".to_string(),
        control_id: "CT-P.DA-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "De-identification".to_string(),
        description: "De-identification techniques are applied to reduce privacy risks.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-PSEUDO".to_string()],
        remediation_guidance: Some("Implement pseudonymization and anonymization for data minimization.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CT-P.DA-P2".to_string(),
        control_id: "CT-P.DA-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Aggregation Techniques".to_string(),
        description: "Data aggregation is used to reduce individual identifiability.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Apply aggregation for analytics to prevent individual identification.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CT-P.DA-P3".to_string(),
        control_id: "CT-P.DA-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Re-identification Risk Assessment".to_string(),
        description: "Re-identification risks for de-identified data are assessed.".to_string(),
        category: "Control-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec![],
        remediation_guidance: Some("Conduct re-identification risk assessments before releasing de-identified datasets.".to_string()),
    });

    // ========================================================================
    // COMMUNICATE-P (CM-P) Function
    // Develop and implement appropriate data processing communication activities.
    // ========================================================================

    // CM-P.TP: Transparency Policies
    controls.push(ComplianceControl {
        id: "NPF-CM-P.TP-P1".to_string(),
        control_id: "CM-P.TP-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Notice".to_string(),
        description: "Privacy notice is provided to individuals regarding data processing.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.12".to_string(),
            "GDPR-Art.13".to_string(),
        ],
        remediation_guidance: Some("Publish clear, accessible privacy notice covering all required information elements.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CM-P.TP-P2".to_string(),
        control_id: "CM-P.TP-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Just-in-Time Notification".to_string(),
        description: "Just-in-time notices are provided at the point of data collection.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.13".to_string()],
        remediation_guidance: Some("Implement contextual privacy notices at each data collection point.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CM-P.TP-P3".to_string(),
        control_id: "CM-P.TP-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Notice Updates".to_string(),
        description: "Privacy notices are updated to reflect changes in data processing.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: false,
        parent_id: None,
        cross_references: vec!["GDPR-Art.12".to_string()],
        remediation_guidance: Some("Implement change management process for privacy notice updates with notification to individuals.".to_string()),
    });

    // CM-P.DPA: Data Processing Awareness
    controls.push(ComplianceControl {
        id: "NPF-CM-P.DPA-P1".to_string(),
        control_id: "CM-P.DPA-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Individual Access Mechanism".to_string(),
        description: "Individuals can access their personal data.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.15".to_string()],
        remediation_guidance: Some("Implement self-service portal or defined process for data subject access requests.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CM-P.DPA-P2".to_string(),
        control_id: "CM-P.DPA-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Correction Mechanism".to_string(),
        description: "Individuals can request correction of their personal data.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.16".to_string()],
        remediation_guidance: Some("Provide mechanism for individuals to correct inaccurate personal data.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CM-P.DPA-P3".to_string(),
        control_id: "CM-P.DPA-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Deletion Mechanism".to_string(),
        description: "Individuals can request deletion of their personal data.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.17".to_string()],
        remediation_guidance: Some("Implement data deletion request process with defined timelines.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CM-P.DPA-P4".to_string(),
        control_id: "CM-P.DPA-P4".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Portability".to_string(),
        description: "Individuals can obtain their personal data in a portable format.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.20".to_string()],
        remediation_guidance: Some("Provide data export capability in machine-readable format (JSON, CSV, XML).".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CM-P.DPA-P5".to_string(),
        control_id: "CM-P.DPA-P5".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Processing Restriction".to_string(),
        description: "Individuals can request restriction of data processing.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.18".to_string()],
        remediation_guidance: Some("Implement capability to flag and restrict processing of specific individual records.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-CM-P.DPA-P6".to_string(),
        control_id: "CM-P.DPA-P6".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Objection Mechanism".to_string(),
        description: "Individuals can object to certain types of data processing.".to_string(),
        category: "Communicate-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.21".to_string()],
        remediation_guidance: Some("Provide mechanism for individuals to opt-out of specific processing activities.".to_string()),
    });

    // ========================================================================
    // PROTECT-P (PR-P) Function
    // Develop and implement appropriate data protection activities.
    // ========================================================================

    // PR-P.DP: Data Protection Policies
    controls.push(ComplianceControl {
        id: "NPF-PR-P.DP-P1".to_string(),
        control_id: "PR-P.DP-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Encryption at Rest".to_string(),
        description: "Personal data at rest is encrypted.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "NIST-CSF-PR.DS-01".to_string(),
            "GDPR-Art.32".to_string(),
        ],
        remediation_guidance: Some("Implement AES-256 encryption for all personal data at rest.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-PR-P.DP-P2".to_string(),
        control_id: "PR-P.DP-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Encryption in Transit".to_string(),
        description: "Personal data in transit is encrypted.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "NIST-CSF-PR.DS-02".to_string(),
            "GDPR-Art.32".to_string(),
        ],
        remediation_guidance: Some("Use TLS 1.2+ for all transmissions of personal data.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-PR-P.DP-P3".to_string(),
        control_id: "PR-P.DP-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Secure Deletion".to_string(),
        description: "Personal data is securely deleted when no longer needed.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["GDPR-Art.17".to_string()],
        remediation_guidance: Some("Implement secure erasure procedures using approved sanitization methods.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-PR-P.DP-P4".to_string(),
        control_id: "PR-P.DP-P4".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Data Backup Protection".to_string(),
        description: "Backups of personal data are protected.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CSF-PR.DS-11".to_string()],
        remediation_guidance: Some("Encrypt backups and ensure retention periods align with data classification.".to_string()),
    });

    // PR-P.IM: Identity Management
    controls.push(ComplianceControl {
        id: "NPF-PR-P.IM-P1".to_string(),
        control_id: "PR-P.IM-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Access Control for Personal Data".to_string(),
        description: "Access to personal data is controlled based on roles and need-to-know.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "NIST-CSF-PR.AA-03".to_string(),
            "GDPR-Art.32".to_string(),
        ],
        remediation_guidance: Some("Implement RBAC with least privilege for all personal data access.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-PR-P.IM-P2".to_string(),
        control_id: "PR-P.IM-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Strong Authentication".to_string(),
        description: "Strong authentication is required for access to personal data.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CSF-PR.AA-02".to_string()],
        remediation_guidance: Some("Implement MFA for all systems containing personal data.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-PR-P.IM-P3".to_string(),
        control_id: "PR-P.IM-P3".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Access Review".to_string(),
        description: "Access to personal data is periodically reviewed.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::Medium,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CSF-PR.AA-01".to_string()],
        remediation_guidance: Some("Conduct quarterly access reviews for systems processing personal data.".to_string()),
    });

    // PR-P.AL: Audit Logging
    controls.push(ComplianceControl {
        id: "NPF-PR-P.AL-P1".to_string(),
        control_id: "PR-P.AL-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Personal Data Access Logging".to_string(),
        description: "Access to personal data is logged and monitored.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec![
            "NIST-CSF-PR.PS-04".to_string(),
            "GDPR-Art.5.2".to_string(),
        ],
        remediation_guidance: Some("Enable comprehensive audit logging for all personal data access events.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-PR-P.AL-P2".to_string(),
        control_id: "PR-P.AL-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Audit Log Protection".to_string(),
        description: "Audit logs are protected from unauthorized modification.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: true,
        parent_id: None,
        cross_references: vec!["NIST-CSF-PR.PS-04".to_string()],
        remediation_guidance: Some("Implement write-once logging with integrity verification.".to_string()),
    });

    // PR-P.BR: Breach Response
    controls.push(ComplianceControl {
        id: "NPF-PR-P.BR-P1".to_string(),
        control_id: "PR-P.BR-P1".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Privacy Incident Response".to_string(),
        description: "Privacy incident response plan is established and tested.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.33".to_string(),
            "NIST-CSF-PR.IR-01".to_string(),
        ],
        remediation_guidance: Some("Develop privacy-specific incident response procedures with defined timelines.".to_string()),
    });

    controls.push(ComplianceControl {
        id: "NPF-PR-P.BR-P2".to_string(),
        control_id: "PR-P.BR-P2".to_string(),
        framework: ComplianceFramework::NistPrivacy,
        title: "Breach Notification".to_string(),
        description: "Privacy breach notification procedures are established.".to_string(),
        category: "Protect-P".to_string(),
        priority: ControlPriority::High,
        automated_check: false,
        parent_id: None,
        cross_references: vec![
            "GDPR-Art.33".to_string(),
            "GDPR-Art.34".to_string(),
        ],
        remediation_guidance: Some("Establish 72-hour notification procedures for regulators and affected individuals.".to_string()),
    });

    controls
}

/// Map a vulnerability to relevant NIST Privacy Framework controls (with severity)
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Encryption issues
    if title_lower.contains("encryption")
        || title_lower.contains("tls")
        || title_lower.contains("ssl")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted")
    {
        mappings.push(("PR-P.DP-P1".to_string(), Severity::High));
        mappings.push(("PR-P.DP-P2".to_string(), Severity::High));
    }

    // Access control / Authorization
    if title_lower.contains("access control")
        || title_lower.contains("authorization")
        || title_lower.contains("authentication")
        || title_lower.contains("privilege")
    {
        mappings.push(("PR-P.IM-P1".to_string(), Severity::High));
        mappings.push(("PR-P.IM-P2".to_string(), Severity::High));
    }

    // Logging / Audit
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("monitoring")
    {
        mappings.push(("PR-P.AL-P1".to_string(), Severity::Medium));
        mappings.push(("PR-P.AL-P2".to_string(), Severity::Medium));
    }

    // Data breach / Incident
    if title_lower.contains("breach")
        || title_lower.contains("incident")
        || title_lower.contains("leak")
        || title_lower.contains("exposed")
    {
        mappings.push(("PR-P.BR-P1".to_string(), Severity::Critical));
        mappings.push(("PR-P.BR-P2".to_string(), Severity::Critical));
    }

    // Consent issues
    if title_lower.contains("consent") {
        mappings.push(("CT-P.DM-P4".to_string(), Severity::High));
        mappings.push(("CM-P.TP-P1".to_string(), Severity::High));
    }

    // Data retention / Deletion
    if title_lower.contains("retention")
        || title_lower.contains("deletion")
        || title_lower.contains("erasure")
    {
        mappings.push(("CT-P.DM-P3".to_string(), Severity::Medium));
        mappings.push(("CM-P.DPA-P3".to_string(), Severity::High));
    }

    // Privacy / PII / Personal data
    if title_lower.contains("privacy")
        || title_lower.contains("pii")
        || title_lower.contains("personal data")
        || title_lower.contains("sensitive data")
    {
        mappings.push(("ID-P.IM-P1".to_string(), Severity::High));
        mappings.push(("ID-P.IM-P3".to_string(), Severity::High));
        mappings.push(("CT-P.DA-P1".to_string(), Severity::Medium));
    }

    // Data transfer / Cross-border
    if title_lower.contains("transfer") || title_lower.contains("cross-border") {
        mappings.push(("ID-P.IM-P6".to_string(), Severity::High));
    }

    // Data quality / Accuracy
    if title_lower.contains("accuracy") || title_lower.contains("data quality") {
        mappings.push(("CT-P.DM-P2".to_string(), Severity::Medium));
    }

    // Minimization
    if title_lower.contains("minimization") || title_lower.contains("excessive data") {
        mappings.push(("CT-P.DM-P1".to_string(), Severity::Medium));
    }

    // Transparency / Notice
    if title_lower.contains("transparency")
        || title_lower.contains("notice")
        || title_lower.contains("disclosure")
    {
        mappings.push(("CM-P.TP-P1".to_string(), Severity::Medium));
        mappings.push(("CM-P.TP-P2".to_string(), Severity::Medium));
    }

    // Third party / Vendor
    if title_lower.contains("third party")
        || title_lower.contains("vendor")
        || title_lower.contains("processor")
    {
        mappings.push(("GV-P.RO-P3".to_string(), Severity::High));
        mappings.push(("ID-P.IM-P6".to_string(), Severity::High));
    }

    // Risk assessment
    if title_lower.contains("risk assessment") || title_lower.contains("impact assessment") {
        mappings.push(("ID-P.RA-P1".to_string(), Severity::Medium));
    }

    // Data subject rights
    if title_lower.contains("access request")
        || title_lower.contains("subject right")
        || title_lower.contains("portability")
    {
        mappings.push(("CM-P.DPA-P1".to_string(), Severity::Medium));
        mappings.push(("CM-P.DPA-P4".to_string(), Severity::Medium));
    }

    // Backup issues
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("PR-P.DP-P4".to_string(), Severity::Medium));
    }

    // De-identification / Anonymization
    if title_lower.contains("anonymization")
        || title_lower.contains("de-identification")
        || title_lower.contains("pseudonymization")
    {
        mappings.push(("CT-P.DA-P1".to_string(), Severity::Medium));
        mappings.push(("CT-P.DA-P3".to_string(), Severity::Medium));
    }

    // Default - map to data protection policies
    if mappings.is_empty() {
        mappings.push(("PR-P.DP-P1".to_string(), Severity::Medium));
    }

    mappings
}

/// Map a vulnerability type to relevant NIST Privacy Framework controls (control IDs only)
pub fn map_vulnerability_to_controls(vuln_type: &str) -> Vec<String> {
    match vuln_type.to_lowercase().as_str() {
        "encryption" | "tls" | "ssl" | "data_at_rest" => vec![
            "PR-P.DP-P1".to_string(),
            "PR-P.DP-P2".to_string(),
        ],
        "access_control" | "authorization" | "authentication" => vec![
            "PR-P.IM-P1".to_string(),
            "PR-P.IM-P2".to_string(),
        ],
        "logging" | "audit" | "monitoring" => vec![
            "PR-P.AL-P1".to_string(),
            "PR-P.AL-P2".to_string(),
        ],
        "data_breach" | "incident" | "leak" => vec![
            "PR-P.BR-P1".to_string(),
            "PR-P.BR-P2".to_string(),
        ],
        "consent" => vec![
            "CT-P.DM-P4".to_string(),
            "CM-P.TP-P1".to_string(),
        ],
        "data_retention" | "deletion" => vec![
            "CT-P.DM-P3".to_string(),
            "CM-P.DPA-P3".to_string(),
        ],
        "privacy" | "pii" | "personal_data" => vec![
            "ID-P.IM-P1".to_string(),
            "ID-P.IM-P3".to_string(),
            "CT-P.DA-P1".to_string(),
        ],
        "data_transfer" | "cross_border" => vec![
            "ID-P.IM-P6".to_string(),
        ],
        "data_quality" | "accuracy" => vec![
            "CT-P.DM-P2".to_string(),
        ],
        "data_minimization" => vec![
            "CT-P.DM-P1".to_string(),
        ],
        "transparency" | "notice" => vec![
            "CM-P.TP-P1".to_string(),
            "CM-P.TP-P2".to_string(),
        ],
        "third_party" | "vendor" | "processor" => vec![
            "GV-P.RO-P3".to_string(),
            "ID-P.IM-P6".to_string(),
        ],
        "risk_assessment" | "impact_assessment" => vec![
            "ID-P.RA-P1".to_string(),
        ],
        "subject_rights" | "access_request" | "portability" => vec![
            "CM-P.DPA-P1".to_string(),
            "CM-P.DPA-P4".to_string(),
        ],
        "backup" | "recovery" => vec![
            "PR-P.DP-P4".to_string(),
        ],
        "de_identification" | "anonymization" | "pseudonymization" => vec![
            "CT-P.DA-P1".to_string(),
            "CT-P.DA-P3".to_string(),
        ],
        _ => vec!["PR-P.DP-P1".to_string()],
    }
}

/// Get NIST Privacy Framework function description
pub fn get_function_description(function: &str) -> Option<&'static str> {
    match function.to_uppercase().as_str() {
        "IDENTIFY-P" | "ID-P" => Some(
            "Develop organizational understanding to manage privacy risk for individuals \
             arising from data processing."
        ),
        "GOVERN-P" | "GV-P" => Some(
            "Develop and implement the organizational governance structure to enable an \
             ongoing understanding of the organization's privacy risk management priorities."
        ),
        "CONTROL-P" | "CT-P" => Some(
            "Develop and implement appropriate activities to enable organizations to manage \
             data with sufficient granularity to manage privacy risks."
        ),
        "COMMUNICATE-P" | "CM-P" => Some(
            "Develop and implement appropriate activities to enable organizations and individuals \
             to have a reliable understanding about how data are processed."
        ),
        "PROTECT-P" | "PR-P" => Some(
            "Develop and implement appropriate data protection safeguards including technical \
             and organizational measures to manage privacy risks."
        ),
        _ => None,
    }
}

/// Get cross-reference mappings to other frameworks
pub fn get_cross_reference_mappings(control_id: &str) -> Vec<(&'static str, &'static str)> {
    match control_id {
        "ID-P.IM-P1" => vec![
            ("NIST CSF", "ID.AM-01"),
            ("GDPR", "Art.30"),
        ],
        "ID-P.IM-P4" => vec![
            ("NIST CSF", "ID.AM-03"),
            ("GDPR", "Art.44"),
        ],
        "ID-P.RA-P1" => vec![
            ("NIST CSF", "ID.RA-01"),
            ("GDPR", "Art.35"),
        ],
        "GV-P.PO-P1" => vec![
            ("NIST CSF", "GV.RM-01"),
            ("GDPR", "Art.12"),
        ],
        "GV-P.RO-P1" => vec![
            ("GDPR", "Art.37"),
        ],
        "CT-P.DM-P1" => vec![
            ("GDPR", "Art.5.1(c)"),
        ],
        "CT-P.DM-P4" => vec![
            ("GDPR", "Art.7"),
        ],
        "CM-P.TP-P1" => vec![
            ("GDPR", "Art.12"),
            ("GDPR", "Art.13"),
        ],
        "CM-P.DPA-P1" => vec![
            ("GDPR", "Art.15"),
        ],
        "CM-P.DPA-P3" => vec![
            ("GDPR", "Art.17"),
        ],
        "PR-P.DP-P1" => vec![
            ("NIST CSF", "PR.DS-01"),
            ("GDPR", "Art.32"),
        ],
        "PR-P.DP-P2" => vec![
            ("NIST CSF", "PR.DS-02"),
            ("GDPR", "Art.32"),
        ],
        "PR-P.BR-P2" => vec![
            ("GDPR", "Art.33"),
            ("GDPR", "Art.34"),
        ],
        _ => vec![],
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
            assert_eq!(control.framework, ComplianceFramework::NistPrivacy);
        }
    }

    #[test]
    fn test_all_categories_covered() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> =
            controls.iter().map(|c| c.category.as_str()).collect();

        assert!(categories.contains("Identify-P"));
        assert!(categories.contains("Govern-P"));
        assert!(categories.contains("Control-P"));
        assert!(categories.contains("Communicate-P"));
        assert!(categories.contains("Protect-P"));
    }

    #[test]
    fn test_vulnerability_mapping() {
        let controls = map_vulnerability_to_controls("encryption");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"PR-P.DP-P1".to_string()));
    }

    #[test]
    fn test_vulnerability_mapping_with_severity() {
        let mappings = map_vulnerability("TLS vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "PR-P.DP-P2"));
    }

    #[test]
    fn test_data_breach_mapping() {
        let mappings = map_vulnerability("Data breach detected", None, None, None);
        assert!(mappings.iter().any(|(id, sev)| id == "PR-P.BR-P1" && *sev == Severity::Critical));
    }

    #[test]
    fn test_function_descriptions() {
        assert!(get_function_description("ID-P").is_some());
        assert!(get_function_description("GV-P").is_some());
        assert!(get_function_description("CT-P").is_some());
        assert!(get_function_description("CM-P").is_some());
        assert!(get_function_description("PR-P").is_some());
        assert!(get_function_description("INVALID").is_none());
    }

    #[test]
    fn test_cross_references() {
        let refs = get_cross_reference_mappings("PR-P.DP-P1");
        assert!(!refs.is_empty());
        assert!(refs.iter().any(|(fw, _)| *fw == "NIST CSF"));
        assert!(refs.iter().any(|(fw, _)| *fw == "GDPR"));
    }

    #[test]
    fn test_control_ids_unique() {
        let controls = get_controls();
        let ids: std::collections::HashSet<_> = controls.iter().map(|c| &c.id).collect();
        assert_eq!(ids.len(), controls.len(), "All control IDs should be unique");
    }

    #[test]
    fn test_automated_checks_present() {
        let controls = get_controls();
        let automated_count = controls.iter().filter(|c| c.automated_check).count();
        // Ensure a reasonable number of controls can be automated
        assert!(automated_count > 20, "Should have significant automated checks");
    }
}
