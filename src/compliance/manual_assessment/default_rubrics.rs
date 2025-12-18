//! Default System Rubrics for Manual Compliance Assessment
//!
//! This module provides default system rubrics for non-automated compliance controls
//! across all supported frameworks (PCI-DSS, SOC2, HIPAA, NIST 800-53).
//!
//! Rubrics are grouped by category:
//! - Physical Security (PE-* controls, PCI-DSS 9.x)
//! - Policy & Documentation (security policies, acceptable use, etc.)
//! - Training & Awareness (AT-* controls, security awareness programs)
//! - Access Control Reviews (periodic access reviews)
//! - Incident Response (IR-* controls, incident response plans)
//! - Vendor Management (third-party assessments)
//! - Business Continuity (CP-* controls, contingency plans)

use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::{
    AssessmentCriterion, ComplianceRubric, EvidenceRequirement, EvidenceType, RatingLevel,
    RatingScale, RatingScaleType,
};
use crate::compliance::types::ControlStatus;

/// Categories for organizing rubrics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RubricCategory {
    PhysicalSecurity,
    PolicyAndDocumentation,
    TrainingAndAwareness,
    AccessControlReviews,
    IncidentResponse,
    VendorManagement,
    BusinessContinuity,
    DataProtection,
    RiskManagement,
    GovernanceAndOversight,
    PrivacyCompliance,
    ChangeManagement,
    SecureDevelopment,
}

impl RubricCategory {
    fn as_str(&self) -> &'static str {
        match self {
            Self::PhysicalSecurity => "Physical Security",
            Self::PolicyAndDocumentation => "Policy & Documentation",
            Self::TrainingAndAwareness => "Training & Awareness",
            Self::AccessControlReviews => "Access Control Reviews",
            Self::IncidentResponse => "Incident Response",
            Self::VendorManagement => "Vendor Management",
            Self::BusinessContinuity => "Business Continuity",
            Self::DataProtection => "Data Protection",
            Self::RiskManagement => "Risk Management",
            Self::GovernanceAndOversight => "Governance & Oversight",
            Self::PrivacyCompliance => "Privacy Compliance",
            Self::ChangeManagement => "Change Management",
            Self::SecureDevelopment => "Secure Development",
        }
    }
}

/// Creates the standard 5-point rating scale used for most rubrics
fn create_standard_rating_scale() -> RatingScale {
    RatingScale {
        scale_type: RatingScaleType::FivePoint,
        levels: vec![
            RatingLevel {
                value: 0,
                label: "Not Applicable".to_string(),
                description: "The control does not apply to this organization or environment."
                    .to_string(),
                maps_to_status: ControlStatus::NotApplicable,
            },
            RatingLevel {
                value: 1,
                label: "Not Implemented".to_string(),
                description: "The control is not implemented. No evidence of implementation exists."
                    .to_string(),
                maps_to_status: ControlStatus::NonCompliant,
            },
            RatingLevel {
                value: 2,
                label: "Partially Implemented".to_string(),
                description:
                    "The control is partially implemented with significant gaps. Less than 50% of requirements are met."
                        .to_string(),
                maps_to_status: ControlStatus::PartiallyCompliant,
            },
            RatingLevel {
                value: 3,
                label: "Substantially Implemented".to_string(),
                description:
                    "The control is substantially implemented with minor gaps. 50-90% of requirements are met."
                        .to_string(),
                maps_to_status: ControlStatus::PartiallyCompliant,
            },
            RatingLevel {
                value: 4,
                label: "Fully Implemented".to_string(),
                description:
                    "The control is fully implemented, documented, and operationally effective."
                        .to_string(),
                maps_to_status: ControlStatus::Compliant,
            },
        ],
    }
}

/// Helper to create an assessment criterion
fn criterion(
    id: &str,
    question: &str,
    description: Option<&str>,
    guidance: Option<&str>,
    weight: f32,
    evidence_hint: Option<&str>,
) -> AssessmentCriterion {
    AssessmentCriterion {
        id: id.to_string(),
        question: question.to_string(),
        description: description.map(|s| s.to_string()),
        guidance: guidance.map(|s| s.to_string()),
        weight,
        evidence_hint: evidence_hint.map(|s| s.to_string()),
    }
}

/// Helper to create an evidence requirement
fn evidence_req(evidence_type: EvidenceType, description: &str, required: bool) -> EvidenceRequirement {
    EvidenceRequirement {
        evidence_type,
        description: description.to_string(),
        required,
    }
}

/// Creates a rubric with common fields populated
fn create_rubric(
    framework_id: &str,
    control_id: &str,
    name: &str,
    description: &str,
    criteria: Vec<AssessmentCriterion>,
    evidence_requirements: Vec<EvidenceRequirement>,
) -> ComplianceRubric {
    let now = Utc::now();
    ComplianceRubric {
        id: Uuid::new_v4().to_string(),
        user_id: None,
        framework_id: framework_id.to_string(),
        control_id: control_id.to_string(),
        name: name.to_string(),
        description: Some(description.to_string()),
        assessment_criteria: criteria,
        rating_scale: create_standard_rating_scale(),
        evidence_requirements,
        is_system_default: true,
        created_at: now,
        updated_at: now,
    }
}

// ============================================================================
// Physical Security Rubrics
// ============================================================================

fn physical_security_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // PCI-DSS 9.1.1 - Physical Security Controls
        create_rubric(
            "pci_dss",
            "9.1.1",
            "Physical Security Controls Assessment",
            "Assess physical security policies, procedures, and implementation for facilities containing cardholder data.",
            vec![
                criterion(
                    "9.1.1-C1",
                    "Are physical access procedures documented and published?",
                    Some("Physical security policies should define access requirements, authorization procedures, and visitor management."),
                    Some("Review physical security policy documents for completeness and currency. Check last review date."),
                    0.25,
                    Some("Physical security policy document with approval signatures"),
                ),
                criterion(
                    "9.1.1-C2",
                    "Are physical access controls implemented at all entry points?",
                    Some("Entry points should have access controls such as badge readers, biometric scanners, or security personnel."),
                    Some("Inspect all entry points to CDE areas. Verify access control mechanisms are operational."),
                    0.25,
                    Some("Photos of access control devices, access system configuration screenshots"),
                ),
                criterion(
                    "9.1.1-C3",
                    "Is visitor access properly controlled and logged?",
                    Some("Visitors must be escorted, issued badges, and logged in a visitor management system."),
                    Some("Review visitor logs for the past 30 days. Interview security personnel on visitor procedures."),
                    0.25,
                    Some("Sample visitor logs, visitor badge examples"),
                ),
                criterion(
                    "9.1.1-C4",
                    "Are physical security procedures communicated to all personnel?",
                    Some("Staff should be aware of physical security requirements and procedures."),
                    Some("Interview random sample of employees. Review training records."),
                    0.25,
                    Some("Training completion records, acknowledgment forms"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Physical security policy document", true),
                evidence_req(EvidenceType::Screenshot, "Access control system configuration", true),
                evidence_req(EvidenceType::File, "Visitor log samples (last 30 days)", true),
                evidence_req(EvidenceType::File, "Training records showing physical security awareness", false),
            ],
        ),
        // HIPAA 164.310(a)(1) - Facility Access Controls
        create_rubric(
            "hipaa",
            "164.310(a)(1)",
            "Facility Access Controls Assessment",
            "Assess implementation of policies and procedures to limit physical access to electronic information systems and the facilities housing them.",
            vec![
                criterion(
                    "164.310a1-C1",
                    "Are facility access policies documented and approved?",
                    Some("Policies must define who can access facilities, under what conditions, and authorization procedures."),
                    Some("Review facility access policy. Verify management approval and regular review schedule."),
                    0.20,
                    Some("Facility access control policy with signatures"),
                ),
                criterion(
                    "164.310a1-C2",
                    "Are access control mechanisms appropriate for the facility type?",
                    Some("Controls should be commensurate with the sensitivity of the data and systems housed."),
                    Some("Assess whether controls (locks, badges, guards) match the risk level of the facility."),
                    0.20,
                    Some("Risk assessment documentation, control mechanism inventory"),
                ),
                criterion(
                    "164.310a1-C3",
                    "Is access granted based on job function and need?",
                    Some("Physical access should follow least privilege principles."),
                    Some("Review access authorization records. Compare against job descriptions."),
                    0.20,
                    Some("Access authorization forms, role-to-access matrix"),
                ),
                criterion(
                    "164.310a1-C4",
                    "Are access permissions regularly reviewed and updated?",
                    Some("Access lists should be reviewed periodically and updated when personnel change roles."),
                    Some("Review access review records. Check for timely deprovisioning."),
                    0.20,
                    Some("Access review logs, termination checklists showing access removal"),
                ),
                criterion(
                    "164.310a1-C5",
                    "Are facility access logs maintained and reviewed?",
                    Some("Access logs should be retained and periodically reviewed for anomalies."),
                    Some("Review retention period compliance. Check for log review procedures."),
                    0.20,
                    Some("Access log samples, log review procedures"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Facility access control policy", true),
                evidence_req(EvidenceType::File, "Access authorization records", true),
                evidence_req(EvidenceType::File, "Access review documentation", true),
                evidence_req(EvidenceType::Screenshot, "Badge/access system configuration", false),
            ],
        ),
        // SOC2 CC6.4 - Physical Access Restrictions
        create_rubric(
            "soc2",
            "CC6.4",
            "Physical Access Restrictions Assessment",
            "Assess restrictions on physical access to facilities and protected information assets.",
            vec![
                criterion(
                    "CC6.4-C1",
                    "Are physical access restrictions defined and documented?",
                    Some("The organization should have documented policies for physical access to facilities housing critical systems."),
                    Some("Review physical access policies. Check for coverage of all sensitive areas."),
                    0.25,
                    Some("Physical security policy, facility classification"),
                ),
                criterion(
                    "CC6.4-C2",
                    "Are badge/key access systems implemented and managed?",
                    Some("Electronic access control systems should manage entry to sensitive areas."),
                    Some("Inspect access control systems. Review badge issuance procedures."),
                    0.25,
                    Some("Access system reports, badge issuance procedures"),
                ),
                criterion(
                    "CC6.4-C3",
                    "Is visitor management implemented effectively?",
                    Some("Visitors should be identified, escorted, and their access logged."),
                    Some("Review visitor procedures. Check sample visitor logs."),
                    0.25,
                    Some("Visitor policy, visitor log samples"),
                ),
                criterion(
                    "CC6.4-C4",
                    "Are physical access violations detected and responded to?",
                    Some("Unauthorized access attempts should be detected, logged, and investigated."),
                    Some("Review incident reports. Check alarm monitoring procedures."),
                    0.25,
                    Some("Security incident logs, alarm monitoring procedures"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Physical security policy", true),
                evidence_req(EvidenceType::File, "Visitor management procedures", true),
                evidence_req(EvidenceType::Screenshot, "Access control system dashboard", false),
                evidence_req(EvidenceType::File, "Sample security incident reports", false),
            ],
        ),
    ]
}

// ============================================================================
// Policy and Documentation Rubrics
// ============================================================================

fn policy_and_documentation_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // PCI-DSS 12.1.1 - Security Policy
        create_rubric(
            "pci_dss",
            "12.1.1",
            "Information Security Policy Assessment",
            "Assess whether an overall information security policy is established, published, maintained, and disseminated.",
            vec![
                criterion(
                    "12.1.1-C1",
                    "Is a comprehensive security policy document established?",
                    Some("The policy should address all PCI-DSS requirements and organizational security objectives."),
                    Some("Review the security policy for completeness. Check coverage of key security domains."),
                    0.25,
                    Some("Information security policy document"),
                ),
                criterion(
                    "12.1.1-C2",
                    "Is the security policy approved by management?",
                    Some("Executive or board-level approval demonstrates organizational commitment."),
                    Some("Check for management signatures and approval dates."),
                    0.25,
                    Some("Signed approval page or approval email"),
                ),
                criterion(
                    "12.1.1-C3",
                    "Is the security policy reviewed at least annually?",
                    Some("Annual review ensures the policy remains current and effective."),
                    Some("Check review dates and change history. Look for documented review process."),
                    0.25,
                    Some("Policy version history, review meeting minutes"),
                ),
                criterion(
                    "12.1.1-C4",
                    "Is the security policy communicated to all personnel?",
                    Some("All relevant personnel should be aware of and acknowledge the policy."),
                    Some("Review distribution records and acknowledgment tracking."),
                    0.25,
                    Some("Distribution records, acknowledgment signatures"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Information security policy document", true),
                evidence_req(EvidenceType::File, "Policy approval documentation", true),
                evidence_req(EvidenceType::File, "Policy acknowledgment records", false),
                evidence_req(EvidenceType::Note, "Date of last policy review", true),
            ],
        ),
        // PCI-DSS 12.3.1 - Acceptable Use Policies
        create_rubric(
            "pci_dss",
            "12.3.1",
            "Acceptable Use Policy Assessment",
            "Assess acceptable use policies for end-user technologies.",
            vec![
                criterion(
                    "12.3.1-C1",
                    "Are acceptable use policies documented for all end-user technologies?",
                    Some("Policies should cover workstations, mobile devices, email, internet, and removable media."),
                    Some("Review AUP documents for technology coverage."),
                    0.25,
                    Some("Acceptable use policy document"),
                ),
                criterion(
                    "12.3.1-C2",
                    "Do policies clearly define permitted and prohibited activities?",
                    Some("Users should understand what is allowed and what is not."),
                    Some("Review policy language for clarity and specificity."),
                    0.25,
                    Some("AUP sections on permitted/prohibited activities"),
                ),
                criterion(
                    "12.3.1-C3",
                    "Are users required to acknowledge the acceptable use policy?",
                    Some("Users should formally agree to comply with the policy."),
                    Some("Review acknowledgment process and records."),
                    0.25,
                    Some("Acknowledgment forms or system records"),
                ),
                criterion(
                    "12.3.1-C4",
                    "Are consequences for policy violations defined?",
                    Some("Users should understand repercussions for non-compliance."),
                    Some("Review policy language on disciplinary actions."),
                    0.25,
                    Some("Policy sections on violations and consequences"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Acceptable use policy document", true),
                evidence_req(EvidenceType::File, "User acknowledgment records", true),
                evidence_req(EvidenceType::Screenshot, "Electronic acknowledgment system", false),
            ],
        ),
        // NIST AC-1 - Access Control Policy and Procedures
        create_rubric(
            "nist_800_53",
            "AC-1",
            "Access Control Policy Assessment",
            "Assess access control policy and procedures documentation.",
            vec![
                criterion(
                    "AC-1-C1",
                    "Is an access control policy documented and approved?",
                    Some("Policy should address purpose, scope, roles, responsibilities, and management commitment."),
                    Some("Review policy document structure and content completeness."),
                    0.20,
                    Some("Access control policy document"),
                ),
                criterion(
                    "AC-1-C2",
                    "Are access control procedures documented?",
                    Some("Procedures should detail how policy requirements are implemented."),
                    Some("Review procedures for actionable steps and responsible parties."),
                    0.20,
                    Some("Access control procedures document"),
                ),
                criterion(
                    "AC-1-C3",
                    "Is the policy reviewed and updated at the required frequency?",
                    Some("Policy should be reviewed annually or when significant changes occur."),
                    Some("Check review dates and version history."),
                    0.20,
                    Some("Policy review records, version history"),
                ),
                criterion(
                    "AC-1-C4",
                    "Are procedures reviewed and updated at the required frequency?",
                    Some("Procedures should be reviewed annually or when systems change."),
                    Some("Check procedure review dates and change documentation."),
                    0.20,
                    Some("Procedure review records"),
                ),
                criterion(
                    "AC-1-C5",
                    "Are policy and procedures disseminated to relevant personnel?",
                    Some("Responsible parties must have access to current documentation."),
                    Some("Review distribution methods and acknowledgment records."),
                    0.20,
                    Some("Distribution records, access logs for policy repository"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Access control policy", true),
                evidence_req(EvidenceType::File, "Access control procedures", true),
                evidence_req(EvidenceType::File, "Policy review and approval records", true),
                evidence_req(EvidenceType::Note, "Distribution method description", false),
            ],
        ),
        // NIST CM-1 - Configuration Management Policy
        create_rubric(
            "nist_800_53",
            "CM-1",
            "Configuration Management Policy Assessment",
            "Assess configuration management policy and procedures documentation.",
            vec![
                criterion(
                    "CM-1-C1",
                    "Is a configuration management policy established and documented?",
                    Some("Policy should cover baseline configurations, change control, and configuration documentation."),
                    Some("Review policy document for completeness and organizational context."),
                    0.25,
                    Some("Configuration management policy"),
                ),
                criterion(
                    "CM-1-C2",
                    "Are configuration management procedures documented?",
                    Some("Procedures should detail configuration baseline development, change processes, and monitoring."),
                    Some("Review procedures for actionable guidance."),
                    0.25,
                    Some("Configuration management procedures"),
                ),
                criterion(
                    "CM-1-C3",
                    "Are policies and procedures reviewed at least annually?",
                    Some("Regular review ensures documents remain current and effective."),
                    Some("Check review dates and change documentation."),
                    0.25,
                    Some("Review records, version history"),
                ),
                criterion(
                    "CM-1-C4",
                    "Are policies and procedures communicated to relevant personnel?",
                    Some("IT staff and system administrators should be aware of CM requirements."),
                    Some("Review training records and distribution logs."),
                    0.25,
                    Some("Training records, acknowledgment forms"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Configuration management policy", true),
                evidence_req(EvidenceType::File, "Configuration management procedures", true),
                evidence_req(EvidenceType::File, "Review and approval records", true),
            ],
        ),
        // SOC2 CC5.3 - Policy Deployment
        create_rubric(
            "soc2",
            "CC5.3",
            "Security Policy Deployment Assessment",
            "Assess deployment of control activities through policies and procedures.",
            vec![
                criterion(
                    "CC5.3-C1",
                    "Are security policies documented and current?",
                    Some("Policies should be comprehensive, approved, and regularly reviewed."),
                    Some("Review policy inventory and version control."),
                    0.25,
                    Some("Security policy inventory, approval records"),
                ),
                criterion(
                    "CC5.3-C2",
                    "Are operational procedures derived from policies?",
                    Some("Procedures should translate policy requirements into actionable steps."),
                    Some("Trace procedures to supporting policies."),
                    0.25,
                    Some("Procedures with policy references"),
                ),
                criterion(
                    "CC5.3-C3",
                    "Are policies and procedures accessible to relevant personnel?",
                    Some("Staff should know where to find and access governing documents."),
                    Some("Check policy repository access and awareness."),
                    0.25,
                    Some("Policy repository access logs, staff interviews"),
                ),
                criterion(
                    "CC5.3-C4",
                    "Is policy compliance monitored and enforced?",
                    Some("Mechanisms should exist to verify and enforce policy adherence."),
                    Some("Review compliance monitoring processes."),
                    0.25,
                    Some("Compliance monitoring reports, audit findings"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Security policies inventory", true),
                evidence_req(EvidenceType::File, "Sample operational procedures", true),
                evidence_req(EvidenceType::Screenshot, "Policy repository/intranet", false),
            ],
        ),
    ]
}

// ============================================================================
// Training and Awareness Rubrics
// ============================================================================

fn training_and_awareness_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // PCI-DSS 12.6.1 - Security Awareness Program
        create_rubric(
            "pci_dss",
            "12.6.1",
            "Security Awareness Program Assessment",
            "Assess the formal security awareness program implementation.",
            vec![
                criterion(
                    "12.6.1-C1",
                    "Is a formal security awareness program established?",
                    Some("A documented program with objectives, curriculum, and schedule should exist."),
                    Some("Review program documentation and training materials."),
                    0.20,
                    Some("Security awareness program documentation"),
                ),
                criterion(
                    "12.6.1-C2",
                    "Does training cover all relevant security topics?",
                    Some("Training should address password security, phishing, social engineering, data handling, and PCI-DSS requirements."),
                    Some("Review training curriculum against required topics."),
                    0.20,
                    Some("Training curriculum, course materials"),
                ),
                criterion(
                    "12.6.1-C3",
                    "Is training provided upon hire and at least annually?",
                    Some("New employees should be trained promptly; annual refresher training is required."),
                    Some("Review training records for onboarding and annual completion."),
                    0.20,
                    Some("Training completion records"),
                ),
                criterion(
                    "12.6.1-C4",
                    "Is training completion tracked and documented?",
                    Some("Records should show who completed training and when."),
                    Some("Review tracking system and sample records."),
                    0.20,
                    Some("Training tracking system, completion reports"),
                ),
                criterion(
                    "12.6.1-C5",
                    "Are personnel required to acknowledge understanding?",
                    Some("Employees should confirm they understand their security responsibilities."),
                    Some("Review acknowledgment requirements and records."),
                    0.20,
                    Some("Acknowledgment forms or system records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Security awareness program documentation", true),
                evidence_req(EvidenceType::File, "Training curriculum/materials", true),
                evidence_req(EvidenceType::Screenshot, "Training completion tracking system", true),
                evidence_req(EvidenceType::File, "Sample completion certificates", false),
            ],
        ),
        // HIPAA 164.308(a)(5)(i) - Security Awareness and Training
        create_rubric(
            "hipaa",
            "164.308(a)(5)(i)",
            "HIPAA Security Awareness Training Assessment",
            "Assess the security awareness and training program for HIPAA compliance.",
            vec![
                criterion(
                    "164.308a5i-C1",
                    "Is a security awareness and training program implemented?",
                    Some("A formal program addressing ePHI security should be in place for all workforce members."),
                    Some("Review program documentation and scope."),
                    0.20,
                    Some("Training program documentation"),
                ),
                criterion(
                    "164.308a5i-C2",
                    "Does training address HIPAA-specific requirements?",
                    Some("Training should cover ePHI handling, privacy rules, security requirements, and breach notification."),
                    Some("Review training content for HIPAA coverage."),
                    0.20,
                    Some("Training materials showing HIPAA content"),
                ),
                criterion(
                    "164.308a5i-C3",
                    "Is training provided to all workforce members?",
                    Some("All employees, contractors, and volunteers with ePHI access should receive training."),
                    Some("Compare training records against workforce list."),
                    0.20,
                    Some("Training completion report, workforce roster"),
                ),
                criterion(
                    "164.308a5i-C4",
                    "Is training provided upon onboarding and periodically?",
                    Some("Training should occur during onboarding and be refreshed at least annually."),
                    Some("Review training schedule and completion dates."),
                    0.20,
                    Some("Training schedule, historical completion data"),
                ),
                criterion(
                    "164.308a5i-C5",
                    "Are training records retained appropriately?",
                    Some("Training documentation should be retained for at least 6 years per HIPAA requirements."),
                    Some("Review retention policy and historical records."),
                    0.20,
                    Some("Training record retention policy, historical records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Training program documentation", true),
                evidence_req(EvidenceType::File, "HIPAA training materials", true),
                evidence_req(EvidenceType::File, "Training completion records", true),
                evidence_req(EvidenceType::Note, "Training record retention period", true),
            ],
        ),
        // NIST AT-2 - Literacy Training and Awareness
        create_rubric(
            "nist_800_53",
            "AT-2",
            "Security Literacy Training Assessment",
            "Assess security and privacy literacy training for system users.",
            vec![
                criterion(
                    "AT-2-C1",
                    "Is security literacy training provided to system users?",
                    Some("Training should cover security risks, policies, and user responsibilities."),
                    Some("Review training program and materials."),
                    0.20,
                    Some("Training program documentation"),
                ),
                criterion(
                    "AT-2-C2",
                    "Is training provided within required timeframes?",
                    Some("Initial training within 30 days of access, updates when requirements change, annual refresher."),
                    Some("Review training completion dates against requirements."),
                    0.20,
                    Some("Training completion records with dates"),
                ),
                criterion(
                    "AT-2-C3",
                    "Does training address insider threat awareness?",
                    Some("Users should understand indicators and reporting of potential insider threats."),
                    Some("Review training content for insider threat coverage."),
                    0.20,
                    Some("Training materials on insider threats"),
                ),
                criterion(
                    "AT-2-C4",
                    "Does training include practical exercises?",
                    Some("Practical exercises like phishing simulations reinforce learning."),
                    Some("Review exercise implementation and results."),
                    0.20,
                    Some("Phishing simulation reports, exercise documentation"),
                ),
                criterion(
                    "AT-2-C5",
                    "Is training effectiveness measured?",
                    Some("Assessments should verify learning and identify gaps."),
                    Some("Review assessment methods and results."),
                    0.20,
                    Some("Training assessments, pass rates, improvement plans"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Security awareness training materials", true),
                evidence_req(EvidenceType::File, "Training completion records", true),
                evidence_req(EvidenceType::File, "Phishing simulation results", false),
                evidence_req(EvidenceType::File, "Training assessments/quizzes", false),
            ],
        ),
    ]
}

// ============================================================================
// Access Control Reviews Rubrics
// ============================================================================

fn access_control_reviews_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // PCI-DSS 7.1.1 - Access Limited to Need-to-Know
        create_rubric(
            "pci_dss",
            "7.1.1",
            "Need-to-Know Access Control Assessment",
            "Assess policies and processes for restricting access to system components.",
            vec![
                criterion(
                    "7.1.1-C1",
                    "Are access control policies documented and approved?",
                    Some("Policies should define access requirements based on job function and need-to-know."),
                    Some("Review access control policy documentation."),
                    0.20,
                    Some("Access control policy"),
                ),
                criterion(
                    "7.1.1-C2",
                    "Are access roles defined based on job classification?",
                    Some("Roles should clearly map job functions to required access levels."),
                    Some("Review role definitions and job function mapping."),
                    0.20,
                    Some("Role definitions, access matrix"),
                ),
                criterion(
                    "7.1.1-C3",
                    "Is access granted through a formal authorization process?",
                    Some("Access requests should require approval based on business need."),
                    Some("Review access request and approval workflow."),
                    0.20,
                    Some("Access request forms, approval records"),
                ),
                criterion(
                    "7.1.1-C4",
                    "Are access rights reviewed periodically?",
                    Some("Regular reviews ensure access remains appropriate as roles change."),
                    Some("Review access review schedule and completion records."),
                    0.20,
                    Some("Access review reports, remediation records"),
                ),
                criterion(
                    "7.1.1-C5",
                    "Is access promptly revoked upon role change or termination?",
                    Some("Access should be modified or revoked when no longer needed."),
                    Some("Review termination procedures and sample records."),
                    0.20,
                    Some("Termination checklists, deprovisioning records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Access control policy", true),
                evidence_req(EvidenceType::File, "Role definitions and access matrix", true),
                evidence_req(EvidenceType::File, "Access review records", true),
                evidence_req(EvidenceType::File, "Sample termination deprovisioning records", false),
            ],
        ),
        // PCI-DSS 7.2.1 - Access Control Model
        create_rubric(
            "pci_dss",
            "7.2.1",
            "Access Control Model Assessment",
            "Assess the access control model including job classification-based access.",
            vec![
                criterion(
                    "7.2.1-C1",
                    "Is an access control model defined and documented?",
                    Some("The model should specify how access decisions are made (RBAC, ABAC, etc.)."),
                    Some("Review access control model documentation."),
                    0.25,
                    Some("Access control model documentation"),
                ),
                criterion(
                    "7.2.1-C2",
                    "Are access levels defined by job classification?",
                    Some("Access should be determined by job function, not individual requests."),
                    Some("Review job classifications and associated access levels."),
                    0.25,
                    Some("Job classification access matrix"),
                ),
                criterion(
                    "7.2.1-C3",
                    "Is the access control model consistently applied?",
                    Some("All systems handling CDE should follow the same access model."),
                    Some("Sample systems to verify model implementation."),
                    0.25,
                    Some("System access configuration samples"),
                ),
                criterion(
                    "7.2.1-C4",
                    "Is the access control model reviewed and updated as needed?",
                    Some("The model should evolve with organizational changes."),
                    Some("Review model change history and triggers."),
                    0.25,
                    Some("Model review records, change documentation"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Access control model documentation", true),
                evidence_req(EvidenceType::File, "Job classification access matrix", true),
                evidence_req(EvidenceType::Screenshot, "System access configuration", false),
            ],
        ),
        // NIST AC-5 - Separation of Duties
        create_rubric(
            "nist_800_53",
            "AC-5",
            "Separation of Duties Assessment",
            "Assess separation of duties to prevent single points of control for critical functions.",
            vec![
                criterion(
                    "AC-5-C1",
                    "Are duties requiring separation identified and documented?",
                    Some("Critical duties that should not be performed by the same individual should be identified."),
                    Some("Review separation of duties documentation."),
                    0.25,
                    Some("Separation of duties matrix"),
                ),
                criterion(
                    "AC-5-C2",
                    "Is separation of duties implemented in access controls?",
                    Some("Technical controls should prevent individuals from having conflicting duties."),
                    Some("Review role assignments for separation enforcement."),
                    0.25,
                    Some("Role assignments, access control configurations"),
                ),
                criterion(
                    "AC-5-C3",
                    "Are separation requirements enforced for development and operations?",
                    Some("Developers should not have production deployment rights; operations should not modify code."),
                    Some("Review development and operations access separation."),
                    0.25,
                    Some("Development and operations role definitions"),
                ),
                criterion(
                    "AC-5-C4",
                    "Are separation violations detected and addressed?",
                    Some("Monitoring should identify when separation is bypassed."),
                    Some("Review monitoring mechanisms and incident records."),
                    0.25,
                    Some("Separation violation reports, remediation records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Separation of duties matrix", true),
                evidence_req(EvidenceType::File, "Role definition documentation", true),
                evidence_req(EvidenceType::Screenshot, "Access control showing separation", false),
            ],
        ),
    ]
}

// ============================================================================
// Incident Response Rubrics
// ============================================================================

fn incident_response_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // PCI-DSS 12.10.1 - Incident Response Plan
        create_rubric(
            "pci_dss",
            "12.10.1",
            "Incident Response Plan Assessment",
            "Assess whether an incident response plan exists and is ready for immediate activation.",
            vec![
                criterion(
                    "12.10.1-C1",
                    "Is an incident response plan documented?",
                    Some("A formal plan should exist covering roles, procedures, and communication."),
                    Some("Review incident response plan documentation."),
                    0.20,
                    Some("Incident response plan document"),
                ),
                criterion(
                    "12.10.1-C2",
                    "Does the plan include breach notification procedures?",
                    Some("Procedures for notifying payment brands, law enforcement, and affected parties should be defined."),
                    Some("Review notification procedures in the plan."),
                    0.20,
                    Some("Breach notification procedures"),
                ),
                criterion(
                    "12.10.1-C3",
                    "Are incident response team roles and contacts current?",
                    Some("Team members and escalation contacts should be up-to-date."),
                    Some("Verify contact information is current."),
                    0.20,
                    Some("Team roster, contact list"),
                ),
                criterion(
                    "12.10.1-C4",
                    "Is the incident response plan tested at least annually?",
                    Some("Regular testing validates plan effectiveness."),
                    Some("Review test records and results."),
                    0.20,
                    Some("Incident response test records"),
                ),
                criterion(
                    "12.10.1-C5",
                    "Is the plan updated based on lessons learned?",
                    Some("The plan should incorporate improvements from tests and actual incidents."),
                    Some("Review plan updates and change history."),
                    0.20,
                    Some("Plan update history, lessons learned documents"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Incident response plan", true),
                evidence_req(EvidenceType::File, "Team roster and contact list", true),
                evidence_req(EvidenceType::File, "Annual test results", true),
                evidence_req(EvidenceType::File, "Lessons learned documentation", false),
            ],
        ),
        // HIPAA 164.308(a)(6)(i) - Security Incident Procedures
        create_rubric(
            "hipaa",
            "164.308(a)(6)(i)",
            "Security Incident Procedures Assessment",
            "Assess policies and procedures for identifying, responding to, and reporting security incidents.",
            vec![
                criterion(
                    "164.308a6i-C1",
                    "Are security incident procedures documented?",
                    Some("Procedures should cover identification, response, mitigation, and documentation of incidents."),
                    Some("Review incident response procedures."),
                    0.25,
                    Some("Incident response procedures document"),
                ),
                criterion(
                    "164.308a6i-C2",
                    "Are breach notification requirements addressed?",
                    Some("Procedures should align with HIPAA breach notification requirements."),
                    Some("Review breach notification procedures for HIPAA compliance."),
                    0.25,
                    Some("Breach notification procedures"),
                ),
                criterion(
                    "164.308a6i-C3",
                    "Is the incident response team identified and trained?",
                    Some("Team members should be designated and trained on response procedures."),
                    Some("Review team designations and training records."),
                    0.25,
                    Some("Team roster, training records"),
                ),
                criterion(
                    "164.308a6i-C4",
                    "Are incidents documented and tracked?",
                    Some("All security incidents should be logged with investigation and resolution details."),
                    Some("Review incident documentation and tracking system."),
                    0.25,
                    Some("Incident log, tracking system screenshots"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Incident response procedures", true),
                evidence_req(EvidenceType::File, "Breach notification procedures", true),
                evidence_req(EvidenceType::File, "Incident response team roster", true),
                evidence_req(EvidenceType::Screenshot, "Incident tracking system", false),
            ],
        ),
        // NIST IR-1 - Incident Response Policy and Procedures
        create_rubric(
            "nist_800_53",
            "IR-1",
            "Incident Response Policy Assessment",
            "Assess incident response policy and procedures documentation.",
            vec![
                criterion(
                    "IR-1-C1",
                    "Is an incident response policy established and documented?",
                    Some("Policy should address purpose, scope, roles, responsibilities, and management commitment."),
                    Some("Review incident response policy."),
                    0.25,
                    Some("Incident response policy"),
                ),
                criterion(
                    "IR-1-C2",
                    "Are incident response procedures documented?",
                    Some("Procedures should provide step-by-step guidance for incident handling."),
                    Some("Review incident response procedures."),
                    0.25,
                    Some("Incident response procedures"),
                ),
                criterion(
                    "IR-1-C3",
                    "Are policy and procedures reviewed and updated regularly?",
                    Some("Annual review ensures documents remain current."),
                    Some("Check review dates and update history."),
                    0.25,
                    Some("Review records, version history"),
                ),
                criterion(
                    "IR-1-C4",
                    "Are policy and procedures disseminated to appropriate personnel?",
                    Some("Incident responders must have access to current documentation."),
                    Some("Review distribution and acknowledgment records."),
                    0.25,
                    Some("Distribution records, acknowledgments"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Incident response policy", true),
                evidence_req(EvidenceType::File, "Incident response procedures", true),
                evidence_req(EvidenceType::File, "Review and approval records", true),
            ],
        ),
        // NIST IR-2 - Incident Response Training
        create_rubric(
            "nist_800_53",
            "IR-2",
            "Incident Response Training Assessment",
            "Assess incident response training for personnel with incident response roles.",
            vec![
                criterion(
                    "IR-2-C1",
                    "Is incident response training provided to designated personnel?",
                    Some("Personnel with incident response roles should receive role-appropriate training."),
                    Some("Review training program and completion records."),
                    0.25,
                    Some("Training program documentation, completion records"),
                ),
                criterion(
                    "IR-2-C2",
                    "Is training provided within required timeframes?",
                    Some("Training should occur within 30 days of role assignment and upon significant changes."),
                    Some("Compare training dates against role assignments."),
                    0.25,
                    Some("Role assignment dates, training completion dates"),
                ),
                criterion(
                    "IR-2-C3",
                    "Does training include practical exercises?",
                    Some("Tabletop exercises and simulations reinforce learning."),
                    Some("Review exercise participation and results."),
                    0.25,
                    Some("Exercise documentation, after-action reports"),
                ),
                criterion(
                    "IR-2-C4",
                    "Is training updated to address emerging threats?",
                    Some("Training should evolve to cover new attack vectors and response techniques."),
                    Some("Review training curriculum updates."),
                    0.25,
                    Some("Training curriculum versions, update records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Training program documentation", true),
                evidence_req(EvidenceType::File, "Training completion records", true),
                evidence_req(EvidenceType::File, "Exercise after-action reports", false),
            ],
        ),
        // NIST IR-4 - Incident Handling
        create_rubric(
            "nist_800_53",
            "IR-4",
            "Incident Handling Assessment",
            "Assess incident handling capability including preparation, detection, analysis, containment, eradication, and recovery.",
            vec![
                criterion(
                    "IR-4-C1",
                    "Is an incident handling capability implemented?",
                    Some("The organization should have resources and processes for handling security incidents."),
                    Some("Review incident handling resources and processes."),
                    0.20,
                    Some("Incident handling capability documentation"),
                ),
                criterion(
                    "IR-4-C2",
                    "Does the capability cover all phases of incident handling?",
                    Some("Preparation, detection/analysis, containment, eradication, and recovery should be addressed."),
                    Some("Review procedures for each phase coverage."),
                    0.20,
                    Some("Procedures for each incident handling phase"),
                ),
                criterion(
                    "IR-4-C3",
                    "Are incidents correlated and analyzed for patterns?",
                    Some("Analysis should identify related incidents and attack patterns."),
                    Some("Review analysis processes and tools."),
                    0.20,
                    Some("Incident analysis tools, pattern identification records"),
                ),
                criterion(
                    "IR-4-C4",
                    "Are lessons learned incorporated into the program?",
                    Some("Post-incident reviews should drive process improvements."),
                    Some("Review lessons learned documentation and resulting changes."),
                    0.20,
                    Some("Lessons learned documents, improvement records"),
                ),
                criterion(
                    "IR-4-C5",
                    "Is incident information shared with appropriate parties?",
                    Some("Information sharing with law enforcement, ISACs, or other organizations as appropriate."),
                    Some("Review information sharing agreements and practices."),
                    0.20,
                    Some("Information sharing agreements, sharing records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Incident handling procedures", true),
                evidence_req(EvidenceType::File, "Sample incident reports", false),
                evidence_req(EvidenceType::File, "Lessons learned documentation", true),
                evidence_req(EvidenceType::File, "Information sharing agreements", false),
            ],
        ),
        // SOC2 CC7.4 - Incident Response
        create_rubric(
            "soc2",
            "CC7.4",
            "SOC2 Incident Response Assessment",
            "Assess whether the entity responds to identified security incidents according to established procedures.",
            vec![
                criterion(
                    "CC7.4-C1",
                    "Are incident response procedures documented?",
                    Some("Procedures should guide response to various types of security incidents."),
                    Some("Review incident response procedures."),
                    0.25,
                    Some("Incident response procedures"),
                ),
                criterion(
                    "CC7.4-C2",
                    "Is an incident response team established?",
                    Some("A team with defined roles should be responsible for incident response."),
                    Some("Review team structure and responsibilities."),
                    0.25,
                    Some("Team roster, responsibility matrix"),
                ),
                criterion(
                    "CC7.4-C3",
                    "Are incidents documented and tracked to resolution?",
                    Some("All incidents should be logged, investigated, and resolved with documentation."),
                    Some("Review incident records and tracking system."),
                    0.25,
                    Some("Incident logs, tracking system"),
                ),
                criterion(
                    "CC7.4-C4",
                    "Is incident response capability tested?",
                    Some("Regular testing validates response effectiveness."),
                    Some("Review test records and results."),
                    0.25,
                    Some("Test documentation, improvement actions"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Incident response procedures", true),
                evidence_req(EvidenceType::File, "Incident response team roster", true),
                evidence_req(EvidenceType::Screenshot, "Incident tracking system", true),
                evidence_req(EvidenceType::File, "Test results documentation", false),
            ],
        ),
    ]
}

// ============================================================================
// Vendor Management Rubrics
// ============================================================================

fn vendor_management_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // PCI-DSS 12.8.1 - Service Provider List
        create_rubric(
            "pci_dss",
            "12.8.1",
            "Service Provider Management Assessment",
            "Assess maintenance of list of service providers with whom account data is shared.",
            vec![
                criterion(
                    "12.8.1-C1",
                    "Is a list of all service providers maintained?",
                    Some("An inventory of third parties with access to account data should be maintained."),
                    Some("Review service provider inventory."),
                    0.25,
                    Some("Service provider list/inventory"),
                ),
                criterion(
                    "12.8.1-C2",
                    "Does the list document services provided?",
                    Some("Services provided and data shared should be documented for each provider."),
                    Some("Review service descriptions in inventory."),
                    0.25,
                    Some("Service descriptions, data flow documentation"),
                ),
                criterion(
                    "12.8.1-C3",
                    "Are service providers assessed for PCI-DSS compliance?",
                    Some("Service providers handling account data should demonstrate compliance."),
                    Some("Review compliance attestations or assessment records."),
                    0.25,
                    Some("AOC documents, assessment reports"),
                ),
                criterion(
                    "12.8.1-C4",
                    "Is the service provider list reviewed and updated regularly?",
                    Some("The list should be reviewed at least annually and updated when relationships change."),
                    Some("Review update history and review records."),
                    0.25,
                    Some("Review records, update history"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Service provider inventory", true),
                evidence_req(EvidenceType::File, "Service provider compliance attestations", true),
                evidence_req(EvidenceType::File, "Review records", false),
            ],
        ),
        // HIPAA 164.308(b)(1) - Business Associate Contracts
        create_rubric(
            "hipaa",
            "164.308(b)(1)",
            "Business Associate Agreement Assessment",
            "Assess Business Associate Agreement implementation with all entities handling ePHI.",
            vec![
                criterion(
                    "164.308b1-C1",
                    "Is a list of all Business Associates maintained?",
                    Some("All entities with access to ePHI should be identified."),
                    Some("Review Business Associate inventory."),
                    0.25,
                    Some("Business Associate list"),
                ),
                criterion(
                    "164.308b1-C2",
                    "Are BAAs in place with all Business Associates?",
                    Some("Written agreements meeting HIPAA requirements should exist for all BAs."),
                    Some("Review BAA status for each Business Associate."),
                    0.25,
                    Some("BAA inventory, sample agreements"),
                ),
                criterion(
                    "164.308b1-C3",
                    "Do BAAs contain required elements?",
                    Some("BAAs must include required safeguards, breach notification, and termination provisions."),
                    Some("Review BAA content against requirements."),
                    0.25,
                    Some("BAA template, compliance checklist"),
                ),
                criterion(
                    "164.308b1-C4",
                    "Are BAAs reviewed and updated as needed?",
                    Some("BAAs should be reviewed periodically and updated for regulatory changes."),
                    Some("Review BAA update history and triggers."),
                    0.25,
                    Some("BAA review records, amendment history"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Business Associate inventory", true),
                evidence_req(EvidenceType::File, "Sample BAA documents", true),
                evidence_req(EvidenceType::File, "BAA compliance checklist", true),
            ],
        ),
        // SOC2 CC9.2 - Vendor Risk Management
        create_rubric(
            "soc2",
            "CC9.2",
            "Vendor Risk Management Assessment",
            "Assess and manage risks associated with vendors and business partners.",
            vec![
                criterion(
                    "CC9.2-C1",
                    "Is a vendor risk management program established?",
                    Some("A formal program for assessing and managing vendor risks should exist."),
                    Some("Review vendor risk management program documentation."),
                    0.20,
                    Some("Vendor risk management policy/procedures"),
                ),
                criterion(
                    "CC9.2-C2",
                    "Are vendors inventoried and categorized by risk?",
                    Some("Vendors should be classified based on access to data and criticality of services."),
                    Some("Review vendor inventory and risk categorization."),
                    0.20,
                    Some("Vendor inventory with risk tiers"),
                ),
                criterion(
                    "CC9.2-C3",
                    "Are vendor security assessments conducted?",
                    Some("Vendors should be assessed before onboarding and periodically thereafter."),
                    Some("Review assessment procedures and records."),
                    0.20,
                    Some("Vendor assessment questionnaires, reports"),
                ),
                criterion(
                    "CC9.2-C4",
                    "Are contractual security requirements in place?",
                    Some("Contracts should include security requirements and right-to-audit clauses."),
                    Some("Review contract templates and sample agreements."),
                    0.20,
                    Some("Contract templates, security requirements"),
                ),
                criterion(
                    "CC9.2-C5",
                    "Is vendor performance and compliance monitored?",
                    Some("Ongoing monitoring should verify continued compliance with requirements."),
                    Some("Review monitoring procedures and records."),
                    0.20,
                    Some("Monitoring reports, compliance tracking"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Vendor risk management policy", true),
                evidence_req(EvidenceType::File, "Vendor inventory with risk tiers", true),
                evidence_req(EvidenceType::File, "Sample vendor assessment", true),
                evidence_req(EvidenceType::File, "Contract security requirements", false),
            ],
        ),
    ]
}

// ============================================================================
// Business Continuity Rubrics
// ============================================================================

fn business_continuity_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // HIPAA 164.308(a)(7)(i) - Contingency Plan
        create_rubric(
            "hipaa",
            "164.308(a)(7)(i)",
            "Contingency Plan Assessment",
            "Assess policies and procedures for responding to emergencies affecting ePHI systems.",
            vec![
                criterion(
                    "164.308a7i-C1",
                    "Is a contingency plan documented?",
                    Some("A plan addressing emergency response, backup, disaster recovery, and testing should exist."),
                    Some("Review contingency plan documentation."),
                    0.20,
                    Some("Contingency plan document"),
                ),
                criterion(
                    "164.308a7i-C2",
                    "Does the plan address data backup procedures?",
                    Some("Procedures for creating and maintaining retrievable copies of ePHI should be defined."),
                    Some("Review backup procedures in the plan."),
                    0.20,
                    Some("Data backup plan"),
                ),
                criterion(
                    "164.308a7i-C3",
                    "Does the plan address disaster recovery?",
                    Some("Procedures for restoring lost data and systems should be documented."),
                    Some("Review disaster recovery procedures."),
                    0.20,
                    Some("Disaster recovery plan"),
                ),
                criterion(
                    "164.308a7i-C4",
                    "Is the contingency plan tested periodically?",
                    Some("Testing validates plan effectiveness and identifies gaps."),
                    Some("Review test records and results."),
                    0.20,
                    Some("Test records, exercise documentation"),
                ),
                criterion(
                    "164.308a7i-C5",
                    "Are applications and data prioritized for recovery?",
                    Some("Criticality analysis should determine recovery priorities."),
                    Some("Review criticality assessment and priority list."),
                    0.20,
                    Some("Criticality analysis, recovery priority list"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Contingency plan document", true),
                evidence_req(EvidenceType::File, "Disaster recovery plan", true),
                evidence_req(EvidenceType::File, "Test results documentation", true),
                evidence_req(EvidenceType::File, "Criticality analysis", false),
            ],
        ),
        // HIPAA 164.308(a)(7)(ii)(B) - Disaster Recovery Plan
        create_rubric(
            "hipaa",
            "164.308(a)(7)(ii)(B)",
            "Disaster Recovery Plan Assessment",
            "Assess procedures to restore any loss of data.",
            vec![
                criterion(
                    "164.308a7iiB-C1",
                    "Is a disaster recovery plan documented?",
                    Some("A documented plan for data and system restoration should exist."),
                    Some("Review disaster recovery plan documentation."),
                    0.25,
                    Some("Disaster recovery plan"),
                ),
                criterion(
                    "164.308a7iiB-C2",
                    "Are recovery time objectives (RTOs) defined?",
                    Some("Maximum acceptable downtime for systems should be established."),
                    Some("Review RTO definitions for critical systems."),
                    0.25,
                    Some("RTO documentation, criticality analysis"),
                ),
                criterion(
                    "164.308a7iiB-C3",
                    "Are recovery procedures tested and validated?",
                    Some("Regular testing ensures recovery procedures work as intended."),
                    Some("Review test records and success criteria."),
                    0.25,
                    Some("Test records, validation results"),
                ),
                criterion(
                    "164.308a7iiB-C4",
                    "Are recovery resources adequate?",
                    Some("Resources including alternate sites, personnel, and equipment should be available."),
                    Some("Review resource inventory and arrangements."),
                    0.25,
                    Some("Resource inventory, alternate site agreements"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Disaster recovery plan", true),
                evidence_req(EvidenceType::File, "RTO/RPO documentation", true),
                evidence_req(EvidenceType::File, "DR test results", true),
            ],
        ),
        // NIST CP-1 - Contingency Planning Policy
        create_rubric(
            "nist_800_53",
            "CP-1",
            "Contingency Planning Policy Assessment",
            "Assess contingency planning policy and procedures documentation.",
            vec![
                criterion(
                    "CP-1-C1",
                    "Is a contingency planning policy established?",
                    Some("Policy should address purpose, scope, roles, responsibilities, and management commitment."),
                    Some("Review contingency planning policy."),
                    0.25,
                    Some("Contingency planning policy"),
                ),
                criterion(
                    "CP-1-C2",
                    "Are contingency planning procedures documented?",
                    Some("Procedures should detail how policy requirements are implemented."),
                    Some("Review contingency planning procedures."),
                    0.25,
                    Some("Contingency planning procedures"),
                ),
                criterion(
                    "CP-1-C3",
                    "Are policy and procedures reviewed and updated regularly?",
                    Some("Annual review ensures documents remain current."),
                    Some("Check review dates and update history."),
                    0.25,
                    Some("Review records, version history"),
                ),
                criterion(
                    "CP-1-C4",
                    "Are policy and procedures disseminated to appropriate personnel?",
                    Some("Personnel with contingency roles must have access to current documentation."),
                    Some("Review distribution and acknowledgment records."),
                    0.25,
                    Some("Distribution records, acknowledgments"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Contingency planning policy", true),
                evidence_req(EvidenceType::File, "Contingency planning procedures", true),
                evidence_req(EvidenceType::File, "Review and approval records", true),
            ],
        ),
        // NIST CP-4 - Contingency Plan Testing
        create_rubric(
            "nist_800_53",
            "CP-4",
            "Contingency Plan Testing Assessment",
            "Assess contingency plan testing to determine effectiveness and organizational readiness.",
            vec![
                criterion(
                    "CP-4-C1",
                    "Is the contingency plan tested at the required frequency?",
                    Some("Testing should occur at least annually or when significant changes occur."),
                    Some("Review test schedule and completion records."),
                    0.20,
                    Some("Test schedule, completion records"),
                ),
                criterion(
                    "CP-4-C2",
                    "Do tests use realistic scenarios?",
                    Some("Test scenarios should reflect likely disruption events."),
                    Some("Review test scenarios for realism."),
                    0.20,
                    Some("Test scenarios, exercise plans"),
                ),
                criterion(
                    "CP-4-C3",
                    "Are test results documented and analyzed?",
                    Some("Results should be documented with identified gaps and lessons learned."),
                    Some("Review test reports and analysis."),
                    0.20,
                    Some("Test reports, after-action reviews"),
                ),
                criterion(
                    "CP-4-C4",
                    "Are identified gaps addressed through corrective actions?",
                    Some("Problems identified during testing should be remediated."),
                    Some("Review corrective action tracking."),
                    0.20,
                    Some("Corrective action plans, remediation tracking"),
                ),
                criterion(
                    "CP-4-C5",
                    "Do tests involve key personnel and stakeholders?",
                    Some("Personnel with recovery responsibilities should participate in testing."),
                    Some("Review participant lists and roles."),
                    0.20,
                    Some("Participant lists, role assignments"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Test plan and scenarios", true),
                evidence_req(EvidenceType::File, "Test results documentation", true),
                evidence_req(EvidenceType::File, "After-action reports", true),
                evidence_req(EvidenceType::File, "Corrective action tracking", false),
            ],
        ),
        // NIST CP-10 - System Recovery and Reconstitution
        create_rubric(
            "nist_800_53",
            "CP-10",
            "System Recovery Assessment",
            "Assess provisions for system recovery and reconstitution to a known state.",
            vec![
                criterion(
                    "CP-10-C1",
                    "Are recovery procedures documented for critical systems?",
                    Some("Step-by-step recovery procedures should exist for each critical system."),
                    Some("Review recovery procedures documentation."),
                    0.25,
                    Some("Recovery procedures for critical systems"),
                ),
                criterion(
                    "CP-10-C2",
                    "Are recovery resources and capabilities adequate?",
                    Some("Resources including backups, spare equipment, and personnel should be available."),
                    Some("Review resource availability and testing."),
                    0.25,
                    Some("Resource inventory, availability testing"),
                ),
                criterion(
                    "CP-10-C3",
                    "Are recovery capabilities validated through testing?",
                    Some("Recovery capabilities should be tested to verify they work as intended."),
                    Some("Review recovery testing records."),
                    0.25,
                    Some("Recovery test records"),
                ),
                criterion(
                    "CP-10-C4",
                    "Are reconstitution procedures defined for returning to normal operations?",
                    Some("Procedures for transitioning from recovery to normal operations should be documented."),
                    Some("Review reconstitution procedures."),
                    0.25,
                    Some("Reconstitution procedures"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Recovery procedures", true),
                evidence_req(EvidenceType::File, "Recovery testing records", true),
                evidence_req(EvidenceType::File, "Resource inventory", false),
            ],
        ),
        // SOC2 A1.3 - Recovery Testing
        create_rubric(
            "soc2",
            "A1.3",
            "Recovery Testing Assessment",
            "Assess testing of recovery plan procedures supporting system recovery.",
            vec![
                criterion(
                    "A1.3-C1",
                    "Are recovery procedures documented?",
                    Some("Procedures should exist for recovering systems and data from disruptions."),
                    Some("Review recovery procedure documentation."),
                    0.25,
                    Some("Recovery procedures"),
                ),
                criterion(
                    "A1.3-C2",
                    "Is recovery testing performed regularly?",
                    Some("Testing should occur at least annually."),
                    Some("Review test schedule and records."),
                    0.25,
                    Some("Test schedule, testing records"),
                ),
                criterion(
                    "A1.3-C3",
                    "Do test results demonstrate recovery capability?",
                    Some("Tests should verify ability to recover within defined timeframes."),
                    Some("Review test results against recovery objectives."),
                    0.25,
                    Some("Test results, recovery time measurements"),
                ),
                criterion(
                    "A1.3-C4",
                    "Are test findings addressed through improvements?",
                    Some("Issues identified during testing should result in plan improvements."),
                    Some("Review improvement tracking and implementation."),
                    0.25,
                    Some("Improvement tracking, plan updates"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Recovery procedures", true),
                evidence_req(EvidenceType::File, "Annual test results", true),
                evidence_req(EvidenceType::File, "Improvement documentation", false),
            ],
        ),
    ]
}

// ============================================================================
// Risk Management Rubrics
// ============================================================================

fn risk_management_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // HIPAA 164.308(a)(1)(ii)(B) - Risk Management
        create_rubric(
            "hipaa",
            "164.308(a)(1)(ii)(B)",
            "HIPAA Risk Management Assessment",
            "Assess implementation of security measures to reduce risks to reasonable and appropriate levels.",
            vec![
                criterion(
                    "164.308a1iiB-C1",
                    "Is a risk management process implemented?",
                    Some("A formal process for identifying, assessing, and managing risks should exist."),
                    Some("Review risk management documentation."),
                    0.25,
                    Some("Risk management policy/procedures"),
                ),
                criterion(
                    "164.308a1iiB-C2",
                    "Are identified risks documented and tracked?",
                    Some("A risk register should document identified risks and their status."),
                    Some("Review risk register."),
                    0.25,
                    Some("Risk register"),
                ),
                criterion(
                    "164.308a1iiB-C3",
                    "Are security measures implemented to address risks?",
                    Some("Controls should be implemented to reduce risks to acceptable levels."),
                    Some("Review risk treatment plans and control implementation."),
                    0.25,
                    Some("Risk treatment plans, control mapping"),
                ),
                criterion(
                    "164.308a1iiB-C4",
                    "Is residual risk documented and accepted?",
                    Some("Remaining risk after controls should be documented and formally accepted."),
                    Some("Review residual risk documentation and acceptance records."),
                    0.25,
                    Some("Residual risk assessments, acceptance records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Risk management policy", true),
                evidence_req(EvidenceType::File, "Risk register", true),
                evidence_req(EvidenceType::File, "Risk treatment plans", true),
            ],
        ),
        // NIST RA-1 - Risk Assessment Policy and Procedures
        create_rubric(
            "nist_800_53",
            "RA-1",
            "Risk Assessment Policy Assessment",
            "Assess risk assessment policy and procedures documentation.",
            vec![
                criterion(
                    "RA-1-C1",
                    "Is a risk assessment policy established?",
                    Some("Policy should define the risk assessment methodology and requirements."),
                    Some("Review risk assessment policy."),
                    0.25,
                    Some("Risk assessment policy"),
                ),
                criterion(
                    "RA-1-C2",
                    "Are risk assessment procedures documented?",
                    Some("Procedures should guide the risk assessment process."),
                    Some("Review risk assessment procedures."),
                    0.25,
                    Some("Risk assessment procedures"),
                ),
                criterion(
                    "RA-1-C3",
                    "Are policy and procedures reviewed and updated regularly?",
                    Some("Annual review ensures documents remain current."),
                    Some("Check review dates and update history."),
                    0.25,
                    Some("Review records, version history"),
                ),
                criterion(
                    "RA-1-C4",
                    "Are policy and procedures disseminated appropriately?",
                    Some("Risk management personnel should have access to current documentation."),
                    Some("Review distribution and acknowledgment records."),
                    0.25,
                    Some("Distribution records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Risk assessment policy", true),
                evidence_req(EvidenceType::File, "Risk assessment procedures", true),
                evidence_req(EvidenceType::File, "Review records", true),
            ],
        ),
        // NIST RA-3 - Risk Assessment
        create_rubric(
            "nist_800_53",
            "RA-3",
            "Risk Assessment Conduct Assessment",
            "Assess conduct of risk assessments including likelihood and magnitude of harm.",
            vec![
                criterion(
                    "RA-3-C1",
                    "Are risk assessments conducted at the required frequency?",
                    Some("Assessments should occur at least annually or when significant changes occur."),
                    Some("Review assessment schedule and records."),
                    0.20,
                    Some("Assessment schedule, completion records"),
                ),
                criterion(
                    "RA-3-C2",
                    "Does the assessment methodology align with organizational approach?",
                    Some("A consistent methodology should be used for risk identification and analysis."),
                    Some("Review methodology documentation and application."),
                    0.20,
                    Some("Risk assessment methodology"),
                ),
                criterion(
                    "RA-3-C3",
                    "Are threats and vulnerabilities identified?",
                    Some("The assessment should identify relevant threats and system vulnerabilities."),
                    Some("Review threat and vulnerability identification."),
                    0.20,
                    Some("Threat analysis, vulnerability identification"),
                ),
                criterion(
                    "RA-3-C4",
                    "Are risk impacts and likelihoods assessed?",
                    Some("Risk should be quantified based on potential impact and likelihood."),
                    Some("Review risk scoring methodology and results."),
                    0.20,
                    Some("Risk scoring, impact analysis"),
                ),
                criterion(
                    "RA-3-C5",
                    "Are assessment results documented and communicated?",
                    Some("Results should be documented and shared with appropriate stakeholders."),
                    Some("Review assessment reports and distribution."),
                    0.20,
                    Some("Risk assessment reports, distribution records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Risk assessment methodology", true),
                evidence_req(EvidenceType::File, "Risk assessment report", true),
                evidence_req(EvidenceType::File, "Threat analysis documentation", false),
            ],
        ),
        // NIST RA-7 - Risk Response
        create_rubric(
            "nist_800_53",
            "RA-7",
            "Risk Response Assessment",
            "Assess response to findings from assessments, monitoring, and audits.",
            vec![
                criterion(
                    "RA-7-C1",
                    "Is a process for responding to identified risks established?",
                    Some("A formal process should guide risk response decisions and implementation."),
                    Some("Review risk response process documentation."),
                    0.25,
                    Some("Risk response policy/procedures"),
                ),
                criterion(
                    "RA-7-C2",
                    "Are risk responses documented and tracked?",
                    Some("Risk treatment decisions and implementation should be tracked."),
                    Some("Review risk response tracking."),
                    0.25,
                    Some("Risk treatment tracking, POA&M"),
                ),
                criterion(
                    "RA-7-C3",
                    "Are responses implemented within appropriate timeframes?",
                    Some("Response timelines should align with risk severity."),
                    Some("Review response timelines against requirements."),
                    0.25,
                    Some("Response timeline tracking"),
                ),
                criterion(
                    "RA-7-C4",
                    "Is response effectiveness verified?",
                    Some("Implemented responses should be verified to confirm risk reduction."),
                    Some("Review response verification activities."),
                    0.25,
                    Some("Response verification records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Risk response policy", true),
                evidence_req(EvidenceType::File, "Risk treatment tracking (POA&M)", true),
                evidence_req(EvidenceType::File, "Response verification records", false),
            ],
        ),
        // SOC2 CC3.1 - Risk Objectives
        create_rubric(
            "soc2",
            "CC3.1",
            "Risk Objectives Assessment",
            "Assess whether objectives are specified with sufficient clarity for risk identification.",
            vec![
                criterion(
                    "CC3.1-C1",
                    "Are security objectives clearly defined?",
                    Some("Objectives should be specific, measurable, and aligned with business goals."),
                    Some("Review security objectives documentation."),
                    0.25,
                    Some("Security objectives, strategic plan"),
                ),
                criterion(
                    "CC3.1-C2",
                    "Do objectives cover key security domains?",
                    Some("Objectives should address confidentiality, integrity, and availability."),
                    Some("Review objective coverage."),
                    0.25,
                    Some("Objective mapping to security domains"),
                ),
                criterion(
                    "CC3.1-C3",
                    "Are objectives communicated to stakeholders?",
                    Some("Relevant personnel should understand security objectives."),
                    Some("Review communication of objectives."),
                    0.25,
                    Some("Communication records, awareness materials"),
                ),
                criterion(
                    "CC3.1-C4",
                    "Are objectives reviewed and updated regularly?",
                    Some("Objectives should be reviewed at least annually."),
                    Some("Review objective update history."),
                    0.25,
                    Some("Objective review records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Security objectives documentation", true),
                evidence_req(EvidenceType::File, "Strategic security plan", false),
                evidence_req(EvidenceType::File, "Review records", true),
            ],
        ),
    ]
}

// ============================================================================
// Additional Rubrics (Governance, Privacy, Change Management, etc.)
// ============================================================================

fn governance_and_privacy_rubrics() -> Vec<ComplianceRubric> {
    vec![
        // SOC2 CC1.1 - Control Environment - Integrity and Ethics
        create_rubric(
            "soc2",
            "CC1.1",
            "Integrity and Ethics Assessment",
            "Assess the organization's commitment to integrity and ethical values.",
            vec![
                criterion(
                    "CC1.1-C1",
                    "Is a code of conduct established and communicated?",
                    Some("A code of conduct should define expected behaviors and ethical standards."),
                    Some("Review code of conduct documentation."),
                    0.25,
                    Some("Code of conduct document"),
                ),
                criterion(
                    "CC1.1-C2",
                    "Are ethics expectations reinforced through training?",
                    Some("Personnel should receive training on ethical expectations."),
                    Some("Review ethics training materials and records."),
                    0.25,
                    Some("Ethics training materials, completion records"),
                ),
                criterion(
                    "CC1.1-C3",
                    "Are mechanisms for reporting concerns available?",
                    Some("Confidential channels for reporting ethical concerns should exist."),
                    Some("Review reporting mechanisms and usage."),
                    0.25,
                    Some("Whistleblower policy, reporting channel documentation"),
                ),
                criterion(
                    "CC1.1-C4",
                    "Are ethics violations addressed consistently?",
                    Some("Violations should be investigated and addressed according to policy."),
                    Some("Review investigation and enforcement procedures."),
                    0.25,
                    Some("Investigation procedures, enforcement records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Code of conduct", true),
                evidence_req(EvidenceType::File, "Ethics training materials", true),
                evidence_req(EvidenceType::File, "Whistleblower policy", false),
            ],
        ),
        // SOC2 CC1.2 - Board Oversight
        create_rubric(
            "soc2",
            "CC1.2",
            "Board Oversight Assessment",
            "Assess board of directors independence and oversight of internal control.",
            vec![
                criterion(
                    "CC1.2-C1",
                    "Does the board exercise oversight of security?",
                    Some("The board should review and approve security strategies and significant risks."),
                    Some("Review board meeting minutes and security presentations."),
                    0.25,
                    Some("Board meeting minutes, security reports to board"),
                ),
                criterion(
                    "CC1.2-C2",
                    "Is security regularly reported to the board?",
                    Some("Security status should be reported to the board at least quarterly."),
                    Some("Review reporting schedule and content."),
                    0.25,
                    Some("Board security reports, reporting schedule"),
                ),
                criterion(
                    "CC1.2-C3",
                    "Does the board demonstrate security competence?",
                    Some("Board members should have or have access to security expertise."),
                    Some("Review board composition and expertise."),
                    0.25,
                    Some("Board member qualifications, expert advisors"),
                ),
                criterion(
                    "CC1.2-C4",
                    "Does the board review significant security incidents?",
                    Some("Major incidents should be escalated to and reviewed by the board."),
                    Some("Review incident escalation and board review records."),
                    0.25,
                    Some("Incident escalation policy, board review records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Board meeting minutes with security topics", true),
                evidence_req(EvidenceType::File, "Security reports to board", true),
                evidence_req(EvidenceType::Note, "Board security expertise description", false),
            ],
        ),
        // SOC2 P1.1 - Privacy Notice
        create_rubric(
            "soc2",
            "P1.1",
            "Privacy Notice Assessment",
            "Assess provision of notice about privacy practices.",
            vec![
                criterion(
                    "P1.1-C1",
                    "Is a privacy notice/policy published?",
                    Some("A privacy notice describing data practices should be publicly available."),
                    Some("Review privacy notice content and availability."),
                    0.25,
                    Some("Privacy notice/policy document"),
                ),
                criterion(
                    "P1.1-C2",
                    "Does the notice describe data collection practices?",
                    Some("The notice should explain what data is collected and why."),
                    Some("Review data collection descriptions."),
                    0.25,
                    Some("Privacy notice sections on data collection"),
                ),
                criterion(
                    "P1.1-C3",
                    "Does the notice describe data use and sharing?",
                    Some("How data is used and with whom it may be shared should be explained."),
                    Some("Review data use and sharing descriptions."),
                    0.25,
                    Some("Privacy notice sections on use and sharing"),
                ),
                criterion(
                    "P1.1-C4",
                    "Is the notice kept current?",
                    Some("The privacy notice should be updated when practices change."),
                    Some("Review notice update history."),
                    0.25,
                    Some("Privacy notice version history"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::Link, "Published privacy notice URL", true),
                evidence_req(EvidenceType::File, "Privacy notice document", true),
                evidence_req(EvidenceType::Note, "Last privacy notice update date", true),
            ],
        ),
        // NIST CM-3 - Configuration Change Control
        create_rubric(
            "nist_800_53",
            "CM-3",
            "Configuration Change Control Assessment",
            "Assess configuration-controlled changes to the system.",
            vec![
                criterion(
                    "CM-3-C1",
                    "Are configuration-controlled changes documented?",
                    Some("Types of changes requiring configuration control should be defined."),
                    Some("Review change control scope documentation."),
                    0.20,
                    Some("Change control policy, scope definition"),
                ),
                criterion(
                    "CM-3-C2",
                    "Are changes reviewed and approved before implementation?",
                    Some("Changes should go through a formal approval process."),
                    Some("Review change approval workflow and records."),
                    0.20,
                    Some("Change approval workflow, approval records"),
                ),
                criterion(
                    "CM-3-C3",
                    "Are changes tested before production implementation?",
                    Some("Changes should be tested to identify potential issues."),
                    Some("Review testing requirements and records."),
                    0.20,
                    Some("Test requirements, test records"),
                ),
                criterion(
                    "CM-3-C4",
                    "Are changes documented with rollback procedures?",
                    Some("Changes should be documented with plans to revert if needed."),
                    Some("Review change documentation requirements."),
                    0.20,
                    Some("Change documentation, rollback procedures"),
                ),
                criterion(
                    "CM-3-C5",
                    "Are emergency changes handled through an expedited process?",
                    Some("Emergency changes should follow a documented expedited process with post-implementation review."),
                    Some("Review emergency change procedures and records."),
                    0.20,
                    Some("Emergency change procedures, emergency change records"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Change control policy", true),
                evidence_req(EvidenceType::Screenshot, "Change management system", true),
                evidence_req(EvidenceType::File, "Sample change records", true),
            ],
        ),
        // PCI-DSS 6.2.1 - Secure Development Practices
        create_rubric(
            "pci_dss",
            "6.2.1",
            "Secure Development Practices Assessment",
            "Assess secure development of bespoke and custom software.",
            vec![
                criterion(
                    "6.2.1-C1",
                    "Are secure coding standards documented?",
                    Some("Standards should define secure coding requirements based on industry practices like OWASP."),
                    Some("Review secure coding standards documentation."),
                    0.20,
                    Some("Secure coding standards document"),
                ),
                criterion(
                    "6.2.1-C2",
                    "Are developers trained on secure coding practices?",
                    Some("Developers should receive training on secure coding and common vulnerabilities."),
                    Some("Review developer security training records."),
                    0.20,
                    Some("Developer training records, curriculum"),
                ),
                criterion(
                    "6.2.1-C3",
                    "Is code reviewed for security vulnerabilities?",
                    Some("Code should be reviewed (manually or automated) for security issues."),
                    Some("Review code review procedures and records."),
                    0.20,
                    Some("Code review procedures, SAST reports"),
                ),
                criterion(
                    "6.2.1-C4",
                    "Are security vulnerabilities addressed before release?",
                    Some("Identified vulnerabilities should be fixed before code is deployed to production."),
                    Some("Review vulnerability remediation in release process."),
                    0.20,
                    Some("Release criteria, vulnerability remediation records"),
                ),
                criterion(
                    "6.2.1-C5",
                    "Is the SDLC integrated with security activities?",
                    Some("Security activities should be integrated throughout the development lifecycle."),
                    Some("Review SDLC documentation for security integration."),
                    0.20,
                    Some("SDLC documentation, security gates"),
                ),
            ],
            vec![
                evidence_req(EvidenceType::File, "Secure coding standards", true),
                evidence_req(EvidenceType::File, "Developer security training records", true),
                evidence_req(EvidenceType::File, "Code review/SAST reports", true),
            ],
        ),
    ]
}

// ============================================================================
// Main Functions
// ============================================================================

/// Returns all default rubrics for non-automated compliance controls
pub fn get_default_rubrics() -> Vec<ComplianceRubric> {
    let mut rubrics = Vec::new();

    rubrics.extend(physical_security_rubrics());
    rubrics.extend(policy_and_documentation_rubrics());
    rubrics.extend(training_and_awareness_rubrics());
    rubrics.extend(access_control_reviews_rubrics());
    rubrics.extend(incident_response_rubrics());
    rubrics.extend(vendor_management_rubrics());
    rubrics.extend(business_continuity_rubrics());
    rubrics.extend(risk_management_rubrics());
    rubrics.extend(governance_and_privacy_rubrics());

    rubrics
}

/// Get a specific default rubric for a framework and control
pub fn get_default_rubric_for_control(framework_id: &str, control_id: &str) -> Option<ComplianceRubric> {
    get_default_rubrics()
        .into_iter()
        .find(|r| r.framework_id == framework_id && r.control_id == control_id)
}

/// Get all default rubrics for a specific category
pub fn get_rubrics_by_category(category: RubricCategory) -> Vec<ComplianceRubric> {
    match category {
        RubricCategory::PhysicalSecurity => physical_security_rubrics(),
        RubricCategory::PolicyAndDocumentation => policy_and_documentation_rubrics(),
        RubricCategory::TrainingAndAwareness => training_and_awareness_rubrics(),
        RubricCategory::AccessControlReviews => access_control_reviews_rubrics(),
        RubricCategory::IncidentResponse => incident_response_rubrics(),
        RubricCategory::VendorManagement => vendor_management_rubrics(),
        RubricCategory::BusinessContinuity => business_continuity_rubrics(),
        RubricCategory::RiskManagement => risk_management_rubrics(),
        RubricCategory::GovernanceAndOversight |
        RubricCategory::PrivacyCompliance |
        RubricCategory::ChangeManagement |
        RubricCategory::SecureDevelopment |
        RubricCategory::DataProtection => governance_and_privacy_rubrics(),
    }
}

/// Get all default rubrics for a specific framework
pub fn get_rubrics_by_framework(framework_id: &str) -> Vec<ComplianceRubric> {
    get_default_rubrics()
        .into_iter()
        .filter(|r| r.framework_id == framework_id)
        .collect()
}

/// Seeds the default rubrics into the database if they don't already exist
pub async fn seed_default_rubrics(pool: &SqlitePool) -> Result<usize, sqlx::Error> {
    let rubrics = get_default_rubrics();
    let mut inserted_count = 0;

    for rubric in rubrics {
        // Check if this rubric already exists (by framework_id + control_id + is_system_default)
        let existing: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT COUNT(*) as count
            FROM compliance_rubrics
            WHERE framework_id = ? AND control_id = ? AND is_system_default = 1
            "#
        )
        .bind(&rubric.framework_id)
        .bind(&rubric.control_id)
        .fetch_optional(pool)
        .await?;

        if existing.map(|(count,)| count).unwrap_or(0) > 0 {
            continue; // Skip if already exists
        }

        // Serialize the complex fields to JSON
        let criteria_json = serde_json::to_string(&rubric.assessment_criteria)
            .unwrap_or_else(|_| "[]".to_string());
        let rating_scale_json = serde_json::to_string(&rubric.rating_scale)
            .unwrap_or_else(|_| "{}".to_string());
        let evidence_requirements_json = serde_json::to_string(&rubric.evidence_requirements)
            .unwrap_or_else(|_| "[]".to_string());

        // Insert the rubric
        sqlx::query(
            r#"
            INSERT INTO compliance_rubrics (
                id, user_id, framework_id, control_id, name, description,
                assessment_criteria, rating_scale, evidence_requirements,
                is_system_default, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&rubric.id)
        .bind(&rubric.user_id)
        .bind(&rubric.framework_id)
        .bind(&rubric.control_id)
        .bind(&rubric.name)
        .bind(&rubric.description)
        .bind(&criteria_json)
        .bind(&rating_scale_json)
        .bind(&evidence_requirements_json)
        .bind(rubric.is_system_default)
        .bind(rubric.created_at.to_rfc3339())
        .bind(rubric.updated_at.to_rfc3339())
        .execute(pool)
        .await?;

        inserted_count += 1;
    }

    Ok(inserted_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_rubrics_not_empty() {
        let rubrics = get_default_rubrics();
        assert!(!rubrics.is_empty(), "Default rubrics should not be empty");
    }

    #[test]
    fn test_all_rubrics_have_criteria() {
        let rubrics = get_default_rubrics();
        for rubric in &rubrics {
            assert!(
                !rubric.assessment_criteria.is_empty(),
                "Rubric {} should have assessment criteria",
                rubric.id
            );
        }
    }

    #[test]
    fn test_all_rubrics_have_at_least_three_criteria() {
        let rubrics = get_default_rubrics();
        for rubric in &rubrics {
            assert!(
                rubric.assessment_criteria.len() >= 3,
                "Rubric {} should have at least 3 criteria, has {}",
                rubric.id,
                rubric.assessment_criteria.len()
            );
        }
    }

    #[test]
    fn test_all_rubrics_are_system_defaults() {
        let rubrics = get_default_rubrics();
        for rubric in &rubrics {
            assert!(
                rubric.is_system_default,
                "Rubric {} should be marked as system default",
                rubric.id
            );
        }
    }

    #[test]
    fn test_criteria_weights_sum_to_one() {
        let rubrics = get_default_rubrics();
        for rubric in &rubrics {
            let total_weight: f32 = rubric.assessment_criteria.iter()
                .map(|c| c.weight)
                .sum();
            assert!(
                (total_weight - 1.0).abs() < 0.01,
                "Rubric {} criteria weights should sum to 1.0, got {}",
                rubric.id,
                total_weight
            );
        }
    }

    #[test]
    fn test_get_rubric_for_specific_control() {
        let rubric = get_default_rubric_for_control("pci_dss", "12.1.1");
        assert!(rubric.is_some(), "Should find rubric for PCI-DSS 12.1.1");

        let rubric = rubric.unwrap();
        assert_eq!(rubric.framework_id, "pci_dss");
        assert_eq!(rubric.control_id, "12.1.1");
    }

    #[test]
    fn test_get_rubrics_by_framework() {
        let pci_rubrics = get_rubrics_by_framework("pci_dss");
        assert!(!pci_rubrics.is_empty(), "Should have PCI-DSS rubrics");

        for rubric in &pci_rubrics {
            assert_eq!(rubric.framework_id, "pci_dss");
        }
    }

    #[test]
    fn test_rubric_categories_covered() {
        let rubrics = get_default_rubrics();

        // Check we have rubrics for each framework
        let has_pci = rubrics.iter().any(|r| r.framework_id == "pci_dss");
        let has_hipaa = rubrics.iter().any(|r| r.framework_id == "hipaa");
        let has_nist = rubrics.iter().any(|r| r.framework_id == "nist_800_53");
        let has_soc2 = rubrics.iter().any(|r| r.framework_id == "soc2");

        assert!(has_pci, "Should have PCI-DSS rubrics");
        assert!(has_hipaa, "Should have HIPAA rubrics");
        assert!(has_nist, "Should have NIST 800-53 rubrics");
        assert!(has_soc2, "Should have SOC2 rubrics");
    }

    #[test]
    fn test_rating_scale_has_five_levels() {
        let scale = create_standard_rating_scale();
        assert_eq!(scale.levels.len(), 5, "Standard scale should have 5 levels");
    }

    #[test]
    fn test_evidence_requirements_not_empty() {
        let rubrics = get_default_rubrics();
        for rubric in &rubrics {
            assert!(
                !rubric.evidence_requirements.is_empty(),
                "Rubric {} should have evidence requirements",
                rubric.id
            );
        }
    }
}
