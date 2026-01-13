//! NIST Risk Management Framework (RMF) Controls
//!
//! The Risk Management Framework provides a disciplined, structured, and flexible
//! process for managing security and privacy risk. Based on NIST SP 800-37 Rev 2
//! and aligned with NIST SP 800-53 Rev 5 security controls.
//!
//! The RMF consists of 7 steps:
//! 1. Prepare - Essential activities to prepare for security and privacy risk management
//! 2. Categorize - Categorize the system and information based on impact analysis
//! 3. Select - Select an initial set of controls and tailor as needed
//! 4. Implement - Implement the controls and document deployment
//! 5. Assess - Assess controls to determine effectiveness
//! 6. Authorize - Authorize the system based on risk determination
//! 7. Monitor - Continuously monitor the system and maintain authorization

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of RMF controls in this module
pub const CONTROL_COUNT: usize = 63;

/// Get all RMF controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // STEP 1: PREPARE
        // Essential activities to prepare the organization to manage
        // security and privacy risks
        // ============================================================
        ComplianceControl {
            id: "RMF-P-1".to_string(),
            control_id: "P-1".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Risk Management Roles".to_string(),
            description: "Identify and assign individuals to specific roles associated with security and privacy risk management.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-1".to_string(),
                "NIST-PM-2".to_string(),
                "NIST-PM-10".to_string(),
            ],
            remediation_guidance: Some("Document and assign risk management roles including Authorizing Official (AO), System Owner, CISO, and ISSO.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-2".to_string(),
            control_id: "P-2".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Risk Management Strategy".to_string(),
            description: "Establish a risk management strategy for the organization including risk tolerance determination.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-2".to_string(),
                "NIST-PM-9".to_string(),
                "NIST-RA-1".to_string(),
            ],
            remediation_guidance: Some("Develop organizational risk management strategy defining risk tolerance, assumptions, constraints, and priorities.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-3".to_string(),
            control_id: "P-3".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Risk Assessment Organization".to_string(),
            description: "Conduct organization-level risk assessment to identify threats, vulnerabilities, and risks.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-3".to_string(),
                "NIST-RA-3".to_string(),
            ],
            remediation_guidance: Some("Perform enterprise-wide risk assessment considering organizational operations, assets, and individuals.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-4".to_string(),
            control_id: "P-4".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Organizationally-Tailored Control Baselines".to_string(),
            description: "Establish, document, and publish organization-wide tailored control baselines.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-4".to_string(),
                "NIST-PM-6".to_string(),
            ],
            remediation_guidance: Some("Create organizationally-tailored control baselines that supplement NIST 800-53 baselines.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-5".to_string(),
            control_id: "P-5".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Common Control Identification".to_string(),
            description: "Identify, document, and publish common controls available for inheritance.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-5".to_string(),
                "NIST-PM-5".to_string(),
            ],
            remediation_guidance: Some("Identify common controls that can be inherited by multiple systems to reduce duplication.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-6".to_string(),
            control_id: "P-6".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Impact-Level Prioritization".to_string(),
            description: "Prioritize systems requiring authorization based on mission/business importance and risk.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-6".to_string(),
                "NIST-PM-7".to_string(),
            ],
            remediation_guidance: Some("Develop system prioritization criteria based on criticality, risk level, and operational requirements.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-7".to_string(),
            control_id: "P-7".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Continuous Monitoring Strategy Organization".to_string(),
            description: "Develop and implement an organization-wide continuous monitoring strategy.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-7".to_string(),
                "NIST-CA-7".to_string(),
                "NIST-PM-14".to_string(),
            ],
            remediation_guidance: Some("Establish continuous monitoring strategy including metrics, frequencies, and reporting requirements.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-8".to_string(),
            control_id: "P-8".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Mission/Business Focus".to_string(),
            description: "Identify mission or business functions supported by the system.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-8".to_string(),
                "NIST-PM-11".to_string(),
            ],
            remediation_guidance: Some("Document mission/business processes and their dependencies on information systems.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-9".to_string(),
            control_id: "P-9".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "System Stakeholders".to_string(),
            description: "Identify stakeholders with security and privacy interests in the system.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-9".to_string(),
            ],
            remediation_guidance: Some("Identify and document all stakeholders including system owners, users, and business process owners.".to_string()),
        },
        ComplianceControl {
            id: "RMF-P-10".to_string(),
            control_id: "P-10".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Asset Identification".to_string(),
            description: "Identify assets requiring protection within the authorization boundary.".to_string(),
            category: "Prepare".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-P-10".to_string(),
                "NIST-CM-8".to_string(),
            ],
            remediation_guidance: Some("Maintain comprehensive inventory of hardware, software, and data assets within system boundary.".to_string()),
        },

        // ============================================================
        // STEP 2: CATEGORIZE
        // Categorize the system and information processed, stored,
        // and transmitted based on impact analysis
        // ============================================================
        ComplianceControl {
            id: "RMF-C-1".to_string(),
            control_id: "C-1".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "System Description".to_string(),
            description: "Document the characteristics of the system including its purpose, functions, and capabilities.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-C-1".to_string(),
                "NIST-PL-2".to_string(),
            ],
            remediation_guidance: Some("Create comprehensive system description documenting architecture, components, and interconnections.".to_string()),
        },
        ComplianceControl {
            id: "RMF-C-2".to_string(),
            control_id: "C-2".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Security Categorization".to_string(),
            description: "Categorize the system based on potential impact to confidentiality, integrity, and availability.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-C-2".to_string(),
                "NIST-RA-2".to_string(),
                "FIPS-199".to_string(),
            ],
            remediation_guidance: Some("Apply FIPS 199 methodology to determine system impact level (Low, Moderate, High) for C/I/A.".to_string()),
        },
        ComplianceControl {
            id: "RMF-C-3".to_string(),
            control_id: "C-3".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Security Categorization Review".to_string(),
            description: "Review and approve the security categorization with appropriate organizational officials.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-C-3".to_string(),
            ],
            remediation_guidance: Some("Obtain Authorizing Official review and approval of security categorization determination.".to_string()),
        },
        ComplianceControl {
            id: "RMF-C-4".to_string(),
            control_id: "C-4".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Information Type Identification".to_string(),
            description: "Identify information types processed, stored, or transmitted by the system.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-C-4".to_string(),
                "NIST-800-60".to_string(),
            ],
            remediation_guidance: Some("Map information types using NIST SP 800-60 guidance and determine impact levels per type.".to_string()),
        },
        ComplianceControl {
            id: "RMF-C-5".to_string(),
            control_id: "C-5".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Authorization Boundary".to_string(),
            description: "Define and document the authorization boundary for the system.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-C-5".to_string(),
                "NIST-CA-3".to_string(),
            ],
            remediation_guidance: Some("Clearly define system boundaries including all components, interconnections, and interfaces.".to_string()),
        },
        ComplianceControl {
            id: "RMF-C-6".to_string(),
            control_id: "C-6".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Privacy Impact Analysis".to_string(),
            description: "Analyze the system for privacy implications and document PII handling.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-C-6".to_string(),
                "NIST-AR-2".to_string(),
            ],
            remediation_guidance: Some("Conduct Privacy Impact Assessment (PIA) for systems handling personally identifiable information.".to_string()),
        },
        ComplianceControl {
            id: "RMF-C-7".to_string(),
            control_id: "C-7".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "System Registration".to_string(),
            description: "Register the system with appropriate organizational program/management offices.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-C-7".to_string(),
                "NIST-PM-4".to_string(),
            ],
            remediation_guidance: Some("Register system in enterprise architecture inventory and obtain tracking identifier.".to_string()),
        },
        ComplianceControl {
            id: "RMF-C-8".to_string(),
            control_id: "C-8".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Interconnection Analysis".to_string(),
            description: "Identify and document all system interconnections and data exchanges.".to_string(),
            category: "Categorize".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-3".to_string(),
                "NIST-AC-4".to_string(),
            ],
            remediation_guidance: Some("Document all external connections, data flows, and interface specifications.".to_string()),
        },

        // ============================================================
        // STEP 3: SELECT
        // Select, tailor, and document controls needed to protect
        // the system and organization
        // ============================================================
        ComplianceControl {
            id: "RMF-S-1".to_string(),
            control_id: "S-1".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Control Selection".to_string(),
            description: "Select controls from NIST SP 800-53 based on the security categorization.".to_string(),
            category: "Select".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-S-1".to_string(),
                "NIST-800-53".to_string(),
            ],
            remediation_guidance: Some("Select initial baseline controls from NIST 800-53 based on system impact level.".to_string()),
        },
        ComplianceControl {
            id: "RMF-S-2".to_string(),
            control_id: "S-2".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Control Tailoring".to_string(),
            description: "Tailor the selected control baseline by applying scoping guidance and compensating controls.".to_string(),
            category: "Select".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-S-2".to_string(),
                "NIST-PL-2".to_string(),
            ],
            remediation_guidance: Some("Apply tailoring guidance: identify common controls, add organization-specific controls, apply scoping considerations.".to_string()),
        },
        ComplianceControl {
            id: "RMF-S-3".to_string(),
            control_id: "S-3".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Control Allocation".to_string(),
            description: "Allocate controls to specific system components and determine implementation responsibility.".to_string(),
            category: "Select".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-S-3".to_string(),
            ],
            remediation_guidance: Some("Map controls to system components and designate system-specific vs. hybrid vs. common controls.".to_string()),
        },
        ComplianceControl {
            id: "RMF-S-4".to_string(),
            control_id: "S-4".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Documentation of Planned Controls".to_string(),
            description: "Document the planned implementation of controls in the security and privacy plans.".to_string(),
            category: "Select".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-S-4".to_string(),
                "NIST-PL-2".to_string(),
            ],
            remediation_guidance: Some("Create System Security Plan (SSP) documenting all selected controls and implementation approach.".to_string()),
        },
        ComplianceControl {
            id: "RMF-S-5".to_string(),
            control_id: "S-5".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Continuous Monitoring Strategy System".to_string(),
            description: "Develop a system-level continuous monitoring strategy based on organizational strategy.".to_string(),
            category: "Select".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-S-5".to_string(),
                "NIST-CA-7".to_string(),
            ],
            remediation_guidance: Some("Define system-specific monitoring approach including control assessment frequency and metrics.".to_string()),
        },
        ComplianceControl {
            id: "RMF-S-6".to_string(),
            control_id: "S-6".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Security and Privacy Plan Review".to_string(),
            description: "Review and approve the security and privacy plans prior to implementation.".to_string(),
            category: "Select".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-S-6".to_string(),
            ],
            remediation_guidance: Some("Obtain AO review and approval of security and privacy plans before proceeding to implementation.".to_string()),
        },
        ComplianceControl {
            id: "RMF-S-7".to_string(),
            control_id: "S-7".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Risk Assessment System".to_string(),
            description: "Conduct system-level risk assessment to identify threats and vulnerabilities.".to_string(),
            category: "Select".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-S-7".to_string(),
                "NIST-RA-3".to_string(),
                "NIST-RA-5".to_string(),
            ],
            remediation_guidance: Some("Perform system-specific risk assessment including vulnerability scanning and threat analysis.".to_string()),
        },

        // ============================================================
        // STEP 4: IMPLEMENT
        // Implement the controls and document how controls are deployed
        // ============================================================
        ComplianceControl {
            id: "RMF-I-1".to_string(),
            control_id: "I-1".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Control Implementation".to_string(),
            description: "Implement the controls specified in the security and privacy plans.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-I-1".to_string(),
                "NIST-SA-3".to_string(),
            ],
            remediation_guidance: Some("Deploy and configure security controls according to SSP specifications and security engineering practices.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-2".to_string(),
            control_id: "I-2".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Control Documentation".to_string(),
            description: "Document the implementation of controls including configuration settings and parameters.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-I-2".to_string(),
                "NIST-CM-6".to_string(),
            ],
            remediation_guidance: Some("Document actual control implementation details, deviations from plan, and configuration parameters.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-3".to_string(),
            control_id: "I-3".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Security Architecture Implementation".to_string(),
            description: "Implement the security architecture according to security engineering principles.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-I-3".to_string(),
                "NIST-SA-8".to_string(),
                "NIST-SC-7".to_string(),
            ],
            remediation_guidance: Some("Deploy defense-in-depth architecture including network segmentation, boundary protection, and access controls.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-4".to_string(),
            control_id: "I-4".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Access Control Implementation".to_string(),
            description: "Implement access control mechanisms as specified in the security plan.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-2".to_string(),
                "NIST-AC-3".to_string(),
                "NIST-AC-6".to_string(),
            ],
            remediation_guidance: Some("Configure identity management, authentication, and authorization controls per SSP requirements.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-5".to_string(),
            control_id: "I-5".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Audit and Accountability Implementation".to_string(),
            description: "Implement audit logging and accountability mechanisms.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-2".to_string(),
                "NIST-AU-3".to_string(),
                "NIST-AU-12".to_string(),
            ],
            remediation_guidance: Some("Deploy comprehensive audit logging covering authentication, authorization, and system events.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-6".to_string(),
            control_id: "I-6".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Configuration Management Implementation".to_string(),
            description: "Implement configuration management controls and establish baselines.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-2".to_string(),
                "NIST-CM-6".to_string(),
                "NIST-CM-7".to_string(),
            ],
            remediation_guidance: Some("Establish secure configuration baselines and implement configuration change control processes.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-7".to_string(),
            control_id: "I-7".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Incident Response Capability".to_string(),
            description: "Implement incident response capabilities as specified in the security plan.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-1".to_string(),
                "NIST-IR-4".to_string(),
                "NIST-IR-8".to_string(),
            ],
            remediation_guidance: Some("Deploy incident detection, response tools, and establish incident handling procedures.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-8".to_string(),
            control_id: "I-8".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Contingency Planning Implementation".to_string(),
            description: "Implement contingency planning controls including backup and recovery capabilities.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CP-2".to_string(),
                "NIST-CP-9".to_string(),
                "NIST-CP-10".to_string(),
            ],
            remediation_guidance: Some("Implement backup systems, disaster recovery capabilities, and business continuity procedures.".to_string()),
        },
        ComplianceControl {
            id: "RMF-I-9".to_string(),
            control_id: "I-9".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Cryptographic Protection Implementation".to_string(),
            description: "Implement cryptographic mechanisms to protect data confidentiality and integrity.".to_string(),
            category: "Implement".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-8".to_string(),
                "NIST-SC-13".to_string(),
                "NIST-SC-28".to_string(),
            ],
            remediation_guidance: Some("Deploy FIPS-validated cryptography for data at rest and in transit with proper key management.".to_string()),
        },

        // ============================================================
        // STEP 5: ASSESS
        // Assess the controls to determine if they are implemented
        // correctly and producing desired outcomes
        // ============================================================
        ComplianceControl {
            id: "RMF-A-1".to_string(),
            control_id: "A-1".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Assessment Preparation".to_string(),
            description: "Prepare for security and privacy control assessment by developing assessment plans.".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-A-1".to_string(),
                "NIST-CA-2".to_string(),
            ],
            remediation_guidance: Some("Develop Security Assessment Plan (SAP) defining scope, methodology, and assessment procedures.".to_string()),
        },
        ComplianceControl {
            id: "RMF-A-2".to_string(),
            control_id: "A-2".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Assessor Selection".to_string(),
            description: "Select qualified assessors with independence appropriate to the assessment.".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-A-2".to_string(),
                "NIST-CA-2".to_string(),
            ],
            remediation_guidance: Some("Engage independent assessors meeting required qualifications and independence criteria.".to_string()),
        },
        ComplianceControl {
            id: "RMF-A-3".to_string(),
            control_id: "A-3".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Control Assessment".to_string(),
            description: "Conduct assessment of security and privacy controls using approved assessment procedures.".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-A-3".to_string(),
                "NIST-CA-2".to_string(),
                "NIST-800-53A".to_string(),
            ],
            remediation_guidance: Some("Execute control assessment using examine, interview, and test procedures per NIST 800-53A.".to_string()),
        },
        ComplianceControl {
            id: "RMF-A-4".to_string(),
            control_id: "A-4".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Security Assessment Report".to_string(),
            description: "Document assessment findings in a Security Assessment Report (SAR).".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-A-4".to_string(),
                "NIST-CA-2".to_string(),
            ],
            remediation_guidance: Some("Produce comprehensive SAR documenting control effectiveness, weaknesses, and recommendations.".to_string()),
        },
        ComplianceControl {
            id: "RMF-A-5".to_string(),
            control_id: "A-5".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Vulnerability Assessment".to_string(),
            description: "Conduct vulnerability scanning and penetration testing as part of assessment.".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-5".to_string(),
                "NIST-CA-8".to_string(),
            ],
            remediation_guidance: Some("Perform automated vulnerability scanning and authorized penetration testing of system.".to_string()),
        },
        ComplianceControl {
            id: "RMF-A-6".to_string(),
            control_id: "A-6".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Remediation Actions".to_string(),
            description: "Develop and implement remediation actions for identified deficiencies.".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-A-5".to_string(),
                "NIST-CA-5".to_string(),
            ],
            remediation_guidance: Some("Create Plan of Action and Milestones (POA&M) with remediation timeline and resource allocation.".to_string()),
        },
        ComplianceControl {
            id: "RMF-A-7".to_string(),
            control_id: "A-7".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Plan of Action and Milestones".to_string(),
            description: "Develop POA&M documenting remediation plans for control deficiencies.".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-A-6".to_string(),
                "NIST-CA-5".to_string(),
            ],
            remediation_guidance: Some("Document each weakness with risk level, remediation approach, milestones, and completion dates.".to_string()),
        },
        ComplianceControl {
            id: "RMF-A-8".to_string(),
            control_id: "A-8".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Technical Testing".to_string(),
            description: "Conduct technical testing including configuration compliance and security function verification.".to_string(),
            category: "Assess".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-2".to_string(),
                "NIST-CM-6".to_string(),
            ],
            remediation_guidance: Some("Perform automated compliance scanning and security configuration verification.".to_string()),
        },

        // ============================================================
        // STEP 6: AUTHORIZE
        // Authorize system operation based on determination of risk
        // ============================================================
        ComplianceControl {
            id: "RMF-R-1".to_string(),
            control_id: "R-1".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Authorization Package".to_string(),
            description: "Prepare the authorization package for submission to the Authorizing Official.".to_string(),
            category: "Authorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-R-1".to_string(),
                "NIST-CA-6".to_string(),
            ],
            remediation_guidance: Some("Compile authorization package including SSP, SAR, and POA&M for AO review.".to_string()),
        },
        ComplianceControl {
            id: "RMF-R-2".to_string(),
            control_id: "R-2".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Risk Determination".to_string(),
            description: "Determine the risk to organizational operations, assets, and individuals.".to_string(),
            category: "Authorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-R-2".to_string(),
                "NIST-RA-3".to_string(),
            ],
            remediation_guidance: Some("Analyze residual risk considering control effectiveness, vulnerabilities, and threat environment.".to_string()),
        },
        ComplianceControl {
            id: "RMF-R-3".to_string(),
            control_id: "R-3".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Risk Response".to_string(),
            description: "Identify and implement appropriate risk response for determined risks.".to_string(),
            category: "Authorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-R-3".to_string(),
                "NIST-RA-7".to_string(),
            ],
            remediation_guidance: Some("Select risk response: accept, avoid, mitigate, share, or transfer for each identified risk.".to_string()),
        },
        ComplianceControl {
            id: "RMF-R-4".to_string(),
            control_id: "R-4".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Authorization Decision".to_string(),
            description: "Obtain authorization decision from the Authorizing Official.".to_string(),
            category: "Authorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-R-4".to_string(),
                "NIST-CA-6".to_string(),
            ],
            remediation_guidance: Some("Submit authorization package and obtain AO decision: Authorization to Operate (ATO), Denial, or Interim ATO.".to_string()),
        },
        ComplianceControl {
            id: "RMF-R-5".to_string(),
            control_id: "R-5".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Authorization to Operate".to_string(),
            description: "Document and communicate the authorization decision and any conditions.".to_string(),
            category: "Authorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-R-5".to_string(),
                "NIST-CA-6".to_string(),
            ],
            remediation_guidance: Some("Issue formal ATO letter specifying authorization period, conditions, and ongoing requirements.".to_string()),
        },
        ComplianceControl {
            id: "RMF-R-6".to_string(),
            control_id: "R-6".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Interconnection Agreements".to_string(),
            description: "Establish and document system interconnection agreements.".to_string(),
            category: "Authorize".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-3".to_string(),
            ],
            remediation_guidance: Some("Execute Interconnection Security Agreements (ISA) and Memoranda of Understanding (MOU) for system connections.".to_string()),
        },
        ComplianceControl {
            id: "RMF-R-7".to_string(),
            control_id: "R-7".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Authorization Maintenance".to_string(),
            description: "Maintain the currency of the authorization through ongoing activities.".to_string(),
            category: "Authorize".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-R-6".to_string(),
                "NIST-CA-6".to_string(),
            ],
            remediation_guidance: Some("Conduct reauthorization activities per organizational policy and authorization terms.".to_string()),
        },

        // ============================================================
        // STEP 7: MONITOR
        // Continuously monitor the system and the environment
        // ============================================================
        ComplianceControl {
            id: "RMF-M-1".to_string(),
            control_id: "M-1".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "System Monitoring".to_string(),
            description: "Implement continuous monitoring of the system and its environment of operation.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-1".to_string(),
                "NIST-CA-7".to_string(),
                "NIST-SI-4".to_string(),
            ],
            remediation_guidance: Some("Deploy continuous monitoring capabilities including SIEM, IDS/IPS, and automated assessment tools.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-2".to_string(),
            control_id: "M-2".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Ongoing Control Assessment".to_string(),
            description: "Assess controls on an ongoing basis per the continuous monitoring strategy.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-2".to_string(),
                "NIST-CA-2".to_string(),
                "NIST-CA-7".to_string(),
            ],
            remediation_guidance: Some("Perform ongoing automated and manual control assessments per defined monitoring frequencies.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-3".to_string(),
            control_id: "M-3".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Ongoing Risk Assessment".to_string(),
            description: "Conduct ongoing risk assessments to identify new threats and vulnerabilities.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-3".to_string(),
                "NIST-RA-3".to_string(),
                "NIST-RA-5".to_string(),
            ],
            remediation_guidance: Some("Perform continuous vulnerability scanning and threat intelligence monitoring.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-4".to_string(),
            control_id: "M-4".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "POA&M Maintenance".to_string(),
            description: "Update POA&M based on continuous monitoring findings and assessment results.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-4".to_string(),
                "NIST-CA-5".to_string(),
            ],
            remediation_guidance: Some("Track POA&M items, update status, and add new findings from continuous monitoring activities.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-5".to_string(),
            control_id: "M-5".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Security Status Reporting".to_string(),
            description: "Report security and privacy status to organizational officials per reporting requirements.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-5".to_string(),
                "NIST-CA-7".to_string(),
            ],
            remediation_guidance: Some("Generate and deliver security status reports to AO and stakeholders per defined frequency.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-6".to_string(),
            control_id: "M-6".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Ongoing Risk Response".to_string(),
            description: "Respond to identified risks based on continuous monitoring and assessment results.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-6".to_string(),
                "NIST-RA-7".to_string(),
            ],
            remediation_guidance: Some("Implement timely risk response actions for newly identified vulnerabilities and threats.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-7".to_string(),
            control_id: "M-7".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "SSP Update".to_string(),
            description: "Update security and privacy plans to reflect system and environment changes.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-7".to_string(),
                "NIST-PL-2".to_string(),
            ],
            remediation_guidance: Some("Review and update SSP at least annually and upon significant system changes.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-8".to_string(),
            control_id: "M-8".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Change Management".to_string(),
            description: "Manage changes to the system through the change management process.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-3".to_string(),
                "NIST-CM-4".to_string(),
            ],
            remediation_guidance: Some("Implement formal change control process with security impact analysis for all changes.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-9".to_string(),
            control_id: "M-9".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Configuration Control".to_string(),
            description: "Monitor and control configuration changes to maintain security posture.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-2".to_string(),
                "NIST-CM-6".to_string(),
            ],
            remediation_guidance: Some("Monitor configuration drift and enforce baseline compliance through automated tools.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-10".to_string(),
            control_id: "M-10".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Threat Intelligence Integration".to_string(),
            description: "Integrate threat intelligence into continuous monitoring activities.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-PM-16".to_string(),
                "NIST-SI-5".to_string(),
            ],
            remediation_guidance: Some("Subscribe to threat intelligence feeds and integrate indicators into monitoring systems.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-11".to_string(),
            control_id: "M-11".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Security Information Sharing".to_string(),
            description: "Share security information with appropriate parties per sharing agreements.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PM-15".to_string(),
                "NIST-SI-5".to_string(),
            ],
            remediation_guidance: Some("Participate in information sharing communities and report security events as required.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-12".to_string(),
            control_id: "M-12".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Authorization Termination".to_string(),
            description: "Decommission the system when authorization is terminated or system is retired.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-37-M-8".to_string(),
                "NIST-MP-6".to_string(),
            ],
            remediation_guidance: Some("Execute system decommissioning procedures including data sanitization and documentation retention.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-13".to_string(),
            control_id: "M-13".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Incident Response Monitoring".to_string(),
            description: "Monitor for and respond to security incidents affecting the system.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-4".to_string(),
                "NIST-IR-5".to_string(),
                "NIST-IR-6".to_string(),
            ],
            remediation_guidance: Some("Maintain incident detection and response capabilities with documented procedures.".to_string()),
        },
        ComplianceControl {
            id: "RMF-M-14".to_string(),
            control_id: "M-14".to_string(),
            framework: ComplianceFramework::Rmf,
            title: "Supply Chain Risk Monitoring".to_string(),
            description: "Monitor supply chain risks affecting system components and services.".to_string(),
            category: "Monitor".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-SR-1".to_string(),
                "NIST-SR-6".to_string(),
            ],
            remediation_guidance: Some("Monitor vendor security posture and supply chain threats affecting system components.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant RMF controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Risk assessment related vulnerabilities
    if title_lower.contains("vulnerability")
        || title_lower.contains("cve")
        || title_lower.contains("exploit")
    {
        mappings.push(("RMF-S-7".to_string(), Severity::High)); // System Risk Assessment
        mappings.push(("RMF-A-5".to_string(), Severity::High)); // Vulnerability Assessment
        mappings.push(("RMF-M-3".to_string(), Severity::High)); // Ongoing Risk Assessment
    }

    // Access control vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("authentication")
        || title_lower.contains("privilege escalation")
    {
        mappings.push(("RMF-I-4".to_string(), Severity::Critical)); // Access Control Implementation
        mappings.push(("RMF-M-1".to_string(), Severity::High)); // System Monitoring
    }

    // Authentication and credential issues
    if title_lower.contains("weak password")
        || title_lower.contains("default credential")
        || title_lower.contains("authentication bypass")
    {
        mappings.push(("RMF-I-4".to_string(), Severity::Critical)); // Access Control Implementation
        mappings.push(("RMF-A-3".to_string(), Severity::High)); // Control Assessment
    }

    // Configuration management issues
    if title_lower.contains("misconfigur")
        || title_lower.contains("insecure config")
        || title_lower.contains("hardening")
    {
        mappings.push(("RMF-I-6".to_string(), Severity::High)); // Configuration Management Implementation
        mappings.push(("RMF-M-9".to_string(), Severity::High)); // Configuration Control
    }

    // Encryption and cryptographic vulnerabilities
    if title_lower.contains("unencrypted")
        || title_lower.contains("weak encryption")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("cryptograph")
    {
        mappings.push(("RMF-I-9".to_string(), Severity::High)); // Cryptographic Protection Implementation
    }

    // Audit and logging issues
    if title_lower.contains("no logging")
        || title_lower.contains("audit")
        || title_lower.contains("log")
    {
        mappings.push(("RMF-I-5".to_string(), Severity::Medium)); // Audit and Accountability Implementation
        mappings.push(("RMF-M-1".to_string(), Severity::Medium)); // System Monitoring
    }

    // Patch management and outdated software
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("unsupported")
    {
        mappings.push(("RMF-M-6".to_string(), Severity::High)); // Ongoing Risk Response
        mappings.push(("RMF-M-4".to_string(), Severity::High)); // POA&M Maintenance
    }

    // Network security issues
    if title_lower.contains("firewall")
        || title_lower.contains("network")
        || title_lower.contains("segmentation")
        || title_lower.contains("boundary")
    {
        mappings.push(("RMF-I-3".to_string(), Severity::High)); // Security Architecture Implementation
        mappings.push(("RMF-C-5".to_string(), Severity::Medium)); // Authorization Boundary
    }

    // Incident response related
    if title_lower.contains("incident")
        || title_lower.contains("breach")
        || title_lower.contains("compromise")
    {
        mappings.push(("RMF-I-7".to_string(), Severity::High)); // Incident Response Capability
        mappings.push(("RMF-M-13".to_string(), Severity::High)); // Incident Response Monitoring
    }

    // Backup and recovery issues
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
        || title_lower.contains("disaster")
    {
        mappings.push(("RMF-I-8".to_string(), Severity::High)); // Contingency Planning Implementation
    }

    // Change management issues
    if title_lower.contains("unauthorized change")
        || title_lower.contains("change control")
    {
        mappings.push(("RMF-M-8".to_string(), Severity::High)); // Change Management
    }

    // Asset inventory issues
    if title_lower.contains("unknown device")
        || title_lower.contains("unauthorized asset")
        || title_lower.contains("rogue")
    {
        mappings.push(("RMF-P-10".to_string(), Severity::Medium)); // Asset Identification
    }

    // Security monitoring gaps
    if title_lower.contains("unmonitored")
        || title_lower.contains("no detection")
        || title_lower.contains("blind spot")
    {
        mappings.push(("RMF-M-1".to_string(), Severity::High)); // System Monitoring
        mappings.push(("RMF-M-2".to_string(), Severity::Medium)); // Ongoing Control Assessment
    }

    // Threat intelligence related
    if title_lower.contains("threat")
        || title_lower.contains("ioc")
        || title_lower.contains("indicator")
    {
        mappings.push(("RMF-M-10".to_string(), Severity::High)); // Threat Intelligence Integration
    }

    // Supply chain issues
    if title_lower.contains("supply chain")
        || title_lower.contains("third party")
        || title_lower.contains("vendor")
    {
        mappings.push(("RMF-M-14".to_string(), Severity::Medium)); // Supply Chain Risk Monitoring
    }

    // Documentation gaps
    if title_lower.contains("undocumented")
        || title_lower.contains("missing documentation")
    {
        mappings.push(("RMF-I-2".to_string(), Severity::Low)); // Control Documentation
        mappings.push(("RMF-M-7".to_string(), Severity::Low)); // SSP Update
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
    fn test_all_rmf_steps_covered() {
        let controls = get_controls();
        let categories: Vec<&str> = controls.iter().map(|c| c.category.as_str()).collect();

        assert!(categories.contains(&"Prepare"));
        assert!(categories.contains(&"Categorize"));
        assert!(categories.contains(&"Select"));
        assert!(categories.contains(&"Implement"));
        assert!(categories.contains(&"Assess"));
        assert!(categories.contains(&"Authorize"));
        assert!(categories.contains(&"Monitor"));
    }

    #[test]
    fn test_control_ids_unique() {
        let controls = get_controls();
        let mut ids: Vec<&str> = controls.iter().map(|c| c.id.as_str()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "Duplicate control IDs found");
    }

    #[test]
    fn test_framework_is_rmf() {
        let controls = get_controls();
        for control in &controls {
            assert_eq!(control.framework, ComplianceFramework::Rmf);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("SQL Injection vulnerability CVE-2023-1234", Some("CVE-2023-1234"), None, None);
        assert!(!mappings.is_empty());

        let control_ids: Vec<&str> = mappings.iter().map(|(id, _)| id.as_str()).collect();
        assert!(control_ids.contains(&"RMF-A-5")); // Vulnerability Assessment
    }

    #[test]
    fn test_cross_references_exist() {
        let controls = get_controls();
        let controls_with_refs = controls.iter().filter(|c| !c.cross_references.is_empty()).count();
        assert!(controls_with_refs > 50, "Most controls should have cross-references");
    }

    #[test]
    fn test_remediation_guidance_exists() {
        let controls = get_controls();
        let controls_with_guidance = controls.iter().filter(|c| c.remediation_guidance.is_some()).count();
        assert_eq!(controls_with_guidance, CONTROL_COUNT, "All controls should have remediation guidance");
    }
}
