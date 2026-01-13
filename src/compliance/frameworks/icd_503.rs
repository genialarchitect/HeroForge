//! ICD 503 Controls - Intelligence Community Directive 503
//!
//! Security risk management controls for Intelligence Community IT systems.
//! ICD 503 establishes the security policy and procedures for IC IT systems
//! and implements the IC Risk Management Framework (RMF) process.
//!
//! The directive covers six key phases:
//! 1. Security Categorization - Classify systems based on impact levels
//! 2. Control Selection - Choose appropriate security controls
//! 3. Control Implementation - Deploy and configure controls
//! 4. Security Assessment - Evaluate control effectiveness
//! 5. Authorization - Grant authority to operate (ATO)
//! 6. Continuous Monitoring - Ongoing security status tracking
//!
//! Cross-references: NIST 800-53 Rev 5, CNSSI 1253

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of ICD 503 controls in this module
pub const CONTROL_COUNT: usize = 50;

/// Get all ICD 503 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // Phase 1: Security Categorization Controls (SC)
        // ============================================================
        ComplianceControl {
            id: "ICD503-SC-1".to_string(),
            control_id: "SC-1".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Information Type Identification".to_string(),
            description: "Identify and document all information types processed, stored, or transmitted by the system based on IC Information Type Catalog.".to_string(),
            category: "Security Categorization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-2".to_string(),
                "CNSSI-1253-CAT-1".to_string(),
            ],
            remediation_guidance: Some("Complete information type identification using the IC Information Type Catalog and document in the system security plan.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SC-2".to_string(),
            control_id: "SC-2".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Security Impact Level Determination".to_string(),
            description: "Determine the security impact level (confidentiality, integrity, availability) for each information type based on potential harm to national security.".to_string(),
            category: "Security Categorization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-2".to_string(),
                "CNSSI-1253-CAT-2".to_string(),
            ],
            remediation_guidance: Some("Apply CNSSI 1253 methodology to determine impact levels considering national security implications.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SC-3".to_string(),
            control_id: "SC-3".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "System Security Categorization".to_string(),
            description: "Categorize the overall system based on the highest impact level of information types processed, establishing the system security baseline.".to_string(),
            category: "Security Categorization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-2".to_string(),
                "CNSSI-1253-CAT-3".to_string(),
            ],
            remediation_guidance: Some("Document system categorization in accordance with CNSSI 1253 and obtain AO approval.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SC-4".to_string(),
            control_id: "SC-4".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Categorization Review and Approval".to_string(),
            description: "Obtain Authorizing Official (AO) review and approval of the system security categorization before proceeding with control selection.".to_string(),
            category: "Security Categorization".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CNSSI-1253-CAT-4".to_string(),
            ],
            remediation_guidance: Some("Submit categorization documentation to the AO for formal approval and maintain approval artifacts.".to_string()),
        },

        // ============================================================
        // Phase 2: Control Selection Controls (CS)
        // ============================================================
        ComplianceControl {
            id: "ICD503-CS-1".to_string(),
            control_id: "CS-1".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Baseline Control Selection".to_string(),
            description: "Select the initial control baseline corresponding to the system security categorization level from CNSSI 1253.".to_string(),
            category: "Control Selection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PM-1".to_string(),
                "CNSSI-1253-SEL-1".to_string(),
            ],
            remediation_guidance: Some("Apply CNSSI 1253 control baselines based on system categorization level (Low, Moderate, High).".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CS-2".to_string(),
            control_id: "CS-2".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Control Tailoring".to_string(),
            description: "Tailor baseline controls by applying scoping guidance, selecting compensating controls, and adding supplemental controls based on organizational requirements.".to_string(),
            category: "Control Selection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PM-1".to_string(),
                "CNSSI-1253-SEL-2".to_string(),
            ],
            remediation_guidance: Some("Document control tailoring decisions with rationale and obtain AO concurrence.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CS-3".to_string(),
            control_id: "CS-3".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Overlay Application".to_string(),
            description: "Apply applicable IC, DoD, or organizational security control overlays to address specialized requirements.".to_string(),
            category: "Control Selection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "CNSSI-1253-SEL-3".to_string(),
            ],
            remediation_guidance: Some("Identify and apply required overlays (e.g., privacy, cross-domain, space systems) per mission requirements.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CS-4".to_string(),
            control_id: "CS-4".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Control Documentation".to_string(),
            description: "Document all selected controls, tailoring decisions, and overlays in the System Security Plan (SSP).".to_string(),
            category: "Control Selection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PL-2".to_string(),
                "CNSSI-1253-SEL-4".to_string(),
            ],
            remediation_guidance: Some("Maintain comprehensive SSP with all control selections, implementation details, and tailoring rationale.".to_string()),
        },

        // ============================================================
        // Phase 3: Control Implementation Controls (CI)
        // ============================================================
        ComplianceControl {
            id: "ICD503-CI-1".to_string(),
            control_id: "CI-1".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Access Control Implementation".to_string(),
            description: "Implement access control mechanisms ensuring need-to-know enforcement, multi-factor authentication, and least privilege for IC systems.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-2".to_string(),
                "NIST-AC-3".to_string(),
                "NIST-IA-2".to_string(),
                "CNSSI-1253-AC-2".to_string(),
            ],
            remediation_guidance: Some("Deploy identity and access management (IAM) with PKI/CAC authentication and role-based access control.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-2".to_string(),
            control_id: "CI-2".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Audit and Accountability Implementation".to_string(),
            description: "Implement comprehensive audit logging capturing all security-relevant events with tamper-evident protection.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-2".to_string(),
                "NIST-AU-3".to_string(),
                "NIST-AU-9".to_string(),
                "CNSSI-1253-AU-2".to_string(),
            ],
            remediation_guidance: Some("Configure comprehensive audit logging per IC ITE standards with secure log forwarding to SIEM.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-3".to_string(),
            control_id: "CI-3".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Encryption Implementation".to_string(),
            description: "Implement NSA-approved cryptography for data at rest and in transit on all IC systems handling classified information.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-8".to_string(),
                "NIST-SC-13".to_string(),
                "NIST-SC-28".to_string(),
                "CNSSI-1253-SC-13".to_string(),
            ],
            remediation_guidance: Some("Deploy NSA-approved Type 1 encryption for classified systems or Suite B/CNSA algorithms as appropriate.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-4".to_string(),
            control_id: "CI-4".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Boundary Protection Implementation".to_string(),
            description: "Implement network boundary protections including firewalls, guards, and cross-domain solutions as required.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "NIST-AC-4".to_string(),
                "CNSSI-1253-SC-7".to_string(),
            ],
            remediation_guidance: Some("Deploy NSA-evaluated boundary protection devices and cross-domain solutions per IC standards.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-5".to_string(),
            control_id: "CI-5".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Malware Protection Implementation".to_string(),
            description: "Implement anti-malware capabilities with real-time scanning and automatic signature updates across all endpoints.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SI-3".to_string(),
                "CNSSI-1253-SI-3".to_string(),
            ],
            remediation_guidance: Some("Deploy IC-approved endpoint protection solutions with centralized management and reporting.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-6".to_string(),
            control_id: "CI-6".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Configuration Management Implementation".to_string(),
            description: "Implement configuration management processes ensuring secure baseline configurations and change control.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-2".to_string(),
                "NIST-CM-6".to_string(),
                "CNSSI-1253-CM-2".to_string(),
            ],
            remediation_guidance: Some("Apply DISA STIGs and IC-specific hardening guidance; implement automated compliance checking.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-7".to_string(),
            control_id: "CI-7".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Vulnerability Management Implementation".to_string(),
            description: "Implement vulnerability scanning and remediation processes with defined timelines based on severity.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-5".to_string(),
                "NIST-SI-2".to_string(),
                "CNSSI-1253-RA-5".to_string(),
            ],
            remediation_guidance: Some("Deploy IC-approved vulnerability scanners; remediate critical findings within 30 days.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-8".to_string(),
            control_id: "CI-8".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Incident Response Implementation".to_string(),
            description: "Implement incident response capabilities with defined procedures for detection, reporting, and remediation.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-1".to_string(),
                "NIST-IR-4".to_string(),
                "CNSSI-1253-IR-4".to_string(),
            ],
            remediation_guidance: Some("Establish incident response team with documented procedures aligned to IC-IRT requirements.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-9".to_string(),
            control_id: "CI-9".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Personnel Security Implementation".to_string(),
            description: "Implement personnel security controls ensuring appropriate clearances, access agreements, and termination procedures.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PS-2".to_string(),
                "NIST-PS-3".to_string(),
                "CNSSI-1253-PS-3".to_string(),
            ],
            remediation_guidance: Some("Verify clearance levels before granting access; implement need-to-know verification procedures.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CI-10".to_string(),
            control_id: "CI-10".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Physical Security Implementation".to_string(),
            description: "Implement physical security controls for IC facilities including access control, surveillance, and environmental protections.".to_string(),
            category: "Control Implementation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PE-2".to_string(),
                "NIST-PE-3".to_string(),
                "CNSSI-1253-PE-3".to_string(),
            ],
            remediation_guidance: Some("Implement ICD 705 compliant physical security for SCIFs and sensitive compartmented areas.".to_string()),
        },

        // ============================================================
        // Phase 4: Security Assessment Controls (SA)
        // ============================================================
        ComplianceControl {
            id: "ICD503-SA-1".to_string(),
            control_id: "SA-1".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Security Assessment Plan".to_string(),
            description: "Develop and document a Security Assessment Plan (SAP) defining assessment scope, methodology, and procedures.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-2".to_string(),
                "CNSSI-1253-CA-2".to_string(),
            ],
            remediation_guidance: Some("Create SAP covering all selected controls with test procedures and pass/fail criteria.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SA-2".to_string(),
            control_id: "SA-2".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Security Control Assessment".to_string(),
            description: "Assess implemented security controls to determine correct implementation, operation, and effectiveness.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-2".to_string(),
                "CNSSI-1253-CA-2".to_string(),
            ],
            remediation_guidance: Some("Conduct assessment using approved methodologies; document findings in Security Assessment Report.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SA-3".to_string(),
            control_id: "SA-3".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Penetration Testing".to_string(),
            description: "Conduct penetration testing to identify exploitable vulnerabilities in IC systems.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-8".to_string(),
                "CNSSI-1253-CA-8".to_string(),
            ],
            remediation_guidance: Some("Perform annual penetration testing using IC-approved red team methodologies.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SA-4".to_string(),
            control_id: "SA-4".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Security Assessment Report".to_string(),
            description: "Document assessment results in a Security Assessment Report (SAR) including findings, weaknesses, and recommendations.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-2".to_string(),
                "CNSSI-1253-CA-2".to_string(),
            ],
            remediation_guidance: Some("Produce SAR documenting control assessment results and risk determination for AO review.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SA-5".to_string(),
            control_id: "SA-5".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Independent Assessment".to_string(),
            description: "Ensure security assessments are conducted by qualified independent assessors for high-impact systems.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-2".to_string(),
                "CNSSI-1253-CA-2".to_string(),
            ],
            remediation_guidance: Some("Engage IC-certified Security Control Assessors (SCA) for independent assessment activities.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-SA-6".to_string(),
            control_id: "SA-6".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Remediation Tracking".to_string(),
            description: "Track and manage remediation of identified security weaknesses through Plan of Action and Milestones (POA&M).".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-5".to_string(),
                "CNSSI-1253-CA-5".to_string(),
            ],
            remediation_guidance: Some("Maintain POA&M with specific milestones, resources, and completion dates for all findings.".to_string()),
        },

        // ============================================================
        // Phase 5: Authorization Controls (AZ)
        // ============================================================
        ComplianceControl {
            id: "ICD503-AZ-1".to_string(),
            control_id: "AZ-1".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Authorization Package".to_string(),
            description: "Prepare complete authorization package including SSP, SAR, POA&M, and risk assessment for AO review.".to_string(),
            category: "Authorization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-6".to_string(),
                "CNSSI-1253-CA-6".to_string(),
            ],
            remediation_guidance: Some("Compile authorization package per IC RMF guidance for AO submission.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-AZ-2".to_string(),
            control_id: "AZ-2".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Risk Determination".to_string(),
            description: "Determine organizational risk based on assessment findings, threat environment, and mission impact.".to_string(),
            category: "Authorization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-6".to_string(),
                "NIST-RA-3".to_string(),
                "CNSSI-1253-RA-3".to_string(),
            ],
            remediation_guidance: Some("Document risk determination considering residual vulnerabilities and compensating controls.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-AZ-3".to_string(),
            control_id: "AZ-3".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Authorization Decision".to_string(),
            description: "Obtain formal authorization decision (ATO, IATO, or DATO) from the Authorizing Official.".to_string(),
            category: "Authorization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-6".to_string(),
                "CNSSI-1253-CA-6".to_string(),
            ],
            remediation_guidance: Some("Submit authorization package to AO; maintain documentation of authorization decision.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-AZ-4".to_string(),
            control_id: "AZ-4".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Authorization Terms and Conditions".to_string(),
            description: "Document and implement any terms and conditions specified in the authorization decision.".to_string(),
            category: "Authorization".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-6".to_string(),
                "CNSSI-1253-CA-6".to_string(),
            ],
            remediation_guidance: Some("Track compliance with authorization conditions; report status to AO as required.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-AZ-5".to_string(),
            control_id: "AZ-5".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Interconnection Authorization".to_string(),
            description: "Obtain authorization for system interconnections through Memoranda of Understanding/Agreement (MOU/MOA).".to_string(),
            category: "Authorization".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-3".to_string(),
                "CNSSI-1253-CA-3".to_string(),
            ],
            remediation_guidance: Some("Document interconnection security requirements in ISA/MOU and obtain AO approval.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-AZ-6".to_string(),
            control_id: "AZ-6".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Reauthorization".to_string(),
            description: "Conduct system reauthorization at defined intervals or when significant changes occur.".to_string(),
            category: "Authorization".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-6".to_string(),
                "CNSSI-1253-CA-6".to_string(),
            ],
            remediation_guidance: Some("Initiate reauthorization every 3 years or upon significant system changes per IC policy.".to_string()),
        },

        // ============================================================
        // Phase 6: Continuous Monitoring Controls (CM)
        // ============================================================
        ComplianceControl {
            id: "ICD503-CM-1".to_string(),
            control_id: "CM-1".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Continuous Monitoring Strategy".to_string(),
            description: "Develop and implement a continuous monitoring strategy addressing security status, configuration management, and vulnerability management.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-7".to_string(),
                "CNSSI-1253-CA-7".to_string(),
            ],
            remediation_guidance: Some("Document continuous monitoring strategy aligned with IC continuous diagnostics and mitigation (CDM) requirements.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CM-2".to_string(),
            control_id: "CM-2".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Automated Security Monitoring".to_string(),
            description: "Implement automated tools for continuous security status monitoring and anomaly detection.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SI-4".to_string(),
                "NIST-CA-7".to_string(),
                "CNSSI-1253-SI-4".to_string(),
            ],
            remediation_guidance: Some("Deploy SIEM, EDR, and network monitoring tools integrated with IC threat intelligence.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CM-3".to_string(),
            control_id: "CM-3".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Ongoing Vulnerability Scanning".to_string(),
            description: "Conduct regular vulnerability scanning and report findings per continuous monitoring schedule.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-5".to_string(),
                "CNSSI-1253-RA-5".to_string(),
            ],
            remediation_guidance: Some("Perform vulnerability scans at least monthly; report critical findings within 72 hours.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CM-4".to_string(),
            control_id: "CM-4".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Configuration Monitoring".to_string(),
            description: "Monitor system configurations for unauthorized changes and compliance with security baselines.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-3".to_string(),
                "NIST-CM-8".to_string(),
                "CNSSI-1253-CM-3".to_string(),
            ],
            remediation_guidance: Some("Implement automated configuration compliance monitoring against approved baselines.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CM-5".to_string(),
            control_id: "CM-5".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Security Status Reporting".to_string(),
            description: "Report security status to the Authorizing Official and designated stakeholders at defined intervals.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-7".to_string(),
                "CNSSI-1253-CA-7".to_string(),
            ],
            remediation_guidance: Some("Provide monthly security status reports to AO; escalate critical issues immediately.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CM-6".to_string(),
            control_id: "CM-6".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Threat Intelligence Integration".to_string(),
            description: "Integrate IC threat intelligence feeds into security monitoring and vulnerability management processes.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-PM-16".to_string(),
                "NIST-RA-3".to_string(),
            ],
            remediation_guidance: Some("Subscribe to IC-ITE threat feeds and automate indicator ingestion into security tools.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CM-7".to_string(),
            control_id: "CM-7".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "POA&M Management".to_string(),
            description: "Maintain and update Plan of Action and Milestones (POA&M) with ongoing remediation activities.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-5".to_string(),
                "CNSSI-1253-CA-5".to_string(),
            ],
            remediation_guidance: Some("Review and update POA&M monthly; close items upon remediation verification.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-CM-8".to_string(),
            control_id: "CM-8".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Ongoing Authorization".to_string(),
            description: "Implement ongoing authorization processes enabling continuous ATO status based on real-time security posture.".to_string(),
            category: "Continuous Monitoring".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-6".to_string(),
                "CNSSI-1253-CA-6".to_string(),
            ],
            remediation_guidance: Some("Establish ongoing authorization criteria and automated risk scoring for continuous ATO.".to_string()),
        },

        // ============================================================
        // Additional IC-Specific Controls
        // ============================================================
        ComplianceControl {
            id: "ICD503-IC-1".to_string(),
            control_id: "IC-1".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Insider Threat Protection".to_string(),
            description: "Implement controls to detect, deter, and mitigate insider threats to IC systems and information.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-PM-12".to_string(),
                "CNSSI-1253-PM-12".to_string(),
            ],
            remediation_guidance: Some("Deploy user activity monitoring and anomaly detection per ICD 732 requirements.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-2".to_string(),
            control_id: "IC-2".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Data Loss Prevention".to_string(),
            description: "Implement data loss prevention controls to prevent unauthorized exfiltration of classified information.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "NIST-AC-4".to_string(),
            ],
            remediation_guidance: Some("Deploy DLP solutions at network boundaries and endpoints monitoring for classified markings.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-3".to_string(),
            control_id: "IC-3".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Removable Media Controls".to_string(),
            description: "Implement strict controls on removable media use in IC environments to prevent data spillage.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-MP-7".to_string(),
                "CNSSI-1253-MP-7".to_string(),
            ],
            remediation_guidance: Some("Disable unauthorized removable media; implement approved media registration and tracking.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-4".to_string(),
            control_id: "IC-4".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Cross-Domain Security".to_string(),
            description: "Implement approved cross-domain solutions for information sharing between different security domains.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-4".to_string(),
                "NIST-SC-7".to_string(),
                "CNSSI-1253-AC-4".to_string(),
            ],
            remediation_guidance: Some("Deploy NSA-evaluated cross-domain solutions with appropriate guards and filters.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-5".to_string(),
            control_id: "IC-5".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Security Classification Marking".to_string(),
            description: "Implement automated security classification marking and enforcement for all IC information.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-16".to_string(),
                "CNSSI-1253-AC-16".to_string(),
            ],
            remediation_guidance: Some("Deploy classification marking tools enforcing IC marking requirements and dissemination controls.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-6".to_string(),
            control_id: "IC-6".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Supply Chain Risk Management".to_string(),
            description: "Implement supply chain risk management controls for IC IT systems and components.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-SR-1".to_string(),
                "NIST-SR-3".to_string(),
                "CNSSI-1253-SR-1".to_string(),
            ],
            remediation_guidance: Some("Implement IC SCRM processes including vendor vetting and trusted sourcing requirements.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-7".to_string(),
            control_id: "IC-7".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Privileged Access Management".to_string(),
            description: "Implement enhanced controls for privileged accounts including just-in-time access and session monitoring.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-2".to_string(),
                "NIST-AC-6".to_string(),
                "CNSSI-1253-AC-2".to_string(),
            ],
            remediation_guidance: Some("Deploy PAM solution with session recording, approval workflows, and time-limited access.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-8".to_string(),
            control_id: "IC-8".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Counterintelligence Integration".to_string(),
            description: "Integrate counterintelligence requirements into security monitoring and incident response processes.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-4".to_string(),
                "NIST-IR-6".to_string(),
            ],
            remediation_guidance: Some("Establish CI coordination procedures and reporting channels for security incidents.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-9".to_string(),
            control_id: "IC-9".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Secure Communications".to_string(),
            description: "Implement secure communications capabilities using NSA-approved cryptographic solutions for classified communications.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-8".to_string(),
                "NIST-SC-13".to_string(),
                "CNSSI-1253-SC-8".to_string(),
            ],
            remediation_guidance: Some("Deploy Type 1 encryption for classified voice/data communications; implement secure VTC solutions.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-10".to_string(),
            control_id: "IC-10".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Secure Remote Access".to_string(),
            description: "Implement secure remote access capabilities for IC personnel requiring off-site access to classified systems.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-17".to_string(),
                "NIST-IA-2".to_string(),
                "CNSSI-1253-AC-17".to_string(),
            ],
            remediation_guidance: Some("Implement IC-approved remote access solutions with hardware tokens and strong mutual authentication.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-11".to_string(),
            control_id: "IC-11".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Information Spillage Response".to_string(),
            description: "Implement procedures for detecting, reporting, and remediating information spillage incidents involving classified information.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-4".to_string(),
                "NIST-IR-6".to_string(),
                "CNSSI-1253-IR-4".to_string(),
            ],
            remediation_guidance: Some("Establish spillage response procedures per ICD 701 including containment, assessment, and remediation.".to_string()),
        },
        ComplianceControl {
            id: "ICD503-IC-12".to_string(),
            control_id: "IC-12".to_string(),
            framework: ComplianceFramework::Icd503,
            title: "Security Training and Awareness".to_string(),
            description: "Implement IC-specific security training covering classification, handling procedures, and threat awareness.".to_string(),
            category: "IC-Specific Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AT-2".to_string(),
                "NIST-AT-3".to_string(),
                "CNSSI-1253-AT-2".to_string(),
            ],
            remediation_guidance: Some("Provide annual IC security awareness training and role-specific training for privileged users.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant ICD 503 controls
///
/// This function maps detected vulnerabilities to applicable ICD 503 controls
/// based on vulnerability characteristics, enabling automated compliance assessment.
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control and authentication vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("privilege escalation")
        || title_lower.contains("authentication bypass")
    {
        mappings.push(("ICD503-CI-1".to_string(), Severity::Critical));
        mappings.push(("ICD503-IC-7".to_string(), Severity::Critical));
    }

    // Weak authentication
    if title_lower.contains("weak password")
        || title_lower.contains("default credentials")
        || title_lower.contains("default password")
    {
        mappings.push(("ICD503-CI-1".to_string(), Severity::Critical));
        mappings.push(("ICD503-CI-6".to_string(), Severity::High));
    }

    // Missing or weak MFA
    if title_lower.contains("no mfa")
        || title_lower.contains("missing mfa")
        || title_lower.contains("weak authentication")
    {
        mappings.push(("ICD503-CI-1".to_string(), Severity::Critical));
    }

    // Encryption vulnerabilities
    if title_lower.contains("unencrypted")
        || title_lower.contains("weak encryption")
        || title_lower.contains("ssl") && title_lower.contains("vulnerable")
        || title_lower.contains("tls") && title_lower.contains("weak")
        || title_lower.contains("cleartext")
    {
        mappings.push(("ICD503-CI-3".to_string(), Severity::Critical));
    }

    // Non-compliant cryptography
    if title_lower.contains("non-fips")
        || title_lower.contains("deprecated cipher")
        || title_lower.contains("weak cipher")
    {
        mappings.push(("ICD503-CI-3".to_string(), Severity::Critical));
    }

    // Audit/logging issues
    if title_lower.contains("no logging")
        || title_lower.contains("audit disabled")
        || title_lower.contains("missing audit")
    {
        mappings.push(("ICD503-CI-2".to_string(), Severity::High));
    }

    // Patching and vulnerability management
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("unsupported")
    {
        mappings.push(("ICD503-CI-7".to_string(), Severity::High));
        mappings.push(("ICD503-CM-3".to_string(), Severity::High));
    }

    // Malware/endpoint protection
    if title_lower.contains("no antivirus")
        || title_lower.contains("malware")
        || title_lower.contains("missing edr")
    {
        mappings.push(("ICD503-CI-5".to_string(), Severity::High));
    }

    // Network boundary issues
    if title_lower.contains("firewall") || title_lower.contains("open port") {
        mappings.push(("ICD503-CI-4".to_string(), Severity::Medium));
    }

    // Remote access vulnerabilities
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
            mappings.push(("ICD503-CI-1".to_string(), Severity::High));
            mappings.push(("ICD503-CI-4".to_string(), Severity::High));
        }
    }

    // Insecure protocols
    if port == Some(23)
        || title_lower.contains("telnet")
        || title_lower.contains("ftp")
        || title_lower.contains("http") && !title_lower.contains("https")
    {
        mappings.push(("ICD503-CI-3".to_string(), Severity::High));
        mappings.push(("ICD503-CI-6".to_string(), Severity::Medium));
    }

    // Configuration management issues
    if title_lower.contains("misconfiguration")
        || title_lower.contains("insecure configuration")
        || title_lower.contains("hardening")
    {
        mappings.push(("ICD503-CI-6".to_string(), Severity::Medium));
        mappings.push(("ICD503-CM-4".to_string(), Severity::Medium));
    }

    // Data leakage/exfiltration
    if title_lower.contains("data leak")
        || title_lower.contains("data exfiltration")
        || title_lower.contains("information disclosure")
    {
        mappings.push(("ICD503-IC-2".to_string(), Severity::Critical));
    }

    // Removable media issues
    if title_lower.contains("usb")
        || title_lower.contains("removable media")
        || title_lower.contains("external storage")
    {
        mappings.push(("ICD503-IC-3".to_string(), Severity::High));
    }

    // Insider threat indicators
    if title_lower.contains("insider")
        || title_lower.contains("lateral movement")
        || title_lower.contains("privilege abuse")
    {
        mappings.push(("ICD503-IC-1".to_string(), Severity::Critical));
    }

    // Injection vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("xss")
        || title_lower.contains("code injection")
    {
        mappings.push(("ICD503-CI-7".to_string(), Severity::Critical));
        mappings.push(("ICD503-SA-3".to_string(), Severity::High));
    }

    // Security monitoring gaps
    if title_lower.contains("no monitoring")
        || title_lower.contains("missing siem")
        || title_lower.contains("blind spot")
    {
        mappings.push(("ICD503-CM-2".to_string(), Severity::High));
    }

    // Supply chain risks
    if title_lower.contains("supply chain")
        || title_lower.contains("third party")
        || title_lower.contains("dependency vulnerability")
    {
        mappings.push(("ICD503-IC-6".to_string(), Severity::High));
    }

    // Classification marking issues
    if title_lower.contains("unmarked")
        || title_lower.contains("classification")
        || title_lower.contains("marking")
    {
        mappings.push(("ICD503-IC-5".to_string(), Severity::High));
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
    fn test_all_controls_have_framework() {
        let controls = get_controls();
        for control in &controls {
            assert_eq!(control.framework, ComplianceFramework::Icd503);
        }
    }

    #[test]
    fn test_all_controls_have_cross_references() {
        let controls = get_controls();
        let mut controls_with_refs = 0;
        for control in &controls {
            if !control.cross_references.is_empty() {
                controls_with_refs += 1;
            }
        }
        // Most controls should have cross-references to NIST or CNSSI
        assert!(
            controls_with_refs > controls.len() / 2,
            "Expected majority of controls to have cross-references"
        );
    }

    #[test]
    fn test_control_categories() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> =
            controls.iter().map(|c| c.category.as_str()).collect();

        // Verify the six RMF phases are represented
        assert!(categories.contains("Security Categorization"));
        assert!(categories.contains("Control Selection"));
        assert!(categories.contains("Control Implementation"));
        assert!(categories.contains("Security Assessment"));
        assert!(categories.contains("Authorization"));
        assert!(categories.contains("Continuous Monitoring"));
        assert!(categories.contains("IC-Specific Requirements"));
    }

    #[test]
    fn test_map_vulnerability_access_control() {
        let mappings = map_vulnerability("Unauthorized access to admin panel", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ICD503-CI-1"));
    }

    #[test]
    fn test_map_vulnerability_encryption() {
        let mappings = map_vulnerability("Weak TLS configuration detected", None, Some(443), None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ICD503-CI-3"));
    }

    #[test]
    fn test_map_vulnerability_patching() {
        let mappings = map_vulnerability("Outdated software version", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ICD503-CI-7"));
    }

    #[test]
    fn test_map_vulnerability_data_loss() {
        let mappings = map_vulnerability("Potential data exfiltration detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ICD503-IC-2"));
    }
}
