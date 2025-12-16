//! SOC 2 Trust Services Criteria Controls
//!
//! Service Organization Control 2 Trust Services Criteria for security,
//! availability, processing integrity, confidentiality, and privacy.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of SOC 2 controls in this module
pub const CONTROL_COUNT: usize = 52;

/// Get all SOC 2 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // Common Criteria (CC) - Security
        ComplianceControl {
            id: "SOC2-CC1.1".to_string(),
            control_id: "CC1.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Control Environment - Integrity and Ethics".to_string(),
            description: "The entity demonstrates a commitment to integrity and ethical values.".to_string(),
            category: "Control Environment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Establish and communicate code of conduct and ethics policies.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC1.2".to_string(),
            control_id: "CC1.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Board Oversight".to_string(),
            description: "The board of directors demonstrates independence and exercises oversight.".to_string(),
            category: "Control Environment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document board oversight of security and risk management.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC1.3".to_string(),
            control_id: "CC1.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Organizational Structure".to_string(),
            description: "Management establishes structures, reporting lines, and authorities.".to_string(),
            category: "Control Environment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document organizational structure with security roles.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC1.4".to_string(),
            control_id: "CC1.4".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Human Resources Policies".to_string(),
            description: "The entity demonstrates commitment to attract, develop, and retain competent individuals.".to_string(),
            category: "Control Environment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-1".to_string()],
            remediation_guidance: Some("Implement security requirements in HR processes.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC1.5".to_string(),
            control_id: "CC1.5".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Accountability".to_string(),
            description: "The entity holds individuals accountable for their internal control responsibilities.".to_string(),
            category: "Control Environment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Define accountability measures for security responsibilities.".to_string()),
        },

        // Communication and Information (CC2)
        ComplianceControl {
            id: "SOC2-CC2.1".to_string(),
            control_id: "CC2.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Information Quality".to_string(),
            description: "The entity obtains or generates relevant, quality information to support internal control.".to_string(),
            category: "Communication and Information".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Establish information quality standards and validation.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC2.2".to_string(),
            control_id: "CC2.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Internal Communication".to_string(),
            description: "The entity internally communicates information necessary to support internal control.".to_string(),
            category: "Communication and Information".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Establish internal security communication channels.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC2.3".to_string(),
            control_id: "CC2.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "External Communication".to_string(),
            description: "The entity communicates with external parties regarding matters affecting internal control.".to_string(),
            category: "Communication and Information".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Define external communication policies for security matters.".to_string()),
        },

        // Risk Assessment (CC3)
        ComplianceControl {
            id: "SOC2-CC3.1".to_string(),
            control_id: "CC3.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Risk Objectives".to_string(),
            description: "The entity specifies objectives with sufficient clarity to enable risk identification.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-1".to_string()],
            remediation_guidance: Some("Document clear security objectives aligned with business goals.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC3.2".to_string(),
            control_id: "CC3.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Risk Identification and Analysis".to_string(),
            description: "The entity identifies risks and analyzes them to determine how they should be managed.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string(), "CIS-7.1".to_string()],
            remediation_guidance: Some("Conduct annual risk assessments with documented methodology.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC3.3".to_string(),
            control_id: "CC3.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Fraud Risk".to_string(),
            description: "The entity considers the potential for fraud in assessing risks.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Include fraud scenarios in risk assessments.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC3.4".to_string(),
            control_id: "CC3.4".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Change Management".to_string(),
            description: "The entity identifies and assesses changes that could significantly impact internal control.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string()],
            remediation_guidance: Some("Implement formal change management with security review.".to_string()),
        },

        // Monitoring Activities (CC4)
        ComplianceControl {
            id: "SOC2-CC4.1".to_string(),
            control_id: "CC4.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Ongoing Monitoring".to_string(),
            description: "The entity selects, develops, and performs ongoing evaluations of internal control.".to_string(),
            category: "Monitoring Activities".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Implement continuous security monitoring and assessment.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC4.2".to_string(),
            control_id: "CC4.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Deficiency Communication".to_string(),
            description: "The entity evaluates and communicates internal control deficiencies in a timely manner.".to_string(),
            category: "Monitoring Activities".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Establish deficiency reporting and remediation tracking.".to_string()),
        },

        // Control Activities (CC5)
        ComplianceControl {
            id: "SOC2-CC5.1".to_string(),
            control_id: "CC5.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Control Selection and Development".to_string(),
            description: "The entity selects and develops control activities to mitigate risks.".to_string(),
            category: "Control Activities".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Map controls to identified risks and document rationale.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC5.2".to_string(),
            control_id: "CC5.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Technology Controls".to_string(),
            description: "The entity selects and develops general control activities over technology.".to_string(),
            category: "Control Activities".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string()],
            remediation_guidance: Some("Implement and document technology-specific security controls.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC5.3".to_string(),
            control_id: "CC5.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Policy Deployment".to_string(),
            description: "The entity deploys control activities through policies and procedures.".to_string(),
            category: "Control Activities".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document and distribute security policies and procedures.".to_string()),
        },

        // Logical and Physical Access (CC6)
        ComplianceControl {
            id: "SOC2-CC6.1".to_string(),
            control_id: "CC6.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Logical Access Security".to_string(),
            description: "The entity implements logical access security software and infrastructure.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string(), "CIS-6.1".to_string()],
            remediation_guidance: Some("Implement access controls for all systems and applications.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC6.2".to_string(),
            control_id: "CC6.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "User Registration and Authorization".to_string(),
            description: "Prior to access, new users are registered and authorized.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "CIS-5.1".to_string()],
            remediation_guidance: Some("Implement formal user provisioning with approval workflow.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC6.3".to_string(),
            control_id: "CC6.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Access Removal".to_string(),
            description: "The entity removes access when no longer required.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "CIS-6.2".to_string()],
            remediation_guidance: Some("Implement automated deprovisioning on termination.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC6.4".to_string(),
            control_id: "CC6.4".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Physical Access Restrictions".to_string(),
            description: "The entity restricts physical access to facilities and protected assets.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["PCI-DSS-9.1".to_string()],
            remediation_guidance: Some("Implement badge access and visitor management.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC6.5".to_string(),
            control_id: "CC6.5".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Asset Disposal".to_string(),
            description: "The entity disposes of, destroys, and sanitizes protected assets.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string(), "CIS-3.5".to_string()],
            remediation_guidance: Some("Implement secure media disposal procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC6.6".to_string(),
            control_id: "CC6.6".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "External Threats".to_string(),
            description: "The entity implements controls to prevent or detect external threats.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "CIS-4.4".to_string()],
            remediation_guidance: Some("Deploy firewalls, IDS/IPS, and endpoint protection.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC6.7".to_string(),
            control_id: "CC6.7".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Transmission Protection".to_string(),
            description: "The entity protects transmitted information using encryption.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Use TLS 1.2+ for all data in transit.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC6.8".to_string(),
            control_id: "CC6.8".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Malware Prevention".to_string(),
            description: "The entity implements controls to prevent or detect malicious software.".to_string(),
            category: "Logical and Physical Access".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "CIS-10.1".to_string()],
            remediation_guidance: Some("Deploy and maintain endpoint protection software.".to_string()),
        },

        // System Operations (CC7)
        ComplianceControl {
            id: "SOC2-CC7.1".to_string(),
            control_id: "CC7.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Vulnerability Management".to_string(),
            description: "The entity uses detection and monitoring procedures to identify security events.".to_string(),
            category: "System Operations".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-RA-5".to_string(), "CIS-7.5".to_string()],
            remediation_guidance: Some("Perform regular vulnerability scanning and monitoring.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC7.2".to_string(),
            control_id: "CC7.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Security Event Monitoring".to_string(),
            description: "The entity monitors system components for anomalies indicative of security events.".to_string(),
            category: "System Operations".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "PCI-DSS-10.6".to_string()],
            remediation_guidance: Some("Deploy SIEM for centralized security monitoring.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC7.3".to_string(),
            control_id: "CC7.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Security Event Evaluation".to_string(),
            description: "The entity evaluates security events to determine if they are incidents.".to_string(),
            category: "System Operations".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Establish security event triage and classification procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC7.4".to_string(),
            control_id: "CC7.4".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Incident Response".to_string(),
            description: "The entity responds to identified security incidents per established procedures.".to_string(),
            category: "System Operations".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string(), "PCI-DSS-12.10".to_string()],
            remediation_guidance: Some("Document and test incident response procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC7.5".to_string(),
            control_id: "CC7.5".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Incident Recovery".to_string(),
            description: "The entity identifies, develops, and implements recovery from security incidents.".to_string(),
            category: "System Operations".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-10".to_string()],
            remediation_guidance: Some("Document recovery procedures and conduct DR testing.".to_string()),
        },

        // Change Management (CC8)
        ComplianceControl {
            id: "SOC2-CC8.1".to_string(),
            control_id: "CC8.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Infrastructure and Software Changes".to_string(),
            description: "The entity authorizes, designs, develops, configures, and tests changes to infrastructure and software.".to_string(),
            category: "Change Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-3".to_string(), "PCI-DSS-6.4".to_string()],
            remediation_guidance: Some("Implement formal change control with testing and approval.".to_string()),
        },

        // Risk Mitigation (CC9)
        ComplianceControl {
            id: "SOC2-CC9.1".to_string(),
            control_id: "CC9.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Risk Mitigation through Controls".to_string(),
            description: "The entity identifies, selects, and develops risk mitigation activities.".to_string(),
            category: "Risk Mitigation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-7".to_string()],
            remediation_guidance: Some("Document risk treatment decisions with control mapping.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-CC9.2".to_string(),
            control_id: "CC9.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Vendor Risk Management".to_string(),
            description: "The entity assesses and manages risks associated with vendors and partners.".to_string(),
            category: "Risk Mitigation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement vendor security assessment program.".to_string()),
        },

        // Availability Criteria (A)
        ComplianceControl {
            id: "SOC2-A1.1".to_string(),
            control_id: "A1.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Capacity Planning".to_string(),
            description: "The entity maintains capacity to meet availability commitments.".to_string(),
            category: "Availability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement capacity monitoring and forecasting.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-A1.2".to_string(),
            control_id: "A1.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Environmental Protections".to_string(),
            description: "The entity protects against environmental threats.".to_string(),
            category: "Availability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement environmental controls for data centers.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-A1.3".to_string(),
            control_id: "A1.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Recovery Testing".to_string(),
            description: "The entity tests recovery plan procedures supporting system recovery.".to_string(),
            category: "Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-4".to_string(), "CIS-11.5".to_string()],
            remediation_guidance: Some("Conduct annual DR tests with documented results.".to_string()),
        },

        // Confidentiality Criteria (C)
        ComplianceControl {
            id: "SOC2-C1.1".to_string(),
            control_id: "C1.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Confidential Information Identification".to_string(),
            description: "The entity identifies and classifies confidential information.".to_string(),
            category: "Confidentiality".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CIS-3.1".to_string()],
            remediation_guidance: Some("Implement data classification with handling procedures.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-C1.2".to_string(),
            control_id: "C1.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Confidential Information Disposal".to_string(),
            description: "The entity disposes of confidential information according to policies.".to_string(),
            category: "Confidentiality".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Implement secure deletion and disposal procedures.".to_string()),
        },

        // Processing Integrity Criteria (PI)
        ComplianceControl {
            id: "SOC2-PI1.1".to_string(),
            control_id: "PI1.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Processing Integrity Policies".to_string(),
            description: "The entity defines processing integrity objectives.".to_string(),
            category: "Processing Integrity".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document data processing integrity requirements.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-PI1.2".to_string(),
            control_id: "PI1.2".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "System Inputs".to_string(),
            description: "The entity validates system inputs for processing integrity.".to_string(),
            category: "Processing Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string()],
            remediation_guidance: Some("Implement input validation and sanitization.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-PI1.3".to_string(),
            control_id: "PI1.3".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Processing Accuracy".to_string(),
            description: "The entity uses processing activities to achieve completeness and accuracy.".to_string(),
            category: "Processing Integrity".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement data validation and reconciliation controls.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-PI1.4".to_string(),
            control_id: "PI1.4".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "System Outputs".to_string(),
            description: "The entity validates system outputs for processing integrity.".to_string(),
            category: "Processing Integrity".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement output validation and verification.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-PI1.5".to_string(),
            control_id: "PI1.5".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Error Handling".to_string(),
            description: "The entity identifies and addresses processing errors.".to_string(),
            category: "Processing Integrity".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement error detection, logging, and correction procedures.".to_string()),
        },

        // Privacy Criteria (P)
        ComplianceControl {
            id: "SOC2-P1.1".to_string(),
            control_id: "P1.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Privacy Notice".to_string(),
            description: "The entity provides notice about its privacy practices.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Publish and maintain privacy policy notice.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-P2.1".to_string(),
            control_id: "P2.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Data Subject Choice".to_string(),
            description: "The entity provides choices about data collection and use.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement consent management and preference center.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-P3.1".to_string(),
            control_id: "P3.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Personal Information Collection".to_string(),
            description: "The entity collects personal information according to privacy objectives.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement data minimization in collection practices.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-P4.1".to_string(),
            control_id: "P4.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Personal Information Use".to_string(),
            description: "The entity uses personal information according to privacy objectives.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Limit use of personal data to stated purposes.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-P5.1".to_string(),
            control_id: "P5.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Data Retention".to_string(),
            description: "The entity retains personal information according to retention policy.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CIS-3.4".to_string()],
            remediation_guidance: Some("Implement data retention policy with automated enforcement.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-P6.1".to_string(),
            control_id: "P6.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Data Subject Access".to_string(),
            description: "The entity provides data subjects access to their personal information.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement data subject access request handling.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-P7.1".to_string(),
            control_id: "P7.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Third Party Disclosure".to_string(),
            description: "The entity discloses personal information to third parties according to policy.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Document and control third-party data sharing.".to_string()),
        },
        ComplianceControl {
            id: "SOC2-P8.1".to_string(),
            control_id: "P8.1".to_string(),
            framework: ComplianceFramework::Soc2,
            title: "Data Quality".to_string(),
            description: "The entity maintains accurate and complete personal information.".to_string(),
            category: "Privacy".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement data quality controls and correction procedures.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant SOC 2 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("authentication bypass")
    {
        mappings.push(("SOC2-CC6.1".to_string(), Severity::Critical));
        mappings.push(("SOC2-CC6.2".to_string(), Severity::High));
    }

    // Credential issues
    if title_lower.contains("default password")
        || title_lower.contains("weak password")
        || title_lower.contains("credential")
    {
        mappings.push(("SOC2-CC6.1".to_string(), Severity::High));
        mappings.push(("SOC2-CC6.2".to_string(), Severity::High));
    }

    // Encryption issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
    {
        mappings.push(("SOC2-CC6.7".to_string(), Severity::High));
    }

    // Malware/AV issues
    if title_lower.contains("malware")
        || title_lower.contains("antivirus")
        || title_lower.contains("endpoint protection")
    {
        mappings.push(("SOC2-CC6.8".to_string(), Severity::High));
    }

    // Vulnerability findings
    if title_lower.contains("cve")
        || title_lower.contains("vulnerability")
        || title_lower.contains("outdated")
    {
        mappings.push(("SOC2-CC7.1".to_string(), Severity::High));
    }

    // Monitoring issues
    if title_lower.contains("logging")
        || title_lower.contains("monitoring")
        || title_lower.contains("audit")
    {
        mappings.push(("SOC2-CC7.2".to_string(), Severity::Medium));
        mappings.push(("SOC2-CC4.1".to_string(), Severity::Medium));
    }

    // Firewall/network issues
    if title_lower.contains("firewall")
        || title_lower.contains("network")
        || title_lower.contains("open port")
    {
        mappings.push(("SOC2-CC6.6".to_string(), Severity::Medium));
    }

    // Change management issues
    if title_lower.contains("configuration")
        || title_lower.contains("misconfigur")
    {
        mappings.push(("SOC2-CC8.1".to_string(), Severity::Medium));
        mappings.push(("SOC2-CC5.2".to_string(), Severity::Medium));
    }

    // Input validation issues
    if title_lower.contains("injection")
        || title_lower.contains("xss")
    {
        mappings.push(("SOC2-PI1.2".to_string(), Severity::Critical));
    }

    // Backup/recovery issues
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
    {
        mappings.push(("SOC2-A1.3".to_string(), Severity::Medium));
    }

    // Data exposure
    if title_lower.contains("data exposure")
        || title_lower.contains("information disclosure")
    {
        mappings.push(("SOC2-C1.1".to_string(), Severity::High));
    }

    // Vendor/third party issues
    if title_lower.contains("third party")
        || title_lower.contains("vendor")
        || title_lower.contains("supply chain")
    {
        mappings.push(("SOC2-CC9.2".to_string(), Severity::High));
    }

    mappings
}
