//! EU NIS2 Directive Compliance Framework
//!
//! This module implements controls for the EU Network and Information Security
//! Directive (NIS2) - Directive (EU) 2022/2555, which came into force in January 2023.
//!
//! NIS2 applies to essential and important entities across critical infrastructure
//! sectors including energy, transport, banking, health, water, digital infrastructure,
//! ICT service management, public administration, and space.
//!
//! The directive establishes minimum cybersecurity risk management measures and
//! incident reporting obligations for entities in scope.
//!
//! Key requirement areas:
//! - Risk analysis and information system security policies
//! - Incident handling
//! - Business continuity and crisis management
//! - Supply chain security
//! - Security in network and information systems acquisition
//! - Vulnerability handling and disclosure
//! - Cybersecurity hygiene practices and training
//! - Cryptography and encryption policies
//! - Human resources security
//! - Access control and asset management

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NIS2 Directive controls in this module
pub const CONTROL_COUNT: usize = 60;

/// Get all NIS2 Directive controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ========================================================================
        // Article 21(2)(a): Risk Analysis and Information Security Policies
        // ========================================================================
        ComplianceControl {
            id: "NIS2-RA-1".to_string(),
            control_id: "RA-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Risk Analysis Framework".to_string(),
            description: "Establish and maintain a comprehensive risk analysis framework to identify, assess, and manage cybersecurity risks to network and information systems.".to_string(),
            category: "Risk Analysis and Security Policies".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.1".to_string(), "NIST-RA-3".to_string()],
            remediation_guidance: Some("Implement a formal risk assessment methodology (e.g., ISO 31000, NIST RMF) and conduct regular risk assessments.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-RA-2".to_string(),
            control_id: "RA-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Information Security Policy".to_string(),
            description: "Develop, document, and maintain information security policies approved by management and communicated to all relevant personnel.".to_string(),
            category: "Risk Analysis and Security Policies".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.1".to_string(), "NIST-PL-1".to_string()],
            remediation_guidance: Some("Create comprehensive security policies covering all NIS2 requirements. Review annually and after significant changes.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-RA-3".to_string(),
            control_id: "RA-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Risk Treatment Plan".to_string(),
            description: "Develop and implement risk treatment plans that address identified risks through appropriate security measures.".to_string(),
            category: "Risk Analysis and Security Policies".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.1".to_string(), "NIST-RA-7".to_string()],
            remediation_guidance: Some("Document risk treatment decisions (accept, mitigate, transfer, avoid) with justification and timeline for implementation.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-RA-4".to_string(),
            control_id: "RA-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Management Accountability".to_string(),
            description: "Ensure management bodies approve and oversee the implementation of cybersecurity risk-management measures and can be held accountable for infringements.".to_string(),
            category: "Risk Analysis and Security Policies".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.2".to_string(), "NIST-PM-2".to_string()],
            remediation_guidance: Some("Establish board-level accountability for cybersecurity. Document management approval of security policies and risk assessments.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-RA-5".to_string(),
            control_id: "RA-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Security Risk Monitoring".to_string(),
            description: "Continuously monitor and review cybersecurity risks and the effectiveness of security measures.".to_string(),
            category: "Risk Analysis and Security Policies".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.16".to_string(), "NIST-CA-7".to_string()],
            remediation_guidance: Some("Implement continuous security monitoring with regular risk assessment reviews (at least annually).".to_string()),
        },

        // ========================================================================
        // Article 21(2)(b): Incident Handling
        // ========================================================================
        ComplianceControl {
            id: "NIS2-IH-1".to_string(),
            control_id: "IH-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Incident Response Plan".to_string(),
            description: "Establish and maintain documented incident response procedures for detecting, managing, and recovering from security incidents.".to_string(),
            category: "Incident Handling".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.24".to_string(), "NIST-IR-1".to_string()],
            remediation_guidance: Some("Develop incident response plan covering detection, containment, eradication, recovery, and lessons learned phases.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-IH-2".to_string(),
            control_id: "IH-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Incident Detection Capabilities".to_string(),
            description: "Implement technical and organizational measures to detect security incidents affecting network and information systems.".to_string(),
            category: "Incident Handling".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.16".to_string(), "NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy SIEM, IDS/IPS, and endpoint detection systems. Establish 24/7 security monitoring capability.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-IH-3".to_string(),
            control_id: "IH-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Incident Classification".to_string(),
            description: "Establish criteria for classifying incidents by severity and impact to prioritize response activities.".to_string(),
            category: "Incident Handling".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.25".to_string(), "NIST-IR-4".to_string()],
            remediation_guidance: Some("Define incident classification scheme aligned with NIS2 reporting thresholds (significant incidents).".to_string()),
        },
        ComplianceControl {
            id: "NIS2-IH-4".to_string(),
            control_id: "IH-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Incident Reporting to Authorities".to_string(),
            description: "Notify competent authority or CSIRT of significant incidents within 24 hours (early warning), 72 hours (incident notification), and 1 month (final report).".to_string(),
            category: "Incident Handling".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.26".to_string(), "NIST-IR-6".to_string()],
            remediation_guidance: Some("Establish incident reporting procedures compliant with NIS2 timelines. Maintain contact details for national CSIRT.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-IH-5".to_string(),
            control_id: "IH-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Incident Response Team".to_string(),
            description: "Establish a dedicated incident response capability with trained personnel available to respond to security incidents.".to_string(),
            category: "Incident Handling".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.24".to_string(), "NIST-IR-2".to_string()],
            remediation_guidance: Some("Designate incident response team with clear roles. Conduct regular incident response training and exercises.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-IH-6".to_string(),
            control_id: "IH-6".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Post-Incident Analysis".to_string(),
            description: "Conduct post-incident reviews to identify lessons learned and improve security measures and incident handling procedures.".to_string(),
            category: "Incident Handling".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.27".to_string(), "NIST-IR-4".to_string()],
            remediation_guidance: Some("Document lessons learned from incidents. Update procedures and controls based on findings.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(c): Business Continuity and Crisis Management
        // ========================================================================
        ComplianceControl {
            id: "NIS2-BC-1".to_string(),
            control_id: "BC-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Business Continuity Plan".to_string(),
            description: "Develop and maintain business continuity plans that ensure the availability and integrity of critical services during and after disruptions.".to_string(),
            category: "Business Continuity".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.30".to_string(), "NIST-CP-1".to_string()],
            remediation_guidance: Some("Develop BCP covering critical services. Define RTO and RPO for essential functions.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-BC-2".to_string(),
            control_id: "BC-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Disaster Recovery".to_string(),
            description: "Implement disaster recovery capabilities including backup systems and recovery procedures for critical network and information systems.".to_string(),
            category: "Business Continuity".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.13".to_string(), "NIST-CP-9".to_string()],
            remediation_guidance: Some("Implement backup and recovery solutions. Test recovery procedures regularly.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-BC-3".to_string(),
            control_id: "BC-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Crisis Management".to_string(),
            description: "Establish crisis management procedures and communication channels for coordinating response to major security incidents.".to_string(),
            category: "Business Continuity".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.29".to_string(), "NIST-IR-1".to_string()],
            remediation_guidance: Some("Define crisis management team and escalation procedures. Establish out-of-band communication channels.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-BC-4".to_string(),
            control_id: "BC-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Business Continuity Testing".to_string(),
            description: "Regularly test business continuity and disaster recovery plans to ensure effectiveness and identify improvements.".to_string(),
            category: "Business Continuity".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.30".to_string(), "NIST-CP-4".to_string()],
            remediation_guidance: Some("Conduct annual BCP/DR tests including tabletop exercises and technical recovery tests.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-BC-5".to_string(),
            control_id: "BC-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "System Redundancy".to_string(),
            description: "Implement appropriate redundancy for critical systems to ensure availability of essential services.".to_string(),
            category: "Business Continuity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.14".to_string(), "NIST-CP-10".to_string()],
            remediation_guidance: Some("Deploy redundant systems for critical infrastructure. Implement failover mechanisms.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(d): Supply Chain Security
        // ========================================================================
        ComplianceControl {
            id: "NIS2-SC-1".to_string(),
            control_id: "SC-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Supply Chain Risk Assessment".to_string(),
            description: "Assess and manage security risks in the supply chain, including direct suppliers and service providers.".to_string(),
            category: "Supply Chain Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.19".to_string(), "NIST-SR-1".to_string()],
            remediation_guidance: Some("Conduct supply chain risk assessments. Maintain inventory of critical suppliers and dependencies.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-SC-2".to_string(),
            control_id: "SC-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Supplier Security Requirements".to_string(),
            description: "Define and communicate security requirements to suppliers and ensure contractual agreements include appropriate security clauses.".to_string(),
            category: "Supply Chain Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.20".to_string(), "NIST-SA-9".to_string()],
            remediation_guidance: Some("Include security requirements in supplier contracts. Define minimum security standards for vendors.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-SC-3".to_string(),
            control_id: "SC-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Third-Party Risk Monitoring".to_string(),
            description: "Monitor and review supplier security practices and compliance with contractual security requirements.".to_string(),
            category: "Supply Chain Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.22".to_string(), "NIST-SA-9".to_string()],
            remediation_guidance: Some("Implement vendor risk management program. Conduct regular supplier security assessments.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-SC-4".to_string(),
            control_id: "SC-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Software Supply Chain Security".to_string(),
            description: "Manage security risks in the ICT supply chain including software development and maintenance processes.".to_string(),
            category: "Supply Chain Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.21".to_string(), "NIST-SA-12".to_string()],
            remediation_guidance: Some("Implement SBOM management. Verify software integrity and provenance.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-SC-5".to_string(),
            control_id: "SC-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Cloud Service Provider Security".to_string(),
            description: "Assess and manage security risks associated with cloud services, including data protection and access controls.".to_string(),
            category: "Supply Chain Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.23".to_string(), "NIST-SA-9".to_string()],
            remediation_guidance: Some("Assess cloud provider security. Ensure appropriate data protection and contractual guarantees.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(e): Network and Information Systems Security
        // ========================================================================
        ComplianceControl {
            id: "NIS2-NS-1".to_string(),
            control_id: "NS-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Network Security Architecture".to_string(),
            description: "Design and implement secure network architectures with appropriate segmentation and protection measures.".to_string(),
            category: "Network and Information Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.20".to_string(), "NIST-SC-7".to_string()],
            remediation_guidance: Some("Implement network segmentation. Deploy firewalls at trust boundaries.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-NS-2".to_string(),
            control_id: "NS-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Secure System Acquisition".to_string(),
            description: "Ensure security considerations are integrated into the acquisition, development, and maintenance of network and information systems.".to_string(),
            category: "Network and Information Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.26".to_string(), "NIST-SA-3".to_string()],
            remediation_guidance: Some("Include security requirements in system acquisition. Conduct security assessments before deployment.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-NS-3".to_string(),
            control_id: "NS-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Secure Development Practices".to_string(),
            description: "Apply secure development practices throughout the software development lifecycle for internally developed systems.".to_string(),
            category: "Network and Information Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.25".to_string(), "NIST-SA-15".to_string()],
            remediation_guidance: Some("Implement secure SDLC. Conduct code reviews and security testing.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-NS-4".to_string(),
            control_id: "NS-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Configuration Management".to_string(),
            description: "Establish and maintain secure configurations for all network and information system components.".to_string(),
            category: "Network and Information Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.9".to_string(), "NIST-CM-2".to_string()],
            remediation_guidance: Some("Define secure baseline configurations. Use configuration management tools to enforce standards.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-NS-5".to_string(),
            control_id: "NS-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Network Monitoring".to_string(),
            description: "Implement network monitoring capabilities to detect unauthorized access and malicious activities.".to_string(),
            category: "Network and Information Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.16".to_string(), "NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy network monitoring and intrusion detection systems. Establish security operations center.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-NS-6".to_string(),
            control_id: "NS-6".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Malware Protection".to_string(),
            description: "Implement protection against malware across all network and information system endpoints.".to_string(),
            category: "Network and Information Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.7".to_string(), "NIST-SI-3".to_string()],
            remediation_guidance: Some("Deploy endpoint protection with anti-malware, EDR capabilities, and automatic updates.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(f): Vulnerability Handling and Disclosure
        // ========================================================================
        ComplianceControl {
            id: "NIS2-VH-1".to_string(),
            control_id: "VH-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Vulnerability Management Program".to_string(),
            description: "Establish a vulnerability management program to identify, assess, and remediate vulnerabilities in network and information systems.".to_string(),
            category: "Vulnerability Handling".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.8".to_string(), "NIST-RA-5".to_string()],
            remediation_guidance: Some("Implement vulnerability scanning program. Define remediation timelines based on severity.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-VH-2".to_string(),
            control_id: "VH-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Vulnerability Scanning".to_string(),
            description: "Conduct regular vulnerability scans of network and information systems to identify security weaknesses.".to_string(),
            category: "Vulnerability Handling".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.8".to_string(), "NIST-RA-5".to_string()],
            remediation_guidance: Some("Perform authenticated vulnerability scans at least quarterly. Scan critical systems more frequently.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-VH-3".to_string(),
            control_id: "VH-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Patch Management".to_string(),
            description: "Implement timely patching of security vulnerabilities based on risk assessment and defined timelines.".to_string(),
            category: "Vulnerability Handling".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.8".to_string(), "NIST-SI-2".to_string()],
            remediation_guidance: Some("Deploy patches for critical vulnerabilities within 14 days. Establish automated patch management.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-VH-4".to_string(),
            control_id: "VH-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Coordinated Vulnerability Disclosure".to_string(),
            description: "Participate in coordinated vulnerability disclosure processes and maintain contact with CSIRTs for vulnerability information sharing.".to_string(),
            category: "Vulnerability Handling".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.6".to_string(), "NIST-SI-5".to_string()],
            remediation_guidance: Some("Establish vulnerability disclosure policy. Register with EU vulnerability database.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-VH-5".to_string(),
            control_id: "VH-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Penetration Testing".to_string(),
            description: "Conduct regular penetration testing to identify vulnerabilities that may not be detected by automated scanning.".to_string(),
            category: "Vulnerability Handling".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.29".to_string(), "NIST-CA-8".to_string()],
            remediation_guidance: Some("Conduct annual penetration tests of critical systems. Address findings based on severity.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(g): Cybersecurity Hygiene and Training
        // ========================================================================
        ComplianceControl {
            id: "NIS2-CH-1".to_string(),
            control_id: "CH-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Cybersecurity Awareness Program".to_string(),
            description: "Implement cybersecurity awareness training for all personnel to promote basic cyber hygiene practices.".to_string(),
            category: "Cybersecurity Hygiene".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.6.3".to_string(), "NIST-AT-2".to_string()],
            remediation_guidance: Some("Provide annual security awareness training. Include phishing simulations and current threat awareness.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CH-2".to_string(),
            control_id: "CH-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Management Cybersecurity Training".to_string(),
            description: "Ensure members of management bodies receive specific cybersecurity training to understand risks and management measures.".to_string(),
            category: "Cybersecurity Hygiene".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.4".to_string(), "NIST-AT-3".to_string()],
            remediation_guidance: Some("Provide board-level cybersecurity briefings. Include training on NIS2 accountability requirements.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CH-3".to_string(),
            control_id: "CH-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Secure Password Practices".to_string(),
            description: "Enforce secure password practices including complexity requirements and multi-factor authentication where appropriate.".to_string(),
            category: "Cybersecurity Hygiene".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.17".to_string(), "NIST-IA-5".to_string()],
            remediation_guidance: Some("Enforce strong password policies. Implement MFA for privileged and remote access.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CH-4".to_string(),
            control_id: "CH-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Phishing Protection".to_string(),
            description: "Implement measures to protect against phishing and social engineering attacks.".to_string(),
            category: "Cybersecurity Hygiene".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.7".to_string(), "NIST-AT-2".to_string()],
            remediation_guidance: Some("Deploy email security controls. Conduct regular phishing awareness training and simulations.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CH-5".to_string(),
            control_id: "CH-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Secure Remote Working".to_string(),
            description: "Implement security measures for remote working including secure access and endpoint protection.".to_string(),
            category: "Cybersecurity Hygiene".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.6.7".to_string(), "NIST-AC-17".to_string()],
            remediation_guidance: Some("Require VPN for remote access. Ensure endpoint protection on remote devices.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(h): Cryptography and Encryption
        // ========================================================================
        ComplianceControl {
            id: "NIS2-CR-1".to_string(),
            control_id: "CR-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Cryptography Policy".to_string(),
            description: "Establish and implement policies and procedures for the use of cryptography to protect the confidentiality and integrity of information.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.24".to_string(), "NIST-SC-13".to_string()],
            remediation_guidance: Some("Document cryptography policy specifying approved algorithms and key lengths.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CR-2".to_string(),
            control_id: "CR-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Data Encryption at Rest".to_string(),
            description: "Implement encryption for sensitive data stored in network and information systems.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.24".to_string(), "NIST-SC-28".to_string()],
            remediation_guidance: Some("Encrypt sensitive data at rest using AES-256 or equivalent. Enable full-disk encryption.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CR-3".to_string(),
            control_id: "CR-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Data Encryption in Transit".to_string(),
            description: "Implement encryption for data transmitted over networks to protect confidentiality and integrity.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.14".to_string(), "NIST-SC-8".to_string()],
            remediation_guidance: Some("Use TLS 1.2 or higher for data in transit. Disable legacy SSL/TLS versions.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CR-4".to_string(),
            control_id: "CR-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Cryptographic Key Management".to_string(),
            description: "Implement secure key management practices including key generation, storage, distribution, and destruction.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.24".to_string(), "NIST-SC-12".to_string()],
            remediation_guidance: Some("Implement key management system. Use HSMs for critical key protection.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-CR-5".to_string(),
            control_id: "CR-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "End-to-End Encryption".to_string(),
            description: "Where appropriate, implement end-to-end encryption for highly sensitive communications and data.".to_string(),
            category: "Cryptography".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.24".to_string(), "NIST-SC-8".to_string()],
            remediation_guidance: Some("Implement E2E encryption for sensitive communications. Consider quantum-resistant algorithms.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(i): Human Resources Security
        // ========================================================================
        ComplianceControl {
            id: "NIS2-HR-1".to_string(),
            control_id: "HR-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Personnel Screening".to_string(),
            description: "Conduct appropriate background verification checks on personnel with access to critical network and information systems.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.6.1".to_string(), "NIST-PS-3".to_string()],
            remediation_guidance: Some("Implement background checks for personnel with privileged access. Review screening requirements.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-HR-2".to_string(),
            control_id: "HR-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Security Responsibilities in Employment".to_string(),
            description: "Define and communicate security responsibilities in employment agreements and throughout the employment lifecycle.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.6.2".to_string(), "NIST-PS-6".to_string()],
            remediation_guidance: Some("Include security responsibilities in employment contracts. Ensure acknowledgment of policies.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-HR-3".to_string(),
            control_id: "HR-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Termination and Change Procedures".to_string(),
            description: "Implement procedures to revoke access and return assets when personnel leave or change roles.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.11".to_string(), "NIST-PS-4".to_string()],
            remediation_guidance: Some("Implement offboarding procedures. Automate access revocation on termination.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-HR-4".to_string(),
            control_id: "HR-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Security Incident Reporting by Personnel".to_string(),
            description: "Provide mechanisms for personnel to report security events and incidents without fear of retaliation.".to_string(),
            category: "Human Resources Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.6.8".to_string(), "NIST-IR-6".to_string()],
            remediation_guidance: Some("Establish incident reporting channels. Protect reporters from retaliation.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(j): Access Control and Asset Management
        // ========================================================================
        ComplianceControl {
            id: "NIS2-AC-1".to_string(),
            control_id: "AC-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Access Control Policy".to_string(),
            description: "Establish and implement access control policies based on business and security requirements.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.15".to_string(), "NIST-AC-1".to_string()],
            remediation_guidance: Some("Document access control policy. Define access requirements for different user categories.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-AC-2".to_string(),
            control_id: "AC-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "User Access Management".to_string(),
            description: "Implement formal user registration, access provisioning, and de-provisioning processes.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.18".to_string(), "NIST-AC-2".to_string()],
            remediation_guidance: Some("Implement identity lifecycle management. Automate access provisioning and deprovisioning.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-AC-3".to_string(),
            control_id: "AC-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Privileged Access Management".to_string(),
            description: "Restrict and manage privileged access rights with enhanced controls and monitoring.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.2".to_string(), "NIST-AC-6".to_string()],
            remediation_guidance: Some("Implement PAM solution. Enforce just-in-time privileged access. Monitor all privileged sessions.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-AC-4".to_string(),
            control_id: "AC-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Multi-Factor Authentication".to_string(),
            description: "Implement multi-factor authentication for access to critical systems and remote access.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.5".to_string(), "NIST-IA-2".to_string()],
            remediation_guidance: Some("Deploy MFA for all administrative access and remote access. Use phishing-resistant MFA where possible.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-AC-5".to_string(),
            control_id: "AC-5".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Access Review".to_string(),
            description: "Conduct regular reviews of access rights to ensure they remain appropriate and aligned with business needs.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.18".to_string(), "NIST-AC-2".to_string()],
            remediation_guidance: Some("Conduct quarterly access reviews. Implement user access certification campaigns.".to_string()),
        },

        // ========================================================================
        // Article 21(2)(j): Asset Management
        // ========================================================================
        ComplianceControl {
            id: "NIS2-AM-1".to_string(),
            control_id: "AM-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Asset Inventory".to_string(),
            description: "Maintain an accurate and up-to-date inventory of all network and information system assets.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.9".to_string(), "NIST-CM-8".to_string()],
            remediation_guidance: Some("Implement automated asset discovery. Maintain CMDB with all critical assets.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-AM-2".to_string(),
            control_id: "AM-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Asset Classification".to_string(),
            description: "Classify assets based on their criticality and sensitivity to apply appropriate protection measures.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.12".to_string(), "NIST-RA-2".to_string()],
            remediation_guidance: Some("Classify assets by criticality. Apply appropriate controls based on classification.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-AM-3".to_string(),
            control_id: "AM-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Media Handling".to_string(),
            description: "Implement procedures for secure handling, transport, and disposal of storage media.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.7.10".to_string(), "NIST-MP-6".to_string()],
            remediation_guidance: Some("Implement media handling procedures. Use secure disposal methods for storage media.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-AM-4".to_string(),
            control_id: "AM-4".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Data Protection".to_string(),
            description: "Implement measures to protect sensitive data throughout its lifecycle including storage, processing, and transmission.".to_string(),
            category: "Asset Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.33".to_string(), "NIST-SC-28".to_string()],
            remediation_guidance: Some("Implement DLP solutions. Encrypt sensitive data. Control data access.".to_string()),
        },

        // ========================================================================
        // Additional NIS2 Specific Controls
        // ========================================================================
        ComplianceControl {
            id: "NIS2-LOG-1".to_string(),
            control_id: "LOG-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Security Logging".to_string(),
            description: "Implement comprehensive logging of security events across network and information systems.".to_string(),
            category: "Logging and Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.15".to_string(), "NIST-AU-2".to_string()],
            remediation_guidance: Some("Enable security logging on all systems. Centralize log collection.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-LOG-2".to_string(),
            control_id: "LOG-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Log Retention".to_string(),
            description: "Retain security logs for an appropriate period to support incident investigation and compliance requirements.".to_string(),
            category: "Logging and Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.15".to_string(), "NIST-AU-11".to_string()],
            remediation_guidance: Some("Retain logs for minimum 12 months. Protect log integrity.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-LOG-3".to_string(),
            control_id: "LOG-3".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Time Synchronization".to_string(),
            description: "Synchronize clocks across all network and information systems to support accurate logging and incident correlation.".to_string(),
            category: "Logging and Monitoring".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.8.17".to_string(), "NIST-AU-8".to_string()],
            remediation_guidance: Some("Configure NTP on all systems. Use authoritative time sources.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-GOV-1".to_string(),
            control_id: "GOV-1".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Cybersecurity Governance".to_string(),
            description: "Establish cybersecurity governance structures with clear accountability and oversight.".to_string(),
            category: "Governance".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.2".to_string(), "NIST-PM-1".to_string()],
            remediation_guidance: Some("Establish CISO role. Define board-level cybersecurity oversight.".to_string()),
        },
        ComplianceControl {
            id: "NIS2-GOV-2".to_string(),
            control_id: "GOV-2".to_string(),
            framework: ComplianceFramework::Nis2,
            title: "Compliance Monitoring".to_string(),
            description: "Monitor and ensure ongoing compliance with NIS2 requirements and other applicable regulations.".to_string(),
            category: "Governance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["ISO27001-A.5.36".to_string(), "NIST-CA-2".to_string()],
            remediation_guidance: Some("Implement compliance monitoring. Conduct regular internal audits.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant NIS2 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Authentication/Access Control issues
    if title_lower.contains("authentication")
        || title_lower.contains("password")
        || title_lower.contains("mfa")
        || title_lower.contains("credential")
    {
        mappings.push(("NIS2-AC-4".to_string(), Severity::Critical));
        mappings.push(("NIS2-CH-3".to_string(), Severity::High));
        mappings.push(("NIS2-AC-2".to_string(), Severity::High));
    }

    // Privilege escalation
    if title_lower.contains("privilege")
        || title_lower.contains("escalation")
        || title_lower.contains("admin")
    {
        mappings.push(("NIS2-AC-3".to_string(), Severity::Critical));
        mappings.push(("NIS2-AC-1".to_string(), Severity::High));
    }

    // Encryption/TLS issues
    if title_lower.contains("encryption")
        || title_lower.contains("tls")
        || title_lower.contains("ssl")
        || title_lower.contains("certificate")
        || title_lower.contains("plaintext")
        || title_lower.contains("unencrypted")
    {
        mappings.push(("NIS2-CR-3".to_string(), Severity::High));
        mappings.push(("NIS2-CR-2".to_string(), Severity::High));
        mappings.push(("NIS2-CR-1".to_string(), Severity::Medium));
    }

    // Vulnerability/Patching issues
    if title_lower.contains("outdated")
        || title_lower.contains("patch")
        || title_lower.contains("update")
        || title_lower.contains("end of life")
        || title_lower.contains("eol")
        || title_lower.contains("unsupported")
    {
        mappings.push(("NIS2-VH-3".to_string(), Severity::Critical));
        mappings.push(("NIS2-VH-1".to_string(), Severity::High));
        mappings.push(("NIS2-NS-4".to_string(), Severity::High));
    }

    // Injection vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("xss")
        || title_lower.contains("xxe")
        || title_lower.contains("injection")
    {
        mappings.push(("NIS2-NS-3".to_string(), Severity::Critical));
        mappings.push(("NIS2-VH-1".to_string(), Severity::High));
    }

    // Malware/Virus
    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("ransomware")
        || title_lower.contains("trojan")
    {
        mappings.push(("NIS2-NS-6".to_string(), Severity::Critical));
        mappings.push(("NIS2-IH-2".to_string(), Severity::High));
    }

    // Network security issues
    if title_lower.contains("firewall")
        || title_lower.contains("network")
        || title_lower.contains("segmentation")
        || title_lower.contains("open port")
    {
        mappings.push(("NIS2-NS-1".to_string(), Severity::High));
        mappings.push(("NIS2-NS-5".to_string(), Severity::Medium));
    }

    // Remote access issues
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
            mappings.push(("NIS2-CH-5".to_string(), Severity::High));
            mappings.push(("NIS2-AC-4".to_string(), Severity::High));
        }
    }

    // Database exposure
    if port == Some(1433)
        || port == Some(3306)
        || port == Some(5432)
        || port == Some(27017)
        || title_lower.contains("database")
    {
        mappings.push(("NIS2-NS-1".to_string(), Severity::High));
        mappings.push(("NIS2-AM-4".to_string(), Severity::High));
        mappings.push(("NIS2-CR-2".to_string(), Severity::Medium));
    }

    // Logging/Monitoring issues
    if title_lower.contains("logging")
        || title_lower.contains("audit")
        || title_lower.contains("monitoring")
    {
        mappings.push(("NIS2-LOG-1".to_string(), Severity::Medium));
        mappings.push(("NIS2-IH-2".to_string(), Severity::Medium));
    }

    // Backup/Recovery issues
    if title_lower.contains("backup") || title_lower.contains("recovery") {
        mappings.push(("NIS2-BC-2".to_string(), Severity::High));
        mappings.push(("NIS2-BC-1".to_string(), Severity::Medium));
    }

    // Supply chain issues
    if title_lower.contains("supply chain")
        || title_lower.contains("third party")
        || title_lower.contains("vendor")
        || title_lower.contains("dependency")
    {
        mappings.push(("NIS2-SC-1".to_string(), Severity::High));
        mappings.push(("NIS2-SC-4".to_string(), Severity::High));
    }

    // Phishing
    if title_lower.contains("phishing") || title_lower.contains("social engineering") {
        mappings.push(("NIS2-CH-4".to_string(), Severity::High));
        mappings.push(("NIS2-CH-1".to_string(), Severity::Medium));
    }

    // Default credentials
    if title_lower.contains("default password")
        || title_lower.contains("default credentials")
        || title_lower.contains("default account")
    {
        mappings.push(("NIS2-NS-4".to_string(), Severity::Critical));
        mappings.push(("NIS2-AC-2".to_string(), Severity::High));
    }

    // Insecure protocols
    if title_lower.contains("telnet")
        || title_lower.contains("ftp")
        || title_lower.contains("http")
            && !title_lower.contains("https")
    {
        mappings.push(("NIS2-CR-3".to_string(), Severity::High));
        mappings.push(("NIS2-NS-4".to_string(), Severity::Medium));
    }

    // Incident response gaps
    if title_lower.contains("incident") || title_lower.contains("breach") {
        mappings.push(("NIS2-IH-1".to_string(), Severity::High));
        mappings.push(("NIS2-IH-4".to_string(), Severity::High));
    }

    // Asset management issues
    if title_lower.contains("unknown asset")
        || title_lower.contains("shadow it")
        || title_lower.contains("unauthorized device")
    {
        mappings.push(("NIS2-AM-1".to_string(), Severity::High));
        mappings.push(("NIS2-AM-2".to_string(), Severity::Medium));
    }

    // Business continuity
    if title_lower.contains("availability")
        || title_lower.contains("dos")
        || title_lower.contains("denial of service")
    {
        mappings.push(("NIS2-BC-5".to_string(), Severity::High));
        mappings.push(("NIS2-BC-1".to_string(), Severity::High));
    }

    // Default mapping if nothing matches
    if mappings.is_empty() {
        mappings.push(("NIS2-VH-1".to_string(), Severity::Medium));
        mappings.push(("NIS2-RA-1".to_string(), Severity::Low));
    }

    mappings
}

/// Map vulnerability type string to relevant NIS2 control IDs
pub fn map_vulnerability_to_controls(vuln_type: &str) -> Vec<String> {
    match vuln_type.to_lowercase().as_str() {
        "authentication" | "password" | "mfa" => vec![
            "NIS2-AC-4".to_string(),
            "NIS2-CH-3".to_string(),
            "NIS2-AC-2".to_string(),
        ],
        "access_control" | "authorization" | "privilege" => vec![
            "NIS2-AC-1".to_string(),
            "NIS2-AC-3".to_string(),
            "NIS2-AC-5".to_string(),
        ],
        "encryption" | "cryptography" | "tls" | "ssl" => vec![
            "NIS2-CR-1".to_string(),
            "NIS2-CR-2".to_string(),
            "NIS2-CR-3".to_string(),
        ],
        "vulnerability" | "patching" | "update" => vec![
            "NIS2-VH-1".to_string(),
            "NIS2-VH-2".to_string(),
            "NIS2-VH-3".to_string(),
        ],
        "malware" | "virus" | "ransomware" => vec![
            "NIS2-NS-6".to_string(),
            "NIS2-IH-2".to_string(),
        ],
        "network" | "firewall" | "segmentation" => vec![
            "NIS2-NS-1".to_string(),
            "NIS2-NS-5".to_string(),
        ],
        "logging" | "monitoring" | "audit" => vec![
            "NIS2-LOG-1".to_string(),
            "NIS2-LOG-2".to_string(),
            "NIS2-IH-2".to_string(),
        ],
        "backup" | "recovery" | "continuity" => vec![
            "NIS2-BC-1".to_string(),
            "NIS2-BC-2".to_string(),
            "NIS2-BC-5".to_string(),
        ],
        "incident" | "breach" => vec![
            "NIS2-IH-1".to_string(),
            "NIS2-IH-4".to_string(),
            "NIS2-IH-5".to_string(),
        ],
        "supply_chain" | "vendor" | "third_party" => vec![
            "NIS2-SC-1".to_string(),
            "NIS2-SC-2".to_string(),
            "NIS2-SC-3".to_string(),
        ],
        "training" | "awareness" => vec![
            "NIS2-CH-1".to_string(),
            "NIS2-CH-2".to_string(),
        ],
        "asset" | "inventory" => vec![
            "NIS2-AM-1".to_string(),
            "NIS2-AM-2".to_string(),
        ],
        "risk" | "assessment" => vec![
            "NIS2-RA-1".to_string(),
            "NIS2-RA-3".to_string(),
            "NIS2-RA-5".to_string(),
        ],
        _ => vec!["NIS2-VH-1".to_string()],
    }
}

/// Get controls by NIS2 Article reference
pub fn get_controls_by_article(article: &str) -> Vec<ComplianceControl> {
    let all_controls = get_controls();
    let category = match article.to_lowercase().as_str() {
        "21(2)(a)" | "risk" => "Risk Analysis and Security Policies",
        "21(2)(b)" | "incident" => "Incident Handling",
        "21(2)(c)" | "continuity" => "Business Continuity",
        "21(2)(d)" | "supply" => "Supply Chain Security",
        "21(2)(e)" | "network" => "Network and Information Security",
        "21(2)(f)" | "vulnerability" => "Vulnerability Handling",
        "21(2)(g)" | "hygiene" | "training" => "Cybersecurity Hygiene",
        "21(2)(h)" | "crypto" | "encryption" => "Cryptography",
        "21(2)(i)" | "hr" | "human" => "Human Resources Security",
        "21(2)(j)" | "access" => "Access Control",
        "asset" => "Asset Management",
        "logging" | "monitoring" => "Logging and Monitoring",
        "governance" => "Governance",
        _ => return vec![],
    };

    all_controls
        .into_iter()
        .filter(|c| c.category == category)
        .collect()
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
            assert_eq!(control.framework, ComplianceFramework::Nis2);
        }
    }

    #[test]
    fn test_all_controls_have_cross_references() {
        let controls = get_controls();
        let controls_with_refs: Vec<_> = controls
            .iter()
            .filter(|c| !c.cross_references.is_empty())
            .collect();
        // Most controls should have ISO 27001 cross-references
        assert!(controls_with_refs.len() > 50);
    }

    #[test]
    fn test_vulnerability_mapping() {
        let mappings = map_vulnerability("SQL Injection vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.starts_with("NIS2-")));
    }

    #[test]
    fn test_vulnerability_mapping_authentication() {
        let mappings = map_vulnerability("Weak password authentication", None, None, None);
        assert!(mappings.iter().any(|(id, _)| id == "NIS2-AC-4"));
    }

    #[test]
    fn test_vulnerability_mapping_encryption() {
        let mappings = map_vulnerability("TLS 1.0 deprecated", None, None, None);
        assert!(mappings.iter().any(|(id, _)| id == "NIS2-CR-3"));
    }

    #[test]
    fn test_vulnerability_type_mapping() {
        let controls = map_vulnerability_to_controls("encryption");
        assert!(controls.contains(&"NIS2-CR-1".to_string()));
        assert!(controls.contains(&"NIS2-CR-2".to_string()));
    }

    #[test]
    fn test_get_controls_by_article() {
        let incident_controls = get_controls_by_article("21(2)(b)");
        assert!(!incident_controls.is_empty());
        assert!(incident_controls.iter().all(|c| c.category == "Incident Handling"));
    }

    #[test]
    fn test_categories_covered() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> =
            controls.iter().map(|c| c.category.as_str()).collect();

        // Verify all main NIS2 requirement areas are covered
        assert!(categories.contains("Risk Analysis and Security Policies"));
        assert!(categories.contains("Incident Handling"));
        assert!(categories.contains("Business Continuity"));
        assert!(categories.contains("Supply Chain Security"));
        assert!(categories.contains("Network and Information Security"));
        assert!(categories.contains("Vulnerability Handling"));
        assert!(categories.contains("Cybersecurity Hygiene"));
        assert!(categories.contains("Cryptography"));
        assert!(categories.contains("Human Resources Security"));
        assert!(categories.contains("Access Control"));
        assert!(categories.contains("Asset Management"));
    }
}
