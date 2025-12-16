//! NIST Cybersecurity Framework (CSF) Controls
//!
//! Framework for improving critical infrastructure cybersecurity.
//! Based on NIST CSF v2.0 with its six core functions.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NIST CSF controls in this module
pub const CONTROL_COUNT: usize = 48;

/// Get all NIST CSF controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // GOVERN (GV) Function - New in CSF 2.0
        ComplianceControl {
            id: "CSF-GV.OC-01".to_string(),
            control_id: "GV.OC-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Organizational Context Understanding".to_string(),
            description: "The organizational mission is understood and informs cybersecurity risk management.".to_string(),
            category: "Govern".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-2".to_string()],
            remediation_guidance: Some("Document organizational mission and its cybersecurity implications.".to_string()),
        },
        ComplianceControl {
            id: "CSF-GV.RM-01".to_string(),
            control_id: "GV.RM-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Risk Management Strategy".to_string(),
            description: "Risk management objectives are established and agreed to by organizational stakeholders.".to_string(),
            category: "Govern".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-1".to_string()],
            remediation_guidance: Some("Establish and document organizational risk tolerance and management strategy.".to_string()),
        },
        ComplianceControl {
            id: "CSF-GV.SC-01".to_string(),
            control_id: "GV.SC-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Supply Chain Risk Management".to_string(),
            description: "A supply chain risk management program is established.".to_string(),
            category: "Govern".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement third-party risk management program for vendors and suppliers.".to_string()),
        },

        // IDENTIFY (ID) Function
        ComplianceControl {
            id: "CSF-ID.AM-01".to_string(),
            control_id: "ID.AM-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Asset Inventory".to_string(),
            description: "Inventories of hardware managed by the organization are maintained.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-1.1".to_string(), "NIST-CM-8".to_string()],
            remediation_guidance: Some("Implement automated asset discovery and maintain hardware inventory.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.AM-02".to_string(),
            control_id: "ID.AM-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Software Inventory".to_string(),
            description: "Inventories of software, services, and systems managed by the organization are maintained.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-2.1".to_string(), "NIST-CM-8".to_string()],
            remediation_guidance: Some("Deploy software inventory tools and maintain application catalog.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.AM-03".to_string(),
            control_id: "ID.AM-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Data Flow Mapping".to_string(),
            description: "Representations of the organization's authorized network communication and data flows are maintained.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string(), "PCI-DSS-1.1".to_string()],
            remediation_guidance: Some("Document network diagrams and data flow maps showing sensitive data paths.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.AM-05".to_string(),
            control_id: "ID.AM-05".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Asset Classification".to_string(),
            description: "Assets are prioritized based on classification, criticality, resources, and mission.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CIS-3.1".to_string(), "NIST-RA-2".to_string()],
            remediation_guidance: Some("Classify assets by criticality and implement tiered protection.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.RA-01".to_string(),
            control_id: "ID.RA-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Vulnerability Identification".to_string(),
            description: "Vulnerabilities in assets are identified, validated, and recorded.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-7.5".to_string(), "NIST-RA-5".to_string()],
            remediation_guidance: Some("Perform regular vulnerability scanning and maintain vulnerability database.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.RA-02".to_string(),
            control_id: "ID.RA-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Threat Intelligence".to_string(),
            description: "Cyber threat intelligence is received from information sharing forums and sources.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-5".to_string()],
            remediation_guidance: Some("Subscribe to threat intelligence feeds and participate in ISACs.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.RA-03".to_string(),
            control_id: "ID.RA-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Threat Identification".to_string(),
            description: "Internal and external threats to the organization are identified and recorded.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string()],
            remediation_guidance: Some("Conduct threat modeling and maintain threat registry.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.RA-04".to_string(),
            control_id: "ID.RA-04".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Impact Analysis".to_string(),
            description: "Potential business impacts and likelihoods are identified.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string()],
            remediation_guidance: Some("Perform business impact analysis for critical systems.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.RA-05".to_string(),
            control_id: "ID.RA-05".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Risk Determination".to_string(),
            description: "Risks are determined based on threats, vulnerabilities, likelihoods, and impacts.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string()],
            remediation_guidance: Some("Calculate risk scores and maintain risk register.".to_string()),
        },
        ComplianceControl {
            id: "CSF-ID.RA-06".to_string(),
            control_id: "ID.RA-06".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Risk Response".to_string(),
            description: "Risk responses are chosen, prioritized, planned, tracked, and communicated.".to_string(),
            category: "Identify".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-7".to_string()],
            remediation_guidance: Some("Document risk treatment decisions and track remediation progress.".to_string()),
        },

        // PROTECT (PR) Function
        ComplianceControl {
            id: "CSF-PR.AA-01".to_string(),
            control_id: "PR.AA-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Identity Management".to_string(),
            description: "Identities and credentials for authorized users, services, and hardware are managed.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-5.1".to_string(), "NIST-AC-2".to_string()],
            remediation_guidance: Some("Implement centralized identity management with lifecycle automation.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.AA-02".to_string(),
            control_id: "PR.AA-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Authentication".to_string(),
            description: "Identities are proofed and bound to credentials based on risk context.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-6.3".to_string(), "NIST-IA-2".to_string()],
            remediation_guidance: Some("Implement MFA for all users with risk-based authentication.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.AA-03".to_string(),
            control_id: "PR.AA-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Access Permissions".to_string(),
            description: "Access permissions, entitlements, and authorizations are defined and managed.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-3.3".to_string(), "NIST-AC-3".to_string()],
            remediation_guidance: Some("Implement RBAC with regular access reviews and least privilege.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.AA-05".to_string(),
            control_id: "PR.AA-05".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Network Integrity".to_string(),
            description: "Network integrity is protected, incorporating network segregation where appropriate.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.2".to_string()],
            remediation_guidance: Some("Implement network segmentation and firewall controls at boundaries.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.DS-01".to_string(),
            control_id: "PR.DS-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Data-at-Rest Protection".to_string(),
            description: "The confidentiality, integrity, and availability of data-at-rest are protected.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-3.6".to_string(), "NIST-SC-28".to_string()],
            remediation_guidance: Some("Implement encryption for data at rest using AES-256.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.DS-02".to_string(),
            control_id: "PR.DS-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Data-in-Transit Protection".to_string(),
            description: "The confidentiality, integrity, and availability of data-in-transit are protected.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string(), "PCI-DSS-4.1".to_string()],
            remediation_guidance: Some("Use TLS 1.2+ for all network communications.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.DS-10".to_string(),
            control_id: "PR.DS-10".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Data-in-Use Protection".to_string(),
            description: "The confidentiality, integrity, and availability of data-in-use are protected.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement memory protection and consider confidential computing.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.DS-11".to_string(),
            control_id: "PR.DS-11".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Backup Management".to_string(),
            description: "Backups of data are created, protected, maintained, and tested.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-11.2".to_string(), "NIST-CP-9".to_string()],
            remediation_guidance: Some("Implement automated encrypted backups with regular restore tests.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.PS-01".to_string(),
            control_id: "PR.PS-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Configuration Management".to_string(),
            description: "Configuration management practices are established and applied.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.1".to_string(), "NIST-CM-2".to_string()],
            remediation_guidance: Some("Implement secure baseline configurations with drift detection.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.PS-02".to_string(),
            control_id: "PR.PS-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Software Maintenance".to_string(),
            description: "Software is maintained, replaced, and removed commensurate with risk.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-7.3".to_string(), "NIST-SI-2".to_string()],
            remediation_guidance: Some("Implement automated patch management with defined SLAs.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.PS-04".to_string(),
            control_id: "PR.PS-04".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Log Management".to_string(),
            description: "Log records are generated and made available for continuous monitoring.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-8.2".to_string(), "NIST-AU-2".to_string()],
            remediation_guidance: Some("Enable comprehensive logging and forward to centralized SIEM.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.IR-01".to_string(),
            control_id: "PR.IR-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Incident Response Planning".to_string(),
            description: "Incident response and recovery plans are established, maintained, and tested.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string(), "PCI-DSS-12.10".to_string()],
            remediation_guidance: Some("Document IR plan and conduct annual tabletop exercises.".to_string()),
        },
        ComplianceControl {
            id: "CSF-PR.AT-01".to_string(),
            control_id: "PR.AT-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Security Awareness".to_string(),
            description: "Personnel are provided awareness and training to perform general tasks.".to_string(),
            category: "Protect".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AT-2".to_string(), "PCI-DSS-12.6".to_string()],
            remediation_guidance: Some("Conduct annual security awareness training for all personnel.".to_string()),
        },

        // DETECT (DE) Function
        ComplianceControl {
            id: "CSF-DE.CM-01".to_string(),
            control_id: "DE.CM-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Network Monitoring".to_string(),
            description: "Networks and network services are monitored to find potentially adverse events.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "PCI-DSS-11.4".to_string()],
            remediation_guidance: Some("Deploy IDS/IPS and establish 24/7 network monitoring.".to_string()),
        },
        ComplianceControl {
            id: "CSF-DE.CM-02".to_string(),
            control_id: "DE.CM-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Physical Environment Monitoring".to_string(),
            description: "The physical environment is monitored to find potentially adverse events.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Implement environmental monitoring for data centers.".to_string()),
        },
        ComplianceControl {
            id: "CSF-DE.CM-03".to_string(),
            control_id: "DE.CM-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Personnel Activity Monitoring".to_string(),
            description: "Personnel activity is monitored to find potentially adverse events.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string()],
            remediation_guidance: Some("Implement user behavior analytics and privileged activity monitoring.".to_string()),
        },
        ComplianceControl {
            id: "CSF-DE.CM-06".to_string(),
            control_id: "DE.CM-06".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "External Provider Monitoring".to_string(),
            description: "External service provider activities and services are monitored.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Monitor third-party access and review provider security reports.".to_string()),
        },
        ComplianceControl {
            id: "CSF-DE.CM-09".to_string(),
            control_id: "DE.CM-09".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Vulnerability Scanning".to_string(),
            description: "Computing hardware and software, runtime environments, and data are scanned.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-7.5".to_string(), "NIST-RA-5".to_string()],
            remediation_guidance: Some("Perform continuous vulnerability scanning with defined remediation SLAs.".to_string()),
        },
        ComplianceControl {
            id: "CSF-DE.AE-02".to_string(),
            control_id: "DE.AE-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Event Analysis".to_string(),
            description: "Potentially adverse events are analyzed to better understand attack activity.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string()],
            remediation_guidance: Some("Implement SIEM with automated correlation and alerting.".to_string()),
        },
        ComplianceControl {
            id: "CSF-DE.AE-03".to_string(),
            control_id: "DE.AE-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Event Aggregation".to_string(),
            description: "Information is correlated from multiple sources.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string()],
            remediation_guidance: Some("Aggregate logs from all sources into centralized platform.".to_string()),
        },
        ComplianceControl {
            id: "CSF-DE.AE-06".to_string(),
            control_id: "DE.AE-06".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Incident Declaration".to_string(),
            description: "Information on adverse events is provided to authorized staff.".to_string(),
            category: "Detect".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Establish incident escalation procedures and notification criteria.".to_string()),
        },

        // RESPOND (RS) Function
        ComplianceControl {
            id: "CSF-RS.MA-01".to_string(),
            control_id: "RS.MA-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Incident Management".to_string(),
            description: "Incidents are managed to ensure responses are aligned with organizational needs.".to_string(),
            category: "Respond".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Implement incident management process with defined roles.".to_string()),
        },
        ComplianceControl {
            id: "CSF-RS.AN-03".to_string(),
            control_id: "RS.AN-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Incident Analysis".to_string(),
            description: "Analysis is performed to establish what has taken place during an incident.".to_string(),
            category: "Respond".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Establish forensic analysis capabilities and procedures.".to_string()),
        },
        ComplianceControl {
            id: "CSF-RS.CO-02".to_string(),
            control_id: "RS.CO-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Incident Reporting".to_string(),
            description: "Incidents are reported consistent with established criteria.".to_string(),
            category: "Respond".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Document reporting requirements and communication templates.".to_string()),
        },
        ComplianceControl {
            id: "CSF-RS.MI-01".to_string(),
            control_id: "RS.MI-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Incident Containment".to_string(),
            description: "Incidents are contained.".to_string(),
            category: "Respond".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Develop containment playbooks for common incident types.".to_string()),
        },
        ComplianceControl {
            id: "CSF-RS.MI-02".to_string(),
            control_id: "RS.MI-02".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Incident Eradication".to_string(),
            description: "Incidents are eradicated.".to_string(),
            category: "Respond".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Document eradication procedures and verify complete removal.".to_string()),
        },

        // RECOVER (RC) Function
        ComplianceControl {
            id: "CSF-RC.RP-01".to_string(),
            control_id: "RC.RP-01".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Recovery Plan Execution".to_string(),
            description: "The recovery portion of the incident response plan is executed.".to_string(),
            category: "Recover".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-10".to_string()],
            remediation_guidance: Some("Maintain and test recovery procedures for critical systems.".to_string()),
        },
        ComplianceControl {
            id: "CSF-RC.RP-03".to_string(),
            control_id: "RC.RP-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Backup Integrity Verification".to_string(),
            description: "The integrity of backups and other restoration assets is verified.".to_string(),
            category: "Recover".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-11.5".to_string()],
            remediation_guidance: Some("Perform regular backup integrity verification and restore tests.".to_string()),
        },
        ComplianceControl {
            id: "CSF-RC.RP-05".to_string(),
            control_id: "RC.RP-05".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Post-Incident Review".to_string(),
            description: "The effectiveness of response and recovery activities is evaluated.".to_string(),
            category: "Recover".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Conduct post-incident reviews and implement lessons learned.".to_string()),
        },
        ComplianceControl {
            id: "CSF-RC.CO-03".to_string(),
            control_id: "RC.CO-03".to_string(),
            framework: ComplianceFramework::NistCsf,
            title: "Recovery Communication".to_string(),
            description: "Recovery activities and progress in restoring are communicated to stakeholders.".to_string(),
            category: "Recover".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![],
            remediation_guidance: Some("Establish communication plan for recovery status updates.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant NIST CSF controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Asset management issues
    if title_lower.contains("unknown device")
        || title_lower.contains("unauthorized asset")
    {
        mappings.push(("CSF-ID.AM-01".to_string(), Severity::Medium));
        mappings.push(("CSF-ID.AM-02".to_string(), Severity::Medium));
    }

    // Vulnerability findings
    if title_lower.contains("cve")
        || title_lower.contains("vulnerability")
        || title_lower.contains("exploit")
    {
        mappings.push(("CSF-ID.RA-01".to_string(), Severity::High));
        mappings.push(("CSF-DE.CM-09".to_string(), Severity::High));
    }

    // Authentication issues
    if title_lower.contains("authentication")
        || title_lower.contains("password")
        || title_lower.contains("credential")
    {
        mappings.push(("CSF-PR.AA-01".to_string(), Severity::High));
        mappings.push(("CSF-PR.AA-02".to_string(), Severity::High));
    }

    // Access control issues
    if title_lower.contains("unauthorized access")
        || title_lower.contains("privilege")
    {
        mappings.push(("CSF-PR.AA-03".to_string(), Severity::Critical));
    }

    // Encryption issues
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
    {
        mappings.push(("CSF-PR.DS-01".to_string(), Severity::High));
        mappings.push(("CSF-PR.DS-02".to_string(), Severity::High));
    }

    // Configuration issues
    if title_lower.contains("misconfigur")
        || title_lower.contains("default")
    {
        mappings.push(("CSF-PR.PS-01".to_string(), Severity::Medium));
    }

    // Patching issues
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
    {
        mappings.push(("CSF-PR.PS-02".to_string(), Severity::High));
    }

    // Network security issues
    if title_lower.contains("firewall")
        || title_lower.contains("network")
        || title_lower.contains("segmentation")
    {
        mappings.push(("CSF-PR.AA-05".to_string(), Severity::High));
    }

    // Logging issues
    if title_lower.contains("logging")
        || title_lower.contains("audit")
    {
        mappings.push(("CSF-PR.PS-04".to_string(), Severity::Medium));
    }

    // Monitoring gaps
    if title_lower.contains("unmonitored")
        || title_lower.contains("no detection")
    {
        mappings.push(("CSF-DE.CM-01".to_string(), Severity::Medium));
    }

    mappings
}
