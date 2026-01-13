//! NIST SP 800-82 Rev 3 - Guide to Operational Technology (OT) Security
//!
//! This module contains controls for securing Industrial Control Systems (ICS),
//! including SCADA, DCS, PLCs, and other operational technology environments.
//! NIST 800-82 provides guidance on integrating IT security with OT-specific
//! requirements while maintaining safety and operational availability.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NIST 800-82 controls in this module
pub const CONTROL_COUNT: usize = 52;

/// Get all NIST 800-82 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // ICS Access Control (ICS-AC)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-AC-1".to_string(),
            control_id: "ICS-AC-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Access Control Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate access control policies and procedures specific to ICS environments, addressing unique OT requirements and safety considerations.".to_string(),
            category: "ICS Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-1".to_string(),
                "IEC-62443-2-1-4.3.3.3".to_string(),
            ],
            remediation_guidance: Some("Document ICS-specific access control policies that address operator roles, emergency access procedures, and integration with safety systems.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AC-2".to_string(),
            control_id: "ICS-AC-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Account Management".to_string(),
            description: "Manage ICS accounts including HMI operator accounts, engineering workstation accounts, and shared operational accounts with proper authorization and review.".to_string(),
            category: "ICS Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-2".to_string(),
                "IEC-62443-2-1-4.3.3.5".to_string(),
            ],
            remediation_guidance: Some("Implement centralized account management for ICS with role-based access, regular reviews, and procedures for shared operator accounts.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AC-3".to_string(),
            control_id: "ICS-AC-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Access Enforcement".to_string(),
            description: "Enforce approved authorizations for logical access to ICS components including PLCs, RTUs, HMIs, and engineering workstations.".to_string(),
            category: "ICS Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-3".to_string(),
                "IEC-62443-3-3-SR-2.1".to_string(),
            ],
            remediation_guidance: Some("Implement role-based access control on all ICS components; restrict engineering access to authorized personnel only.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AC-4".to_string(),
            control_id: "ICS-AC-4".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Remote Access Control".to_string(),
            description: "Control and monitor remote access to ICS environments including vendor access, remote engineering, and remote operations support.".to_string(),
            category: "ICS Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-17".to_string(),
                "IEC-62443-3-3-SR-1.13".to_string(),
            ],
            remediation_guidance: Some("Implement jump servers for remote ICS access; require MFA; log and monitor all remote sessions; disable remote access when not in use.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AC-5".to_string(),
            control_id: "ICS-AC-5".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Separation of Duties".to_string(),
            description: "Separate duties for ICS operations, engineering, maintenance, and security to prevent unauthorized changes and ensure operational integrity.".to_string(),
            category: "ICS Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-5".to_string(),
                "IEC-62443-2-1-4.3.3.4".to_string(),
            ],
            remediation_guidance: Some("Define separate roles for ICS operators, engineers, maintenance technicians, and security personnel with distinct access rights.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AC-6".to_string(),
            control_id: "ICS-AC-6".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Least Privilege".to_string(),
            description: "Apply least privilege principle to ICS access, limiting users to minimum access required for their operational role.".to_string(),
            category: "ICS Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-6".to_string(),
                "IEC-62443-3-3-SR-2.1".to_string(),
            ],
            remediation_guidance: Some("Review and minimize ICS access rights; operators should not have engineering access; use time-limited elevated privileges.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AC-7".to_string(),
            control_id: "ICS-AC-7".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Emergency Access".to_string(),
            description: "Establish and document emergency access procedures for ICS that balance security with operational safety requirements.".to_string(),
            category: "ICS Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-2".to_string(),
                "IEC-62443-2-1-4.3.3.6".to_string(),
            ],
            remediation_guidance: Some("Document break-glass procedures for emergency ICS access; ensure procedures do not compromise safety systems; conduct annual drills.".to_string()),
        },

        // ============================================================
        // Network Segmentation for SCADA/DCS (ICS-SC)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-SC-1".to_string(),
            control_id: "ICS-SC-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Network Architecture Documentation".to_string(),
            description: "Document ICS network architecture including network diagrams, data flow diagrams, and connectivity between IT and OT networks.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-8".to_string(),
                "IEC-62443-2-1-4.2.3.4".to_string(),
            ],
            remediation_guidance: Some("Create and maintain accurate network diagrams showing all ICS zones, conduits, and connections to corporate/external networks.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SC-2".to_string(),
            control_id: "ICS-SC-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "DMZ Architecture".to_string(),
            description: "Implement a demilitarized zone (DMZ) between corporate IT networks and ICS networks to control and monitor traffic flow.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "IEC-62443-3-3-SR-5.1".to_string(),
            ],
            remediation_guidance: Some("Deploy ICS DMZ with data diodes or application proxies; no direct connections between IT and ICS control networks.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SC-3".to_string(),
            control_id: "ICS-SC-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Zone and Conduit Segmentation".to_string(),
            description: "Implement zone and conduit network segmentation model per IEC 62443, separating ICS into security zones based on criticality and function.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "IEC-62443-3-2-ZCR".to_string(),
            ],
            remediation_guidance: Some("Define security zones (Level 0-4 per Purdue model); implement firewalls at zone boundaries; document all conduits.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SC-4".to_string(),
            control_id: "ICS-SC-4".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Firewall Configuration".to_string(),
            description: "Configure firewalls protecting ICS networks with rules specific to ICS protocols and operational requirements.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "IEC-62443-3-3-SR-5.2".to_string(),
            ],
            remediation_guidance: Some("Configure ICS-aware firewalls with whitelist rules for ICS protocols (Modbus, DNP3, OPC); enable deep packet inspection.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SC-5".to_string(),
            control_id: "ICS-SC-5".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Safety System Isolation".to_string(),
            description: "Isolate safety instrumented systems (SIS) from control networks and IT networks to prevent unauthorized modification.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "IEC-62443-3-3-SR-5.1".to_string(),
                "IEC-61511".to_string(),
            ],
            remediation_guidance: Some("Implement air-gap or unidirectional gateway between SIS and control networks; restrict engineering access to SIS.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SC-6".to_string(),
            control_id: "ICS-SC-6".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Unidirectional Security Gateways".to_string(),
            description: "Implement unidirectional security gateways (data diodes) where appropriate to ensure one-way data flow from ICS to corporate networks.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "IEC-62443-3-3-SR-5.1".to_string(),
            ],
            remediation_guidance: Some("Deploy data diodes for historian replication and monitoring data transfer from ICS to IT; evaluate operational impact.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SC-7".to_string(),
            control_id: "ICS-SC-7".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Wireless Network Security".to_string(),
            description: "Secure wireless networks in ICS environments including industrial wireless, WiFi, and cellular connections.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-18".to_string(),
                "IEC-62443-3-3-SR-5.3".to_string(),
            ],
            remediation_guidance: Some("Implement WPA3-Enterprise for industrial WiFi; segment wireless from critical control networks; monitor for rogue access points.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SC-8".to_string(),
            control_id: "ICS-SC-8".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Protocol Security".to_string(),
            description: "Implement security controls for ICS protocols including Modbus, DNP3, EtherNet/IP, OPC UA, and legacy protocols.".to_string(),
            category: "Network Segmentation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-8".to_string(),
                "IEC-62443-3-3-SR-3.1".to_string(),
            ],
            remediation_guidance: Some("Use secure protocol versions (OPC UA, Secure DNP3) where possible; implement protocol-aware firewalls; encrypt sensitive communications.".to_string()),
        },

        // ============================================================
        // Audit and Monitoring for OT Environments (ICS-AU)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-AU-1".to_string(),
            control_id: "ICS-AU-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Audit Policy".to_string(),
            description: "Establish audit and logging policies for ICS that capture security-relevant events while considering resource constraints of OT devices.".to_string(),
            category: "Audit and Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-1".to_string(),
                "IEC-62443-3-3-SR-6.1".to_string(),
            ],
            remediation_guidance: Some("Define ICS logging requirements balancing security needs with device capabilities; prioritize critical event logging.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AU-2".to_string(),
            control_id: "ICS-AU-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Event Logging".to_string(),
            description: "Log security-relevant events on ICS components including authentication, configuration changes, and operational commands.".to_string(),
            category: "Audit and Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-2".to_string(),
                "IEC-62443-3-3-SR-6.1".to_string(),
            ],
            remediation_guidance: Some("Enable logging on HMIs, historians, engineering workstations; capture PLC program changes and operator commands.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AU-3".to_string(),
            control_id: "ICS-AU-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Network Traffic Monitoring".to_string(),
            description: "Monitor ICS network traffic for anomalies, unauthorized communications, and potential cyber attacks.".to_string(),
            category: "Audit and Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SI-4".to_string(),
                "IEC-62443-3-3-SR-6.2".to_string(),
            ],
            remediation_guidance: Some("Deploy ICS-specific intrusion detection; implement network traffic analysis for OT protocols; establish traffic baselines.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AU-4".to_string(),
            control_id: "ICS-AU-4".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Process Historian Security".to_string(),
            description: "Secure process historians and ensure integrity of historical process data for forensics and compliance.".to_string(),
            category: "Audit and Monitoring".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-9".to_string(),
                "IEC-62443-3-3-SR-6.1".to_string(),
            ],
            remediation_guidance: Some("Harden historian servers; implement access controls; ensure data integrity through checksums or digital signatures.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AU-5".to_string(),
            control_id: "ICS-AU-5".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Security Information Integration".to_string(),
            description: "Integrate ICS security event data with enterprise SIEM while maintaining network segmentation.".to_string(),
            category: "Audit and Monitoring".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-6".to_string(),
                "IEC-62443-3-3-SR-6.2".to_string(),
            ],
            remediation_guidance: Some("Use unidirectional data transfer for SIEM integration; deploy OT-specific SIEM or log collectors in DMZ.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AU-6".to_string(),
            control_id: "ICS-AU-6".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Anomaly Detection".to_string(),
            description: "Implement anomaly detection for ICS process behavior and network communications to identify potential attacks or equipment issues.".to_string(),
            category: "Audit and Monitoring".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SI-4".to_string(),
                "IEC-62443-3-3-SR-3.5".to_string(),
            ],
            remediation_guidance: Some("Deploy OT network monitoring with baseline analysis; implement process anomaly detection; alert on deviation from normal operations.".to_string()),
        },

        // ============================================================
        // Patch Management for ICS (ICS-SI)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-SI-1".to_string(),
            control_id: "ICS-SI-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Patch Management Policy".to_string(),
            description: "Establish patch management policies for ICS that balance security with operational availability and vendor support requirements.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-SI-2".to_string(),
                "IEC-62443-2-3".to_string(),
            ],
            remediation_guidance: Some("Document ICS patching procedures including vendor approval requirements, testing protocols, and rollback procedures.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SI-2".to_string(),
            control_id: "ICS-SI-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Vulnerability Assessment".to_string(),
            description: "Conduct vulnerability assessments of ICS components using OT-appropriate scanning methods that do not impact operations.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-5".to_string(),
                "IEC-62443-2-1-4.2.3.7".to_string(),
            ],
            remediation_guidance: Some("Use passive network scanning for production ICS; conduct active scans during maintenance windows; validate scanner compatibility.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SI-3".to_string(),
            control_id: "ICS-SI-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Patch Testing".to_string(),
            description: "Test patches in a representative ICS test environment before deployment to production systems.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-SI-2".to_string(),
                "IEC-62443-2-3-4.3".to_string(),
            ],
            remediation_guidance: Some("Maintain ICS test environment mirroring production; test patches with vendor approval; validate control system functionality.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SI-4".to_string(),
            control_id: "ICS-SI-4".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Legacy System Compensating Controls".to_string(),
            description: "Implement compensating controls for legacy ICS components that cannot be patched or updated.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SA-22".to_string(),
                "IEC-62443-2-1-4.2.3.12".to_string(),
            ],
            remediation_guidance: Some("Document legacy systems; implement network isolation, application whitelisting, and enhanced monitoring as compensating controls.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SI-5".to_string(),
            control_id: "ICS-SI-5".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Malware Protection".to_string(),
            description: "Implement malware protection for ICS components where feasible, using OT-compatible solutions that do not impact real-time operations.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SI-3".to_string(),
                "IEC-62443-3-3-SR-3.2".to_string(),
            ],
            remediation_guidance: Some("Deploy ICS-certified antimalware on HMIs and engineering workstations; use application whitelisting on critical systems.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-SI-6".to_string(),
            control_id: "ICS-SI-6".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Application Whitelisting".to_string(),
            description: "Implement application whitelisting on ICS workstations and servers to prevent execution of unauthorized code.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-7".to_string(),
                "IEC-62443-3-3-SR-3.2".to_string(),
            ],
            remediation_guidance: Some("Deploy application whitelisting on HMIs, engineering workstations, and servers; maintain whitelist with vendor-approved applications.".to_string()),
        },

        // ============================================================
        // Incident Response for ICS (ICS-IR)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-IR-1".to_string(),
            control_id: "ICS-IR-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Incident Response Plan".to_string(),
            description: "Develop incident response plans specific to ICS that address cyber-physical attacks and operational safety considerations.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-1".to_string(),
                "IEC-62443-2-1-4.3.4.5".to_string(),
            ],
            remediation_guidance: Some("Document ICS-specific incident response procedures; integrate with safety procedures; define roles for OT and IT personnel.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-IR-2".to_string(),
            control_id: "ICS-IR-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Incident Response Team".to_string(),
            description: "Establish incident response team with expertise in both cybersecurity and industrial control systems operations.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-4".to_string(),
                "IEC-62443-2-1-4.3.4.5".to_string(),
            ],
            remediation_guidance: Some("Train incident response team on ICS protocols and safety systems; establish communication with ICS-CERT and vendors.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-IR-3".to_string(),
            control_id: "ICS-IR-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Incident Detection".to_string(),
            description: "Implement detection capabilities for ICS-specific attack techniques and indicators of compromise.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-5".to_string(),
                "IEC-62443-3-3-SR-6.2".to_string(),
            ],
            remediation_guidance: Some("Deploy OT-specific threat detection; monitor for ICS malware indicators; implement detection for protocol anomalies.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-IR-4".to_string(),
            control_id: "ICS-IR-4".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Incident Containment".to_string(),
            description: "Establish incident containment procedures that can isolate affected ICS components while maintaining safe operations.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-4".to_string(),
                "IEC-62443-2-1-4.3.4.5.5".to_string(),
            ],
            remediation_guidance: Some("Document network isolation procedures that preserve safety; pre-configure firewall rules for containment; test procedures during exercises.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-IR-5".to_string(),
            control_id: "ICS-IR-5".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Recovery Procedures".to_string(),
            description: "Establish and test recovery procedures for ICS systems including backup restoration and system rebuilding.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CP-10".to_string(),
                "IEC-62443-2-1-4.3.4.5.9".to_string(),
            ],
            remediation_guidance: Some("Maintain offline backups of ICS configurations; document recovery procedures; conduct annual recovery exercises.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-IR-6".to_string(),
            control_id: "ICS-IR-6".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Tabletop Exercises".to_string(),
            description: "Conduct regular tabletop exercises and simulations specific to ICS cyber incidents.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-2".to_string(),
                "IEC-62443-2-1-4.3.4.5".to_string(),
            ],
            remediation_guidance: Some("Conduct quarterly tabletop exercises for ICS incidents; involve operations, engineering, IT security, and management.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-IR-7".to_string(),
            control_id: "ICS-IR-7".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Forensics Capability".to_string(),
            description: "Establish forensics capabilities appropriate for ICS environments including collection of OT-specific evidence.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-9".to_string(),
                "IEC-62443-2-1-4.3.4.5.6".to_string(),
            ],
            remediation_guidance: Some("Train personnel on ICS forensics; maintain forensic tools compatible with ICS; document chain of custody procedures.".to_string()),
        },

        // ============================================================
        // Physical Security for Control Systems (ICS-PE)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-PE-1".to_string(),
            control_id: "ICS-PE-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Physical Access Control".to_string(),
            description: "Implement physical access controls for ICS components including control rooms, equipment cabinets, and remote sites.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PE-3".to_string(),
                "IEC-62443-2-1-4.3.3.3.2".to_string(),
            ],
            remediation_guidance: Some("Implement badge access for control rooms; lock network cabinets; install physical security for remote substations/RTUs.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-PE-2".to_string(),
            control_id: "ICS-PE-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Control Room Security".to_string(),
            description: "Secure control rooms with appropriate physical access controls, monitoring, and environmental protections.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PE-3".to_string(),
                "IEC-62443-2-1-4.3.3.3".to_string(),
            ],
            remediation_guidance: Some("Implement multi-factor physical access; install CCTV; limit and log visitor access; maintain environmental controls.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-PE-3".to_string(),
            control_id: "ICS-PE-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Remote Site Physical Security".to_string(),
            description: "Implement appropriate physical security for unmanned remote ICS sites including substations, pump stations, and RTU locations.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PE-3".to_string(),
                "IEC-62443-2-1-4.3.3.3".to_string(),
            ],
            remediation_guidance: Some("Install perimeter fencing, intrusion detection, and tamper-evident enclosures; implement remote monitoring of physical access.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-PE-4".to_string(),
            control_id: "ICS-PE-4".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Network Infrastructure Physical Security".to_string(),
            description: "Protect physical network infrastructure including cables, switches, and wireless equipment from tampering.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-PE-4".to_string(),
                "IEC-62443-2-1-4.3.3.3".to_string(),
            ],
            remediation_guidance: Some("Use locked cabinets for network equipment; install conduit for cables; implement cable integrity monitoring where feasible.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-PE-5".to_string(),
            control_id: "ICS-PE-5".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Portable Media Controls".to_string(),
            description: "Control the use of portable media and devices in ICS environments to prevent malware introduction.".to_string(),
            category: "Physical Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-MP-7".to_string(),
                "IEC-62443-3-3-SR-2.3".to_string(),
            ],
            remediation_guidance: Some("Implement USB scanning kiosks; disable USB ports on critical systems; establish procedures for vendor media.".to_string()),
        },

        // ============================================================
        // Configuration Management (ICS-CM)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-CM-1".to_string(),
            control_id: "ICS-CM-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Asset Inventory".to_string(),
            description: "Maintain comprehensive inventory of all ICS assets including PLCs, RTUs, HMIs, network devices, and software versions.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-8".to_string(),
                "IEC-62443-2-1-4.2.3.4".to_string(),
            ],
            remediation_guidance: Some("Deploy OT asset discovery tools; maintain CMDB for ICS assets; track firmware and software versions.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-CM-2".to_string(),
            control_id: "ICS-CM-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Baseline Configuration".to_string(),
            description: "Establish and maintain secure baseline configurations for ICS components including PLCs, HMIs, and network devices.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-2".to_string(),
                "IEC-62443-2-1-4.3.4.3.2".to_string(),
            ],
            remediation_guidance: Some("Document secure configurations; use vendor hardening guides; implement configuration monitoring tools.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-CM-3".to_string(),
            control_id: "ICS-CM-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Change Management".to_string(),
            description: "Implement change management procedures for ICS that include security review and operational impact assessment.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-3".to_string(),
                "IEC-62443-2-1-4.3.4.3".to_string(),
            ],
            remediation_guidance: Some("Implement formal change control for ICS; require security review; document changes to PLC programs and configurations.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-CM-4".to_string(),
            control_id: "ICS-CM-4".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "PLC/RTU Program Backup".to_string(),
            description: "Maintain backups of PLC programs, RTU configurations, and control logic with version control and integrity verification.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CP-9".to_string(),
                "IEC-62443-2-1-4.3.4.3.8".to_string(),
            ],
            remediation_guidance: Some("Implement automated PLC backup; maintain version history; store backups offline; verify backup integrity regularly.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-CM-5".to_string(),
            control_id: "ICS-CM-5".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Hardening".to_string(),
            description: "Harden ICS components by disabling unnecessary services, removing default accounts, and applying security configurations.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-7".to_string(),
                "IEC-62443-3-3-SR-7.6".to_string(),
            ],
            remediation_guidance: Some("Apply vendor hardening guides; disable unused ports and services; remove default credentials; document hardening procedures.".to_string()),
        },

        // ============================================================
        // Awareness and Training (ICS-AT)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-AT-1".to_string(),
            control_id: "ICS-AT-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Security Awareness Training".to_string(),
            description: "Provide security awareness training to all personnel with access to ICS environments, covering OT-specific threats.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AT-2".to_string(),
                "IEC-62443-2-1-4.3.2.4".to_string(),
            ],
            remediation_guidance: Some("Develop ICS-specific security awareness training; cover social engineering, USB threats, and safe browsing for operators.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-AT-2".to_string(),
            control_id: "ICS-AT-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Security Role-Based Training".to_string(),
            description: "Provide role-specific security training for ICS operators, engineers, and administrators.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AT-3".to_string(),
                "IEC-62443-2-1-4.3.2.4".to_string(),
            ],
            remediation_guidance: Some("Develop training tracks for ICS operators, control engineers, network administrators, and security personnel.".to_string()),
        },

        // ============================================================
        // Risk Assessment (ICS-RA)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-RA-1".to_string(),
            control_id: "ICS-RA-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Risk Assessment".to_string(),
            description: "Conduct risk assessments specific to ICS that consider cyber-physical impacts, safety, and operational consequences.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-3".to_string(),
                "IEC-62443-3-2".to_string(),
            ],
            remediation_guidance: Some("Conduct annual ICS risk assessments using methodologies that account for physical consequences; involve operations personnel.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-RA-2".to_string(),
            control_id: "ICS-RA-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Security Level Targeting".to_string(),
            description: "Determine target security levels for ICS zones and conduits based on risk assessment per IEC 62443.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-RA-2".to_string(),
                "IEC-62443-3-2-ZCR-4".to_string(),
            ],
            remediation_guidance: Some("Define target security levels (SL-T) for each zone based on consequence analysis; map required controls to security levels.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-RA-3".to_string(),
            control_id: "ICS-RA-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Supply Chain Risk Management".to_string(),
            description: "Assess and manage supply chain risks for ICS components including software, firmware, and hardware.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-SA-12".to_string(),
                "IEC-62443-2-4".to_string(),
            ],
            remediation_guidance: Some("Evaluate ICS vendor security practices; verify component authenticity; assess risks from third-party integrators.".to_string()),
        },

        // ============================================================
        // Contingency Planning (ICS-CP)
        // ============================================================
        ComplianceControl {
            id: "NIST-800-82-CP-1".to_string(),
            control_id: "ICS-CP-1".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Business Continuity Planning".to_string(),
            description: "Develop business continuity plans for ICS that address cyber incidents and their impact on physical operations.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CP-1".to_string(),
                "IEC-62443-2-1-4.3.4.5".to_string(),
            ],
            remediation_guidance: Some("Develop ICS-specific BCP addressing cyber-physical scenarios; coordinate with safety and operations teams.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-CP-2".to_string(),
            control_id: "ICS-CP-2".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "Manual Operations Capability".to_string(),
            description: "Maintain capability to operate critical processes manually in case of cyber incident or control system failure.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CP-10".to_string(),
                "IEC-62443-2-1-4.3.4.5.9".to_string(),
            ],
            remediation_guidance: Some("Document manual operation procedures; train operators on manual controls; conduct periodic manual operation drills.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-82-CP-3".to_string(),
            control_id: "ICS-CP-3".to_string(),
            framework: ComplianceFramework::Nist80082,
            title: "ICS Backup and Recovery".to_string(),
            description: "Implement backup and recovery procedures for ICS components including system images, configurations, and control logic.".to_string(),
            category: "Contingency Planning".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CP-9".to_string(),
                "IEC-62443-2-1-4.3.4.3.8".to_string(),
            ],
            remediation_guidance: Some("Maintain full system backups including OS images, applications, and configurations; test restoration procedures quarterly.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant NIST 800-82 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();
    let service_lower = service.map(|s| s.to_lowercase()).unwrap_or_default();

    // ICS Protocol vulnerabilities
    if title_lower.contains("modbus")
        || title_lower.contains("dnp3")
        || title_lower.contains("opc")
        || title_lower.contains("bacnet")
        || title_lower.contains("profinet")
    {
        mappings.push(("ICS-SC-8".to_string(), Severity::High));
        mappings.push(("ICS-AU-3".to_string(), Severity::Medium));
    }

    // Common ICS ports
    match port {
        Some(502) => {
            // Modbus
            mappings.push(("ICS-SC-8".to_string(), Severity::High));
            mappings.push(("ICS-SC-4".to_string(), Severity::High));
        }
        Some(20000) | Some(20547) => {
            // DNP3
            mappings.push(("ICS-SC-8".to_string(), Severity::High));
            mappings.push(("ICS-SC-4".to_string(), Severity::High));
        }
        Some(4840) | Some(4843) => {
            // OPC UA
            mappings.push(("ICS-SC-8".to_string(), Severity::High));
        }
        Some(102) => {
            // S7comm (Siemens)
            mappings.push(("ICS-SC-8".to_string(), Severity::Critical));
            mappings.push(("ICS-AC-3".to_string(), Severity::High));
        }
        Some(44818) => {
            // EtherNet/IP
            mappings.push(("ICS-SC-8".to_string(), Severity::High));
        }
        Some(47808) => {
            // BACnet
            mappings.push(("ICS-SC-8".to_string(), Severity::High));
        }
        _ => {}
    }

    // SCADA/HMI vulnerabilities
    if title_lower.contains("scada")
        || title_lower.contains("hmi")
        || title_lower.contains("plc")
        || title_lower.contains("rtu")
    {
        mappings.push(("ICS-AC-3".to_string(), Severity::Critical));
        mappings.push(("ICS-CM-2".to_string(), Severity::High));
        mappings.push(("ICS-SI-5".to_string(), Severity::High));
    }

    // Default credentials in ICS
    if title_lower.contains("default") && (title_lower.contains("password") || title_lower.contains("credential")) {
        mappings.push(("ICS-AC-2".to_string(), Severity::Critical));
        mappings.push(("ICS-CM-5".to_string(), Severity::Critical));
    }

    // Remote access vulnerabilities
    if title_lower.contains("remote access")
        || title_lower.contains("vpn")
        || title_lower.contains("rdp")
    {
        mappings.push(("ICS-AC-4".to_string(), Severity::High));
        mappings.push(("ICS-SC-2".to_string(), Severity::High));
    }

    // Network segmentation issues
    if title_lower.contains("network segmentation")
        || title_lower.contains("flat network")
        || title_lower.contains("dmz")
    {
        mappings.push(("ICS-SC-2".to_string(), Severity::Critical));
        mappings.push(("ICS-SC-3".to_string(), Severity::Critical));
    }

    // Unencrypted communications
    if title_lower.contains("unencrypted")
        || title_lower.contains("cleartext")
        || title_lower.contains("plain text")
    {
        mappings.push(("ICS-SC-8".to_string(), Severity::High));
    }

    // Missing authentication
    if title_lower.contains("no authentication")
        || title_lower.contains("authentication bypass")
        || title_lower.contains("unauthenticated")
    {
        mappings.push(("ICS-AC-3".to_string(), Severity::Critical));
        mappings.push(("ICS-AC-2".to_string(), Severity::High));
    }

    // Patch/update vulnerabilities
    if title_lower.contains("unpatched")
        || title_lower.contains("outdated")
        || title_lower.contains("end of life")
        || title_lower.contains("legacy")
    {
        mappings.push(("ICS-SI-1".to_string(), Severity::High));
        mappings.push(("ICS-SI-4".to_string(), Severity::High));
    }

    // Malware concerns
    if title_lower.contains("malware")
        || title_lower.contains("ransomware")
        || title_lower.contains("worm")
    {
        mappings.push(("ICS-SI-5".to_string(), Severity::Critical));
        mappings.push(("ICS-SI-6".to_string(), Severity::High));
    }

    // Logging/monitoring gaps
    if title_lower.contains("no logging")
        || title_lower.contains("audit")
        || title_lower.contains("monitoring disabled")
    {
        mappings.push(("ICS-AU-2".to_string(), Severity::Medium));
        mappings.push(("ICS-AU-3".to_string(), Severity::Medium));
    }

    // Wireless vulnerabilities in ICS context
    if title_lower.contains("wireless")
        || title_lower.contains("wifi")
        || title_lower.contains("802.11")
        || service_lower.contains("wireless")
    {
        mappings.push(("ICS-SC-7".to_string(), Severity::High));
    }

    // Historian vulnerabilities
    if title_lower.contains("historian")
        || title_lower.contains("pi server")
        || title_lower.contains("osisoft")
    {
        mappings.push(("ICS-AU-4".to_string(), Severity::High));
        mappings.push(("ICS-SC-2".to_string(), Severity::Medium));
    }

    // Physical security issues detected via scan
    if title_lower.contains("physical")
        || title_lower.contains("tamper")
        || title_lower.contains("unlocked")
    {
        mappings.push(("ICS-PE-1".to_string(), Severity::High));
    }

    // USB/removable media
    if title_lower.contains("usb") || title_lower.contains("removable media") {
        mappings.push(("ICS-PE-5".to_string(), Severity::High));
    }

    // Safety system concerns
    if title_lower.contains("safety")
        || title_lower.contains("sis")
        || title_lower.contains("safety instrumented")
    {
        mappings.push(("ICS-SC-5".to_string(), Severity::Critical));
    }

    // Firewall misconfigurations
    if title_lower.contains("firewall")
        || title_lower.contains("open port")
        || title_lower.contains("exposed service")
    {
        mappings.push(("ICS-SC-4".to_string(), Severity::High));
        mappings.push(("ICS-SC-3".to_string(), Severity::Medium));
    }

    // Configuration/hardening issues
    if title_lower.contains("misconfiguration")
        || title_lower.contains("default config")
        || title_lower.contains("hardening")
    {
        mappings.push(("ICS-CM-5".to_string(), Severity::Medium));
        mappings.push(("ICS-CM-2".to_string(), Severity::Medium));
    }

    // Backup concerns
    if title_lower.contains("backup")
        || title_lower.contains("recovery")
        || title_lower.contains("disaster")
    {
        mappings.push(("ICS-CP-3".to_string(), Severity::Medium));
        mappings.push(("ICS-CM-4".to_string(), Severity::Medium));
    }

    // Vendor/supply chain
    if title_lower.contains("supply chain")
        || title_lower.contains("third party")
        || title_lower.contains("vendor")
    {
        mappings.push(("ICS-RA-3".to_string(), Severity::Medium));
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
    fn test_all_controls_have_required_fields() {
        for control in get_controls() {
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
            assert_eq!(control.framework, ComplianceFramework::Nist80082);
        }
    }

    #[test]
    fn test_map_modbus_vulnerability() {
        let mappings = map_vulnerability("Modbus service exposed without authentication", None, Some(502), None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ICS-SC-8"));
    }

    #[test]
    fn test_map_scada_vulnerability() {
        let mappings = map_vulnerability("SCADA system with default credentials", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ICS-AC-3"));
    }

    #[test]
    fn test_map_network_segmentation_vulnerability() {
        let mappings = map_vulnerability("Flat network with no ICS DMZ", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "ICS-SC-2"));
    }

    #[test]
    fn test_categories_coverage() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> = controls.iter().map(|c| c.category.as_str()).collect();

        // Verify key categories are present
        assert!(categories.contains("ICS Access Control"));
        assert!(categories.contains("Network Segmentation"));
        assert!(categories.contains("Audit and Monitoring"));
        assert!(categories.contains("Patch Management"));
        assert!(categories.contains("Incident Response"));
        assert!(categories.contains("Physical Security"));
        assert!(categories.contains("Configuration Management"));
    }

    #[test]
    fn test_cross_references_to_nist_800_53() {
        let controls = get_controls();
        let has_nist_refs = controls.iter().any(|c| {
            c.cross_references.iter().any(|r| r.starts_with("NIST-"))
        });
        assert!(has_nist_refs, "Should have cross-references to NIST 800-53");
    }

    #[test]
    fn test_cross_references_to_iec_62443() {
        let controls = get_controls();
        let has_iec_refs = controls.iter().any(|c| {
            c.cross_references.iter().any(|r| r.contains("IEC-62443") || r.contains("62443"))
        });
        assert!(has_iec_refs, "Should have cross-references to IEC 62443");
    }
}
