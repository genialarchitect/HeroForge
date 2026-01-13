//! NIST 800-61 Rev 2 Controls
//!
//! Computer Security Incident Handling Guide
//!
//! This module contains controls based on NIST Special Publication 800-61
//! Revision 2, which provides guidelines for incident handling, particularly
//! for analyzing incident-related data and determining the appropriate
//! response to each incident.
//!
//! The four incident handling phases covered are:
//! 1. Preparation
//! 2. Detection and Analysis
//! 3. Containment, Eradication, and Recovery
//! 4. Post-Incident Activity

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of NIST 800-61 controls in this module
pub const CONTROL_COUNT: usize = 42;

/// Get all NIST 800-61 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // PREPARATION CONTROLS
        // ============================================================
        ComplianceControl {
            id: "NIST-800-61-PREP-1".to_string(),
            control_id: "PREP-1".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Response Policy".to_string(),
            description: "Establish an incident response policy that defines the organization's commitment to incident response and assigns authority and responsibility.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string(), "PCI-DSS-12.10.1".to_string()],
            remediation_guidance: Some("Develop and document an incident response policy approved by senior management that includes scope, roles, reporting requirements, and communication procedures.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-2".to_string(),
            control_id: "PREP-2".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Response Plan".to_string(),
            description: "Develop an incident response plan that provides a roadmap for implementing the incident response program.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-8".to_string(), "PCI-DSS-12.10".to_string()],
            remediation_guidance: Some("Create a detailed incident response plan including mission, strategies, goals, organizational approach, communication methods, and metrics.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-3".to_string(),
            control_id: "PREP-3".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Response Team".to_string(),
            description: "Establish an incident response team (IRT) with clearly defined roles and responsibilities for handling security incidents.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string(), "PCI-DSS-12.10.3".to_string()],
            remediation_guidance: Some("Form a dedicated incident response team with defined roles (team leader, technical lead, communications liaison) and 24/7 coverage capability.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-4".to_string(),
            control_id: "PREP-4".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Response Training".to_string(),
            description: "Provide incident response training to incident handlers and other personnel with incident response roles.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-2".to_string(), "PCI-DSS-12.10.4".to_string()],
            remediation_guidance: Some("Conduct regular incident response training including tabletop exercises, hands-on drills, and simulated attacks at least annually.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-5".to_string(),
            control_id: "PREP-5".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Communication Equipment".to_string(),
            description: "Maintain necessary communication equipment and methods for incident response coordination.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Establish and test out-of-band communication methods including encrypted messaging, war room capabilities, and emergency contact lists.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-6".to_string(),
            control_id: "PREP-6".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Analysis Hardware and Software".to_string(),
            description: "Acquire and maintain incident analysis hardware and software tools for forensic analysis and incident investigation.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Deploy forensic workstations, disk imaging tools, memory analysis tools, network packet analyzers, and evidence collection software.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-7".to_string(),
            control_id: "PREP-7".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Documentation Resources".to_string(),
            description: "Maintain documentation resources including incident tracking systems and standard forms for incident documentation.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-5".to_string()],
            remediation_guidance: Some("Implement an incident tracking system (ticketing system) with standardized incident report templates and chain-of-custody forms.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-8".to_string(),
            control_id: "PREP-8".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Network Diagrams and Documentation".to_string(),
            description: "Maintain current network diagrams, asset inventories, and system documentation for incident response.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "PCI-DSS-1.1.2".to_string()],
            remediation_guidance: Some("Maintain up-to-date network topology diagrams, data flow diagrams, asset inventories, and critical system documentation accessible during incidents.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-9".to_string(),
            control_id: "PREP-9".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Cryptographic Keys and Credentials".to_string(),
            description: "Securely store cryptographic keys and credentials needed for incident response activities.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string()],
            remediation_guidance: Some("Maintain secure offline copies of administrative credentials, encryption keys, and certificates needed for emergency system access.".to_string()),
        },

        // ============================================================
        // DETECTION CONTROLS
        // ============================================================
        ComplianceControl {
            id: "NIST-800-61-DET-1".to_string(),
            control_id: "DET-1".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Security Event Logging".to_string(),
            description: "Implement comprehensive security event logging across all systems and applications.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string(), "NIST-AU-12".to_string(), "PCI-DSS-10.2".to_string()],
            remediation_guidance: Some("Enable and centralize security logging for authentication events, privilege changes, system events, and network activity.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-DET-2".to_string(),
            control_id: "DET-2".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "SIEM Deployment".to_string(),
            description: "Deploy Security Information and Event Management (SIEM) for log aggregation, correlation, and alerting.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string(), "NIST-SI-4".to_string()],
            remediation_guidance: Some("Implement SIEM with real-time log correlation, automated alerting, and dashboards for security monitoring.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-DET-3".to_string(),
            control_id: "DET-3".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Intrusion Detection Systems".to_string(),
            description: "Deploy network and host-based intrusion detection systems (IDS) to identify malicious activity.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string(), "PCI-DSS-11.4".to_string()],
            remediation_guidance: Some("Deploy NIDS at network perimeters and HIDS on critical systems with regularly updated signatures and behavioral analysis.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-DET-4".to_string(),
            control_id: "DET-4".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Endpoint Detection and Response".to_string(),
            description: "Implement endpoint detection and response (EDR) solutions for advanced threat detection on endpoints.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy EDR solutions with behavioral analysis, threat hunting capabilities, and automated response actions.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-DET-5".to_string(),
            control_id: "DET-5".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Network Traffic Analysis".to_string(),
            description: "Monitor network traffic for anomalies and indicators of compromise using network traffic analysis tools.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Implement network traffic analysis with baseline monitoring, anomaly detection, and full packet capture capability.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-DET-6".to_string(),
            control_id: "DET-6".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Threat Intelligence Integration".to_string(),
            description: "Integrate threat intelligence feeds into detection systems for proactive threat identification.".to_string(),
            category: "Detection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-PM-16".to_string()],
            remediation_guidance: Some("Subscribe to threat intelligence feeds and integrate IOCs (Indicators of Compromise) into SIEM and detection systems.".to_string()),
        },

        // ============================================================
        // ANALYSIS CONTROLS
        // ============================================================
        ComplianceControl {
            id: "NIST-800-61-ANA-1".to_string(),
            control_id: "ANA-1".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Categorization".to_string(),
            description: "Establish incident categorization criteria to classify incidents by type and severity.".to_string(),
            category: "Analysis".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Define incident categories (malware, denial of service, unauthorized access, etc.) and severity levels with escalation criteria.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ANA-2".to_string(),
            control_id: "ANA-2".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Prioritization".to_string(),
            description: "Implement incident prioritization procedures based on business impact and technical factors.".to_string(),
            category: "Analysis".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Develop prioritization matrix considering functional impact, information impact, and recoverability with clear handling time SLAs.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ANA-3".to_string(),
            control_id: "ANA-3".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Indicators of Compromise Analysis".to_string(),
            description: "Analyze indicators of compromise (IOCs) to understand attack scope and attribution.".to_string(),
            category: "Analysis".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Develop IOC analysis capabilities including file hashes, IP addresses, domain names, and behavioral patterns.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ANA-4".to_string(),
            control_id: "ANA-4".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Forensic Evidence Collection".to_string(),
            description: "Follow proper forensic evidence collection procedures to maintain evidence integrity.".to_string(),
            category: "Analysis".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Implement forensic evidence collection procedures including chain of custody, disk imaging, memory acquisition, and log preservation.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ANA-5".to_string(),
            control_id: "ANA-5".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Timeline Analysis".to_string(),
            description: "Perform timeline analysis to reconstruct incident events and determine attack sequence.".to_string(),
            category: "Analysis".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Use timeline analysis tools to correlate events across multiple systems and reconstruct attack chronology.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ANA-6".to_string(),
            control_id: "ANA-6".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Malware Analysis".to_string(),
            description: "Conduct malware analysis to understand malicious code behavior and capabilities.".to_string(),
            category: "Analysis".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Establish malware analysis capability including sandboxed execution environment and static/dynamic analysis tools.".to_string()),
        },

        // ============================================================
        // CONTAINMENT CONTROLS
        // ============================================================
        ComplianceControl {
            id: "NIST-800-61-CON-1".to_string(),
            control_id: "CON-1".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Containment Strategy".to_string(),
            description: "Develop containment strategies for different incident types to limit damage.".to_string(),
            category: "Containment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Document containment strategies for each incident category including network isolation, account disabling, and system shutdown criteria.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-CON-2".to_string(),
            control_id: "CON-2".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Network Segmentation Capability".to_string(),
            description: "Maintain capability to dynamically segment networks to contain incidents.".to_string(),
            category: "Containment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string(), "NIST-AC-4".to_string()],
            remediation_guidance: Some("Implement network segmentation controls that can be rapidly deployed including VLANs, firewall rules, and SDN policies.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-CON-3".to_string(),
            control_id: "CON-3".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Evidence Preservation".to_string(),
            description: "Preserve evidence during containment activities for potential legal proceedings.".to_string(),
            category: "Containment".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Implement evidence preservation procedures during containment including forensic imaging before system changes.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-CON-4".to_string(),
            control_id: "CON-4".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Attacker Identification".to_string(),
            description: "Attempt to identify the attacking host(s) and attacker while maintaining containment.".to_string(),
            category: "Containment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Document attacker identification procedures including IP tracing, WHOIS lookups, and coordination with ISPs and law enforcement.".to_string()),
        },

        // ============================================================
        // ERADICATION CONTROLS
        // ============================================================
        ComplianceControl {
            id: "NIST-800-61-ERA-1".to_string(),
            control_id: "ERA-1".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Malware Removal".to_string(),
            description: "Remove malware and other malicious artifacts from affected systems.".to_string(),
            category: "Eradication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Implement malware removal procedures using updated antivirus, manual removal techniques, and verification scanning.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ERA-2".to_string(),
            control_id: "ERA-2".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Vulnerability Remediation".to_string(),
            description: "Identify and remediate vulnerabilities that were exploited during the incident.".to_string(),
            category: "Eradication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "NIST-RA-5".to_string()],
            remediation_guidance: Some("Identify exploited vulnerabilities through analysis, apply patches or mitigations, and verify remediation effectiveness.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ERA-3".to_string(),
            control_id: "ERA-3".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Compromised Account Remediation".to_string(),
            description: "Reset credentials and remediate compromised user and service accounts.".to_string(),
            category: "Eradication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "NIST-AC-2".to_string()],
            remediation_guidance: Some("Force password resets for compromised accounts, revoke sessions, and review account privileges before re-enabling.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-ERA-4".to_string(),
            control_id: "ERA-4".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Backdoor Removal".to_string(),
            description: "Identify and remove attacker persistence mechanisms and backdoors.".to_string(),
            category: "Eradication".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Search for and remove backdoors including web shells, scheduled tasks, startup items, and rootkits.".to_string()),
        },

        // ============================================================
        // RECOVERY CONTROLS
        // ============================================================
        ComplianceControl {
            id: "NIST-800-61-REC-1".to_string(),
            control_id: "REC-1".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "System Restoration".to_string(),
            description: "Restore affected systems to normal operation from trusted backups or rebuild.".to_string(),
            category: "Recovery".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-9".to_string(), "NIST-CP-10".to_string()],
            remediation_guidance: Some("Restore systems from known-good backups or rebuild from trusted media, verifying integrity before returning to production.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-REC-2".to_string(),
            control_id: "REC-2".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Validation and Testing".to_string(),
            description: "Validate that systems are functioning properly after recovery before returning to production.".to_string(),
            category: "Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CP-4".to_string()],
            remediation_guidance: Some("Perform validation testing including functionality verification, security scans, and integrity checks before returning to production.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-REC-3".to_string(),
            control_id: "REC-3".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Enhanced Monitoring".to_string(),
            description: "Implement enhanced monitoring after recovery to detect any recurring malicious activity.".to_string(),
            category: "Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Increase monitoring sensitivity and frequency for recovered systems, watching for signs of attacker return or dormant threats.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-REC-4".to_string(),
            control_id: "REC-4".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Security Control Hardening".to_string(),
            description: "Implement additional security controls to prevent similar incidents.".to_string(),
            category: "Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-6".to_string()],
            remediation_guidance: Some("Apply additional hardening measures based on lessons learned including configuration changes, new detection rules, and access restrictions.".to_string()),
        },

        // ============================================================
        // LESSONS LEARNED CONTROLS
        // ============================================================
        ComplianceControl {
            id: "NIST-800-61-LL-1".to_string(),
            control_id: "LL-1".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Lessons Learned Meeting".to_string(),
            description: "Conduct post-incident lessons learned meeting within specified timeframe after major incidents.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-4".to_string()],
            remediation_guidance: Some("Hold lessons learned meetings within 2 weeks of incident closure, involving all stakeholders and documenting findings.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-LL-2".to_string(),
            control_id: "LL-2".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Documentation".to_string(),
            description: "Complete comprehensive incident documentation including timeline, actions taken, and outcomes.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-5".to_string()],
            remediation_guidance: Some("Document incidents using standardized templates including executive summary, technical details, timeline, and recommendations.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-LL-3".to_string(),
            control_id: "LL-3".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Evidence Retention".to_string(),
            description: "Retain incident evidence according to legal requirements and organizational policy.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AU-11".to_string()],
            remediation_guidance: Some("Implement evidence retention policies with secure storage, access controls, and defined retention periods based on legal requirements.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-LL-4".to_string(),
            control_id: "LL-4".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Policy and Procedure Updates".to_string(),
            description: "Update incident response policies and procedures based on lessons learned.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-1".to_string()],
            remediation_guidance: Some("Review and update incident response documentation incorporating improvements identified during lessons learned.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-LL-5".to_string(),
            control_id: "LL-5".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Incident Metrics and Reporting".to_string(),
            description: "Collect and analyze incident metrics to measure effectiveness and identify trends.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IR-5".to_string()],
            remediation_guidance: Some("Track incident metrics including MTTD, MTTR, incident counts by category, and trending analysis for management reporting.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-LL-6".to_string(),
            control_id: "LL-6".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Information Sharing".to_string(),
            description: "Share relevant incident information with peer organizations, ISACs, and government agencies.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::Low,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PM-16".to_string()],
            remediation_guidance: Some("Participate in information sharing programs like ISACs, sharing sanitized IOCs and TTPs while protecting sensitive information.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-LL-7".to_string(),
            control_id: "LL-7".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Detection Rule Updates".to_string(),
            description: "Create or update detection rules and signatures based on incident findings.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-4".to_string()],
            remediation_guidance: Some("Develop new SIEM correlation rules, IDS signatures, and EDR detection logic based on attack techniques observed.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-LL-8".to_string(),
            control_id: "LL-8".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "Security Architecture Review".to_string(),
            description: "Review and update security architecture based on lessons learned from incidents.".to_string(),
            category: "Lessons Learned".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-PL-8".to_string()],
            remediation_guidance: Some("Conduct security architecture reviews after significant incidents to identify structural improvements.".to_string()),
        },
        ComplianceControl {
            id: "NIST-800-61-PREP-10".to_string(),
            control_id: "PREP-10".to_string(),
            framework: ComplianceFramework::Nist80061,
            title: "External Communication Plan".to_string(),
            description: "Establish procedures for communicating with external parties including media, law enforcement, and regulatory bodies.".to_string(),
            category: "Preparation".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-IR-6".to_string()],
            remediation_guidance: Some("Develop communication templates and establish relationships with law enforcement, regulatory agencies, and legal counsel before incidents occur.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant NIST 800-61 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Detection capability issues
    if title_lower.contains("no logging")
        || title_lower.contains("logging disabled")
        || title_lower.contains("audit disabled")
    {
        mappings.push(("NIST-800-61-DET-1".to_string(), Severity::High));
        mappings.push(("NIST-800-61-DET-2".to_string(), Severity::High));
    }

    // Missing security monitoring
    if title_lower.contains("no ids")
        || title_lower.contains("intrusion detection disabled")
        || title_lower.contains("no monitoring")
    {
        mappings.push(("NIST-800-61-DET-3".to_string(), Severity::High));
        mappings.push(("NIST-800-61-DET-4".to_string(), Severity::Medium));
        mappings.push(("NIST-800-61-DET-5".to_string(), Severity::Medium));
    }

    // Active malware or compromise indicators
    if title_lower.contains("malware")
        || title_lower.contains("trojan")
        || title_lower.contains("backdoor")
        || title_lower.contains("rootkit")
    {
        mappings.push(("NIST-800-61-ANA-3".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-ANA-6".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-ERA-1".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-ERA-4".to_string(), Severity::Critical));
    }

    // Compromised accounts
    if title_lower.contains("compromised account")
        || title_lower.contains("credential theft")
        || title_lower.contains("stolen credentials")
    {
        mappings.push(("NIST-800-61-ERA-3".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-ANA-4".to_string(), Severity::High));
    }

    // Unpatched vulnerabilities
    if title_lower.contains("unpatched")
        || title_lower.contains("outdated")
        || title_lower.contains("cve-")
        || title_lower.contains("vulnerability")
    {
        mappings.push(("NIST-800-61-ERA-2".to_string(), Severity::High));
    }

    // Network segmentation issues
    if title_lower.contains("flat network")
        || title_lower.contains("no segmentation")
        || title_lower.contains("missing firewall")
    {
        mappings.push(("NIST-800-61-CON-2".to_string(), Severity::High));
    }

    // Backup and recovery issues
    if title_lower.contains("no backup")
        || title_lower.contains("backup missing")
        || title_lower.contains("recovery not tested")
    {
        mappings.push(("NIST-800-61-REC-1".to_string(), Severity::High));
        mappings.push(("NIST-800-61-PREP-8".to_string(), Severity::Medium));
    }

    // Incident response readiness issues
    if title_lower.contains("no incident response")
        || title_lower.contains("ir plan missing")
        || title_lower.contains("no ir team")
    {
        mappings.push(("NIST-800-61-PREP-1".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-PREP-2".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-PREP-3".to_string(), Severity::Critical));
    }

    // Forensic capability issues
    if title_lower.contains("no forensic")
        || title_lower.contains("evidence handling")
        || title_lower.contains("chain of custody")
    {
        mappings.push(("NIST-800-61-ANA-4".to_string(), Severity::High));
        mappings.push(("NIST-800-61-PREP-6".to_string(), Severity::Medium));
    }

    // Command and control indicators
    if title_lower.contains("c2")
        || title_lower.contains("command and control")
        || title_lower.contains("beaconing")
    {
        mappings.push(("NIST-800-61-CON-1".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-CON-4".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-DET-5".to_string(), Severity::High));
    }

    // Data exfiltration indicators
    if title_lower.contains("data exfiltration")
        || title_lower.contains("data leak")
        || title_lower.contains("unauthorized transfer")
    {
        mappings.push(("NIST-800-61-CON-1".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-CON-3".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-ANA-5".to_string(), Severity::High));
    }

    // Threat intelligence gaps
    if title_lower.contains("no threat intel")
        || title_lower.contains("outdated ioc")
        || title_lower.contains("missing threat feed")
    {
        mappings.push(("NIST-800-61-DET-6".to_string(), Severity::Medium));
    }

    // Unauthorized access detected
    if title_lower.contains("unauthorized access")
        || title_lower.contains("intrusion detected")
        || title_lower.contains("breach")
    {
        mappings.push(("NIST-800-61-ANA-1".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-ANA-2".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-CON-1".to_string(), Severity::Critical));
    }

    // Persistence mechanisms
    if title_lower.contains("persistence")
        || title_lower.contains("scheduled task")
        || title_lower.contains("startup item")
        || title_lower.contains("web shell")
    {
        mappings.push(("NIST-800-61-ERA-4".to_string(), Severity::Critical));
        mappings.push(("NIST-800-61-ANA-3".to_string(), Severity::High));
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
            assert_eq!(control.framework, ComplianceFramework::Nist80061);
        }
    }

    #[test]
    fn test_categories_cover_all_phases() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> =
            controls.iter().map(|c| c.category.as_str()).collect();

        assert!(categories.contains("Preparation"));
        assert!(categories.contains("Detection"));
        assert!(categories.contains("Analysis"));
        assert!(categories.contains("Containment"));
        assert!(categories.contains("Eradication"));
        assert!(categories.contains("Recovery"));
        assert!(categories.contains("Lessons Learned"));
    }

    #[test]
    fn test_vulnerability_mapping_malware() {
        let mappings = map_vulnerability("Malware detected on system", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "NIST-800-61-ERA-1"));
    }

    #[test]
    fn test_vulnerability_mapping_no_logging() {
        let mappings = map_vulnerability("No logging configured", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "NIST-800-61-DET-1"));
    }

    #[test]
    fn test_vulnerability_mapping_unauthorized_access() {
        let mappings = map_vulnerability("Unauthorized access detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "NIST-800-61-ANA-1"));
        assert!(mappings.iter().any(|(id, _)| id == "NIST-800-61-CON-1"));
    }

    #[test]
    fn test_unique_control_ids() {
        let controls = get_controls();
        let ids: std::collections::HashSet<_> = controls.iter().map(|c| &c.id).collect();
        assert_eq!(ids.len(), controls.len(), "Duplicate control IDs found");
    }
}
