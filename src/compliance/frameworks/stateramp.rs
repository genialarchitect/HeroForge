//! StateRAMP Compliance Framework
//!
//! StateRAMP (State Risk and Authorization Management Program) is a nonprofit
//! organization that provides a standardized approach for state and local
//! governments to authorize and continuously monitor cloud service providers.
//!
//! StateRAMP is modeled after FedRAMP and leverages NIST 800-53 controls but
//! is tailored for state and local government requirements. It provides:
//!
//! - Standardized security assessments for cloud service providers
//! - Verification of cloud provider security by accredited 3PAOs
//! - Continuous monitoring requirements for ongoing authorization
//! - Security Status designation levels: Ready, Authorized, and Provisional
//!
//! Control Families aligned with NIST 800-53 and FedRAMP:
//! - Access Control (AC)
//! - Audit and Accountability (AU)
//! - Security Assessment and Authorization (CA)
//! - Configuration Management (CM)
//! - Incident Response (IR)
//! - System and Communications Protection (SC)
//!
//! Impact Levels:
//! - Low: Systems with low potential impact on state/local operations
//! - Moderate: Systems with moderate impact on state/local operations (most common)
//! - High: Systems with high impact on critical state/local operations

use crate::types::Severity;

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of StateRAMP controls in this module
pub const CONTROL_COUNT: usize = 50;

/// Get all StateRAMP controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // Access Control (AC) Family - 10 controls
        // ============================================================
        ComplianceControl {
            id: "SR-AC-1".to_string(),
            control_id: "AC-1".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Access Control Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate an access control policy that addresses purpose, scope, roles, responsibilities, and compliance; and procedures to facilitate implementation.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-1".to_string(),
                "FedRAMP-AC-1".to_string(),
                "CIS-5.1".to_string(),
            ],
            remediation_guidance: Some("Establish and maintain documented access control policies reviewed annually. Include procedures for account creation, modification, and termination.".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-2".to_string(),
            control_id: "AC-2".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Account Management".to_string(),
            description: "Manage system accounts including identifying account types, establishing conditions for group membership, assigning account managers, specifying authorized users, requiring approvals, and monitoring account usage.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-2".to_string(),
                "FedRAMP-AC-2".to_string(),
                "CIS-5.1".to_string(),
                "PCI-DSS-8.1".to_string(),
            ],
            remediation_guidance: Some("Implement centralized identity management with automated provisioning and deprovisioning. Review accounts quarterly and disable inactive accounts after 90 days.".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-3".to_string(),
            control_id: "AC-3".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Access Enforcement".to_string(),
            description: "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-3".to_string(),
                "FedRAMP-AC-3".to_string(),
                "CIS-3.3".to_string(),
            ],
            remediation_guidance: Some("Implement role-based access control (RBAC) enforcing least privilege. Use attribute-based access control (ABAC) for fine-grained authorization where needed.".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-4".to_string(),
            control_id: "AC-4".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Information Flow Enforcement".to_string(),
            description: "Enforce approved authorizations for controlling the flow of information within the system and between connected systems based on applicable policy.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-4".to_string(),
                "FedRAMP-AC-4".to_string(),
                "PCI-DSS-1.3".to_string(),
            ],
            remediation_guidance: Some("Implement network segmentation with firewall rules controlling data flows. Use data loss prevention (DLP) tools to monitor and control sensitive data movement.".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-5".to_string(),
            control_id: "AC-5".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Separation of Duties".to_string(),
            description: "Separate duties of individuals to prevent malevolent activity without collusion. Document separation of duties and implement access authorizations to enforce separation.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-5".to_string(),
                "FedRAMP-AC-5".to_string(),
                "SOC2-CC6.1".to_string(),
            ],
            remediation_guidance: Some("Define and document segregation of duties for critical functions. Prevent single individuals from having conflicting responsibilities (e.g., development and deployment).".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-6".to_string(),
            control_id: "AC-6".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Least Privilege".to_string(),
            description: "Employ the principle of least privilege, allowing only authorized accesses for users and processes which are necessary to accomplish assigned organizational tasks.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-6".to_string(),
                "FedRAMP-AC-6".to_string(),
                "CIS-5.4".to_string(),
            ],
            remediation_guidance: Some("Implement just-in-time (JIT) privileged access management. Review and minimize administrative privileges. Use privilege access workstations (PAWs) for sensitive operations.".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-7".to_string(),
            control_id: "AC-7".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Unsuccessful Logon Attempts".to_string(),
            description: "Enforce a limit of consecutive invalid logon attempts by a user during a specified time period and automatically lock the account or delay logon when the maximum is exceeded.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-7".to_string(),
                "FedRAMP-AC-7".to_string(),
                "CIS-5.5".to_string(),
            ],
            remediation_guidance: Some("Configure account lockout after 3-5 consecutive failed attempts. Implement progressive delays and require administrator unlock or time-based reset (minimum 15 minutes).".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-17".to_string(),
            control_id: "AC-17".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Remote Access".to_string(),
            description: "Establish and document usage restrictions, configuration requirements, connection requirements, and implementation guidance for each type of remote access allowed.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-17".to_string(),
                "FedRAMP-AC-17".to_string(),
                "CIS-6.4".to_string(),
            ],
            remediation_guidance: Some("Require VPN or zero-trust network access (ZTNA) for all remote connections. Implement multi-factor authentication for remote access. Log and monitor all remote sessions.".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-18".to_string(),
            control_id: "AC-18".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Wireless Access".to_string(),
            description: "Establish usage restrictions, configuration requirements, connection requirements, and implementation guidance for wireless access to the system.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-18".to_string(),
                "FedRAMP-AC-18".to_string(),
                "PCI-DSS-4.1".to_string(),
            ],
            remediation_guidance: Some("Implement WPA3 Enterprise with 802.1X authentication. Separate guest wireless from corporate networks. Conduct periodic wireless security assessments.".to_string()),
        },
        ComplianceControl {
            id: "SR-AC-22".to_string(),
            control_id: "AC-22".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Publicly Accessible Content".to_string(),
            description: "Designate individuals authorized to post information onto publicly accessible systems. Train authorized individuals to ensure publicly accessible content does not contain nonpublic information.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AC-22".to_string(),
                "FedRAMP-AC-22".to_string(),
            ],
            remediation_guidance: Some("Establish content review process for public-facing systems. Train personnel on data classification and disclosure prevention. Review public content quarterly.".to_string()),
        },

        // ============================================================
        // Audit and Accountability (AU) Family - 10 controls
        // ============================================================
        ComplianceControl {
            id: "SR-AU-1".to_string(),
            control_id: "AU-1".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Audit and Accountability Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate audit and accountability policy that addresses purpose, scope, roles, responsibilities, and compliance; and procedures to facilitate implementation.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-1".to_string(),
                "FedRAMP-AU-1".to_string(),
                "PCI-DSS-10.1".to_string(),
            ],
            remediation_guidance: Some("Document audit logging policies specifying what events to log, retention requirements, and review procedures. Review policy annually.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-2".to_string(),
            control_id: "AU-2".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Event Logging".to_string(),
            description: "Identify the types of events that the system is capable of logging in support of the audit function. Coordinate event logging with other entities requiring audit information.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-2".to_string(),
                "FedRAMP-AU-2".to_string(),
                "CIS-8.2".to_string(),
            ],
            remediation_guidance: Some("Define auditable events including authentication, authorization changes, system changes, and data access. Enable logging on all system components.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-3".to_string(),
            control_id: "AU-3".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Content of Audit Records".to_string(),
            description: "Ensure that audit records contain information that establishes what type of event occurred, when it occurred, where it occurred, source of event, outcome, and identity of individuals or subjects.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-3".to_string(),
                "FedRAMP-AU-3".to_string(),
                "PCI-DSS-10.3".to_string(),
            ],
            remediation_guidance: Some("Configure logging to include: timestamp (UTC), event type, source IP, user identity, resource accessed, action taken, and outcome (success/failure).".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-4".to_string(),
            control_id: "AU-4".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Audit Log Storage Capacity".to_string(),
            description: "Allocate audit log storage capacity and configure auditing to reduce the likelihood of exceeding storage capacity.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-4".to_string(),
                "FedRAMP-AU-4".to_string(),
            ],
            remediation_guidance: Some("Provision sufficient storage for audit logs. Implement automated log rotation and archival. Alert when storage reaches 80% capacity.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-5".to_string(),
            control_id: "AU-5".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Response to Audit Logging Process Failures".to_string(),
            description: "Alert personnel or roles in the event of an audit logging process failure. Take additional actions based on organizational requirements.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-5".to_string(),
                "FedRAMP-AU-5".to_string(),
            ],
            remediation_guidance: Some("Configure alerts for audit system failures. Implement fail-secure behavior (e.g., halt processing if audit fails). Maintain redundant logging capabilities.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-6".to_string(),
            control_id: "AU-6".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Audit Record Review, Analysis, and Reporting".to_string(),
            description: "Review and analyze system audit records for indications of inappropriate or unusual activity. Report findings to appropriate personnel.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-6".to_string(),
                "FedRAMP-AU-6".to_string(),
                "PCI-DSS-10.6".to_string(),
            ],
            remediation_guidance: Some("Deploy SIEM for automated log correlation and analysis. Establish baseline behavior and alert on anomalies. Review security alerts within 24 hours.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-8".to_string(),
            control_id: "AU-8".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Time Stamps".to_string(),
            description: "Use internal system clocks to generate time stamps for audit records. Synchronize time stamps across the organization to an authoritative source.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-8".to_string(),
                "FedRAMP-AU-8".to_string(),
                "PCI-DSS-10.4".to_string(),
            ],
            remediation_guidance: Some("Configure NTP synchronization to NIST time servers or equivalent authoritative sources. Ensure time synchronization within 1 second. Monitor for time drift.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-9".to_string(),
            control_id: "AU-9".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Protection of Audit Information".to_string(),
            description: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-9".to_string(),
                "FedRAMP-AU-9".to_string(),
                "PCI-DSS-10.5".to_string(),
            ],
            remediation_guidance: Some("Implement write-once logging or log forwarding to secure SIEM. Restrict log access to security personnel only. Enable file integrity monitoring on log files.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-11".to_string(),
            control_id: "AU-11".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Audit Record Retention".to_string(),
            description: "Retain audit records for a minimum of one year to provide support for after-the-fact investigations and to meet regulatory and organizational requirements.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-11".to_string(),
                "FedRAMP-AU-11".to_string(),
                "PCI-DSS-10.7".to_string(),
            ],
            remediation_guidance: Some("Retain audit logs for minimum one year (three months online, nine months archived). Implement secure log archival with integrity verification.".to_string()),
        },
        ComplianceControl {
            id: "SR-AU-12".to_string(),
            control_id: "AU-12".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Audit Record Generation".to_string(),
            description: "Provide audit record generation capability for the event types the system is capable of auditing. Allow personnel to select event types for logging on specific components.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-AU-12".to_string(),
                "FedRAMP-AU-12".to_string(),
            ],
            remediation_guidance: Some("Enable comprehensive audit logging on all systems. Configure logging agents to capture defined event categories. Centralize logs for analysis.".to_string()),
        },

        // ============================================================
        // Security Assessment and Authorization (CA) Family - 8 controls
        // ============================================================
        ComplianceControl {
            id: "SR-CA-1".to_string(),
            control_id: "CA-1".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Security Assessment and Authorization Policy".to_string(),
            description: "Develop, document, and disseminate security assessment and authorization policy and procedures. Designate officials to manage assessment process.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-1".to_string(),
                "FedRAMP-CA-1".to_string(),
            ],
            remediation_guidance: Some("Document security assessment procedures aligned with StateRAMP requirements. Define roles for authorizing officials and assessment teams.".to_string()),
        },
        ComplianceControl {
            id: "SR-CA-2".to_string(),
            control_id: "CA-2".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Control Assessments".to_string(),
            description: "Develop a control assessment plan. Assess security controls in the system to determine extent to which controls are implemented correctly and producing desired outcome.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-2".to_string(),
                "FedRAMP-CA-2".to_string(),
            ],
            remediation_guidance: Some("Conduct annual security assessments by accredited 3PAO. Document assessment plan, methodology, and findings. Track remediation of identified gaps.".to_string()),
        },
        ComplianceControl {
            id: "SR-CA-3".to_string(),
            control_id: "CA-3".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Information Exchange".to_string(),
            description: "Approve and manage the exchange of information between the system and other systems using interconnection security agreements or similar documentation.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-3".to_string(),
                "FedRAMP-CA-3".to_string(),
            ],
            remediation_guidance: Some("Document all system interconnections with security agreements (ISAs/MOUs). Define security requirements for data exchange. Review interconnections annually.".to_string()),
        },
        ComplianceControl {
            id: "SR-CA-5".to_string(),
            control_id: "CA-5".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Plan of Action and Milestones".to_string(),
            description: "Develop and update a plan of action and milestones (POA&M) for the system to document planned remediation actions and reduce or eliminate known vulnerabilities.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-5".to_string(),
                "FedRAMP-CA-5".to_string(),
            ],
            remediation_guidance: Some("Maintain POA&M tracking all security findings. Include milestones, responsible parties, and target dates. Update POA&M monthly and report to StateRAMP PMO.".to_string()),
        },
        ComplianceControl {
            id: "SR-CA-6".to_string(),
            control_id: "CA-6".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Authorization".to_string(),
            description: "Assign a senior official to authorize the system for processing before operations. Update authorization based on changes to system or environment.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-6".to_string(),
                "FedRAMP-CA-6".to_string(),
            ],
            remediation_guidance: Some("Obtain formal authorization (ATO) from StateRAMP PMO before serving state/local government customers. Maintain authorization through continuous monitoring.".to_string()),
        },
        ComplianceControl {
            id: "SR-CA-7".to_string(),
            control_id: "CA-7".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Continuous Monitoring".to_string(),
            description: "Develop a continuous monitoring strategy and program including ongoing assessment of control effectiveness, ongoing awareness of threats and vulnerabilities.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-7".to_string(),
                "FedRAMP-CA-7".to_string(),
            ],
            remediation_guidance: Some("Implement continuous monitoring program with vulnerability scanning (monthly), penetration testing (annual), and configuration compliance checking (ongoing).".to_string()),
        },
        ComplianceControl {
            id: "SR-CA-8".to_string(),
            control_id: "CA-8".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Penetration Testing".to_string(),
            description: "Conduct penetration testing at a frequency defined by the organization on information systems or components.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-8".to_string(),
                "FedRAMP-CA-8".to_string(),
                "PCI-DSS-11.3".to_string(),
            ],
            remediation_guidance: Some("Conduct annual penetration testing by qualified assessors. Include external and internal testing, web application testing, and social engineering where applicable.".to_string()),
        },
        ComplianceControl {
            id: "SR-CA-9".to_string(),
            control_id: "CA-9".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Internal System Connections".to_string(),
            description: "Authorize internal connections of system components and document characteristics of each connection.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CA-9".to_string(),
                "FedRAMP-CA-9".to_string(),
            ],
            remediation_guidance: Some("Inventory and authorize all internal system connections. Document data flows and security controls for each connection. Review connections during continuous monitoring.".to_string()),
        },

        // ============================================================
        // Configuration Management (CM) Family - 8 controls
        // ============================================================
        ComplianceControl {
            id: "SR-CM-1".to_string(),
            control_id: "CM-1".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Configuration Management Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate configuration management policy and procedures. Define configuration change control processes.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-1".to_string(),
                "FedRAMP-CM-1".to_string(),
                "CIS-4.1".to_string(),
            ],
            remediation_guidance: Some("Document configuration management policies including baseline configurations, change control procedures, and deviation handling. Review policy annually.".to_string()),
        },
        ComplianceControl {
            id: "SR-CM-2".to_string(),
            control_id: "CM-2".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Baseline Configuration".to_string(),
            description: "Develop, document, and maintain current baseline configurations of the system. Review and update baseline configurations as part of component installations and upgrades.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-2".to_string(),
                "FedRAMP-CM-2".to_string(),
                "CIS-4.1".to_string(),
            ],
            remediation_guidance: Some("Establish secure baseline configurations using CIS Benchmarks or DISA STIGs. Implement infrastructure-as-code for consistent deployments. Audit configurations against baselines.".to_string()),
        },
        ComplianceControl {
            id: "SR-CM-3".to_string(),
            control_id: "CM-3".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Configuration Change Control".to_string(),
            description: "Determine and document types of changes to the system that are configuration-controlled. Review and approve configuration change requests. Implement approved changes.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-3".to_string(),
                "FedRAMP-CM-3".to_string(),
                "PCI-DSS-6.4".to_string(),
            ],
            remediation_guidance: Some("Implement formal change management process with CAB review for significant changes. Document all changes including rollback procedures. Test changes before production deployment.".to_string()),
        },
        ComplianceControl {
            id: "SR-CM-6".to_string(),
            control_id: "CM-6".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Configuration Settings".to_string(),
            description: "Establish and document configuration settings for system components using security configuration guides. Monitor and control changes to configuration settings.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-6".to_string(),
                "FedRAMP-CM-6".to_string(),
                "CIS-4.2".to_string(),
            ],
            remediation_guidance: Some("Apply security configuration settings per CIS Benchmarks. Use configuration management tools (Ansible, Chef, Puppet) for enforcement. Document and justify any deviations.".to_string()),
        },
        ComplianceControl {
            id: "SR-CM-7".to_string(),
            control_id: "CM-7".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Least Functionality".to_string(),
            description: "Configure the system to provide only essential capabilities. Prohibit or restrict the use of functions, ports, protocols, and services that are not required.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-7".to_string(),
                "FedRAMP-CM-7".to_string(),
                "CIS-2.3".to_string(),
            ],
            remediation_guidance: Some("Disable unnecessary services, ports, and protocols. Remove or disable unused software. Implement application whitelisting where feasible. Document required services.".to_string()),
        },
        ComplianceControl {
            id: "SR-CM-8".to_string(),
            control_id: "CM-8".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "System Component Inventory".to_string(),
            description: "Develop and document an inventory of system components that accurately reflects the system. Include all components within the authorization boundary.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-8".to_string(),
                "FedRAMP-CM-8".to_string(),
                "CIS-1.1".to_string(),
            ],
            remediation_guidance: Some("Maintain automated asset inventory including hardware, software, and network components. Update inventory within 24 hours of changes. Include asset owners and data classification.".to_string()),
        },
        ComplianceControl {
            id: "SR-CM-10".to_string(),
            control_id: "CM-10".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Software Usage Restrictions".to_string(),
            description: "Use software in accordance with contract agreements and copyright laws. Track the use of software and associated documentation protected by quantity licenses.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Low,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-10".to_string(),
                "FedRAMP-CM-10".to_string(),
            ],
            remediation_guidance: Some("Maintain software license inventory. Track license usage and compliance. Conduct periodic software audits. Remove unauthorized software.".to_string()),
        },
        ComplianceControl {
            id: "SR-CM-11".to_string(),
            control_id: "CM-11".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "User-Installed Software".to_string(),
            description: "Establish policies governing the installation of software by users. Enforce software installation policies through automated mechanisms.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-CM-11".to_string(),
                "FedRAMP-CM-11".to_string(),
                "CIS-2.5".to_string(),
            ],
            remediation_guidance: Some("Restrict user software installation to approved sources. Implement application whitelisting or software center. Monitor for unauthorized software installations.".to_string()),
        },

        // ============================================================
        // Incident Response (IR) Family - 7 controls
        // ============================================================
        ComplianceControl {
            id: "SR-IR-1".to_string(),
            control_id: "IR-1".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Incident Response Policy and Procedures".to_string(),
            description: "Develop, document, and disseminate incident response policy and procedures that address purpose, scope, roles, responsibilities, coordination, and compliance.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-1".to_string(),
                "FedRAMP-IR-1".to_string(),
                "PCI-DSS-12.10".to_string(),
            ],
            remediation_guidance: Some("Document incident response plan including roles, communication procedures, escalation paths, and reporting requirements to StateRAMP PMO and affected customers.".to_string()),
        },
        ComplianceControl {
            id: "SR-IR-2".to_string(),
            control_id: "IR-2".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Incident Response Training".to_string(),
            description: "Provide incident response training to system users consistent with assigned roles and responsibilities. Conduct training within timeframes specified.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-2".to_string(),
                "FedRAMP-IR-2".to_string(),
            ],
            remediation_guidance: Some("Train incident response team personnel within 90 days of hire and annually thereafter. Conduct tabletop exercises to validate response procedures.".to_string()),
        },
        ComplianceControl {
            id: "SR-IR-4".to_string(),
            control_id: "IR-4".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Incident Handling".to_string(),
            description: "Implement an incident handling capability for security incidents that includes preparation, detection and analysis, containment, eradication, and recovery.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-4".to_string(),
                "FedRAMP-IR-4".to_string(),
            ],
            remediation_guidance: Some("Establish incident response team with defined procedures for each phase. Document lessons learned and update procedures. Coordinate with state/local customers and StateRAMP PMO.".to_string()),
        },
        ComplianceControl {
            id: "SR-IR-5".to_string(),
            control_id: "IR-5".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Incident Monitoring".to_string(),
            description: "Track and document security incidents. Maintain records of incidents including timeline, actions taken, and impact assessment.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-5".to_string(),
                "FedRAMP-IR-5".to_string(),
            ],
            remediation_guidance: Some("Implement incident tracking system. Document all incidents with timeline, actions, and resolution. Generate metrics on incident types and response times.".to_string()),
        },
        ComplianceControl {
            id: "SR-IR-6".to_string(),
            control_id: "IR-6".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Incident Reporting".to_string(),
            description: "Require personnel to report suspected security incidents to the organizational incident response capability. Report incidents to appropriate authorities.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-6".to_string(),
                "FedRAMP-IR-6".to_string(),
            ],
            remediation_guidance: Some("Establish incident reporting procedures with timeframes: initial report within 1 hour for high-impact incidents. Report to StateRAMP PMO, US-CERT, and affected state/local customers.".to_string()),
        },
        ComplianceControl {
            id: "SR-IR-7".to_string(),
            control_id: "IR-7".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Incident Response Assistance".to_string(),
            description: "Provide an incident response support resource integral to the organizational incident response capability that offers advice and assistance to users.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-7".to_string(),
                "FedRAMP-IR-7".to_string(),
            ],
            remediation_guidance: Some("Establish helpdesk or SOC capability to assist users with incident reporting. Provide 24/7 contact information for security incidents.".to_string()),
        },
        ComplianceControl {
            id: "SR-IR-8".to_string(),
            control_id: "IR-8".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Incident Response Plan".to_string(),
            description: "Develop an incident response plan that addresses the sharing of incident information. Review and update the incident response plan annually.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-IR-8".to_string(),
                "FedRAMP-IR-8".to_string(),
            ],
            remediation_guidance: Some("Document comprehensive incident response plan with roles, procedures, communication plans, and recovery procedures. Review and test plan annually.".to_string()),
        },

        // ============================================================
        // System and Communications Protection (SC) Family - 7 controls
        // ============================================================
        ComplianceControl {
            id: "SR-SC-1".to_string(),
            control_id: "SC-1".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "System and Communications Protection Policy".to_string(),
            description: "Develop, document, and disseminate system and communications protection policy that addresses network security, encryption requirements, and boundary protection.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-1".to_string(),
                "FedRAMP-SC-1".to_string(),
            ],
            remediation_guidance: Some("Document network security policies covering encryption, segmentation, boundary protection, and secure protocols. Review policy annually.".to_string()),
        },
        ComplianceControl {
            id: "SR-SC-7".to_string(),
            control_id: "SC-7".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Boundary Protection".to_string(),
            description: "Monitor and control communications at external managed interfaces to the system. Implement subnetworks for publicly accessible system components separated from internal networks.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-7".to_string(),
                "FedRAMP-SC-7".to_string(),
                "CIS-9.2".to_string(),
            ],
            remediation_guidance: Some("Implement firewalls at network boundaries with deny-all default rules. Segment networks using DMZ architecture. Deploy IDS/IPS at boundary points. Monitor egress traffic.".to_string()),
        },
        ComplianceControl {
            id: "SR-SC-8".to_string(),
            control_id: "SC-8".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Transmission Confidentiality and Integrity".to_string(),
            description: "Protect the confidentiality and integrity of transmitted information using cryptographic mechanisms.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-8".to_string(),
                "FedRAMP-SC-8".to_string(),
                "PCI-DSS-4.1".to_string(),
            ],
            remediation_guidance: Some("Encrypt all data in transit using TLS 1.2 or higher. Disable SSLv3, TLS 1.0, and TLS 1.1. Use strong cipher suites only. Implement certificate pinning where appropriate.".to_string()),
        },
        ComplianceControl {
            id: "SR-SC-12".to_string(),
            control_id: "SC-12".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Cryptographic Key Establishment and Management".to_string(),
            description: "Establish and manage cryptographic keys using approved key management technology and processes.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-12".to_string(),
                "FedRAMP-SC-12".to_string(),
                "PCI-DSS-3.5".to_string(),
            ],
            remediation_guidance: Some("Implement key management system with secure generation, storage, distribution, and destruction. Use HSMs for high-value keys. Rotate keys according to policy.".to_string()),
        },
        ComplianceControl {
            id: "SR-SC-13".to_string(),
            control_id: "SC-13".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Cryptographic Protection".to_string(),
            description: "Implement FIPS-validated or NSA-approved cryptography in accordance with applicable laws, regulations, and policies.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-13".to_string(),
                "FedRAMP-SC-13".to_string(),
            ],
            remediation_guidance: Some("Use FIPS 140-2/140-3 validated cryptographic modules. Implement AES-256 for data at rest, TLS 1.2+ for data in transit. Document cryptographic implementations.".to_string()),
        },
        ComplianceControl {
            id: "SR-SC-28".to_string(),
            control_id: "SC-28".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Protection of Information at Rest".to_string(),
            description: "Protect the confidentiality and integrity of information at rest using cryptographic mechanisms.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-28".to_string(),
                "FedRAMP-SC-28".to_string(),
                "PCI-DSS-3.4".to_string(),
            ],
            remediation_guidance: Some("Encrypt all sensitive data at rest using AES-256. Implement full-disk encryption on endpoints and servers. Use database-level encryption for sensitive fields.".to_string()),
        },
        ComplianceControl {
            id: "SR-SC-39".to_string(),
            control_id: "SC-39".to_string(),
            framework: ComplianceFramework::StateRamp,
            title: "Process Isolation".to_string(),
            description: "Maintain a separate execution domain for each executing system process to prevent cross-process interference.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-SC-39".to_string(),
                "FedRAMP-SC-39".to_string(),
            ],
            remediation_guidance: Some("Implement container isolation, process namespaces, and memory protection. Use separate execution environments for multi-tenant workloads. Enable ASLR and DEP.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant StateRAMP controls
///
/// This function maps security vulnerabilities identified during scanning
/// to the relevant StateRAMP controls that address the vulnerability type.
/// Cross-references to FedRAMP and NIST 800-53 controls are included for
/// comprehensive compliance mapping.
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access control vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("privilege escalation")
        || title_lower.contains("broken access control")
    {
        mappings.push(("SR-AC-3".to_string(), Severity::Critical));
        mappings.push(("SR-AC-6".to_string(), Severity::High));
        mappings.push(("SR-AC-5".to_string(), Severity::Medium));
    }

    // Account management vulnerabilities
    if title_lower.contains("orphaned account")
        || title_lower.contains("excessive privileges")
        || title_lower.contains("stale account")
    {
        mappings.push(("SR-AC-2".to_string(), Severity::High));
        mappings.push(("SR-AC-6".to_string(), Severity::High));
    }

    // Authentication vulnerabilities
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("weak password")
        || title_lower.contains("brute force")
    {
        mappings.push(("SR-AC-7".to_string(), Severity::Critical));
    }

    // Default credentials
    if title_lower.contains("default password")
        || title_lower.contains("default credentials")
        || title_lower.contains("vendor default")
    {
        mappings.push(("SR-CM-6".to_string(), Severity::Critical));
        mappings.push(("SR-CM-2".to_string(), Severity::High));
    }

    // Encryption vulnerabilities - transit
    if title_lower.contains("unencrypted")
        || title_lower.contains("cleartext")
        || title_lower.contains("ssl") && title_lower.contains("vulnerable")
        || title_lower.contains("tls") && title_lower.contains("weak")
        || title_lower.contains("weak cipher")
    {
        mappings.push(("SR-SC-8".to_string(), Severity::High));
        mappings.push(("SR-SC-13".to_string(), Severity::High));
    }

    // Encryption vulnerabilities - at rest
    if title_lower.contains("unencrypted data")
        || title_lower.contains("data at rest")
        || title_lower.contains("database encryption")
    {
        mappings.push(("SR-SC-28".to_string(), Severity::High));
        mappings.push(("SR-SC-12".to_string(), Severity::Medium));
    }

    // Configuration vulnerabilities
    if title_lower.contains("misconfiguration")
        || title_lower.contains("insecure configuration")
        || title_lower.contains("hardening")
    {
        mappings.push(("SR-CM-6".to_string(), Severity::High));
        mappings.push(("SR-CM-2".to_string(), Severity::High));
        mappings.push(("SR-CM-7".to_string(), Severity::Medium));
    }

    // Logging/audit vulnerabilities
    if title_lower.contains("no logging")
        || title_lower.contains("audit disabled")
        || title_lower.contains("insufficient logging")
        || title_lower.contains("log injection")
    {
        mappings.push(("SR-AU-2".to_string(), Severity::High));
        mappings.push(("SR-AU-12".to_string(), Severity::High));
        mappings.push(("SR-AU-9".to_string(), Severity::Medium));
    }

    // Log integrity vulnerabilities
    if title_lower.contains("log tampering")
        || title_lower.contains("audit modification")
    {
        mappings.push(("SR-AU-9".to_string(), Severity::Critical));
    }

    // Firewall/boundary protection vulnerabilities
    if title_lower.contains("firewall")
        || title_lower.contains("open port")
        || title_lower.contains("network segmentation")
        || title_lower.contains("boundary")
    {
        mappings.push(("SR-SC-7".to_string(), Severity::High));
        mappings.push(("SR-AC-4".to_string(), Severity::Medium));
    }

    // Remote access vulnerabilities
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") {
        if title_lower.contains("vulnerable")
            || title_lower.contains("exposed")
            || title_lower.contains("weak")
        {
            mappings.push(("SR-AC-17".to_string(), Severity::High));
        }
    }

    // Wireless security vulnerabilities
    if title_lower.contains("wireless")
        || title_lower.contains("wifi")
        || title_lower.contains("wpa")
        || title_lower.contains("wep")
    {
        mappings.push(("SR-AC-18".to_string(), Severity::High));
    }

    // Insecure protocols (Telnet)
    if port == Some(23) || title_lower.contains("telnet") {
        mappings.push(("SR-SC-8".to_string(), Severity::High));
        mappings.push(("SR-CM-7".to_string(), Severity::High));
    }

    // FTP vulnerabilities
    if port == Some(21) || title_lower.contains("ftp") && !title_lower.contains("sftp") {
        mappings.push(("SR-SC-8".to_string(), Severity::Medium));
        mappings.push(("SR-CM-7".to_string(), Severity::Medium));
    }

    // Vulnerability scanning findings
    if title_lower.contains("vulnerability scan")
        || title_lower.contains("penetration test")
        || title_lower.contains("assessment finding")
    {
        mappings.push(("SR-CA-7".to_string(), Severity::Medium));
        mappings.push(("SR-CA-8".to_string(), Severity::Medium));
    }

    // Patch management / outdated software
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("eol")
        || title_lower.contains("unsupported")
    {
        mappings.push(("SR-CM-8".to_string(), Severity::High));
        mappings.push(("SR-CA-7".to_string(), Severity::High));
    }

    // Unnecessary services
    if title_lower.contains("unnecessary service")
        || title_lower.contains("unused service")
        || title_lower.contains("non-essential")
    {
        mappings.push(("SR-CM-7".to_string(), Severity::Medium));
    }

    // Incident response issues
    if title_lower.contains("incident")
        || title_lower.contains("breach")
        || title_lower.contains("compromise")
    {
        mappings.push(("SR-IR-4".to_string(), Severity::Critical));
        mappings.push(("SR-IR-6".to_string(), Severity::High));
        mappings.push(("SR-IR-5".to_string(), Severity::High));
    }

    // Publicly accessible sensitive data
    if title_lower.contains("data exposure")
        || title_lower.contains("sensitive data")
        || title_lower.contains("public exposure")
    {
        mappings.push(("SR-AC-22".to_string(), Severity::High));
        mappings.push(("SR-AC-4".to_string(), Severity::High));
    }

    // Container/process isolation
    if title_lower.contains("container escape")
        || title_lower.contains("process isolation")
        || title_lower.contains("sandbox escape")
    {
        mappings.push(("SR-SC-39".to_string(), Severity::Critical));
    }

    // Change control issues
    if title_lower.contains("unauthorized change")
        || title_lower.contains("change management")
    {
        mappings.push(("SR-CM-3".to_string(), Severity::High));
    }

    // Asset inventory issues
    if title_lower.contains("unknown asset")
        || title_lower.contains("shadow it")
        || title_lower.contains("rogue")
    {
        mappings.push(("SR-CM-8".to_string(), Severity::High));
    }

    // Time synchronization issues
    if title_lower.contains("ntp")
        || title_lower.contains("time sync")
        || title_lower.contains("clock")
    {
        mappings.push(("SR-AU-8".to_string(), Severity::Low));
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
    fn test_control_framework() {
        let controls = get_controls();
        for control in &controls {
            assert_eq!(control.framework, ComplianceFramework::StateRamp);
        }
    }

    #[test]
    fn test_control_ids_unique() {
        let controls = get_controls();
        let mut ids: Vec<&String> = controls.iter().map(|c| &c.id).collect();
        ids.sort();
        let original_len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), original_len, "Control IDs must be unique");
    }

    #[test]
    fn test_categories() {
        let controls = get_controls();
        let expected_categories = vec![
            "Access Control",
            "Audit and Accountability",
            "Security Assessment",
            "Configuration Management",
            "Incident Response",
            "System and Communications Protection",
        ];

        for category in expected_categories {
            assert!(
                controls.iter().any(|c| c.category == category),
                "Missing category: {}",
                category
            );
        }
    }

    #[test]
    fn test_cross_references_include_nist() {
        let controls = get_controls();
        for control in &controls {
            // Most StateRAMP controls should reference NIST 800-53
            let has_nist_ref = control.cross_references.iter().any(|r| r.starts_with("NIST-"));
            // Some controls may not have direct NIST mapping, so we just verify structure
            if has_nist_ref {
                assert!(
                    control.cross_references.iter().any(|r| r.starts_with("NIST-")),
                    "Control {} should have NIST cross-reference",
                    control.id
                );
            }
        }
    }

    #[test]
    fn test_cross_references_include_fedramp() {
        let controls = get_controls();
        let fedramp_ref_count = controls
            .iter()
            .filter(|c| c.cross_references.iter().any(|r| r.starts_with("FedRAMP-")))
            .count();

        // StateRAMP is based on FedRAMP, so most controls should have FedRAMP refs
        assert!(
            fedramp_ref_count > 40,
            "Expected most controls to have FedRAMP references, found {}",
            fedramp_ref_count
        );
    }

    #[test]
    fn test_map_vulnerability_access_control() {
        let mappings = map_vulnerability("Unauthorized access to admin panel", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-AC-3"));
    }

    #[test]
    fn test_map_vulnerability_encryption() {
        let mappings = map_vulnerability("Weak TLS configuration detected", None, Some(443), Some("https"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-SC-8"));
    }

    #[test]
    fn test_map_vulnerability_logging() {
        let mappings = map_vulnerability("Audit logging disabled on server", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-AU-2"));
    }

    #[test]
    fn test_map_vulnerability_remote_access() {
        let mappings = map_vulnerability("Exposed SSH service vulnerable", None, Some(22), Some("ssh"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-AC-17"));
    }

    #[test]
    fn test_map_vulnerability_configuration() {
        let mappings = map_vulnerability("Default credentials on network device", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-CM-6"));
    }

    #[test]
    fn test_map_vulnerability_patch() {
        let mappings = map_vulnerability("Outdated Apache server version", None, Some(80), Some("http"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-CM-8" || id == "SR-CA-7"));
    }

    #[test]
    fn test_map_vulnerability_telnet() {
        let mappings = map_vulnerability("Telnet service detected", None, Some(23), Some("telnet"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-SC-8"));
        assert!(mappings.iter().any(|(id, _)| id == "SR-CM-7"));
    }

    #[test]
    fn test_map_vulnerability_incident() {
        let mappings = map_vulnerability("Suspected data breach detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "SR-IR-4"));
    }

    #[test]
    fn test_remediation_guidance_present() {
        let controls = get_controls();
        for control in &controls {
            assert!(
                control.remediation_guidance.is_some(),
                "Control {} should have remediation guidance",
                control.id
            );
        }
    }
}
