//! CMMC 2.0 (Cybersecurity Maturity Model Certification) Compliance Framework
//!
//! CMMC 2.0 Level 2 aligns with NIST SP 800-171 Rev 2 requirements for protecting
//! Controlled Unclassified Information (CUI) in the Defense Industrial Base (DIB).
//!
//! This module implements the 110 security requirements organized across 14 domains,
//! mapped to their corresponding NIST 800-171 controls.
//!
//! Domains:
//! - Access Control (AC) - 22 practices
//! - Awareness and Training (AT) - 3 practices
//! - Audit and Accountability (AU) - 9 practices
//! - Configuration Management (CM) - 9 practices
//! - Identification and Authentication (IA) - 11 practices
//! - Incident Response (IR) - 3 practices
//! - Maintenance (MA) - 6 practices
//! - Media Protection (MP) - 9 practices
//! - Personnel Security (PS) - 2 practices
//! - Physical Protection (PE) - 6 practices
//! - Risk Assessment (RA) - 3 practices
//! - Security Assessment (CA) - 4 practices
//! - System and Communications Protection (SC) - 16 practices
//! - System and Information Integrity (SI) - 7 practices

use crate::compliance::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of CMMC 2.0 Level 2 practices (aligned with NIST 800-171)
pub const CONTROL_COUNT: usize = 110;

/// Get all CMMC 2.0 Level 2 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // ACCESS CONTROL (AC) - 22 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.1".to_string(),
            control_id: "AC.L2-3.1.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Authorized Access Control".to_string(),
            description: "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.1".to_string(),
                "NIST-AC-2".to_string(),
                "NIST-AC-3".to_string(),
                "NIST-AC-17".to_string(),
            ],
            remediation_guidance: Some("Implement access control policies that identify authorized users, processes, and devices. Use authentication mechanisms to verify identity before granting access.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.2".to_string(),
            control_id: "AC.L2-3.1.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Transaction & Function Control".to_string(),
            description: "Limit system access to the types of transactions and functions that authorized users are permitted to execute.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.2".to_string(),
                "NIST-AC-3".to_string(),
            ],
            remediation_guidance: Some("Implement role-based access control (RBAC) to restrict user actions to only those required for their job functions.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.3".to_string(),
            control_id: "AC.L2-3.1.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Control CUI Flow".to_string(),
            description: "Control the flow of CUI in accordance with approved authorizations.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.3".to_string(),
                "NIST-AC-4".to_string(),
            ],
            remediation_guidance: Some("Implement information flow controls using firewalls, network segmentation, and data loss prevention (DLP) tools to control CUI movement.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.4".to_string(),
            control_id: "AC.L2-3.1.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Separation of Duties".to_string(),
            description: "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.4".to_string(),
                "NIST-AC-5".to_string(),
            ],
            remediation_guidance: Some("Define and enforce separation of duties for sensitive operations. Ensure no single individual has complete control over critical processes.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.5".to_string(),
            control_id: "AC.L2-3.1.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Least Privilege".to_string(),
            description: "Employ the principle of least privilege, including for specific security functions and privileged accounts.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.5".to_string(),
                "NIST-AC-6".to_string(),
            ],
            remediation_guidance: Some("Grant users only the minimum access rights necessary. Implement privileged access management (PAM) for administrative accounts.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.6".to_string(),
            control_id: "AC.L2-3.1.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Non-Privileged Account Use".to_string(),
            description: "Use non-privileged accounts or roles when accessing nonsecurity functions.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.6".to_string(),
                "NIST-AC-6(2)".to_string(),
            ],
            remediation_guidance: Some("Ensure administrators use non-privileged accounts for routine tasks. Elevate privileges only when necessary for administrative functions.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.7".to_string(),
            control_id: "AC.L2-3.1.7".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Privileged Functions".to_string(),
            description: "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.7".to_string(),
                "NIST-AC-6(9)".to_string(),
                "NIST-AC-6(10)".to_string(),
            ],
            remediation_guidance: Some("Implement technical controls to prevent privilege escalation. Log all attempts to execute privileged functions.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.8".to_string(),
            control_id: "AC.L2-3.1.8".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Unsuccessful Logon Attempts".to_string(),
            description: "Limit unsuccessful logon attempts.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.8".to_string(),
                "NIST-AC-7".to_string(),
            ],
            remediation_guidance: Some("Configure account lockout policies after 3-5 failed login attempts. Implement progressive delays for repeated failures.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.9".to_string(),
            control_id: "AC.L2-3.1.9".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Privacy & Security Notices".to_string(),
            description: "Provide privacy and security notices consistent with applicable CUI rules.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.9".to_string(),
                "NIST-AC-8".to_string(),
            ],
            remediation_guidance: Some("Display login banners with privacy and security notices. Include consent warnings and authorized use statements.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.10".to_string(),
            control_id: "AC.L2-3.1.10".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Session Lock".to_string(),
            description: "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.10".to_string(),
                "NIST-AC-11".to_string(),
            ],
            remediation_guidance: Some("Configure automatic screen lock after 15 minutes of inactivity. Require password re-authentication to unlock.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.11".to_string(),
            control_id: "AC.L2-3.1.11".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Session Termination".to_string(),
            description: "Terminate (automatically) a user session after a defined condition.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.11".to_string(),
                "NIST-AC-12".to_string(),
            ],
            remediation_guidance: Some("Configure automatic session termination after extended inactivity or when defined security conditions are met.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.12".to_string(),
            control_id: "AC.L2-3.1.12".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Control Remote Access".to_string(),
            description: "Monitor and control remote access sessions.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.12".to_string(),
                "NIST-AC-17(1)".to_string(),
            ],
            remediation_guidance: Some("Implement remote access monitoring with session recording. Use VPN with logging for all remote connections.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.13".to_string(),
            control_id: "AC.L2-3.1.13".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Remote Access Confidentiality".to_string(),
            description: "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.13".to_string(),
                "NIST-AC-17(2)".to_string(),
            ],
            remediation_guidance: Some("Use encrypted VPN (IPsec or TLS) for all remote access. Disable unencrypted remote access protocols.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.14".to_string(),
            control_id: "AC.L2-3.1.14".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Remote Access Routing".to_string(),
            description: "Route remote access via managed access control points.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.14".to_string(),
                "NIST-AC-17(3)".to_string(),
            ],
            remediation_guidance: Some("Force all remote access through centralized access points (VPN concentrators, jump servers). Block direct remote access to internal systems.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.15".to_string(),
            control_id: "AC.L2-3.1.15".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Privileged Remote Access".to_string(),
            description: "Authorize remote execution of privileged commands and remote access to security-relevant information.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.15".to_string(),
                "NIST-AC-17(4)".to_string(),
            ],
            remediation_guidance: Some("Implement privileged access management (PAM) for remote administrative access. Require explicit authorization and logging for privileged remote commands.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.16".to_string(),
            control_id: "AC.L2-3.1.16".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Wireless Access Authorization".to_string(),
            description: "Authorize wireless access prior to allowing such connections.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.16".to_string(),
                "NIST-AC-18".to_string(),
            ],
            remediation_guidance: Some("Implement wireless access policies requiring explicit authorization. Use 802.1X for network access control.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.17".to_string(),
            control_id: "AC.L2-3.1.17".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Wireless Access Protection".to_string(),
            description: "Protect wireless access using authentication and encryption.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.17".to_string(),
                "NIST-AC-18(1)".to_string(),
            ],
            remediation_guidance: Some("Implement WPA3 Enterprise with 802.1X authentication. Disable legacy wireless protocols (WEP, WPA).".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.18".to_string(),
            control_id: "AC.L2-3.1.18".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Mobile Device Connection".to_string(),
            description: "Control connection of mobile devices.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.18".to_string(),
                "NIST-AC-19".to_string(),
            ],
            remediation_guidance: Some("Implement mobile device management (MDM). Require device enrollment and compliance checks before allowing CUI access.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.19".to_string(),
            control_id: "AC.L2-3.1.19".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Encrypt CUI on Mobile".to_string(),
            description: "Encrypt CUI on mobile devices and mobile computing platforms.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.19".to_string(),
                "NIST-AC-19(5)".to_string(),
            ],
            remediation_guidance: Some("Enable full-device encryption on all mobile devices. Use FIPS 140-2 validated encryption modules.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.20".to_string(),
            control_id: "AC.L2-3.1.20".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "External System Connections".to_string(),
            description: "Verify and control/limit connections to and use of external systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.20".to_string(),
                "NIST-AC-20".to_string(),
            ],
            remediation_guidance: Some("Document and approve all external system connections. Implement network controls to restrict external connectivity.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.21".to_string(),
            control_id: "AC.L2-3.1.21".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Portable Storage Use".to_string(),
            description: "Limit use of portable storage devices on external systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.21".to_string(),
                "NIST-AC-20(2)".to_string(),
            ],
            remediation_guidance: Some("Implement USB device control policies. Block unauthorized removable media on external systems containing CUI.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AC.L2-3.1.22".to_string(),
            control_id: "AC.L2-3.1.22".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Control Public Information".to_string(),
            description: "Control information posted or processed on publicly accessible systems.".to_string(),
            category: "Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.1.22".to_string(),
                "NIST-AC-22".to_string(),
            ],
            remediation_guidance: Some("Implement review and approval processes for public content. Ensure CUI is never posted to public-facing systems.".to_string()),
        },

        // ============================================================
        // AWARENESS AND TRAINING (AT) - 3 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-AT.L2-3.2.1".to_string(),
            control_id: "AT.L2-3.2.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Role-Based Risk Awareness".to_string(),
            description: "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.2.1".to_string(),
                "NIST-AT-2".to_string(),
            ],
            remediation_guidance: Some("Conduct role-based security awareness training. Cover security risks relevant to each role's responsibilities.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AT.L2-3.2.2".to_string(),
            control_id: "AT.L2-3.2.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Role-Based Training".to_string(),
            description: "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.2.2".to_string(),
                "NIST-AT-3".to_string(),
            ],
            remediation_guidance: Some("Provide specialized training for security roles. Document training completion and refresher requirements.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AT.L2-3.2.3".to_string(),
            control_id: "AT.L2-3.2.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Insider Threat Awareness".to_string(),
            description: "Provide security awareness training on recognizing and reporting potential indicators of insider threat.".to_string(),
            category: "Awareness and Training".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.2.3".to_string(),
                "NIST-AT-2(2)".to_string(),
            ],
            remediation_guidance: Some("Include insider threat indicators in security training. Establish reporting mechanisms for suspicious activities.".to_string()),
        },

        // ============================================================
        // AUDIT AND ACCOUNTABILITY (AU) - 9 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.1".to_string(),
            control_id: "AU.L2-3.3.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "System Auditing".to_string(),
            description: "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.1".to_string(),
                "NIST-AU-2".to_string(),
                "NIST-AU-3".to_string(),
            ],
            remediation_guidance: Some("Enable comprehensive audit logging on all systems. Log authentication events, file access, and system changes.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.2".to_string(),
            control_id: "AU.L2-3.3.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "User Accountability".to_string(),
            description: "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.2".to_string(),
                "NIST-AU-2".to_string(),
            ],
            remediation_guidance: Some("Assign unique user IDs. Prohibit shared accounts. Include user ID in all audit records.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.3".to_string(),
            control_id: "AU.L2-3.3.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Event Review".to_string(),
            description: "Review and update logged events.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.3".to_string(),
                "NIST-AU-2(3)".to_string(),
            ],
            remediation_guidance: Some("Periodically review audit events to ensure relevance. Update logging configuration based on threat landscape.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.4".to_string(),
            control_id: "AU.L2-3.3.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Audit Failure Alerting".to_string(),
            description: "Alert in the event of an audit logging process failure.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.4".to_string(),
                "NIST-AU-5".to_string(),
            ],
            remediation_guidance: Some("Configure alerts for audit logging failures. Implement fail-secure logging behavior.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.5".to_string(),
            control_id: "AU.L2-3.3.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Audit Correlation".to_string(),
            description: "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.5".to_string(),
                "NIST-AU-6(1)".to_string(),
            ],
            remediation_guidance: Some("Implement SIEM for centralized log correlation. Create detection rules for suspicious activity patterns.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.6".to_string(),
            control_id: "AU.L2-3.3.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Audit Reduction & Reporting".to_string(),
            description: "Provide audit record reduction and report generation to support on-demand analysis and reporting.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.6".to_string(),
                "NIST-AU-7".to_string(),
            ],
            remediation_guidance: Some("Implement log analysis tools with search and reporting capabilities. Enable on-demand report generation.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.7".to_string(),
            control_id: "AU.L2-3.3.7".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Authoritative Time Source".to_string(),
            description: "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.7".to_string(),
                "NIST-AU-8".to_string(),
            ],
            remediation_guidance: Some("Configure NTP synchronization to authoritative time sources. Monitor for time drift.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.8".to_string(),
            control_id: "AU.L2-3.3.8".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Audit Protection".to_string(),
            description: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.8".to_string(),
                "NIST-AU-9".to_string(),
            ],
            remediation_guidance: Some("Restrict access to audit logs. Implement write-once storage and integrity monitoring for log files.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-AU.L2-3.3.9".to_string(),
            control_id: "AU.L2-3.3.9".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Audit Management".to_string(),
            description: "Limit management of audit logging functionality to a subset of privileged users.".to_string(),
            category: "Audit and Accountability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.3.9".to_string(),
                "NIST-AU-9(4)".to_string(),
            ],
            remediation_guidance: Some("Restrict audit configuration access to designated security administrators. Log all changes to audit settings.".to_string()),
        },

        // ============================================================
        // CONFIGURATION MANAGEMENT (CM) - 9 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.1".to_string(),
            control_id: "CM.L2-3.4.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "System Baselining".to_string(),
            description: "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.1".to_string(),
                "NIST-CM-2".to_string(),
                "NIST-CM-8".to_string(),
            ],
            remediation_guidance: Some("Document and maintain baseline configurations. Implement automated inventory management.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.2".to_string(),
            control_id: "CM.L2-3.4.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Security Configuration Enforcement".to_string(),
            description: "Establish and enforce security configuration settings for information technology products employed in organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.2".to_string(),
                "NIST-CM-6".to_string(),
            ],
            remediation_guidance: Some("Apply security configuration standards (CIS Benchmarks, STIGs). Use configuration management tools to enforce settings.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.3".to_string(),
            control_id: "CM.L2-3.4.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "System Change Management".to_string(),
            description: "Track, review, approve or disapprove, and log changes to organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.3".to_string(),
                "NIST-CM-3".to_string(),
            ],
            remediation_guidance: Some("Implement change management process with approval workflows. Log all system changes.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.4".to_string(),
            control_id: "CM.L2-3.4.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Security Impact Analysis".to_string(),
            description: "Analyze the security impact of changes prior to implementation.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.4".to_string(),
                "NIST-CM-4".to_string(),
            ],
            remediation_guidance: Some("Conduct security impact assessments before implementing changes. Document risk acceptance for changes.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.5".to_string(),
            control_id: "CM.L2-3.4.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Access Restrictions for Change".to_string(),
            description: "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.5".to_string(),
                "NIST-CM-5".to_string(),
            ],
            remediation_guidance: Some("Restrict change access to authorized personnel. Implement technical controls to enforce change restrictions.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.6".to_string(),
            control_id: "CM.L2-3.4.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Least Functionality".to_string(),
            description: "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.6".to_string(),
                "NIST-CM-7".to_string(),
            ],
            remediation_guidance: Some("Disable unnecessary services, ports, and protocols. Remove unused software and features.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.7".to_string(),
            control_id: "CM.L2-3.4.7".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Nonessential Functionality".to_string(),
            description: "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.7".to_string(),
                "NIST-CM-7(1)".to_string(),
            ],
            remediation_guidance: Some("Implement application whitelisting. Block unnecessary network services at the firewall.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.8".to_string(),
            control_id: "CM.L2-3.4.8".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Application Execution Policy".to_string(),
            description: "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.8".to_string(),
                "NIST-CM-7(4)".to_string(),
            ],
            remediation_guidance: Some("Implement application whitelisting for critical systems. Maintain authorized software lists.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CM.L2-3.4.9".to_string(),
            control_id: "CM.L2-3.4.9".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "User-Installed Software".to_string(),
            description: "Control and monitor user-installed software.".to_string(),
            category: "Configuration Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.4.9".to_string(),
                "NIST-CM-11".to_string(),
            ],
            remediation_guidance: Some("Restrict user installation rights. Monitor for unauthorized software installations.".to_string()),
        },

        // ============================================================
        // IDENTIFICATION AND AUTHENTICATION (IA) - 11 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.1".to_string(),
            control_id: "IA.L2-3.5.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Identification".to_string(),
            description: "Identify system users, processes acting on behalf of users, and devices.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.1".to_string(),
                "NIST-IA-2".to_string(),
            ],
            remediation_guidance: Some("Implement unique identifiers for all users and devices. Maintain identity management system.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.2".to_string(),
            control_id: "IA.L2-3.5.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Authentication".to_string(),
            description: "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.2".to_string(),
                "NIST-IA-2".to_string(),
            ],
            remediation_guidance: Some("Implement strong authentication for all system access. Use multi-factor authentication for privileged access.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.3".to_string(),
            control_id: "IA.L2-3.5.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Multi-Factor Authentication".to_string(),
            description: "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.3".to_string(),
                "NIST-IA-2(1)".to_string(),
                "NIST-IA-2(2)".to_string(),
            ],
            remediation_guidance: Some("Deploy MFA for all privileged access. Implement MFA for network access to all accounts.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.4".to_string(),
            control_id: "IA.L2-3.5.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Replay-Resistant Authentication".to_string(),
            description: "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.4".to_string(),
                "NIST-IA-2(8)".to_string(),
            ],
            remediation_guidance: Some("Use authentication protocols with replay protection (Kerberos, NTLM v2). Implement nonce-based authentication.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.5".to_string(),
            control_id: "IA.L2-3.5.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Identifier Reuse".to_string(),
            description: "Prevent reuse of identifiers for a defined period.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.5".to_string(),
                "NIST-IA-4".to_string(),
            ],
            remediation_guidance: Some("Configure identity systems to prevent identifier reuse for at least one year after deprovisioning.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.6".to_string(),
            control_id: "IA.L2-3.5.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Identifier Handling".to_string(),
            description: "Disable identifiers after a defined period of inactivity.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.6".to_string(),
                "NIST-IA-4".to_string(),
            ],
            remediation_guidance: Some("Disable accounts after 90 days of inactivity. Implement automated account lifecycle management.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.7".to_string(),
            control_id: "IA.L2-3.5.7".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Password Complexity".to_string(),
            description: "Enforce a minimum password complexity and change of characters when new passwords are created.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.7".to_string(),
                "NIST-IA-5(1)".to_string(),
            ],
            remediation_guidance: Some("Enforce minimum 12-character passwords with complexity requirements. Require password changes when compromised.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.8".to_string(),
            control_id: "IA.L2-3.5.8".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Password Reuse".to_string(),
            description: "Prohibit password reuse for a specified number of generations.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.8".to_string(),
                "NIST-IA-5(1)".to_string(),
            ],
            remediation_guidance: Some("Configure password history to prevent reuse of the last 24 passwords.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.9".to_string(),
            control_id: "IA.L2-3.5.9".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Temporary Passwords".to_string(),
            description: "Allow temporary password use for system logons with an immediate change to a permanent password.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.9".to_string(),
                "NIST-IA-5(1)".to_string(),
            ],
            remediation_guidance: Some("Configure systems to require password change on first login. Set temporary passwords to expire within 24 hours.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.10".to_string(),
            control_id: "IA.L2-3.5.10".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Cryptographically-Protected Passwords".to_string(),
            description: "Store and transmit only cryptographically-protected passwords.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.10".to_string(),
                "NIST-IA-5(1)".to_string(),
            ],
            remediation_guidance: Some("Hash passwords using approved algorithms (bcrypt, PBKDF2, Argon2). Never store plaintext passwords.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IA.L2-3.5.11".to_string(),
            control_id: "IA.L2-3.5.11".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Obscure Feedback".to_string(),
            description: "Obscure feedback of authentication information.".to_string(),
            category: "Identification and Authentication".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.5.11".to_string(),
                "NIST-IA-6".to_string(),
            ],
            remediation_guidance: Some("Mask password input fields. Provide generic error messages for authentication failures.".to_string()),
        },

        // ============================================================
        // INCIDENT RESPONSE (IR) - 3 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-IR.L2-3.6.1".to_string(),
            control_id: "IR.L2-3.6.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Incident Handling".to_string(),
            description: "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.6.1".to_string(),
                "NIST-IR-2".to_string(),
                "NIST-IR-4".to_string(),
                "NIST-IR-5".to_string(),
                "NIST-IR-6".to_string(),
            ],
            remediation_guidance: Some("Develop and maintain incident response plan. Establish incident response team and procedures.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IR.L2-3.6.2".to_string(),
            control_id: "IR.L2-3.6.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Incident Reporting".to_string(),
            description: "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.6.2".to_string(),
                "NIST-IR-6".to_string(),
            ],
            remediation_guidance: Some("Implement incident tracking system. Establish reporting procedures for internal and external stakeholders (DIBNet, law enforcement).".to_string()),
        },
        ComplianceControl {
            id: "CMMC-IR.L2-3.6.3".to_string(),
            control_id: "IR.L2-3.6.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Incident Response Testing".to_string(),
            description: "Test the organizational incident response capability.".to_string(),
            category: "Incident Response".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.6.3".to_string(),
                "NIST-IR-3".to_string(),
            ],
            remediation_guidance: Some("Conduct annual incident response exercises and tabletop drills. Document lessons learned and update procedures.".to_string()),
        },

        // ============================================================
        // MAINTENANCE (MA) - 6 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-MA.L2-3.7.1".to_string(),
            control_id: "MA.L2-3.7.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Perform Maintenance".to_string(),
            description: "Perform maintenance on organizational systems.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.7.1".to_string(),
                "NIST-MA-2".to_string(),
            ],
            remediation_guidance: Some("Establish maintenance schedules and procedures. Document all maintenance activities.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MA.L2-3.7.2".to_string(),
            control_id: "MA.L2-3.7.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "System Maintenance Control".to_string(),
            description: "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.7.2".to_string(),
                "NIST-MA-3".to_string(),
            ],
            remediation_guidance: Some("Approve and control maintenance tools. Verify personnel credentials before allowing maintenance access.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MA.L2-3.7.3".to_string(),
            control_id: "MA.L2-3.7.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Equipment Sanitization".to_string(),
            description: "Ensure equipment removed for off-site maintenance is sanitized of any CUI.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.7.3".to_string(),
                "NIST-MA-2".to_string(),
            ],
            remediation_guidance: Some("Sanitize equipment containing CUI before off-site maintenance. Use NIST SP 800-88 approved methods.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MA.L2-3.7.4".to_string(),
            control_id: "MA.L2-3.7.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Media Inspection".to_string(),
            description: "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.7.4".to_string(),
                "NIST-MA-3(2)".to_string(),
            ],
            remediation_guidance: Some("Scan maintenance media for malware before use. Use isolated systems for initial media scanning.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MA.L2-3.7.5".to_string(),
            control_id: "MA.L2-3.7.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Nonlocal Maintenance".to_string(),
            description: "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.7.5".to_string(),
                "NIST-MA-4".to_string(),
            ],
            remediation_guidance: Some("Require MFA for remote maintenance sessions. Implement session timeout and termination controls.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MA.L2-3.7.6".to_string(),
            control_id: "MA.L2-3.7.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Maintenance Personnel".to_string(),
            description: "Supervise the maintenance activities of maintenance personnel without required access authorization.".to_string(),
            category: "Maintenance".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.7.6".to_string(),
                "NIST-MA-5".to_string(),
            ],
            remediation_guidance: Some("Escort and supervise maintenance personnel without CUI access. Log all supervised maintenance activities.".to_string()),
        },

        // ============================================================
        // MEDIA PROTECTION (MP) - 9 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.1".to_string(),
            control_id: "MP.L2-3.8.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Media Protection".to_string(),
            description: "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.1".to_string(),
                "NIST-MP-2".to_string(),
                "NIST-MP-4".to_string(),
            ],
            remediation_guidance: Some("Store CUI media in locked cabinets or secure areas. Implement access controls for media storage locations.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.2".to_string(),
            control_id: "MP.L2-3.8.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Media Access".to_string(),
            description: "Limit access to CUI on system media to authorized users.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.2".to_string(),
                "NIST-MP-2".to_string(),
            ],
            remediation_guidance: Some("Implement access controls for removable media. Restrict USB and removable storage device usage.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.3".to_string(),
            control_id: "MP.L2-3.8.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Media Disposal".to_string(),
            description: "Sanitize or destroy system media containing CUI before disposal or release for reuse.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.3".to_string(),
                "NIST-MP-6".to_string(),
            ],
            remediation_guidance: Some("Use NIST SP 800-88 approved sanitization methods. Document media destruction with certificates of destruction.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.4".to_string(),
            control_id: "MP.L2-3.8.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Media Markings".to_string(),
            description: "Mark media with necessary CUI markings and distribution limitations.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.4".to_string(),
                "NIST-MP-3".to_string(),
            ],
            remediation_guidance: Some("Apply CUI markings to all media containing controlled information. Include distribution and handling instructions.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.5".to_string(),
            control_id: "MP.L2-3.8.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Media Accountability".to_string(),
            description: "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.5".to_string(),
                "NIST-MP-5".to_string(),
            ],
            remediation_guidance: Some("Implement chain of custody for media transport. Use tamper-evident packaging for shipped media.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.6".to_string(),
            control_id: "MP.L2-3.8.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Portable Storage Encryption".to_string(),
            description: "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.6".to_string(),
                "NIST-MP-5(4)".to_string(),
            ],
            remediation_guidance: Some("Use encrypted portable storage devices (FIPS 140-2 validated). Encrypt files before transfer to removable media.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.7".to_string(),
            control_id: "MP.L2-3.8.7".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Removable Media".to_string(),
            description: "Control the use of removable media on system components.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.7".to_string(),
                "NIST-MP-7".to_string(),
            ],
            remediation_guidance: Some("Implement device control policies for USB and removable media. Whitelist approved devices.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.8".to_string(),
            control_id: "MP.L2-3.8.8".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Shared Media".to_string(),
            description: "Prohibit the use of portable storage devices when such devices have no identifiable owner.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.8".to_string(),
                "NIST-MP-7(1)".to_string(),
            ],
            remediation_guidance: Some("Block unregistered removable devices. Maintain inventory of approved portable storage devices with owner assignment.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-MP.L2-3.8.9".to_string(),
            control_id: "MP.L2-3.8.9".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Protect Backups".to_string(),
            description: "Protect the confidentiality of backup CUI at storage locations.".to_string(),
            category: "Media Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.8.9".to_string(),
                "NIST-CP-9".to_string(),
            ],
            remediation_guidance: Some("Encrypt backup data containing CUI. Store backups in secure locations with access controls.".to_string()),
        },

        // ============================================================
        // PERSONNEL SECURITY (PS) - 2 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-PS.L2-3.9.1".to_string(),
            control_id: "PS.L2-3.9.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Screen Individuals".to_string(),
            description: "Screen individuals prior to authorizing access to organizational systems containing CUI.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.9.1".to_string(),
                "NIST-PS-3".to_string(),
            ],
            remediation_guidance: Some("Conduct background checks before granting CUI access. Verify citizenship and eligibility requirements.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-PS.L2-3.9.2".to_string(),
            control_id: "PS.L2-3.9.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Personnel Actions".to_string(),
            description: "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.".to_string(),
            category: "Personnel Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.9.2".to_string(),
                "NIST-PS-4".to_string(),
                "NIST-PS-5".to_string(),
            ],
            remediation_guidance: Some("Disable access within 24 hours of termination. Conduct exit interviews and recover company assets.".to_string()),
        },

        // ============================================================
        // PHYSICAL PROTECTION (PE) - 6 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-PE.L2-3.10.1".to_string(),
            control_id: "PE.L2-3.10.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Limit Physical Access".to_string(),
            description: "Limit physical access to organizational systems, equipment, and the respective operating environments to authorized individuals.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.10.1".to_string(),
                "NIST-PE-2".to_string(),
                "NIST-PE-3".to_string(),
            ],
            remediation_guidance: Some("Implement physical access controls (badges, locks, biometrics). Maintain access control lists.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-PE.L2-3.10.2".to_string(),
            control_id: "PE.L2-3.10.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Protect & Monitor Facility".to_string(),
            description: "Protect and monitor the physical facility and support infrastructure for organizational systems.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.10.2".to_string(),
                "NIST-PE-3".to_string(),
                "NIST-PE-6".to_string(),
            ],
            remediation_guidance: Some("Implement security cameras and monitoring. Conduct regular facility security assessments.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-PE.L2-3.10.3".to_string(),
            control_id: "PE.L2-3.10.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Escort Visitors".to_string(),
            description: "Escort visitors and monitor visitor activity.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.10.3".to_string(),
                "NIST-PE-3".to_string(),
            ],
            remediation_guidance: Some("Implement visitor management system. Require escort for visitors in secure areas.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-PE.L2-3.10.4".to_string(),
            control_id: "PE.L2-3.10.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Physical Access Logs".to_string(),
            description: "Maintain audit logs of physical access.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.10.4".to_string(),
                "NIST-PE-3".to_string(),
            ],
            remediation_guidance: Some("Log all physical access events. Retain logs for at least one year.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-PE.L2-3.10.5".to_string(),
            control_id: "PE.L2-3.10.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Manage Physical Access".to_string(),
            description: "Control and manage physical access devices.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.10.5".to_string(),
                "NIST-PE-3".to_string(),
            ],
            remediation_guidance: Some("Maintain inventory of physical access devices (keys, badges). Revoke access promptly when no longer needed.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-PE.L2-3.10.6".to_string(),
            control_id: "PE.L2-3.10.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Alternative Work Sites".to_string(),
            description: "Enforce safeguarding measures for CUI at alternate work sites.".to_string(),
            category: "Physical Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.10.6".to_string(),
                "NIST-PE-17".to_string(),
            ],
            remediation_guidance: Some("Establish telework security policies. Require secure home office environments for CUI handling.".to_string()),
        },

        // ============================================================
        // RISK ASSESSMENT (RA) - 3 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-RA.L2-3.11.1".to_string(),
            control_id: "RA.L2-3.11.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Risk Assessments".to_string(),
            description: "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.11.1".to_string(),
                "NIST-RA-3".to_string(),
            ],
            remediation_guidance: Some("Conduct annual risk assessments. Document identified risks and mitigation strategies.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-RA.L2-3.11.2".to_string(),
            control_id: "RA.L2-3.11.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Vulnerability Scan".to_string(),
            description: "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.11.2".to_string(),
                "NIST-RA-5".to_string(),
            ],
            remediation_guidance: Some("Conduct vulnerability scans at least monthly. Scan when new vulnerabilities are announced.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-RA.L2-3.11.3".to_string(),
            control_id: "RA.L2-3.11.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Vulnerability Remediation".to_string(),
            description: "Remediate vulnerabilities in accordance with risk assessments.".to_string(),
            category: "Risk Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.11.3".to_string(),
                "NIST-RA-5".to_string(),
            ],
            remediation_guidance: Some("Remediate critical vulnerabilities within 15 days. Document remediation activities and timelines.".to_string()),
        },

        // ============================================================
        // SECURITY ASSESSMENT (CA) - 4 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-CA.L2-3.12.1".to_string(),
            control_id: "CA.L2-3.12.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Security Control Assessment".to_string(),
            description: "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.12.1".to_string(),
                "NIST-CA-2".to_string(),
            ],
            remediation_guidance: Some("Conduct annual security control assessments. Test technical controls for effectiveness.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CA.L2-3.12.2".to_string(),
            control_id: "CA.L2-3.12.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Plan of Action".to_string(),
            description: "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.12.2".to_string(),
                "NIST-CA-5".to_string(),
            ],
            remediation_guidance: Some("Create POA&Ms for identified deficiencies. Track remediation progress and milestones.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CA.L2-3.12.3".to_string(),
            control_id: "CA.L2-3.12.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Security Control Monitoring".to_string(),
            description: "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.12.3".to_string(),
                "NIST-CA-7".to_string(),
            ],
            remediation_guidance: Some("Implement continuous monitoring. Use automated tools to verify security control status.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-CA.L2-3.12.4".to_string(),
            control_id: "CA.L2-3.12.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "System Security Plan".to_string(),
            description: "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.".to_string(),
            category: "Security Assessment".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.12.4".to_string(),
                "NIST-PL-2".to_string(),
            ],
            remediation_guidance: Some("Create and maintain System Security Plan (SSP). Review and update annually or when significant changes occur.".to_string()),
        },

        // ============================================================
        // SYSTEM AND COMMUNICATIONS PROTECTION (SC) - 16 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.1".to_string(),
            control_id: "SC.L2-3.13.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Boundary Protection".to_string(),
            description: "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.1".to_string(),
                "NIST-SC-7".to_string(),
            ],
            remediation_guidance: Some("Implement firewalls at network boundaries. Monitor traffic between security zones.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.2".to_string(),
            control_id: "SC.L2-3.13.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Security Engineering".to_string(),
            description: "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.2".to_string(),
                "NIST-SA-8".to_string(),
            ],
            remediation_guidance: Some("Apply defense-in-depth principles. Implement secure development practices.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.3".to_string(),
            control_id: "SC.L2-3.13.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Role Separation".to_string(),
            description: "Separate user functionality from system management functionality.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.3".to_string(),
                "NIST-SC-2".to_string(),
            ],
            remediation_guidance: Some("Implement separate interfaces for user and administrative functions. Use jump servers for administrative access.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.4".to_string(),
            control_id: "SC.L2-3.13.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Shared Resource Control".to_string(),
            description: "Prevent unauthorized and unintended information transfer via shared system resources.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.4".to_string(),
                "NIST-SC-4".to_string(),
            ],
            remediation_guidance: Some("Implement memory isolation between processes. Clear shared resources between different classification levels.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.5".to_string(),
            control_id: "SC.L2-3.13.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Network Segmentation".to_string(),
            description: "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.5".to_string(),
                "NIST-SC-7(3)".to_string(),
            ],
            remediation_guidance: Some("Implement DMZ for public-facing systems. Use VLANs to segment internal networks.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.6".to_string(),
            control_id: "SC.L2-3.13.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Network Communication by Exception".to_string(),
            description: "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.6".to_string(),
                "NIST-SC-7(5)".to_string(),
            ],
            remediation_guidance: Some("Configure firewalls with default-deny rules. Whitelist only necessary traffic.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.7".to_string(),
            control_id: "SC.L2-3.13.7".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Split Tunneling".to_string(),
            description: "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.7".to_string(),
                "NIST-SC-7(7)".to_string(),
            ],
            remediation_guidance: Some("Disable split tunneling for VPN connections. Force all traffic through corporate network when connected.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.8".to_string(),
            control_id: "SC.L2-3.13.8".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Data in Transit".to_string(),
            description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.8".to_string(),
                "NIST-SC-8".to_string(),
            ],
            remediation_guidance: Some("Use TLS 1.2+ for all data transmission. Implement VPN for sensitive communications.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.9".to_string(),
            control_id: "SC.L2-3.13.9".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Connections Termination".to_string(),
            description: "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.9".to_string(),
                "NIST-SC-10".to_string(),
            ],
            remediation_guidance: Some("Configure session timeouts for network connections. Implement idle timeout for sensitive sessions.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.10".to_string(),
            control_id: "SC.L2-3.13.10".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Cryptographic Key Establishment and Management".to_string(),
            description: "Establish and manage cryptographic keys for cryptography employed in organizational systems.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.10".to_string(),
                "NIST-SC-12".to_string(),
            ],
            remediation_guidance: Some("Implement key management procedures. Use hardware security modules (HSMs) for key protection.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.11".to_string(),
            control_id: "SC.L2-3.13.11".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "CUI Encryption".to_string(),
            description: "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.11".to_string(),
                "NIST-SC-13".to_string(),
            ],
            remediation_guidance: Some("Use FIPS 140-2 validated cryptographic modules. Implement AES-256 for CUI encryption.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.12".to_string(),
            control_id: "SC.L2-3.13.12".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Collaborative Device Control".to_string(),
            description: "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.12".to_string(),
                "NIST-SC-15".to_string(),
            ],
            remediation_guidance: Some("Disable remote activation of webcams and microphones. Provide visual indicators when devices are active.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.13".to_string(),
            control_id: "SC.L2-3.13.13".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Mobile Code".to_string(),
            description: "Control and monitor the use of mobile code.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.13".to_string(),
                "NIST-SC-18".to_string(),
            ],
            remediation_guidance: Some("Control JavaScript and ActiveX execution. Implement browser security policies.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.14".to_string(),
            control_id: "SC.L2-3.13.14".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Voice over Internet Protocol".to_string(),
            description: "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.14".to_string(),
                "NIST-SC-19".to_string(),
            ],
            remediation_guidance: Some("Implement VoIP security controls. Encrypt VoIP traffic and segment VoIP network.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.15".to_string(),
            control_id: "SC.L2-3.13.15".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Communications Authenticity".to_string(),
            description: "Protect the authenticity of communications sessions.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.15".to_string(),
                "NIST-SC-23".to_string(),
            ],
            remediation_guidance: Some("Use TLS for session protection. Implement certificate validation for communications.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SC.L2-3.13.16".to_string(),
            control_id: "SC.L2-3.13.16".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Data at Rest".to_string(),
            description: "Protect the confidentiality of CUI at rest.".to_string(),
            category: "System and Communications Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.13.16".to_string(),
                "NIST-SC-28".to_string(),
            ],
            remediation_guidance: Some("Implement full-disk encryption. Use database encryption for CUI storage.".to_string()),
        },

        // ============================================================
        // SYSTEM AND INFORMATION INTEGRITY (SI) - 7 Practices
        // ============================================================
        ComplianceControl {
            id: "CMMC-SI.L2-3.14.1".to_string(),
            control_id: "SI.L2-3.14.1".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Flaw Remediation".to_string(),
            description: "Identify, report, and correct system flaws in a timely manner.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.1".to_string(),
                "NIST-SI-2".to_string(),
            ],
            remediation_guidance: Some("Implement patch management process. Remediate critical flaws within 15 days.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SI.L2-3.14.2".to_string(),
            control_id: "SI.L2-3.14.2".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Malicious Code Protection".to_string(),
            description: "Provide protection from malicious code at designated locations within organizational systems.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.2".to_string(),
                "NIST-SI-3".to_string(),
            ],
            remediation_guidance: Some("Deploy anti-malware on all endpoints. Implement email and web filtering.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SI.L2-3.14.3".to_string(),
            control_id: "SI.L2-3.14.3".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Security Alerts & Advisories".to_string(),
            description: "Monitor system security alerts and advisories and take action in response.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.3".to_string(),
                "NIST-SI-5".to_string(),
            ],
            remediation_guidance: Some("Subscribe to vendor security advisories. Implement process to assess and respond to alerts.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SI.L2-3.14.4".to_string(),
            control_id: "SI.L2-3.14.4".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Update Malicious Code Protection".to_string(),
            description: "Update malicious code protection mechanisms when new releases are available.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.4".to_string(),
                "NIST-SI-3".to_string(),
            ],
            remediation_guidance: Some("Enable automatic signature updates. Verify update status daily.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SI.L2-3.14.5".to_string(),
            control_id: "SI.L2-3.14.5".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "System & File Scanning".to_string(),
            description: "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.5".to_string(),
                "NIST-SI-3".to_string(),
            ],
            remediation_guidance: Some("Configure real-time malware scanning. Schedule weekly full system scans.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SI.L2-3.14.6".to_string(),
            control_id: "SI.L2-3.14.6".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Inbound & Outbound Traffic".to_string(),
            description: "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.6".to_string(),
                "NIST-SI-4".to_string(),
            ],
            remediation_guidance: Some("Implement IDS/IPS at network boundaries. Monitor for suspicious traffic patterns.".to_string()),
        },
        ComplianceControl {
            id: "CMMC-SI.L2-3.14.7".to_string(),
            control_id: "SI.L2-3.14.7".to_string(),
            framework: ComplianceFramework::Cmmc,
            title: "Unauthorized Use".to_string(),
            description: "Identify unauthorized use of organizational systems.".to_string(),
            category: "System and Information Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec![
                "NIST-800-171-3.14.7".to_string(),
                "NIST-SI-4".to_string(),
            ],
            remediation_guidance: Some("Implement user behavior analytics. Monitor for anomalous system usage patterns.".to_string()),
        },
    ]
}

/// Map vulnerability patterns to CMMC 2.0 controls
pub fn map_vulnerability(
    vuln_title: &str,
    cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Access Control vulnerabilities
    if title_lower.contains("unauthorized access") || title_lower.contains("privilege escalation") {
        mappings.push(("CMMC-AC.L2-3.1.1".to_string(), Severity::Critical));
        mappings.push(("CMMC-AC.L2-3.1.5".to_string(), Severity::High)); // Least Privilege
        mappings.push(("CMMC-AC.L2-3.1.7".to_string(), Severity::High)); // Privileged Functions
    }

    // Authentication vulnerabilities
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("weak password")
        || title_lower.contains("default password")
        || title_lower.contains("default credentials")
    {
        mappings.push(("CMMC-IA.L2-3.5.2".to_string(), Severity::Critical)); // Authentication
        mappings.push(("CMMC-IA.L2-3.5.7".to_string(), Severity::High)); // Password Complexity
        mappings.push(("CMMC-IA.L2-3.5.10".to_string(), Severity::High)); // Cryptographically-Protected Passwords
    }

    // Multi-factor authentication issues
    if title_lower.contains("mfa") || title_lower.contains("multi-factor") || title_lower.contains("2fa") {
        mappings.push(("CMMC-IA.L2-3.5.3".to_string(), Severity::High)); // Multi-Factor Authentication
    }

    // Session management issues
    if title_lower.contains("session") || title_lower.contains("token") {
        mappings.push(("CMMC-AC.L2-3.1.10".to_string(), Severity::Medium)); // Session Lock
        mappings.push(("CMMC-AC.L2-3.1.11".to_string(), Severity::Medium)); // Session Termination
    }

    // Account lockout issues
    if title_lower.contains("brute force") || title_lower.contains("lockout") {
        mappings.push(("CMMC-AC.L2-3.1.8".to_string(), Severity::High)); // Unsuccessful Logon Attempts
    }

    // Encryption vulnerabilities
    if title_lower.contains("unencrypted")
        || title_lower.contains("weak encryption")
        || title_lower.contains("ssl")
        || title_lower.contains("tls")
        || title_lower.contains("plaintext")
    {
        mappings.push(("CMMC-SC.L2-3.13.8".to_string(), Severity::High)); // Data in Transit
        mappings.push(("CMMC-SC.L2-3.13.11".to_string(), Severity::High)); // CUI Encryption
        mappings.push(("CMMC-SC.L2-3.13.16".to_string(), Severity::High)); // Data at Rest
        mappings.push(("CMMC-AC.L2-3.1.13".to_string(), Severity::High)); // Remote Access Confidentiality
    }

    // Patching and vulnerability management
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("eol")
        || cve_id.is_some()
    {
        mappings.push(("CMMC-SI.L2-3.14.1".to_string(), Severity::High)); // Flaw Remediation
        mappings.push(("CMMC-RA.L2-3.11.2".to_string(), Severity::High)); // Vulnerability Scan
        mappings.push(("CMMC-RA.L2-3.11.3".to_string(), Severity::High)); // Vulnerability Remediation
    }

    // Malware protection
    if title_lower.contains("malware")
        || title_lower.contains("antivirus")
        || title_lower.contains("anti-malware")
        || title_lower.contains("endpoint protection")
    {
        mappings.push(("CMMC-SI.L2-3.14.2".to_string(), Severity::High)); // Malicious Code Protection
        mappings.push(("CMMC-SI.L2-3.14.4".to_string(), Severity::Medium)); // Update Malicious Code Protection
        mappings.push(("CMMC-SI.L2-3.14.5".to_string(), Severity::Medium)); // System & File Scanning
    }

    // Logging and monitoring issues
    if title_lower.contains("no logging")
        || title_lower.contains("audit disabled")
        || title_lower.contains("monitoring")
    {
        mappings.push(("CMMC-AU.L2-3.3.1".to_string(), Severity::Medium)); // System Auditing
        mappings.push(("CMMC-AU.L2-3.3.2".to_string(), Severity::Medium)); // User Accountability
        mappings.push(("CMMC-SI.L2-3.14.6".to_string(), Severity::Medium)); // Inbound & Outbound Traffic
    }

    // Network security issues
    if title_lower.contains("firewall")
        || title_lower.contains("segmentation")
        || title_lower.contains("open port")
    {
        mappings.push(("CMMC-SC.L2-3.13.1".to_string(), Severity::Medium)); // Boundary Protection
        mappings.push(("CMMC-SC.L2-3.13.5".to_string(), Severity::Medium)); // Network Segmentation
        mappings.push(("CMMC-SC.L2-3.13.6".to_string(), Severity::Medium)); // Network Communication by Exception
    }

    // Remote access issues
    if port == Some(22) || port == Some(3389) || title_lower.contains("remote access") || title_lower.contains("rdp") {
        if title_lower.contains("vulnerable") || title_lower.contains("exposed") || title_lower.contains("weak") {
            mappings.push(("CMMC-AC.L2-3.1.12".to_string(), Severity::High)); // Control Remote Access
            mappings.push(("CMMC-AC.L2-3.1.14".to_string(), Severity::High)); // Remote Access Routing
            mappings.push(("CMMC-AC.L2-3.1.15".to_string(), Severity::High)); // Privileged Remote Access
        }
    }

    // VPN and split tunneling
    if title_lower.contains("vpn") || title_lower.contains("split tunnel") {
        mappings.push(("CMMC-SC.L2-3.13.7".to_string(), Severity::High)); // Split Tunneling
    }

    // Wireless security
    if title_lower.contains("wireless") || title_lower.contains("wifi") || title_lower.contains("wpa") {
        mappings.push(("CMMC-AC.L2-3.1.16".to_string(), Severity::High)); // Wireless Access Authorization
        mappings.push(("CMMC-AC.L2-3.1.17".to_string(), Severity::High)); // Wireless Access Protection
    }

    // USB and removable media
    if title_lower.contains("usb") || title_lower.contains("removable") || title_lower.contains("portable storage") {
        mappings.push(("CMMC-AC.L2-3.1.21".to_string(), Severity::Medium)); // Portable Storage Use
        mappings.push(("CMMC-MP.L2-3.8.7".to_string(), Severity::Medium)); // Removable Media
    }

    // Injection vulnerabilities
    if title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("xss")
        || title_lower.contains("injection")
    {
        mappings.push(("CMMC-SI.L2-3.14.1".to_string(), Severity::Critical)); // Flaw Remediation
        mappings.push(("CMMC-SC.L2-3.13.2".to_string(), Severity::High)); // Security Engineering
    }

    // Configuration management
    if title_lower.contains("misconfigur") || title_lower.contains("hardening") || title_lower.contains("baseline") {
        mappings.push(("CMMC-CM.L2-3.4.1".to_string(), Severity::Medium)); // System Baselining
        mappings.push(("CMMC-CM.L2-3.4.2".to_string(), Severity::Medium)); // Security Configuration Enforcement
        mappings.push(("CMMC-CM.L2-3.4.6".to_string(), Severity::Medium)); // Least Functionality
    }

    // Unnecessary services
    if title_lower.contains("unnecessary") || title_lower.contains("telnet") || port == Some(23) {
        mappings.push(("CMMC-CM.L2-3.4.6".to_string(), Severity::Medium)); // Least Functionality
        mappings.push(("CMMC-CM.L2-3.4.7".to_string(), Severity::Medium)); // Nonessential Functionality
    }

    // Information flow and data leakage
    if title_lower.contains("data leak") || title_lower.contains("information disclosure") || title_lower.contains("dlp") {
        mappings.push(("CMMC-AC.L2-3.1.3".to_string(), Severity::High)); // Control CUI Flow
        mappings.push(("CMMC-SC.L2-3.13.4".to_string(), Severity::Medium)); // Shared Resource Control
    }

    // Mobile device issues
    if title_lower.contains("mobile") || title_lower.contains("byod") {
        mappings.push(("CMMC-AC.L2-3.1.18".to_string(), Severity::Medium)); // Mobile Device Connection
        mappings.push(("CMMC-AC.L2-3.1.19".to_string(), Severity::High)); // Encrypt CUI on Mobile
    }

    // IDS/IPS and network monitoring
    if title_lower.contains("ids") || title_lower.contains("ips") || title_lower.contains("intrusion") {
        mappings.push(("CMMC-SI.L2-3.14.6".to_string(), Severity::High)); // Inbound & Outbound Traffic
        mappings.push(("CMMC-SI.L2-3.14.7".to_string(), Severity::High)); // Unauthorized Use
    }

    // Database exposure
    if port == Some(1433) || port == Some(3306) || port == Some(5432) || port == Some(27017) || port == Some(6379) {
        if title_lower.contains("exposed") || title_lower.contains("accessible") {
            mappings.push(("CMMC-SC.L2-3.13.1".to_string(), Severity::High)); // Boundary Protection
            mappings.push(("CMMC-AC.L2-3.1.20".to_string(), Severity::High)); // External System Connections
        }
    }

    // Backup and recovery issues
    if title_lower.contains("backup") {
        mappings.push(("CMMC-MP.L2-3.8.9".to_string(), Severity::Medium)); // Protect Backups
    }

    // Time synchronization
    if title_lower.contains("ntp") || title_lower.contains("time sync") {
        mappings.push(("CMMC-AU.L2-3.3.7".to_string(), Severity::Low)); // Authoritative Time Source
    }

    // Physical security (usually not detected by scans, but include for completeness)
    if title_lower.contains("physical") {
        mappings.push(("CMMC-PE.L2-3.10.1".to_string(), Severity::Medium)); // Limit Physical Access
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
        let controls = get_controls();
        for control in &controls {
            assert!(!control.id.is_empty());
            assert!(!control.control_id.is_empty());
            assert!(!control.title.is_empty());
            assert!(!control.description.is_empty());
            assert!(!control.category.is_empty());
            assert_eq!(control.framework, ComplianceFramework::Cmmc);
            // All CMMC controls should have NIST 800-171 cross-references
            assert!(!control.cross_references.is_empty(), "Control {} should have cross-references", control.id);
        }
    }

    #[test]
    fn test_control_id_format() {
        let controls = get_controls();
        for control in &controls {
            // CMMC control IDs follow pattern: DOMAIN.L2-3.X.Y
            assert!(control.control_id.contains(".L2-"), "Control ID {} should contain '.L2-'", control.control_id);
        }
    }

    #[test]
    fn test_vulnerability_mapping() {
        // Test authentication vulnerability mapping
        let mappings = map_vulnerability("Authentication bypass vulnerability", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("IA.L2")));

        // Test encryption vulnerability mapping
        let mappings = map_vulnerability("Weak TLS configuration", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("SC.L2")));

        // Test patching vulnerability mapping
        let mappings = map_vulnerability("Outdated software version", Some("CVE-2024-1234"), None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("SI.L2") || id.contains("RA.L2")));

        // Test remote access vulnerability mapping
        let mappings = map_vulnerability("Exposed RDP service", None, Some(3389), None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id.contains("AC.L2")));
    }

    #[test]
    fn test_domain_coverage() {
        let controls = get_controls();
        let domains = vec![
            "Access Control",
            "Awareness and Training",
            "Audit and Accountability",
            "Configuration Management",
            "Identification and Authentication",
            "Incident Response",
            "Maintenance",
            "Media Protection",
            "Personnel Security",
            "Physical Protection",
            "Risk Assessment",
            "Security Assessment",
            "System and Communications Protection",
            "System and Information Integrity",
        ];

        for domain in &domains {
            let count = controls.iter().filter(|c| c.category == *domain).count();
            assert!(count > 0, "Domain '{}' should have at least one control", domain);
        }
    }
}
